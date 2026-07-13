use std::{
    collections::BTreeMap,
    io::Write,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use flate2::{Compression, write::GzEncoder};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};

#[derive(Debug)]
pub struct TestServer {
    address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
    counts: Arc<Mutex<BTreeMap<String, usize>>>,
}

impl TestServer {
    pub async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        Self::start_internal(false).await
    }

    pub async fn start_catch_all() -> Result<Self, Box<dyn std::error::Error>> {
        Self::start_internal(true).await
    }

    async fn start_internal(catch_all: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (shutdown, mut shutdown_receiver) = oneshot::channel();
        let counts = Arc::new(Mutex::new(BTreeMap::new()));
        let task_counts = Arc::clone(&counts);
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_receiver => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break; };
                        let connection_counts = Arc::clone(&task_counts);
                        tokio::spawn(async move {
                            let _result =
                                serve_connection(stream, connection_counts, catch_all).await;
                        });
                    }
                }
            }
        });
        Ok(Self { address, shutdown: Some(shutdown), task, counts })
    }

    #[must_use]
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.address, path)
    }

    #[must_use]
    pub fn request_count(&self, path: &str) -> usize {
        self.counts.lock().ok().and_then(|counts| counts.get(path).copied()).unwrap_or_default()
    }

    pub async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _result = shutdown.send(());
        }
        let _result = self.task.await;
    }
}

async fn serve_connection(
    mut stream: TcpStream,
    counts: Arc<Mutex<BTreeMap<String, usize>>>,
    catch_all: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut request = Vec::with_capacity(1_024);
    let mut buffer = [0_u8; 1_024];
    while request.len() < 16 * 1024 {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let first_line =
        String::from_utf8_lossy(&request).lines().next().unwrap_or_default().to_string();
    let mut parts = first_line.split_ascii_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or("/").split('?').next().unwrap_or("/");
    if method != "GET" {
        write_response(&mut stream, "405 Method Not Allowed", &[], b"").await?;
        return Ok(());
    }

    let count = if let Ok(mut locked) = counts.lock() {
        let entry = locked.entry(path.to_string()).or_default();
        *entry += 1;
        *entry
    } else {
        1
    };

    if catch_all {
        write_response(
            &mut stream,
            "200 OK",
            &[("Content-Type", "text/html; charset=utf-8"), ("Server", "nginx")],
            b"<!doctype html><html><title>In Development</title><body><h1>Nebula</h1><a href='/config.json'>config</a><a href='/backup.zip'>backup</a></body></html>",
        )
        .await?;
        return Ok(());
    }

    match path {
        "/ok" => {
            write_response(
                &mut stream,
                "200 OK",
                &[("Content-Type", "text/html; charset=utf-8")],
                b"<!doctype html><html><head><link rel='manifest' href='/manifest.webmanifest'><script type='application/ld+json'>{\"url\":\"/company\"}</script></head><body><a href='/next'>next</a><form method='get' action='/search'></form><form method='post' action='/submit'></form></body></html>",
            )
            .await?;
        }
        "/redirect" => {
            write_response(&mut stream, "302 Found", &[("Location", "/ok")], b"").await?;
        }
        "/loop-a" => {
            write_response(&mut stream, "302 Found", &[("Location", "/loop-b")], b"").await?;
        }
        "/loop-b" => {
            write_response(&mut stream, "302 Found", &[("Location", "/loop-a")], b"").await?;
        }
        "/cross-origin" => {
            write_response(
                &mut stream,
                "302 Found",
                &[("Location", "http://127.0.0.1:1/out-of-scope")],
                b"",
            )
            .await?;
        }
        "/retry" if count <= 2 => {
            write_response(
                &mut stream,
                "503 Service Unavailable",
                &[("Retry-After", "0")],
                b"retry",
            )
            .await?;
        }
        "/retry" => {
            write_response(&mut stream, "200 OK", &[("Content-Type", "text/plain")], b"ok").await?;
        }
        "/rate-limit" if count == 1 => {
            write_response(&mut stream, "429 Too Many Requests", &[("Retry-After", "0")], b"retry")
                .await?;
        }
        "/rate-limit" => {
            write_response(&mut stream, "200 OK", &[("Content-Type", "text/plain")], b"ok").await?;
        }
        "/always-503" => {
            write_response(
                &mut stream,
                "503 Service Unavailable",
                &[("Retry-After", "0")],
                b"retry",
            )
            .await?;
        }
        "/large" => {
            write_response(
                &mut stream,
                "200 OK",
                &[("Content-Type", "text/plain")],
                &vec![b'a'; 8_192],
            )
            .await?;
        }
        "/gzip" => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
            encoder.write_all(&vec![b'g'; 8_192])?;
            let compressed = encoder.finish()?;
            write_response(
                &mut stream,
                "200 OK",
                &[("Content-Type", "text/plain"), ("Content-Encoding", "gzip")],
                &compressed,
            )
            .await?;
        }
        "/headers" => {
            write_response(
                &mut stream,
                "200 OK",
                &[
                    ("Content-Type", "text/plain"),
                    ("Set-Cookie", "session=super-secret; Secure; HttpOnly; SameSite=Lax"),
                    ("Set-Cookie", "preferences=private-value; Path=/; SameSite=Strict"),
                ],
                b"headers",
            )
            .await?;
        }
        "/status/401" => {
            write_response(&mut stream, "401 Unauthorized", &[], b"unauthorized").await?;
        }
        "/status/403" => {
            write_response(&mut stream, "403 Forbidden", &[], b"forbidden").await?;
        }
        "/status/500" => {
            write_response(&mut stream, "500 Internal Server Error", &[], b"error").await?;
        }
        "/status/503" => {
            write_response(&mut stream, "503 Service Unavailable", &[], b"unavailable").await?;
        }
        "/status/304" => {
            write_response(&mut stream, "304 Not Modified", &[("ETag", "fixture")], b"").await?;
        }
        "/status/404" => {
            write_response(&mut stream, "404 Not Found", &[], b"not found").await?;
        }
        "/slow" => {
            tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
            write_response(&mut stream, "200 OK", &[("Content-Type", "text/plain")], b"slow")
                .await?;
        }
        "/aborted" => {
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\npartial",
                )
                .await?;
            stream.shutdown().await?;
        }
        "/chunked" => {
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
                )
                .await?;
            stream.shutdown().await?;
        }
        "/robots.txt" => {
            write_response(
                &mut stream,
                "200 OK",
                &[("Content-Type", "text/plain")],
                b"User-agent: *\nDisallow: /private\nAllow: /public\nSitemap: /sitemap.xml\n",
            )
            .await?;
        }
        "/sitemap.xml" => {
            write_response(
                &mut stream,
                "200 OK",
                &[("Content-Type", "application/xml")],
                b"<sitemapindex><sitemap><loc>/nested-sitemap.xml</loc></sitemap></sitemapindex>",
            )
            .await?;
        }
        "/nested-sitemap.xml" => {
            write_response(
                &mut stream,
                "200 OK",
                &[("Content-Type", "application/xml")],
                b"<urlset><url><loc>/from-sitemap</loc></url></urlset>",
            )
            .await?;
        }
        "/app.js" => {
            write_response(
                &mut stream,
                "200 OK",
                &[("Content-Type", "application/javascript")],
                b"fetch('/api/v1/public'); //# sourceMappingURL=/app.js.map",
            )
            .await?;
        }
        "/app.js.map" => {
            write_response(
                &mut stream,
                "200 OK",
                &[("Content-Type", "application/json")],
                br#"{"version":3,"sources":["app.ts"]}"#,
            )
            .await?;
        }
        "/listing" => {
            write_response(
                &mut stream,
                "200 OK",
                &[("Content-Type", "text/html")],
                b"<html><title>Index of /</title><a>Parent Directory</a></html>",
            )
            .await?;
        }
        "/stack" => {
            let mut body = b"Traceback (most recent call last)\n".to_vec();
            body.resize(336, b'x');
            write_response(&mut stream, "200 OK", &[("Content-Type", "text/plain")], &body).await?;
        }
        "/feed.xml" => {
            write_response(
                &mut stream,
                "200 OK",
                &[("Content-Type", "application/atom+xml")],
                b"<feed xmlns='http://www.w3.org/2005/Atom'><link href='/entry'/></feed>",
            )
            .await?;
        }
        "/manifest.webmanifest" => {
            write_response(
                &mut stream,
                "200 OK",
                &[("Content-Type", "application/manifest+json")],
                br#"{"start_url":"/app","icons":[{"src":"/icon.png"}]}"#,
            )
            .await?;
        }
        "/document.pdf" => {
            write_response(
                &mut stream,
                "200 OK",
                &[("Content-Type", "application/pdf")],
                b"%PDF-1.7\n%fixture",
            )
            .await?;
        }
        path if path.contains("__smart_scanner_missing_") => {
            let body = format!(
                "<html><title>Missing</title><body>Page not found request {count}</body></html>"
            );
            write_response(
                &mut stream,
                "200 OK",
                &[("Content-Type", "text/html")],
                body.as_bytes(),
            )
            .await?;
        }
        _ => {
            write_response(
                &mut stream,
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                b"not found",
            )
            .await?;
        }
    }
    Ok(())
}

async fn write_response(
    stream: &mut TcpStream,
    status: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(), std::io::Error> {
    let mut head =
        format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    for (name, value) in headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await
}
