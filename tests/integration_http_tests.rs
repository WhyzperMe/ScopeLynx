mod support;

use scopelynx::{
    engine::queue::RequestTask,
    http::{HttpPolicy, ScannerHttpClient, content::ContentKind},
    model::{DiscoverySource, ResponseClass},
    scope::ScopePolicy,
    target::Target,
};
use url::Url;

use support::{TestServer, local_profile};

fn task(url: &str) -> Result<RequestTask, url::ParseError> {
    Ok(RequestTask {
        url: Url::parse(url)?,
        source: DiscoverySource::Seed,
        depth: 0,
        priority: 255,
    })
}

fn client(
    target: &str,
    profile: &scopelynx::config::Profile,
) -> Result<ScannerHttpClient, Box<dyn std::error::Error>> {
    let target = Target::parse(target)?;
    Ok(ScannerHttpClient::new(ScopePolicy::new(target, profile), HttpPolicy::from(profile)))
}

#[tokio::test]
async fn captures_bounded_body_and_classifies_content() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServer::start().await?;
    let mut profile = local_profile();
    profile.max_body_bytes = 1_024;
    let client = client(&server.url("/large"), &profile)?;

    let response = client.fetch(task(&server.url("/large"))?).await?;
    assert_eq!(response.body.len(), 1_024);
    assert!(response.observation.truncated);
    assert_eq!(response.observation.content_kind, ContentKind::PlainText);
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn body_limit_applies_after_gzip_decompression() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServer::start().await?;
    let mut profile = local_profile();
    profile.max_body_bytes = 1_024;
    let client = client(&server.url("/gzip"), &profile)?;

    let response = client.fetch(task(&server.url("/gzip"))?).await?;
    assert_eq!(response.body.len(), 1_024);
    assert!(response.observation.truncated);
    assert!(response.body.iter().all(|byte| *byte == b'g'));
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn repeated_cookies_are_retained_without_values() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServer::start().await?;
    let profile = local_profile();
    let client = client(&server.url("/headers"), &profile)?;

    let response = client.fetch(task(&server.url("/headers"))?).await?;
    let cookies = response.observation.headers.get("set-cookie").ok_or("set-cookie missing")?;
    assert_eq!(cookies.len(), 2);
    let rendered = cookies.join(";");
    assert!(rendered.contains("session=<redacted>"));
    assert!(!rendered.contains("super-secret"));
    assert!(!rendered.contains("private-value"));
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn reads_chunked_responses_and_isolates_aborted_bodies()
-> Result<(), Box<dyn std::error::Error>> {
    let server = TestServer::start().await?;
    let profile = local_profile();
    let client = client(&server.url("/chunked"), &profile)?;

    let response = client.fetch(task(&server.url("/chunked"))?).await?;
    assert_eq!(response.body, b"hello world");

    let error = client
        .fetch(task(&server.url("/aborted?token=must-not-leak"))?)
        .await
        .err()
        .ok_or("expected aborted response error")?;
    assert!(!error.to_string().contains("must-not-leak"));
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn request_timeout_is_structured() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServer::start().await?;
    let mut profile = local_profile();
    profile.timeout_seconds = 1;
    profile.max_retries = 0;
    let client = client(&server.url("/slow"), &profile)?;

    let error = client.fetch(task(&server.url("/slow"))?).await.err().ok_or("expected timeout")?;
    assert!(matches!(error, scopelynx::error::ScannerError::Timeout(_)));
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn distinguishes_200_304_404_and_503_without_conflation()
-> Result<(), Box<dyn std::error::Error>> {
    let server = TestServer::start().await?;
    let mut profile = local_profile();
    profile.max_retries = 0;
    let client = client(&server.url("/ok"), &profile)?;

    for (path, status, class) in [
        ("/ok", 200, ResponseClass::Success),
        ("/status/304", 304, ResponseClass::NotModified),
        ("/status/404", 404, ResponseClass::NotFound),
        ("/status/503", 503, ResponseClass::ServerError),
    ] {
        let response = client.fetch(task(&server.url(path))?).await?;
        assert_eq!(response.observation.status, status);
        assert_eq!(response.observation.class, class);
    }

    server.stop().await;
    Ok(())
}
