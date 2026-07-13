use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use futures_util::StreamExt;
use reqwest::{
    Client, StatusCode,
    header::{self, HeaderMap},
    redirect::Policy,
};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use url::Url;

use crate::{
    engine::queue::RequestTask,
    error::{Result, ScannerError},
    model::{HeaderSnapshot, Observation, ResponseClass},
    redaction::headers::redact_header_value,
    scope::{ResolvedTarget, ScopePolicy, redact_url, redacted_url},
};

use super::{FetchedResponse, HttpPolicy};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ClientKey {
    scheme: String,
    host: String,
    port: u16,
}

#[derive(Debug, Clone)]
pub struct ScannerHttpClient {
    scope: ScopePolicy,
    policy: HttpPolicy,
    clients: Arc<Mutex<BTreeMap<ClientKey, Client>>>,
    next_request_at: Arc<Mutex<BTreeMap<String, Instant>>>,
    wire_requests: Arc<AtomicUsize>,
}

impl ScannerHttpClient {
    #[must_use]
    pub fn new(scope: ScopePolicy, policy: HttpPolicy) -> Self {
        Self {
            scope,
            policy,
            clients: Arc::new(Mutex::new(BTreeMap::new())),
            next_request_at: Arc::new(Mutex::new(BTreeMap::new())),
            wire_requests: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub async fn fetch(&self, task: RequestTask) -> Result<FetchedResponse> {
        let requested_url = task.url.clone();
        let started = Instant::now();
        let mut current_url = task.url.clone();
        let mut redirect_chain = Vec::new();
        let mut visited = BTreeSet::new();
        let mut total_retries = 0usize;

        loop {
            if !visited.insert(current_url.as_str().to_string()) {
                return Err(ScannerError::Redirect(format!(
                    "redirect loop detected at {}",
                    redact_url(&current_url)
                )));
            }

            let resolved = self.scope.resolve_network_target(&current_url).await?;
            let client = self.client_for(&current_url, &resolved).await?;
            let response = self
                .send_with_retries(&client, &current_url, &resolved, &mut total_retries)
                .await?;
            let status = response.status();

            if status.is_redirection() && self.policy.follow_redirects {
                if redirect_chain.len() >= self.policy.max_redirects {
                    return Err(ScannerError::Redirect(format!(
                        "redirect limit exceeded for {}",
                        redact_url(&current_url)
                    )));
                }
                let Some(location) = response.headers().get(header::LOCATION) else {
                    return self
                        .finish_response(
                            requested_url,
                            current_url,
                            redirect_chain,
                            task,
                            response,
                            started,
                            total_retries,
                        )
                        .await;
                };
                let location = location.to_str().map_err(|_| {
                    ScannerError::Parse("redirect Location is not valid UTF-8".into())
                })?;
                let next_url = current_url.join(location)?;
                if !self.scope.allows_url(&next_url)
                    || crate::discovery::is_potentially_destructive(&next_url)
                {
                    return Err(ScannerError::Scope(redact_url(&next_url)));
                }
                redirect_chain.push(redacted_url(&next_url));
                current_url = next_url;
                continue;
            }

            return self
                .finish_response(
                    requested_url,
                    current_url,
                    redirect_chain,
                    task,
                    response,
                    started,
                    total_retries,
                )
                .await;
        }
    }

    #[must_use]
    pub fn wire_requests(&self) -> usize {
        self.wire_requests.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn budget_exhausted(&self) -> bool {
        self.wire_requests() >= self.policy.max_requests
    }

    async fn send_with_retries(
        &self,
        client: &Client,
        url: &Url,
        resolved: &ResolvedTarget,
        total_retries: &mut usize,
    ) -> Result<reqwest::Response> {
        let mut attempt = 0usize;
        loop {
            self.wait_for_rate_limit(resolved).await;
            self.take_request_budget()?;

            match client.get(url.clone()).send().await {
                Ok(response) => {
                    if is_retryable_status(response.status()) && attempt < self.policy.max_retries {
                        let delay =
                            retry_delay(response.headers(), self.policy.retry_backoff, attempt);
                        attempt += 1;
                        *total_retries += 1;
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    return Ok(response);
                }
                Err(error)
                    if attempt < self.policy.max_retries
                        && (error.is_timeout() || error.is_connect()) =>
                {
                    let delay = exponential_backoff(self.policy.retry_backoff, attempt);
                    attempt += 1;
                    *total_retries += 1;
                    tokio::time::sleep(delay).await;
                }
                Err(error) if error.is_timeout() => {
                    return Err(ScannerError::Timeout("request timeout".into()));
                }
                Err(error) if error.is_connect() => {
                    return Err(ScannerError::Connect("connection attempt failed".into()));
                }
                Err(error) => return Err(ScannerError::Http(error.without_url())),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_response(
        &self,
        requested_url: Url,
        final_url: Url,
        redirect_chain: Vec<Url>,
        task: RequestTask,
        response: reqwest::Response,
        started: Instant,
        retry_count: usize,
    ) -> Result<FetchedResponse> {
        let status = response.status();
        let declared_body_length = response.content_length();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.chars().take(512).collect::<String>());
        let headers =
            sanitized_headers(response.headers(), &final_url, self.policy.max_header_bytes);
        let (body, truncated) = read_bounded_body(response, self.policy.max_body_bytes).await?;
        let body_sha256 = hex::encode(Sha256::digest(&body));
        let content_kind =
            super::content::classify(content_type.as_deref(), final_url.path(), &body);

        Ok(FetchedResponse {
            effective_url: final_url.clone(),
            observation: Observation {
                requested_url: redacted_url(&requested_url),
                final_url: redacted_url(&final_url),
                redirect_chain,
                source: task.source,
                depth: task.depth,
                status: status.as_u16(),
                class: ResponseClass::from_status(status.as_u16()),
                content_type,
                content_kind,
                headers,
                elapsed_ms: started.elapsed().as_millis(),
                declared_body_length,
                captured_body_length: body.len(),
                body_sha256,
                truncated,
                soft_404: false,
                soft_404_score: None,
                soft_404_reasons: Vec::new(),
                retry_count,
                stored_body: None,
            },
            body,
        })
    }

    async fn client_for(&self, url: &Url, resolved: &ResolvedTarget) -> Result<Client> {
        let key = ClientKey {
            scheme: url.scheme().to_string(),
            host: resolved.host.clone(),
            port: resolved.port,
        };
        if let Some(client) = self.clients.lock().await.get(&key).cloned() {
            return Ok(client);
        }

        let mut clients = self.clients.lock().await;
        if let Some(client) = clients.get(&key).cloned() {
            return Ok(client);
        }
        if clients.len() >= self.policy.max_cached_hosts {
            return Err(ScannerError::Limit(
                "maximum number of cached network hosts reached".into(),
            ));
        }

        let mut builder = Client::builder()
            .user_agent(self.policy.user_agent.clone())
            .timeout(self.policy.timeout)
            .connect_timeout(self.policy.connect_timeout)
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .tcp_nodelay(true)
            .pool_idle_timeout(Duration::from_secs(30));

        if resolved.host.parse::<IpAddr>().is_err() {
            builder = builder.resolve_to_addrs(&resolved.host, &resolved.addresses);
        }

        let client = builder.build()?;
        clients.insert(key, client.clone());
        Ok(client)
    }

    async fn wait_for_rate_limit(&self, resolved: &ResolvedTarget) {
        let interval = Duration::from_secs_f64(1.0 / f64::from(self.policy.requests_per_second));
        let key = format!("{}:{}", resolved.host, resolved.port);
        let delay = {
            let mut limits = self.next_request_at.lock().await;
            let now = Instant::now();
            let next = limits.entry(key).or_insert(now);
            let scheduled = (*next).max(now);
            *next = scheduled + interval;
            scheduled.saturating_duration_since(now)
        };
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    fn take_request_budget(&self) -> Result<()> {
        let result =
            self.wire_requests.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < self.policy.max_requests).then_some(current + 1)
            });
        result.map(|_| ()).map_err(|_| ScannerError::RequestBudgetExhausted)
    }
}

async fn read_bounded_body(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<(Vec<u8>, bool)> {
    let mut body = Vec::with_capacity(max_bytes.min(64 * 1024));
    let mut stream = response.bytes_stream();
    let mut truncated = false;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| ScannerError::Http(error.without_url()))?;
        let remaining = max_bytes.saturating_sub(body.len());
        if remaining == 0 {
            truncated = true;
            break;
        }
        if chunk.len() > remaining {
            body.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }

    Ok((body, truncated))
}

fn sanitized_headers(headers: &HeaderMap, base: &Url, max_bytes: usize) -> HeaderSnapshot {
    const ALLOWED: &[&str] = &[
        "access-control-allow-credentials",
        "access-control-allow-origin",
        "cache-control",
        "content-encoding",
        "content-length",
        "content-security-policy",
        "content-type",
        "cross-origin-embedder-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "etag",
        "last-modified",
        "location",
        "permissions-policy",
        "referrer-policy",
        "server",
        "set-cookie",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "x-powered-by",
    ];

    let mut output = HeaderSnapshot::new();
    let mut captured = 0usize;
    for name in ALLOWED {
        for value in headers.get_all(*name) {
            let raw = value.to_str().unwrap_or("<non-utf8>");
            let rendered = match *name {
                "set-cookie" => redact_set_cookie(raw),
                "location" => base
                    .join(raw)
                    .map_or_else(|_| "<invalid-location>".into(), |url| redact_url(&url)),
                _ => redact_header_value(raw),
            };
            let remaining = max_bytes.saturating_sub(captured.saturating_add(name.len()));
            if remaining == 0 {
                return output;
            }
            let bounded = truncate_utf8_bytes(&rendered, remaining.min(4_096));
            captured = captured.saturating_add(name.len() + bounded.len());
            output.entry((*name).to_string()).or_default().push(bounded);
        }
    }
    output
}

fn truncate_utf8_bytes(value: &str, maximum: usize) -> String {
    let end = value
        .char_indices()
        .map(|(index, character)| index + character.len_utf8())
        .take_while(|end| *end <= maximum)
        .last()
        .unwrap_or_default();
    value[..end].to_string()
}

fn redact_set_cookie(raw: &str) -> String {
    let mut parts = raw.split(';');
    let first = parts.next().unwrap_or_default().trim();
    let name = first.split_once('=').map_or(first, |(name, _)| name).trim();
    let safe_name = name
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
        .take(128)
        .collect::<String>();
    let attributes = parts
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            let attribute_name = value.split_once('=').map_or(value, |(name, _)| name);
            if attribute_name.eq_ignore_ascii_case("samesite") {
                let rendered = value
                    .split_once('=')
                    .map(|(_, value)| value.trim())
                    .filter(|value| {
                        ["lax", "strict", "none"]
                            .iter()
                            .any(|allowed| value.eq_ignore_ascii_case(allowed))
                    })
                    .unwrap_or("<invalid>");
                format!("SameSite={rendered}")
            } else if attribute_name.eq_ignore_ascii_case("max-age") {
                let rendered = value
                    .split_once('=')
                    .map(|(_, value)| value.trim())
                    .filter(|value| value.parse::<i64>().is_ok())
                    .unwrap_or("<invalid>");
                format!("Max-Age={rendered}")
            } else if attribute_name.eq_ignore_ascii_case("domain")
                || attribute_name.eq_ignore_ascii_case("path")
            {
                format!("{attribute_name}=<redacted>")
            } else if attribute_name.eq_ignore_ascii_case("expires") {
                "Expires=<present>".into()
            } else {
                attribute_name.chars().take(128).collect()
            }
        })
        .collect::<Vec<_>>();

    if attributes.is_empty() {
        format!("{safe_name}=<redacted>")
    } else {
        format!("{safe_name}=<redacted>; {}", attributes.join("; "))
    }
}

fn is_retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

fn retry_delay(headers: &HeaderMap, base: Duration, attempt: usize) -> Duration {
    let retry_after = headers
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .map(|delay| delay.min(Duration::from_secs(30)));
    retry_after.unwrap_or_else(|| exponential_backoff(base, attempt))
}

fn exponential_backoff(base: Duration, attempt: usize) -> Duration {
    let multiplier = 1u32.checked_shl(attempt.min(8) as u32).unwrap_or(u32::MAX);
    base.saturating_mul(multiplier).min(Duration::from_secs(30))
}
