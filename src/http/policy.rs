use std::time::Duration;

use crate::config::Profile;

#[derive(Debug, Clone)]
pub struct HttpPolicy {
    pub user_agent: String,
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub max_redirects: usize,
    pub follow_redirects: bool,
    pub max_retries: usize,
    pub retry_backoff: Duration,
    pub max_body_bytes: usize,
    pub max_header_bytes: usize,
    pub requests_per_second: u32,
    pub max_requests: usize,
    pub max_cached_hosts: usize,
}

impl From<&Profile> for HttpPolicy {
    fn from(profile: &Profile) -> Self {
        Self {
            user_agent: profile.user_agent.clone(),
            timeout: Duration::from_secs(profile.timeout_seconds),
            connect_timeout: Duration::from_secs(profile.connect_timeout_seconds),
            max_redirects: profile.max_redirects,
            follow_redirects: profile.follow_redirects,
            max_retries: profile.max_retries,
            retry_backoff: Duration::from_millis(profile.retry_backoff_ms),
            max_body_bytes: profile.max_body_bytes,
            max_header_bytes: profile.max_header_bytes,
            requests_per_second: profile.requests_per_second,
            max_requests: profile.max_requests,
            max_cached_hosts: profile.max_cached_hosts,
        }
    }
}
