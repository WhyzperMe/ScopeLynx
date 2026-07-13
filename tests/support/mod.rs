#![allow(dead_code)]

mod test_server;

pub use test_server::TestServer;

use scopelynx::config::{Profile, ScopeMode};

pub fn local_profile() -> Profile {
    Profile {
        name: "integration".into(),
        user_agent: "ScopeLynx/Test".into(),
        scope_mode: ScopeMode::SameOrigin,
        allow_cross_scheme: false,
        allowed_ports: Vec::new(),
        allow_private_networks: true,
        follow_redirects: true,
        max_redirects: 4,
        max_retries: 2,
        retry_backoff_ms: 10,
        concurrency: 4,
        requests_per_second: 100,
        timeout_seconds: 2,
        connect_timeout_seconds: 1,
        max_depth: 2,
        max_requests: 30,
        max_discovered_urls: 100,
        max_candidates_per_response: 100,
        max_body_bytes: 4_096,
        max_header_bytes: 8_192,
        max_wordlist_bytes: 4_096,
        max_wordlist_entries: 100,
        max_cached_hosts: 4,
        max_dns_addresses: 4,
        max_errors: 100,
        max_findings: 100,
        discover_robots: true,
        discover_sitemap: true,
        discover_html: true,
        discover_javascript: true,
        allow_wordlists: true,
        sensitive_paths: false,
    }
}
