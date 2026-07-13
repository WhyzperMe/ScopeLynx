use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use scopelynx::{
    config::{Profile, ScopeMode},
    scope::{ScopePolicy, is_non_public_ip, redact_url},
    target::Target,
};
use url::Url;

fn profile() -> Profile {
    Profile {
        name: "test".into(),
        user_agent: "test".into(),
        scope_mode: ScopeMode::SameOrigin,
        allow_cross_scheme: false,
        allowed_ports: Vec::new(),
        allow_private_networks: false,
        follow_redirects: true,
        max_redirects: 3,
        max_retries: 1,
        retry_backoff_ms: 100,
        concurrency: 2,
        requests_per_second: 2,
        timeout_seconds: 5,
        connect_timeout_seconds: 3,
        max_depth: 1,
        max_requests: 10,
        max_discovered_urls: 40,
        max_candidates_per_response: 20,
        max_body_bytes: 1024,
        max_header_bytes: 4096,
        max_wordlist_bytes: 4096,
        max_wordlist_entries: 100,
        max_cached_hosts: 4,
        max_dns_addresses: 4,
        max_errors: 100,
        max_findings: 100,
        discover_robots: true,
        discover_sitemap: true,
        discover_html: true,
        discover_javascript: false,
        allow_wordlists: true,
        sensitive_paths: false,
    }
}

#[test]
fn enforces_same_origin() -> Result<(), Box<dyn std::error::Error>> {
    let target = Target::parse("https://example.org/app")?;
    let scope = ScopePolicy::new(target, &profile());
    assert!(scope.allows_url(&Url::parse("https://example.org/docs")?));
    assert!(!scope.allows_url(&Url::parse("http://example.org/docs")?));
    assert!(!scope.allows_url(&Url::parse("https://other.example/docs")?));
    Ok(())
}

#[test]
fn blocks_private_ipv4() {
    assert!(is_non_public_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    assert!(is_non_public_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert!(!is_non_public_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
}

#[test]
fn redacts_query_values() -> Result<(), Box<dyn std::error::Error>> {
    let url = Url::parse("https://example.org/callback?code=secret&state=abc#fragment")?;
    let redacted = redact_url(&url);
    assert!(redacted.contains("code=%3Credacted%3E"));
    assert!(!redacted.contains("secret"));
    assert!(!redacted.contains("fragment"));
    Ok(())
}

#[test]
fn normalizes_idna_and_ipv6_targets() -> Result<(), Box<dyn std::error::Error>> {
    let idna = Target::parse("https://b\u{00fc}cher.example/")?;
    assert_eq!(idna.host, "xn--bcher-kva.example");

    let ipv6 = Target::parse("http://[::1]/")?;
    assert!(ipv6.host_is_ip());
    assert_eq!(ipv6.host, "::1");
    Ok(())
}

#[test]
fn rejects_trailing_dot_to_keep_dns_override_identity_exact() {
    assert!(Target::parse("https://example.org./").is_err());
}

#[test]
fn blocks_ipv4_mapped_ipv6() {
    assert!(is_non_public_ip(IpAddr::V6(Ipv6Addr::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1,
    ]))));
}

#[tokio::test]
async fn private_lan_literal_requires_opt_in_and_then_resolves_without_dns()
-> Result<(), Box<dyn std::error::Error>> {
    let target = Target::parse("http://192.168.1.101:8080/")?;
    let blocked = ScopePolicy::new(target.clone(), &profile());
    assert!(blocked.resolve_network_target(&target.base_url).await.is_err());

    let mut authorized = profile();
    authorized.allow_private_networks = true;
    let allowed = ScopePolicy::new(target.clone(), &authorized)
        .resolve_network_target(&target.base_url)
        .await?;
    assert_eq!(allowed.addresses[0].ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)));
    assert_eq!(allowed.addresses[0].port(), 8080);
    Ok(())
}

#[tokio::test]
async fn public_wan_literal_remains_allowed_without_private_opt_in()
-> Result<(), Box<dyn std::error::Error>> {
    let target = Target::parse("https://1.1.1.1/")?;
    let resolved = ScopePolicy::new(target.clone(), &profile())
        .resolve_network_target(&target.base_url)
        .await?;
    assert_eq!(resolved.addresses[0].ip(), IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    assert_eq!(resolved.addresses[0].port(), 443);
    Ok(())
}
