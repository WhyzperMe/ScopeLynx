use proptest::prelude::*;
use scopelynx::{
    engine::canonicalize::canonical_key, redaction::redact_url, scope::is_non_public_ip,
};
use url::Url;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]
    #[test]
    fn canonicalization_is_idempotent(path in "[a-zA-Z0-9/_-]{0,80}", value in "[a-zA-Z0-9_-]{0,40}") {
        let raw = format!("https://example.org/{path}?utm_source=x&id={value}#fragment");
        let url = Url::parse(&raw).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let first = canonical_key(&url);
        let reparsed = Url::parse(&first).map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(&first, &canonical_key(&reparsed));
        prop_assert!(!first.contains('#'));
    }

    #[test]
    fn redacted_urls_do_not_retain_secret_values(secret in "[A-Z0-9]{24}") {
        let raw = format!("https://user:{secret}@example.org/callback?token={secret}#private");
        let url = Url::parse(&raw).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let redacted = redact_url(&url);
        prop_assert!(!redacted.contains(&secret));
        prop_assert!(!redacted.contains("private"));
        prop_assert!(!redacted.contains("user"));
    }

    #[test]
    fn private_ipv4_ranges_are_never_public(a in 10u8..=10, b in any::<u8>(), c in any::<u8>(), d in any::<u8>()) {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d));
        prop_assert!(is_non_public_ip(ip));
    }
}
