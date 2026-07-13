use chrono::Utc;
use scopelynx::{
    config::ScopeMode,
    model::{
        Confidence, Finding, FindingKind, LimitState, PolicySnapshot, ScanReport, ScanStats,
        Severity,
    },
    report::diff,
};

fn report(findings: Vec<Finding>) -> ScanReport {
    ScanReport {
        schema_version: 3,
        scanner_version: "test".into(),
        scan_id: "test-scan".into(),
        config_fingerprint: "test-config".into(),
        target: "https://example.org/".into(),
        profile: "test".into(),
        policy: PolicySnapshot {
            scope_mode: ScopeMode::SameOrigin,
            allow_cross_scheme: false,
            allowed_ports: Vec::new(),
            allow_private_networks: false,
            follow_redirects: true,
            max_redirects: 3,
            max_retries: 1,
            concurrency: 1,
            requests_per_second: 1,
            max_depth: 1,
            max_requests: 10,
            max_discovered_urls: 40,
            max_body_bytes: 1024,
            max_findings: 100,
            sensitive_paths: false,
            store_bodies: false,
        },
        started_at: Utc::now(),
        finished_at: Utc::now(),
        stats: ScanStats::default(),
        limits: LimitState::default(),
        observations: Vec::new(),
        findings,
        discovered_resources: Vec::new(),
        errors: Vec::new(),
        complete: true,
        abort_reason: None,
    }
}

#[test]
fn reports_added_findings() {
    let finding = Finding::new(
        FindingKind::Information,
        Severity::Info,
        Confidence::High,
        "Example",
        "Example finding",
        "https://example.org/",
    );
    let difference = diff::compare(&report(Vec::new()), &report(vec![finding]));
    assert_eq!(difference.added_findings.len(), 1);
    assert!(difference.removed_finding_ids.is_empty());
}
