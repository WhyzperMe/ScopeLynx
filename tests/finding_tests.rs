use scopelynx::model::{Confidence, Finding, FindingKind, Severity};

#[test]
fn finding_id_is_stable_when_evidence_detail_changes() {
    let first = Finding::new(
        FindingKind::Information,
        Severity::Info,
        Confidence::High,
        "Stable rule",
        "Description",
        "https://example.org/",
    )
    .with_evidence("source", "first observation");
    let second = Finding::new(
        FindingKind::Information,
        Severity::Info,
        Confidence::High,
        "Stable rule",
        "Description",
        "https://example.org/",
    )
    .with_evidence("source", "second observation");
    assert_eq!(first.id, second.id);
}
