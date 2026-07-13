use super::text::redact_text;

/// Redacts and bounds evidence before it enters a finding.
#[must_use]
pub fn redact_evidence(value: &str) -> String {
    redact_text(value).chars().take(1_024).collect()
}
