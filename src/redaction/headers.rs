use super::text::redact_text;

/// Sanitizes a non-cookie header value retained by the allowlist.
#[must_use]
pub fn redact_header_value(value: &str) -> String {
    redact_text(value)
        .chars()
        .filter(|character| !character.is_control() || *character == '\t')
        .take(4_096)
        .collect()
}
