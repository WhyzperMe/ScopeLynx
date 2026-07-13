use scopelynx::redaction::{redact_text, redact_url};
use url::Url;

#[test]
fn redacts_url_credentials_query_values_and_fragment() -> Result<(), Box<dyn std::error::Error>> {
    let url = Url::parse("https://user:pass@example.org/callback?token=secret&id=7#fragment")?;
    let rendered = redact_url(&url);
    assert!(!rendered.contains("user"));
    assert!(!rendered.contains("pass"));
    assert!(!rendered.contains("secret"));
    assert!(!rendered.contains("fragment"));
    assert!(rendered.contains("token=%3Credacted%3E"));
    assert!(rendered.contains("id=%3Credacted%3E"));
    Ok(())
}

#[test]
fn redacts_secrets_embedded_in_error_text() {
    let rendered = redact_text(
        "request https://example.org/?api_key=secret failed; Authorization=abc Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
    );
    assert!(!rendered.contains("secret"));
    assert!(!rendered.contains("eyJhbGci"));
    assert!(!rendered.contains("Authorization=abc"));
}

#[test]
fn redacts_email_local_parts_but_keeps_domain_context() {
    let rendered = redact_text("Contact Alice.Example@example.org");
    assert!(!rendered.contains("Alice.Example"));
    assert!(rendered.contains("<redacted>@example.org"));
}
