use url::Url;

/// Maximum length retained for any report-safe URL.
const MAX_REDACTED_URL_CHARS: usize = 8_192;

/// Produces a report-safe URL while preserving parameter names for diagnostics.
#[must_use]
pub fn redact_url(url: &Url) -> String {
    let mut redacted = url.clone();
    let _ = redacted.set_username("");
    let _ = redacted.set_password(None);
    let query = redacted
        .query_pairs()
        .map(|(name, _)| (name.into_owned(), "<redacted>".to_string()))
        .collect::<Vec<_>>();
    redacted.set_query(None);
    if !query.is_empty() {
        redacted.query_pairs_mut().extend_pairs(query.iter().map(|(name, value)| (name, value)));
    }
    redacted.set_fragment(None);
    redacted.to_string().chars().take(MAX_REDACTED_URL_CHARS).collect()
}

/// Produces a URL object suitable for report models.
#[must_use]
pub fn redacted_url(url: &Url) -> Url {
    let mut redacted = url.clone();
    let _ = redacted.set_username("");
    let _ = redacted.set_password(None);
    let names = redacted.query_pairs().map(|(name, _)| name.into_owned()).collect::<Vec<_>>();
    redacted.set_query(None);
    if !names.is_empty() {
        redacted.query_pairs_mut().extend_pairs(names.iter().map(|name| (name, "<redacted>")));
    }
    redacted.set_fragment(None);
    redacted
}
