use url::Url;

const TRACKING_PARAMETERS: &[&str] = &[
    "fbclid",
    "gclid",
    "mc_cid",
    "mc_eid",
    "msclkid",
    "utm_campaign",
    "utm_content",
    "utm_medium",
    "utm_source",
    "utm_term",
];

#[must_use]
pub fn canonical_key(url: &Url) -> String {
    let mut normalized = url.clone();
    normalized.set_fragment(None);

    if normalized.port() == normalized.port_or_known_default() {
        let _ = normalized.set_port(None);
    }

    let mut pairs = normalized
        .query_pairs()
        .filter(|(name, _)| {
            !TRACKING_PARAMETERS.iter().any(|tracking| name.eq_ignore_ascii_case(tracking))
        })
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    pairs.sort();
    normalized.set_query(None);
    if !pairs.is_empty() {
        normalized
            .query_pairs_mut()
            .extend_pairs(pairs.iter().map(|(name, value)| (name.as_str(), value.as_str())));
    }

    if normalized.path().is_empty() {
        normalized.set_path("/");
    }
    normalized.to_string()
}
