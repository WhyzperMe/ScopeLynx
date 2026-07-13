pub mod feeds;
pub mod html;
pub mod javascript;
pub mod manifests;
pub mod robots;
pub mod sitemap;
pub mod wordlist;

use std::collections::BTreeMap;

use url::Url;

use crate::{engine::canonicalize::canonical_key, model::DiscoverySource};

#[derive(Debug, Clone)]
pub struct DiscoveredUrl {
    pub url: Url,
    pub source: DiscoverySource,
    pub priority: u8,
    pub relation: &'static str,
}

#[must_use]
pub fn deduplicate(candidates: Vec<DiscoveredUrl>) -> Vec<DiscoveredUrl> {
    let mut unique = BTreeMap::<String, DiscoveredUrl>::new();
    for candidate in candidates {
        let key = canonical_key(&candidate.url);
        match unique.get(&key) {
            Some(existing) if existing.priority >= candidate.priority => {}
            _ => {
                unique.insert(key, candidate);
            }
        }
    }
    unique.into_values().collect()
}

pub(crate) fn resolve_http_url(base: &Url, raw: &str) -> Option<Url> {
    let value = raw.trim();
    if value.is_empty()
        || value.starts_with('#')
        || value.starts_with("javascript:")
        || value.starts_with("data:")
        || value.starts_with("mailto:")
        || value.starts_with("tel:")
        || value.len() > 8_192
    {
        return None;
    }
    let mut url = base.join(value).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    url.set_fragment(None);
    (!is_potentially_destructive(&url)).then_some(url)
}

/// Conservative protection against GET endpoints commonly used to mutate session state.
#[must_use]
pub fn is_potentially_destructive(url: &Url) -> bool {
    let decoded = percent_decode_path(url.path()).to_ascii_lowercase();
    decoded.split('/').any(|segment| {
        matches!(
            segment.trim(),
            "logout"
                | "log-out"
                | "signout"
                | "sign-out"
                | "delete"
                | "destroy"
                | "remove-account"
                | "revoke"
                | "unsubscribe"
        )
    })
}

#[must_use]
pub fn is_sensitive_path(url: &Url) -> bool {
    let path = percent_decode_path(url.path()).to_ascii_lowercase();
    path.contains("/.git/")
        || path.ends_with("/.git")
        || path.contains("/.env")
        || path.ends_with("phpinfo.php")
        || path.ends_with("server-status")
        || path.ends_with(".sql")
        || path.ends_with(".bak")
        || path.ends_with(".backup")
        || path.ends_with("backup.zip")
        || path.ends_with("config.yml")
        || path.ends_with("config.yaml")
}

fn percent_decode_path(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = hex_nibble(bytes[index + 1]);
            let low = hex_nibble(bytes[index + 2]);
            if let (Some(high), Some(low)) = (high, low) {
                output.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
