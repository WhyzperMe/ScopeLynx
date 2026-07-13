use std::sync::OnceLock;

use regex::Regex;
use url::Url;

use crate::model::DiscoverySource;

use super::{DiscoveredUrl, resolve_http_url};

#[must_use]
pub fn discover(base: &Url, body: &str, limit: usize) -> Vec<DiscoveredUrl> {
    let mut output = Vec::new();

    if let Some(regex) = absolute_url_regex() {
        for capture in regex.find_iter(body) {
            if output.len() >= limit {
                break;
            }
            let raw = trim_javascript_suffix(capture.as_str());
            if let Some(url) = resolve_http_url(base, raw) {
                output.push(DiscoveredUrl {
                    url,
                    source: DiscoverySource::JavaScript,
                    priority: endpoint_priority(raw),
                    relation: "javascript-absolute-url",
                });
            }
        }
    }

    if let Some(regex) = quoted_path_regex() {
        for captures in regex.captures_iter(body) {
            if output.len() >= limit {
                break;
            }
            let Some(raw) = captures.name("path").map(|value| value.as_str()) else {
                continue;
            };
            if !looks_useful(raw) {
                continue;
            }
            if let Some(url) = resolve_http_url(base, raw) {
                output.push(DiscoveredUrl {
                    url,
                    source: DiscoverySource::JavaScript,
                    priority: endpoint_priority(raw),
                    relation: "javascript-path",
                });
            }
        }
    }

    output
}

fn absolute_url_regex() -> Option<&'static Regex> {
    static REGEX: OnceLock<Option<Regex>> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r#"(?i)\bhttps?://[^\s\"'<>\\]{3,2048}"#).ok()).as_ref()
}

fn quoted_path_regex() -> Option<&'static Regex> {
    static REGEX: OnceLock<Option<Regex>> = OnceLock::new();
    REGEX
        .get_or_init(|| {
            Regex::new(
                r#"[\"'`](?:\\.|[^\"'`\\]){0,16}(?P<path>/[A-Za-z0-9._~!$&()*+,;=:@%?/#\-]{2,2048})[\"'`]"#,
            )
            .ok()
        })
        .as_ref()
}

fn looks_useful(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("/api/")
        || lower.starts_with("/api")
        || lower.contains("graphql")
        || lower.contains("openapi")
        || lower.contains("swagger")
        || lower.ends_with(".json")
        || lower.ends_with(".map")
        || lower.starts_with("/admin")
        || lower.starts_with("/auth")
        || lower.starts_with("/login")
}

fn endpoint_priority(value: &str) -> u8 {
    let lower = value.to_ascii_lowercase();
    if lower.contains("graphql") || lower.contains("openapi") || lower.contains("swagger") {
        210
    } else if lower.contains("/api") {
        200
    } else if lower.ends_with(".map") {
        150
    } else {
        130
    }
}

fn trim_javascript_suffix(value: &str) -> &str {
    value.trim_end_matches([',', '.', ')', ']', '}'])
}
