use url::Url;

use crate::model::DiscoverySource;

use super::{DiscoveredUrl, resolve_http_url};

#[must_use]
pub fn discover(base: &Url, body: &str, limit: usize) -> Vec<DiscoveredUrl> {
    let mut output = Vec::new();
    for raw_line in body.lines() {
        if output.len() >= limit {
            break;
        }
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        let Some((directive, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() || value == "*" {
            continue;
        }

        let (source, priority, relation) = if directive.eq_ignore_ascii_case("sitemap") {
            (DiscoverySource::Sitemap, 245, "robots-sitemap")
        } else if directive.eq_ignore_ascii_case("allow") {
            (DiscoverySource::Robots, 235, "robots-rule")
        } else {
            continue;
        };

        if source == DiscoverySource::Robots && (value.contains('*') || value.ends_with('$')) {
            continue;
        }

        if let Some(url) = resolve_http_url(base, value) {
            output.push(DiscoveredUrl { url, source, priority, relation });
        }
    }
    output
}
