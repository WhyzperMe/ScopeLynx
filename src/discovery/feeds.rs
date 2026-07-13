use roxmltree::Document;
use url::Url;

use crate::{
    error::{Result, ScannerError},
    model::DiscoverySource,
};

use super::{DiscoveredUrl, resolve_http_url};

pub fn discover(base: &Url, body: &str, limit: usize) -> Result<Vec<DiscoveredUrl>> {
    if body.len() > 4 * 1024 * 1024 {
        return Err(ScannerError::Limit("feed XML exceeds 4 MiB parser limit".into()));
    }
    let document = Document::parse(body).map_err(|error| ScannerError::Parse(error.to_string()))?;
    let root = document.root_element().tag_name().name().to_ascii_lowercase();
    if !matches!(root.as_str(), "rss" | "feed") {
        return Ok(Vec::new());
    }
    let mut output = Vec::new();
    for node in document.descendants().filter(|node| node.has_tag_name("link")) {
        if output.len() >= limit {
            break;
        }
        let raw = node.attribute("href").or_else(|| node.text()).map(str::trim);
        if let Some(url) = raw.and_then(|value| resolve_http_url(base, value)) {
            output.push(DiscoveredUrl {
                url,
                source: DiscoverySource::HtmlLink,
                priority: 120,
                relation: "feed-link",
            });
        }
    }
    Ok(output)
}
