use roxmltree::Document;
use url::Url;

use crate::{
    error::{Result, ScannerError},
    model::DiscoverySource,
};

use super::{DiscoveredUrl, resolve_http_url};

pub fn discover(base: &Url, body: &str, limit: usize) -> Result<Vec<DiscoveredUrl>> {
    if body.len() > 16 * 1024 * 1024 {
        return Err(ScannerError::Limit("sitemap XML exceeds 16 MiB parser limit".into()));
    }
    let document = Document::parse(body).map_err(|error| ScannerError::Parse(error.to_string()))?;
    let root = document.root_element().tag_name().name().to_ascii_lowercase();
    if !matches!(root.as_str(), "urlset" | "sitemapindex") {
        return Ok(Vec::new());
    }

    let mut output = Vec::new();
    for node in document.descendants().filter(|node| node.has_tag_name("loc")) {
        if output.len() >= limit {
            break;
        }
        let Some(value) = node.text().map(str::trim) else {
            continue;
        };
        if let Some(url) = resolve_http_url(base, value) {
            output.push(DiscoveredUrl {
                url,
                source: DiscoverySource::Sitemap,
                priority: if root == "sitemapindex" { 245 } else { 230 },
                relation: if root == "sitemapindex" { "sitemap-index" } else { "sitemap-url" },
            });
        }
    }
    Ok(output)
}
