use url::Url;

use crate::{
    error::{Result, ScannerError},
    model::DiscoverySource,
};

use super::{DiscoveredUrl, resolve_http_url};

pub fn discover(base: &Url, body: &str, limit: usize) -> Result<Vec<DiscoveredUrl>> {
    if body.len() > 1024 * 1024 {
        return Err(ScannerError::Limit("web manifest exceeds 1 MiB parser limit".into()));
    }
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|error| ScannerError::Parse(error.to_string()))?;
    let mut output = Vec::new();
    collect(&value, base, limit, &mut output, 0);
    Ok(output)
}

fn collect(
    value: &serde_json::Value,
    base: &Url,
    limit: usize,
    output: &mut Vec<DiscoveredUrl>,
    depth: usize,
) {
    if output.len() >= limit || depth > 12 {
        return;
    }
    match value {
        serde_json::Value::Object(values) => {
            for (key, nested) in values.iter().take(256) {
                if matches!(key.as_str(), "start_url" | "scope" | "src" | "url" | "action")
                    && let Some(raw) = nested.as_str()
                    && let Some(url) = resolve_http_url(base, raw)
                {
                    output.push(DiscoveredUrl {
                        url,
                        source: DiscoverySource::HtmlAsset,
                        priority: 110,
                        relation: "manifest-resource",
                    });
                }
                collect(nested, base, limit, output, depth + 1);
            }
        }
        serde_json::Value::Array(values) => {
            for nested in values.iter().take(256) {
                collect(nested, base, limit, output, depth + 1);
            }
        }
        _ => {}
    }
}
