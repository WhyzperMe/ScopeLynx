use std::{collections::BTreeMap, sync::OnceLock};

use scraper::{Html, Selector};
use url::Url;

use crate::model::DiscoverySource;

use super::{DiscoveredUrl, resolve_http_url};

#[must_use]
pub fn discover(base: &Url, body: &str, limit: usize) -> Vec<DiscoveredUrl> {
    let document = Html::parse_document(body);
    let mut output = Vec::new();

    collect_attribute(
        &document,
        base,
        "a[href], area[href]",
        "href",
        DiscoverySource::HtmlLink,
        180,
        "link",
        limit,
        &mut output,
    );
    collect_attribute(
        &document,
        base,
        "script[src], link[href], iframe[src], frame[src]",
        "src",
        DiscoverySource::HtmlAsset,
        170,
        "asset",
        limit,
        &mut output,
    );
    collect_link_hrefs(&document, base, limit, &mut output);
    collect_attribute(
        &document,
        base,
        "img[src], source[src], video[src], audio[src], embed[src]",
        "src",
        DiscoverySource::HtmlAsset,
        90,
        "media",
        limit,
        &mut output,
    );
    collect_srcset(&document, base, limit, &mut output);
    collect_get_forms(&document, base, limit, &mut output);
    collect_meta_refresh(&document, base, limit, &mut output);
    collect_meta_urls(&document, base, limit, &mut output);
    collect_json_ld(&document, base, limit, &mut output);

    output.truncate(limit);
    output
}

#[allow(clippy::too_many_arguments)]
fn collect_attribute(
    document: &Html,
    base: &Url,
    selector: &str,
    attribute: &str,
    source: DiscoverySource,
    priority: u8,
    relation: &'static str,
    limit: usize,
    output: &mut Vec<DiscoveredUrl>,
) {
    let Some(selector) = compiled_selector(selector) else {
        return;
    };
    for element in document.select(selector) {
        if output.len() >= limit {
            return;
        }
        let Some(raw) = element.value().attr(attribute) else {
            continue;
        };
        if let Some(url) = resolve_http_url(base, raw) {
            output.push(DiscoveredUrl { url, source, priority, relation });
        }
    }
}

fn collect_link_hrefs(document: &Html, base: &Url, limit: usize, output: &mut Vec<DiscoveredUrl>) {
    let Some(selector) = compiled_selector("link[href]") else {
        return;
    };
    for element in document.select(selector) {
        if output.len() >= limit {
            return;
        }
        let Some(raw) = element.value().attr("href") else {
            continue;
        };
        let relation = element.value().attr("rel").unwrap_or("link");
        let priority = if relation
            .split_ascii_whitespace()
            .any(|value| matches!(value.to_ascii_lowercase().as_str(), "manifest" | "canonical"))
        {
            175
        } else {
            120
        };
        if let Some(url) = resolve_http_url(base, raw) {
            output.push(DiscoveredUrl {
                url,
                source: DiscoverySource::HtmlAsset,
                priority,
                relation: "link-resource",
            });
        }
    }
}

fn collect_srcset(document: &Html, base: &Url, limit: usize, output: &mut Vec<DiscoveredUrl>) {
    let Some(selector) = compiled_selector("[srcset]") else {
        return;
    };
    for element in document.select(selector) {
        let Some(srcset) = element.value().attr("srcset") else {
            continue;
        };
        for candidate in srcset.split(',') {
            if output.len() >= limit {
                return;
            }
            let raw = candidate.split_ascii_whitespace().next().unwrap_or_default();
            if let Some(url) = resolve_http_url(base, raw) {
                output.push(DiscoveredUrl {
                    url,
                    source: DiscoverySource::HtmlAsset,
                    priority: 80,
                    relation: "srcset",
                });
            }
        }
    }
}

fn collect_get_forms(document: &Html, base: &Url, limit: usize, output: &mut Vec<DiscoveredUrl>) {
    let Some(selector) = compiled_selector("form[action]") else {
        return;
    };
    for form in document.select(selector) {
        if output.len() >= limit {
            return;
        }
        let method = form.value().attr("method").unwrap_or("get");
        if !method.eq_ignore_ascii_case("get") {
            continue;
        }
        let Some(action) = form.value().attr("action") else {
            continue;
        };
        if let Some(url) = resolve_http_url(base, action) {
            output.push(DiscoveredUrl {
                url,
                source: DiscoverySource::HtmlForm,
                priority: 190,
                relation: "get-form-action",
            });
        }
    }
}

fn collect_meta_refresh(
    document: &Html,
    base: &Url,
    limit: usize,
    output: &mut Vec<DiscoveredUrl>,
) {
    if output.len() >= limit {
        return;
    }
    let Some(selector) = compiled_selector("meta[http-equiv][content]") else {
        return;
    };
    for element in document.select(selector) {
        if output.len() >= limit {
            return;
        }
        let Some(equivalent) = element.value().attr("http-equiv") else {
            continue;
        };
        if !equivalent.eq_ignore_ascii_case("refresh") {
            continue;
        }
        let Some(content) = element.value().attr("content") else {
            continue;
        };
        let raw = content.split(';').find_map(parse_refresh_url);
        if let Some(url) = raw.and_then(|value| resolve_http_url(base, value)) {
            output.push(DiscoveredUrl {
                url,
                source: DiscoverySource::HtmlLink,
                priority: 200,
                relation: "meta-refresh",
            });
        }
    }
}

fn parse_refresh_url(part: &str) -> Option<&str> {
    let (name, value) = part.trim().split_once('=')?;
    name.trim()
        .eq_ignore_ascii_case("url")
        .then(|| value.trim().trim_matches(|character| matches!(character, '\'' | '"')))
}

fn collect_meta_urls(document: &Html, base: &Url, limit: usize, output: &mut Vec<DiscoveredUrl>) {
    let Some(selector) = compiled_selector("meta[property][content], meta[name][content]") else {
        return;
    };
    for element in document.select(selector) {
        if output.len() >= limit {
            return;
        }
        let key = element
            .value()
            .attr("property")
            .or_else(|| element.value().attr("name"))
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !matches!(
            key.as_str(),
            "og:url" | "og:image" | "og:video" | "twitter:image" | "twitter:player"
        ) {
            continue;
        }
        let Some(content) = element.value().attr("content") else {
            continue;
        };
        if let Some(url) = resolve_http_url(base, content) {
            output.push(DiscoveredUrl {
                url,
                source: DiscoverySource::HtmlAsset,
                priority: 120,
                relation: "social-meta-resource",
            });
        }
    }
}

fn collect_json_ld(document: &Html, base: &Url, limit: usize, output: &mut Vec<DiscoveredUrl>) {
    let Some(selector) = compiled_selector("script[type='application/ld+json']") else {
        return;
    };
    for script in document.select(selector).take(32) {
        if output.len() >= limit {
            return;
        }
        let raw = script.text().collect::<String>();
        if raw.len() > 256 * 1024 {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
            continue;
        };
        collect_json_urls(&value, base, limit, output, 0);
    }
}

fn compiled_selector(query: &str) -> Option<&'static Selector> {
    static SELECTORS: OnceLock<BTreeMap<&'static str, Selector>> = OnceLock::new();
    SELECTORS
        .get_or_init(|| {
            [
                "a[href], area[href]",
                "script[src], link[href], iframe[src], frame[src]",
                "img[src], source[src], video[src], audio[src], embed[src]",
                "link[href]",
                "[srcset]",
                "form[action]",
                "meta[http-equiv][content]",
                "meta[property][content], meta[name][content]",
                "script[type='application/ld+json']",
            ]
            .into_iter()
            .filter_map(|query| Selector::parse(query).ok().map(|selector| (query, selector)))
            .collect()
        })
        .get(query)
}

fn collect_json_urls(
    value: &serde_json::Value,
    base: &Url,
    limit: usize,
    output: &mut Vec<DiscoveredUrl>,
    depth: usize,
) {
    if output.len() >= limit || depth > 16 {
        return;
    }
    match value {
        serde_json::Value::Object(values) => {
            for (key, nested) in values.iter().take(256) {
                if output.len() >= limit {
                    return;
                }
                if matches!(key.as_str(), "url" | "@id" | "contentUrl" | "embedUrl" | "sameAs") {
                    if let Some(raw) = nested.as_str() {
                        if let Some(url) = resolve_http_url(base, raw) {
                            output.push(DiscoveredUrl {
                                url,
                                source: DiscoverySource::HtmlLink,
                                priority: 110,
                                relation: "json-ld-url",
                            });
                        }
                    }
                }
                collect_json_urls(nested, base, limit, output, depth + 1);
            }
        }
        serde_json::Value::Array(values) => {
            for nested in values.iter().take(256) {
                collect_json_urls(nested, base, limit, output, depth + 1);
            }
        }
        _ => {}
    }
}
