use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    Html,
    JavaScript,
    Css,
    Json,
    Xml,
    Sitemap,
    Rss,
    Atom,
    PlainText,
    Pdf,
    OfficeDocument,
    Image,
    WebManifest,
    SourceMap,
    Binary,
    #[default]
    Unknown,
}

impl ContentKind {
    #[must_use]
    pub const fn is_text(self) -> bool {
        matches!(
            self,
            Self::Html
                | Self::JavaScript
                | Self::Css
                | Self::Json
                | Self::Xml
                | Self::Sitemap
                | Self::Rss
                | Self::Atom
                | Self::PlainText
                | Self::WebManifest
                | Self::SourceMap
        )
    }

    #[must_use]
    pub const fn is_storable(self) -> bool {
        !matches!(self, Self::Binary | Self::Unknown)
    }
}

/// Classifies only bounded response data. Callers pass at most the captured body.
#[must_use]
pub fn classify(content_type: Option<&str>, path: &str, body: &[u8]) -> ContentKind {
    let media_type = content_type
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let path = path.to_ascii_lowercase();
    let prefix = &body[..body.len().min(4_096)];
    let text = String::from_utf8_lossy(prefix).trim_start().to_ascii_lowercase();

    if prefix.starts_with(b"%PDF-") || media_type == "application/pdf" {
        return ContentKind::Pdf;
    }
    if prefix.starts_with(b"PK\x03\x04")
        && matches!(path.rsplit('.').next(), Some("docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp"))
    {
        return ContentKind::OfficeDocument;
    }
    if prefix.starts_with(&[0xd0, 0xcf, 0x11, 0xe0])
        || media_type.contains("msword")
        || media_type.contains("ms-excel")
        || media_type.contains("ms-powerpoint")
        || media_type.contains("officedocument")
        || media_type.contains("oasis.opendocument")
    {
        return ContentKind::OfficeDocument;
    }
    if media_type.starts_with("image/")
        || prefix.starts_with(b"\x89PNG\r\n\x1a\n")
        || prefix.starts_with(&[0xff, 0xd8, 0xff])
        || prefix.starts_with(b"GIF87a")
        || prefix.starts_with(b"GIF89a")
    {
        return ContentKind::Image;
    }
    if path.ends_with(".map") || media_type == "application/source-map+json" {
        return ContentKind::SourceMap;
    }
    if media_type == "application/manifest+json" || path.ends_with(".webmanifest") {
        return ContentKind::WebManifest;
    }
    if media_type.contains("html")
        || text.starts_with("<!doctype html")
        || text.starts_with("<html")
    {
        return ContentKind::Html;
    }
    if text.contains("<sitemapindex") || text.contains("<urlset") {
        return ContentKind::Sitemap;
    }
    if text.contains("<rss") {
        return ContentKind::Rss;
    }
    if text.contains("<feed") && text.contains("xmlns") {
        return ContentKind::Atom;
    }
    if media_type.contains("javascript") || path.ends_with(".js") || path.ends_with(".mjs") {
        return ContentKind::JavaScript;
    }
    if media_type == "text/css" || path.ends_with(".css") {
        return ContentKind::Css;
    }
    if media_type.contains("json") || text.starts_with('{') || text.starts_with('[') {
        return ContentKind::Json;
    }
    if media_type.contains("xml") || text.starts_with("<?xml") {
        return ContentKind::Xml;
    }
    if media_type.starts_with("text/") || looks_like_text(prefix) {
        return ContentKind::PlainText;
    }
    if body.is_empty() { ContentKind::Unknown } else { ContentKind::Binary }
}

fn looks_like_text(prefix: &[u8]) -> bool {
    if std::str::from_utf8(prefix).is_err() {
        return false;
    }
    let controls = prefix
        .iter()
        .filter(|byte| **byte < 0x20 && !matches!(**byte, b'\n' | b'\r' | b'\t'))
        .count();
    controls.saturating_mul(20) <= prefix.len().max(1)
}
