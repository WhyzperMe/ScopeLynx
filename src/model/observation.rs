use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::http::content::ContentKind;

pub type HeaderSnapshot = BTreeMap<String, Vec<String>>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    Seed,
    Robots,
    Sitemap,
    HtmlLink,
    HtmlAsset,
    HtmlForm,
    JavaScript,
    Wordlist,
    Redirect,
    Soft404Probe,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ResponseClass {
    Success,
    NotModified,
    Redirect,
    AuthenticationRequired,
    Forbidden,
    NotFound,
    RateLimited,
    ClientError,
    ServerError,
    Other,
}

impl ResponseClass {
    #[must_use]
    pub const fn from_status(status: u16) -> Self {
        match status {
            200..=299 => Self::Success,
            304 => Self::NotModified,
            300..=399 => Self::Redirect,
            401 => Self::AuthenticationRequired,
            403 => Self::Forbidden,
            404 | 410 => Self::NotFound,
            429 => Self::RateLimited,
            400..=499 => Self::ClientError,
            500..=599 => Self::ServerError,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub requested_url: Url,
    pub final_url: Url,
    pub redirect_chain: Vec<Url>,
    pub source: DiscoverySource,
    pub depth: usize,
    pub status: u16,
    pub class: ResponseClass,
    pub content_type: Option<String>,
    #[serde(default)]
    pub content_kind: ContentKind,
    pub headers: HeaderSnapshot,
    pub elapsed_ms: u128,
    pub declared_body_length: Option<u64>,
    pub captured_body_length: usize,
    pub body_sha256: String,
    pub truncated: bool,
    pub soft_404: bool,
    #[serde(default)]
    pub soft_404_score: Option<f32>,
    #[serde(default)]
    pub soft_404_reasons: Vec<String>,
    pub retry_count: usize,
    pub stored_body: Option<String>,
}
