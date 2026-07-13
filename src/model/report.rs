use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::{Profile, ScopeMode};

use super::{DiscoverySource, Finding, Observation};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStats {
    pub scheduled_tasks: usize,
    pub wire_requests: usize,
    #[serde(default)]
    pub status_counts: BTreeMap<u16, usize>,
    pub unique_urls: usize,
    pub queued_peak: usize,
    pub successful: usize,
    pub redirects: usize,
    #[serde(default)]
    pub not_modified: usize,
    pub authentication_required: usize,
    pub forbidden: usize,
    pub not_found: usize,
    pub soft_404: usize,
    pub rate_limited: usize,
    pub server_errors: usize,
    pub failed: usize,
    pub truncated_bodies: usize,
    pub captured_body_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LimitState {
    pub request_budget_exhausted: bool,
    pub discovery_limit_reached: bool,
    pub error_limit_reached: bool,
    #[serde(default)]
    pub finding_limit_reached: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanErrorRecord {
    pub stage: String,
    pub location: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiscoveredResource {
    pub url: String,
    pub source: DiscoverySource,
    pub depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySnapshot {
    pub scope_mode: ScopeMode,
    pub allow_cross_scheme: bool,
    pub allowed_ports: Vec<u16>,
    pub allow_private_networks: bool,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub max_retries: usize,
    pub concurrency: usize,
    pub requests_per_second: u32,
    pub max_depth: usize,
    pub max_requests: usize,
    pub max_discovered_urls: usize,
    pub max_body_bytes: usize,
    #[serde(default = "default_max_findings")]
    pub max_findings: usize,
    pub sensitive_paths: bool,
    pub store_bodies: bool,
}

impl PolicySnapshot {
    #[must_use]
    pub fn from_profile(profile: &Profile, store_bodies: bool) -> Self {
        Self {
            scope_mode: profile.scope_mode,
            allow_cross_scheme: profile.allow_cross_scheme,
            allowed_ports: profile.allowed_ports.clone(),
            allow_private_networks: profile.allow_private_networks,
            follow_redirects: profile.follow_redirects,
            max_redirects: profile.max_redirects,
            max_retries: profile.max_retries,
            concurrency: profile.concurrency,
            requests_per_second: profile.requests_per_second,
            max_depth: profile.max_depth,
            max_requests: profile.max_requests,
            max_discovered_urls: profile.max_discovered_urls,
            max_body_bytes: profile.max_body_bytes,
            max_findings: profile.max_findings,
            sensitive_paths: profile.sensitive_paths,
            store_bodies,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub scanner_version: String,
    #[serde(default)]
    pub scan_id: String,
    #[serde(default)]
    pub config_fingerprint: String,
    pub target: String,
    pub profile: String,
    pub policy: PolicySnapshot,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub stats: ScanStats,
    pub limits: LimitState,
    pub observations: Vec<Observation>,
    pub findings: Vec<Finding>,
    pub discovered_resources: Vec<DiscoveredResource>,
    pub errors: Vec<ScanErrorRecord>,
    #[serde(default = "default_true")]
    pub complete: bool,
    #[serde(default)]
    pub abort_reason: Option<String>,
}

const fn default_true() -> bool {
    true
}

const fn default_max_findings() -> usize {
    1_000
}
