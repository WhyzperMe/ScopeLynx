use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::fs;

use crate::{
    cli::{FailOn, ReportFormat, ScanArgs},
    error::{Result, ScannerError, io_error},
    target::Target,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScopeMode {
    SameOrigin,
    SameHost,
    Subdomains,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    pub user_agent: String,
    pub scope_mode: ScopeMode,
    pub allow_cross_scheme: bool,
    #[serde(default)]
    pub allowed_ports: Vec<u16>,
    pub allow_private_networks: bool,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub max_retries: usize,
    pub retry_backoff_ms: u64,
    pub concurrency: usize,
    pub requests_per_second: u32,
    pub timeout_seconds: u64,
    pub connect_timeout_seconds: u64,
    pub max_depth: usize,
    pub max_requests: usize,
    pub max_discovered_urls: usize,
    pub max_candidates_per_response: usize,
    pub max_body_bytes: usize,
    pub max_header_bytes: usize,
    pub max_wordlist_bytes: usize,
    pub max_wordlist_entries: usize,
    pub max_cached_hosts: usize,
    pub max_dns_addresses: usize,
    pub max_errors: usize,
    pub max_findings: usize,
    pub discover_robots: bool,
    pub discover_sitemap: bool,
    pub discover_html: bool,
    pub discover_javascript: bool,
    pub allow_wordlists: bool,
    pub sensitive_paths: bool,
}

impl Profile {
    pub async fn load(path: &Path) -> Result<Self> {
        let metadata = fs::metadata(path).await.map_err(|error| io_error(path, error))?;
        if metadata.len() > 256 * 1024 {
            return Err(ScannerError::Limit(format!(
                "profile exceeds 256 KiB: {}",
                path.display()
            )));
        }

        let raw = fs::read_to_string(path).await.map_err(|error| io_error(path, error))?;
        let profile: Self = toml::from_str(&raw)?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() || self.name.len() > 80 {
            return Err(ScannerError::InvalidConfig(
                "profile name must contain 1 to 80 characters".into(),
            ));
        }
        if self.user_agent.trim().is_empty() || self.user_agent.len() > 256 {
            return Err(ScannerError::InvalidConfig(
                "user_agent must contain 1 to 256 characters".into(),
            ));
        }
        validate_range("concurrency", self.concurrency, 1, 64)?;
        validate_range("requests_per_second", self.requests_per_second as usize, 1, 100)?;
        validate_range("timeout_seconds", self.timeout_seconds as usize, 1, 120)?;
        validate_range("connect_timeout_seconds", self.connect_timeout_seconds as usize, 1, 60)?;
        validate_range("max_redirects", self.max_redirects, 0, 20)?;
        validate_range("max_retries", self.max_retries, 0, 5)?;
        validate_range("retry_backoff_ms", self.retry_backoff_ms as usize, 10, 30_000)?;
        validate_range("max_depth", self.max_depth, 0, 10)?;
        validate_range("max_requests", self.max_requests, 1, 100_000)?;
        validate_range(
            "max_discovered_urls",
            self.max_discovered_urls,
            self.max_requests,
            400_000,
        )?;
        validate_range("max_candidates_per_response", self.max_candidates_per_response, 1, 20_000)?;
        validate_range("max_body_bytes", self.max_body_bytes, 1_024, 16 * 1024 * 1024)?;
        validate_range("max_header_bytes", self.max_header_bytes, 1_024, 256 * 1024)?;
        validate_range("max_wordlist_bytes", self.max_wordlist_bytes, 1_024, 128 * 1024 * 1024)?;
        validate_range("max_wordlist_entries", self.max_wordlist_entries, 1, 2_000_000)?;
        validate_range("max_cached_hosts", self.max_cached_hosts, 1, 10_000)?;
        validate_range("max_dns_addresses", self.max_dns_addresses, 1, 64)?;
        validate_range("max_errors", self.max_errors, 1, 100_000)?;
        validate_range("max_findings", self.max_findings, 1, 100_000)?;

        if self.connect_timeout_seconds > self.timeout_seconds {
            return Err(ScannerError::InvalidConfig(
                "connect_timeout_seconds must not exceed timeout_seconds".into(),
            ));
        }
        if matches!(self.scope_mode, ScopeMode::SameOrigin)
            && (self.allow_cross_scheme || !self.allowed_ports.is_empty())
        {
            return Err(ScannerError::InvalidConfig(
                "same_origin scope cannot set allow_cross_scheme or allowed_ports".into(),
            ));
        }
        if self.allowed_ports.contains(&0) {
            return Err(ScannerError::InvalidConfig(
                "allowed_ports must not contain port 0".into(),
            ));
        }
        let unique_ports = self.allowed_ports.iter().copied().collect::<BTreeSet<_>>();
        if unique_ports.len() != self.allowed_ports.len() {
            return Err(ScannerError::InvalidConfig("allowed_ports contains duplicates".into()));
        }

        let in_flight_body_budget = self
            .max_body_bytes
            .checked_mul(self.concurrency)
            .ok_or_else(|| ScannerError::InvalidConfig("body memory budget overflow".into()))?;
        if in_flight_body_budget > 128 * 1024 * 1024 {
            return Err(ScannerError::InvalidConfig(
                "concurrency × max_body_bytes must not exceed 128 MiB".into(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub target: Target,
    pub profile: Profile,
    pub wordlists: Vec<PathBuf>,
    pub output_dir: PathBuf,
    pub authorized: bool,
    pub store_bodies: bool,
    pub scope_hosts: Vec<String>,
    pub formats: Vec<ReportFormat>,
    pub dry_run: bool,
    pub fail_on: Option<FailOn>,
    pub progress: bool,
}

impl ScanConfig {
    pub async fn from_args(args: ScanArgs) -> Result<Self> {
        let target = Target::parse(&args.target)?;
        if crate::discovery::is_potentially_destructive(&target.base_url) {
            return Err(ScannerError::InvalidConfig(
                "target URL appears to perform a destructive or session-changing GET action".into(),
            ));
        }
        let mut profile = Profile::load(&args.profile).await?;

        if let Some(value) = args.max_requests {
            profile.max_requests = value;
        }
        if let Some(value) = args.max_depth {
            profile.max_depth = value;
        }
        if let Some(value) = args.max_urls {
            profile.max_discovered_urls = value;
        }
        if let Some(value) = args.max_findings {
            profile.max_findings = value;
        }
        if let Some(value) = args.concurrency {
            profile.concurrency = value;
        }
        if let Some(value) = args.rate {
            profile.requests_per_second = value;
        }
        if let Some(value) = args.timeout {
            profile.timeout_seconds = value;
        }
        if let Some(value) = args.max_body_size {
            profile.max_body_bytes = value;
        }
        if args.allow_subdomains {
            profile.scope_mode = ScopeMode::Subdomains;
        }
        if args.allow_private {
            profile.allow_private_networks = true;
        }
        profile.validate()?;

        let scope_hosts = normalize_scope_hosts(&args.scope_hosts)?;

        let expanded_scope = !matches!(profile.scope_mode, ScopeMode::SameOrigin)
            || profile.allow_cross_scheme
            || !profile.allowed_ports.is_empty();
        if (profile.sensitive_paths
            || profile.allow_private_networks
            || expanded_scope
            || args.store_bodies
            || !scope_hosts.is_empty())
            && !args.authorized
        {
            return Err(ScannerError::Authorization(
                "this configuration requires explicit --authorized acknowledgement".into(),
            ));
        }

        if !args.wordlists.is_empty() && !profile.allow_wordlists {
            return Err(ScannerError::InvalidConfig(format!(
                "profile '{}' does not permit wordlist discovery",
                profile.name
            )));
        }
        if target.host_is_ip() && matches!(profile.scope_mode, ScopeMode::Subdomains) {
            return Err(ScannerError::InvalidConfig(
                "subdomain scope cannot be used with an IP-address target".into(),
            ));
        }

        for path in &args.wordlists {
            let metadata = fs::metadata(path).await.map_err(|error| io_error(path, error))?;
            if !metadata.is_file() {
                return Err(ScannerError::InvalidConfig(format!(
                    "wordlist is not a regular file: {}",
                    path.display()
                )));
            }
            if metadata.len() > profile.max_wordlist_bytes as u64 {
                return Err(ScannerError::Limit(format!(
                    "wordlist exceeds configured size limit: {}",
                    path.display()
                )));
            }
        }

        Ok(Self {
            target,
            profile,
            wordlists: args.wordlists,
            output_dir: args.output,
            authorized: args.authorized,
            store_bodies: args.store_bodies,
            scope_hosts,
            formats: args.formats,
            dry_run: args.dry_run,
            fail_on: args.fail_on,
            progress: !args.no_progress,
        })
    }

    pub fn fingerprint(&self) -> Result<String> {
        let serialized = serde_json::to_vec(&(
            self.target.redacted(),
            &self.profile,
            &self.scope_hosts,
            self.store_bodies,
        ))
        .map_err(|error| ScannerError::InvalidConfig(format!("fingerprint failed: {error}")))?;
        Ok(hex::encode(Sha256::digest(serialized)))
    }

    #[must_use]
    pub fn dry_run_summary(&self) -> String {
        format!(
            "Dry run (no network)\nTarget: {}\nProfile: {}\nScope: {:?}\nAdditional hosts: {}\nPrivate networks: {}\nWire-request budget: {}\nURL limit: {}\nFinding limit: {}\nDepth: {}\nConcurrency: {}\nRate/origin: {}/s\nBody limit: {} bytes\nLive progress: {}\nOutput root: {}\nWordlists: {}",
            self.target.redacted(),
            self.profile.name,
            self.profile.scope_mode,
            if self.scope_hosts.is_empty() {
                "<none>".to_string()
            } else {
                self.scope_hosts.join(", ")
            },
            self.profile.allow_private_networks,
            self.profile.max_requests,
            self.profile.max_discovered_urls,
            self.profile.max_findings,
            self.profile.max_depth,
            self.profile.concurrency,
            self.profile.requests_per_second,
            self.profile.max_body_bytes,
            self.progress,
            self.output_dir.display(),
            self.wordlists.len(),
        )
    }
}

fn normalize_scope_hosts(values: &[String]) -> Result<Vec<String>> {
    let mut hosts = BTreeSet::new();
    for raw in values {
        let trimmed = raw.trim().trim_end_matches('.');
        if trimmed.is_empty()
            || trimmed.contains('/')
            || trimmed.contains('?')
            || trimmed.contains('#')
            || trimmed.contains('@')
        {
            return Err(ScannerError::InvalidConfig(format!("invalid --scope host: {raw}")));
        }
        let candidate = format!("http://{trimmed}/");
        let url = url::Url::parse(&candidate)?;
        let host = match url
            .host()
            .ok_or_else(|| ScannerError::InvalidConfig(format!("invalid --scope host: {raw}")))?
        {
            url::Host::Domain(domain) => domain.trim_end_matches('.').to_ascii_lowercase(),
            url::Host::Ipv4(address) => address.to_string(),
            url::Host::Ipv6(address) => address.to_string(),
        };
        hosts.insert(host);
    }
    Ok(hosts.into_iter().collect())
}

fn validate_range(name: &str, value: usize, minimum: usize, maximum: usize) -> Result<()> {
    if !(minimum..=maximum).contains(&value) {
        return Err(ScannerError::InvalidConfig(format!(
            "{name} must be between {minimum} and {maximum}"
        )));
    }
    Ok(())
}
