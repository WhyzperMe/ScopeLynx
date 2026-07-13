use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use tokio::net::lookup_host;
use url::{Host, Url};

use crate::{
    config::{Profile, ScopeMode},
    error::{Result, ScannerError},
    redaction,
    target::Target,
};

#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub host: String,
    pub port: u16,
    pub addresses: Vec<SocketAddr>,
}

#[derive(Debug, Clone)]
pub struct ScopePolicy {
    target: Target,
    mode: ScopeMode,
    allow_cross_scheme: bool,
    allowed_ports: Vec<u16>,
    allow_private_networks: bool,
    max_dns_addresses: usize,
    allowed_hosts: Vec<String>,
    dns_timeout: Duration,
}

impl ScopePolicy {
    #[must_use]
    pub fn new(target: Target, profile: &Profile) -> Self {
        Self {
            target,
            mode: profile.scope_mode,
            allow_cross_scheme: profile.allow_cross_scheme,
            allowed_ports: profile.allowed_ports.clone(),
            allow_private_networks: profile.allow_private_networks,
            max_dns_addresses: profile.max_dns_addresses,
            allowed_hosts: Vec::new(),
            dns_timeout: Duration::from_secs(profile.connect_timeout_seconds),
        }
    }

    #[must_use]
    pub fn with_allowed_hosts(mut self, allowed_hosts: Vec<String>) -> Self {
        self.allowed_hosts = allowed_hosts;
        self
    }

    #[must_use]
    pub fn allows_url(&self, url: &Url) -> bool {
        if url.as_str().len() > 8_192
            || !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return false;
        }

        let Some(host) = normalized_host(url) else {
            return false;
        };
        let Some(port) = url.port_or_known_default() else {
            return false;
        };

        if self.allowed_hosts.binary_search(&host).is_ok() {
            return url.scheme() == self.target.scheme && port == self.target.port;
        }

        match self.mode {
            ScopeMode::SameOrigin => {
                host == self.target.host
                    && url.scheme() == self.target.scheme
                    && port == self.target.port
            }
            ScopeMode::SameHost | ScopeMode::Subdomains => {
                let host_allowed = host == self.target.host
                    || (matches!(self.mode, ScopeMode::Subdomains)
                        && is_strict_subdomain(&host, &self.target.host));
                let scheme_allowed = url.scheme() == self.target.scheme || self.allow_cross_scheme;
                let port_allowed = port == self.target.port || self.allowed_ports.contains(&port);
                host_allowed && scheme_allowed && port_allowed
            }
        }
    }

    pub async fn resolve_network_target(&self, url: &Url) -> Result<ResolvedTarget> {
        if !self.allows_url(url) {
            return Err(ScannerError::Scope(redact_url(url)));
        }

        let host =
            normalized_host(url).ok_or_else(|| ScannerError::Scope("URL has no host".into()))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| ScannerError::Scope("URL has no known port".into()))?;

        let mut addresses = if let Ok(ip) = IpAddr::from_str(&host) {
            vec![SocketAddr::new(ip, port)]
        } else {
            let lookup = tokio::time::timeout(self.dns_timeout, lookup_host((host.as_str(), port)))
                .await
                .map_err(|_| {
                    ScannerError::Dns(format!("resolution timed out for {}", redact_host(&host)))
                })?
                .map_err(|error| ScannerError::Dns(format!("{}: {error}", redact_host(&host))))?;
            let resolved =
                lookup.take(self.max_dns_addresses.saturating_add(1)).collect::<Vec<_>>();
            if resolved.len() > self.max_dns_addresses {
                return Err(ScannerError::Limit(format!(
                    "DNS address limit exceeded for {}",
                    redact_host(&host)
                )));
            }
            resolved
        };

        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(ScannerError::Scope(format!(
                "DNS returned no addresses for {}",
                redact_host(&host)
            )));
        }
        if !self.allow_private_networks
            && addresses.iter().any(|address| is_non_public_ip(address.ip()))
        {
            return Err(ScannerError::Scope(format!(
                "{} resolves to a non-public address",
                redact_host(&host)
            )));
        }

        Ok(ResolvedTarget { host, port, addresses })
    }
}

#[must_use]
pub fn is_non_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_non_public_ipv4(ip),
        IpAddr::V6(ip) => is_non_public_ipv6(ip),
    }
}

fn is_non_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || a == 0
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 198 && matches!(b, 18 | 19))
        || (a == 192 && b == 0)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
}

fn is_non_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_non_public_ipv4(mapped);
    }
    let segments = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || (segments[0] & 0xffc0) == 0xfec0
        || (segments[0] & 0xff00) == 0xff00
        || (segments[0] == 0x0064 && segments[1] == 0xff9b)
        || (segments[0] == 0x0100 && segments[1..4] == [0, 0, 0])
        || (segments[0] == 0x2001 && segments[1] == 0x0002)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || segments[0] == 0x2002
}

#[must_use]
pub fn redact_url(url: &Url) -> String {
    redaction::redact_url(url)
}

#[must_use]
pub fn redacted_url(url: &Url) -> Url {
    redaction::redacted_url(url)
}

fn is_strict_subdomain(host: &str, parent: &str) -> bool {
    host.len() > parent.len()
        && host.ends_with(parent)
        && host.as_bytes().get(host.len() - parent.len() - 1) == Some(&b'.')
}

fn redact_host(host: &str) -> String {
    if host.parse::<IpAddr>().is_ok() { "<ip-address>".into() } else { host.to_string() }
}

fn normalized_host(url: &Url) -> Option<String> {
    match url.host()? {
        Host::Domain(domain) if domain.ends_with('.') => None,
        Host::Domain(domain) => Some(domain.to_ascii_lowercase()),
        Host::Ipv4(address) => Some(address.to_string()),
        Host::Ipv6(address) => Some(address.to_string()),
    }
}
