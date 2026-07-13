use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::error::{Result, ScannerError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub base_url: Url,
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl Target {
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.len() > 8_192 {
            return Err(ScannerError::InvalidConfig("target URL exceeds 8192 bytes".into()));
        }

        let mut url = Url::parse(raw)?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ScannerError::InvalidConfig("target scheme must be http or https".into()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ScannerError::InvalidConfig(
                "embedded URL credentials are not allowed".into(),
            ));
        }
        url.set_fragment(None);

        let host = match url
            .host()
            .ok_or_else(|| ScannerError::InvalidConfig("target URL requires a host".into()))?
        {
            Host::Domain(domain) if domain.ends_with('.') => {
                return Err(ScannerError::InvalidConfig(
                    "trailing-dot hostnames are rejected to preserve DNS pinning".into(),
                ));
            }
            Host::Domain(domain) => domain.to_ascii_lowercase(),
            Host::Ipv4(address) => address.to_string(),
            Host::Ipv6(address) => address.to_string(),
        };
        if host.is_empty() {
            return Err(ScannerError::InvalidConfig("target host is empty".into()));
        }

        let port = url
            .port_or_known_default()
            .ok_or_else(|| ScannerError::InvalidConfig("unable to determine target port".into()))?;

        Ok(Self { scheme: url.scheme().to_string(), base_url: url, host, port })
    }

    #[must_use]
    pub fn origin_root(&self) -> Url {
        let mut root = self.base_url.clone();
        root.set_path("/");
        root.set_query(None);
        root.set_fragment(None);
        root
    }

    #[must_use]
    pub fn redacted(&self) -> String {
        crate::scope::redact_url(&self.base_url)
    }

    #[must_use]
    pub fn host_is_ip(&self) -> bool {
        self.host.parse::<IpAddr>().is_ok()
    }
}
