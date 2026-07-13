use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, ScannerError>;

#[derive(Debug, Error)]
pub enum ScannerError {
    #[error("I/O error for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid URL: {0}")]
    Url(#[from] url::ParseError),

    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("invalid TOML profile: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("JSON processing failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("scope rejected target: {0}")]
    Scope(String),

    #[error("authorization required: {0}")]
    Authorization(String),

    #[error("DNS resolution failed: {0}")]
    Dns(String),

    #[error("connection failed: {0}")]
    Connect(String),

    #[error("request timed out: {0}")]
    Timeout(String),

    #[error("redirect policy rejected response: {0}")]
    Redirect(String),

    #[error("network request budget exhausted")]
    RequestBudgetExhausted,

    #[error("resource limit exceeded: {0}")]
    Limit(String),

    #[error("parser error: {0}")]
    Parse(String),

    #[error("logging initialization failed: {0}")]
    Logging(String),

    #[error("incompatible schema: {0}")]
    IncompatibleSchema(String),

    #[error("finding severity threshold reached ({0} matching findings)")]
    FindingsThreshold(usize),
}

impl ScannerError {
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::InvalidConfig(_) | Self::Url(_) | Self::Toml(_) => 2,
            Self::Scope(_) | Self::Authorization(_) => 3,
            Self::RequestBudgetExhausted
            | Self::Limit(_)
            | Self::Dns(_)
            | Self::Connect(_)
            | Self::Timeout(_)
            | Self::Redirect(_) => 4,
            Self::IncompatibleSchema(_) => 6,
            Self::FindingsThreshold(_) => 5,
            _ => 1,
        }
    }
}

pub fn io_error(path: impl Into<PathBuf>, source: std::io::Error) -> ScannerError {
    ScannerError::Io { path: path.into(), source }
}
