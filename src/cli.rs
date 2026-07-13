use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use tracing_subscriber::EnvFilter;

use crate::error::{Result, ScannerError};

#[derive(Debug, Parser)]
#[command(author, version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Enable verbose scanner logs.
    #[arg(long, global = true, conflicts_with = "quiet")]
    pub verbose: bool,

    /// Suppress non-error console output.
    #[arg(long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    /// Emit structured JSON logs.
    #[arg(long, global = true)]
    pub json_logs: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan one explicitly authorized web target.
    Scan(ScanArgs),
    /// Compare two JSON reports.
    Diff(DiffArgs),
    /// Inspect a report without network activity.
    Inspect(InspectArgs),
    /// Validate a TOML profile without starting a scan.
    ValidateProfile(ValidateProfileArgs),
    /// Generate shell completion output.
    Completion(CompletionArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum ReportFormat {
    All,
    Json,
    Markdown,
    Text,
    Sarif,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum FailOn {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Initial target URL, including http:// or https://.
    pub target: String,

    /// Scanner profile.
    #[arg(long, default_value = "profiles/safe.toml")]
    pub profile: PathBuf,

    /// Additional wordlists. May be supplied more than once.
    #[arg(short = 'w', long = "wordlist")]
    pub wordlists: Vec<PathBuf>,

    /// Explicit additional in-scope host. May be supplied more than once.
    #[arg(long = "scope")]
    pub scope_hosts: Vec<String>,

    /// Expand scope to subdomains of the target host.
    #[arg(long)]
    pub allow_subdomains: bool,

    /// Permit private destinations; also requires --authorized.
    #[arg(long)]
    pub allow_private: bool,

    /// Root output directory.
    #[arg(long, default_value = "output")]
    pub output: PathBuf,

    /// Report views to create. report.json is always written.
    #[arg(long = "format", value_delimiter = ',', default_value = "all")]
    pub formats: Vec<ReportFormat>,

    /// Return exit code 5 when a finding reaches this severity.
    #[arg(long)]
    pub fail_on: Option<FailOn>,

    /// Store bounded, classified response bodies by content hash.
    #[arg(long)]
    pub store_bodies: bool,

    /// Explicit acknowledgement required by sensitive, private, or expanded modes.
    #[arg(long)]
    pub authorized: bool,

    /// Validate and print the effective scan plan without network or output writes.
    #[arg(long)]
    pub dry_run: bool,

    /// Disable periodic live scan progress output.
    #[arg(long)]
    pub no_progress: bool,

    /// Override the profile wire-request budget.
    #[arg(long)]
    pub max_requests: Option<usize>,

    /// Override the maximum discovery depth.
    #[arg(long)]
    pub max_depth: Option<usize>,

    /// Override the discovered URL/queue bound.
    #[arg(long = "max-urls")]
    pub max_urls: Option<usize>,

    /// Override the maximum number of retained findings.
    #[arg(long)]
    pub max_findings: Option<usize>,

    /// Override concurrent scheduler tasks.
    #[arg(long)]
    pub concurrency: Option<usize>,

    /// Override per-origin requests per second.
    #[arg(long)]
    pub rate: Option<u32>,

    /// Override request timeout in seconds.
    #[arg(long)]
    pub timeout: Option<u64>,

    /// Override the decompressed response-body limit in bytes.
    #[arg(long = "max-body-size")]
    pub max_body_size: Option<usize>,
}

#[derive(Debug, Args)]
pub struct ValidateProfileArgs {
    pub profile: PathBuf,
}

#[derive(Debug, Args)]
pub struct DiffArgs {
    pub previous: PathBuf,
    pub current: PathBuf,

    /// Optional JSON output path. Without this flag a text diff is printed.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct InspectArgs {
    pub report: PathBuf,
}

#[derive(Debug, Args)]
pub struct CompletionArgs {
    #[arg(value_enum)]
    pub shell: Shell,
}

impl Cli {
    pub fn init_logging(&self) -> Result<()> {
        let filter = if self.quiet {
            EnvFilter::new("scopelynx=error")
        } else if self.verbose {
            EnvFilter::new("scopelynx=debug")
        } else {
            let environment =
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
            let scanner_info = "scopelynx=info".parse().map_err(|error| {
                ScannerError::Logging(format!("invalid log directive: {error}"))
            })?;
            environment.add_directive(scanner_info)
        };
        let builder = tracing_subscriber::fmt().with_env_filter(filter).with_target(false);

        let result = if self.json_logs { builder.json().try_init() } else { builder.try_init() };
        result.map_err(|error| ScannerError::Logging(error.to_string()))
    }
}
