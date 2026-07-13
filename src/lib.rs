//! ScopeLynx library.
//!
//! The crate is intentionally split into scope enforcement, HTTP transport,
//! discovery, analysis, reporting, and storage layers. Network access is only
//! performed by the HTTP module after scope validation.

pub mod analyzers;
pub mod cli;
pub mod config;
pub mod discovery;
pub mod engine;
pub mod error;
pub mod http;
pub mod model;
pub mod redaction;
pub mod report;
pub mod scope;
pub mod storage;
pub mod target;

use clap::CommandFactory;
use cli::{Cli, Command};
use error::Result;

/// Executes one CLI command.
pub async fn run(cli: Cli) -> Result<()> {
    cli.init_logging()?;
    let quiet = cli.quiet;

    match cli.command {
        Command::Scan(mut args) => {
            if quiet {
                args.no_progress = true;
            }
            let config = config::ScanConfig::from_args(args).await?;
            if config.dry_run {
                if !quiet {
                    println!("{}", config.dry_run_summary());
                }
                return Ok(());
            }
            let formats = config.formats.clone();
            let fail_on = config.fail_on;
            let outcome = engine::run_scan(config).await?;
            report::write_all(&outcome.report, &outcome.run_directory, &formats).await?;
            if !quiet {
                report::console::print_summary(&outcome.report);
                println!("Output:          {}", outcome.run_directory.display());
            }
            if let Some(threshold) = fail_on {
                let minimum = match threshold {
                    cli::FailOn::Low => model::Severity::Low,
                    cli::FailOn::Medium => model::Severity::Medium,
                    cli::FailOn::High => model::Severity::High,
                    cli::FailOn::Critical => model::Severity::Critical,
                };
                let count = outcome
                    .report
                    .findings
                    .iter()
                    .filter(|finding| finding.severity >= minimum)
                    .count();
                if count > 0 {
                    return Err(error::ScannerError::FindingsThreshold(count));
                }
            }
            if outcome.report.observations.is_empty()
                && outcome.report.limits.request_budget_exhausted
            {
                return Err(error::ScannerError::RequestBudgetExhausted);
            }
            if outcome.report.observations.is_empty() && outcome.report.stats.failed > 0 {
                return Err(error::ScannerError::Connect(
                    "scan produced no usable HTTP response; review report errors".into(),
                ));
            }
        }
        Command::ValidateProfile(args) => {
            let profile = config::Profile::load(&args.profile).await?;
            profile.validate()?;
            if !quiet {
                println!("profile '{}' is valid", profile.name);
            }
        }
        Command::Diff(args) => {
            let previous = report::json::read(&args.previous).await?;
            let current = report::json::read(&args.current).await?;
            let diff = report::diff::compare(&previous, &current);
            if let Some(path) = args.output {
                report::diff::write(&diff, &path).await?;
                if !quiet {
                    println!("diff written to {}", path.display());
                }
            } else if !quiet {
                println!("{}", report::diff::render_text(&diff));
            }
        }
        Command::Inspect(args) => {
            let report = report::json::read(&args.report).await?;
            if !quiet {
                report::console::print_summary(&report);
            }
        }
        Command::Completion(args) => {
            let mut command = cli::Cli::command();
            let name = command.get_name().to_string();
            clap_complete::generate(args.shell, &mut command, name, &mut std::io::stdout());
        }
    }

    Ok(())
}
