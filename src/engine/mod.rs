pub mod canonicalize;
pub mod queue;
pub mod scheduler;
pub mod similarity;
pub mod soft_404;

use std::path::PathBuf;

use crate::{config::ScanConfig, error::Result, model::ScanReport};

#[derive(Debug)]
pub struct ScanOutcome {
    pub report: ScanReport,
    pub run_directory: PathBuf,
}

pub async fn run_scan(config: ScanConfig) -> Result<ScanOutcome> {
    scheduler::run(config).await
}
