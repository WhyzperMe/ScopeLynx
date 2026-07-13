use std::path::Path;

use tokio::fs;

use crate::{
    error::{Result, ScannerError, io_error},
    model::ScanReport,
    storage::filesystem,
};

pub async fn write(report: &ScanReport, path: &Path) -> Result<()> {
    let data = serde_json::to_vec_pretty(report)?;
    filesystem::write_atomic(path, &data).await
}

pub async fn read(path: &Path) -> Result<ScanReport> {
    let metadata = fs::metadata(path).await.map_err(|error| io_error(path, error))?;
    if metadata.len() > 128 * 1024 * 1024 {
        return Err(ScannerError::Limit("report exceeds 128 MiB".into()));
    }
    let data = fs::read(path).await.map_err(|error| io_error(path, error))?;
    let report: ScanReport = serde_json::from_slice(&data)?;
    if !matches!(report.schema_version, 3 | 4) {
        return Err(ScannerError::IncompatibleSchema(format!(
            "expected report schema 3 or 4, found {}",
            report.schema_version
        )));
    }
    Ok(report)
}
