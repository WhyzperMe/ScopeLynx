pub mod console;
pub mod diff;
pub mod json;
pub mod markdown;
pub mod sarif;
pub mod text;

use std::path::Path;

use crate::{cli::ReportFormat, error::Result, model::ScanReport};

pub async fn write_all(
    report: &ScanReport,
    directory: &Path,
    formats: &[ReportFormat],
) -> Result<()> {
    json::write(report, &directory.join("report.json")).await?;
    let all = formats.contains(&ReportFormat::All);
    if all || formats.contains(&ReportFormat::Markdown) {
        markdown::write(report, &directory.join("report.md")).await?;
    }
    if all || formats.contains(&ReportFormat::Text) {
        text::write(report, &directory.join("summary.txt")).await?;
    }
    if all || formats.contains(&ReportFormat::Sarif) {
        sarif::write(report, &directory.join("report.sarif")).await?;
    }
    Ok(())
}
