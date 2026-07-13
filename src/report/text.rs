use std::path::Path;

use crate::{error::Result, model::ScanReport, storage::filesystem};

pub async fn write(report: &ScanReport, path: &Path) -> Result<()> {
    let mut output = format!(
        "ScopeLynx\nTarget: {}\nProfile: {}\nWire requests: {}\nHTTP statuses: {}\nScheduled tasks: {}\nSoft 404: {}\nNative 404/410: {}\nNot modified: {}\nServer errors: {}\nFindings: {}\n\n",
        report.target,
        report.profile,
        report.stats.wire_requests,
        report
            .stats
            .status_counts
            .iter()
            .map(|(status, count)| format!("{status}={count}"))
            .collect::<Vec<_>>()
            .join(", "),
        report.stats.scheduled_tasks,
        report.stats.soft_404,
        report.stats.not_found,
        report.stats.not_modified,
        report.stats.server_errors,
        report.findings.len()
    );

    for finding in &report.findings {
        output.push_str(&format!(
            "[{:?}/{:?}] {} ({})\n  {}\n  Location: {}\n",
            finding.severity,
            finding.confidence,
            finding.title,
            finding.id,
            finding.description,
            finding.location
        ));
        if let Some(remediation) = &finding.remediation {
            output.push_str(&format!("  Remediation: {remediation}\n"));
        }
        output.push('\n');
    }

    filesystem::write_atomic(path, output.as_bytes()).await
}
