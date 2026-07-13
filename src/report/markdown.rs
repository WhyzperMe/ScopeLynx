use std::{collections::BTreeMap, path::Path};

use crate::{
    error::Result,
    model::{ScanReport, Severity},
    storage::filesystem,
};

pub async fn write(report: &ScanReport, path: &Path) -> Result<()> {
    let mut output = String::new();
    output.push_str("# ScopeLynx Report\n\n");
    output.push_str(&format!("- Target: `{}`\n", escape_inline(&report.target)));
    output.push_str(&format!("- Profile: `{}`\n", escape_inline(&report.profile)));
    output.push_str(&format!("- Scanner: `{}`\n", escape_inline(&report.scanner_version)));
    output.push_str(&format!("- Started: `{}`\n", report.started_at));
    output.push_str(&format!("- Finished: `{}`\n\n", report.finished_at));

    output.push_str("## Summary\n\n");
    output.push_str(&format!("- Wire requests: {}\n", report.stats.wire_requests));
    output.push_str(&format!("- Scheduled tasks: {}\n", report.stats.scheduled_tasks));
    output.push_str(&format!("- Unique URLs: {}\n", report.stats.unique_urls));
    output.push_str(&format!("- Successful responses: {}\n", report.stats.successful));
    output.push_str(&format!("- Semantic soft 404 responses: {}\n", report.stats.soft_404));
    output.push_str(&format!("- Failed tasks: {}\n", report.stats.failed));
    output.push_str(&format!("- Findings: {}\n\n", report.findings.len()));

    output.push_str("## HTTP Status Distribution\n\n");
    output.push_str("| Status | Count |\n|---:|---:|\n");
    for (status, count) in &report.stats.status_counts {
        output.push_str(&format!("| {status} | {count} |\n"));
    }
    output.push_str(&format!("\n- Semantic soft 404: {}\n", report.stats.soft_404));
    output.push_str(&format!("- Native not found (404/410): {}\n", report.stats.not_found));
    output.push_str(&format!("- Not modified (304): {}\n", report.stats.not_modified));
    output.push_str(&format!("- Rate limited (429): {}\n", report.stats.rate_limited));
    output.push_str(&format!("- Server errors (5xx): {}\n\n", report.stats.server_errors));

    let mut severity_counts = BTreeMap::<Severity, usize>::new();
    for finding in &report.findings {
        *severity_counts.entry(finding.severity).or_default() += 1;
    }
    output.push_str("| Severity | Count |\n|---|---:|\n");
    for severity in
        [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info]
    {
        output.push_str(&format!(
            "| {:?} | {} |\n",
            severity,
            severity_counts.get(&severity).copied().unwrap_or(0)
        ));
    }
    output.push('\n');

    output.push_str("## Findings\n\n");
    if report.findings.is_empty() {
        output.push_str("No findings were produced.\n\n");
    }
    for finding in &report.findings {
        output.push_str(&format!(
            "### {:?}: {}\n\n",
            finding.severity,
            escape_text(&finding.title)
        ));
        output.push_str(&format!("- ID: `{}`\n", escape_inline(&finding.id)));
        output.push_str(&format!("- Kind: `{:?}`\n", finding.kind));
        output.push_str(&format!("- Confidence: `{:?}`\n", finding.confidence));
        output.push_str(&format!("- Location: `{}`\n", escape_inline(&finding.location)));
        if !finding.tags.is_empty() {
            output.push_str(&format!(
                "- Tags: {}\n",
                finding
                    .tags
                    .iter()
                    .map(|tag| format!("`{}`", escape_inline(tag)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        output.push_str(&format!("\n{}\n\n", escape_text(&finding.description)));
        if !finding.evidence.is_empty() {
            output.push_str("**Evidence**\n\n");
            for evidence in &finding.evidence {
                output.push_str(&format!(
                    "- `{}`: `{}`\n",
                    escape_inline(&evidence.source),
                    escape_inline(&evidence.value)
                ));
            }
            output.push('\n');
        }
        if let Some(remediation) = &finding.remediation {
            output.push_str(&format!("**Remediation:** {}\n\n", escape_text(remediation)));
        }
    }

    output.push_str("## Limits and Errors\n\n");
    output.push_str(&format!(
        "- Request budget exhausted: `{}`\n",
        report.limits.request_budget_exhausted
    ));
    output.push_str(&format!(
        "- Discovery limit reached: `{}`\n",
        report.limits.discovery_limit_reached
    ));
    output.push_str(&format!("- Error limit reached: `{}`\n", report.limits.error_limit_reached));
    output
        .push_str(&format!("- Finding limit reached: `{}`\n", report.limits.finding_limit_reached));
    output.push_str(&format!("- Recorded errors: `{}`\n", report.errors.len()));

    filesystem::write_atomic(path, output.as_bytes()).await
}

fn escape_inline(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('`', "\\`")
        .replace(['\n', '\r'], " ")
}

fn escape_text(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}
