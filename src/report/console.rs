use std::collections::BTreeMap;

use crate::model::{ScanReport, Severity};

pub fn print_summary(report: &ScanReport) {
    let mut severities = BTreeMap::<Severity, usize>::new();
    for finding in &report.findings {
        *severities.entry(finding.severity).or_default() += 1;
    }

    println!();
    println!("Scan completed");
    println!("Target:          {}", report.target);
    println!("Profile:         {}", report.profile);
    println!("Wire requests:   {}", report.stats.wire_requests);
    if !report.stats.status_counts.is_empty() {
        let statuses = report
            .stats
            .status_counts
            .iter()
            .map(|(status, count)| format!("{status}={count}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("HTTP statuses:   {statuses}");
    }
    println!("Scheduled tasks: {}", report.stats.scheduled_tasks);
    println!("Successful:      {}", report.stats.successful);
    println!("Soft 404:        {}", report.stats.soft_404);
    println!("Native 404/410:  {}", report.stats.not_found);
    println!("Not modified:    {}", report.stats.not_modified);
    println!("Authentication:  {}", report.stats.authentication_required);
    println!("Forbidden:       {}", report.stats.forbidden);
    println!("Rate limited:    {}", report.stats.rate_limited);
    println!("Server errors:   {}", report.stats.server_errors);
    println!("Failed:          {}", report.stats.failed);
    println!("Findings:        {}", report.findings.len());
    println!("  Critical:      {}", severities.get(&Severity::Critical).copied().unwrap_or(0));
    println!("  High:          {}", severities.get(&Severity::High).copied().unwrap_or(0));
    println!("  Medium:        {}", severities.get(&Severity::Medium).copied().unwrap_or(0));
    println!("  Low:           {}", severities.get(&Severity::Low).copied().unwrap_or(0));
    if report.limits.request_budget_exhausted
        || report.limits.discovery_limit_reached
        || report.limits.error_limit_reached
        || report.limits.finding_limit_reached
    {
        println!("Limits reached:  yes (review report.json)");
    }
}
