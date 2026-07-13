use std::{collections::BTreeMap, path::Path};

use serde::{Deserialize, Serialize};

use crate::{
    error::Result,
    model::{Finding, ScanReport},
    storage::filesystem,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportDiff {
    pub previous_target: String,
    pub current_target: String,
    pub added_findings: Vec<Finding>,
    pub removed_finding_ids: Vec<String>,
    pub added_urls: Vec<String>,
    pub removed_urls: Vec<String>,
}

#[must_use]
pub fn compare(previous: &ScanReport, current: &ScanReport) -> ReportDiff {
    let previous_findings = previous
        .findings
        .iter()
        .cloned()
        .map(|finding| (finding.id.clone(), finding))
        .collect::<BTreeMap<_, _>>();
    let current_findings = current
        .findings
        .iter()
        .cloned()
        .map(|finding| (finding.id.clone(), finding))
        .collect::<BTreeMap<_, _>>();

    let mut added_findings = current_findings
        .iter()
        .filter(|(id, _)| !previous_findings.contains_key(*id))
        .map(|(_, finding)| finding.clone())
        .collect::<Vec<_>>();
    added_findings.sort_by(|left, right| {
        right.severity.cmp(&left.severity).then_with(|| left.id.cmp(&right.id))
    });

    let removed_finding_ids = previous_findings
        .keys()
        .filter(|id| !current_findings.contains_key(*id))
        .cloned()
        .collect();

    let previous_urls = previous
        .discovered_resources
        .iter()
        .map(|resource| resource.url.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let current_urls = current
        .discovered_resources
        .iter()
        .map(|resource| resource.url.clone())
        .collect::<std::collections::BTreeSet<_>>();

    ReportDiff {
        previous_target: previous.target.clone(),
        current_target: current.target.clone(),
        added_findings,
        removed_finding_ids,
        added_urls: current_urls.difference(&previous_urls).cloned().collect(),
        removed_urls: previous_urls.difference(&current_urls).cloned().collect(),
    }
}

pub async fn write(diff: &ReportDiff, path: &Path) -> Result<()> {
    let data = serde_json::to_vec_pretty(diff)?;
    filesystem::write_atomic(path, &data).await
}

#[must_use]
pub fn render_text(diff: &ReportDiff) -> String {
    let mut output = format!(
        "Report diff\nPrevious: {}\nCurrent: {}\n\nAdded findings: {}\nRemoved findings: {}\nAdded URLs: {}\nRemoved URLs: {}\n",
        diff.previous_target,
        diff.current_target,
        diff.added_findings.len(),
        diff.removed_finding_ids.len(),
        diff.added_urls.len(),
        diff.removed_urls.len()
    );
    for finding in &diff.added_findings {
        output
            .push_str(&format!("+ [{:?}] {} ({})\n", finding.severity, finding.title, finding.id));
    }
    for id in &diff.removed_finding_ids {
        output.push_str(&format!("- finding {id}\n"));
    }
    for url in &diff.added_urls {
        output.push_str(&format!("+ URL {url}\n"));
    }
    for url in &diff.removed_urls {
        output.push_str(&format!("- URL {url}\n"));
    }
    output
}
