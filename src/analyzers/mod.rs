pub mod cookies;
pub mod document;
pub mod endpoints;
pub mod exposure;
pub mod forms;
pub mod headers;
pub mod technologies;

use std::collections::BTreeMap;

use crate::model::{Finding, Observation, ResponseClass};

#[must_use]
pub fn analyze(
    observation: &Observation,
    body: Option<&str>,
    sensitive_profile: bool,
) -> Vec<Finding> {
    if observation.soft_404 || matches!(observation.class, ResponseClass::NotFound) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    findings.extend(headers::analyze(observation));
    findings.extend(cookies::analyze(observation));
    findings.extend(endpoints::analyze(observation, body));
    findings.extend(exposure::analyze(observation, body, sensitive_profile));

    if let Some(body) = body {
        findings.extend(document::analyze(observation, body));
        findings.extend(forms::analyze(observation, body));
        findings.extend(technologies::analyze(observation, body));
    }

    let mut unique = BTreeMap::new();
    for finding in findings {
        unique.entry(finding.id.clone()).or_insert(finding);
    }
    unique.into_values().collect()
}
