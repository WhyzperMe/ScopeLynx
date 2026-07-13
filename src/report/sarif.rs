use std::path::Path;

use serde::Serialize;

use crate::{
    error::Result,
    model::{Finding, ScanReport, Severity},
    storage::filesystem,
};

#[derive(Serialize)]
struct SarifReport<'a> {
    version: &'static str,
    #[serde(rename = "$schema")]
    schema: &'static str,
    runs: Vec<SarifRun<'a>>,
}

#[derive(Serialize)]
struct SarifRun<'a> {
    tool: SarifTool,
    results: Vec<SarifResult<'a>>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct SarifResult<'a> {
    #[serde(rename = "ruleId")]
    rule_id: &'a str,
    level: &'static str,
    message: SarifMessage<'a>,
    locations: Vec<SarifLocation<'a>>,
    properties: SarifProperties<'a>,
}

#[derive(Serialize)]
struct SarifMessage<'a> {
    text: &'a str,
}

#[derive(Serialize)]
struct SarifLocation<'a> {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation<'a>,
}

#[derive(Serialize)]
struct SarifPhysicalLocation<'a> {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation<'a>,
}

#[derive(Serialize)]
struct SarifArtifactLocation<'a> {
    uri: &'a str,
}

#[derive(Serialize)]
struct SarifProperties<'a> {
    confidence: &'a str,
    finding_id: &'a str,
}

pub async fn write(report: &ScanReport, path: &Path) -> Result<()> {
    let sarif = SarifReport {
        version: "2.1.0",
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver { name: "scopelynx", version: env!("CARGO_PKG_VERSION") },
            },
            results: report.findings.iter().map(sarif_result).collect(),
        }],
    };
    let bytes = serde_json::to_vec_pretty(&sarif)?;
    filesystem::write_atomic(path, &bytes).await
}

fn sarif_result(finding: &Finding) -> SarifResult<'_> {
    SarifResult {
        rule_id: &finding.id,
        level: match finding.severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium | Severity::Low => "warning",
            Severity::Info => "note",
        },
        message: SarifMessage { text: &finding.description },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation { uri: &finding.location },
            },
        }],
        properties: SarifProperties {
            confidence: match finding.confidence {
                crate::model::Confidence::Low => "low",
                crate::model::Confidence::Medium => "medium",
                crate::model::Confidence::High => "high",
            },
            finding_id: &finding.id,
        },
    }
}
