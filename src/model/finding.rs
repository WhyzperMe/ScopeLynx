use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::redaction::{redact_evidence, redact_text};

const MAX_EVIDENCE_ITEMS: usize = 16;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Technology,
    Endpoint,
    SecurityHeader,
    Cookie,
    Form,
    Exposure,
    Information,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Evidence {
    pub source: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub kind: FindingKind,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub description: String,
    pub location: String,
    pub evidence: Vec<Evidence>,
    pub remediation: Option<String>,
    pub tags: BTreeSet<String>,
    #[serde(default = "default_analyzer_version")]
    pub analyzer_version: String,
}

impl Finding {
    #[must_use]
    pub fn new(
        kind: FindingKind,
        severity: Severity,
        confidence: Confidence,
        title: impl Into<String>,
        description: impl Into<String>,
        location: impl Into<String>,
    ) -> Self {
        let mut finding = Self {
            id: String::new(),
            kind,
            severity,
            confidence,
            title: redact_text(&title.into()).chars().take(256).collect(),
            description: redact_text(&description.into()).chars().take(2_048).collect(),
            location: redact_text(&location.into()),
            evidence: Vec::new(),
            remediation: None,
            tags: BTreeSet::new(),
            analyzer_version: default_analyzer_version(),
        };
        finding.refresh_id();
        finding
    }

    #[must_use]
    pub fn with_evidence(mut self, source: impl Into<String>, value: impl Into<String>) -> Self {
        if self.evidence.len() < MAX_EVIDENCE_ITEMS {
            self.evidence.push(Evidence {
                source: redact_evidence(&source.into()).chars().take(128).collect(),
                value: redact_evidence(&value.into()),
            });
        }
        self.evidence.sort();
        self.evidence.dedup();
        self.refresh_id();
        self
    }

    #[must_use]
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(redact_text(&remediation.into()).chars().take(2_048).collect());
        self
    }

    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.insert(redact_text(&tag.into()).chars().take(128).collect());
        self
    }

    fn refresh_id(&mut self) {
        let input =
            format!("{:?}|{}|{}|{}", self.kind, self.title, self.location, self.analyzer_version);
        let digest = Sha256::digest(input.as_bytes());
        self.id = hex::encode(&digest[..12]);
    }
}

fn default_analyzer_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
