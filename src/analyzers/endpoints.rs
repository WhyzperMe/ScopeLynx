use crate::{
    discovery,
    model::{Confidence, Finding, FindingKind, Observation, Severity},
    scope::redact_url,
};

#[must_use]
pub fn analyze(observation: &Observation, body: Option<&str>) -> Vec<Finding> {
    if observation.soft_404 {
        return Vec::new();
    }

    let mut findings = Vec::new();
    if looks_like_endpoint(observation.final_url.path()) {
        findings.push(
            Finding::new(
                FindingKind::Endpoint,
                Severity::Info,
                Confidence::Medium,
                "Potential API endpoint",
                "The requested URL resembles an API or API-documentation endpoint.",
                redact_url(&observation.final_url),
            )
            .with_evidence("url.path", observation.final_url.path()),
        );
    }

    if let Some(body) = body {
        let content_type =
            observation.content_type.as_deref().unwrap_or_default().to_ascii_lowercase();
        if content_type.contains("javascript") || content_type.contains("html") {
            for candidate in discovery::javascript::discover(&observation.final_url, body, 50) {
                if !looks_like_endpoint(candidate.url.path()) {
                    continue;
                }
                findings.push(
                    Finding::new(
                        FindingKind::Endpoint,
                        Severity::Info,
                        Confidence::Medium,
                        "Endpoint reference discovered",
                        "A static URL reference resembling an API endpoint was extracted from response content.",
                        redact_url(&candidate.url),
                    )
                    .with_evidence("content.reference", candidate.relation),
                );
            }
        }
    }

    findings
}

fn looks_like_endpoint(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    path.starts_with("/api")
        || path.contains("/api/")
        || path.contains("graphql")
        || path.contains("openapi")
        || path.contains("swagger")
        || path.ends_with("/health")
        || path.ends_with("/metrics")
}
