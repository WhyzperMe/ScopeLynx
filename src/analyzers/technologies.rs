use std::collections::BTreeMap;

use crate::{
    model::{Confidence, Finding, FindingKind, Observation, Severity},
    scope::redact_url,
};

#[derive(Debug, Default)]
struct Detection {
    score: u16,
    evidence: Vec<String>,
}

#[must_use]
pub fn analyze(observation: &Observation, body: &str) -> Vec<Finding> {
    let lower = body.to_ascii_lowercase();
    let mut detections = BTreeMap::<&'static str, Detection>::new();

    score(&mut detections, "Next.js", 90, lower.contains("__next_data__"), "__NEXT_DATA__ marker");
    score(
        &mut detections,
        "Next.js",
        70,
        lower.contains("/_next/static/"),
        "/_next/static asset path",
    );
    score(&mut detections, "React", 80, lower.contains("data-reactroot"), "data-reactroot marker");
    score(
        &mut detections,
        "React",
        60,
        lower.contains("react.production.min.js"),
        "React production asset",
    );
    score(&mut detections, "Angular", 95, lower.contains("ng-version="), "ng-version attribute");
    score(&mut detections, "Vue", 65, lower.contains("data-v-"), "Vue scoped-style marker");
    score(&mut detections, "WordPress", 85, lower.contains("wp-content/"), "wp-content asset path");
    score(
        &mut detections,
        "WordPress",
        70,
        lower.contains("wp-includes/"),
        "wp-includes asset path",
    );

    if let Some(server) = first_header(observation, "server") {
        let normalized = server.to_ascii_lowercase();
        for technology in ["nginx", "apache", "caddy", "cloudflare"] {
            score(&mut detections, technology, 75, normalized.contains(technology), server);
        }
    }
    if let Some(powered_by) = first_header(observation, "x-powered-by") {
        for technology in ["express", "php", "asp.net"] {
            score(
                &mut detections,
                technology,
                85,
                powered_by.to_ascii_lowercase().contains(technology),
                powered_by,
            );
        }
    }

    detections
        .into_iter()
        .filter(|(_, detection)| detection.score >= 60)
        .map(|(technology, mut detection)| {
            detection.evidence.sort();
            detection.evidence.dedup();
            let confidence = match detection.score {
                100.. => Confidence::High,
                75..=99 => Confidence::Medium,
                _ => Confidence::Low,
            };
            Finding::new(
                FindingKind::Technology,
                Severity::Info,
                confidence,
                format!("Technology detected: {technology}"),
                format!(
                    "Independent response indicators produced a fingerprint score of {}.",
                    detection.score
                ),
                origin_location(observation),
            )
            .with_evidence("technology.fingerprint", detection.evidence.join("; "))
        })
        .collect()
}

fn origin_location(observation: &Observation) -> String {
    let mut origin = observation.final_url.clone();
    origin.set_path("/");
    origin.set_query(None);
    origin.set_fragment(None);
    redact_url(&origin)
}

fn score(
    detections: &mut BTreeMap<&'static str, Detection>,
    technology: &'static str,
    points: u16,
    condition: bool,
    evidence: &str,
) {
    if condition {
        let detection = detections.entry(technology).or_default();
        detection.score = detection.score.saturating_add(points).min(150);
        detection.evidence.push(evidence.chars().take(256).collect());
    }
}

fn first_header<'a>(observation: &'a Observation, name: &str) -> Option<&'a str> {
    observation.headers.get(name).and_then(|values| values.first()).map(String::as_str)
}
