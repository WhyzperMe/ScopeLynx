use sha2::{Digest, Sha256};

use crate::model::Confidence;

use super::similarity::text_similarity;

#[derive(Debug, Clone)]
struct Soft404Sample {
    status: u16,
    body_hash: [u8; 32],
    body: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct Soft404Detector {
    samples: Vec<Soft404Sample>,
}

#[derive(Debug, Clone)]
pub struct Soft404Decision {
    pub is_soft_404: bool,
    pub confidence: Confidence,
    pub score: f32,
    pub reasons: Vec<String>,
    pub matched_baselines: Vec<usize>,
}

impl Soft404Detector {
    #[must_use]
    pub fn from_samples(samples: impl IntoIterator<Item = (u16, Vec<u8>)>) -> Self {
        Self {
            samples: samples
                .into_iter()
                .map(|(status, body)| Soft404Sample {
                    status,
                    body_hash: Sha256::digest(&body).into(),
                    body: body.into_iter().take(512 * 1024).collect(),
                })
                .collect(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    #[must_use]
    pub fn matches(&self, status: u16, body: &[u8]) -> bool {
        self.classify(status, body).is_soft_404
    }

    #[must_use]
    pub fn classify(&self, status: u16, body: &[u8]) -> Soft404Decision {
        if matches!(status, 404 | 410) {
            return Soft404Decision {
                is_soft_404: false,
                confidence: Confidence::Low,
                score: 0.0,
                reasons: vec![format!(
                    "native not-found status {status}; no soft-404 inference required"
                )],
                matched_baselines: Vec::new(),
            };
        }
        if !(200..=299).contains(&status) || body.is_empty() {
            return Soft404Decision {
                is_soft_404: false,
                confidence: Confidence::Low,
                score: 0.0,
                reasons: vec![format!(
                    "HTTP status {status} with {} captured bytes is not eligible for soft-404 similarity",
                    body.len()
                )],
                matched_baselines: Vec::new(),
            };
        }
        let hash: [u8; 32] = Sha256::digest(body).into();
        let mut matched_baselines = Vec::new();
        let mut strongest_similarity = 0.0f64;
        let mut exact_hash = false;
        for (index, sample) in
            self.samples.iter().enumerate().filter(|(_, sample)| sample.status == status)
        {
            let similarity = text_similarity(&sample.body, body);
            strongest_similarity = strongest_similarity.max(similarity);
            if sample.body_hash == hash || similarity >= 0.92 {
                exact_hash |= sample.body_hash == hash;
                matched_baselines.push(index);
            }
        }
        let required = self.samples.len().min(2);
        let is_soft_404 = required > 0 && matched_baselines.len() >= required;
        let coverage = if self.samples.is_empty() {
            0.0
        } else {
            matched_baselines.len() as f32 / self.samples.len() as f32
        };
        let score = ((strongest_similarity as f32 * 0.7) + (coverage * 0.3)).clamp(0.0, 1.0);
        let mut reasons = Vec::new();
        if exact_hash {
            reasons.push("captured body hash matches a baseline".into());
        }
        if strongest_similarity >= 0.92 {
            reasons.push(format!("normalized text similarity {strongest_similarity:.3}"));
        }
        if is_soft_404 {
            reasons.push(format!(
                "matched {} of {} not-found baselines",
                matched_baselines.len(),
                self.samples.len()
            ));
        }
        Soft404Decision {
            is_soft_404,
            confidence: if is_soft_404 && (exact_hash || coverage >= 1.0) {
                Confidence::High
            } else if is_soft_404 {
                Confidence::Medium
            } else {
                Confidence::Low
            },
            score,
            reasons,
            matched_baselines,
        }
    }
}
