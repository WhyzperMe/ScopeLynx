use std::collections::BTreeSet;

#[must_use]
pub fn text_similarity(left: &[u8], right: &[u8]) -> f64 {
    if left == right {
        return 1.0;
    }
    if left.is_empty() || right.is_empty() {
        return 0.0;
    }

    let left = &left[..left.len().min(512 * 1024)];
    let right = &right[..right.len().min(512 * 1024)];
    let left_text = normalize(&String::from_utf8_lossy(left));
    let right_text = normalize(&String::from_utf8_lossy(right));
    if left_text == right_text {
        return 1.0;
    }

    let left_tokens = shingles(&left_text);
    let right_tokens = shingles(&right_text);
    if left_tokens.is_empty() || right_tokens.is_empty() {
        return length_similarity(left_text.len(), right_text.len());
    }

    let intersection = left_tokens.intersection(&right_tokens).count();
    let union = left_tokens.union(&right_tokens).count();
    let jaccard = intersection as f64 / union.max(1) as f64;
    (jaccard * 0.85) + (length_similarity(left_text.len(), right_text.len()) * 0.15)
}

fn normalize(value: &str) -> String {
    value
        .split_whitespace()
        .map(|token| {
            let lower = token.to_ascii_lowercase();
            let secret_named = lower.split_once('=').is_some_and(|(name, _)| {
                ["csrf", "xsrf", "session", "request-id", "request_id", "nonce"]
                    .iter()
                    .any(|marker| name.contains(marker))
            });
            let digits = token.chars().filter(char::is_ascii_digit).count();
            let looks_dynamic = secret_named
                || (token.len() >= 8
                    && digits > 0
                    && token
                        .chars()
                        .all(|character| character.is_ascii_hexdigit() || character == '-'))
                || (token.len() >= 10 && digits >= 6);
            if looks_dynamic { "<dynamic>".to_string() } else { lower }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn shingles(value: &str) -> BTreeSet<String> {
    let characters = value.chars().take(200_000).collect::<Vec<_>>();
    if characters.len() < 5 {
        return characters.into_iter().map(|value| value.to_string()).collect();
    }
    characters.windows(5).take(50_000).map(|window| window.iter().collect::<String>()).collect()
}

fn length_similarity(left: usize, right: usize) -> f64 {
    let maximum = left.max(right) as f64;
    if maximum == 0.0 { 1.0 } else { 1.0 - (left.abs_diff(right) as f64 / maximum) }
}
