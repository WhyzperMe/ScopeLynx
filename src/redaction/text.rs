use std::sync::OnceLock;

use regex::Regex;
use url::Url;

use super::url::redact_url;

const MAX_REDACTED_TEXT_CHARS: usize = 4_096;

/// Redacts common URL, credential, token, and private-key representations.
#[must_use]
pub fn redact_text(value: &str) -> String {
    let mut output = redact_urls(value);
    for regex in secret_assignment_regexes() {
        output = regex.replace_all(&output, "${name}=<redacted>").into_owned();
    }
    if let Some(regex) = bearer_regex() {
        output = regex.replace_all(&output, "Bearer <redacted>").into_owned();
    }
    if let Some(regex) = private_key_regex() {
        output = regex.replace_all(&output, "<redacted-private-key>").into_owned();
    }
    if let Some(regex) = windows_path_regex() {
        output = regex.replace_all(&output, "<local-path>").into_owned();
    }
    if let Some(regex) = email_regex() {
        output = regex.replace_all(&output, "<redacted>@${domain}").into_owned();
    }
    output
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .take(MAX_REDACTED_TEXT_CHARS)
        .collect()
}

fn redact_urls(value: &str) -> String {
    let Some(regex) = url_regex() else {
        return value.to_string();
    };
    regex
        .replace_all(value, |captures: &regex::Captures<'_>| {
            let raw = captures.get(0).map_or("", |matched| matched.as_str());
            Url::parse(raw).map_or_else(|_| "<redacted-url>".to_string(), |url| redact_url(&url))
        })
        .into_owned()
}

fn url_regex() -> Option<&'static Regex> {
    static REGEX: OnceLock<Option<Regex>> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r#"(?i)https?://[^\s<>\"']{1,8192}"#).ok()).as_ref()
}

fn secret_assignment_regexes() -> &'static [Regex] {
    static REGEXES: OnceLock<Vec<Regex>> = OnceLock::new();
    REGEXES.get_or_init(|| {
        [
            r#"(?i)(?P<name>access[_-]?token|refresh[_-]?token|api[_-]?key|apikey|secret|password|passwd|session[_-]?id|csrf|xsrf|authorization)\s*[=:]\s*[^\s,;]+"#,
            r#"(?i)(?P<name>aws_access_key_id|aws_secret_access_key|client_secret|private_key)\s*[=:]\s*[^\s,;]+"#,
        ]
        .into_iter()
        .filter_map(|pattern| Regex::new(pattern).ok())
        .collect()
    })
}

fn bearer_regex() -> Option<&'static Regex> {
    static REGEX: OnceLock<Option<Regex>> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+\-/]+=*").ok()).as_ref()
}

fn private_key_regex() -> Option<&'static Regex> {
    static REGEX: OnceLock<Option<Regex>> = OnceLock::new();
    REGEX
        .get_or_init(|| {
            Regex::new(
                r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            )
            .ok()
        })
        .as_ref()
}

fn windows_path_regex() -> Option<&'static Regex> {
    static REGEX: OnceLock<Option<Regex>> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"(?i)\b[A-Z]:\\[^\r\n]+(?:\\[^\r\n]+)*").ok()).as_ref()
}

fn email_regex() -> Option<&'static Regex> {
    static REGEX: OnceLock<Option<Regex>> = OnceLock::new();
    REGEX
        .get_or_init(|| {
            Regex::new(
                r"(?i)\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@(?P<domain>[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+)\b",
            )
            .ok()
        })
        .as_ref()
}
