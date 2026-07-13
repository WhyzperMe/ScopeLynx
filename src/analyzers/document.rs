use std::{collections::BTreeSet, sync::OnceLock};

use regex::Regex;
use scraper::{Html, Selector};

use crate::{
    model::{Confidence, Finding, FindingKind, Observation, Severity},
    scope::redact_url,
};

#[must_use]
pub fn analyze(observation: &Observation, body: &str) -> Vec<Finding> {
    if observation.soft_404 || observation.status >= 400 || !is_html(observation) {
        return Vec::new();
    }

    let document = Html::parse_document(body);
    let mut findings = Vec::new();

    if let Some(title) = extract_text(&document, "title") {
        findings.push(
            Finding::new(
                FindingKind::Information,
                Severity::Info,
                Confidence::High,
                "Document title",
                "The HTML document exposes a page title.",
                redact_url(&observation.final_url),
            )
            .with_evidence("html.title", truncate(&title, 256)),
        );
    }

    if let Some(generator) = extract_meta_generator(&document) {
        findings.push(
            Finding::new(
                FindingKind::Information,
                Severity::Info,
                Confidence::High,
                "Generator metadata exposed",
                "The page publishes generator metadata that may aid technology fingerprinting.",
                redact_url(&observation.final_url),
            )
            .with_evidence("html.meta.generator", truncate(&generator, 256))
            .with_remediation("Remove generator metadata when it is not operationally required."),
        );
    }

    let email_domains = extract_email_domains(body);
    if !email_domains.is_empty() {
        findings.push(
            Finding::new(
                FindingKind::Information,
                Severity::Info,
                Confidence::Medium,
                "Email domains referenced",
                "The response contains syntactically valid email-address references. Local parts are not stored in the report.",
                redact_url(&observation.final_url),
            )
            .with_evidence(
                "document.email_domains",
                email_domains.into_iter().collect::<Vec<_>>().join(", "),
            ),
        );
    }

    if let Some(keyword) = suspicious_comment_keyword(body) {
        findings.push(
            Finding::new(
                FindingKind::Information,
                Severity::Low,
                Confidence::Medium,
                "Potentially sensitive HTML comment",
                "An HTML comment contains a development or secret-related keyword. Comment content is intentionally not copied into the report.",
                redact_url(&observation.final_url),
            )
            .with_evidence("html.comment.keyword", keyword)
            .with_remediation("Remove development notes and sensitive operational details from production HTML."),
        );
    }

    findings
}

fn extract_text(document: &Html, selector: &str) -> Option<String> {
    let selector = document_selector(selector)?;
    let text = document.select(selector).next()?.text().collect::<Vec<_>>().join(" ");
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    (!normalized.is_empty()).then_some(normalized)
}

fn extract_meta_generator(document: &Html) -> Option<String> {
    let selector = document_selector("meta[name][content]")?;
    document.select(selector).find_map(|element| {
        let name = element.value().attr("name")?;
        name.eq_ignore_ascii_case("generator")
            .then(|| element.value().attr("content").unwrap_or_default().trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn extract_email_domains(body: &str) -> BTreeSet<String> {
    let Some(regex) = email_regex() else {
        return BTreeSet::new();
    };
    regex
        .captures_iter(body)
        .filter_map(|capture| capture.get(1))
        .map(|domain| domain.as_str().to_ascii_lowercase())
        .take(100)
        .collect()
}

fn suspicious_comment_keyword(body: &str) -> Option<String> {
    let comment_regex = comment_regex()?;
    const KEYWORDS: &[&str] =
        &["api key", "debug", "password", "secret", "temporary", "todo", "token"];
    comment_regex.captures_iter(body).find_map(|capture| {
        let comment = capture.name("comment")?.as_str().to_ascii_lowercase();
        KEYWORDS
            .iter()
            .find(|keyword| comment.contains(**keyword))
            .map(|keyword| (*keyword).to_string())
    })
}

fn document_selector(query: &str) -> Option<&'static Selector> {
    static TITLE: OnceLock<Option<Selector>> = OnceLock::new();
    static META: OnceLock<Option<Selector>> = OnceLock::new();
    match query {
        "title" => TITLE.get_or_init(|| Selector::parse("title").ok()).as_ref(),
        "meta[name][content]" => {
            META.get_or_init(|| Selector::parse("meta[name][content]").ok()).as_ref()
        }
        _ => None,
    }
}

fn email_regex() -> Option<&'static Regex> {
    static REGEX: OnceLock<Option<Regex>> = OnceLock::new();
    REGEX
        .get_or_init(|| {
            Regex::new(
                r"(?i)\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@([a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+)\b",
            )
            .ok()
        })
        .as_ref()
}

fn comment_regex() -> Option<&'static Regex> {
    static REGEX: OnceLock<Option<Regex>> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"(?is)<!--(?P<comment>.{0,4096}?)-->").ok()).as_ref()
}

fn is_html(observation: &Observation) -> bool {
    observation
        .content_type
        .as_deref()
        .map(|value| value.to_ascii_lowercase().contains("html"))
        .unwrap_or(false)
}

fn truncate(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}
