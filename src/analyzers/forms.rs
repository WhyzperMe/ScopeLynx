use std::sync::OnceLock;

use scraper::{Html, Selector};

use crate::{
    model::{Confidence, Finding, FindingKind, Observation, Severity},
    scope::redact_url,
};

#[must_use]
pub fn analyze(observation: &Observation, body: &str) -> Vec<Finding> {
    if observation.soft_404 || observation.status >= 400 {
        return Vec::new();
    }
    let document = Html::parse_document(body);
    let Some(form_selector) = form_selector() else {
        return Vec::new();
    };
    let Some(password_selector) = password_selector() else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    for (index, form) in document.select(form_selector).take(500).enumerate() {
        let password_inputs = form.select(password_selector).collect::<Vec<_>>();
        if password_inputs.is_empty() {
            continue;
        }
        let method = form.value().attr("method").unwrap_or("get");
        let location = format!("{} (form {})", redact_url(&observation.final_url), index + 1);

        findings.push(
            Finding::new(
                FindingKind::Form,
                Severity::Info,
                Confidence::High,
                "Password form detected",
                format!("A form containing a password input uses HTTP method {method}."),
                location.clone(),
            )
            .with_evidence("html.form", format!("method={method}")),
        );

        if method.eq_ignore_ascii_case("get") {
            findings.push(
                Finding::new(
                    FindingKind::Form,
                    Severity::High,
                    Confidence::High,
                    "Password form uses GET",
                    "A credential-bearing form may place secrets in URLs, history, logs, and referrer data.",
                    location.clone(),
                )
                .with_evidence("html.form.method", method)
                .with_remediation("Submit credential-bearing forms with POST over HTTPS."),
            );
        }
        if observation.final_url.scheme() != "https" {
            findings.push(
                Finding::new(
                    FindingKind::Form,
                    Severity::High,
                    Confidence::High,
                    "Password form served without HTTPS",
                    "Credentials entered into this page may be exposed in transit.",
                    location.clone(),
                )
                .with_evidence("document.scheme", observation.final_url.scheme())
                .with_remediation("Serve authentication pages exclusively over HTTPS and redirect HTTP before rendering forms."),
            );
        }

        if password_inputs.iter().any(|input| {
            input.value().attr("autocomplete").is_none_or(|value| value.trim().is_empty())
        }) {
            findings.push(
                Finding::new(
                    FindingKind::Form,
                    Severity::Info,
                    Confidence::Medium,
                    "Password input lacks explicit autocomplete semantics",
                    "At least one password input does not declare current-password or new-password autocomplete semantics.",
                    location.clone(),
                )
                .with_evidence("html.input.autocomplete", "<missing>")
                .with_remediation("Set autocomplete=current-password or new-password as appropriate."),
            );
        }

        if let Some(action) = form.value().attr("action")
            && let Ok(action_url) = observation.final_url.join(action)
            && action_url.host_str() != observation.final_url.host_str()
        {
            findings.push(
                Finding::new(
                    FindingKind::Form,
                    Severity::Medium,
                    Confidence::High,
                    "Password form submits cross-origin",
                    "The password form action targets a different host.",
                    location,
                )
                .with_evidence("html.form.action", redact_url(&action_url))
                .with_remediation("Verify the external destination and keep credential submission within a trusted origin."),
            );
        }
    }
    findings
}

fn form_selector() -> Option<&'static Selector> {
    static SELECTOR: OnceLock<Option<Selector>> = OnceLock::new();
    SELECTOR.get_or_init(|| Selector::parse("form").ok()).as_ref()
}

fn password_selector() -> Option<&'static Selector> {
    static SELECTOR: OnceLock<Option<Selector>> = OnceLock::new();
    SELECTOR.get_or_init(|| Selector::parse("input[type='password']").ok()).as_ref()
}
