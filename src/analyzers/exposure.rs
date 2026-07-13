use crate::{
    model::{Confidence, Finding, FindingKind, Observation, Severity},
    scope::redact_url,
};

#[must_use]
pub fn analyze(
    observation: &Observation,
    body: Option<&str>,
    sensitive_profile: bool,
) -> Vec<Finding> {
    if observation.soft_404 || observation.status >= 400 {
        return Vec::new();
    }

    let path = observation.final_url.path().to_ascii_lowercase();
    let text = body.unwrap_or_default();
    let lower = text.to_ascii_lowercase();
    let mut findings = Vec::new();

    if lower.contains("index of /") && lower.contains("parent directory") {
        findings.push(exposure(
            observation,
            "Directory listing enabled",
            Severity::Medium,
            Confidence::High,
            "The response matches common auto-index directory listing markers.",
            "Disable directory listing unless it is explicitly required.",
            "body markers: index of /; parent directory",
        ));
    }

    if path.ends_with(".map") && (lower.contains("\"sources\"") || lower.contains("\"sourcemap\""))
    {
        findings.push(exposure(
            observation,
            "Source map publicly accessible",
            Severity::Low,
            Confidence::High,
            "A production source map appears to expose source structure or source content.",
            "Review whether source maps should be public and avoid embedding secrets in source files.",
            "source-map JSON markers",
        ));
    }

    if contains_stack_trace(&lower) {
        findings.push(exposure(
            observation,
            "Application stack trace exposed",
            Severity::Medium,
            Confidence::Medium,
            "The response contains markers associated with a runtime stack trace.",
            "Return generic production error pages and keep diagnostic traces in protected logging systems.",
            "runtime stack-trace markers",
        ));
    }

    if sensitive_profile {
        if dotenv_signature(&path, text) {
            findings.push(exposure(
                observation,
                "Environment configuration exposed",
                Severity::Critical,
                Confidence::High,
                "The response path and body resemble a dotenv configuration file.",
                "Remove the file from the web root, rotate exposed secrets, and review access logs.",
                "dotenv key=value signature",
            ));
        } else if git_signature(&path, &lower) {
            findings.push(exposure(
                observation,
                "Git repository metadata exposed",
                Severity::High,
                Confidence::High,
                "The response resembles Git repository metadata.",
                "Block repository metadata at the web server and assess whether repository contents were retrievable.",
                "git metadata signature",
            ));
        } else if sql_signature(&path, &lower) {
            findings.push(exposure(
                observation,
                "Database dump exposed",
                Severity::Critical,
                Confidence::High,
                "The response resembles a SQL database dump.",
                "Remove the dump, rotate affected credentials, and initiate an incident review.",
                "SQL dump signature",
            ));
        } else if path.ends_with("phpinfo.php") && lower.contains("php version") {
            findings.push(exposure(
                observation,
                "phpinfo output exposed",
                Severity::High,
                Confidence::High,
                "A phpinfo page may disclose environment, module, and configuration details.",
                "Remove phpinfo pages from production systems.",
                "phpinfo response markers",
            ));
        }
    }

    findings
}

fn exposure(
    observation: &Observation,
    title: &str,
    severity: Severity,
    confidence: Confidence,
    description: &str,
    remediation: &str,
    evidence: &str,
) -> Finding {
    Finding::new(
        FindingKind::Exposure,
        severity,
        confidence,
        title,
        description,
        redact_url(&observation.final_url),
    )
    .with_evidence("http.response", format!("status={}; {evidence}", observation.status))
    .with_remediation(remediation)
    .with_tag("owasp:a05-security-misconfiguration")
}

fn dotenv_signature(path: &str, text: &str) -> bool {
    if !path.contains("/.env") {
        return false;
    }
    text.lines()
        .take(200)
        .filter(|line| {
            let line = line.trim();
            !line.is_empty()
                && !line.starts_with('#')
                && line.split_once('=').is_some_and(|(name, _)| {
                    !name.is_empty()
                        && name.chars().all(|character| {
                            character.is_ascii_uppercase()
                                || character == '_'
                                || character.is_ascii_digit()
                        })
                })
        })
        .count()
        >= 2
}

fn git_signature(path: &str, lower: &str) -> bool {
    (path.ends_with("/.git/config")
        && lower.contains("[core]")
        && lower.contains("repositoryformatversion"))
        || (path.ends_with("/.git/head") && lower.trim_start().starts_with("ref: refs/"))
}

fn sql_signature(path: &str, lower: &str) -> bool {
    (path.ends_with(".sql") || path.contains("backup"))
        && (lower.contains("create table") || lower.contains("insert into"))
}

fn contains_stack_trace(lower: &str) -> bool {
    (lower.contains("traceback (most recent call last)")
        || lower.contains("exception in thread")
        || lower.contains(" at system.")
        || lower.contains("stack trace:"))
        && lower.len() > 200
}
