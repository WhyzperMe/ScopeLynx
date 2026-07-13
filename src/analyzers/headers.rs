use crate::{
    model::{Confidence, Finding, FindingKind, Observation, Severity},
    scope::redact_url,
};

#[must_use]
pub fn analyze(observation: &Observation) -> Vec<Finding> {
    if observation.soft_404 || observation.status >= 400 || !is_document(observation) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let location = redact_url(&observation.final_url);
    let csp = first_header(observation, "content-security-policy");

    if csp.is_none() {
        findings.push(
            missing_header(
                observation,
                "Content-Security-Policy",
                Severity::Low,
                "Define a restrictive CSP tailored to the application.",
            )
            .with_tag("owasp:a05-security-misconfiguration"),
        );
    }
    if first_header(observation, "x-content-type-options")
        .is_none_or(|value| !value.eq_ignore_ascii_case("nosniff"))
    {
        findings.push(
            Finding::new(
                FindingKind::SecurityHeader,
                Severity::Low,
                Confidence::High,
                "MIME sniffing protection missing or invalid",
                "The response does not provide X-Content-Type-Options: nosniff.",
                location.clone(),
            )
            .with_evidence(
                "response.headers.x-content-type-options",
                first_header(observation, "x-content-type-options").unwrap_or("<missing>"),
            )
            .with_remediation("Set X-Content-Type-Options: nosniff."),
        );
    }
    if first_header(observation, "referrer-policy").is_none() {
        findings.push(missing_header(
            observation,
            "Referrer-Policy",
            Severity::Info,
            "Set an explicit Referrer-Policy appropriate for the application.",
        ));
    }
    if first_header(observation, "permissions-policy").is_none() {
        findings.push(missing_header(
            observation,
            "Permissions-Policy",
            Severity::Info,
            "Disable browser capabilities that the application does not require.",
        ));
    }

    let has_frame_ancestors =
        csp.map(|value| value.to_ascii_lowercase().contains("frame-ancestors")).unwrap_or(false);
    if !has_frame_ancestors && first_header(observation, "x-frame-options").is_none() {
        findings.push(
            Finding::new(
                FindingKind::SecurityHeader,
                Severity::Low,
                Confidence::High,
                "Clickjacking protection not declared",
                "Neither CSP frame-ancestors nor X-Frame-Options is present.",
                location.clone(),
            )
            .with_evidence("response.headers", "frame-ancestors=<missing>; x-frame-options=<missing>")
            .with_remediation("Prefer CSP frame-ancestors and optionally retain X-Frame-Options for legacy clients."),
        );
    }

    if observation.final_url.scheme() == "https" {
        match first_header(observation, "strict-transport-security") {
            None => findings.push(missing_header(
                observation,
                "Strict-Transport-Security",
                Severity::Low,
                "After validating complete HTTPS coverage, deploy HSTS.",
            )),
            Some(value) if !valid_hsts(value) => findings.push(
                Finding::new(
                    FindingKind::SecurityHeader,
                    Severity::Low,
                    Confidence::High,
                    "HSTS header appears ineffective",
                    "Strict-Transport-Security is present but does not contain a positive max-age value.",
                    location.clone(),
                )
                .with_evidence("response.headers.strict-transport-security", value)
                .with_remediation("Set a positive max-age and evaluate includeSubDomains and preload carefully."),
            ),
            Some(_) => {}
        }
    }

    if first_header(observation, "access-control-allow-origin") == Some("*")
        && first_header(observation, "access-control-allow-credentials")
            .is_some_and(|value| value.eq_ignore_ascii_case("true"))
    {
        findings.push(
            Finding::new(
                FindingKind::SecurityHeader,
                Severity::Medium,
                Confidence::High,
                "Inconsistent credentialed CORS policy",
                "The response combines wildcard Access-Control-Allow-Origin with credential allowance.",
                location,
            )
            .with_evidence("response.headers.cors", "allow-origin=*; allow-credentials=true")
            .with_remediation("Return a validated explicit origin when credentials are allowed."),
        );
    }

    findings
}

fn missing_header(
    observation: &Observation,
    header: &str,
    severity: Severity,
    remediation: &str,
) -> Finding {
    Finding::new(
        FindingKind::SecurityHeader,
        severity,
        Confidence::High,
        format!("{header} header missing"),
        format!("The HTML response does not include the {header} header."),
        redact_url(&observation.final_url),
    )
    .with_evidence("response.headers", format!("{header}: <missing>"))
    .with_remediation(remediation)
}

fn first_header<'a>(observation: &'a Observation, name: &str) -> Option<&'a str> {
    observation.headers.get(name).and_then(|values| values.first()).map(String::as_str)
}

fn valid_hsts(value: &str) -> bool {
    value.split(';').any(|directive| {
        directive.trim().split_once('=').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("max-age")
                && value.trim().parse::<u64>().is_ok_and(|seconds| seconds > 0)
        })
    })
}

fn is_document(observation: &Observation) -> bool {
    observation
        .content_type
        .as_deref()
        .map(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("text/html") || value.contains("application/xhtml")
        })
        .unwrap_or(false)
}
