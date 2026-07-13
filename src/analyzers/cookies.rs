use crate::{
    model::{Confidence, Finding, FindingKind, Observation, Severity},
    scope::redact_url,
};

#[must_use]
pub fn analyze(observation: &Observation) -> Vec<Finding> {
    let Some(cookies) = observation.headers.get("set-cookie") else {
        return Vec::new();
    };
    let mut findings = Vec::new();

    for cookie in cookies {
        let name = cookie.split_once('=').map_or("<unknown>", |(name, _)| name).trim();
        let attributes = cookie.split(';').skip(1).map(str::trim).collect::<Vec<_>>();
        let has_secure = has_attribute(&attributes, "secure");
        let has_http_only = has_attribute(&attributes, "httponly");
        let same_site = attribute_value(&attributes, "samesite");
        let location = redact_url(&observation.final_url);

        if observation.final_url.scheme() == "https" && !has_secure {
            findings.push(
                Finding::new(
                    FindingKind::Cookie,
                    Severity::Medium,
                    Confidence::High,
                    format!("Cookie '{name}' lacks Secure"),
                    "A cookie set over HTTPS is not marked Secure.",
                    location.clone(),
                )
                .with_evidence("response.set-cookie", format!("{name}; Secure=<missing>"))
                .with_remediation("Mark security-sensitive cookies Secure."),
            );
        }
        if !has_http_only {
            findings.push(
                Finding::new(
                    FindingKind::Cookie,
                    Severity::Low,
                    Confidence::Medium,
                    format!("Cookie '{name}' lacks HttpOnly"),
                    "The cookie is accessible to client-side JavaScript unless the application intentionally requires this.",
                    location.clone(),
                )
                .with_evidence("response.set-cookie", format!("{name}; HttpOnly=<missing>"))
                .with_remediation("Mark session and authentication cookies HttpOnly."),
            );
        }
        match same_site {
            None => findings.push(
                Finding::new(
                    FindingKind::Cookie,
                    Severity::Low,
                    Confidence::Medium,
                    format!("Cookie '{name}' has no explicit SameSite policy"),
                    "The cookie does not declare an explicit SameSite attribute.",
                    location.clone(),
                )
                .with_evidence("response.set-cookie", format!("{name}; SameSite=<missing>"))
                .with_remediation("Set SameSite=Lax or Strict where compatible."),
            ),
            Some(value) if value.eq_ignore_ascii_case("none") && !has_secure => findings.push(
                Finding::new(
                    FindingKind::Cookie,
                    Severity::Medium,
                    Confidence::High,
                    format!("Cookie '{name}' uses SameSite=None without Secure"),
                    "Modern browsers require Secure for cookies using SameSite=None.",
                    location,
                )
                .with_evidence(
                    "response.set-cookie",
                    format!("{name}; SameSite=None; Secure=<missing>"),
                )
                .with_remediation("Add Secure or choose a stricter SameSite policy."),
            ),
            Some(_) => {}
        }
    }

    findings
}

fn has_attribute(attributes: &[&str], name: &str) -> bool {
    attributes.iter().any(|attribute| attribute.eq_ignore_ascii_case(name))
}

fn attribute_value<'a>(attributes: &'a [&str], name: &str) -> Option<&'a str> {
    attributes.iter().find_map(|attribute| {
        let (attribute_name, value) = attribute.split_once('=')?;
        attribute_name.trim().eq_ignore_ascii_case(name).then_some(value.trim())
    })
}
