use std::collections::BTreeMap;

use scopelynx::{
    analyzers,
    model::{DiscoverySource, Observation, ResponseClass},
};
use url::Url;

fn observation(url: &str) -> Result<Observation, Box<dyn std::error::Error>> {
    Ok(Observation {
        requested_url: Url::parse(url)?,
        final_url: Url::parse(url)?,
        redirect_chain: Vec::new(),
        source: DiscoverySource::Seed,
        depth: 0,
        status: 200,
        class: ResponseClass::Success,
        content_type: Some("text/html; charset=utf-8".into()),
        content_kind: scopelynx::http::content::ContentKind::Html,
        headers: BTreeMap::new(),
        elapsed_ms: 5,
        declared_body_length: Some(10),
        captured_body_length: 10,
        body_sha256: "fixture".into(),
        truncated: false,
        soft_404: false,
        soft_404_score: None,
        soft_404_reasons: Vec::new(),
        retry_count: 0,
        stored_body: None,
    })
}

#[test]
fn detects_react_and_password_form() -> Result<(), Box<dyn std::error::Error>> {
    let findings = analyzers::analyze(
        &observation("https://example.org/")?,
        Some(include_str!("fixtures/react_page.html")),
        false,
    );
    assert!(findings.iter().any(|finding| finding.title.contains("React")));
    assert!(findings.iter().any(|finding| finding.title == "Password form detected"));
    assert!(findings.iter().all(|finding| !finding.id.is_empty()));
    Ok(())
}

#[test]
fn flags_password_form_over_http() -> Result<(), Box<dyn std::error::Error>> {
    let findings = analyzers::analyze(
        &observation("http://example.org/login")?,
        Some("<form method='post'><input type='password'></form>"),
        false,
    );
    assert!(findings.iter().any(|finding| finding.title == "Password form served without HTTPS"));
    Ok(())
}

#[test]
fn soft_404_responses_never_produce_findings() -> Result<(), Box<dyn std::error::Error>> {
    let mut response = observation("https://example.org/config.json")?;
    response.soft_404 = true;
    response.headers.insert("server".into(), vec!["nginx".into()]);
    response.headers.insert("set-cookie".into(), vec!["session=<redacted>; SameSite=None".into()]);

    assert!(analyzers::analyze(&response, Some("<html>nginx</html>"), true).is_empty());
    Ok(())
}

#[test]
fn technology_findings_are_correlated_at_origin_scope() -> Result<(), Box<dyn std::error::Error>> {
    let mut root = observation("https://example.org/")?;
    root.headers.insert("server".into(), vec!["nginx".into()]);
    let mut path = observation("https://example.org/config.json")?;
    path.headers.insert("server".into(), vec!["nginx".into()]);

    let root_finding = analyzers::technologies::analyze(&root, "")
        .into_iter()
        .next()
        .ok_or("root technology finding missing")?;
    let path_finding = analyzers::technologies::analyze(&path, "")
        .into_iter()
        .next()
        .ok_or("path technology finding missing")?;
    assert_eq!(root_finding.id, path_finding.id);
    assert_eq!(root_finding.location, "https://example.org/");
    assert_eq!(path_finding.location, "https://example.org/");
    Ok(())
}
