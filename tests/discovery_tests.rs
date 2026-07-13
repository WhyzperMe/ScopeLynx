use scopelynx::discovery;
use url::Url;

#[test]
fn extracts_html_urls_without_submitting_post_forms() -> Result<(), Box<dyn std::error::Error>> {
    let base = Url::parse("https://example.org/")?;
    let found = discovery::html::discover(&base, include_str!("fixtures/react_page.html"), 100);
    let urls = found.iter().map(|item| item.url.as_str()).collect::<Vec<_>>();

    assert!(urls.contains(&"https://example.org/dashboard"));
    assert!(urls.contains(&"https://example.org/static/react.production.min.js"));
    assert!(!urls.contains(&"https://example.org/login"));
    Ok(())
}

#[test]
fn parses_robots_and_sitemap() -> Result<(), Box<dyn std::error::Error>> {
    let base = Url::parse("https://example.org/")?;
    let robots = discovery::robots::discover(&base, include_str!("fixtures/robots.txt"), 100);
    assert_eq!(robots.len(), 2);

    let sitemap = discovery::sitemap::discover(&base, include_str!("fixtures/sitemap.xml"), 100)?;
    assert_eq!(sitemap.len(), 2);
    Ok(())
}

#[test]
fn javascript_discovery_limits_results() -> Result<(), Box<dyn std::error::Error>> {
    let base = Url::parse("https://example.org/app.js")?;
    let found = discovery::javascript::discover(
        &base,
        "fetch('/api/v1/users'); fetch('/api/v1/admin');",
        1,
    );
    assert_eq!(found.len(), 1);
    Ok(())
}

#[test]
fn discovers_json_ld_feed_and_manifest_urls() -> Result<(), Box<dyn std::error::Error>> {
    let base = Url::parse("https://example.org/")?;
    let html = r#"<script type="application/ld+json">{"url":"/company"}</script>"#;
    let html_urls = discovery::html::discover(&base, html, 20);
    assert!(html_urls.iter().any(|candidate| candidate.url.path() == "/company"));

    let feed = r#"<feed xmlns="http://www.w3.org/2005/Atom"><link href="/entry"/></feed>"#;
    let feed_urls = discovery::feeds::discover(&base, feed, 20)?;
    assert!(feed_urls.iter().any(|candidate| candidate.url.path() == "/entry"));

    let manifest = r#"{"start_url":"/app","icons":[{"src":"/icon.png"}]}"#;
    let manifest_urls = discovery::manifests::discover(&base, manifest, 20)?;
    assert_eq!(manifest_urls.len(), 2);
    Ok(())
}
