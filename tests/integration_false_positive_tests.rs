mod support;

use scopelynx::{cli::ReportFormat, config::ScanConfig, engine, target::Target};
use tempfile::tempdir;

use support::{TestServer, local_profile};

#[tokio::test]
async fn catch_all_200_page_keeps_seed_and_suppresses_path_false_positives()
-> Result<(), Box<dyn std::error::Error>> {
    let server = TestServer::start_catch_all().await?;
    let directory = tempdir()?;
    let mut profile = local_profile();
    profile.max_requests = 20;
    profile.sensitive_paths = true;
    let config = ScanConfig {
        target: Target::parse(&server.url("/"))?,
        profile,
        wordlists: Vec::new(),
        output_dir: directory.path().to_path_buf(),
        authorized: true,
        store_bodies: false,
        scope_hosts: Vec::new(),
        formats: vec![ReportFormat::Json],
        dry_run: false,
        fail_on: None,
        progress: false,
    };

    let outcome = engine::run_scan(config).await?;
    let seed = outcome
        .report
        .observations
        .iter()
        .find(|observation| observation.final_url.path() == "/")
        .ok_or("seed observation missing")?;
    assert!(!seed.soft_404);
    assert_eq!(seed.status, 200);

    for path in ["/config.json", "/backup.zip", "/robots.txt", "/sitemap.xml"] {
        let observation = outcome
            .report
            .observations
            .iter()
            .find(|observation| observation.final_url.path() == path)
            .ok_or("catch-all observation missing")?;
        assert!(observation.soft_404, "{path} should be a semantic soft 404");
        assert_eq!(observation.status, 200);
    }

    assert_eq!(outcome.report.stats.successful, 1);
    assert_eq!(outcome.report.stats.status_counts.get(&200).copied(), Some(5));
    assert_eq!(outcome.report.stats.soft_404, 4);
    assert!(outcome.report.findings.iter().all(|finding| finding.location == server.url("/")));
    let technologies = outcome
        .report
        .findings
        .iter()
        .filter(|finding| finding.title == "Technology detected: nginx")
        .collect::<Vec<_>>();
    assert_eq!(technologies.len(), 1);
    assert_eq!(technologies[0].location, server.url("/"));

    server.stop().await;
    Ok(())
}
