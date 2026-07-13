mod support;

use scopelynx::{cli::ReportFormat, config::ScanConfig, engine, target::Target};
use tempfile::tempdir;

use support::{TestServer, local_profile};

#[tokio::test]
async fn soft_404_probes_share_the_wire_budget() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServer::start().await?;
    let directory = tempdir()?;
    let mut profile = local_profile();
    profile.max_requests = 2;
    let config = ScanConfig {
        target: Target::parse(&server.url("/ok"))?,
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
    assert_eq!(outcome.report.stats.wire_requests, 2);
    assert!(outcome.report.limits.request_budget_exhausted);
    assert!(!outcome.report.complete);
    server.stop().await;
    Ok(())
}
