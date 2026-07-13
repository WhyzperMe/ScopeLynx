mod support;

use scopelynx::{cli::ReportFormat, config::ScanConfig, engine, report, target::Target};
use tempfile::tempdir;

use support::{TestServer, local_profile};

#[tokio::test]
async fn full_local_scan_writes_redacted_deterministic_report_views()
-> Result<(), Box<dyn std::error::Error>> {
    let server = TestServer::start().await?;
    let directory = tempdir()?;
    let mut profile = local_profile();
    profile.max_requests = 20;
    let config = ScanConfig {
        target: Target::parse(&server.url("/listing?token=raw-secret"))?,
        profile,
        wordlists: Vec::new(),
        output_dir: directory.path().to_path_buf(),
        authorized: true,
        store_bodies: false,
        scope_hosts: Vec::new(),
        formats: vec![ReportFormat::All],
        dry_run: false,
        fail_on: None,
        progress: false,
    };

    let outcome = engine::run_scan(config).await?;
    assert!(
        outcome.report.findings.iter().any(|finding| finding.title == "Directory listing enabled")
    );
    let first = serde_json::to_vec_pretty(&outcome.report)?;
    let second = serde_json::to_vec_pretty(&outcome.report)?;
    assert_eq!(first, second);
    assert!(!String::from_utf8_lossy(&first).contains("raw-secret"));

    report::write_all(&outcome.report, &outcome.run_directory, &[ReportFormat::All]).await?;
    for name in ["report.json", "report.md", "report.sarif", "summary.txt"] {
        assert!(outcome.run_directory.join(name).is_file());
    }
    let markdown = tokio::fs::read_to_string(outcome.run_directory.join("report.md")).await?;
    assert!(markdown.contains("## HTTP Status Distribution"));
    assert!(markdown.contains("| 200 |"));
    let reloaded = report::json::read(&outcome.run_directory.join("report.json")).await?;
    assert_eq!(reloaded.schema_version, 4);
    assert_eq!(reloaded.scan_id, outcome.report.scan_id);
    server.stop().await;
    Ok(())
}
