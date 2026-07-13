use clap::Parser;
use scopelynx::{
    cli::{Cli, Command},
    config::ScanConfig,
};

#[tokio::test]
async fn authorized_profile_enables_lan_and_live_progress_by_default()
-> Result<(), Box<dyn std::error::Error>> {
    let profile = format!("{}/profiles/authorized-sensitive.toml", env!("CARGO_MANIFEST_DIR"));
    let cli = Cli::try_parse_from([
        "scopelynx",
        "scan",
        "https://192.168.1.101/",
        "--profile",
        &profile,
        "--authorized",
        "--dry-run",
    ])?;
    let Command::Scan(args) = cli.command else {
        return Err("scan command was not parsed".into());
    };
    let config = ScanConfig::from_args(args).await?;

    assert!(config.profile.allow_private_networks);
    assert!(config.progress);
    assert_eq!(config.profile.concurrency, 32);
    assert_eq!(config.profile.requests_per_second, 40);
    Ok(())
}

#[tokio::test]
async fn no_progress_disables_live_progress() -> Result<(), Box<dyn std::error::Error>> {
    let profile = format!("{}/profiles/authorized-sensitive.toml", env!("CARGO_MANIFEST_DIR"));
    let cli = Cli::try_parse_from([
        "scopelynx",
        "scan",
        "http://10.0.0.5/",
        "--profile",
        &profile,
        "--authorized",
        "--no-progress",
        "--dry-run",
    ])?;
    let Command::Scan(args) = cli.command else {
        return Err("scan command was not parsed".into());
    };
    let config = ScanConfig::from_args(args).await?;

    assert!(!config.progress);
    Ok(())
}
