use scopelynx::storage::filesystem;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

#[tokio::test]
async fn atomic_write_and_content_addressed_body_storage_work()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let report = directory.path().join("report.json");
    filesystem::write_atomic(&report, b"{\"ok\":true}").await?;
    assert_eq!(tokio::fs::read(&report).await?, b"{\"ok\":true}");

    let body = b"bounded test body";
    let hash = hex::encode(Sha256::digest(body));
    let first = filesystem::store_body(directory.path(), &hash, body).await?;
    let second = filesystem::store_body(directory.path(), &hash, body).await?;
    assert_eq!(first, second);
    assert_eq!(tokio::fs::read(directory.path().join(first)).await?, body);
    Ok(())
}

#[tokio::test]
async fn rejects_mismatched_body_digest() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let result = filesystem::store_body(directory.path(), &"0".repeat(64), b"different").await;
    assert!(result.is_err());
    Ok(())
}
