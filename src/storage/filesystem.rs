use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use tokio::{fs, io::AsyncWriteExt};

use crate::error::{Result, io_error};

static RUN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub async fn create_run_directory(
    root: &Path,
    host: &str,
    started_at: DateTime<Utc>,
) -> Result<(PathBuf, String)> {
    let safe_host = sanitize_component(host, 255);
    let timestamp = started_at.format("%Y%m%dT%H%M%S%.3fZ").to_string();
    let sequence = RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let run_id = format!("{timestamp}-{}-{sequence}", std::process::id());
    fs::create_dir_all(root).await.map_err(|error| io_error(root, error))?;
    let host_directory = root.join(safe_host);
    if fs::try_exists(&host_directory).await.map_err(|error| io_error(&host_directory, error))? {
        let metadata = fs::symlink_metadata(&host_directory)
            .await
            .map_err(|error| io_error(&host_directory, error))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(crate::error::ScannerError::Scope(
                "output host component is not a regular directory".into(),
            ));
        }
    } else {
        fs::create_dir(&host_directory).await.map_err(|error| io_error(&host_directory, error))?;
    }
    let directory = host_directory.join(&run_id);
    fs::create_dir(&directory).await.map_err(|error| io_error(&directory, error))?;
    restrict_directory_permissions(&directory).await?;
    Ok((directory, run_id))
}

pub async fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).await.map_err(|error| io_error(parent, error))?;

    let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or("output");
    let temporary = parent.join(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .await
        .map_err(|error| io_error(&temporary, error))?;
    let write_result: Result<()> = async {
        file.write_all(data).await.map_err(|error| io_error(&temporary, error))?;
        file.flush().await.map_err(|error| io_error(&temporary, error))?;
        file.sync_all().await.map_err(|error| io_error(&temporary, error))?;
        Ok(())
    }
    .await;
    drop(file);
    if let Err(error) = write_result {
        let _cleanup = fs::remove_file(&temporary).await;
        return Err(error);
    }
    if let Err(error) = restrict_file_permissions(&temporary).await {
        let _cleanup = fs::remove_file(&temporary).await;
        return Err(error);
    }

    fs::rename(&temporary, path).await.map_err(|error| {
        let _cleanup = std::fs::remove_file(&temporary);
        io_error(path, error)
    })
}

pub async fn store_body(run_directory: &Path, hash: &str, body: &[u8]) -> Result<String> {
    let actual_hash = hex::encode(Sha256::digest(body));
    if hash.len() != 64
        || !hash.chars().all(|character| character.is_ascii_hexdigit())
        || !hash.eq_ignore_ascii_case(&actual_hash)
    {
        return Err(crate::error::ScannerError::InvalidConfig(
            "body digest is not a valid SHA-256 hash for the supplied content".into(),
        ));
    }
    let relative = PathBuf::from("bodies").join(format!("{actual_hash}.bin"));
    let path = run_directory.join(&relative);
    if fs::try_exists(&path).await.map_err(|error| io_error(&path, error))? {
        let metadata = fs::symlink_metadata(&path).await.map_err(|error| io_error(&path, error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(crate::error::ScannerError::Scope(
                "stored body path is not a regular file".into(),
            ));
        }
        let existing = fs::read(&path).await.map_err(|error| io_error(&path, error))?;
        if Sha256::digest(&existing) != Sha256::digest(body) {
            return Err(crate::error::ScannerError::Scope(
                "stored body hash collision or content mismatch".into(),
            ));
        }
    } else {
        write_atomic(&path, body).await?;
    }
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

fn sanitize_component(value: &str, maximum: usize) -> String {
    let mut value = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .take(maximum)
        .collect::<String>();
    if value.is_empty() {
        return "target".into();
    }
    let upper = value.to_ascii_uppercase();
    let reserved = matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (upper.len() == 4
            && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.as_bytes()[3].is_ascii_digit()
            && upper.as_bytes()[3] != b'0');
    if reserved {
        value.insert(0, '_');
    }
    value
}

#[cfg(unix)]
async fn restrict_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .await
        .map_err(|error| io_error(path, error))
}

#[cfg(not(unix))]
async fn restrict_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
async fn restrict_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .await
        .map_err(|error| io_error(path, error))
}

#[cfg(not(unix))]
async fn restrict_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
