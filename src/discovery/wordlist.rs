use std::{collections::BTreeSet, path::Path};

use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
};
use url::Url;

use crate::{
    error::{Result, ScannerError, io_error},
    model::DiscoverySource,
};

use super::{DiscoveredUrl, resolve_http_url};

pub async fn load(
    base: &Url,
    path: &Path,
    max_bytes: usize,
    max_entries: usize,
) -> Result<Vec<DiscoveredUrl>> {
    let metadata = tokio::fs::metadata(path).await.map_err(|error| io_error(path, error))?;
    if metadata.len() > max_bytes as u64 {
        return Err(ScannerError::Limit(format!(
            "wordlist exceeds {} bytes: {}",
            max_bytes,
            path.display()
        )));
    }

    let file = File::open(path).await.map_err(|error| io_error(path, error))?;
    let mut lines = BufReader::new(file).lines();
    let mut unique = BTreeSet::new();
    let mut output = Vec::new();

    while let Some(line) = lines.next_line().await.map_err(|error| io_error(path, error))? {
        if output.len() >= max_entries {
            break;
        }
        let value = line.trim().trim_start_matches('\u{feff}');
        if value.is_empty() || value.starts_with('#') || value.len() > 8_192 {
            continue;
        }
        let normalized =
            if value.starts_with('/') { value.to_string() } else { format!("/{value}") };
        if !unique.insert(normalized.clone()) {
            continue;
        }
        if let Some(url) = resolve_http_url(base, &normalized) {
            output.push(DiscoveredUrl {
                url,
                source: DiscoverySource::Wordlist,
                priority: 80,
                relation: "wordlist",
            });
        }
    }

    Ok(output)
}
