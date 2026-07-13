use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    time::Instant,
};

use chrono::Utc;
use futures_util::{StreamExt, stream::FuturesUnordered};
use tracing::{debug, info, warn};
use url::Url;

use crate::{
    analyzers,
    config::ScanConfig,
    discovery::{self, DiscoveredUrl},
    engine::{
        ScanOutcome,
        queue::{RequestQueue, RequestTask},
        soft_404::Soft404Detector,
    },
    error::{Result, ScannerError},
    http::{HttpPolicy, ScannerHttpClient, content::ContentKind},
    model::{
        DiscoveredResource, DiscoverySource, Finding, LimitState, Observation, PolicySnapshot,
        ResponseClass, ScanErrorRecord, ScanReport, ScanStats, Severity,
    },
    scope::{ScopePolicy, redact_url},
    storage,
};

pub async fn run(config: ScanConfig) -> Result<ScanOutcome> {
    let started_at = Utc::now();
    let (run_directory, scan_id) = storage::filesystem::create_run_directory(
        &config.output_dir,
        &config.target.host,
        started_at,
    )
    .await?;

    let scope = ScopePolicy::new(config.target.clone(), &config.profile)
        .with_allowed_hosts(config.scope_hosts.clone());
    let http = ScannerHttpClient::new(scope.clone(), HttpPolicy::from(&config.profile));
    if config.progress {
        info!(
            target = %config.target.redacted(),
            profile = %config.profile.name,
            private_networks = config.profile.allow_private_networks,
            concurrency = config.profile.concurrency,
            requests_per_second = config.profile.requests_per_second,
            max_requests = config.profile.max_requests,
            "scan started"
        );
    }
    let soft_404 = build_soft_404_detector(&config, &http).await;

    let mut queue = RequestQueue::new(config.profile.max_discovered_urls);
    let mut discovered = BTreeSet::new();
    let mut observations = Vec::new();
    let mut findings = BTreeMap::<String, Finding>::new();
    let mut errors = Vec::new();
    let mut stats = ScanStats::default();
    let mut limits = LimitState::default();
    let mut completed_tasks = 0usize;
    let mut last_progress_at = Instant::now();

    enqueue(
        &mut queue,
        RequestTask {
            url: config.target.base_url.clone(),
            source: DiscoverySource::Seed,
            depth: 0,
            priority: 255,
        },
        &config,
        &scope,
        &mut limits,
    );

    let root = config.target.origin_root();
    if config.profile.discover_robots {
        enqueue_url(
            &mut queue,
            root.join("robots.txt")?,
            DiscoverySource::Robots,
            0,
            250,
            &config,
            &scope,
            &mut limits,
        );
    }
    if config.profile.discover_sitemap {
        enqueue_url(
            &mut queue,
            root.join("sitemap.xml")?,
            DiscoverySource::Sitemap,
            0,
            245,
            &config,
            &scope,
            &mut limits,
        );
    }

    for wordlist in &config.wordlists {
        match discovery::wordlist::load(
            &root,
            wordlist,
            config.profile.max_wordlist_bytes,
            config.profile.max_wordlist_entries,
        )
        .await
        {
            Ok(candidates) => {
                for candidate in candidates {
                    record_and_enqueue_candidate(
                        &mut queue,
                        &mut discovered,
                        candidate,
                        0,
                        &config,
                        &scope,
                        &mut limits,
                    );
                }
            }
            Err(error) => push_error(
                &mut errors,
                &mut limits,
                &config,
                "wordlist",
                wordlist.display().to_string(),
                error.to_string(),
            ),
        }
    }

    while !queue.is_empty() && !http.budget_exhausted() {
        let batch_size = config.profile.concurrency.min(queue.len());
        let mut futures = FuturesUnordered::new();

        for _ in 0..batch_size {
            let Some(task) = queue.pop() else {
                break;
            };
            let client = http.clone();
            stats.scheduled_tasks = stats.scheduled_tasks.saturating_add(1);
            futures.push(async move {
                let result = client.fetch(task.clone()).await;
                (task, result)
            });
        }

        if config.progress && (completed_tasks == 0 || last_progress_at.elapsed().as_secs() >= 1) {
            info!(
                phase = "dispatch",
                scheduled = stats.scheduled_tasks,
                completed = completed_tasks,
                active = futures.len(),
                queued = queue.len(),
                wire_requests = http.wire_requests(),
                findings = findings.len(),
                "scan progress"
            );
            last_progress_at = Instant::now();
        }

        while let Some((task, result)) = futures.next().await {
            match result {
                Ok(mut fetched) => {
                    let decision = soft_404.classify(fetched.observation.status, &fetched.body);
                    let explicit_successful_origin_seed = decision.is_soft_404
                        && (200..=299).contains(&fetched.observation.status)
                        && matches!(task.source, DiscoverySource::Seed)
                        && fetched.effective_url.path() == "/";
                    fetched.observation.soft_404 =
                        decision.is_soft_404 && !explicit_successful_origin_seed;
                    fetched.observation.soft_404_score = Some(decision.score);
                    fetched.observation.soft_404_reasons = decision.reasons;
                    if explicit_successful_origin_seed {
                        fetched.observation.soft_404_reasons.push(
                            "explicit successful origin seed retained as the requested landing representation"
                                .into(),
                        );
                    }
                    update_stats(&mut stats, &fetched.observation);

                    if config.store_bodies
                        && !fetched.body.is_empty()
                        && fetched.observation.content_kind.is_storable()
                    {
                        match storage::filesystem::store_body(
                            &run_directory,
                            &fetched.observation.body_sha256,
                            &fetched.body,
                        )
                        .await
                        {
                            Ok(relative_path) => {
                                fetched.observation.stored_body = Some(relative_path);
                            }
                            Err(error) => push_error(
                                &mut errors,
                                &mut limits,
                                &config,
                                "body-storage",
                                redact_url(&fetched.effective_url),
                                error.to_string(),
                            ),
                        }
                    }

                    let text = fetched.text_lossy();
                    for finding in analyzers::analyze(
                        &fetched.observation,
                        text.as_deref(),
                        config.profile.sensitive_paths,
                    ) {
                        if findings.len() >= config.profile.max_findings {
                            limits.finding_limit_reached = true;
                            break;
                        }
                        if let Entry::Vacant(entry) = findings.entry(finding.id.clone()) {
                            if config.progress && finding.severity >= Severity::Medium {
                                info!(
                                    severity = ?finding.severity,
                                    confidence = ?finding.confidence,
                                    title = %finding.title,
                                    location = %finding.location,
                                    "finding discovered"
                                );
                            }
                            entry.insert(finding);
                        }
                    }

                    if should_discover(&fetched.observation)
                        && task.depth < config.profile.max_depth
                    {
                        if let Some(body) = text.as_deref() {
                            match discover_from_response(
                                &config,
                                &fetched.effective_url,
                                fetched.observation.content_type.as_deref(),
                                fetched.observation.content_kind,
                                body,
                            ) {
                                Ok(candidates) => {
                                    for candidate in candidates {
                                        record_and_enqueue_candidate(
                                            &mut queue,
                                            &mut discovered,
                                            candidate,
                                            task.depth + 1,
                                            &config,
                                            &scope,
                                            &mut limits,
                                        );
                                    }
                                }
                                Err(error) => push_error(
                                    &mut errors,
                                    &mut limits,
                                    &config,
                                    "discovery",
                                    redact_url(&fetched.effective_url),
                                    error.to_string(),
                                ),
                            }
                        }
                    }

                    debug!(
                        url = %redact_url(&task.url),
                        status = fetched.observation.status,
                        soft_404 = fetched.observation.soft_404,
                        "request completed"
                    );
                    observations.push(fetched.observation);
                }
                Err(ScannerError::RequestBudgetExhausted) => {
                    limits.request_budget_exhausted = true;
                }
                Err(error) => {
                    stats.failed = stats.failed.saturating_add(1);
                    warn!(url = %redact_url(&task.url), %error, "request failed");
                    push_error(
                        &mut errors,
                        &mut limits,
                        &config,
                        "request",
                        redact_url(&task.url),
                        error.to_string(),
                    );
                }
            }

            completed_tasks = completed_tasks.saturating_add(1);
            if config.progress && last_progress_at.elapsed().as_secs() >= 1 {
                info!(
                    phase = "receive",
                    scheduled = stats.scheduled_tasks,
                    completed = completed_tasks,
                    active = futures.len(),
                    queued = queue.len(),
                    wire_requests = http.wire_requests(),
                    successful = stats.successful,
                    failed = stats.failed,
                    findings = findings.len(),
                    "scan progress"
                );
                last_progress_at = Instant::now();
            }
        }
    }

    if http.budget_exhausted() && !queue.is_empty() {
        limits.request_budget_exhausted = true;
    }

    stats.wire_requests = http.wire_requests();
    stats.unique_urls = queue.unique_count();
    stats.queued_peak = queue.peak();

    let mut findings = findings.into_values().collect::<Vec<_>>();
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| right.confidence.cmp(&left.confidence))
            .then_with(|| left.title.cmp(&right.title))
            .then_with(|| left.location.cmp(&right.location))
    });
    observations.sort_by(|left, right| {
        left.final_url
            .as_str()
            .cmp(right.final_url.as_str())
            .then_with(|| left.status.cmp(&right.status))
    });
    errors.sort_by(|left, right| {
        left.stage
            .cmp(&right.stage)
            .then_with(|| left.location.cmp(&right.location))
            .then_with(|| left.message.cmp(&right.message))
    });

    let finished_at = Utc::now();
    let no_usable_response = observations.is_empty() && stats.failed > 0;
    let complete = !limits.request_budget_exhausted
        && !limits.discovery_limit_reached
        && !limits.error_limit_reached
        && !limits.finding_limit_reached
        && !no_usable_response;
    let abort_reason = if limits.request_budget_exhausted {
        Some("wire-request budget exhausted".into())
    } else if no_usable_response {
        Some("no usable HTTP response".into())
    } else {
        None
    };
    if config.progress {
        info!(
            phase = "complete",
            scheduled = stats.scheduled_tasks,
            completed = completed_tasks,
            queued = queue.len(),
            wire_requests = stats.wire_requests,
            successful = stats.successful,
            failed = stats.failed,
            findings = findings.len(),
            "scan progress"
        );
    }
    info!(wire_requests = stats.wire_requests, findings = findings.len(), "scan completed");

    Ok(ScanOutcome {
        run_directory,
        report: ScanReport {
            schema_version: 4,
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            scan_id,
            config_fingerprint: config.fingerprint()?,
            target: config.target.redacted(),
            profile: config.profile.name.clone(),
            policy: PolicySnapshot::from_profile(&config.profile, config.store_bodies),
            started_at,
            finished_at,
            stats,
            limits,
            observations,
            findings,
            discovered_resources: discovered.into_iter().collect(),
            errors,
            complete,
            abort_reason,
        },
    })
}

async fn build_soft_404_detector(
    config: &ScanConfig,
    client: &ScannerHttpClient,
) -> Soft404Detector {
    let mut samples = Vec::new();
    let mut probes = FuturesUnordered::new();
    let probe_count = config.profile.max_requests.saturating_sub(1).min(3);
    let nonce = format!("{}_{}", std::process::id(), Utc::now().timestamp_micros());
    let probe_paths = [
        format!("__smart_scanner_missing_{nonce}"),
        format!(".well-known/__smart_scanner_missing_{nonce}.json"),
        format!("__smart_scanner_missing_{nonce}/nested/resource.html"),
    ];
    for (index, probe) in probe_paths.into_iter().take(probe_count).enumerate() {
        if client.budget_exhausted() {
            break;
        }
        let Ok(url) = config.target.origin_root().join(&probe) else {
            continue;
        };
        let task =
            RequestTask { url, source: DiscoverySource::Soft404Probe, depth: 0, priority: 0 };
        if config.progress {
            info!(
                phase = "soft-404-baseline",
                probe = index + 1,
                probes = probe_count,
                "scan progress"
            );
        }
        let probe_client = client.clone();
        probes.push(async move { probe_client.fetch(task).await });
    }
    while let Some(result) = probes.next().await {
        if let Ok(response) = result {
            samples.push((response.observation.status, response.body));
        }
    }
    if config.progress {
        info!(
            phase = "soft-404-baseline",
            usable_samples = samples.len(),
            wire_requests = client.wire_requests(),
            "scan progress"
        );
    }
    Soft404Detector::from_samples(samples)
}

fn discover_from_response(
    config: &ScanConfig,
    base: &Url,
    content_type: Option<&str>,
    content_kind: ContentKind,
    body: &str,
) -> Result<Vec<DiscoveredUrl>> {
    let content_type = content_type.unwrap_or_default().to_ascii_lowercase();
    let path = base.path().to_ascii_lowercase();
    let limit = config.profile.max_candidates_per_response;
    let mut candidates = Vec::new();

    if matches!(content_kind, ContentKind::Rss | ContentKind::Atom) {
        candidates.extend(discovery::feeds::discover(base, body, limit)?);
    }
    if matches!(content_kind, ContentKind::WebManifest) {
        candidates.extend(discovery::manifests::discover(base, body, limit)?);
    }

    if path.ends_with("/robots.txt") || path == "/robots.txt" {
        candidates.extend(discovery::robots::discover(base, body, limit));
    }
    let body_prefix = body.chars().take(2_048).collect::<String>().to_ascii_lowercase();
    let sitemap_document = body_prefix.contains("<urlset") || body_prefix.contains("<sitemapindex");
    if config.profile.discover_sitemap
        && (path.ends_with("sitemap.xml")
            || path.contains("sitemap")
            || (content_type.contains("xml") && sitemap_document))
    {
        candidates.extend(discovery::sitemap::discover(base, body, limit)?);
    }
    if config.profile.discover_html
        && (matches!(content_kind, ContentKind::Html)
            || content_type.contains("html")
            || body_prefix.contains("<!doctype html")
            || body_prefix.contains("<html"))
    {
        candidates.extend(discovery::html::discover(base, body, limit));
        if config.profile.discover_javascript {
            candidates.extend(discovery::javascript::discover(base, body, limit));
        }
    } else if config.profile.discover_javascript
        && (matches!(content_kind, ContentKind::JavaScript)
            || content_type.contains("javascript")
            || path.ends_with(".js")
            || path.ends_with(".mjs"))
    {
        candidates.extend(discovery::javascript::discover(base, body, limit));
    }

    let mut deduplicated = discovery::deduplicate(candidates);
    deduplicated.truncate(limit);
    Ok(deduplicated)
}

fn record_and_enqueue_candidate(
    queue: &mut RequestQueue,
    discovered: &mut BTreeSet<DiscoveredResource>,
    candidate: DiscoveredUrl,
    depth: usize,
    config: &ScanConfig,
    scope: &ScopePolicy,
    limits: &mut LimitState,
) {
    if !config.profile.sensitive_paths && discovery::is_sensitive_path(&candidate.url) {
        return;
    }
    if discovered.len() >= config.profile.max_discovered_urls {
        limits.discovery_limit_reached = true;
        return;
    }
    discovered.insert(DiscoveredResource {
        url: redact_url(&candidate.url),
        source: candidate.source,
        depth,
    });
    enqueue_url(
        queue,
        candidate.url,
        candidate.source,
        depth,
        candidate.priority,
        config,
        scope,
        limits,
    );
}

#[allow(clippy::too_many_arguments)]
fn enqueue_url(
    queue: &mut RequestQueue,
    url: Url,
    source: DiscoverySource,
    depth: usize,
    priority: u8,
    config: &ScanConfig,
    scope: &ScopePolicy,
    limits: &mut LimitState,
) {
    enqueue(queue, RequestTask { url, source, depth, priority }, config, scope, limits);
}

fn enqueue(
    queue: &mut RequestQueue,
    task: RequestTask,
    config: &ScanConfig,
    scope: &ScopePolicy,
    limits: &mut LimitState,
) {
    if task.depth > config.profile.max_depth
        || !scope.allows_url(&task.url)
        || discovery::is_potentially_destructive(&task.url)
        || (!config.profile.sensitive_paths && discovery::is_sensitive_path(&task.url))
    {
        return;
    }
    if queue.at_capacity() {
        limits.discovery_limit_reached = true;
        return;
    }
    if !queue.push(task) && queue.at_capacity() {
        limits.discovery_limit_reached = true;
    }
}

fn should_discover(observation: &Observation) -> bool {
    !observation.soft_404
        && matches!(observation.class, ResponseClass::Success)
        && !observation.truncated
}

fn update_stats(stats: &mut ScanStats, observation: &Observation) {
    *stats.status_counts.entry(observation.status).or_default() += 1;
    stats.redirects = stats.redirects.saturating_add(observation.redirect_chain.len());
    stats.captured_body_bytes =
        stats.captured_body_bytes.saturating_add(observation.captured_body_length as u64);
    if observation.truncated {
        stats.truncated_bodies = stats.truncated_bodies.saturating_add(1);
    }
    if observation.soft_404 {
        stats.soft_404 = stats.soft_404.saturating_add(1);
        return;
    }
    match observation.class {
        ResponseClass::Success => stats.successful = stats.successful.saturating_add(1),
        ResponseClass::NotModified => {
            stats.not_modified = stats.not_modified.saturating_add(1);
        }
        ResponseClass::Redirect => stats.redirects = stats.redirects.saturating_add(1),
        ResponseClass::AuthenticationRequired => {
            stats.authentication_required = stats.authentication_required.saturating_add(1);
        }
        ResponseClass::Forbidden => stats.forbidden = stats.forbidden.saturating_add(1),
        ResponseClass::NotFound => stats.not_found = stats.not_found.saturating_add(1),
        ResponseClass::RateLimited => stats.rate_limited = stats.rate_limited.saturating_add(1),
        ResponseClass::ServerError => stats.server_errors = stats.server_errors.saturating_add(1),
        ResponseClass::ClientError | ResponseClass::Other => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn push_error(
    errors: &mut Vec<ScanErrorRecord>,
    limits: &mut LimitState,
    config: &ScanConfig,
    stage: &str,
    location: String,
    message: String,
) {
    if errors.len() >= config.profile.max_errors {
        limits.error_limit_reached = true;
        return;
    }
    errors.push(ScanErrorRecord {
        stage: stage.to_string(),
        location,
        message: crate::redaction::redact_text(&message).chars().take(2048).collect(),
    });
}
