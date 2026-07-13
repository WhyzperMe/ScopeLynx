mod support;

use scopelynx::{
    engine::queue::RequestTask,
    error::ScannerError,
    http::{HttpPolicy, ScannerHttpClient},
    model::DiscoverySource,
    scope::ScopePolicy,
    target::Target,
};
use url::Url;

use support::{TestServer, local_profile};

fn task(url: &str) -> Result<RequestTask, url::ParseError> {
    Ok(RequestTask {
        url: Url::parse(url)?,
        source: DiscoverySource::Seed,
        depth: 0,
        priority: 255,
    })
}

#[tokio::test]
async fn retries_are_bounded_and_counted_as_wire_requests() -> Result<(), Box<dyn std::error::Error>>
{
    let server = TestServer::start().await?;
    let mut profile = local_profile();
    profile.max_requests = 3;
    profile.max_retries = 2;
    let target = Target::parse(&server.url("/retry"))?;
    let client =
        ScannerHttpClient::new(ScopePolicy::new(target, &profile), HttpPolicy::from(&profile));

    let response = client.fetch(task(&server.url("/retry"))?).await?;
    assert_eq!(response.observation.status, 200);
    assert_eq!(response.observation.retry_count, 2);
    assert_eq!(client.wire_requests(), 3);
    assert_eq!(server.request_count("/retry"), 3);
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn retry_cannot_overrun_global_budget() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServer::start().await?;
    let mut profile = local_profile();
    profile.max_requests = 2;
    profile.max_retries = 5;
    let target = Target::parse(&server.url("/always-503"))?;
    let client =
        ScannerHttpClient::new(ScopePolicy::new(target, &profile), HttpPolicy::from(&profile));

    let error = client
        .fetch(task(&server.url("/always-503"))?)
        .await
        .err()
        .ok_or("expected budget error")?;
    assert!(matches!(error, ScannerError::RequestBudgetExhausted));
    assert_eq!(client.wire_requests(), 2);
    assert_eq!(server.request_count("/always-503"), 2);
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn retry_after_on_429_is_honored_and_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServer::start().await?;
    let mut profile = local_profile();
    profile.max_requests = 2;
    profile.max_retries = 1;
    let target = Target::parse(&server.url("/rate-limit"))?;
    let client =
        ScannerHttpClient::new(ScopePolicy::new(target, &profile), HttpPolicy::from(&profile));

    let response = client.fetch(task(&server.url("/rate-limit"))?).await?;
    assert_eq!(response.observation.status, 200);
    assert_eq!(response.observation.retry_count, 1);
    assert_eq!(client.wire_requests(), 2);
    server.stop().await;
    Ok(())
}
