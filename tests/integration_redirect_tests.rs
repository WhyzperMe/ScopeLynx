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
async fn redirect_hops_consume_wire_budget() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServer::start().await?;
    let mut profile = local_profile();
    profile.max_requests = 1;
    let target = Target::parse(&server.url("/redirect"))?;
    let client =
        ScannerHttpClient::new(ScopePolicy::new(target, &profile), HttpPolicy::from(&profile));

    let error =
        client.fetch(task(&server.url("/redirect"))?).await.err().ok_or("expected budget error")?;
    assert!(matches!(error, ScannerError::RequestBudgetExhausted));
    assert_eq!(client.wire_requests(), 1);
    assert_eq!(server.request_count("/redirect"), 1);
    assert_eq!(server.request_count("/ok"), 0);
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn cross_origin_redirect_is_rejected_before_connection()
-> Result<(), Box<dyn std::error::Error>> {
    let server = TestServer::start().await?;
    let profile = local_profile();
    let target = Target::parse(&server.url("/cross-origin"))?;
    let client =
        ScannerHttpClient::new(ScopePolicy::new(target, &profile), HttpPolicy::from(&profile));

    let error = client
        .fetch(task(&server.url("/cross-origin"))?)
        .await
        .err()
        .ok_or("expected scope error")?;
    assert!(matches!(error, ScannerError::Scope(_)));
    assert_eq!(client.wire_requests(), 1);
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn redirect_loop_is_reported_structurally() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServer::start().await?;
    let profile = local_profile();
    let target = Target::parse(&server.url("/loop-a"))?;
    let client =
        ScannerHttpClient::new(ScopePolicy::new(target, &profile), HttpPolicy::from(&profile));

    let error =
        client.fetch(task(&server.url("/loop-a"))?).await.err().ok_or("expected redirect error")?;
    assert!(matches!(error, ScannerError::Redirect(_)));
    assert_eq!(client.wire_requests(), 2);
    server.stop().await;
    Ok(())
}
