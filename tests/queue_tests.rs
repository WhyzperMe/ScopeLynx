use scopelynx::{
    engine::queue::{RequestQueue, RequestTask},
    model::DiscoverySource,
};
use url::Url;

#[test]
fn queue_prioritizes_high_priority_and_deduplicates() -> Result<(), Box<dyn std::error::Error>> {
    let mut queue = RequestQueue::new(10);
    assert!(queue.push(RequestTask {
        url: Url::parse("https://example.org/low")?,
        source: DiscoverySource::Wordlist,
        depth: 0,
        priority: 10,
    }));
    assert!(queue.push(RequestTask {
        url: Url::parse("https://example.org/high")?,
        source: DiscoverySource::Robots,
        depth: 0,
        priority: 200,
    }));
    assert!(!queue.push(RequestTask {
        url: Url::parse("https://example.org/high#fragment")?,
        source: DiscoverySource::HtmlLink,
        depth: 1,
        priority: 100,
    }));
    assert_eq!(queue.pop().map(|task| task.url.path().to_string()), Some("/high".into()));
    Ok(())
}
