use scopelynx::engine::canonicalize::canonical_key;
use url::Url;

#[test]
fn removes_fragment_default_port_and_tracking_parameters() -> Result<(), Box<dyn std::error::Error>>
{
    let url = Url::parse("https://example.org:443/docs?utm_source=test&id=7#section")?;
    assert_eq!(canonical_key(&url), "https://example.org/docs?id=7");
    Ok(())
}

#[test]
fn canonical_query_order_is_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    let left = Url::parse("https://example.org/api?b=2&a=1")?;
    let right = Url::parse("https://example.org/api?a=1&b=2")?;
    assert_eq!(canonical_key(&left), canonical_key(&right));
    Ok(())
}
