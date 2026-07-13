use scopelynx::http::content::{ContentKind, classify};

#[test]
fn sniffs_html_without_content_type() {
    assert_eq!(classify(None, "/", b"<!doctype html><html></html>"), ContentKind::Html);
}

#[test]
fn magic_bytes_override_misleading_text_header() {
    assert_eq!(classify(Some("text/plain"), "/download", b"%PDF-1.7\n"), ContentKind::Pdf);
}

#[test]
fn null_heavy_utf8_is_binary() {
    assert_eq!(classify(None, "/blob", &[0; 128]), ContentKind::Binary);
}
