use scopelynx::engine::soft_404::Soft404Detector;

#[test]
fn matches_two_similar_custom_not_found_pages() {
    let detector = Soft404Detector::from_samples([
        (200, b"Page 6f37a9e3 not found. Return home.".to_vec()),
        (200, b"Page 8a21b7c4 not found. Return home.".to_vec()),
    ]);
    assert!(detector.matches(200, b"Page 1d44c8f2 not found. Return home."));
    assert!(!detector.matches(200, b"Welcome to the customer dashboard"));
}

#[test]
fn native_404_is_not_mislabeled_as_soft_404() {
    let detector = Soft404Detector::default();
    assert!(!detector.matches(404, b"anything"));
    let decision = detector.classify(404, b"anything");
    assert!(decision.reasons.iter().any(|reason| reason.contains("native not-found")));
}

#[test]
fn never_relabels_304_or_5xx_as_soft_404() {
    let detector = Soft404Detector::from_samples([
        (304, Vec::new()),
        (304, Vec::new()),
        (503, b"temporarily unavailable".to_vec()),
        (503, b"temporarily unavailable".to_vec()),
    ]);
    assert!(!detector.matches(304, b""));
    assert!(!detector.matches(503, b"temporarily unavailable"));
}
