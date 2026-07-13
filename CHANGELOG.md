# Changelog

## 0.3.2 — 2026-07-13

- Fixed false-positive findings from responses already classified as semantic soft 404s.
- Retained an explicitly requested successful origin root as the landing representation even when
  a catch-all server returns the same page for random missing paths.
- Correlated server/framework technology fingerprints at origin scope instead of generating one
  duplicate per path.
- Added an exact final-response HTTP status histogram and a dedicated 304 Not Modified response class; 304 and
  5xx responses can never be reclassified as soft 404 by body similarity.
- Counted native 404/410 responses separately from heuristic 2xx soft 404s.
- Diversified and parallelized the three missing-resource baselines across root, `.well-known`, and
  nested path shapes.
- Added a deterministic catch-all-200 regression server plus explicit 200/304/404/503,
  analyzer-gating, origin-correlation, and report status-table tests.
- Advanced reports to schema 4 while retaining schema-3 read compatibility for inspect and diff.

## 0.3.1 — 2026-07-13

- Enabled explicitly authorized LAN and WAN scanning in the authorized-sensitive profile while
  retaining the mandatory `--authorized` acknowledgement.
- Increased the standard and authorized profile throughput, discovery, and request budgets within
  the validated global memory and rate ceilings.
- Added efficient periodic live progress events and immediate medium-or-higher finding events;
  `--no-progress` and `--quiet` disable them for automation.
- Made CLI verbosity authoritative for scanner events so an inherited `RUST_LOG=warn` cannot
  accidentally suppress default live progress.
- Added deterministic tests for private LAN opt-in, public WAN literals, authorized-profile
  defaults, and progress configuration.

## 0.3.0 — 2026-07-13

- Added central URL, text, header, error, and evidence redaction.
- Added bounded findings/evidence and stable rule/location-based finding identifiers.
- Added content classification using headers, paths, magic bytes, and bounded body prefixes.
- Added feed, web-manifest, OpenGraph/Twitter, and JSON-LD discovery.
- Added destructive-GET and non-authorized sensitive-path suppression.
- Hardened DNS answer limits, reserved IP classification, output components, body hashes, and
  report-schema validation.
- Added explainable three-baseline soft-404 decisions and report completion state.
- Added dry-run, inspect, shell completion, expanded resource overrides, and SARIF output.
- Added deterministic local HTTP integration tests for redirects, retries, shared wire budgets,
  gzip post-decompression body limits, repeated cookies, soft-404 probes, and storage.
- Added property tests for canonicalization, URL redaction, and private-network invariants.
- Reworked Windows quality automation and pinned multi-platform CI/supply-chain jobs.
- Removed unused legacy `src/scanner.rs` and obsolete intermediate change documentation.

## 0.2.0

- Introduced scope modes, DNS pinning, manual redirects, wire-request budgets, bounded discovery,
  evidence-based analyzers, deterministic reports, and content-addressed optional body storage.
