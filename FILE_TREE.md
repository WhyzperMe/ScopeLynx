# File Tree

Generated from the repository root on 2026-07-13. Build artifacts and local/editor output
(`target`, `output`, `.git`, `.idea`, `.vscode`, `*.log`, and `*.tmp`) are intentionally excluded.

```text
ScopeLynx/
├── .github/
│   └── workflows/
│       └── ci.yml
├── docs/
│   ├── ARCHITECTURE.md
│   ├── AUDIT_REPORT.md
│   ├── GAMEPLAN.md
│   └── VALIDATION_REPORT.md
├── example_wordlist/
│   ├── authorized-sensitive.txt
│   ├── big.txt
│   └── common.txt
├── profiles/
│   ├── authorized-sensitive.toml
│   ├── safe.toml
│   └── standard.toml
├── scripts/
│   ├── quality.ps1
│   ├── quality.sh
│   ├── run-example.ps1
│   └── update-manifest.ps1
├── src/
│   ├── analyzers/
│   │   ├── cookies.rs
│   │   ├── document.rs
│   │   ├── endpoints.rs
│   │   ├── exposure.rs
│   │   ├── forms.rs
│   │   ├── headers.rs
│   │   ├── mod.rs
│   │   └── technologies.rs
│   ├── discovery/
│   │   ├── feeds.rs
│   │   ├── html.rs
│   │   ├── javascript.rs
│   │   ├── manifests.rs
│   │   ├── mod.rs
│   │   ├── robots.rs
│   │   ├── sitemap.rs
│   │   └── wordlist.rs
│   ├── engine/
│   │   ├── canonicalize.rs
│   │   ├── mod.rs
│   │   ├── queue.rs
│   │   ├── scheduler.rs
│   │   ├── similarity.rs
│   │   └── soft_404.rs
│   ├── http/
│   │   ├── client.rs
│   │   ├── content.rs
│   │   ├── mod.rs
│   │   ├── policy.rs
│   │   └── response.rs
│   ├── model/
│   │   ├── finding.rs
│   │   ├── mod.rs
│   │   ├── observation.rs
│   │   └── report.rs
│   ├── redaction/
│   │   ├── evidence.rs
│   │   ├── headers.rs
│   │   ├── mod.rs
│   │   ├── text.rs
│   │   └── url.rs
│   ├── report/
│   │   ├── console.rs
│   │   ├── diff.rs
│   │   ├── json.rs
│   │   ├── markdown.rs
│   │   ├── mod.rs
│   │   ├── sarif.rs
│   │   └── text.rs
│   ├── storage/
│   │   ├── filesystem.rs
│   │   └── mod.rs
│   ├── cli.rs
│   ├── config.rs
│   ├── error.rs
│   ├── lib.rs
│   ├── main.rs
│   ├── scope.rs
│   └── target.rs
├── tests/
│   ├── fixtures/
│   │   ├── react_page.html
│   │   ├── robots.txt
│   │   ├── sitemap.xml
│   │   └── soft_404.html
│   ├── support/
│   │   ├── mod.rs
│   │   └── test_server.rs
│   ├── analyzer_tests.rs
│   ├── canonicalization_tests.rs
│   ├── config_tests.rs
│   ├── content_classification_tests.rs
│   ├── discovery_tests.rs
│   ├── finding_tests.rs
│   ├── integration_false_positive_tests.rs
│   ├── integration_http_tests.rs
│   ├── integration_redirect_tests.rs
│   ├── integration_reporting_tests.rs
│   ├── integration_retry_tests.rs
│   ├── integration_soft_404_tests.rs
│   ├── integration_storage_tests.rs
│   ├── property_tests.rs
│   ├── queue_tests.rs
│   ├── redaction_tests.rs
│   ├── report_diff_tests.rs
│   ├── scope_tests.rs
│   └── soft_404_tests.rs
├── .gitignore
├── Cargo.lock
├── Cargo.toml
├── CHANGELOG.md
├── deny.toml
├── FILE_TREE.md
├── LICENSE
├── MANIFEST.sha256
├── README.md
├── rust-toolchain.toml
├── rustfmt.toml
└── SECURITY.md
```

Total files: **104**
