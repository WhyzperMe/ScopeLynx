# Engineering Gameplan

## Ausgangslage

Der vorhandene Scanner kompiliert mit Rust stable, besteht aber den Format-Gate nicht und ist noch
kein konsistenter Release-Kandidat. Die Transportbasis ist asynchron und begrenzt, Scope-Prüfung,
DNS-Pinning, manuelle Redirects, Analyzer und atomare Berichtsschreibvorgänge sind bereits vorhanden.
Im Arbeitsordner fehlen Git-Metadaten; Git-Status und Git-Diff sind daher nicht verfügbar.

## Wichtigste Audit-Ergebnisse und priorisierte Risiken

1. **High – Datenschutz:** Transport- und Parserfehler können unredigierte URLs oder Secret-Muster
   über Fehlermeldungen in Logs und Reports übernehmen.
2. **High – Ressourcen:** Findings sind nicht durch ein Profil-Limit begrenzt; Berichtsevidenz und
   einige Analyzer-Ausgaben brauchen eine zentrale Redaction- und Größengrenze.
3. **High – Verifikation:** Es fehlen lokale Transport-Integrationstests für Wire-Budget,
   Redirect-Scope, Retry, Dekompression und Body-Limits.
4. **Medium – Bedienung:** `--dry-run`, `inspect`, Ausgabeformate und eindeutige unvollständige
   Scan-Zustände fehlen. Sicheres Resume ist wegen redigierter signierter URLs gesondert zu bewerten.
5. **Medium – Korrektheit:** Content-Klassifikation verlässt sich zu stark auf `Content-Type`; die
   Soft-404-Entscheidung ist boolesch statt erklärbar.
6. **Medium – Scope:** DNS-Antworten werden nach dem konfigurierten Limit abgeschnitten, ohne eine
   übergroße Antwort ausdrücklich abzulehnen. Destruktiv wirkende GET-Pfade werden nicht zentral
   ausgesondert.
7. **Low – Wartbarkeit:** `src/scanner.rs` ist unreferenzierter Legacy-Code mit verbotenen
   `unwrap()`-Aufrufen und einer zweiten, datenschutzschwachen Analysepipeline.
8. **Low – Release:** SARIF, aktuelle Dokumentation, ein vollständiger Dateibaum und ein aktuelles
   Manifest fehlen; CI und `quality.ps1` bilden die verlangten Gates nur teilweise ab.

## Architekturentscheidungen

- Netzwerkzugriffe bleiben ausschließlich in `http::ScannerHttpClient`; Budgeterwerb erfolgt direkt
  vor jedem realen Send-Versuch. Redirects, Retries und Soft-404-Probes teilen dasselbe Budget.
- Request-URL, kanonischer Deduplizierungsschlüssel und redigierte Report-URL bleiben getrennt.
- Eine zentrale `redaction`-Schicht redigiert URLs, Header, Fehler und Evidenz vor Persistenz.
- Content-Klassifikation wird als kleines, deterministisches Modul eingeführt und arbeitet auf
  begrenzten Body-Präfixen, Headern und Pfaden.
- Checkpoint/Resume wird nicht als unzuverlässiger Platzhalter implementiert: Redaction verändert
  signierte Request-URLs, Roh-URLs verletzen den Persistenzvertrag. Eine spätere Lösung benötigt
  verschlüsselte, authentifizierte Checkpoints mit explizitem Schlüsselmodell.
- Der vorhandene Scheduler wird gehärtet statt durch ungenutzte Enterprise-Abstraktionen ersetzt.
- `src/scanner.rs` und die veraltete Zwischenstandsdokumentation werden nach Referenzprüfung entfernt.

## Betroffene Dateien und neue Module

- Kern: `src/cli.rs`, `src/config.rs`, `src/error.rs`, `src/scope.rs`, `src/target.rs`.
- Transport/Engine: `src/http/**`, `src/engine/**`.
- Modelle/Reports/Storage: `src/model/**`, `src/report/**`, `src/storage/**`.
- Neue fachliche Module: `src/redaction/**`, `src/http/content.rs`, Feed-/Manifest-Discovery und
  `src/report/sarif.rs`.
- Tests: bestehende Unit-Tests plus lokaler Server in `tests/support/**` und fokussierte
  Integrationstests.
- Automatisierung/Dokumentation: `.github/workflows/ci.yml`, `scripts/quality.ps1`, Profile,
  README, Security-/Architektur-/Audit-/Validierungsdokumente, `FILE_TREE.md`, `MANIFEST.sha256`.

## Migration und Bereinigung

Die bestehende Reportstruktur wird auf ein neues Schema angehoben. Leser lehnen unbekannte
Schema-Versionen strukturiert ab. Neue Profilfelder sind verpflichtend in allen mitgelieferten
Profilen; unbekannte Felder bleiben verboten. Legacy-Dateien werden erst entfernt, nachdem `rg`
bestätigt hat, dass kein produktiver Modulpfad sie referenziert.

## Teststrategie

- Unit- und Property-Tests für Kanonisierung, Redaction, Scope/IP, Content-Klassifikation,
  Finding-IDs, Soft-404-Erklärungen und Profilvalidierung.
- Deterministischer lokaler Tokio-Testserver ohne externe Netzverbindungen für Statuscodes,
  Redirects, Retry-After, mehrfach gesetzte Header/Cookies, komprimierte und große Bodies.
- Integrationstests prüfen insbesondere Wire-Request-Zählung, Budgetgrenzen, Redirect-Scope,
  Body-Limit nach Dekompression, Report-Redaction und Storage.
- Keine realen Scans gegen externe Ziele während der Validierung.

## Abnahmekriterien und Quality Gates

- Keine verbotenen Panic-/Debug-Konstrukte und kein `unsafe` im Produktionscode.
- Begrenzte Queues, Bodies, Header, DNS-Ergebnisse, Fehler, Evidenzen und Findings.
- Keine Cookie-Werte, Authorization-Werte oder Roh-Secrets in Logs und Reports.
- `cargo fmt --all -- --check`.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- `cargo test --workspace --all-targets --all-features` und `cargo test --doc`.
- `cargo build --release`; soweit verfügbar `cargo audit` und `cargo deny check`.
- Aktuelle Dokumentation, aktueller Dateibaum, reproduzierbares Manifest und kontrollierter finaler
  Dateistatus.

## Bekannte verbleibende Risiken

- Statische JavaScript-Analyse bleibt unvollständig; JavaScript wird bewusst nicht ausgeführt.
- Soft-404- und Technologieerkennung bleiben erklärbare Heuristiken und benötigen reale, autorisierte
  Korpusvalidierung.
- DNS-Pinning verhindert Rebinding innerhalb eines Scan-Clients, reagiert aber absichtlich nicht
  auf legitime DNS-Änderungen während eines Laufs.
- Windows bietet mit portabler Tokio-Datei-API keine vollständige Unix-äquivalente Rechtehärtung.
- Ohne `.git` kann der Ausgangsdiff nicht rekonstruiert werden; alle finalen Dateiänderungen werden
  deshalb explizit dokumentiert.

## LAN/WAN- und Live-Output-Nachhärtung

Nach der Erstabnahme wurde ein autorisierter Zielname beobachtet, der lokal auf eine RFC1918-Adresse
auflöst. Die Sperre war policy-konform, aber das autorisierte Sensitive-Profil war für LAN-Red-Team-
Einsätze unpraktisch. Version 0.3.1 aktiviert private Zieladressen deshalb ausschließlich in diesem
bereits zustimmungspflichtigen Profil, erhöht dessen validierte Durchsatzgrenzen und ergänzt
gedrosselten Live-Fortschritt. Safe und Standard behalten die private Standardsperre; Standard kann
sie nur mit `--allow-private --authorized` übersteuern.

## Catch-all-200- und Statusmodell-Nachhärtung

Ein reales autorisiertes Ziel lieferte dieselbe Landingpage für zufällige fehlende Pfade mit Status
200. Die Soft-404-Erkennung bewertete diese Pfade bereits korrekt, die zentrale Analyzer-Pipeline
ließ Cookie- und Technology-Analyse jedoch weiterlaufen. Version 0.3.2 macht Soft-404 zu einem
globalen Analyzer-Gate, behält die explizite erfolgreiche Origin-Seedseite als Landing-Repräsentation
und korreliert Technology-Fingerprints originweit. Rohstatus, Response-Klasse und semantischer
Soft-404-Zustand bleiben getrennte Berichtsdimensionen; ein Statushistogramm und Regressionstests
für 200/304/404/503 sichern das Verhalten.
