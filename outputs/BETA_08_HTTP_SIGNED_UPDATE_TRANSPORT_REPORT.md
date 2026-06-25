# BETA 08 — HTTP SIGNED-UPDATE TRANSPORT REPORT

Phase: `08_HTTP_SIGNED_UPDATE_TRANSPORT` (DataVanger V.Beta Improvement Plan)
Executed: 2026-06-14
Verdict: **AUDIT + COMPLETION. The bounded HTTP signed-update transport is already fully implemented, safe, and
comprehensively tested. This phase made zero production-behaviour change: it fixed the stale `IUpdateTransport`
doc comment and added the two required tests that were missing (no-app-binary-self-update; file-transport
regression). Verification-before-apply and anti-downgrade remain authoritative and untouched. No .NET SDK here,
so nothing was compiled or run — Windows/Codex validation pending.**

- **Branch/checkpoint:** `claude/confident-gates-f355wn`, on the Phase-07-stabilized baseline.

## Baseline replacement result

- **ZIP cleanliness:** no `bin/`, `obj/`, `TestResults/`, `Publicar/`, `.vs/`, no nested zip; exact-mirror
  replace (post-copy `diff -rq` empty).
- **Exact delta vs previous baseline** (HEAD `21b9eab`): **3 files** — `DataVanger/Core/ScanEngine.cs`,
  `DataVanger.Tests/CsvSafeTests.cs`, `DataVanger/ALTERACOES_BETA.md`. The Codex Phase-07 stabilization hardened
  the Phase-07 CSV round-trip (a new RFC-4180 record reader `ReadCsvRecords` that accumulates physical lines
  until quoted fields are balanced, so CsvSafe-quoted fields with embedded CR/LF still round-trip; plus a
  `\r`-leader formula test and a multiline-record SHA256 round-trip test). Adopted as commit `b760c7a`.

## Audit findings (the transport was already done and correct)

`DataVanger.Engine/Updates/SignedUpdates/HttpUpdateTransport.cs` already implements a bounded, opt-in,
fail-closed HTTPS transport. Confirmed against §9/§13:

- **Opt-in / no I/O when off:** inert unless `Enabled` AND a valid absolute `https` feed URL — otherwise no
  `HttpClient` is constructed and every fetch returns `null`.
- **HTTPS only:** non-https feed/package URL rejected; no request made.
- **No redirects:** `AllowAutoRedirect=false` AND any 3xx response rejected (SSRF/cross-host defense).
- **Bounded size:** declared `Content-Length > max` rejected before reading; body streamed with a hard cap so a
  missing/lying length cannot produce an unbounded buffer.
- **Bounded time:** per-request `CancellationTokenSource(timeout)`; expiry fails closed.
- **Fail closed:** any `HttpRequestException`/`OperationCanceledException`/`IOException`/`SocketException`/… →
  `null`; returning `null` mutates no state (service preserves last-known-good).
- **Same-origin package paths:** crafted relative paths are rejected (`IsSafeRelativePath`) and the resolved
  package URL must stay on the same https origin under the feed directory.
- **Transport only fetches bytes:** signature verification, package hash/size validation, and anti-downgrade
  sequencing all remain in `SignedUpdateService` + the verifiers.

## HTTP bounds and timeout values

`HttpUpdateTransportOptions` safe defaults: **timeout 30 s**, **manifest cap 512 KB**, **package cap 128 MB**,
disabled with an empty feed (no I/O). `Create(...)` normalizes any non-positive value to the safe default, so
invalid/missing config can never produce an unbounded fetch.

## Verification path / anti-downgrade preservation evidence

Unchanged and authoritative: `SignedUpdateService.CheckAndApply()` runs manifest signature verification
(`SignedManifestVerifier`, RSA-PSS, pinned key), package validation (`UpdatePackageVerifier`: path → kind →
size → SHA-256), and anti-downgrade sequence pinning before staging/applying. The existing tests prove a
tampered manifest → `SignatureInvalid`, a tampered package → `PackageHashMismatch`, and an older sequence →
`DowngradeRejected`, each with **state preserved** — all over HTTP, proving these gates stay upstream of the
transport. **No verification or anti-downgrade code was touched this phase.**

## No app-binary self-update — explicit statement

**App-binary self-update is not implemented and is structurally impossible.** `UpdatePackageKind` declares only
passive data kinds (HashBlacklist, HashAllowlist, ReputationMetadata, YaraRules, BrowserExtensionFeed,
Configuration, ThreatMetadata) plus `Unknown` (always rejected). There is no executable/application-binary
kind, and `UpdatePackageVerifier` rejects an `Unknown`/non-allowlisted kind with `PackageKindRejected`. The new
tests assert both: the enum contains no executable-ish kind name, and a validly **signed** manifest carrying an
`Unknown`-kind package is rejected (`PackageKindRejected`) with state preserved.

## Files changed

- `DataVanger.Engine/Updates/SignedUpdates/IUpdateTransport.cs` — **doc comment only** (the stale "There is NO
  network transport / MUST NOT construct HTTP clients" replaced with an accurate description: transports include
  an opt-in bounded HTTPS transport; a transport only fetches bytes and makes no trust decision).
- `DataVanger.Tests/SignedUpdateHttpTransportTests.cs` — **3 tests added** (reusing the file's signing/manifest
  helpers).
- `DataVanger/ALTERACOES_BETA.md` — Phase 08 entry.

**No production code changed.** `HttpUpdateTransport.cs`, `SignedUpdateService.cs`, `UpdatePackageVerifier.cs`,
and `SignedManifestVerifier.cs` are byte-unchanged.

## What was intentionally NOT implemented

- **Live wiring of the HTTP transport** into the update flow. Today `UpdateCommandHandler` returns only an
  `UpdateStatusDto` snapshot; no composition maps `AppSettings` → `HttpUpdateTransportOptions` →
  `SignedUpdateService` with the HTTP transport. The transport is opt-in and off by default; the mapping is a
  documented "future composition layer" deferral (Engine deliberately does not reference the UI `AppSettings`).
  Wiring it blind (no SDK) into the live service path would be an unverifiable change to the update path, so it
  is left as a flagged follow-up rather than claimed live.
- **App-binary self-update** — forbidden; not added (structurally impossible, see above).

## Tests added / results

3 tests in `SignedUpdateHttpTransportTests` (now 26 total in that class): `NoAppBinaryOrExecutable
UpdatePackageKindExists` (enum reflection), `SignedManifest_WithUnknownPackageKind_RejectedOverHttp_State
Preserved`, and `FileTransport_ValidSignedUpdate_AppliedThroughService` (file-transport regression). The
existing 23 already cover the success path, timeout, oversize (declared + streaming cap), invalid signature,
downgrade refusal, redirect/scheme/path defenses, network error/5xx, last-known-good, options clamping, and
anti-FP. In-memory transport regression is covered by `Phase10SignedUpdates` (in `LegacyParityTests`).
**Could not be executed here** (no .NET SDK; `DataVanger.Tests` is `net8.0-windows`).

## Validation commands run and results

No .NET SDK / MSBuild / mono. The phase's `dotnet build/test` (+ `--arch x64`, `~Update`) are **NOT RUNNABLE
here**. Static validation:

| Check | Result |
|---|---|
| ZIP cleanliness / exact-mirror replace | PASS |
| Production behaviour changed | none — `IUpdateTransport` is doc-comment-only; rest is tests |
| Transport / verifier / service byte-unchanged | PASS (git-verified) |
| Invariants on changed files (anonymous `catch{}` / `lock(qm)` / CRLF) | 0 / 0 / 0 — PASS |
| New tests reference real APIs (`UpdateManifest`, `UpdatePackageEntry`, `UpdateResultKind.PackageKindRejected`, `FileUpdateTransport`, `state.GetCurrent(FeedId).HasState`) | PASS (verified against source) |
| No app-binary package kind exists | PASS (`UpdatePackageKind` has no executable kind) |
| Forbidden artifacts staged | none — PASS |

## Manual validation results

**Not performed — Windows-only and not wired.** The §11 update-UI checklist (status page, "update now" via
HTTP only when enabled, invalid signature leaves signatures unchanged, timeout/oversize errors, "Up to date")
requires the live wiring (deferred) and a Windows runtime.

## Stop conditions encountered

None. No content can apply before verification (transport only fetches bytes; verifiers/service decide).
Downgrade protection unchanged. Downloads are bounded. Unit tests use a mock `HttpMessageHandler` (no real
network). File/in-memory transport tests are preserved (file-transport coverage added). No app-binary
self-update appears in scope.

## Remaining risks / follow-up

1. **Windows validation debt (standing):** `dotnet build/test` + `~Update`.
2. **Live wiring deferred:** map user update settings to `HttpUpdateTransportOptions` and compose the HTTP
   transport into the service/`UpdateCommandHandler` so "update now" can fetch over HTTP (opt-in). This is the
   one remaining step to make the transport reachable end-to-end.

## Recommendation

**Optional Codex stabilization (as the phase states).** A light pass should: build on Windows; run `~Update`;
confirm the 3 new tests pass; and (if desired) implement the deferred composition wiring with the same
verification-before-apply discipline. Risk: **LOW** — this phase changed no production code; the transport was
already complete and the additions are tests + a doc fix.

---

## Self-Stabilization Review

- **Cross-platform blind spots:** all changes are in `DataVanger.Engine` (net8.0) + the test project; no WPF/
  XAML. The new file-transport test uses temp dirs and `Path` APIs that work cross-platform; the HTTP tests use
  a mock handler (no real socket). Nothing was compiled here.
- **Test/API mismatch:** read the real `HttpUpdateTransport`, `IUpdateTransport`, `UpdatePackageVerifier`,
  `UpdatePackageKind`, `UpdatePolicy`, `UpdateResultKind`, `FileUpdateTransport`, and the existing test helpers
  before writing; the new tests reuse the file's proven helpers (`Sign`, `BuildSignedUpdate`, `NewService`,
  `MapHandler`) and only verified members. No `InternalsVisibleTo` reliance.
- **Build integration:** SDK globbing already includes the (modified) test file; no new file added; no resx/
  XAML/csproj change.
- **Safety-policy consistency:** signature verification, anti-downgrade, package validation, anti-FP, YARA, and
  quarantine are **byte-unchanged** (git-verified). The transport is unchanged. The only behavioural surface is
  the new tests' assertions, which are read-only.
- **Phase-boundary enforcement:** no app-binary self-update added; no unbounded download; no real network in
  tests; no verification bypass; no live wiring pulled forward (deferred and documented). Minimal, surgical
  (doc + tests).
- **Issues found and fixed:** the stale `IUpdateTransport` doc comment (now accurate); the two missing required
  tests (no-app-binary-self-update; file-transport regression) added; confirmed in-memory regression is already
  covered so it was not duplicated.
- **Windows-only / Codex-only:** `dotnet build/test` + `~Update`; the deferred live-wiring composition + its
  manual update-UI journeys.
- **Prior mistake patterns prevented:** Linux≠Windows (compiled nothing, said so); test/API mismatch (read real
  types + reused proven helpers); "claiming a feature is live when it is only implemented-not-wired" (the HTTP
  transport is explicitly reported as off-by-default and not wired); "weakening verification for transport
  convenience" (zero production change — verifiers/service untouched).
- **Codex stabilization recommended? Optional, LOW risk.**

## Documentation Review

- **Files reviewed:** `DataVanger/ALTERACOES_BETA.md` (the main Beta change-log) and the `outputs/` phase
  reports (04B–07). Searched for `CHANGELOG.md`/`RELEASE_NOTES.md`/`ALTERACOES_v*.md` — only
  `ALTERACOES_BETA.md` exists (the v2.0/v2.1 logs were consolidated into it in an earlier phase).
- **Files updated:** `DataVanger/ALTERACOES_BETA.md` — appended an `08_HTTP_SIGNED_UPDATE_TRANSPORT (auditoria +
  finalização)` entry stating: what changed (audit of the existing bounded HTTPS transport; stale-interface-doc
  fix; the two added required tests); user-visible impact (none — transport off by default and not wired);
  security/policy impact (verification + anti-downgrade authoritative and untouched; **no production behaviour
  change**; app-binary self-update structurally impossible); status (**implemented + tested but NOT wired into
  the live update flow**; not Windows-validated); limitations/follow-up (composition wiring; manual update-UI
  validation); and stabilization status. Older entries were not rewritten or duplicated. Created
  `outputs/BETA_08_HTTP_SIGNED_UPDATE_TRANSPORT_REPORT.md`.
- **Obsolete / superseded documentation found:** none new. `ALTERACOES_v2_0.md`/`ALTERACOES_v2_1.md` remain
  consolidated into `ALTERACOES_BETA.md` (not present in the tree).
- **Documentation intentionally not changed:** the 00–07 `outputs/` reports (historical record);
  `README.md`/`docs/*` (this phase makes no architecture/installer change and the transport is not user-wired).
  No documentation files were deleted.
