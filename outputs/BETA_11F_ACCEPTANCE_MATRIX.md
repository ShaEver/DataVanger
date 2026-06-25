# BETA 11F — FP Regression Corpus & Acceptance Matrix

Phase: `BETA_11F_FP_REGRESSION_CORPUS`. **Tests/documentation only — no production logic, threshold,
detection, quarantine/remediation, or dormant-engine change.** Finalizes the BETA 11 safety net locking in
fewer false positives for trusted/system/signed files without false negatives for confirmed/actionable
malware.

## Corpus structure

- **Per-sub-phase unit suites (component behavior):**
  - `CatalogSignatureTests` — 11A (catalog vs embedded verification, invalid/unsigned, seams, Windows smoke).
  - `SystemPathContextTests` — 11B (canonical System32/SysWOW64/WinSxS/servicing classification, look-alike
    + world-writable rejection, bounded relief).
  - `PublisherTrustHardeningTests` — 11D (graduated trust levels, anchored spoof-resistant matching,
    invalid-vs-unsigned, default list).
  - `PeRecalibrationTests` — 11C (low-trust cap, strong demote, severe preservation, correlation tightening,
    relief-does-not-erase-severe — Codex-stabilized).
  - `TierActionableSeparationTests` — 11E (HighRisk corroboration gate, evidence category model,
    confirmed-override bypass, predicate consistency).
- **End-to-end acceptance corpus:** `Beta11AcceptanceCorpusTests` — composes the SAME production functions in
  the ScanEngine order (`PublisherIdentity.EvaluatePublisherTrust` → `PeImportRecalibration.Apply` →
  `ScanEngine.HasActionableEvidenceAfterTrustRecalibration` → `ScanEngine.ApplySignedPublisherRelief` →
  `PathTaxonomy.SystemPathRelief` → `ReputationEngine.Evaluate` → Critical clamp →
  `ThreatClassificationPolicy.Classify`). Synthetic, deterministic, no real files/network. No scoring is
  re-implemented — only production functions are called.
- **Windows-only integration:** `[WindowsOnlyFact]` tests over real `System32` files (skip cleanly with an
  explicit reason off-Windows; execute on Windows).

## Acceptance matrix (required §10 cases → tests → RC / sub-phase)

| Required corpus case | Test | RC / sub-phase | Side |
|---|---|---|---|
| Catalog-signed System32 DLL not HighRisk from imports alone | `CatalogSignedSystem32_ImportsAlone_NotHighRisk` | RC-1/RC-2 (11A), RC-3 (11B), RC-4 (11C) | FP↓ |
| WinSxS catalog-signed component not HighRisk from imports alone | `WinSxSCatalogSigned_ImportsAlone_NotHighRisk` | RC-1/RC-2 (11A), RC-3 (11B) | FP↓ |
| Embedded-signed trusted app not HighRisk from normal imports | `EmbeddedSignedTrustedApp_NormalImports_NotHighRisk` | RC-6 (11D), RC-4 (11C) | FP↓ |
| Valid signed-but-untrusted: relief, not immunity | `ValidUntrustedApp_ImportsAlone_Relieved_NotHighRisk` + `ValidUntrusted_WithSevereAnomalies_StaysHighRisk` | RC-6 (11D) | FP↓ / FN guard |
| API-heavy benign DLL not HighRisk solely from imports | `ApiHeavyBenignUnsignedDll_ImportsAlone_NotHighRisk` | RC-4 (11C) | FP↓ |
| Deterministic/future timestamp not strong risk in trusted/system | `DeterministicTimestamp_TrustedSystem_NotStrongRisk` | RC-5 (11C) | FP↓ |
| Trusted relief must not erase severe PE evidence | `TrustedSigned_WithSevereAnomalies_StaysHighRisk` | 11C+11E stabilization | FN guard |
| Unsigned suspicious in user-writable path can still be HighRisk | `UnsignedSuspicious_UserWritable_CanReachHighRisk` | 11C/11E scope | FN guard |
| Masquerading path stays suspicious, not gated | `MasqueradingFile_RemainsAtLeastSuspect_NotGated` | RC-7 / 11E scope | FN guard |
| Known-malicious hash → ConfirmedMalware (beats trust/system) | `KnownMaliciousHash_InTrustedSystemContext_IsConfirmedMalware` | anti-FP contract | FN guard |
| Confirmed YARA → ConfirmedMalware (beats trust/system) | `ConfirmedYara_InTrustedSystemContext_IsConfirmedMalware` | anti-FP contract | FN guard |
| Critical clamp still works (unconfirmed never Confirmed) | `HighUnconfirmedScore_ClampsToHighRisk_NotConfirmedMalware` | Critical clamp | invariant |
| Automatic quarantine ConfirmedMalware-only | `AutomaticAction_OnlyForConfirmedMalware` | auto-action policy | invariant |
| Trusted/system technical-only stays below HighRisk | `TrustedSystem_TechnicalImportsOnly_GatedBelowHighRisk` | RC-7 (11E) | FP↓ |
| Real System32 component is signed & trusted (Windows) | `Integration_RealSystem32Component_IsSignedAndTrusted` | 11A+11D | FP↓ |
| Real System32 path classifies as system (Windows) | `Integration_RealSystem32Path_ClassifiesAsSystem` | 11B | FP↓ |

RC legend: RC-1 catalog blind spot · RC-2 relief blocked by RC-1 · RC-3 no system-path context on
Full/Deep · RC-4 PE imports overweighted/uncapped · RC-5 reproducible-build timestamps · RC-6 publisher
trust underweighted/name-only · RC-7 actionable vs informational not separated.

## Windows-only tests — skip/execute behavior

`[WindowsOnlyFact]` sets the xUnit `Skip` reason at discovery time off-Windows (reported SKIPPED with an
explicit reason, never a silent pass) and executes on Windows. On a real Windows host these tests must
**execute**, not skip. The synthetic corpus and all per-sub-phase unit suites run on every platform.

## Determinism / fixture policy

- No network, no downloads, no live malware samples; synthetic PE-evidence lists model the production
  analyzer strings.
- Real Windows files are used only in platform-guarded integration tests, and only for shipped OS
  components (e.g. `kernel32.dll`) — never a third-party app that may be absent.
- Behavior-level assertions (final tier / trust level / actionable flag), not brittle path substrings.

## Validation results

⚠️ This Linux environment has **no .NET SDK** and the solution targets `net8.0-windows`, so the corpus was
**not compiled/run here**. It is synthetic/deterministic and reuses only production functions. Required
Windows run:

```
dotnet restore && dotnet build DataVanger.sln
dotnet test DataVanger.Tests/DataVanger.Tests.csproj
dotnet test ... --filter "FullyQualifiedName~AntiFalsePositive|~Pe|~Publisher|~Reputation|~Scan|~Detection"
dotnet test ... --arch x64
```
Confirm the `[WindowsOnlyFact]` corpus tests EXECUTE (not skip) on the Windows host.

## Confirmation

No production thresholds, detection, quarantine, remediation, IPC, service, signed-update, or dormant-engine
behavior changed. The 11C-stabilized recalibration/ordering and the 11E actionable gate are exercised, not
modified. ConfirmedMalware, the Critical clamp, and ConfirmedMalware-only automatic action are explicitly
tested.

## Remaining gaps / future expansion

- Full `ScanEngine.RunAsync` integration over a temp directory of synthesized PE files (end-to-end report
  tier) would complement the composition mirror; deferred (needs Windows + file fixtures).
- A labeled benign+malicious binary corpus (approved fixture policy) for empirical FP/FN rates is future
  work, out of scope here (no live samples in-repo).
- Real WinSxS catalog-signed component integration (beyond `kernel32`) on Windows.
