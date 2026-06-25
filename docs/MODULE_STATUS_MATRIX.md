# DataVanger V.Alpha — Module Status Matrix

Truthful classification of each module against **current code reality** (not intent).
Where code and intent disagree, the entry is marked **Needs audit** rather than guessed.

**Status legend**

| Status | Meaning |
|---|---|
| **Active** | Implemented and wired into the default runtime/scan path. |
| **Prepared** | Implemented but not activated by default (e.g. behind a compile symbol / availability gate). |
| **Fallback** | The always-valid default used when a higher-tier path is unavailable. |
| **Stub** | Present but non-functional (throws / no-op / diagnostic only). |
| **Disabled** | Off by default via configuration. |
| **Degraded** | Active but operating in a limited mode. |
| **Needs audit** | State could not be conclusively determined / a code-vs-intent gap exists. |

> Final Windows validation for `22_FINAL_STABILIZATION` executed on 2026-06-10
> (Windows x64, .NET SDK 10.0.301 with .NET 8 WindowsDesktop runtime 8.0.28).
> Build, test, hard real-YARA, publish/native deployment, invariant, and warning gates passed.
> This exported workspace has no `.git` metadata, so branch/commit provenance could not be
> captured here.

---

## Detection & scanning

| Module | Status | Evidence (file) |
|---|---|---|
| ScanEngine | **Active** | `DataVanger/Core/ScanEngine.cs` (5-phase scan; `AnalyzeSingleFileAsync` ≈240 lines — refactor is a future phase) |
| Detection pipeline | **Active** | `DataVanger/Detection/DetectionPipeline.cs`, `DetectionModuleRegistry.cs`, `DataVanger/Engine/EngineComposition.cs` (9 modules wired) |
| PE detection | **Active** | `DataVanger/Detection/PeDetectionModule.cs`, `DataVanger/Detection/PE/*` |
| PE section entropy | **Active** | `DataVanger/Detection/PeDetectionModule.cs` (`AnalyzeEntropyBySectionAsync`, `HighDataSectionEntropy=7.5`) — descriptive-only (Score 0, never confirms) |
| YARA lightweight engine | **Active / Fallback** | `DataVanger/Core/LightweightYaraDatabase.cs` via `DataVanger/Infrastructure/YaraEngineAdapter.cs` — always-valid YARA backend; also the guaranteed fallback |
| Real libyara backend | **Active (compiled-in; Windows-validated per 22_FINAL_STABILIZATION) / Fallback guaranteed** | `DataVanger/Infrastructure/LibyaraEngine.cs` (`#if YARA_REAL`, lifetime-scoped `YaraContext`, idempotent `Dispose`, no invalid `Scanner.Dispose`). **`YARA_REAL` is ACTIVE** in `DataVanger/DataVanger.csproj` with pinned `dnYara 2.1.0` + `dnYara.NativePack 2.1.0.3` (native `libyara.dll` copied as native content via `ExcludeAssets=all` + explicit `<None>`, `PlatformTarget x64`). `ScanEngine` disposes the real engine after each scan. `TryCreate` → null on native-unavailable / zero-rules, so the lightweight engine stays the guaranteed fallback. Real external matches are forced `Confirmed=false, Score=0` (never confirm). Final hard validation passed on Windows x64 with `DATAVANGER_REQUIRE_REAL_YARA=1`: `~Yara` 22 passed / 0 failed / 0 skipped, including the real-path `RealYaraBackend_*` tests. |
| Trusted publishers | **Active** (substring) | `DataVanger/Core/AppSettings.cs` (`TrustedPublishers` + `ExtraTrustedPublishers`), `DataVanger/Reputation/ReputationEngine.cs` / `DataVanger/Core/ScanEngine.cs` (`IsPublisherTrusted`). **Substring match only — certificate-chain/thumbprint validation is Needs hardening (future phase).** Never overrides a malicious hash. |
| Reputation engine | **Active** | `DataVanger/Reputation/ReputationEngine.cs` (trust-state scoring; known-bad/known-good precedence; trusted-signer relief gated on `!knownBad`) |
| Memory scanner | **Needs audit** | Engine exists (`DataVanger/Memory/*`, e.g. `IMemoryScanner.cs`, `MemoryBehavioralBridge.cs`) and is exercised by the legacy parity tests, but is **not** in the per-file `EngineComposition` module set. Activation into the main scan is unverified. |
| Behavioral engine | **Needs audit** | Engine exists (`DataVanger/Behavioral/BehavioralCorrelationEngine.cs` + rules) and is tested, but is **not** in the per-file `EngineComposition` module set (runtime/service path). Heuristic-only; clamps to HighRisk. |

## Quarantine, scheduling, realtime

| Module | Status | Evidence (file) |
|---|---|---|
| Quarantine V2 | **Active** | `DataVanger.Engine/Quarantine/QuarantineService.cs`, `DataVanger.Infrastructure/Quarantine/FileSystemQuarantineStore.cs`, `DpapiQuarantineKeyProtector.cs` (auth-encryption + HMAC + DPAPI key; integrity-verified restore; auto-quarantine `ConfirmedMalware`-only; restore never automatic) |
| Scheduler | **Active** | `DataVanger/Scheduling/*` (deterministic tick-driven; persists job state; never classifies) |
| Realtime protection | **Prepared** | `DataVanger.Engine/Realtime/ConservativeRealtimeDecisionEngine.cs`, `DataVanger.Service/Realtime/RealtimeProtectionService.cs` (conservative; authorizes auto-action only for `ConfirmedMalware`, non-passive). Running it as a privileged background service depends on the stubbed Windows service. |

## Updates

| Module | Status | Evidence (file) |
|---|---|---|
| Signed update verification | **Active** | `DataVanger.Engine/Updates/SignedUpdates/SignedUpdateService.cs`, `SignedManifestVerifier.cs`, `UpdatePackageVerifier.cs` (RSA-PSS / ECDsa, anti-downgrade, pinned keys; file/in-memory transports work; telemetry-only, never a verdict) |
| HTTP update transport | **Stub** | `DataVanger.Engine/Updates/SignedUpdates/HttpUpdateTransport.cs` — every method throws `NotSupportedException("HTTP transport is not implemented in this phase.")`. `DataVanger.Engine/Status/ModuleStatusAggregator.cs` reports signed updates as not configured. |

## Service & IPC

| Module | Status | Evidence (file) |
|---|---|---|
| Windows service mode | **Stub** | `DataVanger.Service/Program.cs:149` — `--service` is a diagnostic stub; "no Windows Service was installed". `--console`/`--status`/`--validate-config`/`--help` work. |
| Named Pipe IPC | **Active (local, payload-validated)** | `DataVanger.Infrastructure/Ipc/NamedPipeDataVangerServiceHost.cs` / `NamedPipeDataVangerServiceClient.cs`, `IpcSecurityPolicy.cs`, `NamedPipeFraming.cs`, `IpcSerialization.cs`; handlers in `DataVanger.Service/Ipc/*` |
| IPC ACLs | **Needs hardening** | No `PipeSecurity`/security-descriptor restriction implemented; `NamedPipeDataVangerServiceHost.cs:25` notes "Future ACL hardening (PipeSecurity) can be added". Payload allowlist/size validation exists, but connection-level ACLs do not. |

## Runtime telemetry

| Module | Status | Evidence (file) |
|---|---|---|
| ETW provider | **Active (real, Windows-validated per Phase 17) / Fallback** | Real provider `DataVanger.Infrastructure/Etw/WindowsEtwRuntimeProvider.cs` (TraceEvent) was Windows-validated in Phase 17 (real session creation, `logman` visibility, disposal). **Focused ETW audit (22_FINAL_STABILIZATION): NO REGRESSION** — the file is byte-identical to the Phase-17 validated baseline (`git diff e0cc9ab HEAD` empty; blob `4b28bbda…`), `TryActivateRealSession` is the single activation path, `EnableKernelProvider` runs once before the `Source.Process()` pump, and the successful Windows validation proves the ordering. Behavior adapter `DataVanger/Behavioral/Adapters/EtwBehaviorProvider.cs:23` remains a **Stub** (`IsAvailable => false`); Null/InMemory providers are the **Fallback**. Never confirms malware alone. |
| AMSI adapter | **Stub** | `DataVanger/Behavioral/Adapters/AmsiBehaviorAdapter.cs:17` `IsAvailable => false`. Seam present; no real amsi.dll integration. Never confirms malware alone. |

## UI, settings, reporting

| Module | Status | Evidence (file) |
|---|---|---|
| Module status UI | **Needs audit** | Data source exists: `DataVanger.Engine/Status/ModuleStatusAggregator.cs` + `DataVanger.Shared/Status/ModuleStatusModels.cs`. A dedicated UI surfacing the Active/Prepared/Stub taxonomy is a future phase; current UI exposure is unverified. |
| Settings UI | **Active** | `DataVanger/SettingsWindow.xaml(.cs)` exposes 28/29 `AppSettings` properties; `TrustedPublishers` base list intentionally not UI-exposed (users edit `ExtraTrustedPublishers`). |
| Reporting / forensics | **Active** | `DataVanger/Core/ReportGenerator.cs`, `DataVanger/Reporting/ReportService.cs` (CSV/TXT/HTML/JSON). *Needs audit (light): CSV quoting/injection not re-verified this round.* |

## Tests

| Module | Status | Evidence (file) |
|---|---|---|
| xUnit tests | **Active** | `DataVanger.Tests/DataVanger.Tests.csproj` (xunit 2.9, runner 2.8, Test.Sdk 17, coverlet 6); `DataVanger.Tests/TestSupport/TestParallelization.cs` disables parallelization. Final validation: full default suite 168 passed / 0 failed / 0 skipped; full `--arch x64` suite 168 passed / 0 failed / 0 skipped. |
| LegacyParityTests | **Active (faithful-wrapper mega-test)** | `DataVanger.Tests/LegacyParityTests.cs` — one `[Fact]` (`DataVanger_LegacySuite_AllChecksPass`, now `async Task`) wrapping ≈49 sections; sync file-scoped helper classes keep blocking calls (documented `xUnit1031-deferred`). Phase 08 + correction applied; final Windows build/test validation passed. Decomposition is a future phase. |
| AntiFalsePositive tests | **Active** | `DataVanger.Tests/AntiFalsePositiveTests.cs` (3 Facts; `--filter ~AntiFalsePositive`) |
| Publisher tests | **Active** | `DataVanger.Tests/TrustedPublisherSettingsTests.cs` (4 Facts; `--filter ~Publisher`) |
| Yara tests | **Active** | `DataVanger.Tests/YaraEngineFallbackTests.cs` (fallback + non-confirmation), `RealYaraBackendTests.cs` (real-path: smoke rule compile/scan, non-confirmation, bad-rule isolation, unavailable→fallback; hard-gated by `DATAVANGER_REQUIRE_REAL_YARA=1`), `YaraRulePackTests.cs` (bounded local rule-pack). `--filter ~Yara` |

---

## Anti-false-positive contract (must remain accurate)

Source: `DataVanger/Core/ThreatClassificationPolicy.cs` (`Classify`,
`AllowsAutomaticAction`) + `AntiFalsePositivePolicy.cs`.

- **`ConfirmedMalware` only** from `IsBlacklisted` (known-malicious hash) **or**
  `HasConfirmedSignature` (evidence with `CanConfirmMalware`, e.g. a curated
  `confirmed` lightweight YARA rule).
- **Heuristics clamp to `HighRisk`** unless confirmed evidence exists.
- **Automatic quarantine only for `ConfirmedMalware`.**
- The following **never confirm malware alone**: heuristics, PE section entropy,
  real external YARA matches, publisher trust, reputation, behavioral correlation,
  ETW events, AMSI events, command-line/PowerShell heuristics, memory-scanner
  evidence, browser-extension heuristics, reporting aggregation, realtime file
  events, IPC events, service failures, update failures, quarantine restore failures.
- **Blacklist precedence over whitelist** and "trusted publisher never overrides a
  known-malicious hash" are preserved.

## Needs-audit gaps (do not guess — confirm in code/Windows)

1. **Memory scanner & behavioral engine** exist and are tested but are **not** in the
   per-file `EngineComposition` module set — confirm whether/where their results reach
   the user (likely the runtime/service path by design).
2. **Module status UI** — confirm whether any UI view surfaces
   `ModuleStatusAggregator`'s Active/Prepared/Stub taxonomy (future phase 18).
3. **Reporting CSV** — re-verify CSV quoting / CSV-injection handling in
   `ReportGenerator` / `ReportService`.
4. **Git provenance** — this validation workspace is an exported source tree without
   `.git`, so branch/commit/clean-tree values and the requested documentation commit could
   not be produced here. Build/test/publish gates were run from the folder containing
   `DataVanger.sln`.
