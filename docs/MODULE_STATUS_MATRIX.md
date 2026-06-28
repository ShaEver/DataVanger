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

> Current implementation validation executed on 2026-06-27 (Windows x64,
> .NET SDK 10.0.301 with .NET 8 WindowsDesktop runtime 8.0.28).
> Build, full/filtered tests, real-YARA, Authenticode-chain integration, and
> anti-FP gates passed. SCM install/service/uninstall and a privileged real ETW
> session were not run because this process is not elevated. This exported
> workspace has no `.git` metadata and no GitHub CLI, so branch/commit/PR
> provenance could not be produced here.

---

## Detection & scanning

| Module | Status | Evidence (file) |
|---|---|---|
| ScanEngine | **Active** | `DataVanger/Core/ScanEngine.cs` (5-phase scan; `AnalyzeSingleFileAsync` ≈240 lines — refactor is a future phase) |
| Detection pipeline | **Active** | `DataVanger/Detection/DetectionPipeline.cs`, `DetectionModuleRegistry.cs`, `DataVanger/Engine/EngineComposition.cs` (9 modules wired) |
| PE detection | **Active** | `DataVanger/Detection/PeDetectionModule.cs`, `DataVanger/Detection/PE/*` |
| PE section entropy | **Active** | `DataVanger/Detection/PeDetectionModule.cs` (`AnalyzeEntropyBySectionAsync`, `HighDataSectionEntropy=7.5`) — descriptive-only (Score 0, never confirms) |
| YARA lightweight engine | **Active / Fallback** | `DataVanger/Core/LightweightYaraDatabase.cs` via `DataVanger/Infrastructure/YaraEngineAdapter.cs` — always-valid YARA backend; also the guaranteed fallback. **Rule content:** previously loaded 0 rules (`Signatures.default/yara_rules` was empty). Now ships an FP-safe starter pack (`Signatures.default/yara_rules/eicar.yar`); `DefaultSignaturePack.SeedYaraRules` seeds `.yar`/`.yara`, and the signature root + `Signatures.default` are excluded from scan targets (`TargetDiscovery.IsExcludedPath`) so rules never self-match. Production rules are operator/feed-sourced. |
| Real libyara backend | **Active (compiled-in; Windows-validated per 22_FINAL_STABILIZATION) / Fallback guaranteed** | `DataVanger/Infrastructure/LibyaraEngine.cs` (`#if YARA_REAL`, lifetime-scoped `YaraContext`, idempotent `Dispose`, no invalid `Scanner.Dispose`). **`YARA_REAL` is ACTIVE** in `DataVanger/DataVanger.csproj` with pinned `dnYara 2.1.0` + `dnYara.NativePack 2.1.0.3` (native `libyara.dll` copied as native content via `ExcludeAssets=all` + explicit `<None>`, `PlatformTarget x64`). `ScanEngine` disposes the real engine after each scan. `TryCreate` → null on native-unavailable / zero-rules, so the lightweight engine stays the guaranteed fallback. Real external matches are forced `Confirmed=false, Score=0` (never confirm). Final hard validation passed on Windows x64 with `DATAVANGER_REQUIRE_REAL_YARA=1`: `~Yara` 22 passed / 0 failed / 0 skipped, including the real-path `RealYaraBackend_*` tests. |
| Trusted publishers | **Active** (certificate-backed) | `DataVanger/Core/WinTrust.cs` retains the signer certificate; `PublisherIdentity.cs` defaults to offline `ChainAndName` and supports `ChainAndThumbprint`; `SignatureTrustCache.cs` preserves the public certificate across cache hits. Legacy name-only matching is explicit compatibility mode and remains anchored/spoof-resistant. `ScanEngine` passes the certificate-backed decision into reputation, and known-malicious hash precedence is unchanged. |
| Reputation engine | **Active** | `DataVanger/Reputation/ReputationEngine.cs` (trust-state scoring; known-bad/known-good precedence; trusted-signer relief gated on `!knownBad`) |
| Memory scanner | **Active engine / Prepared resident pass** | Process-oriented engine and readers now live in OS-neutral `DataVanger.Infrastructure/Memory/*` while preserving `DataVanger.Memory.*` namespaces. The service references Infrastructure directly (never WPF). `EnableMemoryScanPass` (default OFF) runs one bounded startup pass and `MemoryRuntimeBridge` publishes `InjectionObserved` into the shared pipeline. No resident loop; not a per-file `IDetectionModule`; never confirms or acts. |
| Behavioral engine | **Active — wired on the resident path** | The bounded runtime binding (`DataVanger.Engine/Behavioral/Runtime/BehavioralRuntimeBinding.cs`) consumes the single ETW/memory/AMSI pipeline composed by `DataVangerServiceRuntime`. `InjectionObserved` degrades into tamper evidence and `ScriptObserved` drives conservative script rules. Evidence-only; clamps to HighRisk; never confirms malware and never acts. |

## Quarantine, scheduling, realtime

| Module | Status | Evidence (file) |
|---|---|---|
| Quarantine V2 | **Active** | `DataVanger.Engine/Quarantine/QuarantineService.cs`, `DataVanger.Infrastructure/Quarantine/FileSystemQuarantineStore.cs`, `DpapiQuarantineKeyProtector.cs` (auth-encryption + HMAC + DPAPI key; integrity-verified restore; auto-quarantine `ConfirmedMalware`-only; restore never automatic) |
| Scheduler | **Active** | `DataVanger/Scheduling/*` (deterministic tick-driven; persists job state; never classifies) |
| Realtime protection | **Prepared** | `DataVanger.Engine/Realtime/ConservativeRealtimeDecisionEngine.cs`, `DataVanger.Service/Realtime/RealtimeProtectionService.cs` (conservative; authorizes auto-action only for `ConfirmedMalware`, non-passive). Running it as a privileged background service uses the Windows service host (now implemented; opt-in install), but is not active by default. |

## Updates

| Module | Status | Evidence (file) |
|---|---|---|
| Signed update verification | **Active** | `DataVanger.Engine/Updates/SignedUpdates/SignedUpdateService.cs`, `SignedManifestVerifier.cs`, `UpdatePackageVerifier.cs` (RSA-PSS / ECDsa, anti-downgrade, pinned keys; file/in-memory transports work; telemetry-only, never a verdict) |
| HTTP update transport | **Stub** | `DataVanger.Engine/Updates/SignedUpdates/HttpUpdateTransport.cs` — every method throws `NotSupportedException("HTTP transport is not implemented in this phase.")`. `DataVanger.Engine/Status/ModuleStatusAggregator.cs` reports signed updates as not configured. |

## Service & IPC

| Module | Status | Evidence (file) |
|---|---|---|
| Windows service mode | **Prepared (implemented; opt-in)** | `DataVanger.Service/Hosting/WindowsServiceInstaller.cs` implements `--install`/`--uninstall` via admin-gated `sc.exe` (with restart-on-failure recovery); `Program.cs` `--service` hosts the runtime via `AddWindowsService` (`DataVangerServiceWorker : IHostedService`) and maps SCM start/stop to the runtime. Admin-gated, never auto-starts, no silent elevation. `--console`/`--status`/`--validate-config`/`--help` also work. (Earlier "Stub" entry was stale.) |
| Named Pipe IPC | **Active (local, payload-validated)** | `DataVanger.Infrastructure/Ipc/NamedPipeDataVangerServiceHost.cs` / `NamedPipeDataVangerServiceClient.cs`, `IpcSecurityPolicy.cs`, `NamedPipeFraming.cs`, `IpcSerialization.cs`; handlers in `DataVanger.Service/Ipc/*` |
| IPC ACLs | **Active (Windows, cfg-gated)** | `IpcPipeSecurity.cs` builds a `PipeSecurity` descriptor and `NamedPipeDataVangerServiceHost` applies it by default on Windows. Access is limited to the creating user, Local System, and explicitly allowed local principals; broad forbidden principals are rejected. `RequireAclHardening` provides a fail-closed gate. Payload allowlist/size validation remains independent. |

## Runtime telemetry

| Module | Status | Evidence (file) |
|---|---|---|
| ETW provider | **Prepared/opt-in real provider + Fallback** | `WindowsEtwRuntimeProvider` is hosted behind `EnableEtwRuntimeTelemetry`; it publishes into the shared resident pipeline. `CaptureEtwCommandLine` and `CaptureEtwPowerShellSignals` are separate default-OFF settings and reuse sanitization/indicator helpers. Null/InMemory providers remain safe fallbacks. No confirmation or action authority. |
| AMSI scan-path adapter | **Stub** | `DataVanger/Behavioral/Adapters/AmsiBehaviorAdapter.cs` remains unavailable; no system provider is registered and no script is blocked. |
| AMSI resident runtime | **Prepared / Passive when service runs** | OS-neutral provider code lives in `DataVanger.Infrastructure/Runtime/Amsi/*`. `DataVangerServiceRuntime` starts `InMemoryAmsiProvider`; `AmsiRuntimeBridge` republishes explicit `SubmitAmsiContent` observations as `ScriptObserved` with indicator metadata into the shared behavioral pipeline. No `amsi.dll` patch/registration, blocking, confirmation, or automatic action. |

## UI, settings, reporting

| Module | Status | Evidence (file) |
|---|---|---|
| Module status UI | **Needs audit** | Data source exists: `DataVanger.Engine/Status/ModuleStatusAggregator.cs` + `DataVanger.Shared/Status/ModuleStatusModels.cs`. A dedicated UI surfacing the Active/Prepared/Stub taxonomy is a future phase; current UI exposure is unverified. |
| Settings UI | **Active** | `DataVanger/SettingsWindow.xaml(.cs)` exposes 28/29 `AppSettings` properties; `TrustedPublishers` base list intentionally not UI-exposed (users edit `ExtraTrustedPublishers`). |
| Reporting / forensics | **Active** | `DataVanger/Core/ReportGenerator.cs`, `DataVanger/Reporting/ReportService.cs` (CSV/TXT/HTML/JSON). *Needs audit (light): CSV quoting/injection not re-verified this round.* |

## Tests

| Module | Status | Evidence (file) |
|---|---|---|
| xUnit tests | **Active** | `DataVanger.Tests/DataVanger.Tests.csproj` (xunit 2.9, runner 2.8, Test.Sdk 17, coverlet 6); `TestParallelization.cs` disables parallelization. 2026-06-27 Windows x64: full suite **675/675**; filtered ETW **16**, AMSI **7**, Service **74**, Memory **5**, YARA **27**, Publisher **50**, IPC ACL **29**, AntiFalsePositive **14**; `DATAVANGER_REQUIRE_REAL_YARA=1` YARA **27/27**. |
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

1. **Memory/AMSI resident wiring** — resolved. Shared code is in
   `DataVanger.Infrastructure`; the service has no WPF reference; memory is a
   bounded default-OFF startup pass; AMSI is explicit-submission observation.
2. **Module status UI** — confirm whether any UI view surfaces
   `ModuleStatusAggregator`'s Active/Prepared/Stub taxonomy (future phase 18).
3. **Reporting CSV** — re-verify CSV quoting / CSV-injection handling in
   `ReportGenerator` / `ReportService`.
4. **Git provenance** — this validation workspace is an exported source tree without
   `.git`, and `gh` is unavailable, so branches/commits/pushes/PRs could not be
   produced here. Build/test gates were run from the folder containing `DataVanger.sln`.
