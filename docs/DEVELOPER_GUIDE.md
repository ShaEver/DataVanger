# DataVanger V.Alpha — Developer Guide

Audience: contributors. Describes the current code layout, the detection pipeline,
how to extend it safely, the test layout, invariants, and the project's safety rules.

---

## 1. Project layout

```
DataVanger/                     WPF/WinForms UI app (net8.0-windows)
  Core/                         ScanEngine, AppSettings, Models, ThreatClassificationPolicy,
                                AntiFalsePositivePolicy, LightweightYaraDatabase, WinTrust, ...
  Detection/                    *DetectionModule.cs, DetectionPipeline, DetectionModuleRegistry,
                                PE/, Placeholders/ ([Obsolete] seams)
  Engine/                       EngineComposition, DeepScan/
  Infrastructure/               adapters: YaraEngineAdapter, LibyaraEngine (#if YARA_REAL),
                                Quarantine/Scheduler/Realtime service adapters, Sha256HashService, ...
  Reputation/                   ReputationEngine
  Memory/  Behavioral/  Runtime/Etw/   runtime engines (see Needs audit in matrix)
  Scheduling/ SelfProtection/ Reporting/  + windows: MainWindow, SettingsWindow, QuarantineWindow, ...

DataVanger.Engine/              Quarantine V2, Updates/SignedUpdates, Realtime decision engine,
                                ProtectedFiles, Status/ModuleStatusAggregator
DataVanger.Infrastructure/      Ipc/ (NamedPipe + IpcSecurityPolicy), Etw/ providers,
                                Quarantine/ (DPAPI key, FS store), FileSystem/ watchers, Runtime/ clock
DataVanger.Service/             Program.cs (CLI/stub), Ipc/ handlers, Realtime/, Runtime/
DataVanger.Shared/              contracts/DTOs/enums (Ipc, Updates, Quarantine, Realtime, ...)
DataVanger.Tests/               xUnit suite (+ Fixtures/, TestSupport/)
outputs/                        phase specifications + history
docs/                           this documentation set
```

## 2. Detection pipeline overview

- `EngineComposition.BuildDefault` (`DataVanger/Engine/EngineComposition.cs`) wires the
  ordered per-file detection module set and selects the YARA engine (real if available,
  otherwise the guaranteed lightweight fallback).
- Modules (order): `HashDetectionModule`, `HeuristicDetectionModule`,
  `ScriptDetectionModule`, `PeDetectionModule` (incl. **per-section entropy**,
  descriptive-only), `ArchiveDetectionModule`, `DocumentDetectionModule`,
  `BrowserExtensionDetectionModule`, `YaraDetectionModule`, `PersistenceDetectionModule`.
- `DetectionPipeline` runs modules with exception isolation (`DetectionModuleBase`
  catches per-module failures → empty evidence, never a scan-killing crash).
- `ScanEngine.AnalyzeSingleFileAsync` aggregates: hash → known-safe/known-bad →
  reputation → pipeline → **anti-FP clamp** → report/quarantine decision.
- Classification: `ThreatClassificationPolicy` / `AntiFalsePositivePolicy` decide
  `ConfirmedMalware` vs `HighRisk` vs lower (see Anti-FP policy below).

> Note: the shared process-memory engine is in
> `DataVanger.Infrastructure/Memory/*`; behavioral runtime code is in
> `DataVanger.Engine/Behavioral/Runtime/*`. They are exercised on the resident
> service pipeline (memory/ETW/AMSI), but are intentionally **not** per-file
> `EngineComposition` modules. Do not document them as file-scan detection.

## 3. How to add a detection module

1. Implement `IDetectionModule` (usually by extending `DetectionModuleBase` and
   overriding `Supports(...)` + `Analyze(...)`), in `DataVanger/Detection/`.
2. Emit `Evidence` with an appropriate `EvidenceStrength`. **Only** set
   `CanConfirmMalware = true` for genuinely confirming sources (curated/known). Real
   external/heuristic signals must be non-confirming (`Confirmed=false`).
3. Register it in `EngineComposition.BuildDefault`'s module list (mind ordering).
4. Add focused tests (see below). Do not weaken the anti-FP contract.

## 4. How to add tests

- Add a new `*.cs` test class under `DataVanger.Tests/` using xUnit
  (`[Xunit.Fact]` / `[Theory]`). Reuse fixtures in `DataVanger.Tests/Fixtures/`
  (`PeFactory`, `TempFileScope`).
- Prefer focused, independently-runnable Facts (so `--filter` can target them).
- Use `async Task` test methods with `await` for async APIs (avoid blocking
  `.GetAwaiter().GetResult()` in **test methods** — see xUnit1031 below).
- Do not enable parallelization; the suite is intentionally sequential
  (`DataVanger.Tests/TestSupport/TestParallelization.cs`).

## 5. xUnit test layout

- **`DataVanger.Tests/LegacyParityTests.cs`** — a single faithful-wrapper mega-`[Fact]`
  (`DataVanger_LegacySuite_AllChecksPass`) migrated 1:1 from the legacy runner; ≈49
  subsystem sections with a private `Assert(bool,string)` shim. Synchronous,
  file-scoped helper classes (e.g. `Phase08SecureQuarantineV2`, `Phase11ServiceIpcUi`)
  hold section logic invoked by the Fact.
- **Focused suites:** `AntiFalsePositiveTests.cs` (3 Facts),
  `TrustedPublisherSettingsTests.cs` (4 Facts, matches `~Publisher`),
  `YaraEngineFallbackTests.cs` (4 Facts, matches `~Yara`).
- **Fixtures/** `PeFactory.cs`, `TempFileScope.cs`. **TestSupport/** parallelization
  switch.

## 6. Warning debt / Phase 08 status

- **Phase 08 (async test hygiene)** converted blocking `.GetAwaiter().GetResult()`
  calls in the **async mega-`[Fact]` body** to `await` (≈182 sites), removing
  xUnit1031 blocking-async warnings there.
- A **Phase 08 correction** reverted ≈43 conversions that had been wrongly applied
  inside **synchronous file-scoped helper classes** (where `await` is illegal —
  CS4032/CS4033), restored `BuildRouter`'s `out`-parameter helper to synchronous
  (fixed CS0177), and made 5 pre-existing fire-and-forget calls explicit discards
  (`_ = ...;`) to clear CS4014. Those helper-class blocking calls are **not**
  xUnit1031 violations (the analyzer targets `[Fact]`/`[Theory]` bodies, not helper
  methods) and are documented in-file with `xUnit1031-deferred` notes.
- One in-Fact site remains deferred (`xUnit1031-deferred`): a blocking call inside a
  synchronous `DelegateRuntimeEventConsumer` callback (converting it would force
  async-void fire-and-forget and break a "runs exactly once" assertion).
- **Validation status:** the Phase 08 + correction build/test must be validated on
  **Windows** (no SDK is available in non-Windows environments). Do not claim the
  build is green without a Windows `dotnet build`/`dotnet test`.

## 7. Invariant checks (must stay green)

```powershell
Get-ChildItem -Recurse -Filter *.cs |
  Where-Object { $_.FullName -notmatch '\\bin\\|\\obj\\' } |
  Select-String 'catch\s*\{\s*\}'

Get-ChildItem -Recurse -Filter *.cs |
  Where-Object { $_.FullName -notmatch '\\bin\\|\\obj\\' } |
  Select-String 'lock\s*\(qm\)'

Get-ChildItem -Recurse -Filter *.cs |
  Where-Object { $_.FullName -notmatch '\\bin\\|\\obj\\' } |
  ForEach-Object { $c = Get-Content $_.FullName -Raw; if ($c -match "`r") { $_.FullName } }
```
Expected: **zero** anonymous `catch{}` · **zero** `lock(qm)` · **zero** CRLF `.cs`
(typed empty catches such as `catch (IOException) { }` are allowed). `.gitattributes`
enforces `eol=lf`.

## 8. Build / test matrix

```powershell
dotnet build DataVanger/DataVanger.csproj
dotnet build DataVanger.Tests/DataVanger.Tests.csproj
dotnet build DataVanger.Service/DataVanger.Service.csproj
dotnet build DataVanger.Engine/DataVanger.Engine.csproj
dotnet build DataVanger.Shared/DataVanger.Shared.csproj
dotnet build DataVanger.Infrastructure/DataVanger.Infrastructure.csproj
dotnet build DataVanger.sln
dotnet test DataVanger.Tests/DataVanger.Tests.csproj
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~AntiFalsePositive"
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~Publisher"
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~Yara"
```
All require Windows + .NET 8 SDK.

## 9. Safety rules

- **No production behavior changes** in test-only or docs-only phases.
- **Preserve fallbacks** (lightweight YARA, Null/InMemory ETW, file/in-memory update
  transport, console service fallback).
- **Do not enable native packages** (dnYara) without a verified restore/build.
- **Do not expand auto-quarantine** beyond `ConfirmedMalware`.
- **Do not add remote/cloud integrations** or network transports without an isolated,
  opt-in, verify-before-trust design and approval.
- **Do not change assertions** to make tests pass; decompose/migrate faithfully.

## 10. Anti-false-positive policy (authoritative)

`DataVanger/Core/ThreatClassificationPolicy.cs`:
`ConfirmedMalware` iff `IsBlacklisted` (known-malicious hash) **or**
`HasConfirmedSignature` (evidence with `CanConfirmMalware`). Otherwise score ≥
`RiskThresholds.High` → `HighRisk`, etc. `AntiFalsePositivePolicy` clamps
heuristic-only findings to `HighRisk`. `AllowsAutomaticAction(...)` returns true
**only** for `ConfirmedMalware`, gating auto-quarantine. Real external YARA matches
are emitted `Confirmed=false, Score=0` and therefore cannot confirm.

## 11. No-overclaiming rule

Documentation and status reporting must reflect **code reality**, not intent. If code
and intent disagree, document the code reality and mark the gap **Needs audit**.
Never label a Prepared/Stub module as Active. See `docs/MODULE_STATUS_MATRIX.md`.
