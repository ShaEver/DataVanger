# DataVanger V.Alpha

DataVanger is a Windows desktop security/anti-malware suite (WPF UI + a background
service) focused on **high-confidence detection with a strict anti-false-positive
contract**. It performs on-demand and scheduled file scanning, lightweight YARA
matching, PE/script/archive/document/browser-extension analysis, reputation
scoring, secure quarantine, and (prepared) realtime protection.

> **Status honesty:** several subsystems are **implemented and tested** but
> **not yet activated in production** (real libyara, HTTP update transport, the
> Windows service, real ETW/AMSI providers). This README and
> [`docs/MODULE_STATUS_MATRIX.md`](docs/MODULE_STATUS_MATRIX.md) label every module
> **Active / Prepared / Fallback / Stub / Disabled / Degraded / Needs audit** so
> nothing is over-claimed. Do not assume a prepared/stub module is active.

---

## 1. Project overview

- **Goal:** detect malware on Windows with strong guarantees that heuristics alone
  never produce a "confirmed malware" verdict or an automatic destructive action.
- **Shape:** a WPF/WinForms desktop app (`DataVanger`) plus four class libraries and
  a service host, sharing a contract assembly.
- **Anti-FP first:** the entire pipeline is built so that *confirmation* is rare and
  earned (see [Anti-false-positive contract](#7-anti-false-positive-contract)).

## 2. Architecture overview

```
DataVanger (WPF/WinForms UI, net8.0-windows)
  Core/ScanEngine ── 5-phase scan ── DetectionPipeline ── DetectionModuleRegistry
    modules: Hash, Heuristic, Script, Pe (+per-section entropy), Archive, Document,
             BrowserExtension, Yara, Persistence
  Reputation/ReputationEngine      Core/ThreatClassificationPolicy + AntiFalsePositivePolicy
  Engine/EngineComposition (wires modules + IYaraEngine fallback)
  Infrastructure/* adapters → Quarantine / Scheduler / Realtime / Yara
  Memory/* · Behavioral/* · Runtime/Etw/*   (engines exist; not in per-file scan set)

DataVanger.Engine (net8.0)         Quarantine V2 · SignedUpdates · Realtime decision ·
                                   ProtectedFiles (anti-ransomware) · Status aggregator
DataVanger.Infrastructure (net8.0) Ipc (NamedPipe + IpcSecurityPolicy) · Etw providers ·
                                   Quarantine (DPAPI key, FS store) · FileSystem watchers
DataVanger.Service (net8.0)        IPC command handlers · realtime host · (--service = stub)
DataVanger.Shared (net8.0)         all interfaces / DTOs / enums (contracts)
```

## 3. Six-project structure

| Project | TFM | Type | Role |
|---|---|---|---|
| `DataVanger` | net8.0-windows | WinExe (WPF+WinForms) | UI, scan engine, detection modules, adapters |
| `DataVanger.Engine` | net8.0 | classlib | Quarantine V2, signed-update verification, realtime decision engine, protected-files, status aggregator |
| `DataVanger.Infrastructure` | net8.0 | classlib | Named-pipe IPC, ETW providers, DPAPI quarantine key, file watchers |
| `DataVanger.Service` | net8.0 | Exe | Service host + IPC command handlers (diagnostic stub for `--service`) |
| `DataVanger.Shared` | net8.0 | classlib | Shared contracts/DTOs/enums |
| `DataVanger.Tests` | net8.0-windows | xUnit | Test suite (legacy parity mega-test + focused suites) |

`DataVanger.Infrastructure` references `Microsoft.Diagnostics.Tracing.TraceEvent`
and `System.Security.Cryptography.ProtectedData` (DPAPI, Windows-guarded). The main
`DataVanger` project has **no active NuGet PackageReference** (the dnYara reference
in `DataVanger/DataVanger.csproj` is documented **inside an XML comment only** and is
not active — see Real libyara below).

## 4. Build commands

> Requires **Windows + .NET 8 SDK** — `DataVanger`, `DataVanger.Service`, and
> `DataVanger.Tests` target `net8.0-windows` and do not build on Linux/macOS.

```powershell
dotnet build DataVanger/DataVanger.csproj
dotnet build DataVanger.Tests/DataVanger.Tests.csproj
dotnet build DataVanger.Service/DataVanger.Service.csproj
dotnet build DataVanger.Engine/DataVanger.Engine.csproj
dotnet build DataVanger.Shared/DataVanger.Shared.csproj
dotnet build DataVanger.Infrastructure/DataVanger.Infrastructure.csproj
dotnet build DataVanger.sln
```

## 5. Test commands

```powershell
dotnet test DataVanger.Tests/DataVanger.Tests.csproj
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~AntiFalsePositive"
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~Publisher"
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~Yara"
```

## 6. Validation commands (invariants)

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
Expected: **zero** anonymous catch blocks · **zero** `lock(qm)` · **zero** CRLF `.cs` files.

## 7. Anti-false-positive contract

Enforced in `DataVanger/Core/ThreatClassificationPolicy.cs` and
`AntiFalsePositivePolicy.cs`:

- **`ConfirmedMalware` only** when `finding.IsBlacklisted` (known-malicious hash)
  **or** `finding.HasConfirmedSignature` (evidence whose `CanConfirmMalware` is true —
  e.g. a curated lightweight YARA rule explicitly marked `confirmed`).
- **Heuristic-only** evidence is **clamped to `HighRisk`** (`RiskThresholds.High`),
  never `ConfirmedMalware`.
- **Automatic quarantine only occurs for `ConfirmedMalware`** (and a score gate).
- **None of the following can confirm malware on their own:** heuristics, PE
  section entropy, real external YARA matches, publisher trust, reputation,
  behavioral correlation, ETW/AMSI events, memory-scanner findings, browser-extension
  heuristics, realtime file events, IPC events, service errors, update failures, or
  quarantine restore failures.
- **Trusted publisher never overrides a blacklisted/known-malicious hash**, and the
  publisher check is currently a **case-insensitive substring match** of the
  certificate subject (not yet certificate-chain/thumbprint validation —
  *needs hardening*, see matrix).

## 8. Security posture (summary)

- Quarantine V2: authenticated encryption + HMAC integrity + (Windows) DPAPI key
  protection; restore is integrity-verified and **never automatic**.
- Auto-quarantine is gated on `ConfirmedMalware` only.
- Signed updates are the only runtime update path: RSA-PSS / ECDsa verification,
  anti-downgrade and bounded HTTPS transport fail closed. User-settings PEM is
  development/operator trust only; production still needs vendor/admin trust.
- Realtime/service/ETW/AMSI are prepared but not production-activated.

## 9. Active vs Prepared vs Stub (read this before trusting a feature)

| Capability | State |
|---|---|
| File scanning, detection pipeline, anti-FP, quarantine V2, scheduler, lightweight YARA, reputation, configurable trusted publishers | **Active** |
| Real libyara backend (`#if YARA_REAL`, no active package) | **Prepared (not active)** |
| Signed-update HTTPS transport | **Prepared (development/operator; fail-closed)** |
| Windows service (`--service` diagnostic stub) | **Stub** |
| Real ETW / AMSI providers (`IsAvailable=false`) | **Prepared/Stub** |
| Named-pipe IPC ACLs | **Active on Windows, cfg-gated** (`PipeSecurity` restricts local principals; fail-closed mode available) |
| Memory scanner / behavioral engine in the per-file scan set | **Needs audit** (engines exist + are tested, but are not wired into `EngineComposition`) |

Full detail with file references: [`docs/MODULE_STATUS_MATRIX.md`](docs/MODULE_STATUS_MATRIX.md).

## 10. Current known limitations

- **No verified green build/test is on record from a non-Windows environment**
  (the toolchain requires Windows + .NET 8). Do **not** claim a "STABLE" milestone
  until `dotnet build DataVanger.sln` + `dotnet test` pass on Windows.
- `DataVanger.Tests/LegacyParityTests.cs` is a single faithful-wrapper mega-`[Fact]`
  (≈49 subsystem sections). Async/await hygiene (Phase 08) was applied to the test
  body; synchronous helper classes intentionally keep blocking calls (documented
  in-file). Test decomposition is a future phase.
- Real libyara, HTTP updates, Windows service, ETW/AMSI, and IPC ACLs are **approval-
  gated activation phases** — not enabled by default.

## 11. Documentation

- [`docs/OPERATOR_GUIDE.md`](docs/OPERATOR_GUIDE.md) — running, settings, scan/quarantine/scheduler/realtime/update/service behavior, what's active vs prepared.
- [`docs/DEVELOPER_GUIDE.md`](docs/DEVELOPER_GUIDE.md) — layout, detection pipeline, adding modules/tests, invariants, safety rules.
- [`docs/MODULE_STATUS_MATRIX.md`](docs/MODULE_STATUS_MATRIX.md) — per-module status with exact file references.
- `outputs/*` — phase specifications and history.
