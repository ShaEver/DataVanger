# BETA 00 — BASELINE GUARDRAILS REPORT

Phase: `00_BASELINE_GUARDRAILS` (DataVanger V.Beta Improvement Plan, Phase 0)
Executed: 2026-06-11
Verdict: **BASELINE LOCKED — environment exceptions documented below; Windows completion runbook included.**

This phase is documentation/validation only. **No Beta behavior change was introduced.** The only
file-content change relative to the Alpha archive is one behavior-neutral hygiene fix to `.gitignore`
(documented in §6), explicitly permitted by the phase's allowed scope.

---

## 1. Branch / checkpoint identity

| Item | Value |
|------|-------|
| Beta starting branch | `claude/adoring-dirac-jxo678` (repository `ShaEver/claude_workspace`) |
| Branched from | commit `20430e2` ("Add files via upload") — the commit that introduced the Alpha archive |
| Oracle artifact | `DataVanger V.Alpha.zip` (kept tracked at repo root) |
| Oracle SHA-256 | `b38d548c0b60cfc1c9d518a92b2f9ec55bc642d7a5949d1c15ebb6691cf6d9fa` |
| Oracle size / contents | 969,970 bytes; 556 files (508 `.cs`) under `DataVanger V.Alpha/DataVanger V.Alpha/` |
| Import action | Solution root extracted verbatim from the oracle zip to the repository root (this commit). The pre-existing 2-line repository stub `README.md` was replaced by the Alpha solution `README.md` from the archive. |

All six expected projects are present and referenced by `DataVanger.sln`:
`DataVanger/`, `DataVanger.Engine/`, `DataVanger.Infrastructure/`, `DataVanger.Service/`,
`DataVanger.Shared/`, `DataVanger.Tests/` — plus `docs/` and `outputs/` (Alpha phase records 00–22).

Note: the oracle zip remains tracked even though the imported `.gitignore` contains `*.zip`
(it was committed before the ignore rule applied; git keeps tracking already-tracked files).

## 2. Execution environment (governs every classification below)

| Item | Value |
|------|-------|
| OS | Linux 6.18.5 (managed remote container) — **not Windows** |
| .NET SDK | 8.0.128 (Canonical/Ubuntu build, installed from apt during this phase) |
| WindowsDesktop SDK component | **Absent** — Canonical's Linux SDK build does not ship `Microsoft.NET.Sdk.WindowsDesktop`; `-p:EnableWindowsTargeting=true` does not compensate |
| NuGet | Reachable; full solution restore succeeded |
| Consequence | WPF app + test project (both `net8.0-windows`) cannot build/run here. Matches the Alpha README §10 known limitation: "No verified green build on non-Windows (WPF targets only)." |

## 3. Build matrix results

Runbook commands from the phase MD §12, executed from the solution root:

| Command | Result | Classification |
|---------|--------|----------------|
| `dotnet restore` (solution) | **PASS** — all 6 projects restored | — |
| `dotnet build DataVanger.Shared` | **PASS** — 0 warnings, 0 errors | — |
| `dotnet build DataVanger.Engine` | **PASS** — 0 warnings, 0 errors | — |
| `dotnet build DataVanger.Infrastructure` | **PASS** — 0 warnings, 0 errors | — |
| `dotnet build DataVanger.Service` | **PASS** — 0 warnings, 0 errors | — |
| `dotnet build DataVanger` (WPF) | **FAIL** — `MSB4019: Microsoft.NET.Sdk.WindowsDesktop.targets was not found` (also with `EnableWindowsTargeting=true`) | **Environment-only** |
| `dotnet build DataVanger.Tests` | **FAIL** — same `MSB4019` via its `ProjectReference` to `DataVanger.csproj` (TFM `net8.0-windows`) | **Environment-only** |
| `dotnet build DataVanger.sln` | **FAIL** — 2 errors, both the `MSB4019` above; the four cross-platform projects inside the solution build clean | **Environment-only** |

## 4. Test matrix results

| Command | Result | Classification |
|---------|--------|----------------|
| `dotnet test DataVanger.Tests` (default) | **NOT RUNNABLE** — test project cannot build (see §3) | **Environment-only** |
| `dotnet test … --arch x64` | **NOT RUNNABLE** — same root cause | **Environment-only** |
| Focused filters `~AntiFalsePositive`, `~Quarantine`, `~Ipc`, `~Service`, `~Yara`, `~Update` | **NOT RUNNABLE** — same root cause | **Environment-only** |
| Real YARA hard-validation (`DATAVANGER_REQUIRE_REAL_YARA=1`) | **UNAVAILABLE** — requires Windows + libyara native pack at runtime; per Alpha `outputs/22_FINAL_STABILIZATION*` this was last validated green on Windows (168/168, hard real-YARA gate 22/22) on 2026-06-10 | **Environment-only** |

**Stop-condition ruling (§14 vs §9/§20 of the phase MD):** §14 lists build/test failure as a stop
condition, but §9 requires classifying failures first and §20 accepts explicitly documented environment
exceptions. Every failure above is environment-only (missing WindowsDesktop SDK on Linux), reproduces the
Alpha README's own documented limitation, and implicates **zero** source issues — the four projects this
environment *can* compile build with 0 warnings / 0 errors. The phase therefore proceeds with the baseline
locked and the Windows runbook below as the completion path. **No source behavior was changed to make
anything pass.**

## 5. Environment-neutral invariant audit (all PASS)

| Invariant (phase §13) | Method | Result |
|-----------------------|--------|--------|
| No empty catch blocks | grep for `catch {}` / `catch { }` (same-line and multiline) across all 508 `.cs` | **0 found — PASS.** Nuance recorded honestly: 52 *typeless* `catch {` blocks exist, but every one has a non-empty body (`return null;`, best-effort comments, etc.) — consistent with the Alpha invariant "zero anonymous empty catch", not a deviation. |
| No `lock(qm)` | grep | **0 found — PASS** |
| No CRLF in `.cs` | grep for `\r` in all `.cs` | **0 files — PASS** |
| No `bin/`, `obj/`, `Publicar/`, `TestResults/` committed/packed | archive scan + post-import scan | **None present — PASS** |
| Ignore rules cover generated artifacts | `.gitignore` review | `bin/`, `obj/`, `TestResults/`, `coverage/`, `.vs/` covered. **Gap found: `Publicar/`** (the `Compilar.bat` publish output) was not ignored → fixed in this phase (§6). |
| Line-ending policy | `.gitattributes` review | `* text=auto eol=lf`, `.bat/.cmd` CRLF, binaries marked — **consistent with the CRLF invariant — PASS** |
| Anti-FP / YARA / quarantine behavior untouched | scope audit | **No source file modified — PASS by construction** |

## 6. Behavior-neutral fixes applied (complete list)

1. **`.gitignore`: appended `Publicar/`.** Justification: `Compilar.bat` publishes a self-contained
   single-file build to `Publicar/`; it is a generated artifact demonstrably not ignored. Allowed by
   phase §7 ("`.gitignore` only if generated build/test artifacts are demonstrably not ignored").
   No other file from the Alpha archive was modified.

## 7. Module-status snapshot (baseline oracle for later phases)

Authoritative source imported with the baseline: `docs/MODULE_STATUS_MATRIX.md` (Alpha Phase 22 audit).
Independently spot-verified against source during this phase:

| Module / subsystem | Baseline state | Verified anchor |
|--------------------|----------------|-----------------|
| Detection pipeline (9 modules: Hash, Heuristic, Script, PE, Archive, Document, BrowserExtension, Yara, Persistence) | **Active** | `DataVanger/Engine/EngineComposition.cs` wires exactly these 9 |
| Anti-FP contract | **Active** — `ConfirmedMalware` only via blacklist hash or `Confirmed=true` YARA; auto-action only for `ConfirmedMalware` | `DataVanger/Core/ThreatClassificationPolicy.cs`, `DataVanger/Classification/AntiFalsePositivePolicy.cs` |
| Real libyara backend | **Active** (compiled-in: `YARA_REAL` + `PlatformTarget x64` in `DataVanger.csproj`; dnYara 2.1.0 + NativePack 2.1.0.3); lightweight fallback guaranteed | `DataVanger.csproj` lines 41–42; `EngineComposition.BuildDefault` fallback logic |
| Quarantine V2 | **Active** (AES-256-GCM + DPAPI + HMAC; manual verified restore; auto-quarantine gated to ConfirmedMalware) | `DataVanger.Engine/Quarantine/QuarantineService.cs` |
| Scheduler (schtasks) | **Active** | `DataVanger/Core/SchedulerHelper.cs` |
| Signed-update verification | **Active** (RSA-PSS/ECDsa, anti-downgrade); **HTTP transport = Stub** (`HttpUpdateTransport` throws `NotSupportedException`) | `DataVanger.Engine/Updates/SignedUpdates/` |
| Windows service host & installer | **Plumbing real, protection dormant**: `--install`/`--uninstall` are a real admin-gated `sc.exe` installer (demand-start, recovery); `--service` hosts `DataVangerServiceRuntime`; no resident protection capability behind it | `DataVanger.Service/Program.cs`, `DataVanger.Service/Hosting/WindowsServiceInstaller.cs` |
| Named-pipe IPC | **Active, payload-validated; NO Windows ACL (`PipeSecurity`) — needs hardening (Beta Phase 2)** | `DataVanger.Infrastructure/Ipc/NamedPipeDataVangerServiceHost.cs` |
| IPC command surface | Categories: Status, Configuration, ProtectionControl, Scan, Quarantine, Update, EventQuery, Diagnostics. **Known unsupported operations:** `DeleteQuarantineItem` returns structured `Unsupported`; `PauseRealtimeProtection`/`ResumeRealtimeProtection` defined, no resident realtime behind them | `DataVanger.Shared/Ipc/DataVangerCommandCatalog.cs`, `DataVanger.Service/Ipc/QuarantineCommandHandler.cs` |
| ETW runtime telemetry provider | **Active** (real `TraceEvent` kernel-process session, opt-in, Windows-validated per Alpha Phase 17) | `DataVanger.Infrastructure/Etw/WindowsEtwRuntimeProvider.cs` |
| ETW behavioral adapter / AMSI adapter | **Stub** (`IsAvailable=false`, no-op) | `DataVanger/Behavioral/Adapters/` |
| Behavioral engine (5 rules), Memory scanner, ProtectedFiles anti-ransomware monitor | **Dormant** — implemented + tested, **not wired into `EngineComposition`** | `DataVanger/Behavioral/`, `DataVanger/Memory/`, `DataVanger.Engine/ProtectedFiles/` |
| Realtime monitor (FileSystemWatcher) | **Active in UI process only**, manual start; not service-hosted | `DataVanger/Core/RealtimeMonitor.cs` |
| Remediation capability | **NONE** beyond quarantine + junk cleanup (`CleanerEngine`) — the Beta gap by design | (absence verified across solution) |
| Settings schema | `AppSettings` JSON, `SchemaVersion = 1`, migration hook present | `DataVanger/Core/AppSettings.cs` |
| Version identity | `DataVanger` 3.1-alpha / 3.1.0 | `DataVanger/Core/VersionInfo.cs` |

**Later phases must prove against this table that no module was accidentally activated or regressed.**

## 8. Manual validation (phase §11)

UI launch, scan/quarantine/settings surface checks, and `--install`/`--status`/`--uninstall` observation
require a Windows desktop session — **not executable in this Linux container**; classified environment-only
and folded into the Windows runbook (§9). Static confirmation performed instead: no `app.manifest`
requesting elevation exists anywhere in the imported tree (the app remains non-elevated), and no new
elevated-UI requirement was introduced by this phase (no source change).

## 9. Windows completion runbook (for the next executor on a Windows machine)

Run from the repository root, .NET 8 SDK (Microsoft build) installed:

```powershell
dotnet restore
dotnet build DataVanger/DataVanger.csproj
dotnet build DataVanger.Tests/DataVanger.Tests.csproj
dotnet build DataVanger.Service/DataVanger.Service.csproj
dotnet build DataVanger.Engine/DataVanger.Engine.csproj
dotnet build DataVanger.Shared/DataVanger.Shared.csproj
dotnet build DataVanger.Infrastructure/DataVanger.Infrastructure.csproj
dotnet build DataVanger.sln
dotnet test DataVanger.Tests/DataVanger.Tests.csproj
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --arch x64
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~AntiFalsePositive"
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~Quarantine"
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~Ipc"
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~Service"
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~Yara"
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~Update"
$env:DATAVANGER_REQUIRE_REAL_YARA = "1"
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~Yara"   # hard real-YARA gate
```

Expected (per Alpha `outputs/22_FINAL_STABILIZATION*`, 2026-06-10): build matrix 8/8 PASS;
168/168 tests on default and x64; real-YARA hard gate green; libyara.dll present in bin/publish/test output.
Manual checks: launch `DataVanger.exe` without elevation; confirm scan, quarantine, settings,
reports, module-status, scheduled-scan, and update surfaces open; observe (do not change) service
`--install`/`--status`/`--uninstall`; record `Compilar.bat` packaging output and confirm `Publicar/`
stays untracked. Append results to this report.

## 10. Deviations from the Evolution Plan (Reality Rule record)

1. **Evolution Plan §"Direction" described `--install`/`--uninstall` as placeholders in one early audit
   note; reality: they are a real, admin-gated `sc.exe` installer.** Already corrected in the approved
   plan; restated here because it *reduces* Beta Phase 2 scope (activation hardening, not construction).
2. **Execution environment is Linux**, so the phase's Windows validation half is deferred to the §9
   runbook rather than executed. No other deviation found: archive contents, project set, module states,
   and invariants all match the plan's factual baseline.

## 11. Success criteria check (phase §20)

- Alpha baseline identified and preserved (zip SHA-256 + verbatim import): **YES**
- Required build/test commands green **or environment exceptions explicitly documented**: **YES (§3–§4)**
- x64 validation: **deferred to Windows runbook (environment exception)**
- Real YARA hard-validation: **explicitly unavailable here; last-known-green recorded (§4)**
- Packaging / generated-artifact hygiene documented: **YES (§5–§6)**
- Module status snapshotted: **YES (§7)**
- Later phases have a clear oracle: **YES — this report + the tracked Alpha zip + `docs/MODULE_STATUS_MATRIX.md`**

**Explicit statement: no Beta behavior change was introduced in this phase.**
