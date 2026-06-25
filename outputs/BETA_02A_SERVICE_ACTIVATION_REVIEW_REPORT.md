# BETA 02A — SERVICE ACTIVATION REVIEW REPORT

Phase: `02A_SERVICE_ACTIVATION_REVIEW` (DataVanger V.Beta Improvement Plan)
Executed: 2026-06-12
Verdict: **IMPLEMENTED. Activation model audited with live CLI evidence; one fail-closed hardening
added (binPath validation); 17/17 new tests pass on Linux against the real Service assembly;
Windows manual runbook + 02B gap list delivered. No remediation capability added.**

---

## 0. Baseline replacement (pre-phase requirement)

- **ZIP cleanliness:** PASS — 656 entries, **0** matches for `bin/`, `obj/`, `TestResults/`,
  `Publicar/`, `.vs/`, or nested `.zip` (the only initial "hit" was `unzip`'s own `Archive:` header
  line, excluded by checking the entry list via `unzip -Z1`).
- **Replacement:** working tree wiped (except `.git`) and repopulated verbatim; post-copy
  `diff -rq` of tree vs archive: **0 differences**. No merging, no stale files, no old ZIPs.
- **Exact delta vs previous committed baseline:** one new file —
  `DataVanger/Properties/AssemblyInfo.cs` (`InternalsVisibleTo("DataVanger.Tests")`), the
  stabilization fix letting the real test assembly reach `LocalizationService` internals (my Linux
  scratch harness compiled tests into the same assembly, so it could not catch that). Expected,
  behavior-neutral → adopted as commit "Adopt stabilized post-01B baseline".
- **Solution identity:** `DataVanger.sln` references 6 projects; all 6 project directories present.
- **Baseline validation:** `dotnet restore` clean; Shared/Engine/Infrastructure/Service build
  **0 errors**. `DataVanger.sln` full build + default/x64 test suites remain **Windows-only**
  (standing environment exception — WindowsDesktop SDK absent on Linux).

## Phase 02A Final Report

- **Branch/checkpoint:** `claude/adoring-dirac-jxo678`, on top of the adopted post-01B stabilized
  baseline.

- **Files changed:**
  - `DataVanger.Service/Hosting/WindowsServiceInstaller.cs` — hardened (details below).
  - `DataVanger.Tests/ServiceActivationReviewTests.cs` — new (17 tests, `~ServiceActivationReview`).
  - `docs/SERVICE_ACTIVATION_RUNBOOK.md` — new operator runbook.
  - `outputs/BETA_02A_SERVICE_ACTIVATION_REVIEW_REPORT.md` — this report.

- **Service install/status/uninstall behavior (audited, with live Linux CLI evidence):**
  - Default invocation: banner + exit, nothing resident — verified live.
  - `--status`: structured snapshot (state/mode/dev-mode/started-at/active-protection/warnings/
    8 modules with availability) — verified live; protection correctly reports inactive, modules
    Passive/Available.
  - `--validate-config`: safe defaults confirmed live — `service-enabled: True`,
    `force-dev-mode: False`, **`etw-runtime-telem: False` (gate ships OFF)**, 0 warnings.
  - `--install`: Windows-only (verified live on Linux: clear message + exit 3, nothing registered);
    admin-gated fail-closed (exit 4, explicit "re-run elevated", no silent elevation); registers
    via `sc.exe` structured arguments: `start= demand` (never auto-started), display name,
    description, bounded recovery (3× restart/60 s, reset 86 400 s); failures of any `sc` step are
    surfaced (exit 5), never simulated as success.
  - `--uninstall`: admin-gated, stop (best-effort) **then** delete — order now test-asserted.

- **Service binary path evidence:** `ResolveServiceBinPath` prefers the **absolute apphost**
  (`"<dir>\DataVanger.Service.exe" --service`) — registered directly so the SCM controls the real
  process (documented sc-stop-1061 rationale); muxer form only when no apphost; `--config` paths
  normalized to absolute (SCM starts services in System32). **Gap found and closed (the one
  code change of this phase):** the last-ditch compositions could yield a PATH-resolved bare
  `dotnet` or an executable-less `"--service"`, and install would register whatever came back.
  Added `ExtractBinPathExecutable` + `TryValidateServiceBinPath` (absolute + existing executable
  required) called by `InstallWindows`: install now **aborts with new exit code 6
  (`ExitInvalidServicePath`)** instead of registering a relative/guessed path. Fail-closed-only
  behavior change, explicitly required by §9/§17 ("never register a relative or PATH-resolved
  service path").

- **UI elevation evidence:** no `app.manifest` requesting elevation exists anywhere in the tree
  (re-verified this phase); the WPF project gained nothing privilege-related; elevation appears
  exclusively inside `WindowsServiceInstaller` behind `--install`/`--uninstall`. Manual Task-Manager
  check remains in the Windows runbook.

- **Tests run:**
  - New `ServiceActivationReviewTests` — **17/17 PASS on Linux**, compiled against the **real**
    `DataVanger.Service` + `DataVanger.Shared` projects (both net8.0): executable extraction
    (quoted/unquoted/empty), validator accepts absolute+existing only, rejects empty/relative/bare-
    `dotnet`/missing/argument-only compositions, bounded recovery plan details (86 400 reset,
    3× restart/60 000), every plan step is `sc.exe` with structured args, uninstall stops before
    delete, **IPC surface exposes no remediation capability** (no command/category name contains
    Remediat/Kill/Disinfect/RemoveThreat/FixThreat) and every allowlisted command maps to a known
    non-Unknown category.
  - Existing coverage confirmed in place (not duplicated): binPath composition forms, non-Windows
    install/uninstall fail-closed (`ServiceLifecycleTests`).
  - Live CLI regression after the change: `--install` on Linux still exits 3; all four
    cross-platform projects build **0 errors**.
  - Full suite / x64 / `~Service` / `~Ipc` / `~AntiFalsePositive` / `~Quarantine` filters: **pending
    on Windows** (standing environment exception) — commands listed in the phase MD §12.

- **Manual Windows validation:** PENDING — mandatory §11 checklist codified step-by-step (with
  expected outputs and `sc qc`/`sc qfailure` verification) in `docs/SERVICE_ACTIVATION_RUNBOOK.md` §2.

- **Remediation capability added: No.** No remediation command, DTO, handler, or destructive API
  call was introduced; `DeleteQuarantineItem` still returns `Unsupported`; the no-remediation
  boundary is now regression-tested.

- **Open risks for 02B (documented in runbook §4):**
  1. Named pipe has **no `PipeSecurity` ACL** — any local user can connect (payload validation
     only). Must gate before any privileged command exists.
  2. No client-identity attribution/logging on pipe connections.
  3. Single-connection pipe serving model — revisit under 02B load expectations.
  4. ETW telemetry gate stays config-opt-in, default OFF (unchanged).

- **Stop conditions encountered:** none. Install/uninstall/status behavior proved consistent;
  UI remains non-elevated; no remediation-like command introduced; service path handling is now
  provably unambiguous (the previously possible ambiguous registration aborts).

## What was intentionally NOT implemented

IPC ACL changes (02B's gate — documented only); remediation commands/DTOs/handlers (03/04);
Removal Center UI; resident-protection activation beyond Alpha; any change to detection,
quarantine, update, YARA, or anti-FP behavior; UI elevation.

## Recommendation

**Ready for Codex stabilization** as the phase MD prescribes: service lifecycle review +
validation-log sanity on Windows — run the §12 build/test matrix, the `~ServiceActivationReview`
filter, and the runbook §2 manual procedure (install/qc/qfailure/start/stop/uninstall + UI
elevation check). The destructive-API scan items from the phase's stabilization checklist
(`File.Delete`, `Process.Kill`, `Registry.SetValue`, …) should confirm all matches are
pre-existing or test-only — this phase's diff contains none.
