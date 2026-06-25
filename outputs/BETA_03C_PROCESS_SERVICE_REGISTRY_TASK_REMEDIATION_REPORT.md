## Phase 03C Final Report

Phase: `03C_PROCESS_SERVICE_REGISTRY_TASK_REMEDIATION` — UltraCode.
Executed: 2026-06-13.
Verdict: **System-scope remediation actions implemented behind abstractions with critical-target refusal,
backup/export/quarantine-before-mutate, journal-before-change, and rollback metadata; 38 new fake-backed
tests (107 remediation total) pass on Linux against the real Engine; no real destructive OS call exists;
purely additive. Windows full/x64 suite + real OS providers pending.**

- **Branch/checkpoint:** `claude/adoring-dirac-jxo678` on the adopted post-03B stabilized baseline (clean
  ZIP, 699 entries; delta = 2 03B-stabilization files; adopted then validated 0-error builds).

- **Files changed:** purely additive — **7 new Engine files** under `DataVanger.Engine/Remediation/System/`
  (namespace `DataVanger.Engine.Remediation.SystemScope`) and **6 new test files**. `git status` shows only
  new files; **no existing file modified**, so anti-FP, quarantine, scan, YARA, IPC, UI, and the 03A/03B
  remediation core are unchanged by construction.
  - Engine: `SystemRemediationCommon.cs` (shared outcome/result + journal helper), `ProcessRemediation.cs`,
    `ServiceRemediation.cs`, `RegistryRemediation.cs`, `ScheduledTaskRemediation.cs`,
    `StartupFolderRemediation.cs`, `PersistenceRemovalPlan.cs`.
  - Tests: `ProcessRemediationTests`, `ServiceRemediationTests`, `RegistryAutorunRemediationTests`,
    `ScheduledTaskRemediationTests`, `StartupFolderRemediationTests`, `PersistenceRemediationPlanTests`.

- **Process safety/refusal model:** `KillProcessTreeAction` over `IProcessRemediationProvider`, gated by
  `CriticalProcessPolicy`. Refuses PID ≤ 4, the current process, a curated critical image denylist (smss,
  csrss, wininit, winlogon, services, lsass, svchost, …), unknown identity, and recycled-PID identity drift
  (expected name/image no longer matches). Refuses the WHOLE tree if any node is critical (never a partial
  kill). The kill is explicitly IRREVERSIBLE — it produces an irreversible rollback token, never a
  recoverable one. Journaled before any kill; leaves killed before parents.

- **Service safety/refusal model:** `StopDisableServiceAction` over `IServiceRemediationProvider`, gated by
  `CriticalServicePolicy` (refuses a curated critical-service denylist — rpcss, dcomlaunch, lsass, eventlog,
  windefend, mpssvc, wuauserv, trustedinstaller, … — plus blank/missing canonical names). Reads and backs up
  the prior start type + running state BEFORE stop/disable; produces a `ServiceConfigBackup` rollback token;
  `Rollback` restores the start type.

- **Registry backup model:** `RemoveRegistryAutorunAction` over `IRegistryRemediationProvider`. Reads the
  EXACT current value (`RegistryValueBackup` = hive/key/name/type/data) before deletion; refuses with
  `BlockedChangedSincePlan` when the live data differs from the plan's expected data; produces a
  `RegistryValueBackup` rollback token; `Rollback` re-creates the value exactly.

- **Scheduled task export model:** `RemoveScheduledTaskAction` over `IScheduledTaskRemediationProvider`.
  Exports the task XML BEFORE deletion; a failed/empty export returns `BlockedExportFailed` and the task is
  NOT deleted (irreversible-loss protection); the export becomes a `ScheduledTaskExport` rollback token;
  `Rollback` re-imports it.

- **Startup quarantine model:** `RemoveStartupFolderItemAction` composes the **real 03B FileRemediationService**
  to quarantine the link/file first and only then remove it; if quarantine fails the item is left untouched
  (`BlockedQuarantineFailed`); the link's target path is recorded but NEVER deleted by this action; the
  rollback token is the quarantine-restore token.

- **Composite:** `PersistenceRemovalPlan.Build` emits an ordered 03A descriptor plan
  (KillProcessTree → DisablePersistence + QuarantineFile → RemoveRegistryAutorun + DeleteFile → Verify) and
  relies on the 03A plan validator to guarantee neutralize/contain precede destructive removal. It executes
  nothing.

- **Tests run:** 38 new fake-backed tests covering, per family: success with backup/export/quarantine +
  rollback token, journal-intent-before-outcome, critical/unknown/missing refusal, changed-since-plan
  (registry), export-failure-blocks-delete (task), quarantine-failure-leaves-untouched (startup),
  whole-tree-refusal and recycled-PID refusal (process), mutation-failure-keeps-rollback, and rollback
  restore. Combined 03A+03B+03C remediation suite: **107/107 pass** on Linux against the real
  `DataVanger.Engine`. All four cross-platform projects build **0 errors / 0 warnings**. The mandated
  full/x64/`~Service`/`~Scheduler`/`~AntiFalsePositive`/`~Quarantine` runs are **Windows-only** (standing
  exception) but unaffected by construction (no existing file modified).

- **Destructive API audit:** `grep` over `DataVanger.Engine/Remediation/System/` for `Process.Kill`,
  `ServiceController`, `Microsoft.Win32`, `Registry.*`, `RegistryKey`, `schtasks`, `Process.Start` →
  **the only match is `_provider.Kill(pid)`, a call to the injected `IProcessRemediationProvider` interface,
  not a real OS API.** There is **no real process/service/registry/task OS mutation anywhere in the
  codebase** — all mutation flows through fake-tested provider seams. Invariants: 0 empty catch, 0 `lock(qm)`,
  0 CRLF.

- **Policy/UI exposure: None.** No Detection→Action policy, no `Remediation` IPC command/handler, no UI. These
  actions are pure library code driven only by tests; phase 04 policy is still required before any user-facing
  or automatic execution.

- **Intentionally NOT implemented (phase boundary + scope decision):** real OS provider bindings
  (the only place real `Process.Kill` / `ServiceController` / `Microsoft.Win32.Registry` / `schtasks.exe` /
  startup-folder filesystem calls would live) are deliberately deferred to a Windows-validated follow-up. This
  keeps the Engine cross-platform and — more importantly for safety — means **no real destructive system call
  exists in the codebase before phase 04 policy**, exactly matching the phase's "policy-ready, fake-tested"
  Reality Rule. Also not implemented: locked-file/reboot (`03D`), browser-extension removal, any anti-FP or
  quarantine-semantics change.

- **Stop conditions encountered:** none. Every destructive action journals before mutating; critical
  PIDs/services cannot be targeted; registry removal requires an exact backup and refuses changed values;
  task deletion requires a successful XML export; startup removal requires quarantine; anti-FP/quarantine code
  is untouched; nothing is exposed to UI/auto-policy.

## Self-Stabilization Review

**Risks checked, and findings:**

1. **Cross-platform blind spots** — All 03C code is in `DataVanger.Engine` (net8.0, no WPF/XAML), so there is
   no XAML/WinForms ambiguity. **A real namespace-collision bug was FOUND AND FIXED:** naming the namespace
   `DataVanger.Engine.Remediation.System` shadowed the global `System` namespace inside the sibling
   `…Remediation.Files` files (which reference `System.Threading.Tasks.Task` fully-qualified), breaking the
   Engine build with CS0234/CS0535. Renamed the namespace to `…Remediation.SystemScope` (surgical — did not
   touch the stabilized 03B file). The fix was verified by a clean rebuild. No Windows-only API is used
   unguarded (no real OS provider exists). No Windows-only test was added; all 38 tests run cross-platform.

2. **Test/API mismatch** — Every test compiles and runs against the real Engine, so all referenced APIs exist
   with the signatures used. No `InternalsVisibleTo` is required (all types/members the tests touch are
   public; the startup test composes the real `FileRemediationService` exactly as 03B does). **A second
   build issue was found and fixed:** three CS8601/CS8604 nullable warnings from using `?.` on `required`
   (non-null) members in the match-key interpolations; removing the redundant `?.` cleared them and restored
   the zero-warning build.

3. **Resource/build integration** — No .resx/XAML/csproj/satellite added. Both projects use SDK default
   compile globbing (verified previously), so the 7 new Engine files and 6 new test files are automatically
   part of the real `DataVanger.sln` build.

4. **Safety-policy consistency** — Anti-FP not weakened (no classification logic here; persistence-disable is
   never auto-triggered — it is plan-descriptor-only). Quarantine semantics unchanged (startup removal reuses
   the unchanged 03B service; git confirms no quarantine file modified). No remediation IPC/UI exposure. Every
   destructive-looking action is gated (critical refusal), journaled (intent-before-mutate), rollback-aware
   (backup/export/quarantine token or explicit irreversible classification), and policy-ready (driven only by
   tests, not detections).

5. **Phase-boundary enforcement** — 03D (locked-file/reboot) not started; no Removal Center UI; the 03A/03B
   infrastructure was reused, not rewritten; the change is minimal and additive. The decision to defer real OS
   providers is a conservative narrowing, not a broadening.

6. **Required local checks** — Ran the available validation (harness build + 107-test remediation run + 4
   project builds, all green); ran the `~Remediation`-equivalent filter (every new class carries
   "Remediation"); ran the forbidden-API/forbidden-scope grep (only the injected-interface `Kill` call); re-read
   every changed file for namespace/API mistakes; confirmed no `bin/obj/TestResults/Publicar/.vs`/nested-zip is
   staged.

**What remains Windows-only / Codex-only:** (a) The full `DataVanger.Tests` (net8.0-windows, WPF-referencing)
cannot link on Linux — only a Windows run proves the full assembly + all 168 baseline tests + the 107
remediation tests link and pass together. (b) **Real OS provider bindings are not implemented** — the entire
safety surface (actions/policies/backup-before-mutate/journal/rollback) is implemented and fake-tested, but the
real `Process.Kill`/`ServiceController`/`Registry`/`schtasks`/startup-filesystem providers (with Windows-only
child-enumeration, registry typing, and XML export) are a Windows deliverable and were deliberately deferred to
avoid adding untestable, platform-specific surface and to keep the codebase free of any real destructive system
call before phase 04. These could not be proven here because they require Windows APIs and real (disposable)
system artifacts.

**Known prior mistake pattern prevented:** the "named a namespace after a BCL root and shadowed `System`" trap
was caught by an actual compile failure and fixed before any test run; the "`?.` on non-null members produces
phantom nullable warnings" pattern was caught and cleaned; and the "isolated-harness compiles ≠ real test
assembly compiles" trap was mitigated by relying only on public APIs identical across harness and real
assembly, with no InternalsVisibleTo dependency.

**Codex stabilization recommendation:** **Recommended, MEDIUM risk level.** The safety logic is heavily
fake-tested and purely additive, and no real destructive OS call exists yet (which lowers risk), but a Windows
stabilization pass should: run the full default + x64 suites and `~Service`/`~Scheduler`/`~AntiFalsePositive`/
`~Quarantine`/`~Remediation` filters; review the critical process/service denylists with a security reviewer;
and, when real OS providers are later implemented, re-audit each real `Process.Kill`/`ServiceController.Stop`/
registry-delete/`schtasks /delete` against its action's refusal+backup+journal+rollback gates. Risk is medium
(not high) because every gate lives in the tested action layer and the providers are inert interfaces today.
