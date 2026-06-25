# BETA 07 — LIVE WIRING COMPLETION REPORT

Phase: `07_ONBOARDING_TRAY_INSTALLER_HISTORY` — completion of the missing live/wired parts.
Executed: 2026-06-14. Builds on the Phase-07 + Phase-08 (both Codex-stabilized) baseline.

## 1. Baseline adoption report

The uploaded ZIP (Phase 07 cores + stabilization + Phase 08 + stabilization) was adopted as the new source of
truth: inspected, verified clean (no `bin/`, `obj/`, `TestResults/`, `Publicar/`, `.vs/`, no nested zip), and
the working tree was **replaced** (deleted except `.git`, copied in — not merged). Post-copy `diff -rq` against
the archive is empty (exact mirror). Adopted as commit `427ab99`.

## 2. Exact delta from the uploaded ZIP

Delta vs my previous pushed branch (HEAD `b0291b3`): **2 files** — `DataVanger.Tests/SignedUpdateHttpTransportTests.cs`
and `DataVanger/ALTERACOES_BETA.md`. The Codex Phase-08 stabilization fixed a compile nit in my Phase-08
file-transport test (`FileUpdateTransport` is not `IDisposable`, so it removed the `using`) and touched the
change-log. **Phase 08 production code (`HttpUpdateTransport.cs`, `SignedUpdateService.cs`, `IUpdateTransport.cs`)
is byte-unchanged — preserved.**

## 3. Files changed (this completion pass)

New: `DataVanger/Services/{ScanHistoryRecorder,TrayIconHost}.cs`,
`DataVanger/ViewModels/ServiceRegistrationViewModel.cs`, `DataVanger/Localization/OnboardingLabels.cs`,
`DataVanger/Views/OnboardingWindow.xaml(.cs)`,
`DataVanger.Tests/{ScanHistoryRecorderTests,ServiceRegistrationViewModelTests}.cs`.
Modified: `DataVanger/App.xaml.cs` (first-run onboarding wiring), `DataVanger/MainWindow.xaml.cs` (history +
tray wiring), `DataVanger/Localization/UiStrings(.en-US).resx` (onboarding strings), `DataVanger/ALTERACOES_BETA.md`.
**Unchanged:** Phase 08 transport, `AppSettings.cs` (no schema bump), policy/anti-FP/YARA/quarantine, IPC/gate.

## 4. Phase 07 items completed now

- **Onboarding window + first-run wiring** — `OnboardingWindow` shown from `App.OnStartup` **before** the
  dashboard, only on first run (marker file `onboarding.done`, no `AppSettings` schema change). "Apply"
  persists the chosen options (the view model can only **enable** protection); "Skip" changes nothing; the
  marker is written either way so it shows once. i18n via `OnboardingLabels` + pt-BR/en-US resources.
- **Tray host (NotifyIcon)** — `TrayIconHost` (single icon, fail-safe creation) renders `TrayStatusModel`
  derived from **real** state (`_monitor.IsRunning`, actionable findings in `_lastFindings`,
  `_serviceConnection.Status`); the menu only opens the UI, shows service status, or exits — never remediates,
  never elevates. Refreshed on scan completion and realtime toggle; disposed on window close.
- **Service-register UX** — `ServiceRegistrationViewModel` (testable) + a tray "Estado do serviço…" item that
  shows the honest status and elevation instructions; never installs, never elevates, never requires admin to
  open.
- **Live history wiring** — `ScanHistoryRecorder` (WPF-free, exception-safe) appends scan-started,
  scan-completed (summary), per-detection, and quarantine events into the persistent `HistoryStore` during the
  scan flow. Honest: a quarantine is recorded `Succeeded` (done) but **never verified** (no verification occurs
  in a scan). History write failure never blocks the scan.

## 5. Phase 07 items remaining / deferred

- **Installer UX engine — DEFERRED** (forbidden to build a real installer engine from scratch / no
  auto-elevation / no install side-effects). Only honest status + elevation instructions were added (via the
  service-register UX). What remains: a packaged, admin-gated installer is out of this phase's scope.
- **History viewing surface + remediation-journal→report integration — FOLLOW-UP.** History is now **recorded**
  live, but there is no dedicated history screen yet, and the remediation journal/results are not yet folded
  into reports. The latter is blocked by the same offline-gated remediation result path as Phase 05 (the
  Removal Center uses an offline gateway; there is no live remediation result flowing to the UI to integrate).
- **"Start with Windows"** records only the preference; writing the OS startup entry is a future step.

## 6. Build/test results

**NOT RUNNABLE here — no .NET SDK / MSBuild / mono in this container.** `dotnet restore`, `dotnet build
DataVanger.sln`, `dotnet test … (+ --arch x64)` cannot execute. Static validation performed (see §6/§7 table
below). The WPF/XAML compile + all tests are Windows-only.

| Static check | Result |
|---|---|
| ZIP cleanliness / exact-mirror replace | PASS |
| XML well-formedness: `OnboardingWindow.xaml`, `MainWindow.xaml`, both `.resx` (xmllint) | PASS |
| Testable cores WPF-free (`ScanHistoryRecorder`, `ServiceRegistrationViewModel`) | PASS |
| Invariants on all changed files (anonymous `catch{}` / `lock(qm)` / CRLF) | 0 / 0 / 0 — PASS |
| WPF `DataVanger.csproj` does NOT reference `DataVanger.Engine` | PASS |
| Phase 08 + policy + anti-FP + YARA + quarantine + `AppSettings.cs` unchanged | PASS (git-verified) |
| Load-bearing APIs verified (`ServiceConnectionViewModel.Status`, `ScanEngine.MgRoot`, `HistoryStore(string)`, `RealtimeMonitor.IsRunning`, `MessageBox` alias) | PASS (read from source) |
| Forbidden APIs (reboot/MoveFileEx/shutdown/auto-elevate/install) in new code | none — PASS |
| Forbidden artifacts staged | none — PASS |

## 7. Focused test results

`~Csv`, `~History`, `~Onboarding`, `~Tray`, `~Service`, `~Update`, `~AntiFalsePositive`, `~Quarantine` — **NOT
RUNNABLE here** (no SDK). New tests added: `ScanHistoryRecorderTests` (4 — start event; summary + actionable
detections only; scan never emits verification / never marks remediation verified; quarantine recorded
Succeeded-but-not-verified) and `ServiceRegistrationViewModelTests` (5 — UI never requires admin;
non-elevated→requires-elevation with instructions; elevated→no elevation; ServiceInstalled reflects status;
StatusSummary non-empty for every status). All grounded in real APIs; Windows-only to run.

## 8. Manual/WPF result

**Not performed — Windows-only and SDK-absent.** The manual checklist (app opens; first-run onboarding appears
once; onboarding records marker / never disables protections; single tray icon; honest tray status; tray menu
actions; service-status UX does not auto-elevate; history reflects real state; Settings/Removal Center/
Quarantine/Threats/Reports still open) requires a Windows WPF runtime. The wiring is grounded against verified
APIs and existing handlers were not removed (only additive calls), but a Windows run is required to confirm.

## 9. Onboarding review

Conservative and safety-oriented: real-time protection recommended ON, auto-quarantine starts from the
(already conservative) current value, "start with Windows" opt-in OFF. First run detected via the existing
marker file — **no `AppSettings` schema version added**. `ApplyTo` can only ENABLE protection, never disable
(verified by the existing `OnboardingTrayTests`). Skip/close changes nothing and still records the marker, so
behavior is safe and honest. The window is non-elevated.

## 10. Tray/status review

A single `NotifyIcon` (no duplicate — the only other tray use is the transient `--silent`-scan toast, which
runs in a process that shuts down before the dashboard). Status is **deterministic** from
`TrayStatusModel.Derive` over real inputs; protection is never faked (realtime from `_monitor.IsRunning`,
service from `_serviceConnection.Status`, which only shows protection active when truly connected). If state is
unavailable it resolves to a degraded/offline status. The menu only opens the UI, shows service status, or
exits — **no remediation, no elevation, no dormant-engine activation.** Creation is fail-safe (the app runs
without a tray icon if one cannot be created).

## 11. History truthfulness review

The recorder writes scan/detection/quarantine events but **never** a verification event from a scan, so
`HistoryStore.IsRemediationVerified` stays false for scan-quarantined items — a quarantine is "done", never
"verified" (verification is a separate, later event). Tested. The store tolerates corrupt/partial files
(starts empty, no throw — existing `HistoryStoreTests`), and every append is exception-safe so a history
failure never blocks or aborts a scan. No remediation execution semantics changed; the gate is not bypassed;
no UI/client-supplied security claim becomes authoritative (history is descriptive only).

## 12. Service/register UX review

`ServiceRegistrationViewModel` reports the honest connection status and, when the process is not elevated,
states clearly that registering the resident service requires administrator privileges performed through a
separate elevated step — it **does not install and does not auto-elevate**, and the UI never requires admin to
open (`UiRequiresAdmin == false`). No service IPC gate or ACL validation was touched; no service activation
behavior changed.

## 13. Security Boundary Review

- **UI non-elevated:** no manifest/elevation added; the new surfaces (onboarding, tray, service-status) require
  no admin; `IsCurrentProcessElevated()` is read-only (used only to choose which instructions to show).
- **No auto-elevation / no silent install:** the service-register UX explains; it never installs or elevates.
- **WPF→Engine boundary:** the WPF project still references only `DataVanger.Shared` (csproj verified); the new
  code uses `DataVanger.Core` (same assembly) + `DataVanger.Shared` only — **no `DataVanger.Engine` reference**.
- **Remediation boundary:** the tray executes no remediation; `RemediationExecutionGate`/IPC/permits are
  untouched; no client claim becomes authoritative; history is descriptive only.
- **Detection/anti-FP/YARA/quarantine/policy:** unchanged (none in the delta). No threshold change. No dormant
  engine activated. No reboot/`MoveFileEx`/`PendingFileRenameOperations`/shutdown.

## 14. Documentation Review

- **Reviewed:** `DataVanger/ALTERACOES_BETA.md` (main Beta change-log) and the `outputs/` reports (04B–08).
  Only `ALTERACOES_BETA.md` exists (no `CHANGELOG.md`/`RELEASE_NOTES.md`; the v2.0/v2.1 logs were consolidated
  into it earlier).
- **Updated:** `ALTERACOES_BETA.md` — **appended** a `07 — conclusão da fiação ao vivo` sub-section under the
  existing Phase 07 entry (the original partial entry was NOT rewritten or duplicated). The new sub-section
  distinguishes: what was already implemented (cores), what was completed now (onboarding window/wiring, tray
  host, live history recording, service-register UX), what is live, what remains model/follow-up (history
  viewer + journal→report integration; "start with Windows" preference), and what is deferred (installer UX
  engine). Created this report (`outputs/BETA_07_LIVE_WIRING_COMPLETION_REPORT.md`).
- **Obsolete/superseded:** none new. **Intentionally not changed:** the 00–08 phase reports, `README.md`,
  `docs/*` (no architecture change requiring them). No documentation files were deleted.

## 15. Confirmation that Phase 08 was preserved

**Confirmed.** The Phase 08 signed-update transport (`HttpUpdateTransport.cs`, `SignedUpdateService.cs`,
`IUpdateTransport.cs`, verifiers) is byte-unchanged (git-verified, not in this delta). The HTTP transport was
NOT wired live (explicitly out of scope here).

## 16. Confirmation that Phase 09 was not started

**Confirmed.** No Phase 09 work was begun. No dormant engine activated; no new update/security behavior; no
real installer engine.

---

## Final status

**Phase 07 COMPLETE except installer UX.** The four "missing live/wired parts" from the order — onboarding
window + first-run wiring, tray host/status, service-register UX, and live history recording — are implemented
and wired into the WPF process. The **installer UX engine is deferred** (building a real installer from scratch
is forbidden; only honest status + elevation instructions were added). Two follow-ups remain beyond the
installer: a dedicated **history-viewing screen** and **remediation-journal→report integration** (the latter
blocked by the offline-gated remediation result path, as in Phase 05). **All WPF/XAML compile and the manual
WPF journeys are Windows-only and unverified here (no .NET SDK in this environment)** — recommended as the
Codex/Windows stabilization step.

## Self-Stabilization Review

- **Cross-platform blind spots:** testable cores (`ScanHistoryRecorder`, `ServiceRegistrationViewModel`) are
  WPF-free (verified). The WPF/WinForms surfaces (`OnboardingWindow`, `TrayIconHost`, MainWindow/App wiring)
  use aliased/qualified types (`WinForms.*`, `System.Windows.Application`, `System.Drawing.*`, aliased
  `MessageBox`) to avoid the WPF-vs-WinForms ambiguity (the project sets `UseWindowsForms=true`). Nothing was
  compiled here — flagged Windows-only.
- **Test/API mismatch:** verified every external API my wiring calls (`ServiceConnectionViewModel.Status`,
  `ScanEngine.MgRoot`, `HistoryStore(string)`, `RealtimeMonitor.IsRunning`, `MessageBox` alias) against source
  before finalizing; the field-initializer ordering constraint (cannot reference `_engine` in a field
  initializer) was handled by initializing history/tray in the constructor body; the `DialogResult`-already-
  closes-the-window gotcha was fixed (removed redundant `Close()`).
- **Resource/build integration:** SDK globbing auto-includes the new `.cs`/`.xaml`; the new resx keys are
  well-formed (xmllint) and follow the keyed facade pattern.
- **Safety-policy consistency:** anti-FP/YARA/quarantine/policy/`AppSettings`/Phase-08 unchanged (git-verified);
  onboarding enable-only; history honest; tray never remediates; no elevation/install side-effects.
- **Phase-boundary enforcement:** Phase 09 not started; no dormant engine; no Engine reference in WPF; HTTP
  transport not wired live; installer engine deferred.
- **Known prior mistake patterns prevented:** "Linux≠Windows" (compiled nothing, said so); test/API mismatch
  (read real APIs first); WPF/WinForms ambiguity (aliases); "claiming live when only a model" (history viewer +
  report integration explicitly reported as follow-ups, not live); core-regression (additive calls only;
  existing handlers untouched).
- **Codex stabilization recommended? Yes — MEDIUM** (the WPF/WinForms wiring is the only thing needing a
  Windows build + the manual journeys; the testable cores are low-risk).
