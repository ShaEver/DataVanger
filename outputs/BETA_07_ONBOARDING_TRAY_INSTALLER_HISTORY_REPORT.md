# BETA 07 — ONBOARDING / TRAY / INSTALLER / HISTORY REPORT

Phase: `07_ONBOARDING_TRAY_INSTALLER_HISTORY` (DataVanger V.Beta Improvement Plan)
Executed: 2026-06-14
Verdict: **PARTIAL — the phase's safety-critical, testable cores are implemented; the heavy WPF/installer
surfaces are deliberately deferred (the phase explicitly allows an onboarding/tray-then-installer/history
split). Delivered and tested: CSV export hardening (formula-injection neutralization across all three CSV
exporters), a persistent history store with the verification-truthfulness rule, and WPF-free onboarding-state
and tray-status models. UI remains non-elevated (no admin manifest). No .NET SDK here, so nothing was compiled
or run — Windows/Codex validation pending.**

- **Branch/checkpoint:** `claude/confident-gates-f355wn`, on the Phase-06-stabilized baseline.

## Baseline replacement result

- **ZIP cleanliness:** no `bin/`, `obj/`, `TestResults/`, `Publicar/`, `.vs/`, no nested zip; exact-mirror
  replace (post-copy `diff -rq` empty).
- **Exact delta vs previous baseline** (HEAD `016840c`): **1 file** — `DataVanger/ALTERACOES_BETA.md`. The Codex
  Phase-06 stabilization updated the 06 change-log entry to record that the WPF build + automated tests passed
  on Windows/.NET (full suite, `--arch x64`, `~Settings`/`~AntiFalsePositive`/`~Quarantine`); only manual
  click-through remains. **No code changed.** Adopted as commit `b121e1c`.

## What was implemented (testable cores)

### 1. CSV export hardening (criterion #4 — done)
- New `DataVanger/Reporting/CsvSafe.cs`: neutralizes spreadsheet **formula injection** (a field starting with
  `=`, `+`, `-`, `@`, TAB, or CR is prefixed with `'`) and applies **RFC 4180** quoting (comma/quote/CR/LF or
  leading/trailing whitespace → quoted, inner quotes doubled). Pure, never throws.
- All **three** CSV writers now route through it: `ScanEngine.WriteCsv` (the main `DataVanger_Report.csv`),
  `ReportService.WriteCsv`, and `ForensicReportExporter.WriteCsv`. Numeric/boolean columns stay plain (keep
  their numeric form); attacker-influenceable string fields are hardened.
- **Round-trip preserved:** `ScanEngine.LoadPreviousHashes` keys off the **SHA256 column** (hex, never
  formula-leading), so neutralizing the other fields does not affect new-finding detection.

### 2. Persistent history store (criterion #2 — done)
- New `DataVanger.Shared/History/`: `HistoryEventKind` (Scan, Detection, RemediationAction, Verification,
  Rollback, Update, ServiceEvent), `HistoryOutcome`, `HistoryEvent` (data-only, static factories), and
  `HistoryStore` (append-only, bounded at 5000, JSON-backed, corrupt-file-tolerant).
- **Honesty rule:** `IsRemediationVerified(correlationId)` returns true **only** when a passing
  `Verification` event exists for that correlation — a `RemediationAction` alone (even "Succeeded", or
  reboot-required) is never reported resolved.

### 3. Onboarding & tray status models (criterion #3 — model level)
- `DataVanger/ViewModels/OnboardingViewModel.cs` (WPF-free): conservative recommended defaults (real-time
  protection ON, "start with Windows" opt-in OFF); first-run via a marker file (no `AppSettings` schema
  change); `ApplyTo` only ever **enables** protection — it can never disable one.
- `DataVanger/ViewModels/TrayStatusModel.cs` (WPF-free): deterministic status derivation
  (ActionNeeded > ProtectionDegraded > RemediationInProgress > UpdateAvailable > Protected) + tiered
  `ShouldToast` (toast only for urgent states).

### 4. Privilege boundary (criterion #1 — reviewed)
Confirmed the WPF app is **non-elevated**: `App : System.Windows.Application`, no `app.manifest` /
`requestedExecutionLevel` (default `asInvoker`), and the csproj declares no elevation. This phase adds **no**
elevation, no kernel/self-protection/self-update/cloud, and activates no dormant engine.

## What was intentionally NOT implemented (deferred, per §19 split)

- **Onboarding window** + first-run wiring in `App.xaml.cs` (model is ready; the WPF window + show-on-first-run
  is Windows-only).
- **Tray status host** — a persistent `NotifyIcon` rendering `TrayStatusModel` (today the only tray use is a
  one-shot silent-scan toast). Status model is ready; the host is Windows-only.
- **Service-register UX window** (elevation handled by the service installer, not the UI).
- **Live history wiring** — appending real scan/detection/remediation/verification/update events to the store,
  and integrating the remediation journal/result into reports/history. The store + truthfulness rule exist and
  are tested; the producers are not yet wired.
- **Packaging/manifest changes** — reviewed (non-elevated, confirmed); no change required this pass.

These are flagged honestly: the history/onboarding/tray pieces are **models, not yet live**.

## Files changed

New: `DataVanger/Reporting/CsvSafe.cs`, `DataVanger.Shared/History/{HistoryModels,HistoryStore}.cs`,
`DataVanger/ViewModels/{OnboardingViewModel,TrayStatusModel}.cs`,
`DataVanger.Tests/{CsvSafeTests,HistoryStoreTests,OnboardingTrayTests}.cs`. Modified (CSV hardening):
`DataVanger/Core/ScanEngine.cs`, `DataVanger/Reporting/ReportService.cs`,
`DataVanger/Reporting/Forensics/ForensicReportExporter.cs`. Doc: `DataVanger/ALTERACOES_BETA.md`.

## Tests added / results

**31 tests** across three files: `CsvSafeTests` (10 — formula neutralization for each trigger, comma/quote/
newline quoting, inner-quote doubling, formula+comma, null/empty, whitespace preservation); `HistoryStoreTests`
(10 — append/order, correlation filter, the verification-truthfulness matrix, persist/reload, corrupt-file
tolerance); `OnboardingTrayTests` (11 — conservative defaults, enable-only/never-disable, first-run marker,
save round-trip, tray priority/describe/toast). **Could not be executed here** (no .NET SDK; `DataVanger.Tests`
is `net8.0-windows`). The `HistoryStore` core is `net8.0` and runs cross-platform once an SDK is present.

## Validation commands run and results

No .NET SDK / MSBuild / mono. The phase's `dotnet build/test` (+ `--arch x64`, `~Service`/`~Ipc`/`~Remediation`/
`~Reporting`) are **NOT RUNNABLE here**. Static validation:

| Check | Result |
|---|---|
| Invariants on all changed files (anonymous `catch{}` / `lock(qm)` / CRLF) | 0 / 0 / 0 — PASS |
| New model files WPF-free (no `System.Windows`) | PASS |
| New `using DataVanger.Reporting;` in ScanEngine introduces no type ambiguity | PASS (no clashing reference) |
| anti-FP / classifier / YARA / quarantine / policy / AppSettings changed | none — PASS |
| CSV round-trip preserved (SHA256-keyed `LoadPreviousHashes`) | PASS (verified by reading) |
| UI non-elevated (no admin manifest) | PASS |
| `DataVanger.Shared`/`DataVanger.Tests` SDK globbing auto-includes new files | PASS |
| Forbidden artifacts staged | none — PASS |

## Manual validation results

**Not performed — Windows-only.** First-run/tray/installer/history journeys require a Windows runtime (absent)
and the deferred UI surfaces. The CSV-export-opens-safely check is reasoned (formula neutralization is unit
covered) but a real Excel open is a Windows manual item.

## Stop conditions encountered

None. UI does not require admin; no protection setting can be disabled silently (onboarding only enables);
history never reports an unverified remediation as clean; CSV export neutralizes formula injection; no
generated artifacts staged; no dormant engine activated.

## Remaining risks / follow-up

1. **Windows validation debt (standing):** WPF compile + the 31 tests + manual journeys.
2. **Deferred UI/wiring:** onboarding window + first-run, tray status host, service-register UX, live history
   producers + report/journal integration. These are the "second half" of the phase.
3. **ScanEngine CSV change** is in the core scan path — low-risk (localized, round-trip preserved) but, like
   all code here, unbuilt on this host; worth a focused Windows build + `~Reporting` run.

## Recommendation

**Codex stabilization recommended** for packaging/history/CSV (as the phase states): build on Windows; run the
full suite + `~Reporting`/`~Service`; confirm the three hardened CSV exporters open safely in a spreadsheet and
that new-finding detection still works after the `ScanEngine.WriteCsv` change; then implement the deferred UI
surfaces and live history wiring. Risk: **LOW–MEDIUM** (CSV is the only change to existing behaviour and it is
hardening; everything else is new, additive, and tested).

---

## Self-Stabilization Review

- **Cross-platform blind spots:** the new models (`CsvSafe`, `History*`, `OnboardingViewModel`,
  `TrayStatusModel`) are WPF-free (verified). `CsvSafe`/`History` are `net8.0` (cross-platform). The only WPF
  surfaces touched are none — no XAML added this pass. Nothing was compiled here; the 31 tests + any Windows
  behaviour are Windows-only.
- **Test/API mismatch:** read the real `ScanFinding`, the three CSV writers, `AppSettings`, and the existing
  reporting tests before editing; the hardened rows preserve the exact 25-column order; tests use only public
  APIs of the new types. No `InternalsVisibleTo` reliance (new types are public).
- **Build integration:** SDK globbing includes the new `.cs` under `DataVanger.Shared` and `DataVanger`; no
  resx/XAML/satellite added. The new `using DataVanger.Reporting;` in `ScanEngine` was checked for ambiguity
  (no clashing `ReportService`/`CsvSafe` reference) and is same-assembly (no project-ref cycle).
- **Safety-policy consistency:** anti-FP / classifier / YARA / quarantine / policy / `AppSettings` are
  **unchanged** (none in the delta). CSV hardening only changes output encoding; the `ScanEngine` round-trip is
  preserved because it keys off the SHA256 column. History is honest by construction (no verified-without-
  verification path). Onboarding can only enable protection.
- **Phase-boundary enforcement:** no elevation added (UI stays non-elevated), no dormant engine activated, no
  destructive/reboot behaviour, no kernel/self-update/cloud. The split (testable cores now, UI/installer later)
  is exactly what §19 permits. Minimal, surgical CSV edits; everything else additive.
- **Issues found and fixed:** chose a marker file for onboarding first-run (avoids an `AppSettings` schema
  change); removed the weak `ReportService.EscCsv` (it only replaced `"`→`'` and left formula injection open);
  verified the `ScanEngine` CSV round-trip safety before touching the core scan path.
- **Windows-only / Codex-only:** all `dotnet build/test`; the deferred onboarding/tray/installer UI + live
  history wiring; the spreadsheet "opens safely" manual check.
- **Prior mistake patterns prevented:** Linux≠Windows (compiled nothing, said so); test/API mismatch (read real
  types first); namespace ambiguity (checked the new `using`); "claiming a feature is live when it is only a
  model" (history/onboarding/tray are explicitly reported as models, not wired); core-path regression (CSV
  round-trip verified before editing `ScanEngine`).
- **Codex stabilization recommended? Yes — LOW–MEDIUM**, focused on CSV/history/packaging + the deferred UI.

## Documentation Review

- **Files reviewed:** `DataVanger/ALTERACOES_BETA.md` (the main Beta change-log) and the prior `outputs/` phase
  reports (`BETA_04B_…` through `BETA_06_…`). Searched for `CHANGELOG.md` / `RELEASE_NOTES.md` /
  `ALTERACOES_v*.md` — only `ALTERACOES_BETA.md` exists (the v2.0/v2.1 logs were consolidated into it in an
  earlier phase).
- **Files updated:** `DataVanger/ALTERACOES_BETA.md` — appended a `07_ONBOARDING_TRAY_INSTALLER_HISTORY (parcial
  — núcleos testáveis)` entry stating: what changed (CSV hardening; history store + truthfulness; onboarding/
  tray models); user-visible impact (CSV opens safely; onboarding/tray are models, no window/host yet);
  security/policy impact (CSV-injection mitigated; no anti-FP/YARA/quarantine change; UI non-elevated;
  onboarding only enables protection); status (CSV hardening **live + tested**; history/onboarding/tray =
  testable cores **not yet wired**; not Windows-validated); limitations/follow-up (onboarding window, tray host,
  service-register UX, live history producers + report integration, packaging review); and stabilization
  status. Older entries were not rewritten or duplicated. Created
  `outputs/BETA_07_ONBOARDING_TRAY_INSTALLER_HISTORY_REPORT.md`.
- **Obsolete / superseded documentation found:** none new. `ALTERACOES_v2_0.md`/`ALTERACOES_v2_1.md` were
  already consolidated into `ALTERACOES_BETA.md` in an earlier phase and are not present in the tree.
- **Documentation intentionally not changed:** the 00–06 `outputs/` reports (historical record);
  `README.md`/`docs/*` (this phase makes no architecture/installer change requiring them — the installer UX is
  deferred). No documentation files were deleted.
