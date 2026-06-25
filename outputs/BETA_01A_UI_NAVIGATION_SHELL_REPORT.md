# BETA 01A — UI NAVIGATION SHELL REPORT

Phase: `01A_UI_NAVIGATION_SHELL` (DataVanger V.Beta Improvement Plan)
Executed: 2026-06-12
Verdict: **IMPLEMENTED (wrap-not-rewrite). Shell ViewModel verified by passing tests; WPF compile + manual
checklist pending on Windows (environment-only, same classification as Phase 00).**

---

## Oracle Archive Review

**Decision: the tracked archive `DataVanger V.Alpha.zip` was removed from repository tracking
(`git rm --cached`) in this phase's commit. It is redundant after baseline capture.**

Rationale, verified before removal:
1. **The imported source tree is the baseline.** A fresh extraction of the archive was diffed against the
   working tree: byte-identical except the two documented Phase 00 additions (`.gitignore` + `Publicar/`
   line; `outputs/BETA_00_BASELINE_GUARDRAILS_REPORT.md`). No drift.
2. **The oracle remains permanently recoverable.** Untracking at HEAD does not rewrite history: the archive
   is preserved forever in commits `20430e2` and `28d2630`
   (`git show 20430e2:"DataVanger V.Alpha.zip" > restored.zip`), and its SHA-256
   (`b38d548c0b60cfc1c9d518a92b2f9ec55bc642d7a5949d1c15ebb6691cf6d9fa`) is recorded in the Phase 00 report
   for independent verification.
3. **Nothing operational references it.** Grep across `*.cs`, `*.csproj`, `*.sln`, `*.bat`, `*.ps1`: zero
   references to the archive path.
4. **The project's own intent is that archives not be tracked** — `.gitignore` already contains `*.zip`;
   the file was only tracked because it predated the ignore rule.
5. **Outcome matches the requested expectations:** the working source tree remains the baseline; no duplicate
   Alpha source copy is tracked at HEAD; checkouts shrink by ~970 KB; future branch/merge operations stay clean.
   (Note: history size is unchanged — removing it from history would require a rewrite, which is out of scope
   and undesirable for an evidence trail.)

Constraints honored: no source behavior, architecture, build outputs, tests, configuration, or imported
Alpha source files were modified by this review — it is a tracking-only change.

---

## 1. What was implemented

A Beta navigation shell **inside `MainWindow`**, strictly wrap-not-rewrite:

- **Left navigation rail** (new column 0, 172 px, same dark palette) with exactly the nine §8.3 sections:
  Dashboard (Painel), Scan (Varredura), Protection (Proteção), Threats (Ameaças), Quarantine (Quarentena),
  Reports (Relatórios), Updates (Atualizações), Settings (Configurações), Advanced Diagnostics
  (Diagnóstico Avançado). **No Removal Center item exists** (per §9, deferred until phases 03/04).
- **Content region** (former row 1) now hosts four views:
  - `ViewHome` — the **entire existing Alpha layout, unchanged** (top bar, sidebar cards, threat/cleaner
    grids, log). Default view.
  - `ViewReports`, `ViewUpdates`, `ViewDiagnostics` — thin panels whose buttons invoke the **same existing
    handlers** (`OnOpenFolder`, `OnOpenReport`, `OnViewPersist`, `OnUpdateSignatures`, `OnModuleStatus`,
    `OnDiagnostics`). Zero new behavior; the Reports panel visibly defers the future timeline
    ("chega em uma fase futura do Beta") instead of hiding anything.
- **Navigation semantics:**
  - *Hosted* sections swap the content region. Dashboard/Scan/Protection/Threats all show Home; Scan,
    Protection and Threats additionally move focus to the existing control (`BtnScan`, `BtnToggleRealtime`,
    `DgThreats`) — focus only, never an action.
  - *Launcher* sections (Quarantine, Settings) call the existing modal-opening handlers
    (`OnRestore`, `OnSettings`) and do **not** change the selection — exactly the legacy code paths.
- **`ShellNavigationViewModel`** (`DataVanger/Shell/`) — pure, WPF-free navigation state (items, selection,
  `LauncherRequested` event), per §5 "minimal ViewModels for the new shell and navigation state".
- **Shell strings centralized** in `Shell/ShellLabels.cs` (pt-BR), consumed via `{x:Static}` — single sweep
  point for `01B_I18N_SCAFFOLD` (§9).
- All legacy buttons remain in place and wired; every Alpha flow is reachable both the old way and via the rail.
- Cosmetic only: default window `Width` 1180→1320 and `MinWidth` 900→1040 to accommodate the rail without
  cramping the existing layout. No layout inside Home changed.

## 2. Files changed

| File | Change |
|------|--------|
| `DataVanger/Shell/ShellSection.cs` | new — section + kind enums |
| `DataVanger/Shell/ShellLabels.cs` | new — centralized pt-BR shell strings |
| `DataVanger/Shell/ShellNavigationItem.cs` | new — INPC nav item |
| `DataVanger/Shell/ShellNavigationViewModel.cs` | new — nav state VM (WPF-free) |
| `DataVanger/MainWindow.xaml` | rail column + `NavButton` style + view-host wrap of row 1 + 3 thin panels; existing content untouched inside `ViewHome` |
| `DataVanger/MainWindow.xaml.cs` | additive: shell fields, `InitializeShellNavigation`, `NavigateToSection`, `OnShellLauncherRequested`, `ApplyShellSelection`; one call added in ctor |
| `DataVanger.Tests/ShellNavigationTests.cs` | new — 6 tests (`~ShellNavigation` filter) |
| `DataVanger V.Alpha.zip` | untracked (Oracle Archive Review above) |
| `outputs/BETA_01A_UI_NAVIGATION_SHELL_REPORT.md` | this report |

## 3. Which existing windows/views were wrapped

- `MainWindow` content → wrapped as `ViewHome` (unchanged XAML inside).
- `QuarantineWindow`, `SettingsWindow` → reachable as shell **launchers** through their existing handlers;
  the windows themselves were **not modified** (remained read-only per §7).
- `ModuleStatusWindow`, `TextViewerWindow` (diagnostics/persistence), report/log/update actions → reachable
  through thin panels invoking the existing handlers; windows not modified.
- `ScheduledScanWindow`, `ReviewFixWindow` → unchanged, still reachable via their original buttons inside Home.

## 4. What was intentionally NOT implemented

Removal Center (any form); remediation calls; MVVM conversion of existing code-behind; i18n resource
migration (phase 01B); changes to scan/quarantine/settings/report/update/service/YARA/anti-FP behavior;
elevation; dormant-engine activation; hiding of any Alpha feature.

## 5. Tests added or changed

Added `ShellNavigationTests` (6 tests): default selection; exact nine-section list/order with **no Removal
Center**; hosted selection updates flags; launchers raise event and never change selection; launcher set is
exactly {Quarantine, Settings}; `PropertyChanged` only on real change. No existing test touched; no engine
test snapshot changed.

## 6. Validation commands run and results

| Check | Result |
|-------|--------|
| `dotnet build` Shared / Engine / Infrastructure / Service (before AND after edits) | **PASS — 0 errors** (these projects are untouched by this phase) |
| New shell VM + all 6 tests compiled and **executed on Linux** in an isolated xUnit harness (identical sources) | **PASS — 6/6 passed** |
| `MainWindow.xaml` XML well-formedness (`xmllint`) | **PASS** |
| Invariants on changed files: empty catch / new locks / CRLF | **0 / 0 / 0 — PASS** |
| `dotnet build DataVanger` / `DataVanger.Tests` / full suite / x64 | **NOT RUNNABLE here** — WindowsDesktop SDK absent on Linux (same environment-only classification as Phase 00) |

## 7. Manual validation (§11) — PENDING ON WINDOWS

The mandatory manual WPF checklist (launch non-elevated; shell appears; scan/quarantine/settings/reports/
updates/module-status reachable; resize/keyboard behavior; no new destructive action) **could not be run in
this Linux container**. It must be executed on Windows before this phase is declared green, together with:

```powershell
dotnet restore
dotnet build DataVanger.sln
dotnet test DataVanger.Tests/DataVanger.Tests.csproj
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --arch x64
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~ShellNavigation"
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~AntiFalsePositive"
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~Quarantine"
```

## 8. Confirmations

- **UI remains non-elevated** — no manifest added, no elevation request anywhere.
- **No engine/service/quarantine/update/remediation behavior changed** — the only edited product files are
  `MainWindow.xaml(.cs)`; all engine projects byte-identical (still build 0W/0E); every new button routes to
  a pre-existing handler.
- **No destructive action introduced**; Removal Center absent by design.
- **No stop condition encountered** (the Windows-validation gap is the documented Phase-00 environment
  exception, not a failed build).

## 9. Remaining risks / follow-ups

1. **WPF compile + manual checklist must run on Windows** (§7 above) — XAML cannot be compiled in this
   container; this is the phase's main open risk.
2. Focus-on-section behavior (`BringIntoView`) should be eyeballed on Windows for scroll comfort.
3. The enlarged default window width should be sanity-checked on small screens (min 1040 px).

## 10. Recommendation

**Ready for Codex stabilization (light), as the phase file itself recommends** — ideal scope: Windows
build/test execution, the §11 manual checklist, and a string/resource sweep readiness check for 01B.
Do not expand scope.
