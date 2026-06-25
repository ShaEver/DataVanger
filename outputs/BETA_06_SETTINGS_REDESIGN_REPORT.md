# BETA 06 — SETTINGS REDESIGN REPORT

Phase: `06_SETTINGS_REDESIGN` (DataVanger V.Beta Improvement Plan)
Executed: 2026-06-14
Verdict: **IMPLEMENTED as a behaviour-preserving, additive metadata layer over the unchanged
`AppSettings`: a WPF-free, testable settings catalog + grouped `SettingsRedesignViewModel`
(Normal/Advanced/Developer reveal + confirm-on-disable), a metadata-driven settings window wired into the
shell, and 18 tests. `AppSettings` (schema, migration, defaults, thresholds) is untouched, so the existing
schema/anti-FP oracles stay green by construction. No .NET SDK here, so nothing was compiled or run —
WPF/XAML compile and manual flows are Windows-only validation items.**

- **Branch/checkpoint:** `claude/confident-gates-f355wn`, on the Phase-05-stabilized baseline.

## Baseline replacement result

- **ZIP cleanliness:** no `bin/`, `obj/`, `TestResults/`, `Publicar/`, `.vs/`, no nested zip; exact-mirror
  replace (post-copy `diff -rq` empty).
- **Exact delta vs previous baseline** (HEAD `d49e438`): **1 added + 2 deleted + 2 modified, 128 insertions /
  53 deletions.** The archive is the **Codex stabilization of Phase 05** (hardened `RemovalCenterViewModel`:
  `CanProceed`/`CanConfirm` now require `ServiceAvailable`; honest "service unavailable" state; +1 test) **and
  a change-log consolidation** (removed `ALTERACOES_v2_0.md` + `ALTERACOES_v2_1.md`, added
  `ALTERACOES_BETA.md`). Adopted as commit `378d7e3`.

## Settings groups and metadata model

A new `DataVanger.Settings` namespace (WPF-free):
- `SettingMetadata` (record): `Key, DisplayName, Description, Group, Kind, Visibility, Risk, ConfirmOnDisable,
  Dimension`.
- Enums: `SettingGroup` (General, Scanning, RealTimeProtection, ThreatRemoval, Quarantine, Updates, Privacy,
  AdvancedDiagnostics, DeveloperExperimental), `SettingVisibility` (Normal/Advanced/Developer),
  `SettingRisk` (Safe/Caution/Protection), `SettingKind` (Toggle/Number/Text/List).
- `ToggleSetting`: metadata + typed get/set accessors onto the real `AppSettings` field (value-preserving),
  plus the single `RequiresDisableConfirmation(current,new)` rule.
- `SettingsCatalog`: **19 toggles** mapped to real `AppSettings` booleans + **9 metadata-only** entries for
  numeric/text foot-guns (thresholds, archive limits, YARA size, update URL, publisher list, validation mode),
  grouped and reveal-gated. Every toggle key/accessor is reflection-verified against `AppSettings`.

## Migration behaviour

**No schema migration was needed or added.** The metadata layer is descriptive and persists no new keys, so
`AppSettings.CurrentSchemaVersion` stays at 1 and `AppSettings.Migrate` (already additive/lossless) is
untouched. Saving from the new window round-trips through the unchanged `AppSettings.Save`/`Load`; a test
proves a changed value + schema version + unrelated defaults all survive a save/reload.

## Confirm-on-disable coverage

Disabling a **protection** setting (true→false) requires confirmation; **re-enabling never does**; cosmetic/
performance toggles never do. Covered toggles (ConfirmOnDisable, all `Risk=Protection`): real-time tray
protection, auto-quarantine of known malware, YARA, the five scan-location toggles, deep-archive scan, Office/
browser-extension analysis, ADS, advanced persistence, services/drivers, scheduled-task analysis. Cosmetic/
opt-in (no confirm): SuppressAccessDeniedLog, UseSafeCache, IncludeRemovableDrives, EnableHttpSignedUpdates.
The window's confirmation dialog defaults to the **safe answer (No)**.

## Advanced / Developer gating

`SettingsRedesignViewModel.RevealLevel` filters via `(int)visibility <= (int)revealLevel`: Normal shows only
Normal settings; Advanced adds Advanced; Developer reveals all. Raw danger thresholds
(`MinScoreToReport/Quarantine`) and `PublisherValidationMode` are **Developer-only** — never shown to Normal
users (foot-guns hidden).

## Files changed

New: `DataVanger/Settings/{SettingMetadata,ToggleSetting,SettingsCatalog}.cs`,
`DataVanger/ViewModels/SettingsRedesignViewModel.cs`, `DataVanger/Views/SettingsRedesignWindow.xaml(.cs)`,
`DataVanger.Tests/SettingsRedesignTests.cs`. Modified: `DataVanger/MainWindow.xaml.cs` (one line — the shell
Settings launcher now opens the redesigned window), `DataVanger/ALTERACOES_BETA.md` (Phase 06 entry).
**`DataVanger/Core/AppSettings.cs` is unchanged.**

## What was implemented / intentionally not

- Implemented: grouped plain-language catalog, reveal tiers, confirm-on-disable, metadata-driven window wired
  into the shell, value-preserving accessors, 18 tests.
- Not implemented (intentionally): no `AppSettings` property/threshold/default change; **no schema bump** (not
  needed); numeric/text foot-gun **editors** stay in the legacy flat `SettingsWindow` (kept as a fallback);
  full i18n-resource migration of per-setting strings deferred (strings are pt-BR inline, the product default).

## Tests added / results

`SettingsRedesignTests.cs` — **18 tests**: every toggle maps to a real bool `AppSettings` property
(reflection); every accessor round-trips through the named property; metadata completeness + unique keys +
group coverage; every `ConfirmOnDisable` is a Protection setting; Normal/Advanced/Developer visibility;
raw-threshold is Developer-only; confirm-on-disable (disable protection → confirm; enable → none; cosmetic →
none); `SetValue` mutates the backing setting; save→reload preserves the change + schema version + defaults;
the catalog changes no conservative defaults. **Could not be executed here** (no .NET SDK; `DataVanger.Tests`
is `net8.0-windows`).

## Validation commands run and results

No .NET SDK / MSBuild / mono; projects target `net8.0`/`net8.0-windows`. The phase's
`dotnet restore/build/test` (+ `--arch x64`, `~Settings`, `~AntiFalsePositive`) are **NOT RUNNABLE here**.
Static validation:

| Check | Result |
|---|---|
| ZIP cleanliness / exact-mirror replace | PASS |
| XML well-formedness: `SettingsRedesignWindow.xaml` (xmllint) | PASS |
| Metadata/catalog/VM are WPF-free (no `System.Windows`) | PASS |
| Invariants on new `.cs` (empty `catch{}` / CRLF) | 0 / 0 — PASS |
| `AppSettings.cs` / policy / classifier / YARA / quarantine unchanged | PASS (none in delta) |
| Name collision with Shared `SettingsViewModel` record | none (distinct `SettingsRedesignViewModel`, diff namespace) |
| New files auto-included by SDK globbing (`UseWPF=true`, no explicit includes) | PASS |
| Forbidden artifacts staged | none — PASS |

## Manual validation results

**Not performed — Windows-only.** The §11 WPF checklist (open settings; Normal grouped view; Advanced reveal;
Developer hidden by default; disabling protection warns; re-enabling does not; saved settings load; pt-BR
labels; no remediation from settings) requires a Windows WPF runtime (absent here).

## Stop conditions encountered

None. Settings data is preserved (AppSettings untouched, additive); no protection setting can be disabled
silently (confirm-on-disable); anti-FP thresholds/YARA/quarantine unchanged; Developer settings hidden from
Normal; existing schema/migration tests unaffected by construction.

## Remaining risks / follow-up

1. **Windows validation debt (standing):** WPF/XAML compile, the 18 tests, and the manual settings flows are
   Windows-only.
2. **Numeric/text editors:** the redesigned window edits toggles; raw numeric/text settings still use the
   legacy advanced window. Adding metadata-driven number/text editors is a follow-up.
3. **i18n:** per-setting strings are pt-BR inline; resource migration is a later polish step.

## Recommendation

**Optional Codex stabilization (as the phase states).** A light pass should: build on Windows; run `~Settings`
+ `~AntiFalsePositive`; eyeball the grouped layout, reveal selector, and the confirm-on-disable safe default;
and confirm settings round-trip. Risk: **LOW** (behaviour-preserving; AppSettings untouched; the heart is
unit-tested).

---

## Self-Stabilization Review

- **Cross-platform blind spots:** the metadata/catalog/VM are WPF-free (verified — no `System.Windows`), so
  they carry no XAML/WinForms ambiguity. The window code-behind builds controls with **aliased/qualified** WPF
  types (`WpfCheckBox`, `WpfTextBlock`, `System.Windows.Media.Brushes`, aliased `MessageBox*`) to avoid the
  WPF-vs-WinForms `CheckBox` collision (the project sets `UseWindowsForms=true`). XAML compile + manual flows
  remain Windows-only — nothing was compiled here.
- **Test/API mismatch:** read `AppSettings`, the schema tests, `SettingsWindow`, `TypedSettings`, and the
  Shared settings before writing. Tests use reflection to prove each toggle key is a real bool property and
  each accessor round-trips, catching any copy-paste getter/setter mismatch. No `InternalsVisibleTo` reliance
  (types are public). Distinct VM name avoids the Shared `SettingsViewModel` record collision.
- **Resource/build integration:** SDK globbing auto-includes the new `.cs`/`.xaml`; no `.resx`/designer added
  (strings inline pt-BR), so no satellite/culture risk. XAML well-formed (xmllint).
- **Safety-policy consistency:** `AppSettings` (defaults, thresholds, migration), anti-FP, classifier, YARA,
  and quarantine are **byte-unchanged** (none in the delta). Disabling protection now requires confirmation;
  raw thresholds are Developer-only. No remediation behaviour, no destructive action, no dormant-engine
  enablement.
- **Phase-boundary enforcement:** additive metadata only; no schema bump; no settings removed/renamed; the
  legacy window is kept; minimal, surgical (one-line shell wiring).
- **Issues found and fixed:** chose a distinct VM name on discovering the Shared `SettingsViewModel` record;
  kept `AppSettings` untouched so all schema tests pass by construction; used qualified WPF control types in
  code-behind to pre-empt the WinForms ambiguity.
- **Windows-only / Codex-only:** WPF/XAML compile, the 18 tests, manual settings flows; metadata-driven
  number/text editors and i18n resource migration (follow-ups).
- **Prior mistake patterns prevented:** Linux≠Windows (compiled nothing, said so); reflection-guarded
  test/API mismatch; WPF/WinForms ambiguity (aliases); namespace collision (distinct name); "quiet threshold/
  anti-FP weakening" (AppSettings untouched).
- **Codex stabilization recommended? Optional, LOW risk.**

## Documentation Review

- **Files reviewed:** `DataVanger/ALTERACOES_BETA.md` (the main Beta change-log), `DataVanger/ALTERACOES_v2_0.md`
  and `DataVanger/ALTERACOES_v2_1.md` (Alpha-era logs), and the prior phase reports under `outputs/`
  (`BETA_04B_…`, `BETA_05_…`).
- **Files updated:** `DataVanger/ALTERACOES_BETA.md` — appended a `06_SETTINGS_REDESIGN` entry (and a one-line
  summary in the completed-phases list). The entry states: phase name; what changed (additive metadata +
  grouped VM + reveal + confirm-on-disable, AppSettings unchanged); user-visible impact (redesigned grouped
  settings window with reveal selector and protection-disable confirmation; legacy window kept); security/
  policy impact (no anti-FP/threshold/YARA/quarantine change; disabling protection no longer silent;
  thresholds hidden from Normal); status (UI-only, behaviour-preserving, wired into the shell, **not**
  Windows-validated, no schema bump); limitations (numeric/text editors stay legacy; i18n deferred); and
  stabilization status (optional; Windows build/test + manual flows pending). Older entries were not rewritten;
  no entry was duplicated. This report (`outputs/BETA_06_SETTINGS_REDESIGN_REPORT.md`) was created.
- **Obsolete / superseded documentation found:** `ALTERACOES_v2_0.md` and `ALTERACOES_v2_1.md` were already
  **consolidated and removed by the upstream stabilization** captured in the adopted ZIP (their content is
  preserved as summarized "Histórico herdado" sections inside `ALTERACOES_BETA.md`). I did **not** delete them
  myself — adopting the ZIP as the source of truth carried that consolidation in. No further consolidation is
  recommended; `ALTERACOES_BETA.md` is now the single ongoing Beta change-log.
- **Documentation intentionally not changed:** the `outputs/` phase reports for 00–05 (historical record, not
  rewritten); `README.md`, `docs/*`, and the Alpha oracle materials (out of this phase's scope; Phase 06 makes
  no architecture/installer/update-system change requiring them). No documentation files were deleted.
