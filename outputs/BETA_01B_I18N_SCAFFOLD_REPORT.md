# BETA 01B — I18N SCAFFOLD REPORT

Phase: `01B_I18N_SCAFFOLD` (DataVanger V.Beta Improvement Plan)
Executed: 2026-06-12
Verdict: **IMPLEMENTED. pt-BR remains the deterministic default; en-US is a partial scaffold with
verified fallback; 14/14 scaffold tests pass on Linux; WPF build + manual culture checklist pending
on Windows (the standing environment exception).**

---

## 0. Baseline replacement confirmation (pre-phase requirement)

The previously tracked baseline was **replaced by the newly uploaded archive**
(`claude_workspace-claude-adoring-dirac-jxo678.zip`, the stabilized post-01A state):

- Working tree contents were deleted (except `.git`) and replaced verbatim by the new archive —
  no merge of old contents over new; git history preserved.
- Verified delta between old and new baselines: **exactly one file** — `DataVanger/MainWindow.xaml.cs`,
  where `Button` was disambiguated to `System.Windows.Controls.Button` in two places (WPF+WinForms
  ambiguity found by the Windows build during stabilization). Behavior-neutral.
- Adopted as commit `ae8d579` ("Adopt stabilized Phase 01A baseline from uploaded archive").
- Solution identity re-verified after replacement: `DataVanger.sln` with the 6 expected projects;
  baseline validation re-run (the four cross-platform projects build 0 errors).
- The old Alpha oracle zip remains untracked (Phase 01A decision); it was not reintroduced.

## 1. Localization structure created (pattern)

Standard **.resx + ResourceManager**, matching the app's plain code-behind style (no new frameworks):

| File | Role |
|------|------|
| `DataVanger/Localization/UiStrings.resx` | **Neutral resources = pt-BR** (the product default). 17 shell keys + 3 representative legacy keys. |
| `DataVanger/Localization/UiStrings.en-US.resx` | **Partial en-US scaffold**: the 9 navigation labels + navigation header + 3 section headers. Descriptions, deferred note and all `Legacy_*` keys are deliberately absent to exercise fallback. |
| `DataVanger/Localization/LocalizationService.cs` | Culture application + lookup. Deterministic chain: current culture → parent → neutral (pt-BR). Missing key ⇒ visible marker `![key]!` (never blank) + recorded in `MissingKeys` for developer diagnostics. Invalid culture names fall back to pt-BR via `GetCultureInfo(..., predefinedOnly: true)`. |
| `DataVanger/Localization/CommonLabels.cs` | Facade for the migrated legacy strings. |
| `DataVanger/Shell/ShellLabels.cs` | Converted from constants to **resource-backed static properties** — same member names, so the 01A XAML (`{x:Static}`), the navigation ViewModel and the shell tests required no changes. |
| `DataVanger/DataVanger.csproj` | `<NeutralLanguage>pt-BR</NeutralLanguage>` added (one line). |
| `DataVanger/App.xaml.cs` | `LocalizationService.ApplyStartupCulture(e.Args)` at the very top of `OnStartup`, before any window exists. |

## 2. pt-BR default behavior

- The default is **deterministic and OS-independent**: startup forces `pt-BR` unless the user
  explicitly opts in via `--ui-culture <name>` or the `DATAVANGER_UI_CULTURE` environment variable
  (both per-user; **no elevation involved**). Without the explicit forcing, ResourceManager would have
  followed the OS culture — an English Windows would silently switch the product language, which would
  have been a behavior change. This preserves the Alpha experience exactly.
- Only `CurrentUICulture` is touched; thread `CurrentCulture` (number/date formatting) is untouched.

## 3. en-US scaffold / fallback behavior

- Requesting en-US yields English for the translated subset (nav labels, headers) and **falls back to
  the pt-BR neutral resources for everything else** — verified by tests asserting exact pt-BR text for
  untranslated keys under en-US.
- A key missing from **all** cultures returns `![key]!` — visible to developers, never a blank label,
  and registered in `LocalizationService.MissingKeys` (§5 "pseudo-missing-resource behavior").
- Security/consent copy: no warning/consent strings were migrated or altered; pt-BR coverage is the
  complete neutral set by construction, so no destructive-action label can be blank (§9).

## 4. Which strings were migrated / which remain legacy

- **Migrated:** all 17 shell strings from 01A (`ShellLabels` now resource-backed) and a 3-string
  representative legacy set to prove the pattern on pre-existing XAML: footer tagline
  ("DataVanger - Scanner defensivo local"), section labels "INICIAR SCAN" and "AÇÕES"
  (now `{x:Static loc:CommonLabels.*}` in `MainWindow.xaml`).
- **Remain legacy (intentionally):** every other hardcoded string in all windows, dialogs, logs and
  reports. No force-migration occurred (§3/§6). Identifiers, IPC command names, DTO members and
  persisted settings keys were **not** localized or renamed.

## 5. Tests added or changed

New, no existing test touched:

- `DataVanger.Tests/LocalizationTests.cs` — 8 tests (`~Localization` filter): pt-BR default resolution;
  `ShellLabels` resource-backed; en-US partial translation; en-US missing-key fallback to exact pt-BR
  text; unknown-key visible marker + registry; invalid culture name falls back to pt-BR; culture request
  parsing from args (no elevation); reflection sweep asserting **every** `ShellLabels` member is
  non-blank with no missing-marker in both cultures.
- `DataVanger.Tests/LocalizationSettingsInvarianceTests.cs` — serializes `AppSettings` under en-US and
  asserts persisted JSON keys (`SchemaVersion`, `MinScoreToQuarantine`, …) are culture-invariant (§9/§10).

## 6. Validation commands run and results

| Check | Result |
|-------|--------|
| Scratch harness on Linux (identical sources: Shell + Localization incl. both `.resx`, `RootNamespace=DataVanger`, `NeutralLanguage=pt-BR`): `LocalizationTests` + `ShellNavigationTests` | **PASS — 14/14** (also proves the resx files compile and the en-US satellite assembly is generated and loaded) |
| Bug found & fixed by this validation | Under ICU (Linux **and** modern Windows), `GetCultureInfo` accepts synthetic culture names without throwing; fallback now uses `predefinedOnly: true` — the invalid-culture test failed before the fix and passes after |
| `dotnet build` Shared / Engine / Infrastructure / Service | **PASS — 0 errors** (projects untouched by this phase) |
| XML well-formedness: `MainWindow.xaml`, both `.resx` | **PASS** |
| Invariants on changed files (empty catch / CRLF) | **0 / 0 — PASS** |
| `dotnet build DataVanger` / `DataVanger.Tests` / full suite / x64 | **NOT RUNNABLE here** — WindowsDesktop SDK absent on Linux (standing environment exception; commands listed below for Windows) |

```powershell
dotnet restore
dotnet build DataVanger.sln
dotnet test DataVanger.Tests/DataVanger.Tests.csproj
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --arch x64
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~Localization"
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~ShellNavigation"
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --filter "FullyQualifiedName~Settings"
```

## 7. Manual validation (§11) — PENDING ON WINDOWS

Launch default → all UI in pt-BR; launch with `--ui-culture en-US` → nav labels/headers in English,
descriptions/legacy in Portuguese (fallback), no blank labels anywhere; existing Alpha windows
unchanged; no elevation prompted.

## 8. What was intentionally NOT implemented

Full app translation; rewriting views for localization; a persisted language setting (deferred to the
Settings redesign phase — §19 allows skipping it; the explicit-culture plumbing covers validation
needs without touching settings semantics); any change to detection, remediation, quarantine, service,
IPC, update or settings behavior; English as default.

## 9. Stop conditions encountered

None. (App does not default to English; no blank security text possible — pt-BR neutral set is
complete; no persisted/IPC names renamed — guarded by test; no full-translation expansion.)

## 10. Remaining risks / follow-ups

1. Windows build + manual culture checklist (§7) — the standing environment gap.
2. `x:Static` reads label properties once at XAML load; runtime language switching (not required by
   this phase) will need a bindable wrapper when a language setting ships with the Settings redesign.
3. The en-US scaffold is intentionally thin; coverage grows opportunistically in later UI phases.

## 11. Recommendation

**Ready for light Codex stabilization** (as the phase MD recommends): verify resource coverage on
Windows, run the culture checklist, and double-check no serialized-name drift. Do not expand into a
translation sweep.
