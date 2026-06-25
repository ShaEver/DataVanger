# 18_MODULE_STATUS_UI_CLARITY

## 1. Phase name
18_MODULE_STATUS_UI_CLARITY — Honest module-state visibility.

## 2. Phase position
Low-risk UI/status phase; can be done early (after 08). UI/status only.

## 3. Current stable checkpoint
`DataVanger V.Alpha_YARA_PUBLISHERS_STABLE`.

## 4. Objective
Improve module-state visibility so operators can see exactly what is real. Differentiate states: **Active, Prepared, Fallback, Disabled, Stub, Degraded**. Surface them through `DataVanger.Engine/Status/ModuleStatusAggregator.cs` into the UI. No behavior changes.

## 5. Non-goals
- No detection/scoring/runtime behavior changes.
- No faking "Active" for prepared/stub systems.
- No new module wiring.

## 6. Existing behavior to preserve
- `ModuleStatusAggregator` outputs and `Shared/Status/*` models remain the source of truth (extended, not contradicted).
- Real-YARA off ⇒ reported `Fallback`/`Prepared`; updates file-only ⇒ `Prepared`/`Disabled`; `--service` ⇒ `Stub`; ETW/AMSI off ⇒ `Stub`/`Disabled` until phase 17.
- All scanning behavior unchanged.

## 7. Core design principle
Truth-in-status. The UI reflects code reality; nothing is over-claimed. A clear taxonomy prevents operators from trusting inactive systems.

## 8. Recommended structure
- Define/extend a `ModuleState` enum (Active/Prepared/Fallback/Disabled/Stub/Degraded) in `Shared/Status`.
- Have `ModuleStatusAggregator` compute each module's state from real signals (e.g. `IYaraEngine` real vs adapter, update transport enabled, provider availability, service mode).
- Add a read-only status surface in the UI (status view/panel) binding to the aggregator.

## 9. Target files
- `DataVanger.Engine/Status/ModuleStatusAggregator.cs`
- `DataVanger.Shared/Status/ModuleStatusModels.cs`
- Main window / a status view in `DataVanger/` (WPF, read-only)
- Tests in `DataVanger.Tests/` (`ModuleStatusTests.cs`)

## 10. Allowed scope
Status taxonomy + computation from existing signals + read-only UI surfacing + tests.

## 11. Forbidden scope
Changing module behavior; reporting a prepared/stub module as Active; new detection wiring; writing settings.

## 12. Migration / implementation strategy (implementation order)
1. Baseline build+test.
2. Add/extend `ModuleState` taxonomy in Shared.
3. Compute states in the aggregator from real signals (YARA engine type, update enablement, provider availability, service mode, fallback usage).
4. Bind a read-only status panel in the UI.
5. Snapshot tests asserting correct state per known config.
6. Build+test.

## 13. Decision protocol
- When uncertain, report the *more conservative* state (Prepared/Fallback/Stub over Active).
- Never display Active unless the real implementation is in use.
- Degraded = active-but-limited (e.g. provider partially available).

## 14. Failure modes
| Failure mode | Detection method | Mitigation |
|---|---|---|
| Status over-claims Active | Snapshot test vs config | Derive state from real signals only |
| Stale status | Refresh-on-scan/start | Recompute on status query |
| UI binding errors | Manual WPF run | Read-only bindings; defensive null |

## 15. Testing requirements
Snapshot tests: real-YARA off ⇒ Fallback; updates disabled ⇒ Disabled; `--service` ⇒ Stub; ETW/AMSI off ⇒ Stub. `--filter "FullyQualifiedName~Status"`.

## 16. Acceptance criteria
- UI honestly shows per-module Active/Prepared/Fallback/Disabled/Stub/Degraded.
- No behavior change; aggregator matches code reality.
- Build+test green; invariants zero.

## 17. Anti-false-positive policy
Status display does not affect detection or verdicts; cannot impact anti-FP behavior. It *supports* honesty about which detectors are real.

## 18. Forbidden behavior
Mislabeling inactive systems as Active; changing behavior; hiding fallback/stub states.

## 19. Packaging
No ZIP. Commit status + UI + tests + spec. Feed the taxonomy into phase 20 docs (status matrix).

## 20. Final report requirements
Report: state taxonomy, per-module derivation rules, UI surface, snapshot test results, build/test status (Windows/WPF note), invariant results, **Bugs noticed but not fixed**.

## Rollback procedure
Revert the phase commit; status reverts to prior reporting; no behavior affected.

## Stop conditions
Stop if status cannot be derived from real signals (would require guessing) or if validation can't run.

## Approval requirements
None (Claude-only, low-risk, UI/status only).

## Known risks
Low. Main risk is mislabeling; mitigated by deriving state from concrete signals + snapshot tests.

## Windows validation requirements
WPF UI surface validates on Windows; the aggregator logic + snapshot tests are part of the `net8.0-windows` suite.

## Codex stabilization recommendation
Not required.

## Expected outcome
Operators get an honest, at-a-glance view of which modules are truly active vs prepared/fallback/stub — directly supporting trustworthy "STABLE" claims.

### Prior-phase invariant checks (must remain green)
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
Expected: zero anonymous catch blocks · zero `lock(qm)` · zero CRLF `.cs` files.

### Baseline validation commands
```powershell
dotnet build DataVanger/DataVanger.csproj
dotnet build DataVanger.Tests/DataVanger.Tests.csproj
dotnet build DataVanger.Service/DataVanger.Service.csproj
dotnet build DataVanger.Engine/DataVanger.Engine.csproj
dotnet build DataVanger.Shared/DataVanger.Shared.csproj
dotnet build DataVanger.Infrastructure/DataVanger.Infrastructure.csproj
dotnet build DataVanger.sln
dotnet test DataVanger.Tests/DataVanger.Tests.csproj
```

## 21. Claude Code Prompt
> You are implementing phase **18_MODULE_STATUS_UI_CLARITY** on branch `claude/fervent-dirac-0ml0N`. UI/status ONLY — no behavior changes. Extend `DataVanger.Shared/Status/ModuleStatusModels.cs` with a `ModuleState` taxonomy (Active/Prepared/Fallback/Disabled/Stub/Degraded) and have `DataVanger.Engine/Status/ModuleStatusAggregator.cs` derive each module's state from REAL signals (real-YARA vs adapter, update transport enabled, provider availability, service mode, fallback usage) — never over-claim Active; prefer the conservative state when uncertain. Add a read-only WPF status panel binding to the aggregator. Add `DataVanger.Tests/ModuleStatusTests.cs` snapshot tests (real-YARA off ⇒ Fallback; updates disabled ⇒ Disabled; `--service` ⇒ Stub; ETW/AMSI off ⇒ Stub). Re-run prior-phase invariant checks (all zero). Deliver a report with the taxonomy, derivation rules, UI surface, test results, and a "Bugs noticed but not fixed" section. Feed the taxonomy to phase 20 docs. No ZIP. Commit and push.
