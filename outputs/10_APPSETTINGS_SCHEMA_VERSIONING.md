# 10_APPSETTINGS_SCHEMA_VERSIONING

## 1. Phase name
10_APPSETTINGS_SCHEMA_VERSIONING — Versioned, migratable configuration.

## 2. Phase position
Early hygiene phase (after 08, can precede the activation phases). Low–medium risk.

## 3. Current stable checkpoint
`DataVanger V.Alpha_YARA_PUBLISHERS_STABLE`.

## 4. Objective
Introduce an explicit schema version to `AppSettings` and deterministic migration of older configuration files, so settings can evolve (e.g. the `TrustedPublishers` list added in phase 06, and future fields) without losing user data or silently mis-defaulting. Detection behavior must not change.

## 5. Non-goals
- No detection/scoring/threshold changes.
- No new settings that alter scanning behavior.
- No UI redesign (a read-only version display is optional).
- No telemetry/remote config.

## 6. Existing behavior to preserve
- `DataVanger/Core/AppSettings.cs` `Load(path)` stays resilient: malformed JSON → safe defaults, never throws to the caller.
- All 29 existing properties keep their current defaults and meanings (incl. `TrustedPublishers` curated list, `ExtraTrustedPublishers` additive list).
- `Save(path)` continues to persist all properties.
- `DataVanger/Core/Configuration/TypedSettings.cs` consumers keep working.

## 7. Core design principle
Additive, backward-compatible versioning. A missing version field ⇒ treated as the pre-versioning baseline and migrated forward; unknown future fields ⇒ ignored gracefully (as today). Migrations are pure, deterministic, and lossless for user-set values.

## 8. Recommended structure
- Add `int SchemaVersion { get; set; }` (current = 1) to `AppSettings`.
- Add a `private static AppSettings Migrate(AppSettings loaded, int fromVersion)` step invoked inside `Load`.
- Keep a `const int CurrentSchemaVersion`.
- Null-coalesce list fields on load (`TrustedPublishers ??= Defaults`) so an explicit `null` in JSON degrades safely.
- Persist `SchemaVersion = CurrentSchemaVersion` on `Save`.

## 9. Target files
- `DataVanger/Core/AppSettings.cs`
- (read/integrate) `DataVanger/Core/Configuration/TypedSettings.cs`
- (optional, read-only display) `DataVanger/SettingsWindow.xaml(.cs)`
- New tests in `DataVanger.Tests/` (e.g. `AppSettingsSchemaTests.cs`)

## 10. Allowed scope
Add version field + migration logic + null-safe defaults + persistence of version; tests; optional non-functional version label in UI.

## 11. Forbidden scope
Changing any detection-affecting default; reordering/removing existing properties; breaking older file loads; introducing schema that drops unknown fields destructively.

## 12. Migration / implementation strategy (implementation order)
1. Baseline build+test.
2. Add `SchemaVersion` + `CurrentSchemaVersion`; default new instances to current.
3. Implement `Migrate` (v0/absent → v1: ensure lists non-null, ensure `TrustedPublishers` present with curated defaults if absent).
4. Wire `Migrate` into `Load` after deserialize; persist version on next `Save`.
5. Add round-trip + migration tests (old file without version, file with explicit null lists, current file).
6. Build+test.

## 13. Decision protocol
- Never overwrite a user-set value during migration; only fill genuinely-absent fields.
- If a JSON has an explicit empty `TrustedPublishers: []`, respect it (user cleared it) — do NOT re-inject defaults.
- If migration is ambiguous, default to the safest non-destructive choice and document it.

## 14. Failure modes
| Failure mode | Detection method | Mitigation |
|---|---|---|
| Migration clobbers user values | Round-trip test diff | Fill-only-if-absent rule + tests |
| Explicit `null` list → NRE downstream | Reputation/Scan null checks | Null-coalesce on load |
| Version not persisted | Re-load shows version 0 | Set version in `Save` and post-migrate |
| Old file fails to load | `Load` returns defaults unexpectedly | Keep try/catch resilience; test old format |

## 15. Testing requirements
Tests: (a) old file without `SchemaVersion` migrates and keeps user lists; (b) explicit-null lists become safe defaults without NRE; (c) explicit empty `TrustedPublishers` preserved; (d) save→load round-trip stable; (e) unknown future field ignored. `--filter "FullyQualifiedName~Settings"`.

## 16. Acceptance criteria
- Old configs load losslessly and gain the version on save.
- No detection-affecting default changed (verify anti-FP tests still pass).
- Build+test green; invariants zero.

## 17. Anti-false-positive policy
Trusted-publisher defaults remain exactly as shipped in phase 06 (no OpenAI/Wondershare/SweetLabs). Migration must never inject publishers a user removed, nor remove curated safe defaults a user kept.

## 18. Forbidden behavior
Silent destructive migration; changing thresholds; auto-trusting new publishers; writing settings outside the existing settings path.

## 19. Packaging
No ZIP. Commit `AppSettings` + tests + spec to the branch.

## 20. Final report requirements
Report: schema version introduced, migration rules table, fields touched, test list/results, confirmation no detection default changed, build/test status (Windows note), invariant results, **Bugs noticed but not fixed**.

## Rollback procedure
Revert the phase commit; settings files written with `SchemaVersion` still load on the old code (extra field ignored), so rollback is non-destructive.

## Stop conditions
Stop if migration risks user-value loss, if any detection default would change, or if validation cannot run.

## Approval requirements
None (Claude-only). Low–medium risk.

## Known risks
Medium: config migration can lose data if rules are wrong. Mitigated by fill-only-if-absent + explicit-empty preservation + tests.

## Windows validation requirements
`AppSettings` lives in the `net8.0-windows` UI assembly path; validate on Windows. Logic is offline-authorable.

## Codex stabilization recommendation
Optional Codex review of migration edge cases (null vs empty vs absent).

## Expected outcome
Configuration becomes versioned and future-proof while preserving every user setting and all detection defaults.

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
> You are implementing phase **10_APPSETTINGS_SCHEMA_VERSIONING** on branch `claude/fervent-dirac-0ml0N`. Add `SchemaVersion` + `CurrentSchemaVersion` to `DataVanger/Core/AppSettings.cs` and a deterministic, lossless `Migrate` step invoked from `Load` (missing version ⇒ baseline ⇒ migrate forward). Null-coalesce list fields so explicit `null` degrades to safe defaults; preserve an explicit empty `TrustedPublishers` (user cleared) and never inject publishers a user removed or change any detection-affecting default. Persist the version on `Save`. Add tests in `DataVanger.Tests/AppSettingsSchemaTests.cs` covering old/null/empty/current/unknown-field cases. Keep `Load` resilient (never throws to caller). Validate on Windows; confirm anti-FP tests still pass. Re-run prior-phase invariant checks (all zero). Deliver a report with the migration-rules table, fields touched, test results, build/test status (Windows note), and a "Bugs noticed but not fixed" section. No ZIP. Commit and push.
