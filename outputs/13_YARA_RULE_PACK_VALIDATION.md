# 13_YARA_RULE_PACK_VALIDATION

## 1. Phase name
13_YARA_RULE_PACK_VALIDATION — Robust local rule-pack loading & validation.

## 2. Phase position
After 12 for the real-engine path; the lightweight-engine portions are doable independently. Medium-risk.

## 3. Current stable checkpoint
`DataVanger V.Alpha_YARA_PUBLISHERS_STABLE` (+ phases applied so far).

## 4. Objective
Validate compatibility with real-world YARA rule packs, **local only** (no downloads, no cloud). Harden loading of `LightweightYaraDatabase` (and, when active, the real engine) against malformed rules and unsupported constructs; enforce size/count limits; report loaded/failed counts; preserve graceful fallback.

## 5. Non-goals
- No rule downloading, fetching, or cloud integration of any kind.
- No auto-update of rule packs (separate from signed updates).
- No change to confirmation semantics.

## 6. Existing behavior to preserve
- `LightweightYaraDatabase.Load(signatureRoot)` loads from `<SignatureRoot>/yara_rules`, creates the dir if missing, skips README, and isolates a malformed file (logs, continues).
- `YaraDetectionModule.Supports` skips archives and respects `EnableYaraRules` + `YaraMaxScanSizeMB`.
- Lightweight `confirmed` rules keep confirming; real matches never confirm.
- Fallback to lightweight is always valid.

## 7. Core design principle
Trustworthy, bounded, offline loading. Every rule source is validated locally; malformed/unsupported rules degrade gracefully with accurate telemetry, never crash the scan.

## 8. Recommended structure
- A `RulePackValidationResult` (loaded count, skipped count, reasons) surfaced via the engine/status.
- Limits in config (max rules, max rule file size, max total) using phase-10 schema.
- Unsupported-construct detection for the lightweight parser (clear "skipped: unsupported" reasons).
- For the real engine (if active), per-file compile isolation + aggregate report.

## 9. Target files
- `DataVanger/Core/LightweightYaraDatabase.cs`
- `DataVanger/Detection/YaraDetectionModule.cs`
- `DataVanger/Infrastructure/LibyaraEngine.cs` (real path, if active)
- `DataVanger.Engine/Status/ModuleStatusAggregator.cs` (surface counts)
- `DataVanger/Core/AppSettings.cs` (limits; via phase 10)
- Tests in `DataVanger.Tests/` (`YaraRulePackTests.cs`)

## 10. Allowed scope
Loading/validation/limits/telemetry for local rule packs; tests with malformed/unsupported/oversized fixtures; status surfacing.

## 11. Forbidden scope
Network/download/cloud; auto-update; confirmation-semantics changes; removing fallback; unbounded loading.

## 12. Migration / implementation strategy (implementation order)
1. Baseline build+test.
2. Add limits config + `RulePackValidationResult`.
3. Harden lightweight parser: detect unsupported constructs, enforce limits, accurate skip reasons.
4. (If 12 active) mirror per-file isolation + aggregate counts for the real engine.
5. Surface counts via status aggregator.
6. Add fixtures + tests (valid pack, malformed file, unsupported construct, oversized, empty dir).
7. Build+test.

## 13. Decision protocol
- A malformed/unsupported rule is skipped with a reason; it never aborts loading.
- If limits are exceeded, load up to the limit and report truncation; never OOM.
- If a pack yields zero usable rules, the module simply has nothing to match (no error, fallback engine still valid).

## 14. Failure modes
| Failure mode | Detection method | Mitigation |
|---|---|---|
| Malformed rule crashes load | Load test with bad file | Per-file try/catch, skip+log |
| Unsupported construct mis-parsed | Construct fixtures | Detect+skip with reason |
| Oversized pack OOM | Limit tests | Enforce size/count caps |
| Counts wrong/misleading | Telemetry tests | Assert loaded/skipped totals |
| Empty/missing dir | Missing-dir test | Create dir, return 0, no throw |

## 15. Testing requirements
Fixtures for: valid multi-rule pack; a malformed file among valid ones; an unsupported-construct rule; an oversized file; an empty directory. Assert accurate loaded/skipped counts and graceful behavior. `--filter "FullyQualifiedName~Yara"`.

## 16. Acceptance criteria
- Malformed/unsupported/oversized packs degrade gracefully with accurate counts.
- Limits enforced; no crash/OOM.
- Fallback intact; confirmation semantics unchanged.
- Build+test green; invariants zero.

## 17. Anti-false-positive policy
Rule-pack changes do not alter confirmation: lightweight `confirmed` rules still confirm; real matches never do. No new auto-confirmation paths.

## 18. Forbidden behavior
Downloading rules; cloud calls; unbounded memory; treating a skipped rule as a match; confirming from real matches.

## 19. Packaging
No ZIP. Commit code + fixtures + tests + spec to the branch. Document the expected `yara_rules` directory layout.

## 20. Final report requirements
Report: limits added, validation result model, lightweight + (optional) real-path hardening, fixture/test list/results, status surfacing, build/test status (Windows note), invariant results, **Bugs noticed but not fixed**.

## Rollback procedure
Revert the phase commit; loading returns to the prior lightweight behavior. No persisted state to migrate.

## Stop conditions
Stop if any change would introduce a network/download path, if confirmation semantics would change, or if validation can't run.

## Approval requirements
None for the lightweight/local portions (Claude-only). Real-engine portions depend on phase 12 approval being already granted.

## Known risks
Medium: parser hardening can mis-skip valid rules. Mitigated by construct fixtures + accurate reason reporting.

## Windows validation requirements
Real-engine rule-pack tests require Windows (phase 12 active). Lightweight tests run wherever the suite runs (`net8.0-windows` ⇒ Windows).

## Codex stabilization recommendation
Optional for lightweight; **recommended** for any real-engine rule-compile edge cases.

## Expected outcome
DataVanger loads real-world local YARA rule packs robustly, reports exactly what loaded/failed, enforces bounds, and never compromises the fallback or anti-FP contract.

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
> You are implementing phase **13_YARA_RULE_PACK_VALIDATION** on branch `claude/fervent-dirac-0ml0N`. LOCAL ONLY — no downloads, no cloud. Harden `DataVanger/Core/LightweightYaraDatabase.cs` (and the real path in `LibyaraEngine.cs` if phase 12 is active) to load real-world local YARA rule packs from `<SignatureRoot>/yara_rules`: per-file isolation of malformed rules, detection+skip of unsupported constructs with clear reasons, enforced size/count limits (config via phase-10 schema), and an accurate loaded/skipped `RulePackValidationResult` surfaced through `ModuleStatusAggregator`. Preserve the guaranteed lightweight fallback and confirmation semantics (lightweight `confirmed` rules still confirm; real matches never confirm). Add `DataVanger.Tests/YaraRulePackTests.cs` with valid/malformed/unsupported/oversized/empty-dir fixtures asserting graceful behavior and correct counts. Re-run prior-phase invariant checks (all zero). Deliver a report with limits, validation model, hardening notes, test results, and a "Bugs noticed but not fixed" section. No ZIP. Commit and push.
