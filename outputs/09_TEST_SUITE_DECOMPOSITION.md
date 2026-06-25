# 09_TEST_SUITE_DECOMPOSITION

## 1. Phase name
09_TEST_SUITE_DECOMPOSITION — Faithful split of the monolithic legacy parity test.

## 2. Phase position
After 08_XUNIT_WARNING_CLEANUP (must follow it). Test-only.

## 3. Current stable checkpoint
`DataVanger V.Alpha_YARA_PUBLISHERS_STABLE` (+ phase 08 applied).

## 4. Objective
Split `DataVanger.Tests/LegacyParityTests.cs` (≈7,721 lines, **one** `[Fact]` wrapping **49** subsystem sections) into logical xUnit files/classes (one per subsystem area) so failures localize and `--filter` can reach each area. Preserve every assertion, expected value, and support type. No coverage reduction.

## 5. Non-goals
- No new assertions, no changed expected values, no production changes.
- No behavioral test changes; no removal of the private `Assert` shim semantics (it may be promoted to a shared internal helper but must behave identically).
- No enabling of parallelization (state remains disabled).

## 6. Existing behavior to preserve
- Every one of the 49 sections' checks runs and passes with identical outcomes.
- Shared fixtures `Fixtures/PeFactory.cs`, `Fixtures/TempFileScope.cs` reused, not duplicated.
- `TestSupport/TestParallelization.cs` unchanged.
- Deterministic data builders and any inline test state types preserved (move, don't rewrite).

## 7. Core design principle
Move-only decomposition. Cut each section verbatim into a focused `[Fact]` (or `[Theory]`) in a per-area class; share helper/state types via a common `internal` support file. Identical inputs → identical assertions.

## 8. Recommended structure
Create per-area files under `DataVanger.Tests/` such as:
`HashAndSignatureTests`, `HeuristicTests`, `ScriptDetectionTests`, `PeDetectionTests`, `ArchiveTests`, `DocumentTests`, `BrowserExtensionTests`, `ReputationTests`, `ScanProfileTests`, `DetectionPipelineTests`, `BehavioralEngineTests`, `EtwAmsiTests`, `MemoryScannerTests`, `SchedulerTests`, `ReportingForensicsTests`, `SelfProtectionTests`, `ServiceRealtimeTests`, `QuarantineTests`, `UpdateTests`, `IpcTests`. Promote the `Assert(bool,string)` shim into `DataVanger.Tests/TestSupport/LegacyAssert.cs` (identical semantics) for reuse.

## 9. Target files
- `DataVanger.Tests/LegacyParityTests.cs` (source of truth to carve up; may be reduced to a thin residual or removed once fully migrated)
- New per-area `*.Tests.cs` files in `DataVanger.Tests/`
- `DataVanger.Tests/TestSupport/LegacyAssert.cs` (new, optional)
- (reuse) `DataVanger.Tests/Fixtures/*`, `DataVanger.Tests/TestSupport/TestParallelization.cs`

## 10. Allowed scope
Test reorganization: moving code into new classes, extracting shared helpers, adding `[Fact]`/`[Theory]` wrappers. Adjusting `using` directives.

## 11. Forbidden scope
Production code; assertion meaning/values; coverage reduction; broad rewrites; new external test dependencies; csproj changes beyond compile inclusion (which is automatic via SDK globbing).

## 12. Migration / implementation strategy (implementation order)
1. Baseline build+test (must be green; record Fact count and pass count).
2. Extract shared support types/shim into `TestSupport`.
3. Migrate one section at a time into its area class; build+test after each migration; keep the original section commented-then-removed only after its new home passes.
4. When all sections migrated, reduce/remove `LegacyParityTests.cs`.
5. Final build+test; confirm total assertions preserved and new granular filters work.

## 13. Decision protocol
- One section per commit-sized step; never migrate many at once.
- If a moved section fails, the move introduced a context/ordering bug → fix the move (e.g. shared state) or revert that section; never edit the assertion.
- Preserve original section ordering effects by making each Fact self-contained (no hidden cross-section state).

## 14. Failure modes
| Failure mode | Detection method | Mitigation |
|---|---|---|
| Hidden cross-section shared state | Moved Fact fails in isolation | Make each Fact construct its own state/fixtures |
| Duplicate helper definitions | Build error CS0101 | Centralize helpers in TestSupport |
| Lost section (coverage drop) | Fact count / checklist mismatch | Track a 49-section migration checklist |
| Fixture path collisions | Temp-file IO errors | Use `TempFileScope` + unique GUIDs |

## 15. Testing requirements
After migration, `dotnet test` green; the sum of migrated checks equals the original; spot-run filters (e.g. `--filter "FullyQualifiedName~PeDetection"`, `~Quarantine`, `~Reputation`).

## 16. Acceptance criteria
- All 49 sections exist as independently runnable Facts/classes.
- `dotnet test` green; assertion total preserved; no coverage reduction.
- Granular `--filter` reaches each subsystem.
- Prior-phase invariants zero.

## 17. Anti-false-positive policy
Anti-FP/classification tests (sections 1, 2, 7 — already mirrored in `AntiFalsePositiveTests.cs`) must remain and pass unchanged; do not weaken any ConfirmedMalware/clamp assertion.

## 18. Forbidden behavior
Changing expected values; dropping sections; merging distinct checks; rewriting logic "for clarity"; enabling parallel runs.

## 19. Packaging
No ZIP. Commit reorganized tests + this spec to the branch.

## 20. Final report requirements
Report: new file map (section → file), migration checklist (49/49), Fact/assertion counts before/after, filter examples, build/test status (Windows note), invariant results, and a **Bugs noticed but not fixed** section (e.g. any latent ordering coupling discovered).

## Rollback procedure
`git restore DataVanger.Tests/` or revert the phase commits. Test-only; safe.

## Stop conditions
Stop if a section cannot be migrated without changing an assertion, if coverage would drop, or if validation cannot run on Windows.

## Approval requirements
None (Claude-only, low–medium risk, test-only).

## Known risks
Medium: large mechanical change; risk of hidden coupling between sections. Mitigated by one-section-at-a-time + per-step builds.

## Windows validation requirements
`net8.0-windows` test project → validate on Windows + .NET 8 SDK.

## Codex stabilization recommendation
Optional Codex review to confirm faithful 1:1 assertion migration.

## Expected outcome
The opaque single-Fact blob becomes a granular, filterable suite that makes every later phase verifiable subsystem-by-subsystem.

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
> You are implementing phase **09_TEST_SUITE_DECOMPOSITION** on branch `claude/fervent-dirac-0ml0N`, after phase 08. Test-only; no production changes. Split `DataVanger.Tests/LegacyParityTests.cs` (one `[Fact]`, 49 sections) into per-subsystem test classes, preserving every assertion and expected value verbatim (move-only). Extract the private `Assert` shim into `DataVanger.Tests/TestSupport/LegacyAssert.cs` with identical semantics; reuse `Fixtures/*`. Migrate ONE section at a time, building+testing after each, against a 49-section checklist; make each new Fact self-contained (no hidden cross-section state). Keep parallelization disabled. Validate on Windows with the baseline commands; confirm assertion total preserved and granular `--filter` works. Re-run prior-phase invariant checks (all zero). Deliver a final report with the section→file map, 49/49 checklist, before/after counts, build/test status (Windows note), and a "Bugs noticed but not fixed" section. No ZIP. Commit and push.
