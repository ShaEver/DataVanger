# 08_XUNIT_WARNING_CLEANUP

## 1. Phase name
08_XUNIT_WARNING_CLEANUP — Async test hygiene (xUnit1031 debt removal).

## 2. Phase position
First phase after the current stable checkpoint. Test-only. Prerequisite for `09_TEST_SUITE_DECOMPOSITION` (do not split LegacyParityTests in this phase).

## 3. Current stable checkpoint
`DataVanger V.Alpha_YARA_PUBLISHERS_STABLE`
Completed: 01_DECOMPOR_RUNASYNC, 02_ELIMINAR_CATCH_VAZIO, 03_CORRIGIR_CSV, 04_ENTROPIA_POR_SECAO, 05_MIGRAR_PARA_XUNIT, 06_YARA_REAL_PUBLISHERS, 07_LINEENDINGS_LOCK.

## 4. Objective
Remove the xUnit1031 ("do not block on async") analyzer-warning debt safely. There are **226** `.GetAwaiter().GetResult()` blocking calls in the test project (225 in `LegacyParityTests.cs`, 1 in `YaraEngineFallbackTests.cs`). Convert blocking async patterns to `async Task` + `await` **only where it is provably safe and preserves 100% assertion parity**. Document anything unsafe to convert for the later decomposition phase. No production changes.

## 5. Non-goals
- Not splitting/reorganizing `LegacyParityTests` (that is phase 09).
- Not changing any assertion, expected value, threshold, or test ordering semantics.
- Not enabling test parallelization.
- Not touching production code or `TreatWarningsAsErrors`.

## 6. Existing behavior to preserve
- `DataVanger.Tests/TestSupport/TestParallelization.cs` keeps `[assembly: Xunit.CollectionBehavior(DisableTestParallelization = true)]`.
- The single mega-`[Fact]` `DataVanger_LegacySuite_AllChecksPass()` and its private `Assert(bool,string)` shim remain intact in this phase.
- Fixtures `DataVanger.Tests/Fixtures/PeFactory.cs` and `TempFileScope.cs` unchanged in behavior.
- All currently-passing assertions continue to pass with identical results.

## 7. Core design principle
Mechanical, assertion-preserving conversion. A blocking call `X.AnalyzeAsync(...).GetAwaiter().GetResult()` inside an `async Task` test becomes `await X.AnalyzeAsync(...)`. The mega-`[Fact]` may be converted to `async Task` so its internal awaits are legal, but its body stays one method in this phase.

## 8. Recommended structure
1. Convert the small dedicated files first (lowest risk): `YaraEngineFallbackTests.cs` (1 occurrence).
2. Convert the mega-`[Fact]` signature to `public async Task DataVanger_LegacySuite_AllChecksPass()` and replace each `.GetAwaiter().GetResult()` with `await`, line by line.
3. Where a call is inside a non-async lambda/local function, or where converting would change exception-propagation timing relied on by an assertion, **leave it and document it** in the "Bugs noticed but not fixed" + a `// xUnit1031-deferred:` comment.

## 9. Target files
- `DataVanger.Tests/YaraEngineFallbackTests.cs`
- `DataVanger.Tests/LegacyParityTests.cs`
- (read-only) `DataVanger.Tests/AntiFalsePositiveTests.cs`, `DataVanger.Tests/TrustedPublisherSettingsTests.cs`, `DataVanger.Tests/Fixtures/*`, `DataVanger.Tests/TestSupport/TestParallelization.cs`

## 10. Allowed scope
Test-project edits that change only async/await mechanics and method signatures required for legal `await`. Adding `using System.Threading.Tasks;` if needed.

## 11. Forbidden scope
Production code; assertion text/values; test removal; enabling parallelization; introducing new test dependencies; changing `DataVanger.Tests.csproj`.

## 12. Migration / implementation strategy (implementation order)
1. Run baseline build+test; record warning count (xUnit1031 baseline = 226).
2. Convert `YaraEngineFallbackTests.cs`; build+test.
3. Convert mega-`[Fact]` to `async Task`; replace awaits in batches of ~25; build after each batch.
4. For each non-convertible site, add `// xUnit1031-deferred: <reason>` and list it in the final report.
5. Final build+test; confirm warning count dropped and pass-set identical.

## 13. Decision protocol
- If a conversion changes test outcome → revert that conversion immediately; keep blocking form; document.
- Prefer fewer, safe conversions over an aggressive sweep.
- Never alter an assertion to silence a warning.

## 14. Failure modes
| Failure mode | Detection method | Mitigation |
|---|---|---|
| Async conversion reorders exception timing | Test flips pass→fail | Revert that site; keep `.GetAwaiter().GetResult()`; document |
| `await` added in non-async context | Build error CS4033/CS1061 | Make the enclosing method/lambda async or revert |
| Warning count unchanged | `dotnet build` warning summary | Re-scan for remaining `.GetAwaiter().GetResult()` |
| Accidental parallel execution | Tests become flaky | Confirm `DisableTestParallelization` untouched |

## 15. Testing requirements
Full `dotnet test` green; pass-set identical to baseline; xUnit1031 occurrences reduced (ideally to 0 in converted files); document deferred sites.

## 16. Acceptance criteria
- `dotnet build DataVanger.sln` + `dotnet test` green on Windows.
- Same number of passing assertions/Facts as baseline.
- xUnit1031 warnings reduced; every remaining one annotated `// xUnit1031-deferred:` and listed.
- Prior-phase invariants still zero.

## 17. Anti-false-positive policy
No detection behavior is touched; the anti-FP contract is unaffected. This phase must not change any test that asserts the ConfirmedMalware / heuristic-clamp behavior.

## 18. Forbidden behavior
Altering assertions, expected values, or coverage; touching production code; disabling analyzers globally; suppressing xUnit1031 via blanket `#pragma` instead of real conversion or a documented per-site reason.

## 19. Packaging
No ZIP. Commit test changes + this updated spec to the working branch. No installer/artifact changes.

## 20. Final report requirements
Report: files changed, count of conversions, baseline vs final xUnit1031 count, list of `xUnit1031-deferred` sites with reasons, build/test status (with the note that Windows is required), invariant-check results, and a **Bugs noticed but not fixed** section.

## Rollback procedure
`git restore DataVanger.Tests/` (or revert the phase commit). Because the phase is test-only and assertion-preserving, rollback is risk-free.

## Stop conditions
Stop and report if: any conversion cannot keep parity, the suite cannot be run (no Windows SDK available to validate), or warning count cannot be measured.

## Approval requirements
None (Claude-only, low-risk, test-only). No production/security surface.

## Known risks
Low. Largest risk is a subtle exception-timing change in the mega-Fact; mitigated by per-batch builds and immediate revert-on-regression.

## Windows validation requirements
`DataVanger.Tests` targets `net8.0-windows`; build/test must be validated on Windows + .NET 8 SDK. Authoring is offline-safe; **validation is not** (this Linux environment has no SDK).

## Codex stabilization recommendation
Not required. Optional Codex review of the mega-Fact conversion diff for exception-timing parity.

## Expected outcome
Test suite identical in behavior, materially fewer xUnit1031 warnings, and a clean list of any deferred sites to inform phase 09.

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
> You are implementing phase **08_XUNIT_WARNING_CLEANUP** on branch `claude/fervent-dirac-0ml0N`. Test-only; do not touch production code. Goal: remove xUnit1031 blocking-async debt (226 `.GetAwaiter().GetResult()` sites) while preserving 100% assertion parity. Start with `DataVanger.Tests/YaraEngineFallbackTests.cs`, then convert the mega-`[Fact]` in `DataVanger.Tests/LegacyParityTests.cs` to `async Task` and replace each blocking call with `await`, building after every ~25 conversions. Do NOT split LegacyParityTests. For any site that can't be safely converted, keep it and add `// xUnit1031-deferred: <reason>`. Keep `DisableTestParallelization` intact. Validate on Windows with the baseline commands; confirm pass-set is identical and warning count dropped. Re-run the prior-phase invariant checks (expect all zero). Produce a final report including files changed, conversion count, baseline-vs-final warning count, deferred-site list, build/test status (note Windows requirement), and a "Bugs noticed but not fixed" section. Do not create a ZIP. Commit and push to the branch.
