# 20_DOCS_OPERATOR_GUIDE

## 1. Phase name
20_DOCS_OPERATOR_GUIDE — Operator + developer documentation and module status matrix.

## 2. Phase position
Zero-risk, fully-offline documentation phase. Can run immediately after 08 (and ideally before the activation phases so the truth is captured). Documentation-only.

## 3. Current stable checkpoint
`DataVanger V.Alpha_YARA_PUBLISHERS_STABLE`.

## 4. Objective
Replace the effectively-empty `README.md` with comprehensive operator documentation, developer documentation, a **module status matrix** (Active vs Prepared vs Fallback vs Stub vs Disabled), and the canonical validation commands. Documentation only — no code/test changes.

## 5. Non-goals
- No code, test, or config changes.
- No over-claiming: prepared/stub systems must be documented as such.

## 6. Existing behavior to preserve
- All existing behavior is unchanged (docs-only).
- Phase docs continue to live under `outputs/`.

## 7. Core design principle
Documented truth. The guide must match the code reality this planning round established (e.g. real libyara prepared, HTTP update stubbed, `--service` stub, ETW/AMSI stubs, Quarantine V2 implemented).

## 8. Recommended structure
- `README.md`: overview, architecture (6 projects), build/run, validation commands, security posture, anti-FP contract summary.
- `docs/OPERATOR_GUIDE.md`: install/run, settings, quarantine/restore, scheduling, realtime, updates, service modes.
- `docs/DEVELOPER_GUIDE.md`: project layout, detection pipeline, adding a module, test layout, invariant checks.
- `docs/MODULE_STATUS_MATRIX.md`: per-module state (Active/Prepared/Fallback/Stub/Disabled) with file references; keep in sync with phase-18 taxonomy.

## 9. Target files
- `README.md`
- `docs/OPERATOR_GUIDE.md` (new)
- `docs/DEVELOPER_GUIDE.md` (new)
- `docs/MODULE_STATUS_MATRIX.md` (new)
- (reference only) `outputs/*` phase specs

## 10. Allowed scope
Documentation files only.

## 11. Forbidden scope
Any code/test/config change; over-claiming module states; documenting features that don't exist.

## 12. Migration / implementation strategy (implementation order)
1. Inspect current code to confirm each module's real state (do not rely on memory).
2. Write README + the three docs.
3. Cross-check the status matrix against `ModuleStatusAggregator` and the actual stubs (`HttpUpdateTransport`, `Program.cs --service`, ETW/AMSI adapters, `LibyaraEngine` `#if YARA_REAL`).
4. Include the prior-phase invariant checks + baseline validation commands verbatim.

## 13. Decision protocol
- If code and intent disagree, document the **code** reality and flag the gap.
- Mark anything uncertain as "needs audit" rather than guessing.

## 14. Failure modes
| Failure mode | Detection method | Mitigation |
|---|---|---|
| Docs over-claim a stub as Active | Cross-check vs code | Verify each entry against source |
| Docs drift from code | Re-inspect at write time | Reference exact files/lines |
| Validation commands wrong | Dry-read | Copy the canonical command set |

## 15. Testing requirements
No automated tests. Verification = cross-check matrix entries against source files; ensure validation commands match the project layout.

## 16. Acceptance criteria
- README + three docs exist and reflect code reality.
- Status matrix matches `ModuleStatusAggregator` + actual stubs.
- Validation commands + invariant checks included verbatim.

## 17. Anti-false-positive policy
Document the anti-FP contract accurately (ConfirmedMalware only from blacklisted hash / confirmed signature / curated confirmed YARA rule; heuristics clamp to High; real external YARA/behavioral/ETW/AMSI never confirm). Do not misstate it.

## 18. Forbidden behavior
Over-claiming; documenting non-existent features; editing code/tests; removing the "prepared vs active" distinction.

## 19. Packaging
No ZIP. Commit docs to the branch.

## 20. Final report requirements
Report: files created, matrix summary, list of any code/intent gaps found and marked "needs audit", confirmation no code/tests changed.

## Rollback procedure
Revert the phase commit (docs only); zero runtime impact.

## Stop conditions
Stop if writing accurate docs would require code changes (defer those to their phases) or if a module's real state cannot be determined (mark "needs audit").

## Approval requirements
None (Claude-only, zero-risk, offline-safe).

## Known risks
Very low. Only risk is inaccuracy; mitigated by source cross-checking.

## Windows validation requirements
None to author. The documented validation commands themselves require Windows to execute, which the docs state.

## Codex stabilization recommendation
Not required.

## Expected outcome
A truthful, comprehensive documentation set and a module status matrix that prevents over-trust and anchors the path to a defensible "STABLE".

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
> You are implementing phase **20_DOCS_OPERATOR_GUIDE** on branch `claude/fervent-dirac-0ml0N`. DOCUMENTATION ONLY — no code/test/config changes. First inspect the current repository to confirm each module's real state. Replace the empty `README.md` and add `docs/OPERATOR_GUIDE.md`, `docs/DEVELOPER_GUIDE.md`, and `docs/MODULE_STATUS_MATRIX.md`. The matrix must classify every module as Active/Prepared/Fallback/Stub/Disabled with exact file references, cross-checked against `ModuleStatusAggregator` and the real stubs (`HttpUpdateTransport` throwing, `Program.cs --service` stub, `EtwBehaviorProvider`/`AmsiBehaviorAdapter` `IsAvailable=false`, `LibyaraEngine` `#if YARA_REAL`). Document the anti-FP contract accurately and include the prior-phase invariant checks + the eight baseline validation commands verbatim. Mark anything uncertain as "needs audit" instead of guessing; never over-claim. Deliver a report listing files created, a matrix summary, any code/intent gaps found, and confirmation that no code/tests changed. No ZIP. Commit and push.
