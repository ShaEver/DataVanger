# 21_ANALYZESINGLEFILE_DECOMPOSITION

## 1. Phase name
21_ANALYZESINGLEFILE_DECOMPOSITION — Move-only refactor of the per-file analyzer.

## 2. Phase position
Core-refactor hygiene phase; safest after 09 (granular tests). Medium risk (touches the anti-FP spine). Windows validation.

## 3. Current stable checkpoint
`DataVanger V.Alpha_YARA_PUBLISHERS_STABLE`.

## 4. Objective
Decompose `ScanEngine.AnalyzeSingleFileAsync` (~240 lines, the last large residual from phase 01) into named, single-responsibility steps. Move-only: no detection-logic, scoring, evidence, or quarantine behavior changes. Build after every extraction step.

## 5. Non-goals
- No threshold/scoring changes.
- No evidence shape/content changes.
- No quarantine-gating changes.
- No reordering of the anti-FP gate or the Authenticode trust gate.

## 6. Existing behavior to preserve
- Order of operations: hash → known-safe/known-malware → reputation → detection pipeline → anti-FP clamp → report/quarantine decision.
- The Authenticode trust gate (trusted publisher relief only when `!isKnownMalware && !hasConfirmedSignature && isSigned`).
- Anti-FP clamp to `RiskThresholds.High` for unconfirmed heuristics.
- Quarantine gate (ConfirmedMalware + score ≥ max(High, MinScoreToQuarantine)).
- Persistence-bonus suppression rule.
- Identical findings/evidence/scores on a fixed corpus.

## 7. Core design principle
Behavior-identical extraction. Each extracted method is a pure move of existing code with the same inputs/outputs; the public scan result is byte-for-byte equivalent on a fixed input set.

## 8. Recommended structure
Extract private helpers such as: `ComputeHashAndCachePeek`, `ResolveKnownState` (safe/malware/blacklist), `ApplyAuthenticodeGate`, `RunDetectionPipelineStep`, `ApplyAntiFalsePositiveClamp`, `DecideReportAndQuarantine`. Keep them within `ScanEngine` (private), preserving field/closure access.

## 9. Target files
- `DataVanger/Core/ScanEngine.cs`
- (reuse) existing tests + phase-09 granular tests; add a corpus-parity test if helpful

## 10. Allowed scope
Pure method extraction within `ScanEngine`; renaming locals for clarity without semantic change; adding private helpers.

## 11. Forbidden scope
Any behavior change; new thresholds; altered evidence; changed quarantine gating; reordered gates; new dependencies.

## 12. Migration / implementation strategy (implementation order)
1. Baseline build+test (record results on a fixed corpus if available).
2. Extract one step → build → test. Repeat per step.
3. After each extraction, confirm the anti-FP and detection tests stay green.
4. Final build+test; compare findings/scores to baseline (must match exactly).

## 13. Decision protocol
- If an extraction changes any output → revert it; the move introduced a bug.
- Never "improve" logic during the move; behavior parity is the only goal.
- Keep gate ordering identical.

## 14. Failure modes
| Failure mode | Detection method | Mitigation |
|---|---|---|
| Extraction changes scoring | Corpus/anti-FP test diff | Revert that step |
| Closure/field capture lost | Build error / wrong result | Keep helpers private in ScanEngine |
| Gate reordering | Anti-FP test fail | Preserve exact order |
| Hidden side effect dropped | Detection test fail | One step at a time + per-step build |

## 15. Testing requirements
All existing + phase-09 tests green, especially `~AntiFalsePositive`. Optional: a corpus-parity test asserting identical findings/scores before vs after. `dotnet test` full.

## 16. Acceptance criteria
- Identical findings/evidence/scores on a fixed corpus.
- `AnalyzeSingleFileAsync` materially smaller; helpers single-responsibility.
- Anti-FP and detection tests green; invariants zero.

## 17. Anti-false-positive policy
The anti-FP clamp and ConfirmedMalware gating must be byte-for-byte preserved. This phase exists partly to make that spine more auditable — it must not alter it.

## 18. Forbidden behavior
Changing behavior; reordering gates; altering scores/evidence/quarantine; refactoring beyond move-only.

## 19. Packaging
No ZIP. Commit refactor + any parity test + spec to the branch.

## 20. Final report requirements
Report: extracted methods, per-step build/test confirmation, corpus-parity result (identical), confirmation gates/order unchanged, build/test status (Windows note), invariant results, **Bugs noticed but not fixed**.

## Rollback procedure
Revert the phase commit; `AnalyzeSingleFileAsync` returns to its prior single-method form. Behavior was preserved throughout, so rollback is risk-free.

## Stop conditions
Stop if any extraction changes output and the cause can't be made behavior-identical, or if validation can't run.

## Approval requirements
None (Claude-only), but Codex review recommended given it touches the anti-FP spine.

## Known risks
Medium: the method is central to detection. Mitigated by one-step extraction + per-step builds + parity tests (strongly benefits from phase 09 first).

## Windows validation requirements
`ScanEngine` lives in the `net8.0-windows` UI assembly; validate on Windows + .NET 8.

## Codex stabilization recommendation
**Recommended** (review-only) to confirm behavior parity across the extracted gates.

## Expected outcome
A smaller, clearer, single-responsibility per-file analyzer with provably identical detection behavior and a more auditable anti-FP spine.

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
> You are implementing phase **21_ANALYZESINGLEFILE_DECOMPOSITION** on branch `claude/fervent-dirac-0ml0N`. MOVE-ONLY refactor of `DataVanger/Core/ScanEngine.cs` `AnalyzeSingleFileAsync` (~240 lines) into private single-responsibility helpers (e.g. `ComputeHashAndCachePeek`, `ResolveKnownState`, `ApplyAuthenticodeGate`, `RunDetectionPipelineStep`, `ApplyAntiFalsePositiveClamp`, `DecideReportAndQuarantine`). Preserve EXACT order of operations, the Authenticode trust gate condition, the anti-FP clamp to `RiskThresholds.High`, the ConfirmedMalware quarantine gate, and persistence-bonus suppression — no scoring/evidence/quarantine changes. Extract ONE step at a time, building and testing after each; if any output changes, revert that step. Keep helpers private to retain field access. Run all tests (especially `~AntiFalsePositive`) and confirm identical findings/scores on a fixed corpus. Re-run prior-phase invariant checks (all zero). Deliver a report with extracted methods, per-step confirmation, corpus-parity result, and a "Bugs noticed but not fixed" section. No ZIP. Commit and push. Recommend Codex review.
