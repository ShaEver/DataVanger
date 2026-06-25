# 22_FINAL_STABILIZATION

## 1. Phase name
22_FINAL_STABILIZATION — V.Alpha release-readiness gate.

## 2. Phase position
Last phase. Aggregation/validation gate over all selected prior phases. Codex stabilization recommended. Windows validation required.

## 3. Current stable checkpoint
`DataVanger V.Alpha_YARA_PUBLISHERS_STABLE` (entry); target exit checkpoint = `DataVanger V.Alpha_STABLE` (final).

## 4. Objective
Perform final V.Alpha stabilization: a validation matrix, build matrix, test matrix, warning review, packaging review, and release-readiness review. Produce a defensible "STABLE" with evidence (a green Windows build+test), not a named claim.

## 5. Non-goals
- No new features.
- No activation of approval-gated systems that weren't already approved + validated in their phases.
- No behavior changes beyond fixing release blockers.

## 6. Existing behavior to preserve
- All shipped behavior from prior phases.
- Anti-FP contract (ConfirmedMalware gating, heuristic clamp, non-confirming real-YARA/behavioral/ETW/AMSI).
- Guaranteed fallbacks (YARA, providers, update transport, service degradation).

## 7. Core design principle
Evidence-based release readiness. Nothing is "STABLE" without a reproducible green build + test on Windows and an accurate module status matrix.

## 8. Recommended structure
- Build matrix: all six projects + sln.
- Test matrix: full suite + key filters (`~AntiFalsePositive`, `~Publisher`, `~Yara`, `~Quarantine`, `~Update`, `~Ipc`, `~Service`).
- Warning review: xUnit1031 (post-08) and compiler warnings; triage.
- Status matrix: confirm Active/Prepared/Stub matches code (with phase 18/20).
- Packaging review: clean Windows checkout restores+builds; record artifact/version.

## 9. Target files
- No production source (unless fixing a discovered release blocker — scoped + documented).
- `outputs/22_FINAL_STABILIZATION_REPORT.md` (the matrices/evidence) and updated `docs/MODULE_STATUS_MATRIX.md`.

## 10. Allowed scope
Validation, matrices, warning triage, packaging review, documentation, and minimal scoped fixes for genuine release blockers (each with its own justification + tests).

## 11. Forbidden scope
New features; enabling unapproved/unvalidated gated systems; broad refactors; behavior changes unrelated to a blocker.

## 12. Migration / implementation strategy (implementation order)
1. Run the full build matrix on Windows.
2. Run the full test matrix + filters.
3. Run prior-phase invariant checks.
4. Review warnings; triage/record.
5. Verify module status matrix vs code.
6. Packaging review (clean checkout restore+build).
7. Compile the final report + checkpoint/ZIP naming; declare go/no-go.

## 13. Decision protocol
- Any failing build/test = NOT STABLE → fix blocker or defer the offending phase.
- Approval-gated systems remain off unless their phase was approved + validated.
- Prefer deferring an unstable feature over shipping it on.

## 14. Failure modes
| Failure mode | Detection method | Mitigation |
|---|---|---|
| A project fails to build | Build matrix | Fix or revert offending phase |
| Test regression | Test matrix | Bisect to phase; fix/defer |
| Status matrix over-claims | Cross-check vs code | Correct matrix; re-verify |
| Packaging not reproducible | Clean-checkout build | Fix restore/build determinism |
| Warning debt regressed | Warning review | Triage; re-run phase 08 scope |

## 15. Testing requirements
Full `dotnet test` green; all listed filters green; invariant checks zero; clean-checkout restore+build succeeds on Windows.

## 16. Acceptance criteria
- All six builds + sln + full test suite green on Windows.
- Invariants zero; warnings triaged/acceptable.
- Status matrix accurate; no stub mislabeled Active.
- Reproducible packaging; checkpoint/ZIP names assigned.

## 17. Anti-false-positive policy
Re-verify the entire anti-FP contract end-to-end: ConfirmedMalware only from blacklisted hash / confirmed signature / curated confirmed YARA rule; heuristics clamp to High; real-YARA/behavioral/ETW/AMSI/update telemetry never confirm; auto-quarantine ConfirmedMalware-only.

## 18. Forbidden behavior
Declaring STABLE without green Windows build+test; shipping unapproved gated activations; hiding failures; over-claiming module states.

## 19. Packaging
Per release process (this spec does not itself create a ZIP). Record the final checkpoint name, suggested ZIP name, and Master Implementation Order title in the report.

## 20. Final report requirements
Report: build matrix results, test matrix results, invariant results, warning triage, module status matrix, packaging review, anti-FP re-verification, go/no-go verdict, and assigned checkpoint/ZIP names. Include a **Bugs noticed but not fixed** section.

## Rollback procedure
If go/no-go = no-go, revert/defer the offending phase(s); the checkpoint stays at the last green state. No release artifact is published until green.

## Stop conditions
Stop and report no-go if any build/test fails, invariants regress, the status matrix can't be made accurate, or packaging isn't reproducible.

## Approval requirements
Final release/tagging is **approval-gated**. Codex stabilization recommended before declaring STABLE.

## Known risks
Medium: aggregation can surface latent cross-phase issues. Mitigated by the matrices + bisect-to-phase discipline.

## Windows validation requirements
Mandatory and central: the entire premise is a green Windows build+test. Not validatable in a non-Windows/no-SDK environment.

## Codex stabilization recommendation
**Recommended.** Codex should perform a final pass on the matrices, warning triage, and anti-FP re-verification before sign-off.

## Expected outcome
A defensible, evidence-backed `DataVanger V.Alpha_STABLE` milestone with green build/test matrices, an honest status matrix, reproducible packaging, and a clear go/no-go record.

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
Plus filters: `--filter "FullyQualifiedName~AntiFalsePositive"`, `~Publisher`, `~Yara`, `~Quarantine`, `~Update`, `~Ipc`, `~Service`.

## 21. Claude Code Prompt
> You are implementing phase **22_FINAL_STABILIZATION** on branch `claude/fervent-dirac-0ml0N`. APPROVAL-GATED final gate. Run the full build matrix (six projects + sln) and test matrix (full suite + filters `~AntiFalsePositive`, `~Publisher`, `~Yara`, `~Quarantine`, `~Update`, `~Ipc`, `~Service`) on Windows; run the prior-phase invariant checks; triage warnings (incl. xUnit1031 post-08); verify the module status matrix matches code (no stub labeled Active); and confirm reproducible packaging from a clean checkout. Make only minimal, justified, tested fixes for genuine release blockers — no new features and no unapproved gated activations. Re-verify the full anti-FP contract end-to-end. Produce `outputs/22_FINAL_STABILIZATION_REPORT.md` with all matrices, warning triage, status matrix, packaging review, anti-FP re-verification, a go/no-go verdict, assigned final checkpoint name (`DataVanger V.Alpha_STABLE`), suggested ZIP name, and a "Bugs noticed but not fixed" section. Do NOT declare STABLE without a green Windows build+test. No ZIP creation in this step unless the release process calls for it. Commit and push. Recommend Codex final stabilization.
