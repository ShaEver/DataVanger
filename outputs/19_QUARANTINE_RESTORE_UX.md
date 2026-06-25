# 19_QUARANTINE_RESTORE_UX

## 1. Phase name
19_QUARANTINE_RESTORE_UX — Restore workflow, audit visibility, operator clarity.

## 2. Phase position
Low–medium risk UX phase over the already-implemented Quarantine V2. Windows/WPF validation.

## 3. Current stable checkpoint
`DataVanger V.Alpha_YARA_PUBLISHERS_STABLE`.

## 4. Objective
Improve the quarantine restore workflow, audit visibility, and operator clarity in `DataVanger/QuarantineWindow.xaml(.cs)`, layered over the existing `QuarantineService` (Engine) without changing its security logic. Preserve integrity (HMAC), hash, and path validation. No automatic restore.

## 5. Non-goals
- No changes to quarantine crypto, HMAC, key protection, or path policy logic.
- No automatic/silent restore.
- No new auto-actions; ConfirmedMalware-only auto-quarantine preserved.

## 6. Existing behavior to preserve
- `QuarantineService.RestoreAsync`: validates request/path, looks up record, verifies payload integrity (HMAC), decrypts, writes, verifies SHA-256 vs original, emits audit, returns detailed result.
- Automatic quarantine gate: only ConfirmedMalware (not heuristics) → returns PolicyDenied otherwise.
- `DpapiQuarantineKeyProtector` / `FileSystemQuarantineStore` / `QuarantineAuditSinks` unchanged.
- `Infrastructure/QuarantineServiceAdapter` API contract.

## 7. Core design principle
Operator-confirmed, integrity-verified, fully-audited restore. The UX makes the existing safety guarantees visible and requires explicit confirmation; it never weakens or bypasses them.

## 8. Recommended structure
- Restore flow: select record → show metadata (original path, hash, quarantine time, reason, integrity status) → explicit confirm → call `RestoreAsync` → show detailed result + audit entry.
- Surface audit history (from `QuarantineAuditSinks`) in the window.
- Clear failure messaging (integrity fail, path unsafe, hash mismatch) without exposing secrets.

## 9. Target files
- `DataVanger/QuarantineWindow.xaml`
- `DataVanger/QuarantineWindow.xaml.cs`
- `DataVanger/Infrastructure/QuarantineServiceAdapter.cs` (read/extend read-only views)
- (read-only) `DataVanger.Engine/Quarantine/*`, `DataVanger.Shared/Quarantine/*`
- Tests in `DataVanger.Tests/` (adapter/view-model level; restore happy/failure paths via service doubles)

## 10. Allowed scope
UX/workflow, audit display, confirmation prompts, result/error messaging, read-only metadata views, view-model tests.

## 11. Forbidden scope
Changing crypto/HMAC/hash/path validation; automatic restore; weakening the ConfirmedMalware auto-quarantine gate; exposing key material.

## 12. Migration / implementation strategy (implementation order)
1. Baseline build+test.
2. Add a restore-confirmation flow with metadata + integrity-status display.
3. Surface audit history (read-only).
4. Improve failure messaging mapped from `RestoreAsync` results.
5. View-model tests with `InMemoryQuarantineStore`/service doubles (restore success, integrity failure, path-unsafe, hash mismatch).
6. Build+test; manual WPF restore walkthrough on Windows.

## 13. Decision protocol
- Restore is always explicit operator action with confirmation.
- On integrity/hash/path failure → refuse restore, show reason, keep quarantined.
- Never auto-restore; never bypass verification.

## 14. Failure modes
| Failure mode | Detection method | Mitigation |
|---|---|---|
| Restore without confirmation | Flow review/test | Mandatory confirm step |
| Integrity fail silently restored | Service-double test | Honor `RestoreAsync` failure; refuse |
| Secret leakage in UI | Message review | Show status, not key/plaintext |
| Audit not shown | View test | Bind audit sink history |

## 15. Testing requirements
View-model/adapter tests over service doubles: success path; integrity-failure refusal; path-unsafe refusal; hash-mismatch refusal; audit entries surfaced. `--filter "FullyQualifiedName~Quarantine"`. Manual Windows WPF walkthrough.

## 16. Acceptance criteria
- Restore requires explicit confirmation and passes integrity/hash/path checks.
- Audit visible; failures clearly messaged; no secrets exposed.
- Auto-quarantine remains ConfirmedMalware-only; no auto-restore.
- Build+test green; invariants zero.

## 17. Anti-false-positive policy
Unchanged. Automatic quarantine stays gated on ConfirmedMalware; this phase only improves manual restore UX and visibility, never broadening automated action.

## 18. Forbidden behavior
Auto-restore; bypassing verification; weakening crypto/path checks; exposing keys/plaintext; widening auto-quarantine.

## 19. Packaging
No ZIP. Commit UI/adapter + tests + spec to the branch.

## 20. Final report requirements
Report: restore flow, audit surfacing, failure messaging map, view-model test results, manual Windows result (or "pending"), confirmation that security logic is untouched, build/test status, invariant results, **Bugs noticed but not fixed**.

## Rollback procedure
Revert the phase commit; `QuarantineWindow` returns to prior UX; service logic untouched throughout, so no data risk.

## Stop conditions
Stop if any change would touch crypto/HMAC/path logic, enable auto-restore, or cannot be validated.

## Approval requirements
None (Claude-only). UX over existing, already-approved security logic.

## Known risks
Low–medium: UI mistakes could mislead operators. Mitigated by mapping messages directly from `RestoreAsync` results + tests.

## Windows validation requirements
WPF restore walkthrough validates on Windows; view-model/adapter tests run in the `net8.0-windows` suite.

## Codex stabilization recommendation
Not required.

## Expected outcome
A clear, confirmation-driven, fully-audited restore experience that surfaces the existing integrity guarantees without altering any security logic.

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
> You are implementing phase **19_QUARANTINE_RESTORE_UX** on branch `claude/fervent-dirac-0ml0N`. UX ONLY over the existing Quarantine V2 — do NOT change crypto/HMAC/hash/path-validation logic in `DataVanger.Engine/Quarantine/*`. In `DataVanger/QuarantineWindow.xaml(.cs)` add a restore flow: select record → show metadata (original path, hash, time, reason, integrity status) → explicit confirmation → call `QuarantineService.RestoreAsync` → show detailed result. Surface read-only audit history from `QuarantineAuditSinks`; map failure messages (integrity/path/hash) without exposing secrets. Keep restore manual (never automatic) and the ConfirmedMalware-only auto-quarantine gate intact. Add `DataVanger.Tests` view-model/adapter tests over `InMemoryQuarantineStore`/service doubles (success, integrity-fail refusal, path-unsafe refusal, hash-mismatch refusal, audit surfaced). Re-run prior-phase invariant checks (all zero). Deliver a report with the restore flow, audit surfacing, message map, test results, and a "Bugs noticed but not fixed" section. No ZIP. Commit and push.
