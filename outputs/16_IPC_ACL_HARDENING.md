# 16_IPC_ACL_HARDENING

## 1. Phase name
16_IPC_ACL_HARDENING — Named-pipe ACLs / security descriptors.

## 2. Phase position
Security-hardening phase; pairs with 15 (service). Medium–high risk. Approval-gated. Windows validation required.

## 3. Current stable checkpoint
`DataVanger V.Alpha_YARA_PUBLISHERS_STABLE`.

## 4. Objective
Harden IPC by restricting named-pipe access via ACLs / security descriptors, so only authorized local principals can connect to the (potentially privileged) service. Preserve local-only behavior; do not expose remote IPC. The transport already validates payloads via `IpcSecurityPolicy`; this phase adds connection-level access control.

## 5. Non-goals
- No remote/cross-machine IPC.
- No change to the command protocol/DTOs or the existing payload validation.
- No new transport.

## 6. Existing behavior to preserve
- `IpcSecurityPolicy` request allowlist, bounded message size, and safe-path rules.
- `NamedPipeFraming` size enforcement and `IpcSerialization` defensive deserialization.
- `NamedPipeDataVangerServiceHost` / `Client` round-trip semantics; `InMemory*` doubles for tests.
- Local-only operation (no network pipe).

## 7. Core design principle
Least-privilege connection access, defense-in-depth. ACLs gate *who can connect*; the existing policy gates *what they can ask*. Both must pass.

## 8. Recommended structure
- Build a `PipeSecurity` descriptor (allow the expected service/user SIDs, deny network sid) and pass it when creating the `NamedPipeServerStream`.
- Make the allowed-principal set configurable via `IpcOptions` (default = current user / SYSTEM as appropriate), Windows-guarded.
- Keep a guarded no-ACL fallback for non-Windows builds (tests use `InMemory*`).

## 9. Target files
- `DataVanger.Infrastructure/Ipc/NamedPipeDataVangerServiceHost.cs`
- `DataVanger.Infrastructure/Ipc/IpcSecurityPolicy.cs`
- `DataVanger.Infrastructure/Ipc/IpcOptions.cs`
- (read-only) `DataVanger.Infrastructure/Ipc/NamedPipeDataVangerServiceClient.cs`, framing/serialization
- Tests in `DataVanger.Tests/` (`IpcAclTests.cs` where testable; otherwise documented manual)

## 10. Allowed scope
Add `PipeSecurity`/ACL to the host; configurable principals; keep payload validation; tests for policy + (where feasible) unauthorized-connection rejection.

## 11. Forbidden scope
Loosening existing `IpcSecurityPolicy`; exposing remote pipes; removing payload validation; granting Everyone/Network access.

## 12. Migration / implementation strategy (implementation order)
1. Baseline build+test.
2. Add `PipeSecurity` to the host (Windows-guarded), default-restricting to the running principal + SYSTEM.
3. Make principals configurable via `IpcOptions`.
4. Keep all existing validation paths.
5. Add policy unit tests; document manual unauthorized-client rejection on Windows.
6. Build+test.

## 13. Decision protocol
- Default deny: only explicitly-allowed SIDs connect.
- If ACL APIs unavailable (non-Windows) → keep in-memory/test path; never silently open the pipe to all.
- Never weaken payload validation to compensate for ACL complexity.

## 14. Failure modes
| Failure mode | Detection method | Mitigation |
|---|---|---|
| Pipe open to any local user | Unauthorized-connect test (Windows) | Default-deny `PipeSecurity` |
| Legit client blocked | Round-trip test | Include correct principal SIDs |
| ACL APIs missing on build | `dotnet build` | Windows-guard; in-memory fallback for tests |
| Payload validation regressed | Existing IPC tests | Do not touch policy logic |

## 15. Testing requirements
Unit: `IpcSecurityPolicy` still enforces allowlist/size/path; host constructs with restricted ACL. Manual (Windows): authorized client connects; unauthorized principal is rejected. `--filter "FullyQualifiedName~Ipc"`.

## 16. Acceptance criteria
- Only authorized local principals connect; unauthorized rejected (Windows).
- Existing functional IPC tests still pass; payload validation intact.
- No remote exposure.
- Build+test green; invariants zero.

## 17. Anti-false-positive policy
IPC hardening does not touch detection. No verdict is produced by IPC; this phase cannot affect anti-FP behavior.

## 18. Forbidden behavior
Granting Everyone/Network; remote pipes; weakening payload checks; making IPC a verdict source.

## 19. Packaging
No ZIP. Commit host/options + tests + spec. Ensure non-Windows builds still succeed (guarded ACL).

## 20. Final report requirements
Report: ACL model + default principals, configurability, preserved validation, test results (incl. manual Windows rejection or "pending"), build/test status, invariant results, **Bugs noticed but not fixed**, safe-to-enable verdict.

## Rollback procedure
Revert the phase commit; host returns to its prior (no-ACL) construction. Because payload validation is unchanged, security posture only relaxes back to baseline.

## Stop conditions
Stop and request approval before deploying ACLs on a real privileged service host, or if an unauthorized-connection rejection cannot be demonstrated on Windows.

## Approval requirements
**Approval-gated** for deployment alongside a real service (phase 15). Implementation is Claude-allowed; rollout needs approval + Windows validation.

## Known risks
Medium–high: misconfigured ACLs can lock out legit clients or fail to restrict. Mitigated by default-deny + explicit principals + tests.

## Windows validation requirements
Mandatory for ACL enforcement (Windows security descriptors). In-memory tests run in the suite; real rejection requires Windows.

## Codex stabilization recommendation
**Recommended.** Codex should review the SID set, default-deny correctness, and Windows-guard fallback.

## Expected outcome
Named-pipe IPC restricted to authorized local principals with payload validation intact and no remote exposure.

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
> You are implementing phase **16_IPC_ACL_HARDENING** on branch `claude/fervent-dirac-0ml0N`. APPROVAL-GATED + WINDOWS validation. Add a default-deny `PipeSecurity`/security descriptor to `DataVanger.Infrastructure/Ipc/NamedPipeDataVangerServiceHost.cs` (Windows-guarded), restricting connections to explicitly-allowed local principals (current user / SYSTEM), configurable via `IpcOptions`. Preserve `IpcSecurityPolicy` payload validation, framing/size limits, and local-only operation — do NOT loosen any of it and do NOT expose remote pipes. Keep an in-memory/guarded fallback so non-Windows builds compile and tests run. Add `DataVanger.Tests/IpcAclTests.cs` for policy + host construction; document manual Windows unauthorized-connection rejection. Re-run prior-phase invariant checks (all zero). Deliver a report with the ACL model, configurability, preserved validation, test results, and a "Bugs noticed but not fixed" section + safe-to-enable verdict. No ZIP. Commit and push. Recommend Codex stabilization.
