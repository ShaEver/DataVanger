# 15_WINDOWS_SERVICE_INSTALLATION

## 1. Phase name
15_WINDOWS_SERVICE_INSTALLATION — Real Windows service lifecycle.

## 2. Phase position
OS-integration phase. High-risk. Approval-gated. Windows validation required. Pairs with 16 (IPC ACL hardening). Codex stabilization recommended.

## 3. Current stable checkpoint
`DataVanger V.Alpha_YARA_PUBLISHERS_STABLE`.

## 4. Objective
Convert the diagnostic stub in `DataVanger.Service/Program.cs` — which prints "`--service is a diagnostic stub in this phase; no Windows Service was installed.`" (line ~149) — into a real Windows service lifecycle: install, uninstall, start, stop, recovery, and graceful degradation, hosting the existing realtime-protection runtime.

## 5. Non-goals
- Not auto-installing on app launch.
- Not escalating privileges silently.
- Not expanding auto-quarantine beyond ConfirmedMalware.
- Not exposing remote control.

## 6. Existing behavior to preserve
- `DataVanger.Service` CLI modes (`--console`, `--status`, `--validate-config`, `--help`) keep working.
- `DataVangerServiceRuntime` state machine, `RealtimeProtectionService`, IPC command router, and `EtwRuntimeProviderHost` behavior unchanged in logic.
- Conservative realtime decision engine: authorizes auto-action **only** for ConfirmedMalware and only when non-passive.
- Graceful degradation when components are unavailable.

## 7. Core design principle
Explicit, reversible, least-privilege service hosting. Installation is an operator action (not implicit), the service degrades gracefully, and it never widens automatic actions.

## 8. Recommended structure
- Use `Microsoft.Extensions.Hosting.WindowsServices` (or equivalent) to host `DataVangerServiceRuntime` as a `BackgroundService`.
- Add `--install` / `--uninstall` (via `sc`/service controller) and configure recovery (restart-on-failure).
- Keep `--service` as the run-as-service entry; map lifecycle events to runtime start/stop.

## 9. Target files
- `DataVanger.Service/Program.cs`
- `DataVanger.Service/Runtime/DataVangerServiceRuntime.cs`
- `DataVanger.Service/DataVanger.Service.csproj` (hosting package, if needed — Windows-validated)
- (read-only) realtime + IPC host wiring
- Tests in `DataVanger.Tests/` (lifecycle/runtime tests that don't require an installed service)

## 10. Allowed scope
Service host + install/uninstall/start/stop/recovery + graceful degradation + non-install lifecycle tests + docs.

## 11. Forbidden scope
Auto-install/auto-start on app run; silent privilege escalation; remote management; auto-quarantine expansion; making service telemetry a verdict.

## 12. Migration / implementation strategy (implementation order)
1. Baseline build+test.
2. Add Windows-service hosting around `DataVangerServiceRuntime`; preserve all CLI modes.
3. Implement `--install`/`--uninstall` + recovery config (operator-invoked, admin required).
4. Map service start/stop to runtime start/stop; ensure graceful shutdown.
5. Add runtime-lifecycle unit tests (start→ready→stop) using fakes; manual install/uninstall on a Windows VM.
6. Build+test; document operator install steps.

## 13. Decision protocol
- Installation/uninstallation only on explicit operator command with admin rights; never implicit.
- If hosting APIs unavailable (non-Windows) → degrade to console mode, no crash.
- Service failure → recovery restart; never silently widen actions.

## 14. Failure modes
| Failure mode | Detection method | Mitigation |
|---|---|---|
| Service won't start/stop cleanly | Windows VM test | Map lifecycle to runtime; graceful shutdown |
| Auto-install side effects | Install-flow review | Operator-only, admin-gated |
| Privilege misuse | Security review | Least privilege; documented account |
| Crash loop | Recovery config | Restart policy + backoff; logs |
| Non-Windows build breaks | `dotnet build` on CI | Guard Windows-only host; console fallback |

## 15. Testing requirements
Unit: runtime start/ready/stop with fakes; CLI modes still work. Manual (Windows VM): install→start→`--status`→stop→uninstall→recovery-on-kill. `--filter "FullyQualifiedName~Service"` / `~Realtime`.

## 16. Acceptance criteria
- Installs/uninstalls/starts/stops cleanly; recovers from failure; survives reboot.
- CLI modes intact; graceful degradation when components missing.
- No new automatic actions beyond ConfirmedMalware.
- Build+test green; invariants zero.

## 17. Anti-false-positive policy
Running as a service must not change detection or widen auto-quarantine. The conservative realtime decision engine's ConfirmedMalware-only authorization is preserved.

## 18. Forbidden behavior
Implicit install/start; privilege escalation without consent; remote exposure; auto-quarantine beyond ConfirmedMalware; verdicts from service/runtime telemetry alone.

## 19. Packaging
No ZIP from this spec. Define operator install artifacts/steps (e.g. an install script invoking `--install`). Ensure non-Windows builds still succeed (guarded host).

## 20. Final report requirements
Report: hosting approach, lifecycle commands, recovery config, graceful-degradation behavior, Windows VM validation results (or "pending"), confirmation of no auto-action widening, build/test status, invariant results, **Bugs noticed but not fixed**, safe-to-enable verdict.

## Rollback procedure
`--uninstall` removes the service; revert the phase commit to restore the diagnostic stub. No persistent state beyond the service registration is created.

## Stop conditions
Stop and request approval before registering a real service on any machine, before any auto-start, or if clean stop/uninstall cannot be achieved.

## Approval requirements
**Approval-gated.** Service registration, auto-start, and recovery policy require explicit approval + Windows validation.

## Known risks
High: privilege, persistence, system stability. Mitigated by operator-only install, least privilege, recovery + graceful degradation, console fallback.

## Windows validation requirements
Mandatory. Service install/lifecycle/recovery is Windows-only and must be validated on a Windows VM with admin rights.

## Codex stabilization recommendation
**Recommended.** Codex should review lifecycle/recovery, privilege model, and shutdown/cancellation correctness.

## Expected outcome
DataVanger can run as a real, operator-installed Windows service with clean lifecycle and recovery, without changing detection behavior or widening automatic actions.

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
> You are implementing phase **15_WINDOWS_SERVICE_INSTALLATION** on branch `claude/fervent-dirac-0ml0N`. APPROVAL-GATED + WINDOWS-ONLY validation. Replace the `--service` diagnostic stub in `DataVanger.Service/Program.cs` (line ~149) with a real Windows-service host (e.g. `Microsoft.Extensions.Hosting.WindowsServices`) around `DataVangerServiceRuntime`, preserving all existing CLI modes (`--console`/`--status`/`--validate-config`/`--help`). Add operator-only, admin-gated `--install`/`--uninstall` and restart-on-failure recovery; map service start/stop to runtime start/stop with graceful shutdown. Never auto-install/auto-start; never widen auto-quarantine beyond ConfirmedMalware; keep a console fallback so non-Windows builds still compile. Add runtime-lifecycle unit tests with fakes; document manual Windows-VM validation (install→start→status→stop→uninstall→recovery). Re-run prior-phase invariant checks (all zero). Deliver a report with hosting approach, lifecycle/recovery, degradation behavior, Windows validation status, and a "Bugs noticed but not fixed" section + safe-to-enable verdict. No ZIP. Commit and push. Recommend Codex stabilization.
