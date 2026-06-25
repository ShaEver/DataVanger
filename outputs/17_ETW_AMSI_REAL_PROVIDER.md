# 17_ETW_AMSI_REAL_PROVIDER

## 1. Phase name
17_ETW_AMSI_REAL_PROVIDER — Activate real ETW and AMSI runtime providers.

## 2. Phase position
Runtime-telemetry activation phase; depends on 15 (service host). High-risk. Approval-gated. Windows validation required. Codex stabilization recommended.

## 3. Current stable checkpoint
`DataVanger V.Alpha_YARA_PUBLISHERS_STABLE`.

## 4. Objective
Activate the real ETW and AMSI providers, which are currently stubs: `DataVanger/Behavioral/Adapters/EtwBehaviorProvider.cs` (`IsAvailable => false; // No real ETW session`) and `DataVanger/Behavioral/Adapters/AmsiBehaviorAdapter.cs` (`IsAvailable => false`). Wire the real `DataVanger.Infrastructure/Etw/WindowsEtwRuntimeProvider.cs` (TraceEvent already referenced) into behavioral correlation. Preserve `Null` and `InMemory` provider fallbacks. ETW/AMSI alone must never confirm malware.

## 5. Non-goals
- Not removing Null/InMemory fallbacks.
- Not letting behavioral/runtime signal alone confirm malware (clamp stays).
- Not unbounded capture; not making non-Windows builds depend on ETW.

## 6. Existing behavior to preserve
- `Infrastructure/Etw` provider factory selects `Windows` / `Null` / `InMemory`; non-Windows ⇒ Null.
- `BehavioralCorrelationEngine` clamps behavioral findings to `RiskThresholds.High` (heuristic-only).
- `EtwRuntimeEventMapper` / `EtwCommandLineSanitizer` behavior unchanged.
- `EtwRuntimeProviderHost` lifecycle in the service.

## 7. Core design principle
Bounded, privilege-gated, telemetry-only activation with guaranteed fallback. Real providers feed correlation as *heuristic* signal; when unavailable or unprivileged, providers degrade to Null/InMemory without crashing.

## 8. Recommended structure
- Flip the adapters from stub to real by delegating to the existing `WindowsEtwRuntimeProvider` (ETW) and a real AMSI scan submission path, both `IsAvailable`-gated on OS + privilege.
- Bound subscriptions (providers list, buffer/timeout, event caps).
- Keep factory fallback to Null/InMemory.

## 9. Target files
- `DataVanger/Behavioral/Adapters/EtwBehaviorProvider.cs`
- `DataVanger/Behavioral/Adapters/AmsiBehaviorAdapter.cs`
- `DataVanger.Infrastructure/Etw/WindowsEtwRuntimeProvider.cs` (wire-in; read/extend)
- `DataVanger.Service/Runtime/EtwRuntimeProviderHost.cs`
- (read-only) `BehavioralCorrelationEngine`, `EtwRuntimeEventMapper`
- Tests in `DataVanger.Tests/` (`EtwAmsiProviderTests.cs` with fakes; Windows manual for real)

## 10. Allowed scope
Activate providers behind availability/privilege gates; bounded capture; AMSI content submission to existing analyzers; tests; status surfacing. Keep fallbacks.

## 11. Forbidden scope
Behavioral/ETW/AMSI alone confirming malware; unbounded capture; removing Null/InMemory fallback; hard non-Windows dependency; exfiltrating captured content.

## 12. Migration / implementation strategy (implementation order)
1. Baseline build+test.
2. Wire ETW adapter to `WindowsEtwRuntimeProvider` behind `IsAvailable` (OS + admin); bound subscription.
3. Wire AMSI adapter to submit content to `CommandLineAnalyzer`/existing path behind `IsAvailable`.
4. Ensure factory falls back to Null/InMemory when unavailable.
5. Tests with fake providers (event mapping, clamp preserved); document Windows manual capture.
6. Build+test.

## 13. Decision protocol
- If providers can't start (no privilege/OS) → Null/InMemory, no crash, status reports "unavailable".
- Behavioral/runtime evidence stays clamped to `High`; never `Confirmed`.
- Bound everything (events, time, buffers) to protect stability/perf.

## 14. Failure modes
| Failure mode | Detection method | Mitigation |
|---|---|---|
| ETW needs admin / unavailable | Provider `IsAvailable` | Null/InMemory fallback; status note |
| Unbounded event flood (perf/DoS) | Load test on Windows | Caps + drop policy |
| Behavioral signal confirms malware | Clamp test | Keep `High` clamp; never `Confirmed` |
| Captured content leaks | Sanitizer review | `EtwCommandLineSanitizer`; no exfiltration |
| Non-Windows build breaks | CI build | OS guards; Null provider |

## 15. Testing requirements
Fake-provider tests: events map to behavioral evidence; behavioral findings remain clamped (never confirm); fallback selection when unavailable. Manual Windows: real ETW session bounded; AMSI submission path. `--filter "FullyQualifiedName~Etw"` / `~Behavioral`.

## 16. Acceptance criteria
- Real providers activate when available+privileged; Null/InMemory otherwise.
- Behavioral/ETW/AMSI never confirm malware alone (clamp intact).
- Capture bounded; no perf collapse.
- Build+test green; invariants zero.

## 17. Anti-false-positive policy
Runtime telemetry is heuristic-only and clamped to `High`; it contributes evidence but never produces ConfirmedMalware by itself. Confirmation remains hash/curated-rule/confirmed-signature only.

## 18. Forbidden behavior
Confirming malware from runtime signal; unbounded capture; removing fallback; content exfiltration; non-Windows hard dependency.

## 19. Packaging
No ZIP. Commit adapters/host + tests + spec. Document privilege requirements + provider fallback matrix.

## 20. Final report requirements
Report: providers activated, gating (OS/privilege), bounds, fallback behavior, clamp-preservation proof, Windows manual results (or "pending"), build/test status, invariant results, **Bugs noticed but not fixed**, safe-to-enable verdict.

## Rollback procedure
Revert the phase commit; adapters return to stub (`IsAvailable=false`); correlation runs on Null/InMemory exactly as today.

## Stop conditions
Stop and request approval before enabling real ETW/AMSI on any machine, or if the clamp/non-confirmation guarantee cannot be demonstrated.

## Approval requirements
**Approval-gated.** Real provider activation needs explicit approval + Windows (admin) validation.

## Known risks
High: privilege, performance, stability, content sensitivity. Mitigated by gates, bounds, sanitizer, fallback, clamp.

## Windows validation requirements
Mandatory. ETW/AMSI are Windows/admin features; only validatable on Windows. Keep Null fallback for all other contexts.

## Codex stabilization recommendation
**Recommended.** Codex should review ETW session bounds, AMSI submission safety, and the non-confirmation guarantee.

## Expected outcome
Real runtime behavioral telemetry feeding correlation as bounded, heuristic-only signal, with guaranteed fallback and an intact anti-FP clamp.

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
> You are implementing phase **17_ETW_AMSI_REAL_PROVIDER** on branch `claude/fervent-dirac-0ml0N`. APPROVAL-GATED + WINDOWS (admin) validation; depends on phase 15. Flip `DataVanger/Behavioral/Adapters/EtwBehaviorProvider.cs` and `AmsiBehaviorAdapter.cs` from stub (`IsAvailable=false`) to real, delegating ETW to `DataVanger.Infrastructure/Etw/WindowsEtwRuntimeProvider.cs` and AMSI to the existing content-analysis path, each gated on OS + privilege and with bounded capture (provider list, buffers, event caps, timeout). Keep the provider factory's Null/InMemory fallback so non-Windows/unprivileged contexts degrade without crashing. Preserve the behavioral clamp to `RiskThresholds.High` — ETW/AMSI/behavioral signal must NEVER confirm malware alone. Add `DataVanger.Tests/EtwAmsiProviderTests.cs` with fakes (event mapping, clamp preserved, fallback selection); document manual Windows capture. Re-run prior-phase invariant checks (all zero). Deliver a report with activation gating, bounds, fallback, clamp proof, and a "Bugs noticed but not fixed" section + safe-to-enable verdict. No ZIP. Commit and push. Recommend Codex stabilization.
