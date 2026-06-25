# 14_SIGNED_UPDATE_HTTP_TRANSPORT

## 1. Phase name
14_SIGNED_UPDATE_HTTP_TRANSPORT — Production opt-in HTTP transport for signed updates.

## 2. Phase position
Network-activation phase. High-risk. Approval-gated. Codex stabilization recommended.

## 3. Current stable checkpoint
`DataVanger V.Alpha_YARA_PUBLISHERS_STABLE`.

## 4. Objective
Convert the signed-update HTTP transport from its current stub — `DataVanger.Engine/Updates/SignedUpdates/HttpUpdateTransport.cs`, whose methods throw `NotSupportedException("HTTP transport is not implemented in this phase.")` — into a production-ready, **opt-in**, isolated transport. Mandatory signature validation, mandatory rollback (anti-downgrade) support, mandatory size limits, mandatory timeout behavior. No unsigned updates ever applied.

## 5. Non-goals
- Not enabling updates by default.
- Not changing the already-implemented signature/manifest verification or state store.
- Not introducing auto-apply without verification.
- Not making update telemetry a malware verdict.

## 6. Existing behavior to preserve
- `SignedUpdateService` orchestration: validates requests, enforces anti-downgrade via sequence numbers, verifies manifest signature (RSA-PSS-SHA256 / ECDsa-P256-SHA256) and package contents, persists state; **disabled mode returns `Disabled` early**.
- `SignedManifestVerifier` / `UpdatePackageVerifier` / `UpdateCanonicalPayloadBuilder` logic unchanged.
- `FileUpdateTransport` / `InMemoryUpdateTransport` remain for tests.
- `IUpdateTransport` contract unchanged.
- `ModuleStatusAggregator` honestly reports update status.

## 7. Core design principle
Verify-before-trust, opt-in, fail-closed. The transport only fetches bytes; all trust decisions stay in the verifier. Disabled by default; any fetch is bounded (size/timeout) and every artifact is signature- and anti-downgrade-checked before use.

## 8. Recommended structure
- Implement `HttpUpdateTransport` against `IUpdateTransport` using a bounded `HttpClient` (timeout, max response size, TLS, no redirects to other hosts).
- Gate activation behind explicit config (feed URL + enable flag) via phase-10 schema; default disabled.
- Surface enabled/disabled + last-result via `ModuleStatusAggregator` and `Ipc/UpdateCommandHandler`.

## 9. Target files
- `DataVanger.Engine/Updates/SignedUpdates/HttpUpdateTransport.cs`
- `DataVanger.Engine/Updates/SignedUpdates/SignedUpdateService.cs` (wiring/opt-in)
- `DataVanger.Engine/Status/ModuleStatusAggregator.cs`
- `DataVanger.Service/Ipc/UpdateCommandHandler.cs`
- `DataVanger/Core/AppSettings.cs` (feed config; via phase 10)
- Tests in `DataVanger.Tests/` (`SignedUpdateHttpTransportTests.cs`)

## 10. Allowed scope
HTTP fetch with bounds; opt-in config; status surfacing; tests (loopback/mock handler, tamper/downgrade negatives). Signature verification remains mandatory and upstream.

## 11. Forbidden scope
Enabling by default; applying unsigned/unverified updates; bypassing anti-downgrade; unbounded download; following cross-host redirects; making update telemetry a verdict; auto-apply without verification.

## 12. Migration / implementation strategy (implementation order)
1. Baseline build+test (existing stub test asserts `NotSupportedException`; update it to cover enabled+disabled).
2. Implement bounded HTTP fetch behind the `IUpdateTransport` contract.
3. Wire opt-in config; default disabled (service still returns `Disabled`).
4. Keep verification mandatory: fetched manifest/package go through existing verifiers; reject on any failure.
5. Add tests: disabled→no I/O; enabled+valid signed manifest→accept; tampered→reject; downgrade→reject; oversized→reject; timeout→fail-closed.
6. Build+test; document enablement.

## 13. Decision protocol
- No signature/anti-downgrade pass ⇒ reject and keep last-known-good.
- Any network/timeout/size failure ⇒ fail-closed, no state change.
- Default remains disabled until explicitly approved + configured.

## 14. Failure modes
| Failure mode | Detection method | Mitigation |
|---|---|---|
| Unsigned/tampered update applied | Tamper test | Mandatory verify before use; reject |
| Downgrade attack | Downgrade test | Sequence-number anti-downgrade (existing) |
| Unbounded/slow download (DoS) | Size/timeout tests | Max-size + timeout, fail-closed |
| SSRF/redirect abuse | Redirect test | Disable cross-host redirects; pin host |
| Update treated as verdict | Classification test | Telemetry-only; never confirms malware |

## 15. Testing requirements
Mock `HttpMessageHandler`/loopback: disabled (no I/O), valid signed accept, tampered reject, downgrade reject, oversized reject, timeout fail-closed, last-known-good preserved on failure. `--filter "FullyQualifiedName~Update"`.

## 16. Acceptance criteria
- Stub no longer throws when enabled; disabled by default with no I/O.
- Only signature-valid, non-downgrade, size/timeout-bounded manifests accepted.
- Failures degrade safely; state preserved.
- Build+test green; invariants zero.

## 17. Anti-false-positive policy
Updates are telemetry-only and never produce or influence a malware verdict. Rule/signature data delivered via updates does not change confirmation semantics defined elsewhere.

## 18. Forbidden behavior
Applying unsigned updates; auto-enable; bypassing verification/anti-downgrade; unbounded fetch; cross-host redirect; cloud/telemetry exfiltration.

## 19. Packaging
No ZIP. Commit transport + tests + spec to the branch. Document feed config + enablement steps.

## 20. Final report requirements
Report: transport bounds (size/timeout/TLS/redirect policy), opt-in config, verification-mandatory confirmation, test matrix/results, status surfacing, build/test status (Windows note), invariant results, **Bugs noticed but not fixed**, "safe to enable / not safe to enable" verdict.

## Rollback procedure
Revert the phase commit; `HttpUpdateTransport` returns to the throwing stub; service stays in `Disabled`/file-transport mode. No persisted update applied without verification, so no recovery needed.

## Stop conditions
Stop and request approval before enabling by default, before any auto-apply, or if a tamper/downgrade test cannot be made to reject.

## Approval requirements
**Approval-gated.** Implementation may proceed; **enabling** the transport (and any default feed) requires explicit approval. The supply-chain surface demands review.

## Known risks
High: network + supply-chain. Mitigated by fail-closed defaults, mandatory verification, bounded I/O, and negative tests.

## Windows validation requirements
Integration validated on Windows + .NET 8; unit tests (mock handler) are cross-platform but the suite targets `net8.0-windows`.

## Codex stabilization recommendation
**Recommended.** Codex should review TLS/redirect/timeout/size handling and the fail-closed paths.

## Expected outcome
A production-grade, opt-in, verify-before-trust HTTP update transport that is disabled by default and never applies an unsigned or downgraded update.

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
> You are implementing phase **14_SIGNED_UPDATE_HTTP_TRANSPORT** on branch `claude/fervent-dirac-0ml0N`. APPROVAL-GATED. Implement `DataVanger.Engine/Updates/SignedUpdates/HttpUpdateTransport.cs` (currently throws `NotSupportedException`) as a bounded, opt-in `IUpdateTransport`: timeout, max-response-size, TLS, no cross-host redirects. Keep ALL trust in the existing verifiers — fetched manifests/packages must pass `SignedManifestVerifier` + anti-downgrade before use; reject on any failure and preserve last-known-good. Default DISABLED (service returns `Disabled`, no I/O). Wire opt-in feed config via the phase-10 schema and surface status via `ModuleStatusAggregator` + `Ipc/UpdateCommandHandler`. Update the existing stub test and add `DataVanger.Tests/SignedUpdateHttpTransportTests.cs` (disabled-no-IO, valid-accept, tampered-reject, downgrade-reject, oversized-reject, timeout-fail-closed). Do NOT enable by default or auto-apply without verification. Re-run prior-phase invariant checks (all zero). Deliver a report with bounds, opt-in config, verification confirmation, test matrix, and a "Bugs noticed but not fixed" section, ending with a safe-to-enable verdict. No ZIP. Commit and push. Recommend Codex stabilization.
