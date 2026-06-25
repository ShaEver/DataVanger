# 11_PUBLISHER_IDENTITY_VALIDATION

## 1. Phase name
11_PUBLISHER_IDENTITY_VALIDATION — Certificate-aware trusted-publisher decisions.

## 2. Phase position
First security-hardening phase. High-risk. Windows validation required. Codex stabilization recommended.

## 3. Current stable checkpoint
`DataVanger V.Alpha_YARA_PUBLISHERS_STABLE`.

## 4. Objective
Strengthen publisher verification beyond today's case-insensitive **substring name match** (`ScanEngine.IsPublisherTrusted`, `ReputationEngine.IsTrustedPublisher`). Add opt-in identity normalization + certificate **chain validation** + **thumbprint/pin** matching, so a trusted decision reflects a verified signer — not just a spoofable subject string. A trusted publisher must **never** override confirmed-malicious evidence.

## 5. Non-goals
- Not removing the substring path (it remains as an explicit, weaker fallback for environments without chain data).
- Not adding network revocation (CRL/OCSP) unless explicitly opt-in and isolated (default off).
- Not changing scoring magnitudes for already-trusted signers beyond what's needed to gate on validity.

## 6. Existing behavior to preserve
- The Authenticode trust gate ordering in `ScanEngine` (lines ~404–430): trusted-publisher relief applies **only** when `!isKnownMalware && !hasConfirmedSignature && isSigned`.
- `ReputationEngine` precedence: known-bad/confirmed checked first; trusted-publisher branch gated on `!knownBad` and `score -= confirmed ? 0 : 12`.
- `AppSettings.TrustedPublishers` + `ExtraTrustedPublishers` semantics; phase-06 safe defaults.
- `DataVanger/Core/WinTrust.cs` signature-extraction behavior remains the source of signer info.

## 7. Core design principle
Defense-in-depth, opt-in, fail-safe-toward-suspicion. Identity tiers: (1) verified chain + pinned thumbprint = strongest; (2) verified chain + normalized subject match; (3) substring name match = weakest/legacy. Higher assurance never *reduces* safety; failure to verify never upgrades trust.

## 8. Recommended structure
- New `DataVanger/Core/PublisherIdentity.cs`: subject normalization, `X509Chain` build/validate, thumbprint compare.
- Extend `AppSettings` with optional `TrustedPublisherThumbprints` and a `PublisherValidationMode` (Substring | ChainAndName | ChainAndThumbprint), default conservative but backward-compatible (Substring) to avoid surprise regressions until validated on Windows.
- Route `IsPublisherTrusted` / `IsTrustedPublisher` through the new evaluator.

## 9. Target files
- `DataVanger/Core/WinTrust.cs`
- `DataVanger/Core/PublisherIdentity.cs` (new)
- `DataVanger/Core/ScanEngine.cs` (`IsPublisherTrusted`)
- `DataVanger/Reputation/ReputationEngine.cs` (`IsTrustedPublisher`)
- `DataVanger/Core/AppSettings.cs` (new optional config; coordinate with phase 10)
- Tests in `DataVanger.Tests/` (`PublisherIdentityTests.cs`)

## 10. Allowed scope
Publisher-trust evaluation path; optional config (thumbprints, mode); chain/thumbprint logic guarded for Windows; tests with synthetic certs.

## 11. Forbidden scope
Weakening the anti-FP gate; letting trusted-signer override known-bad/confirmed; enabling network revocation by default; changing unrelated scoring.

## 12. Migration / implementation strategy (implementation order)
1. Baseline build+test.
2. Add `PublisherIdentity` (normalization + chain + thumbprint), Windows-guarded; no call-site change yet.
3. Add config (mode + thumbprints) via phase-10 schema (version bump).
4. Route both call sites through the evaluator with `Substring` default (no behavior change yet).
5. Add tests (valid chain, broken chain, thumbprint match/mismatch, malicious-hash-overrides-trust).
6. Document enabling `ChainAndThumbprint` as a Windows-validated opt-in.

## 13. Decision protocol
- Confirmed-malicious/known-bad always wins over any trust tier.
- If chain validation is unavailable/throws → fall back to the configured weaker tier, never to "trusted".
- Pin/thumbprint mismatch → not trusted (even if name matches).
- Default mode stays backward-compatible until Windows validation proves the stronger modes don't regress known-good signed binaries.

## 14. Failure modes
| Failure mode | Detection method | Mitigation |
|---|---|---|
| Stronger mode flags legit signed app (FP) | Windows corpus regression | Default Substring; opt-in; corpus test before enabling |
| Chain build throws on some certs | Unit/integration tests | Guarded try/catch → weaker tier, never "trusted" |
| Thumbprint config typo | Mismatch ⇒ untrusted | Validate/normalize thumbprint input |
| Trusted overrides malware | Anti-FP test | Keep gate ordering; explicit test |

## 15. Testing requirements
Synthetic-cert tests for chain valid/invalid, thumbprint match/mismatch, normalization; regression test that a known-malicious hash signed by a "trusted" publisher stays ConfirmedMalware. `--filter "FullyQualifiedName~Publisher"`. Windows manual run against real signed/unsigned/tampered binaries.

## 16. Acceptance criteria
- Trusted decision requires the configured assurance tier; failures degrade safely.
- Malicious-hash precedence intact; anti-FP tests green.
- No new FPs on a known-good signed-binary corpus (Windows).
- Build+test green; invariants zero.

## 17. Anti-false-positive policy
This phase strengthens, not loosens, trust. A trusted signature must never raise/confirm a verdict; it only provides relief when the file is not known-bad/confirmed. Heuristic clamp to `High` remains.

## 18. Forbidden behavior
Auto-trusting any signer; network calls by default; overriding ConfirmedMalware; persisting private key material; trusting a signer on chain failure.

## 19. Packaging
No ZIP. Commit code + tests + spec to the branch.

## 20. Final report requirements
Report: identity tiers implemented, config added, call-site routing, test matrix/results, Windows corpus result (or "pending Windows validation"), explicit confirmation malware precedence preserved, build/test status, invariant results, **Bugs noticed but not fixed**.

## Rollback procedure
Revert the phase commit; with default `Substring` mode, behavior equals pre-phase even before rollback. Config additions are ignored by old code.

## Stop conditions
Stop and request approval before enabling any non-`Substring` default, before any network-revocation feature, or if a regression corpus shows new FPs.

## Approval requirements
**Approval-gated** to change the default validation mode or enable revocation. Implementation of the (off-by-default) machinery is Claude-allowed; **enabling** stronger modes needs explicit approval + Windows validation.

## Known risks
High: certificate validation is FP-prone and platform-specific; revocation introduces network surface. Mitigated by opt-in defaults, guarded code, and corpus testing.

## Windows validation requirements
Real `X509Chain`/Authenticode behavior is Windows-specific; the stronger modes can only be validated on Windows + .NET 8. Keep Null/weaker fallback for non-Windows builds.

## Codex stabilization recommendation
**Recommended.** Codex GPT-5.5 High should review chain policy flags, normalization edge cases, and FP risk before any default change.

## Expected outcome
A verifiable, opt-in publisher-identity system that hardens trust decisions without weakening the anti-FP contract, ready to enable after Windows corpus validation.

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
> You are implementing phase **11_PUBLISHER_IDENTITY_VALIDATION** on branch `claude/fervent-dirac-0ml0N`. Add a new `DataVanger/Core/PublisherIdentity.cs` providing subject normalization, Windows-guarded `X509Chain` validation, and thumbprint/pin comparison. Add opt-in config (`PublisherValidationMode` = Substring|ChainAndName|ChainAndThumbprint, plus `TrustedPublisherThumbprints`) via the phase-10 schema, defaulting to **Substring** (no behavior change yet). Route `ScanEngine.IsPublisherTrusted` and `ReputationEngine.IsTrustedPublisher` through the new evaluator, preserving the existing gate ordering so a trusted signer NEVER overrides known-bad/confirmed evidence and chain failure NEVER yields "trusted". Add `DataVanger.Tests/PublisherIdentityTests.cs` (valid/invalid chain, thumbprint match/mismatch, normalization, malicious-hash-overrides-trust). Do NOT enable a stronger default or any revocation/network feature without explicit approval + Windows corpus validation. Re-run prior-phase invariant checks (all zero). Deliver a report with tiers, config, test matrix, FP-corpus status (or "pending Windows"), and a "Bugs noticed but not fixed" section. No ZIP. Commit and push. Recommend Codex stabilization review.
