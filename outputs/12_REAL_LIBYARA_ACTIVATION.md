# 12_REAL_LIBYARA_ACTIVATION

## 1. Phase name
12_REAL_LIBYARA_ACTIVATION — Activate the prepared real-YARA backend.

## 2. Phase position
First "native activation" phase. High-risk. Approval-gated. Windows validation required. Codex stabilization recommended.

## 3. Current stable checkpoint
`DataVanger V.Alpha_YARA_PUBLISHERS_STABLE`.

## 4. Objective
Activate the real libyara backend that is already prepared in `DataVanger/Infrastructure/LibyaraEngine.cs` behind `#if YARA_REAL`. Add the dnYara `PackageReference` + the `YARA_REAL` define **only after** verifying restore/build/native-load and rule compilation on Windows. The `LightweightYaraDatabase` + `YaraEngineAdapter` fallback must remain guaranteed. A real YARA match alone must never confirm malware.

## 5. Non-goals
- Not removing or weakening the lightweight fallback.
- Not changing `IYaraEngine` contract.
- Not downloading rules (see phase 13).
- Not letting real matches set `Confirmed`/`CanConfirmMalware`.

## 6. Existing behavior to preserve
- `EngineComposition.BuildDefault` always builds `new YaraEngineAdapter(yaraDb)` and uses it unless a real engine with `RuleCount > 0` is created.
- `LibyaraEngine.TryCreate` returns `null` when the backend is unavailable → fallback.
- `LibyaraEngine` emits every real match with `Confirmed=false, Score=0`.
- `YaraDetectionModule` mapping (`CanConfirmMalware = hit.Confirmed`) unchanged → real matches map to `High`, never `Confirmed`.
- The csproj currently has **no active** dnYara reference (only a commented enablement note).

## 7. Core design principle
Validated, reversible activation with guaranteed fallback. Nothing ships unless `dotnet restore` + `build` + a rule-compile smoke test pass on Windows; if the native lib is absent at runtime, the app silently uses the lightweight engine.

## 8. Recommended structure
- In `DataVanger/DataVanger.csproj`: add `<DefineConstants>$(DefineConstants);YARA_REAL</DefineConstants>` and the verified `<PackageReference Include="dnYara" Version="..."/>` (version pinned to one that restores+builds on Windows).
- Reconcile the `#if YARA_REAL` block in `LibyaraEngine.cs` with the actual dnYara API surface (compiler, scanner, result→match mapping).
- Keep `EngineComposition` selection logic unchanged.

## 9. Target files
- `DataVanger/DataVanger.csproj`
- `DataVanger/Infrastructure/LibyaraEngine.cs`
- `DataVanger/Engine/EngineComposition.cs` (verify only)
- `DataVanger/Detection/YaraDetectionModule.cs` (verify only)
- Tests in `DataVanger.Tests/` (`YaraEngineFallbackTests.cs` + new real-path tests guarded for Windows)

## 10. Allowed scope
Package add + `YARA_REAL` define + reconciling guarded code to the real API + rule-compile tests + docs. Mapping real matches to `LightweightYaraMatch` with truncation and `Confirmed=false`.

## 11. Forbidden scope
Removing the fallback; committing a package that fails to restore/build; allowing real matches to confirm; enabling rule downloads; leaving a broken/dangling `PackageReference`.

## 12. Migration / implementation strategy (implementation order)
1. On Windows: prototype dnYara restore+build in isolation; confirm native load + compile a trivial rule.
2. Add package + define; reconcile `#if YARA_REAL` code to the real API.
3. Build all projects + sln; run the YARA fallback tests (must still pass with fallback) and new real-path tests.
4. Verify: with rules present and real backend available, engine selects real; with backend unavailable, falls back; matches never confirm.
5. Document enablement + the validated package version.

## 13. Decision protocol
- If restore/build/native-load fails on Windows → **do not commit the package**; keep `#if YARA_REAL` dormant; report blocker.
- If real-path API differs from the guarded code → fix the guarded code; never weaken the fallback to compensate.
- Fallback guarantee is non-negotiable.

## 14. Failure modes
| Failure mode | Detection method | Mitigation |
|---|---|---|
| dnYara won't restore/build | `dotnet restore`/`build` errors | Abort activation; keep dormant; report |
| Native `libyara` DLL missing at runtime | `TryCreate` catches `DllNotFound`/`BadImageFormat` → null | Guaranteed fallback to lightweight |
| Real match marked confirmed | YaraDetectionModule/contract test | Force `Confirmed=false, Score=0` in LibyaraEngine |
| Rule compile throws on one file | per-file try/catch | Skip bad rule, continue, log |
| Broken package reference left | sln build fails | Do not commit unless all 6 builds pass |

## 15. Testing requirements
`YaraEngineFallbackTests` still green (fallback path). New Windows-guarded tests: real engine compiles a sample rule, scans a benign file, and the produced evidence is non-confirming. `--filter "FullyQualifiedName~Yara"`.

## 16. Acceptance criteria
- All six project builds + sln + tests green **on Windows** with the package added.
- Real engine activates only when available; lightweight fallback otherwise.
- Real matches never confirm malware.
- No dangling/broken package reference; restore clean.
- Invariants zero.

## 17. Anti-false-positive policy
Real external YARA is additive, non-confirming evidence (`High` strength, `Score=0`). Confirmation stays exclusive to curated lightweight `confirmed` rules and known-malicious hashes. Heuristic clamp unaffected.

## 18. Forbidden behavior
Confirming malware from a real match; default-enabling without Windows validation; removing fallback; auto-fetching rules; shipping an unrestorable package.

## 19. Packaging
No ZIP from this spec. The activation itself changes build config; ensure the solution restores on a clean Windows checkout. Record the pinned dnYara version.

## 20. Final report requirements
Report: Windows restore/build result (the gating evidence), dnYara version pinned, API reconciliation notes, fallback verification, non-confirmation verification, test results, invariant results, **Bugs noticed but not fixed**, and an explicit "safe to enable / not safe to enable" verdict.

## Rollback procedure
Remove the `PackageReference` and the `YARA_REAL` define (revert csproj); `LibyaraEngine` returns to dormant; fallback engine resumes. No data/runtime migration needed.

## Stop conditions
Stop immediately if any of the eight baseline builds fail, restore fails, the native library can't be validated, or a real match can confirm malware.

## Approval requirements
**Approval-gated.** Do not add the package or enable `YARA_REAL` without explicit approval AND a green Windows restore/build/test.

## Known risks
High: native interop, platform/runtime variance, supply-chain (new package). Mitigated by isolation prototype, pinned version, guaranteed fallback, reversible config.

## Windows validation requirements
Mandatory. dnYara + native libyara are Windows/.NET runtime concerns; cannot be validated in this Linux/no-SDK environment.

## Codex stabilization recommendation
**Recommended.** Codex should reconcile the dnYara API specifics and verify native error handling/disposal.

## Expected outcome
A validated, optional real-YARA engine that augments detection while the lightweight engine remains a guaranteed, always-valid fallback and confirmation semantics stay intact.

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
Plus (real path): `dotnet restore` and `dotnet build DataVanger/DataVanger.csproj -p:DefineConstants=YARA_REAL`.

## 21. Claude Code Prompt
> You are implementing phase **12_REAL_LIBYARA_ACTIVATION** on branch `claude/fervent-dirac-0ml0N`. APPROVAL-GATED + WINDOWS-ONLY validation. First, on Windows, verify dnYara restores+builds and the native libyara loads and compiles a trivial rule. Only then add a pinned `<PackageReference Include="dnYara" .../>` and `<DefineConstants>$(DefineConstants);YARA_REAL</DefineConstants>` to `DataVanger/DataVanger.csproj`, and reconcile the `#if YARA_REAL` block in `DataVanger/Infrastructure/LibyaraEngine.cs` to the real API. Keep `EngineComposition`'s guaranteed `YaraEngineAdapter` fallback and force every real match to `Confirmed=false, Score=0`. Run all eight baseline builds/tests on Windows; add Windows-guarded real-path tests proving activation, fallback, and non-confirmation. If restore/build/native-load fails, DO NOT commit the package — keep the code dormant and report the blocker. Re-run prior-phase invariant checks (all zero). Deliver a report with the Windows restore/build evidence, pinned version, fallback + non-confirmation verification, and a "Bugs noticed but not fixed" section, ending with a "safe to enable / not safe to enable" verdict. No ZIP. Commit and push. Recommend Codex stabilization.
