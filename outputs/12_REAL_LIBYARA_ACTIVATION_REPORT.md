# 12_REAL_LIBYARA_ACTIVATION — Activation Report

Phase: `12_REAL_LIBYARA_ACTIVATION` (activate the prepared real-YARA backend)
Baseline: `DataVanger V.Alpha_ETW_AMSI_REAL_PROVIDER_STABLE` (Phase 17 preserved; ETW/AMSI untouched)
Environment: Linux container, **no .NET SDK** (`dotnet` not installed)

## Summary

No code or build configuration was changed. The phase is **approval-gated** and
**Windows-validation-required**, and this environment has no .NET SDK and is not
Windows, so the gating proofs the spec requires (clean `dotnet restore`, all
project builds, native libyara load, trivial-rule compilation, real scan) **cannot
be produced here**. A read-only audit plus an offline dnYara API/package probe also
surfaced two real gaps that would block a naive activation even on Windows. The
repository is already in the spec's acceptable "Safe Dormant Fallback" state, so it
was left there unchanged rather than pushed into a forbidden half-enabled state.

## Repository Reality Findings

Repository reality was verified against the spec's assumptions before any change.

1. `DataVanger/DataVanger.csproj` — the `<DefineConstants>...;YARA_REAL</DefineConstants>`
   (line 36) and `<PackageReference Include="dnYara" Version="2.1.0" />` (line 39) are
   **inside an XML comment block** (lines 29–45). They are an enablement *note*, not
   active. **dnYara is not referenced; `YARA_REAL` is not defined.** Matches the spec.
2. No `Directory.Build.props` / `Directory.Build.targets`; the commented line 36 is the
   only `YARA_REAL`/`DefineConstants` occurrence in the whole repo. `YARA_REAL` is
   inactive solution-wide.
3. `DataVanger.Tests/DataVanger.Tests.csproj` does **not** reference dnYara. No dangling
   or broken package reference exists anywhere.
4. `DataVanger/Infrastructure/LibyaraEngine.cs` — the `#if YARA_REAL` block is present
   and structurally sound. `TryCreate` returns `null` (so callers fall back) when the
   backend is not compiled in, the native lib cannot load
   (`DllNotFoundException`/`BadImageFormatException`/`TypeLoadException`/`FileLoadException`/
   `NotSupportedException`/`InvalidOperationException` are caught), the rules directory is
   missing, or zero rules compile. Per-file rule errors are isolated; `Dispose` releases
   `_rules` and `_scanner`. Every real match is emitted with `Confirmed=false, Score=0`.
5. `IYaraEngine` contract — minimal (`int RuleCount`, `IReadOnlyList<LightweightYaraMatch> Scan(...)`).
   The real `LibyaraEngine` and the `YaraEngineAdapter` fallback both implement it; no
   contract change is needed to activate.
6. `LightweightYaraDatabase` / `YaraEngineAdapter` — the guaranteed fallback. Bounded,
   offline, defensive loader; curated `confirmed=true` rules still confirm. Intact.
7. `EngineComposition.BuildDefault` — always builds `new YaraEngineAdapter(yaraDb)` and
   keeps it unless `settings.EnableYaraRules` + a rules directory yields a
   `LibyaraEngine.TryCreate` with `RuleCount > 0`; otherwise it disposes the real engine
   and keeps the fallback. Selection rule intact; no change needed.
8. `YaraDetectionModule` — `Strength = hit.Confirmed ? Confirmed : High`,
   `CanConfirmMalware = hit.Confirmed`, `ScoreDelta = hit.Score`. With real matches forced
   to `Confirmed=false, Score=0`, real hits map to **`High` / `CanConfirmMalware=false` /
   `ScoreDelta=0`** — non-confirming. No change needed.
9. Tests — `YaraEngineFallbackTests` (TryCreate→null fallback; external-style match is
   non-confirming; curated confirmed rule still confirms; missing dir is non-fatal) and
   `YaraRulePackTests` (bounded local loader) exist and assume no native YARA.
10. `DataVanger.Shared/Status/ModuleStatusModels.cs` honestly reports real-libyara as
    `Prepared` (not Active) under both `#if YARA_REAL` branches.

Conclusion: the repo matches the spec and is already in a clean, dormant, fallback-only
state with no dangling references.

## Package Decision

- Package name: **dnYara** (airbus-cert), a .NET Standard 2.0 PInvoke wrapper for native
  libyara 4.x. License **Apache-2.0** (acceptable supply chain).
- Latest / spec-noted version: **2.1.0** (2022-01-05). 2.0.0 was deprecated for critical
  bugs; 2.1.0 is the correct pin. Target framework (netstandard2.0) is compatible with the
  project's `net8.0-windows`, so **restore is expected to succeed on Windows**.
- Restore result here: **not attempted / not possible** — no .NET SDK in this environment.
- Decision: **do not add the package in this environment.** Pin `dnYara 2.1.0` only after a
  green Windows restore/build, and only together with the native-pack and API fixes below.

## API Reconciliation Notes (offline probe vs. guarded code)

The guarded code's API surface largely matches dnYara 2.1.0, but there are two real gaps.

Matches (no change needed): `new Compiler()` + `compiler.AddRuleFile(string)` +
`compiler.Compile() : CompiledRules`; `new Scanner()` + `Scanner.ScanFile(string, CompiledRules) : List<ScanResult>`;
`ScanResult.MatchingRule.Identifier` (rule name); `ScanResult.Matches` (dictionary-like,
`.Count` valid). These align with the current `#if YARA_REAL` code.

- **GAP 1 — missing `YaraContext` lifetime (runtime correctness, not a compile error).**
  dnYara requires an active `YaraContext` (`yr_initialize`/`yr_finalize`) around all
  Compiler/Scanner work. The guarded code never creates one. Because `LibyaraEngine`
  compiles rules in its constructor but holds `_rules`/`_scanner` for many later `Scan`
  calls, a naive `using var ctx = new YaraContext()` in the constructor would finalize
  yara before any scan runs. Correct fix: hold a `YaraContext` as a field for the engine's
  lifetime and dispose it last in `Dispose()`. This is a small but **required** structural
  reconciliation before activation. (Spec Gate B — reconcile if small; this qualifies.)
- **GAP 2 — native binaries are not in `dnYara`.** The `dnYara` package ships no
  `libyara.dll`; the native lib comes from the separate **`dnYara.NativePack`** package
  (64-bit Windows, libyara 4.1.1) or a self-compiled libyara. The enablement note mentions
  only `dnYara`, so activating it as written would build but **fail native load at runtime
  with `DllNotFoundException`** (the existing `TryCreate` catch would then silently fall
  back — masking the operator's activation attempt). Adding `dnYara.NativePack` is a
  native-deployment change that the spec's **Native Dependency Rule** says to **stop and
  report before applying** — reported here, not applied.
- **GAP 3 — x64 enforcement.** `dnYara.NativePack` is 64-bit only. `DataVanger.csproj`
  sets no `<PlatformTarget>`; if it ever runs 32-bit, native load throws
  `BadImageFormatException`. Activation should pin `<PlatformTarget>x64</PlatformTarget>`
  (also a deployment change → stop-and-report).

Disposal note: confirm on Windows that `CompiledRules` and `Scanner` implement `IDisposable`
(expected — they wrap native handles); the `Dispose()` calls assume this.

## Native Backend Validation

- Native load result: **not validated** — no SDK, not Windows.
- Trivial-rule compile (`DataVangerSmokeRule` / `DataVangerYaraSmokeTest`): **not validated.**
- Real scan: **not validated.**
- Native/RID/copy concerns: real, see GAP 2 (NativePack) and GAP 3 (x64). The spec's
  Native Dependency Rule requires these to be reported, not silently applied — done here.

## Fallback Verification

Fallback is preserved because nothing changed. `EngineComposition` always constructs the
`YaraEngineAdapter(LightweightYaraDatabase)` and only swaps to the real engine when
`TryCreate` yields `RuleCount > 0`; otherwise it disposes the real engine and keeps the
lightweight one. With `YARA_REAL` undefined, `TryCreate` always returns `null`. Existing
fallback tests (`LibyaraEngine_TryCreate_WithoutRealPackage_ReturnsNullSoFallbackIsUsed`,
`LightweightYaraDatabase_MissingRulesDirectory_DegradesGracefully`, the `YaraRulePackTests`
suite) encode this. Spec failure modes (no package/define, native unavailable, no rules,
bad rule file, compile failure, scanner failure, empty dir, zero `RuleCount`) all route to
the lightweight engine without crashing.

## Non-Confirmation Verification

Real matches are non-confirming by construction and verified by code review + existing
tests. `LibyaraEngine.Scan` hard-codes `Confirmed: false, Score: 0` for every real match;
`YaraDetectionModule` maps `Confirmed=false` to `Strength=High`, `CanConfirmMalware=false`,
`ScoreDelta=0`. `YaraDetectionModule_ExternalStyleMatch_IsNotConfirmedMalware` asserts a
non-confirmed match never confirms; `YaraDetectionModule_ConfirmedLightweightRule_StillConfirms`
asserts curated confirmed rules are unaffected. Confirmation stays exclusive to curated
lightweight `confirmed` rules and known-malicious hashes. Heuristic clamp untouched.

## Tests

- `dotnet test ...` — **not run** (no SDK). Existing YARA tests were audited, not executed.
- New real-path tests — **not added.** Adding `#if YARA_REAL` Windows-guarded tests now
  would be unverifiable in this environment and would have to be co-committed with the
  package/API changes during the gated Windows activation. Deferred to that step.

## Builds

- All six project builds, the solution build, and the `-p:DefineConstants=YARA_REAL` real-path
  build — **not run** (no .NET SDK; not Windows). These are the spec's gating evidence and
  remain to be produced on Windows.

## Invariants

Checked (excluding `bin`/`obj`):

- Anonymous `catch {}` blocks: **0**
- `lock(qm)`: **0**
- CRLF `.cs` files: **0** (`.gitattributes` enforces `* text=auto eol=lf`)

No invariant was introduced or affected (no `.cs` files changed).

## Files Changed

- None affecting build/runtime. Added this report: `outputs/12_REAL_LIBYARA_ACTIVATION_REPORT.md`.
- `DataVanger/DataVanger.csproj`: unchanged (dnYara + `YARA_REAL` remain commented/dormant).
- `DataVanger/Infrastructure/LibyaraEngine.cs`: unchanged (guarded code remains dormant).

## Bugs Noticed But Not Fixed (out of scope)

- The guarded `#if YARA_REAL` code omits the required `YaraContext` lifetime (GAP 1). It is
  dormant today, so it harms nothing, but it must be fixed during the gated Windows
  activation or the real backend would fail at runtime and silently fall back.

## Required Windows Activation Checklist (for the gated follow-up)

1. On Windows with the .NET SDK: `dotnet restore` + build a throwaway project referencing
   `dnYara 2.1.0` **and** `dnYara.NativePack` (64-bit); confirm libyara.dll loads and a
   trivial rule compiles + scans.
2. Reconcile `LibyaraEngine.cs`: add a lifetime-scoped `YaraContext` field (GAP 1).
3. In `DataVanger.csproj`: uncomment/add pinned `dnYara 2.1.0`, add `dnYara.NativePack`,
   add `YARA_REAL`, and pin `<PlatformTarget>x64</PlatformTarget>` (GAP 2/3).
4. Run all eight baseline builds/tests + the `-p:DefineConstants=YARA_REAL` build; add the
   Windows-guarded real-path tests (smoke compile, non-confirmation, fallback).
5. Re-run the three invariant checks (expect zero).
6. Only commit activation if every proof passes; otherwise revert to this dormant state.

## Final Verdict

`not safe to enable`

Rationale: activation is approval-gated and Windows-validation-required; the gating
restore/build/native-load/rule-compile/scan proofs cannot be produced in this Linux/no-SDK
environment, and activation additionally requires a `YaraContext` API fix plus a native
deployment package (`dnYara.NativePack`) and x64 pinning that the Native Dependency Rule
mandates be reported before applying. The repository is left in its already-correct,
fully-functional, dormant fallback-only state with no dangling references.
