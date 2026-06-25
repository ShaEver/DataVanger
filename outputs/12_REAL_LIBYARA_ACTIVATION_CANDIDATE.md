# 12_REAL_LIBYARA_ACTIVATION — Activation CANDIDATE

Branch: `claude/quirky-davinci-trbbx3-libyara-candidate`
Status: **candidate for Windows validation — NOT a stable merge, NOT `safe to enable`**
Environment that produced it: Linux, **no .NET SDK** (cannot restore/build/run/validate native)

## Summary

This branch turns the dormant `#if YARA_REAL` backend into an **activation candidate** for
the operator to validate on Windows. It pins the dnYara managed wrapper, adds the native
libyara pack, forces x64, and fixes the real path's missing `YaraContext` lifetime (the
gap found in the audit). The lightweight fallback, `EngineComposition` selection,
`YaraDetectionModule` semantics, and the non-confirming contract are all preserved. Nothing
here is validated for native behavior — this environment has no .NET SDK and is not Windows.

## Package Versions Added (DataVanger/DataVanger.csproj)

| Package | Version | Why |
|---|---|---|
| `dnYara` | `2.1.0` | Managed .NET Standard 2.0 wrapper for native libyara 4.x; Apache-2.0; latest stable (2.0.0 was deprecated for critical bugs). Compatible with `net8.0-windows`. |
| `dnYara.NativePack` | `2.1.0.3` | Ships the pre-compiled **64-bit** `libyara.dll` (libyara 4.1.1) as a NuGet `runtimes/<rid>/native` asset, so the native lib actually deploys to the app output. Latest of the 2.1.0.x line. |

`dnYara.Interop` flows transitively from `dnYara`; it is not pinned directly.

## Platform Change

`<PlatformTarget>x64</PlatformTarget>` was added to `DataVanger/DataVanger.csproj`. The
NativePack `libyara.dll` is 64-bit only, so the process must be x64 or native load throws
`BadImageFormatException`. With the build resolving the host RID (win-x64) and an x64
process, the SDK copies `libyara.dll` into the app output and the runtime resolves the
P/Invoke. **Scope note:** only `DataVanger.exe` runs the real backend — `ScanEngine`
(DataVanger app) → `EngineComposition.BuildDefault` → `LibyaraEngine.TryCreate`.
`DataVanger.Service` does **not** reference the `DataVanger` project, so service deployment
and host behavior are unchanged (no native package added there).

## YaraContext Lifetime Fix (DataVanger/Infrastructure/LibyaraEngine.cs)

dnYara requires the native library to be initialised (`yr_initialize`) before any
`Compiler`/`Scanner`/`CompiledRules` exists and finalised (`yr_finalize`) only after all of
them are released; it models this with `YaraContext`. The dormant code never created one,
and because `LibyaraEngine` compiles rules in its constructor but holds `_scanner`/`_rules`
across many later `Scan` calls, a naive `using` context would have finalised YARA before any
scan. The fix:

- Added a `private readonly YaraContext _context;` owned for the **whole engine lifetime**.
- The constructor creates `_context = new YaraContext()` **first**, before `new Scanner()`,
  the compiler, and `Compile()`.
- `Dispose()` releases in reverse order: `_rules` → `_scanner` → `_context` (yr_finalize last).
- Construction is exception-safe: if anything after `yr_initialize` throws (e.g. the native
  lib can't load), a cleanup `catch` disposes rules/scanner/context in order, then rethrows
  to `TryCreate`'s fallback handler — no leaked native context.
- A whole-pack `compiler.Compile()` failure is now isolated (logs, `_rules = null`,
  `RuleCount = 0`) so a bad pack degrades to fallback instead of throwing.

### Fallback strengthening (also in LibyaraEngine.cs)

`TryCreate`'s catch filter was widened from a fixed type list to "any non-fatal exception"
(`ex is not OutOfMemoryException and not StackOverflowException`), so **any** real-backend
failure — missing/incompatible native libyara or a dnYara backend error — degrades to the
lightweight engine. The exact exception type (`ex.GetType().Name`) and message are still
logged, so native-load failures are surfaced, not hidden. This strengthens (never weakens)
the fallback guarantee. `Confirmed=false, Score=0` for every real match is unchanged.

## Files Changed

1. `DataVanger/DataVanger.csproj` — replaced the dormant enablement comment with an active
   (candidate) `PropertyGroup` (`YARA_REAL` define + `PlatformTarget x64`) and `ItemGroup`
   (dnYara + dnYara.NativePack), plus a candidate/rollback comment.
2. `DataVanger/Infrastructure/LibyaraEngine.cs` — added `YaraContext` lifetime + exception-safe
   construction + isolated compile failure; widened `TryCreate` fallback filter with retained
   diagnostics; `Dispose` now finalises the context last.
3. `DataVanger.Tests/RealYaraBackendTests.cs` — **new** real-path test suite (below).
4. `outputs/12_REAL_LIBYARA_ACTIVATION_CANDIDATE.md` — this report.

Unchanged (verified, preserved): `EngineComposition.cs`, `YaraDetectionModule.cs`,
`IYaraEngine.cs`, `LightweightYaraDatabase.cs`, `YaraEngineAdapter.cs`, existing
`YaraEngineFallbackTests.cs` / `YaraRulePackTests.cs`, all other projects, ETW/AMSI/IPC/
quarantine/signed-updates/scheduler.

## Tests Added/Updated

New file `DataVanger.Tests/RealYaraBackendTests.cs`. All tests go through the public
`LibyaraEngine.TryCreate` / `IYaraEngine` surface (no direct dnYara reference), so they
**compile and pass in every build configuration**. The real native path is exercised only
when `TryCreate` returns a non-null engine (built with `YARA_REAL` and native libyara loaded
at runtime); otherwise each test asserts the guaranteed fallback.

- `RealYaraBackend_CompilesSmokeRule_WhenNativeBackendAvailable` — compiles the trivial
  `DataVangerSmokeRule` (`$a = "DataVangerYaraSmokeTest"`), scans a benign file, asserts the
  match. (No malware-like strings; no network.)
- `RealYaraBackend_RealMatchesAreNonConfirming` — real matches all `Confirmed=false, Score=0`.
- `RealYaraBackend_BadRuleFile_DoesNotBreakEngine` — a malformed rule alongside a valid one
  never throws and never breaks the good rule.
- `RealYaraBackend_UnavailableOrEmpty_FallsBackToLightweight` — empty rules dir → `TryCreate`
  null in every config; `YaraEngineAdapter` remains a valid fallback.
- `YaraDetectionModule_RealYaraHit_DoesNotConfirmMalware` — a real-style hit mapped through
  the module yields `CanConfirmMalware=false`, `Strength != Confirmed`, `ScoreDelta=0`.

**Operator hard-validation switch:** set `DATAVANGER_REQUIRE_REAL_YARA=1` so a "backend
unavailable" result becomes a **test failure** that prints the captured native-load
diagnostics, instead of a soft skip. Use this on Windows to prove the native path actually
ran (otherwise the native tests soft-skip and could mask a missing/failed libyara).

## Windows Validation Commands (run these on x64 Windows with the .NET SDK)

```powershell
# 1. Restore + the eight baseline builds (now WITH the package, on the candidate branch)
dotnet restore
dotnet build DataVanger/DataVanger.csproj
dotnet build DataVanger.Tests/DataVanger.Tests.csproj
dotnet build DataVanger.Service/DataVanger.Service.csproj
dotnet build DataVanger.Engine/DataVanger.Engine.csproj
dotnet build DataVanger.Shared/DataVanger.Shared.csproj
dotnet build DataVanger.Infrastructure/DataVanger.Infrastructure.csproj
dotnet build DataVanger.sln

# 2. Confirm the native lib actually deployed next to the app (proves NativePack worked)
Get-ChildItem -Recurse -Filter libyara.dll DataVanger\bin

# 3. Full test suite (soft real-path tests), then a HARD real-path run that fails if the
#    native backend did not load. Run x64 so the 64-bit libyara.dll can load.
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --arch x64
$env:DATAVANGER_REQUIRE_REAL_YARA = "1"
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --arch x64 --filter "FullyQualifiedName~Yara"
Remove-Item Env:\DATAVANGER_REQUIRE_REAL_YARA

# 4. Prior-phase invariant checks (expect zero each)
Get-ChildItem -Recurse -Filter *.cs | Where-Object { $_.FullName -notmatch '\\bin\\|\\obj\\' } | Select-String 'catch\s*\{\s*\}'
Get-ChildItem -Recurse -Filter *.cs | Where-Object { $_.FullName -notmatch '\\bin\\|\\obj\\' } | Select-String 'lock\s*\(qm\)'
Get-ChildItem -Recurse -Filter *.cs | Where-Object { $_.FullName -notmatch '\\bin\\|\\obj\\' } | ForEach-Object { $c = Get-Content $_.FullName -Raw; if ($c -match "`r") { $_.FullName } }
```

Pass criteria: all eight builds succeed; `libyara.dll` is present under `DataVanger\bin`;
the hard real-path test run is green (smoke rule compiles, scans, matches are non-confirming,
bad rules don't break the engine); invariants are all zero.

### Contingency (only if step 3 hard-run reports native load failure)

If `DATAVANGER_REQUIRE_REAL_YARA=1` fails with `DllNotFoundException`/`BadImageFormatException`,
the native asset did not resolve. Try, in order, and report which was needed:
1. Add `<RuntimeIdentifier>win-x64</RuntimeIdentifier>` to `DataVanger/DataVanger.csproj`
   (forces the native asset to the output root).
2. Confirm the test host is x64 (`--arch x64`) and the OS is 64-bit.
Do **not** treat the phase as enabled until the hard real-path run is green.

## Rollback (return to the validated dormant state)

```powershell
git checkout claude/quirky-davinci-trbbx3   # the dormant, audited branch
# or, to revert in place on this branch:
git revert <this commit>                     # restores the commented csproj + dormant LibyaraEngine
```

Manual equivalent: in `DataVanger/DataVanger.csproj` move the `PropertyGroup`/`ItemGroup`
(YARA_REAL + PlatformTarget x64 + dnYara + dnYara.NativePack) back inside an XML comment;
the `LibyaraEngine.cs` real path then becomes dormant again and the lightweight fallback
resumes. No data/runtime migration is required.

## Invariants (this environment, LF-checked, excl. bin/obj)

- Anonymous `catch {}`: **0** (the new cleanup catch has a body and rethrows; not empty).
- `lock(qm)`: **0**.
- CRLF `.cs` files: **0** (all new/edited files are LF; `.gitattributes` enforces `eol=lf`).

## What Is NOT Proven Here

Restore, builds, native libyara load, rule compilation, real scan, and the full test suite
were **not run** — no .NET SDK, not Windows. dnYara API names were reconciled from package
documentation/source, not from a compiler. The `YaraContext` lifetime, the native asset
deployment, and x64 behavior are **design-correct but unvalidated** until the operator runs
the commands above.

## Final Verdict

`candidate ready for Windows validation`

(Explicitly **not** `safe to enable`. This is an approval-gated candidate; promote it to a
stable baseline only after the Windows restore/build/native-load/rule-compile/test evidence
above is green. If any step fails, roll back per the section above and report the blocker.)
