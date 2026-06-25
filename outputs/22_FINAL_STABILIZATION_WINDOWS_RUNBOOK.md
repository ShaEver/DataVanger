# 22_FINAL_STABILIZATION — Windows Validation Runbook

Purpose: execute the release-gate's **dynamic** evidence (build / test / x64 native-YARA /
packaging / invariants) that cannot run in the Linux/no-SDK authoring environment. If every
**[GATE]** item passes, the verdict flips from `NO-GO — NOT STABLE` to `GO — SAFE TO PROMOTE`.

Scope reminder: this file is documentation only. Do **not** edit production / ETW / YARA code
to make a check pass — if a gate fails, record it and stop (a truthful NO-GO is required).

---

## 0. Prerequisites & environment capture

Requirements:
- Windows 10/11 **x64** (the native `libyara.dll` is 64-bit; the app pins `PlatformTarget x64`).
- **.NET 8 SDK** (includes the Windows Desktop runtime needed by the WPF/WinForms app).
- Network access for NuGet restore (`dnYara`, `dnYara.NativePack`, xUnit, etc.).
- A normal shell is fine for build/test; the **optional** ETW/service drill (§7) needs an
  **elevated** (Administrator) PowerShell.
- If on-access AV blocks restore/native copy, allowlist the repo folder for the run.

Branch under test: `claude/quirky-davinci-trbbx3-libyara-candidate`

```powershell
# Run all commands from the repository root (the folder containing DataVanger.sln).
cd <path-to>\claude_workspace
git checkout claude/quirky-davinci-trbbx3-libyara-candidate
git pull --ff-only

# Capture the environment for the report
"OS            : $([System.Environment]::OSVersion.VersionString)"
"Arch (OS)     : $env:PROCESSOR_ARCHITECTURE"
"dotnet --info:"; dotnet --info
"Branch        : $(git rev-parse --abbrev-ref HEAD)"
"Commit        : $(git rev-parse HEAD)"
"Clean tree?   : $(git status --porcelain)"   # empty == clean
```

Record: OS, `dotnet --version` (expect 8.x), branch, commit, clean tree.

---

## 1. [GATE] Build matrix

```powershell
dotnet restore
$restore = $LASTEXITCODE

dotnet build DataVanger/DataVanger.csproj
$b1 = $LASTEXITCODE
dotnet build DataVanger.Tests/DataVanger.Tests.csproj
$b2 = $LASTEXITCODE
dotnet build DataVanger.Service/DataVanger.Service.csproj
$b3 = $LASTEXITCODE
dotnet build DataVanger.Engine/DataVanger.Engine.csproj
$b4 = $LASTEXITCODE
dotnet build DataVanger.Shared/DataVanger.Shared.csproj
$b5 = $LASTEXITCODE
dotnet build DataVanger.Infrastructure/DataVanger.Infrastructure.csproj
$b6 = $LASTEXITCODE
dotnet build DataVanger.sln
$bsln = $LASTEXITCODE

"restore=$restore d1=$b1 d2=$b2 d3=$b3 d4=$b4 d5=$b5 d6=$b6 sln=$bsln  (all 0 == PASS)"
```

**PASS criteria:** `restore` and all eight build exit codes are `0`; the solution build ends
with `Build succeeded` and **0 Error(s)**. Record the **Warning(s)** count from the `sln`
build for §6.

| Item | Exit code (0=pass) | Result |
|---|---|---|
| `dotnet restore` | ____ | ☐ PASS ☐ FAIL |
| build `DataVanger` | ____ | ☐ PASS ☐ FAIL |
| build `DataVanger.Tests` | ____ | ☐ PASS ☐ FAIL |
| build `DataVanger.Service` | ____ | ☐ PASS ☐ FAIL |
| build `DataVanger.Engine` | ____ | ☐ PASS ☐ FAIL |
| build `DataVanger.Shared` | ____ | ☐ PASS ☐ FAIL |
| build `DataVanger.Infrastructure` | ____ | ☐ PASS ☐ FAIL |
| build `DataVanger.sln` | ____ | ☐ PASS ☐ FAIL |

> Any non-zero exit / any error ⇒ **NO-GO**. Stop and record the first failing project + output.

---

## 2. [GATE] Test matrix

Full suite (x64 so the native libyara can load in the real-YARA tests):

```powershell
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --arch x64
"full suite exit=$LASTEXITCODE  (0 == PASS)"
```

Required filters (record pass/fail + counts for each):

```powershell
$filters = @("AntiFalsePositive","Publisher","Yara","Quarantine","Update","Ipc","Service")
foreach ($f in $filters) {
  Write-Host "==== filter ~$f ===="
  dotnet test DataVanger.Tests/DataVanger.Tests.csproj --arch x64 --filter "FullyQualifiedName~$f"
  Write-Host "exit(~$f)=$LASTEXITCODE"
}
```

Optional (recommended) filters — record if present:

```powershell
$opt = @("Etw","Amsi","Behavioral","Signed","Scheduler","Reporting")
foreach ($f in $opt) {
  Write-Host "==== filter ~$f ===="
  dotnet test DataVanger.Tests/DataVanger.Tests.csproj --arch x64 --filter "FullyQualifiedName~$f"
  Write-Host "exit(~$f)=$LASTEXITCODE"
}
```

**PASS criteria:** full-suite exit code `0` (0 failed); each **required** filter exit `0` with
**≥1 test run** (a filter that runs 0 tests is acceptable only if that area legitimately has no
tests — note it). Record `Passed!/Failed!` and the `Passed:`/`Failed:`/`Skipped:` counts.

| Suite / filter | Passed | Failed | Skipped | Result |
|---|---|---|---|---|
| Full `--arch x64` | ____ | ____ | ____ | ☐ PASS ☐ FAIL |
| `~AntiFalsePositive` | ____ | ____ | ____ | ☐ PASS ☐ FAIL |
| `~Publisher` | ____ | ____ | ____ | ☐ PASS ☐ FAIL |
| `~Yara` | ____ | ____ | ____ | ☐ PASS ☐ FAIL |
| `~Quarantine` | ____ | ____ | ____ | ☐ PASS ☐ FAIL |
| `~Update` | ____ | ____ | ____ | ☐ PASS ☐ FAIL |
| `~Ipc` | ____ | ____ | ____ | ☐ PASS ☐ FAIL |
| `~Service` | ____ | ____ | ____ | ☐ PASS ☐ FAIL |

> Any failed test ⇒ **NO-GO** unless proven unrelated and explicitly deferred with justification.

---

## 3. [GATE] x64 native-YARA hard-validation

This forces the real libyara backend to be present: with `DATAVANGER_REQUIRE_REAL_YARA=1`, the
`RealYaraBackend_*` tests turn a "backend unavailable" result into a **failure** (printing the
native-load diagnostics), so a green run proves the native lib actually loaded, compiled the
smoke rule, scanned, and produced **non-confirming** matches.

```powershell
$env:DATAVANGER_REQUIRE_REAL_YARA = "1"
dotnet test DataVanger.Tests/DataVanger.Tests.csproj --arch x64 --filter "FullyQualifiedName~Yara"
$hard = $LASTEXITCODE
Remove-Item Env:\DATAVANGER_REQUIRE_REAL_YARA
"hard real-YARA exit=$hard  (0 == PASS)"
```

**PASS criteria:** exit code `0`, with the real-path tests actually executing (not soft-skipped):
`RealYaraBackend_CompilesSmokeRule_WhenNativeBackendAvailable`,
`RealYaraBackend_RealMatchesAreNonConfirming`, `RealYaraBackend_BadRuleFile_DoesNotBreakEngine`
all pass. (If they soft-skip under the env var, that is a FAIL — it means the native backend
did not load; see §4 / the contingency at the bottom.)

| Check | Result |
|---|---|
| Hard real-YARA suite (`DATAVANGER_REQUIRE_REAL_YARA=1`, `--arch x64`) exit `0` | ☐ PASS ☐ FAIL |
| Real matches confirmed non-confirming (test names above green) | ☐ PASS ☐ FAIL |

> Hard-validation FAIL ⇒ **NO-GO**.

---

## 4. [GATE] Packaging / publish + libyara.dll deployment

```powershell
# Publish the app (framework-dependent Debug audit publish)
dotnet publish DataVanger/DataVanger.csproj -c Debug -o C:\tmp\datavanger_publish_audit --no-restore
$pub = $LASTEXITCODE
"publish exit=$pub  (0 == PASS)"

# libyara.dll must be deployed to app build output, test build output, and publish output
Write-Host "---- app bin ----";   Get-ChildItem -Recurse -Filter libyara.dll DataVanger\bin
Write-Host "---- tests bin ----"; Get-ChildItem -Recurse -Filter libyara.dll DataVanger.Tests\bin
Write-Host "---- publish ----";   Get-ChildItem -Recurse -Filter libyara.dll C:\tmp\datavanger_publish_audit

# Boolean presence checks
$appDll  = (Get-ChildItem -Recurse -Filter libyara.dll DataVanger\bin            -ErrorAction SilentlyContinue | Measure-Object).Count
$testDll = (Get-ChildItem -Recurse -Filter libyara.dll DataVanger.Tests\bin      -ErrorAction SilentlyContinue | Measure-Object).Count
$pubDll  = (Get-ChildItem -Recurse -Filter libyara.dll C:\tmp\datavanger_publish_audit -ErrorAction SilentlyContinue | Measure-Object).Count
"libyara.dll  app=$appDll  tests=$testDll  publish=$pubDll  (each >=1 == PASS)"
```

**PASS criteria:** publish exit `0`; `libyara.dll` count `>= 1` in **each** of app bin, test
bin, and publish output. Restore is deterministic (re-running §1 restore yields the same
resolved versions); package references are pinned (`dnYara 2.1.0`, `dnYara.NativePack 2.1.0.3`).

| Check | Value | Result |
|---|---|---|
| `dotnet publish` exit `0` | ____ | ☐ PASS ☐ FAIL |
| `libyara.dll` in `DataVanger\bin` | count ____ | ☐ PASS ☐ FAIL |
| `libyara.dll` in `DataVanger.Tests\bin` | count ____ | ☐ PASS ☐ FAIL |
| `libyara.dll` in publish output | count ____ | ☐ PASS ☐ FAIL |

> Missing `libyara.dll` in any location ⇒ **NO-GO** (see contingency at the bottom).

---

## 5. [GATE] Invariant checks

```powershell
Write-Host "== anonymous catch {} (expect NONE) =="
Get-ChildItem -Recurse -Filter *.cs |
  Where-Object { $_.FullName -notmatch '\\bin\\|\\obj\\' } |
  Select-String 'catch\s*\{\s*\}'

Write-Host "== lock(qm) (expect NONE) =="
Get-ChildItem -Recurse -Filter *.cs |
  Where-Object { $_.FullName -notmatch '\\bin\\|\\obj\\' } |
  Select-String 'lock\s*\(qm\)'

Write-Host "== CRLF .cs files (expect NONE) =="
Get-ChildItem -Recurse -Filter *.cs |
  Where-Object { $_.FullName -notmatch '\\bin\\|\\obj\\' } |
  ForEach-Object { $c = Get-Content $_.FullName -Raw; if ($c -match "`r") { $_.FullName } }
```

**PASS criteria:** all three produce **no output** (zero matches).

| Invariant | Matches | Result |
|---|---|---|
| Anonymous `catch { }` | ____ | ☐ PASS ☐ FAIL |
| `lock(qm)` | ____ | ☐ PASS ☐ FAIL |
| CRLF `.cs` files | ____ | ☐ PASS ☐ FAIL |

> Any new invariant match ⇒ **NO-GO**.

---

## 6. [GATE] Warning review

From the §1 `sln` build, record the warning count and confirm only known/acceptable classes:

- `xUnit1031` (sync blocking in `LegacyParityTests`) — pre-existing / deferred (acceptable).
- Processor-architecture mismatch (`DataVanger` x64 vs AnyCPU references) — benign (no
  `TreatWarningsAsErrors` is set in any project).
- Nullable / obsolete API — none expected; investigate any that appear.

**PASS criteria:** build succeeds (warnings do not fail the build), and no warning indicates a
real defect (e.g., a genuine nullable/native-deployment problem). Record the count.

| Check | Value | Result |
|---|---|---|
| `sln` warning count | ____ | ☐ PASS ☐ FAIL |
| Only known/acceptable warning classes | ____ | ☐ PASS ☐ FAIL |

---

## 7. (OPTIONAL — already resolved) ETW / service spot-confirmation

ETW was audited in `22_FINAL_STABILIZATION` as **NO REGRESSION** (the provider is byte-identical
to the Phase-17 validated baseline; session creation / `logman` visibility / disposal already
proven). This section is an **optional** re-confirmation only and is **NOT a GO gate**. Run in an
**elevated** PowerShell if desired:

```powershell
# While the real ETW provider is active, a DataVanger-ProcessEtw-* session should be visible:
logman query -ets | Select-String "DataVanger-ProcessEtw"
```

Record (optional): session visible ☐ yes ☐ no. A "no" here does **not** create a blocker by
itself, since ETW was already validated; investigate separately if unexpected.

---

## 8. Final GO / NO-GO decision

Mark the verdict **GO — SAFE TO PROMOTE** only if **every [GATE] box below is PASS**:

- ☐ §1 Build matrix — restore + all 8 builds exit `0`, solution `Build succeeded`, 0 errors
- ☐ §2 Test matrix — full `--arch x64` green; all required filters green
- ☐ §3 x64 native-YARA hard-validation — green with real-path tests executed (not soft-skipped)
- ☐ §4 Packaging — publish exit `0`; `libyara.dll` present in app bin, test bin, and publish output
- ☐ §5 Invariants — zero anonymous `catch {}`, zero `lock(qm)`, zero CRLF `.cs`
- ☐ §6 Warnings — build succeeds; only known/acceptable warning classes

If ALL are PASS:

```
GO — SAFE TO PROMOTE
Final checkpoint: DataVanger V.Alpha_STABLE
Suggested ZIP:    DataVanger V.Alpha_STABLE.zip
```

If ANY is FAIL:

```
NO-GO — NOT STABLE
First failing gate: <section> — <exact command + output>
```

Do not author a fix to force a pass; record the failure and report it.

---

## Contingency — only if §3/§4 show the native lib did not load

If the hard real-YARA suite (§3) fails with a `DllNotFoundException` / `BadImageFormatException`,
or `libyara.dll` is missing from output (§4):

1. Confirm the run is x64 (`--arch x64`) and the OS is 64-bit.
2. Confirm `dnYara.NativePack 2.1.0.3` restored and that
   `$(PkgdnYara_NativePack)\lib\netstandard1.1\libyara.dll` exists under the NuGet cache.
3. As a documented escalation (apply, re-run §1–§4, and report that it was needed):
   add `<RuntimeIdentifier>win-x64</RuntimeIdentifier>` to `DataVanger/DataVanger.csproj`.

This is the **only** sanctioned code-adjacent change, and only under a proven native-load
failure — it is a packaging/deployment knob, not a behavior change.

---

## Report-back template (paste filled values back)

```
ENV: OS=____  dotnet=____  branch=claude/quirky-davinci-trbbx3-libyara-candidate  commit=____
§1 BUILD:   restore/8 builds/sln exit codes = ____ ;  errors=____  warnings=____
§2 TEST:    full(x64)=____ ; AntiFalsePositive/Publisher/Yara/Quarantine/Update/Ipc/Service = ____
§3 YARA HARD: exit=____ ; real-path tests executed? yes/no
§4 PACKAGING: publish=____ ; libyara.dll app=____ tests=____ publish=____
§5 INVARIANTS: catch{}=____  lock(qm)=____  CRLF=____
§6 WARNINGS: count=____ ; classes=____
§7 (opt) ETW logman visible: yes/no
VERDICT: GO — SAFE TO PROMOTE  /  NO-GO — NOT STABLE (first failing gate: ____)
```

Send this block back and the final report's verdict (§15) will be updated accordingly.
