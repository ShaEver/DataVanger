# 01_DECOMPOR_RUNASYNC.md

## Phase name

Decompor ScanEngine.RunAsync

## Phase position

This phase belongs to the DataVanger improvement plan, applied over the current V.Alpha codebase.

This phase must be applied on top of the phase 07 output ZIP.

Phases 02, 03, and 07 have already been applied and are stabilized.

## Current stable checkpoint

Use the phase 07 output as baseline:

```text
DataVanger V.Alpha_LINEENDINGS_LOCK_CLAUDE.zip
```

Expected baseline commands:

```text
dotnet build DataVanger/DataVanger.csproj
dotnet build DataVanger.Tests/DataVanger.Tests.csproj
dotnet run --project DataVanger.Tests/DataVanger.Tests.csproj
```

Do not proceed until the baseline build and test state passes cleanly.

## Expected current repository state (phases 02 / 03 / 07 applied)

```text
catch { } count = 0
CSV fixes are present in ScanEngine.cs
.gitattributes exists
CRLF .cs file count = 0
lock (qm) no longer exists
quarantineLock exists locally in RunAsync near qm
```

## Objective

Decompose `ScanEngine.RunAsync` in `DataVanger/Core/ScanEngine.cs` from a single ~461-line method into a lean orchestrator of approximately 12 lines (<= 15) that delegates to clearly named private phase methods.

The goal is not to change detection behavior. The goal is to make each phase of the scan independently readable, independently testable in isolation, and independently modifiable without touching the other phases.

## Non-goals

Do not implement any of the following in this phase:

- changes to detection logic, scoring, thresholds, or evidence generation;
- changes to quarantine behavior or policy;
- changes to report format or report content;
- changes to the public interface of `IScanEngine`;
- changes to `ScanOptions`, `ScanMetrics`, `ScanFinding`, `ScanContext`, or any domain model;
- new public classes or new namespaces;
- migration of tests to xUnit or any other framework;
- entropy improvements or YARA integration changes;
- changes to any logic already modified by phases 02, 03, or 07 (catch patterns, CSV methods, SemaphoreSlim);
- any fix not related to the structural decomposition.

This phase is about internal structure only.

## Existing behavior to preserve

- the main app builds without warnings or errors;
- the test project builds without warnings or errors;
- the test runner passes with identical results;
- the public signature of `RunAsync` is unchanged;
- the scan produces identical findings, metrics, and reports for the same input;
- all existing private helper methods remain present and unmodified:
  - `GetRunningProcessPaths`
  - `GetSigInfo`
  - `IsPublisherTrusted`
  - `ExtractYaraName`
  - `LoadPreviousHashes`
  - `WriteCsv`
  - `EscCsv`
  - `ParseCsvLine`
  - `WriteTxt`
- all static field sets remain present and unmodified:
  - `DangerExt`, `ArchiveExt`, `DocumentExt`, `PeExt`, `ScriptExt`, `ExeExt`, `EntropyExt`, `TrustedPublishers`;
- all public path properties remain present and unmodified:
  - `MgRoot`, `QuarantineRoot`, `SignatureRoot`, and all derived path properties;
- the anti-false-positive clamp behavior is preserved exactly;
- the persistence threshold gate behavior is preserved exactly;
- the Authenticode trust gate behavior is preserved exactly;
- automatic quarantine policy is preserved exactly;
- thread safety of metric increments is preserved or improved.

## Core design principle

The refactoring must follow a strict move-only discipline.

No logic may be rewritten, simplified, or improved during this phase. Every line of detection logic, every guard condition, every metric increment, every progress callback must be moved as-is to its new location. The only permitted changes are structural: removing lines from `RunAsync` and adding them to private methods.

If during the move any existing bug or code smell is noticed, document it as a comment but do not fix it.

## Recommended structure

After this phase, `DataVanger/Core/ScanEngine.cs` must contain the following private members in addition to all existing ones:

```text
private sealed record ScanState(...)
private ScanState LoadConfiguration(Action<string> log)
private Task<ScanContext> CollectGlobalContextAsync(...)
private Task<List<FileInfo>> IndexEligibleFilesAsync(...)
private Task<ScanFinding?> AnalyzeSingleFileAsync(...)
private Task<ConcurrentBag<ScanFinding>> RunDetectionPhaseAsync(...)
private Task<(List<ScanFinding>, ScanMetrics)> CommitResultsAsync(...)
```

No new files. No new namespaces. All additions are private members of the existing `ScanEngine` class.

## Suggested responsibilities

### `ScanState`

A private sealed record that holds all service instances and configuration values produced during `LoadConfiguration` and consumed by all subsequent phases.

Must include: `AppSettings`, `SignatureDatabase`, `LightweightYaraDatabase`, `EngineDependencies`, `DetectionPipeline`, `Sha256HashService`, `LocalReputationDatabase`, `ReputationEngine`, `HashSet<string>` for previous hashes, `DelegateScanLogger`, `ScanMetrics`, and the metric lock object.

Must expose an `Inc(Action<ScanMetrics>)` helper that acquires the lock before invoking the action, so that `AnalyzeSingleFileAsync` can increment metrics safely from parallel threads.

`qm` (QuarantineManager) and `quarantineLock` (SemaphoreSlim) must NOT be placed in ScanState — they are detection-phase scoped and created inside `RunDetectionPhaseAsync`.

### `LoadConfiguration`

Synchronous. Loads `AppSettings`, `SignatureDatabase`, `LightweightYaraDatabase`. Builds `EngineDependencies`, `DetectionPipeline`, `LocalReputationDatabase`, `ReputationEngine`. Loads previous hashes. Initializes `ScanMetrics` with signature and YARA counts. Returns `ScanState`. Must also keep `_settings` and `_signatures` instance fields in sync for compatibility with existing helper methods.

### `CollectGlobalContextAsync`

Collects persistence entries via `PersistenceCollector.Collect`. Extracts exact paths from persistence entries. Writes `Persistence_Report.txt`. Collects running process paths via `GetRunningProcessPaths`. Updates metrics for persistence items and running processes. Constructs and returns `ScanContext`.

### `IndexEligibleFilesAsync`

Resolves scan targets via `TargetDiscovery.ResolveTargets` and the custom target in `ScanOptions`. Applies extension filters, excluded path filters, and trusted path filters. Emits indeterminate progress while indexing. Returns `List<FileInfo>` of eligible files.

### `AnalyzeSingleFileAsync`

Contains the entire body of the current `Parallel.ForEachAsync` lambda. Receives all parameters needed to execute the per-file analysis without accessing any shared mutable state directly except through `state.Inc`. Returns a `ScanFinding` if the file meets the report threshold, or null if it is skipped at any gate.

### `RunDetectionPhaseAsync`

Creates `QuarantineManager` and `quarantineLock` (`SemaphoreSlim(1, 1)`, declared with `using`) internally — both have detection-phase scope and must not move into `ScanState`. Sets up `Parallel.ForEachAsync` options and the progress reporting local function. Calls `AnalyzeSingleFileAsync` for each file. Handles `OperationCanceledException` and general exceptions. Emits progress callbacks. Updates scan time metric. Returns `ConcurrentBag<ScanFinding>`.

### `CommitResultsAsync`

Orders findings by score and last write. Persists hash cache and reputation. Writes all four reports: CSV, TXT, HTML, JSON. Logs the final summary line. Returns the ordered `List<ScanFinding>` and the final `ScanMetrics`.

## Implementation phases

Execute in this exact order. Verify that the build passes after each step before proceeding to the next.

Phase 1: add the `ScanState` record inside `ScanEngine` without moving any logic yet. Confirm build passes.

Phase 2: implement `LoadConfiguration` extracting only the initialization block at the top of `RunAsync`. Replace those lines in `RunAsync` with `var state = LoadConfiguration(log)`. Confirm build passes.

Phase 3: implement `CollectGlobalContextAsync` extracting the persistence and process collection block. Replace those lines in `RunAsync` with the corresponding await call. Confirm build passes.

Phase 4: implement `IndexEligibleFilesAsync` extracting the target resolution and file enumeration block. Replace those lines in `RunAsync` with the corresponding await call. Confirm build passes.

Phase 5: implement `AnalyzeSingleFileAsync` with the full body of the `Parallel.ForEachAsync` lambda.

Phase 6: implement `RunDetectionPhaseAsync` wrapping the parallel loop and calling `AnalyzeSingleFileAsync`. Replace those lines in `RunAsync` with the corresponding await call. Confirm build passes.

Phase 7: implement `CommitResultsAsync` extracting the final persistence and reporting block. Replace those lines in `RunAsync` with the corresponding await call. Confirm build and tests pass.

## Testing requirements

- tests must pass without any modification to `DataVanger.Tests/Program.cs`;
- tests must pass without any modification to `DataVanger.Tests/DataVanger.Tests.csproj`;
- no new test files are required for this phase;
- run `dotnet run --project DataVanger.Tests/DataVanger.Tests.csproj` to validate.

## Acceptance criteria

- `RunAsync` body contains 15 lines or fewer after the refactoring;
- `AnalyzeSingleFileAsync` exists as a private method of `ScanEngine`;
- all seven private phase methods listed in the recommended structure exist;
- all existing private helpers listed in "existing behavior to preserve" are still present and unmodified;
- build passes with zero errors;
- test runner passes with identical results to baseline.

## Priorities

1. clean build
2. tests passing
3. move-only discipline — no logic changes
4. `RunAsync` reduced to an orchestrator
5. each phase method has a single responsibility
6. `AnalyzeSingleFileAsync` is independently callable
7. metric thread safety preserved

## Output ZIP name

```text
DataVanger V.Alpha_DECOMPOR_RUNASYNC_CLAUDE.zip
```

Before packaging, remove generated artifacts (bin/obj for every project) and any embedded ZIP files. Preserve `.gitignore` entries: `bin/`, `obj/`, `*.user`, `*.suo`, `.vs/`, `*.zip`.

---

## Re-engagement note (status: HELD — pending buildable environment)

This phase was intentionally NOT implemented in the current cloud session because that
environment cannot build or run the solution:

- no .NET SDK is installed;
- .NET SDK download hosts are blocked by the network allowlist (HTTP 403);
- the projects target `net8.0-windows` (WPF/WinForms) and require Windows to build.

A 461-line decomposition into 7 interdependent private methods involving closures
(`Inc`, `ReportProgress`), async/await + `ConfigureAwait`, `CancellationToken`
propagation, `SemaphoreSlim` lifetime/disposal, tuple return alignment, and
`Parallel.ForEachAsync` lambda binding is too high-risk to attempt without real-time
compiler feedback. Move-only discipline alone is not sufficient.

When re-engaging in a Windows/.NET environment, verify each of the following with the
compiler after every extraction step:

- variable scope capture in each private method;
- async/await patterns (`ConfigureAwait`, `WaitAsync` chains);
- tuple return type alignment `(List<ScanFinding>, ScanMetrics)`;
- parameter passing through `ScanState` and method signatures;
- `SemaphoreSlim` lifetime and disposal (kept inside `RunDetectionPhaseAsync`);
- `Parallel.ForEachAsync` lambda parameter binding;
- shared locals that straddle phases (notably `runningPaths`, `context`, and the
  profile-derived values `deep`, `minPreScore`, `sigThreshold`, `persThreshold`,
  `reportThreshold`) must be threaded explicitly as parameters/returns.

Baseline for re-engagement: current repository HEAD at commit `aa8650e`
(07_LINEENDINGS_LOCK), branch `claude/fervent-dirac-0ml0N`.
