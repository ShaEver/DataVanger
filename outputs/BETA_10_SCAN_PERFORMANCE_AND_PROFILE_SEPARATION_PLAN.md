# BETA 10 — SCAN PERFORMANCE PROFILING & FULL/DEEP PROFILE SEPARATION (PLANNING/JUDGMENT) REPORT

Phase: `BETA_10_SCAN_PERFORMANCE_AND_PROFILE_SEPARATION` (DataVanger V.Beta Improvement Plan)
Executed: 2026-06-14
Branch: `claude/bold-albattani-7o16j4`, on the latest stable DataVanger Beta baseline.

Verdict: **PLANNING / JUDGMENT ONLY. No dormant engine was activated. No scan behavior, profile,
threshold, anti-FP, YARA, quarantine, remediation, IPC, signed-update, or service behavior was
changed. Zero production code changed.** This deliverable is a written performance analysis plus a
planning-only implementation order for a dedicated scan-performance/profile-separation phase, plus a
judgment on its placement relative to `09A_BEHAVIORAL_REPORT_ONLY` and
`09B_PROTECTED_FILES_REPORT_ONLY`.

---

## 1. Files reviewed

- `DataVanger/Core/Models.cs` — `enum ScanProfile { Quick, Standard, Deep, Full }` (`:8`);
  `ScanProgressInfo` / `ScanMetrics` (counters, files/s, ETA).
- `DataVanger/Engine/TargetDiscovery.cs` — per-profile target resolution + dedup (`ResolveTargets`,
  `IsExcludedPath`).
- `DataVanger/Engine/ScanProfileRegistry.cs` — per-profile thresholds / detection-module gating.
- `DataVanger/Engine/DeepScan/DeepScanProfileSettings.cs` — per-profile ceilings (archive depth,
  file size, timeouts, DOP) (`Resolve`, `:93-215`).
- `DataVanger/Core/ScanEngine.cs` — 5-phase scan; pre-indexing (`IndexEligibleFilesAsync`,
  `:203-285`); detection phase + progress/ETA (`:580-659`); DOP default (`:584`).
- `DataVanger/Engine/DeepScan/` — `DeepScanOrchestrator.cs`, `Stages/HashingStage.cs`,
  `StreamHasher.cs`, `Stages/FileTypeIdentificationStage.cs`, `Stages/ArchiveExpansionStage.cs`,
  `ScanThrottle.cs`, `RecursionGuard.cs`, `DeepScanTelemetry.cs`.
- `DataVanger/Infrastructure/Sha256HashService.cs` — hash cache `(path, mtime, size)`.
- `DataVanger/Infrastructure/ResilientFileSystemService.cs` — BFS walker, reparse-point skip,
  access-denied callback.
- `DataVanger/MainWindow.xaml.cs` — UI progress throttle (250 ms), CPU/RAM sampling.
- `DataVanger/Core/Abstractions/IScanLogger.cs`, `DataVanger/Infrastructure/DelegateScanLogger.cs` —
  logging.
- `docs/MODULE_STATUS_MATRIX.md`, `outputs/00_REMAINING_PHASES_INDEX.md`,
  `outputs/BETA_09_LATER_DORMANT_ENGINE_ACTIVATION_REPORT.md`, `outputs/09A`/`09B`/`09C`/`09D_*.md`,
  `outputs/10_APPSETTINGS_SCHEMA_VERSIONING.md` — phase conventions and dormant-engine roadmap.

## 2. Files changed

- `outputs/BETA_10_SCAN_PERFORMANCE_AND_PROFILE_SEPARATION_PLAN.md` (new) — this document.
- `DataVanger/ALTERACOES_BETA.md` (appended) — Beta 10 planning/readiness entry.

**No `.cs`, `.csproj`, `.sln`, `.xaml`, settings, or test file was modified. No `bin/`, `obj/`,
`TestResults/`, or `Publicar/` was created or staged.**

## 3. Scan-profile inventory

| Profile | Targets | Archives | Office docs | Browser ext | ADS | Hash | Archive depth | Max file | Overall timeout |
|---|---|---|---|---|---|---|---|---|---|
| **Quick** | user-pref folders + Temp (startup/persistence/processes collected separately) | off | off | off | off | size-gated | 0 | 64 MB | 10 min |
| **Standard** | user profile + Program Files + ProgramData + drivers + Tasks | on (settings⊕options) | on | off | off | size-gated | 1 | 256 MB | 1 h |
| **Deep** | **all fixed drive roots** + ~18 nested folders | on | on | on | configurable | size-gated | 3 | 1 GB | 6 h |
| **Full** | **all fixed drive roots** + ~18 nested folders (**identical to Deep**) | on | on | on | configurable | size-gated | 6 | 4 GB | **none (unbounded)** |

Source: `Models.cs:8`, `TargetDiscovery.cs:27-99`, `DeepScanProfileSettings.cs:93-215`,
`ScanProfileRegistry.cs`.

## 4. Full Scan scope judgment

Confirmed in `TargetDiscovery.cs:27-64`: Full (and Deep) intentionally include every ready **fixed
drive root** (`C:\`, …) via `DriveInfo.GetDrives()`, **plus** ~18 explicit nested folders that are
already inside `C:\` (Startup×2, Tasks×2, drivers, Downloads, Desktop, Documents, Temp×2, AppData,
LocalAppData, ProgramData, Program Files×2, 5 browser-extension roots). Dedup is exact-string only
(`Distinct(StringComparer.OrdinalIgnoreCase)`, `:99`) with **no prefix subsumption**, so the nested
targets are **not removed** when `C:\` is present — both `C:\` and `C:\Users\…\Downloads` survive and
each subtree is walked independently. The user's log ("Indexando: C:\" then the nested folders) is
exactly this redundant list. Indexing appends each file with no per-file dedup, so files under the
busiest nested trees (AppData, ProgramData, Program Files, Downloads) are **enumerated and indexed
twice**, inflating the 174,862 eligible count and doubling enumeration + filtering work on the highest-
volume directories. Per-file SHA-256 dedup happens downstream and does not prevent the double-walk.

**Judgment: Full Scan scope is redundant. Target deduplication is insufficient (exact-string only,
no canonical prefix subsumption).**

## 5. Performance interpretation of the user test

- 144,645 files / 18,274 s ≈ **7.9 files/s**; 174,862 at that rate ≈ 22,100 s ≈ **6.1 h**. The UI
  numbers are internally consistent when elapsed time is read as **seconds** (18,274 s), confirming the
  82.7% progress and ~1 h 2 m ETA.
- **0 hashes / 0 lightweight YARA / real-YARA compiled 0 rules → lightweight fallback.** So the
  slowness is **not** signature/YARA workload.
- **33% CPU on 4 threads** ⇒ workers are stalling on I/O, not CPU-bound. 569 MB RAM is fine.
- ~5–6× slower than Defender by raw file count (~46 files/s) on the same machine — not proof of a
  defect (DataVanger may do heavier per-file work), but a strong signal that Full is behaving like a
  Deep scan and needs profiling.

Structural cost drivers (code-grounded): per-file SHA-256 on every eligible file
(`HashingStage.cs`/`StreamHasher.cs`); multiple separate stream opens per file (type-sniff 32 B, full
hash read, PE parse…) → I/O amplification; redundant double-walk of nested targets; Deep-level
analysis (archive depth 6, Office, ADS, PE entropy) across the entire `C:\` scope with trusted-path
skip disabled on Full/Deep and no downgrade for high-volume low-signal trees; and **no detection-
result cache** (only a hash cache), so unchanged files are fully re-analyzed every scan.

## 6. Is DataVanger currently too slow for Full Scan?

**Yes — for a *Full* scan.** ~6 h for 175k files is impractical and is driven by structural per-file
and I/O cost, not signatures (which were zero). It is only "acceptable" under the interpretation that
Full is currently a Deep scan — which it is. As a broad, optimized, cache-aware Full scan it is too
slow.

## 7. Do Full and Deep need clearer separation?

**Yes.** Today Full = Deep + larger ceilings (archive depth 6 vs 3, 4 GB vs 1 GB, no time cap vs 6 h,
bigger caps) with **identical scope and identical detection modules**. Full ⊇ Deep in work. The
intended product distinction — Full = broad but optimized/cache-aware with heavy analysis gated by
file type/risk; Deep = expensive opt-in (full hashing, deep archive/Office/script internals, broader
heuristics) behind an explicit warning — is not reflected in code and should be implemented.

## 8. Is target deduplication missing or insufficient?

**Insufficient.** Only exact-string `Distinct`. Add canonical **prefix-subsumption**: after
`Path.GetFullPath`, drop any target that is a descendant of another retained target (so `C:\` subsumes
all nested entries). This removes ~17 redundant subtree walks under Full/Deep.

## 9. Is cache missing or insufficient?

**Insufficient.** A persistent hash cache keyed `(path, LastWriteTimeUtc.Ticks, Length)` exists
(`Sha256HashService.cs`, 250k cap). There is **no detection-result / clean-file cache** — the full
detection pipeline re-runs every file on every scan even when unchanged. A result cache keyed on
`(path, mtime, size)`, always bypassed for known-malicious-hash and confirmed-YARA/signature checks,
is the largest safe repeat-scan win.

## 10. Is 4-thread parallelism justified?

**Only as a conservative default, not as a fixed ceiling.** Default is
`Math.Clamp(Environment.ProcessorCount/2, 2, 6)` legacy / `…,2,8)` deep (`ScanEngine.cs:584`,
`DeepScanProfileSettings.cs:98`); the "4 thread(s)" log is this default on an ~8-core machine. 33% CPU
shows headroom on this (likely SSD) machine, but raising the count blindly risks HDD thrash, UI jank,
and thermal throttling. `ScanThrottle` is a fixed semaphore + constant `Task.Delay` with no adaptive
I/O/CPU/thermal feedback. ⇒ Make parallelism **adaptive** (storage-type aware, back off on
contention), keeping the current count as a safe floor.

## 11. Is UI/log telemetry sufficient?

**No.** UI throttling is fine (≥250 ms `MainWindow.xaml.cs:454`; engine progress every 5 files
`ScanEngine.cs:647`; logging synchronous but cheap). Reported metrics are totals + aggregate counters
(`ScanMetrics`) + files/s + ETA + global CPU/RAM + current file + profile. **Missing:** per-stage time
breakdown (enumeration / hashing / PE / script / archive / Office / YARA / persistence / process
collection), cache hit/miss rate, slowest paths/types, top slow directories, and skipped-file category
visibility. `DeepScanTelemetry.cs` has stage **counters** but is **not wired** into the live scan path
and has no timing. Without this, optimizing is guesswork — which is the core justification for the
phase.

## 12. Recommended phase name

**`BETA_10_SCAN_PERFORMANCE_AND_PROFILE_SEPARATION`.**
- **Option A `09C_PERFORMANCE_…` rejected:** `09C` already exists (`09C_MEMORY_REPORT_ONLY.md`) and
  the `09x` namespace is reserved for dormant-engine report-only orders — performance is not a dormant
  engine (collision **and** wrong category).
- **Literal Option B `10_SCAN_PERFORMANCE…` rejected:** plain `10` is owned by
  `10_APPSETTINGS_SCHEMA_VERSIONING.md`.
- **Recommended = Option C (standalone phase)** carrying Option B's descriptive title under the active
  Beta numbering (`BETA_00…BETA_09` → `BETA_10` is free and unambiguous).

## 13. Recommended phase placement

**Before `09A`** (and therefore before `09B`).

## 14. Recommended relationship to 09A and 09B

- The ~6 h Full Scan is a current, user-facing Beta defect independent of any dormant engine and
  merits priority on its own.
- The per-stage profiling instrumentation is **foundational tooling**: the only way to measure the
  runtime cost that `09A` (behavioral report-only) and especially `09B` (protected-files report-only,
  which adds runtime file-event monitoring) will add. Building the baseline first makes any
  `09A`/`09B` regression attributable rather than entangled with an un-profiled scan.
- The order explicitly flags that `09B` could worsen scan/runtime performance, so profiling must
  precede `09B` at minimum; placing it before `09A` is the cleaner, lower-risk sequencing.
- Recommended order: **`BETA_10` (profile/instrument) → `09A` (re-measure) → `09B` (re-measure) →
  `09C`/`09D` → later dormant-engine activation.**

## 15. Full proposed order for `BETA_10` (PLANNING-ONLY)

1. **Profiling instrumentation** — wire `DeepScanTelemetry` into the live scan path; add a
   `StageProfiler` for per-stage wall-time + counts, off by default behind a diagnostics flag.
2. **Per-stage timing** — enumeration, hashing, PE, script, archive, Office, YARA, persistence,
   process collection, cache lookup; plus cache hit/miss, skipped, access-denied, oversized-skipped.
3. **Slow-path reporting** — top slow paths, slowest file types, highest-cumulative-time directories,
   surfaced in the scan report (not per-file UI spam).
4. **Target deduplication** — canonical prefix-subsumption in `TargetDiscovery.ResolveTargets`; add a
   regression test proving `C:\` subsumes its nested targets.
5. **Scan profile separation** — recalibrate Full (broad, optimized, cache-aware, heavy analysis gated
   by type/risk) vs Deep (expensive opt-in, explicit warning). No threshold/anti-FP change; only
   work-gating and ceilings.
6. **Cache strategy** — add a detection-result/clean-file cache keyed `(path, mtime, size)` with
   explicit invalidation; **always bypassed** for known-malicious-hash and confirmed-signature checks.
7. **Expensive-analysis gating** — gate PE-entropy / archive / Office / ADS by file type + risk so
   Full does heavy work only when justified; Deep keeps full depth.
8. **Archive/Office depth limits** — confirm/parameterize per-profile caps; Full optimized uses sane
   (not maximal) depths; Deep keeps deep.
9. **High-volume low-signal handling** — downgrade/skip `node_modules`, package/NuGet/npm caches,
   build outputs, browser caches — **never silently**; counted and shown; never security locations.
10. **Adaptive parallelism** — storage-type-aware worker count; back off on I/O saturation / UI
    pressure / thermal; keep current count as the safe floor default.
11. **UI update throttling** — keep/confirm 250 ms + 5-file gates; ensure current-file dispatch is not
    per-file.
12. **Logging throttling** — keep logging off the hot path.
13. **Regression tests** — `~Scan`, `~Performance`, `~Profile`, `~AntiFalsePositive`, `~Quarantine`
    stay green; new tests for dedup, cache invalidation, profile gating, skipped-file visibility.
14. **Manual benchmarking protocol** — repeatable Full/Deep runs, cold/warm cache, SSD vs HDD; record
    files/s + per-stage split.
15. **Stop conditions** — abort if anti-FP weakens, a security location is silently skipped, skipped
    files are hidden, or a malicious-hash / confirmed-YARA check could be bypassed.

**Forbidden in `BETA_10`:** weaken anti-FP; silently skip security locations; hide skipped files;
bypass known-malicious-hash or confirmed-YARA/signature checks; reduce safety for speed; silently
exclude risky file types; change quarantine/remediation semantics; add destructive behavior; change
dormant-engine activation policy.

## 16. No dormant engine activated — explicit statement

**No dormant engine was activated, silently or otherwise.** Behavioral, protected-files, memory, and
ETW-correlation engines remain dormant; all readiness flags remain default-off; the live verdict path
is still the nine composed modules in `DataVanger/Engine/EngineComposition.cs`.

## 17. No scan behavior changed — explicit statement

**No scan behavior, scope, profile, threshold, anti-FP policy, YARA, quarantine, remediation, IPC,
signed-update, or service behavior was changed.** This phase is documentation/planning only; no code
changes were required.

## 18. Risks and open questions

- **HDD vs SSD** on the test machine is unknown; it changes the adaptive-parallelism and I/O
  conclusions. Resolved by the `BETA_10` instrumentation, not assumable now.
- The exact split between enumeration / hashing / per-stage analysis and the true magnitude of the
  double-walk are **hypotheses pending instrumentation** — precisely why profiling must come before any
  optimization.
- Profile separation (step 5) and expensive-analysis gating (step 7) touch detection work-gating;
  every change must preserve the anti-FP contract and never bypass malicious-hash / confirmed-YARA
  checks. These are approval-sensitive and should be Codex-stabilized when implemented.

## 19. Final recommendation / status

**Performance phase RECOMMENDED — created as `BETA_10_SCAN_PERFORMANCE_AND_PROFILE_SEPARATION`,
placed BEFORE `09A_BEHAVIORAL_REPORT_ONLY` (and necessarily before
`09B_PROTECTED_FILES_REPORT_ONLY`).** Profiling instrumentation and Full/Deep separation are
prerequisites for both a practical Full scan and for measuring the runtime cost that later dormant-
engine sub-phases add. No dormant engine was activated; no scan behavior was changed.
