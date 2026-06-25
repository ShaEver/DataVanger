# DataVanger Phase 1: Baseline Telemetry Report

**Generated**: 2026-06-20  
**Phase**: 1 (Profiling & Telemetry Foundation)  
**Status**: Template / Pending Initial Benchmark Run  

---

## Overview

This report documents the **baseline performance metrics** for DataVanger's scan pipeline. The baseline establishes a quantitative reference point against which all subsequent optimization phases (Phases 2-12) can be measured. Without this baseline, regressions and improvements are invisible.

**Key Questions This Report Answers:**
1. How much time is spent in each stage (Enumeration, Hashing, Authenticode, Detection, Reputation, Quarantine)?
2. Which detector modules (Hash, Heuristic, Script, PE, Archive, Document, BrowserExt, YARA, Persistence) consume the most CPU time?
3. What is the tail behavior (P50, P95, Max) of per-file processing?
4. Are there pathological files (very slow) or file types (archives, documents) that dominate scan time?
5. What is the file discovery and enumeration overhead?

---

## Executive Summary

| Metric | Value | Notes |
|--------|-------|-------|
| **Profile** | Full | Comprehensive scan of all enabled modules |
| **Duration (Total)** | *pending* | Includes enumeration, hashing, detection, profiling overhead |
| **Duration (Scan Phase)** | *pending* | Excludes enumeration and post-processing |
| **Files Scanned** | *pending* | Eligible files counted as "files scanned" |
| **Throughput** | *pending* files/sec | Average across all stages |
| **Cold Cache** | *pending* | Initial run after system boot / cache flush |
| **Warm Cache** | *pending* | Subsequent run with OS I/O cache populated |

---

## Detailed Stage Breakdown

### Per-Stage Wall-Time Analysis

| Stage | Total Time (s) | File Count | Time/File (ms) | Files/sec | P50 (ms) | P95 (ms) | Max (ms) | Avg File Size |
|-------|---|---|---|---|---|---|---|---|
| Enumeration | *pending* | - | - | - | - | - | - | - |
| Hashing | *pending* | *pending* | *pending* | *pending* | *pending* | *pending* | *pending* | *pending* |
| Authenticode | *pending* | *pending* | *pending* | *pending* | *pending* | *pending* | *pending* | *pending* |
| ReputationEval | *pending* | *pending* | *pending* | *pending* | *pending* | *pending* | *pending* | *pending* |
| DetectionPipeline | *pending* | *pending* | *pending* | *pending* | *pending* | *pending* | *pending* | *pending* |
| Quarantine | *pending* | *pending* | *pending* | *pending* | *pending* | *pending* | *pending* | *pending* |

**Interpretation:**
- **Files/sec** shows throughput. Low files/sec (< 5) indicates a bottleneck.
- **P50** is the median per-file time. Half of files are processed faster, half slower.
- **P95** shows the tail: 95% of files complete within this time. High P95 vs P50 indicates skew (some files much slower).
- **Max** is the slowest single file. Extreme Max suggests pathological edge cases (archives, very large files).

---

## Detection Pipeline Module Breakdown

The DetectionPipeline consists of 9 independent detector modules. Each is invoked sequentially within the pipeline stage.

| Detector Module | Invocations | Avg Time (ms) | Total Time (s) | % of Pipeline | Cache Hits | Notes |
|---|---|---|---|---|---|---|
| Hash | *pending* | *pending* | *pending* | *pending* | *pending* | Known-good/known-bad lookups |
| Heuristic | *pending* | *pending* | *pending* | *pending* | - | Structural entropy, unusual imports |
| Script | *pending* | *pending* | *pending* | *pending* | - | Script injection, inline obfuscation |
| PE Module | *pending* | *pending* | *pending* | *pending* | - | Authenticode, imports, sections |
| Archive Handler | *pending* | *pending* | *pending* | *pending* | - | Zip bombs, recursive decompression |
| Document Inspector | *pending* | *pending* | *pending* | *pending* | - | Macro execution, embedded objects |
| BrowserExt Analyzer | *pending* | *pending* | *pending* | *pending* | - | Extension manifest, permissions |
| YARA Rules | *pending* | *pending* | *pending* | *pending* | - | Signature scanning |
| Persistence Checker | *pending* | *pending* | *pending* | *pending* | - | Startup, services, scheduled tasks |

**Interpretation:**
- **% of Pipeline** = (Total Time for Module) / (Total DetectionPipeline Time) × 100.
- High % indicates an optimization candidate for Phase 2+.
- **Cache Hits** (Hash module only) shows how many scanned files match known-good hashes → cached result, no need for full detection.

---

## Distribution Analysis: Per-File Processing Time

This section analyzes the distribution of individual file processing times. Files are grouped by percentile.

### Hashing Stage (Example Distribution)

```
P5th:    1 ms   (fastest 5%)
P25th:   5 ms
P50th:  12 ms   (median)
P75th:  25 ms
P95th:  85 ms   (slowest 5%)
P99th: 150 ms
Max:    250 ms  (pathological file: 500 MB binary archive)
```

**Interpretation:** The 250ms outlier suggests large files or archives dominate the tail. Investigating the max-time file can reveal optimization opportunities (e.g., archive depth limiting, size capping).

---

## File Type Analysis: Time Distribution by Extension

Top 10 file types consuming the most cumulative scan time.

| Extension | Count | Cumulative Time (s) | Avg Time (ms) | % of Total | Category |
|---|---|---|---|---|---|
| `.exe` | *pending* | *pending* | *pending* | *pending* | Binary/Executable |
| `.dll` | *pending* | *pending* | *pending* | *pending* | Binary/Executable |
| `.zip` | *pending* | *pending* | *pending* | *pending* | Archive |
| `.rar` | *pending* | *pending* | *pending* | *pending* | Archive |
| `.docx` | *pending* | *pending* | *pending* | *pending* | Document |
| `.ps1` | *pending* | *pending* | *pending* | *pending* | Script |
| `.msi` | *pending* | *pending* | *pending* | *pending* | Installer |
| `.sys` | *pending* | *pending* | *pending* | *pending* | Driver |
| `.scr` | *pending* | *pending* | *pending* | *pending* | Screensaver |
| `.ocx` | *pending* | *pending* | *pending* | *pending* | ActiveX |

**Interpretation:**
- Archives (.zip, .rar) and complex formats (.docx, .msi) typically take longer due to decompression and embedded scanning.
- Executables (.exe, .dll, .sys) incur Authenticode overhead if signed.
- Script files (.ps1) trigger Script module analysis.

---

## Directory Hotspots: Cumulative Time by Path

Top 10 directories consuming the most cumulative scan time. Identifies which folders dominate the scan profile.

| Directory Path | File Count | Cumulative Time (s) | Avg Time/File (ms) | % of Total |
|---|---|---|---|---|
| `C:\Program Files\...` | *pending* | *pending* | *pending* | *pending* |
| `C:\Windows\System32\` | *pending* | *pending* | *pending* | *pending* |
| `C:\Users\*\AppData\...` | *pending* | *pending* | *pending* | *pending* |
| `C:\Users\*\Downloads\` | *pending* | *pending* | *pending* | *pending* |
| *... other dirs ...* | | | | |

**Interpretation:** Large system directories (System32, Program Files) will naturally show high cumulative times due to volume. Per-file averages highlight scanning efficiency: if a directory's Avg Time/File is much higher than baseline, that path may have unusual files (archives, large binaries).

---

## Slowest Individual Files: Top 10 Pathological Cases

These are the 10 files that consumed the most wall-clock time during the scan. Understanding these files helps identify optimization targets.

| # | File Path | Size (MB) | Time (ms) | Extension | Detected Issues |
|---|---|---|---|---|---|
| 1 | *pending* | *pending* | *pending* | *pending* | Archive depth limit, decompression time |
| 2 | *pending* | *pending* | *pending* | *pending* | Large binary, many imports |
| 3 | *pending* | *pending* | *pending* | *pending* | Nested archive |
| 4-10 | *pending* | *pending* | *pending* | *pending* | *pending* |

**Interpretation:**
- If top slowest files are archives, consider Phase 2 optimization: depth limiting, early termination.
- If large system binaries dominate, consider Phase 2: parallel detection modules, caching per-module results.
- If document files dominate, consider Phase 2: sandboxed macro parsing, lazy embedding extraction.

---

## Problem Correlation Matrix

DataVanger's scan engine has 8 known structural problems (identified in Phase 0 analysis):

| Problem | Visible in Baseline? | Evidence | Optimization Phase |
|---------|---|---|---|
| **1. No per-stage parallelism** | ✅ / ❌ | High P95 in Detection stage? | Phase 2 |
| **2. I/O stalling on index discovery** | ✅ / ❌ | High Enumeration time vs file count? | Phase 3 |
| **3. Authenticode verification redone per file** | ✅ / ❌ | High Authenticode stage time, large .exe count? | Phase 4 |
| **4. Detection modules not parallelized** | ✅ / ❌ | High P95/Max in detection, many slow .exe/.dll? | Phase 5 |
| **5. Archive decompression unbounded** | ✅ / ❌ | Top slowest files are .zip/.rar/.7z? | Phase 6 |
| **6. YARA rule set not optimized** | ✅ / ❌ | High % in YARA module, many false scans? | Phase 7 |
| **7. OS cache not leveraged** | ✅ / ❌ | Warm cache run same speed as cold? | Phase 8 |
| **8. No CPU core utilization** | ✅ / ❌ | Low files/sec despite 8-core system? | Phase 9 |

**How to Use This Table:**
1. Check which problems are **confirmed** (Evidence: ✅) by the baseline data.
2. Problems with ❌ are not visible in baseline → may be false alarms or architectural assumptions.
3. Organize optimization phases by confirmed problems + highest impact.

---

## Cache Effectiveness Analysis

### Hash Cache (Known-Safe Lookups)

| Metric | Value | Notes |
|---|---|---|
| Files Scanned | *pending* | Total eligible files |
| Hash Cache Hits | *pending* | Files matching known-safe hashes |
| Hash Cache Hit Rate | *pending* % | (Cache Hits / Scanned) × 100 |
| Time Saved by Caching | *pending* s | Estimated time if all cache hits were rescanned |

**Interpretation:**
- High hit rate (> 50%) suggests most files are stable / system files. Good for warm-cache runs.
- Low hit rate (< 20%) suggests dynamic code or user-generated content. Optimize detection speed instead.

### Warm vs Cold Cache Performance

| Run Type | Total Time (s) | Files/sec | Cache Hit Rate | Improvement vs Cold |
|---|---|---|---|---|
| **Cold** | *pending* | *pending* | *pending* | baseline |
| **Warm** | *pending* | *pending* | *pending* | *pending* % |

**Interpretation:**
- If warm cache is **significantly faster** (> 20% improvement), Phase 8 should prioritize OS cache leveraging.
- If warm cache is **similar** to cold, OS page cache is not the bottleneck. Focus on algorithm efficiency instead.

---

## Baseline Verification Checklist

Before optimizations begin, verify that this baseline is **stable and representative**:

- [ ] **Build consistency**: Baseline built with Release configuration (no Debug symbols slowing I/O).
- [ ] **System state**: No antivirus scanning in parallel (would skew timings).
- [ ] **Cold cache**: First run after system boot or `ipconfig /flushdns` + cache clear.
- [ ] **Warm cache**: Subsequent run without intervening disk activity.
- [ ] **Stable set**: Same files scanned both runs (no additions/deletions).
- [ ] **JSON validity**: DataVanger_Telemetry.json parses without errors.
- [ ] **Telemetry enabled**: AppSettings.EnableDetailedTelemetry = true.
- [ ] **No regressions**: Baseline matches production behavior (no test harness artifacts).

---

## Instructions for Re-Running Baseline

To regenerate or update this baseline:

1. **Prepare the system:**
   ```powershell
   ipconfig /flushdns          # Clear DNS cache
   Clear-DiskCache -Force       # (Admin) Clear OS page cache
   Restart-Computer             # Or wait for natural idle
   ```

2. **Run the benchmark harness (cold cache):**
   ```powershell
   cd tools
   .\benchmark.ps1 -Profile Full -Count 2 -OutputDir ..\outputs\benchmarks
   ```

3. **Copy telemetry output:**
   ```powershell
   Copy-Item outputs\benchmarks\telemetry_Full_run1_*.json outputs\BASELINE_DATA.json
   ```

4. **Parse telemetry and update this report:**
   - Open `BASELINE_DATA.json` in VS Code.
   - Update all `*pending*` cells with actual values from JSON.
   - Recompute percentages and interpretations.

---

## Conclusion

This baseline establishes the **starting point** for DataVanger's performance journey. Phases 2-12 will implement targeted optimizations, each measured against these metrics.

**Success Criteria:**
- Each phase achieves ≥ 10% improvement in throughput or ≤ 10% regression in safety.
- No false-negative regressions (anti-FP contract remains unbroken).
- Cumulative end-of-phase-12 goal: **Full Scan ≤ 45 minutes** on typical Windows 10/11 system (vs current 6+ hours).

---

## References

- **Phase 0 Analysis**: Problems identified in antivirus architecture.
- **Phase 1 Plan**: Profiling & Telemetry Foundation (this document's justification).
- **ALTERACOES_BETA.md**: Detailed commit log of telemetry infrastructure.
- **ScanEngine.cs**: RunAsync() method (lines 1-900) defines 5-phase pipeline.
- **ScanStageProfiler.cs**: Per-stage and per-item metrics collection.
- **TelemetryReportGenerator.cs**: JSON schema and export logic.

---

**Report Maintainer**: Claude (optimization harness)  
**Last Updated**: 2026-06-20  
**Baseline Status**: ⏳ Awaiting initial benchmark run
