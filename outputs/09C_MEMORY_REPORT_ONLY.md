# Sub-Phase Order — 09C_MEMORY_REPORT_ONLY

> **Status: PLANNED order, not yet executed.** This is a later-activation order produced by the Phase 09
> readiness plan. It activates the memory scanner in **report-only** mode only. It does not confirm
> malware, does not feed remediation, and does not run in Phase 09.

## 1. Title & engine
Bring the **memory scanner** online in report-only mode. One engine, this order only.

## 2. Dependency / prerequisite
Phase 09 readiness plan accepted; `09A`/`09B` design in place (sequencing only); Phases 02B–05, 07, 08
complete and stable; baseline Alpha remains the regression oracle.

## 3. Reality rule
Report-only first. Memory-scan evidence is heuristic — it may **never** become `ConfirmedMalware` and may
**never** drive destructive action. A false-positive surge keeps the engine report-only.

## 4. Engine inventory (current state)
`DataVanger/Memory/` — 14 core types (`IMemoryScanner`, `MemoryCorrelationEngine`, `MemoryEvidenceFactory`,
`MemoryFinding`, `MemoryRegionAnalyzer`, `MemoryBehavioralBridge`, …) + 8 rules + 3 readers. Tests:
`DataVanger.Tests/MemoryScannerTests.cs` (~360 lines, ~9 sub-checks). No production caller; exercised only
by tests. Not in `EngineComposition`.

## 5. Current anti-FP bound (must be preserved)
`MemoryFinding.CanConfirmMalware => false` (hard property). `MemoryEvidenceFactory` and
`MemoryCorrelationEngine` both set `CanConfirmMalware=false` and `Strength ≤ High`; evidence score is
ceilinged (`score > 6 → 6`). On the matrix "never confirm malware alone" list. This order keeps every
ceiling exactly as-is.

## 6. Current live-wiring status
Dormant. No production code constructs or calls a memory scan; no memory evidence reaches the live verdict
path today.

## 7. Activation goal for this sub-phase
Add a **bounded, report-only** memory-scan caller (e.g. opt-in deep inspection of an already-flagged
process) and route its findings to **local history / diagnostics only**. Observe in the field under the
existing resource bounds. No verdict elevation, no action.

## 8. Strict scope (allowed)
- Add a report-only memory-scan caller behind a default-off flag.
- Emit report-only history/diagnostic entries with `CanConfirmMalware=false`, `Strength ≤ High`,
  `score ≤ 6`.
- Add report-only and FP-corpus tests; add a soak harness and local counters.

## 9. Forbidden scope
- No verdict elevation; no `ConfirmedMalware`; no change to `CanConfirmMalware` or the score ceiling.
- No remediation/quarantine/process-kill feed.
- No always-on system-wide scanning (must stay bounded/opt-in).
- No self-protection, kernel minifilter, or real AMSI.
- No activation of any other engine.

## 10. Feature flag / readiness metadata
No dedicated flag exists today (the engine is dormant via "no caller"). Add a **new default-off
`MemoryScanReportOnlyRequested`** flag *in this order*, with report-only semantics and validator
downgrade when its prerequisites (bounded resources / supported OS) are unmet. Default state: off.

## 11. Evidence model & local telemetry
Report-only findings carry: target process, region summary, matched rule ids, and the clamped
`Strength ≤ High` / `score ≤ 6`. Telemetry is **local**; no egress. No finding confirms malware.

## 12. FP-rate target & stop condition (binding)
- Target: upper bound on report-only memory findings per benign-machine-day; max benign
  misclassification rate against an FP corpus of legitimate processes (JIT/.NET runtimes, packers used by
  legitimate software, browsers, game anti-cheat).
- **Stop condition:** exceed the target → engine **stays report-only**; promotion halted. (phase MD §14)

## 13. Soak-test corpus & duration
- Corpus: legitimate processes with executable/dynamic memory (managed runtimes, JITs, legitimately
  packed apps, browsers) for FP pressure, plus a labeled in-memory-malicious set for true-positive
  observation.
- Duration: ≥ 14 days representative runtime (or equivalent replayed scans), report-only throughout.

## 14. Performance budget & degradation behavior
- Budget: the engine's existing options — `MaxProcesses 64`, `MaxBytesPerRegion 256 KB`,
  `MaxTotalBytes 16 MB`, `OverallTimeout 30 s` — plus a bounded CPU envelope.
- Degradation: on budget/timeout breach, **stop early and report a degraded/partial state**; never lift
  the byte/time ceilings, never escalate to action. Non-measurable degradation is a stop condition.

## 15. Policy integration criteria (deferred)
No policy feed here. A later explicit gate may let memory evidence **raise visibility only** (still
High-clamped, score-ceilinged) after a passing soak under the FP target. Anti-FP contract preserved.

## 16. Remediation integration gate (deferred, forbidden here)
No remediation feed. Memory-driven process termination/quarantine is high-risk and explicitly deferred:
it requires passing soak, FP target met, journal/rollback design, IPC ACL security gate, and an explicit
policy-gate pass — all out of scope for `09C`.

## 17. Required tests
- Existing `~Memory` tests remain green.
- New: report-only emission test (asserts `CanConfirmMalware=false`, `score ≤ 6`, no remediation event);
  FP-corpus test over legitimate processes; flag-default-off test; budget/timeout degraded-state test.
- `~AntiFalsePositive` remains green and unchanged.

## 18. Manual validation checklist
- Diagnostics label the scanner "report-only / observing".
- No tray/modal action and no process kill is driven by memory evidence.
- Report-only findings appear in history/diagnostics; no remediation is offered.

## 19. Stop conditions
- Scanner activated into action mode; memory evidence can trigger destructive action; soak FP exceeds
  target; score ceiling or `CanConfirmMalware` changes; anti-FP tests regress; degradation not
  measurable; more than this one engine touched.

## 20. Exact success criteria
Memory scanner runs report-only behind a default-off flag, emits bounded local telemetry with
`CanConfirmMalware=false`/`score ≤ 6`, has a soak + FP harness with a binding stop condition, and **is not
promoted to policy or action**. Explicitly: no memory evidence becomes `ConfirmedMalware`, and no
automatic action is possible.
