# Sub-Phase Order — 09B_PROTECTED_FILES_REPORT_ONLY

> **Status: PLANNED order, not yet executed.** This is a later-activation order produced by the Phase 09
> readiness plan. It activates the anti-ransomware / protected-files monitor in **report-only** mode only.
> It does not confirm malware, does not feed remediation, and does not run in Phase 09.

## 1. Title & engine
Bring the **anti-ransomware / protected-files activity monitor** online in report-only mode. One engine,
this order only.

## 2. Dependency / prerequisite
Phase 09 readiness plan accepted; `09A` design in place (sequencing only); Phases 02B–05, 07, 08 complete
and stable; baseline Alpha remains the regression oracle.

## 3. Reality rule
Report-only first. Protected-files activity is behavioral/heuristic evidence of *suspected* tamper — it
may **never** become `ConfirmedMalware` and may **never** drive destructive action. A false-positive
surge keeps the engine report-only.

## 4. Engine inventory (current state)
`DataVanger.Engine/ProtectedFiles/` (13 files): `ProtectedFilesActivityMonitor.cs`,
`ActivityScoringPolicy.cs`, `SafeResponsePolicy.cs`, `ProtectedFolderPolicy.cs`, `EntropyDeltaAnalyzer.cs`,
`ExtensionTransitionAnalyzer.cs`, `ProtectedFilesEvidenceFactory.cs`, and supporting types. Tests:
`DataVanger.Tests/ProtectedFilesTests.cs` (~395 lines, ~30 sub-checks). Not started in the live runtime;
constructed only by tests.

## 5. Current anti-FP bound (must be preserved)
Severity ceiling: `ProtectedFilesActivitySeverity.ProtectedActivitySuspected → RuntimeEventSeverity.High`
(`ProtectedFilesEvidenceFactory`). `ProtectedActivitySuspected` **requires ≥ 3 correlated categories**
(`ActivityScoringPolicy`). `SafeResponsePolicy` recommends only safe responses; there is no
`IsConfirmedMalware` path. This order keeps all of that exactly as-is.

## 6. Current live-wiring status
Dormant. No production code starts `ProtectedFilesActivityMonitor`; its output reaches no classifier and
no remediation today.

## 7. Activation goal for this sub-phase
Start the monitor under its existing flag in **report-only** mode and emit `ProtectedActivitySuspected`
observations to **local history / diagnostics only**. Observe protected-folder tamper signals in the
field. No safe-response recommendation is auto-executed; it is displayed only.

## 8. Strict scope (allowed)
- Start the monitor behind the existing default-off flag.
- Emit report-only history/diagnostic entries at `ProtectedActivitySuspected` (High) ceiling.
- Add report-only and FP-corpus tests; add a soak harness and local counters.
- Surface `SafeResponsePolicy` recommendations as **advice only** (never executed).

## 9. Forbidden scope
- No verdict elevation; no `ConfirmedMalware`; no new confirm path.
- No automatic protective action (no auto-block, auto-quarantine, no kill).
- No remediation/`RemediationExecutionGate` feed.
- No self-protection, kernel minifilter, or real AMSI.
- No activation of any other engine.

## 10. Feature flag / readiness metadata
Guarded by the existing **default-`false` `ProtectedFilesActivityRequested`**. The validator already
**downgrades it when `RuntimeEventPipelineEnabled` is false**, so the monitor cannot start without its
prerequisite. Default state: off. Enabling it grants observation + reporting only.

## 11. Evidence model & local telemetry
Report-only observations carry: protected folder, correlated category set (entropy delta, extension
transition, rate, ancestry), the ≥3-category gate result, and a clamped `High` severity. Telemetry is
**local**; no egress. No observation confirms malware.

## 12. FP-rate target & stop condition (binding)
- Target: upper bound on `ProtectedActivitySuspected` events per benign-machine-day; max benign
  misclassification rate against an FP corpus rich in legitimate bulk file operations (backups, archivers,
  encryptors, large builds, installers).
- **Stop condition:** exceed the target → engine **stays report-only**; promotion halted. (phase MD §14)

## 13. Soak-test corpus & duration
- Corpus: legitimate high-volume file activity (backup tools, 7-Zip/WinRAR, BitLocker/EFS, large git
  checkouts, compilers) for false-positive pressure, plus a labeled ransomware-like behavior set for
  true-positive observation.
- Duration: ≥ 14 days representative runtime (or equivalent replayed activity), report-only throughout.

## 14. Performance budget & degradation behavior
- Budget: the monitor's existing caps — ~12000 events/min, ~4096 tracked processes, ~10 min TTL — plus a
  bounded CPU/IO envelope.
- Degradation: on budget breach, degrade and **report a degraded state**; never drop to unbounded
  tracking, never escalate to action. Non-measurable degradation is a stop condition.

## 15. Policy integration criteria (deferred)
No policy feed here. A later explicit gate may let `ProtectedActivitySuspected` **raise visibility only**
(still High-clamped) after a passing soak under the FP target. Anti-FP contract preserved.

## 16. Remediation integration gate (deferred, forbidden here)
No remediation feed. Anti-ransomware response (e.g. blocking a tampering process) is high-risk and
explicitly deferred: it requires passing soak, FP target met, journal/rollback design, IPC ACL security
gate, and an explicit policy-gate pass — all out of scope for `09B`.

## 17. Required tests
- Existing `~ProtectedFiles` tests remain green.
- New: report-only emission test (asserts no `ConfirmedMalware`, no executed response, no remediation
  event); FP-corpus test over legitimate bulk operations; flag-default-off + validator-downgrade test;
  degraded-state test.
- `~AntiFalsePositive` remains green and unchanged.

## 18. Manual validation checklist
- Diagnostics label the monitor "report-only / observing".
- No tray/modal action and no file block is driven by protected-files evidence.
- `SafeResponsePolicy` advice is shown but never auto-applied.

## 19. Stop conditions
- Monitor activated into action mode; protected-files evidence can trigger destructive action; soak FP
  exceeds target; anti-FP tests regress; degradation not measurable; more than this one engine touched.

## 20. Exact success criteria
Protected-files monitor runs report-only behind the default-off `ProtectedFilesActivityRequested`, emits
`ProtectedActivitySuspected` (High) local telemetry, has a soak + FP harness with a binding stop
condition, and **is not promoted to policy or action**. Explicitly: no protected-files evidence becomes
`ConfirmedMalware`, and no automatic action is possible.
