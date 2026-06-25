# Sub-Phase Order — 09A_BEHAVIORAL_REPORT_ONLY

> **Status: PLANNED order, not yet executed.** This is a later-activation order produced by the Phase 09
> readiness plan. It activates the behavioral correlation engine in **report-only** mode only. It does
> not confirm malware, does not feed remediation, and does not run in Phase 09.

## 1. Title & engine
Bring the **behavioral correlation engine** online in report-only mode. One engine, this order only.

## 2. Dependency / prerequisite
Phase 09 readiness plan accepted; Phases 02B–05, 07, 08 complete and stable; baseline Alpha remains the
regression oracle. `09A` precedes `09B`/`09C`/`09D` only by sequencing, not coupling.

## 3. Reality rule
Report-only first. Behavioral evidence is heuristic/correlation evidence — it may **never** become
`ConfirmedMalware` and may **never** drive destructive action. A false-positive surge keeps the engine
report-only.

## 4. Engine inventory (current state)
- Legacy/dormant: `DataVanger/Behavioral/BehavioralEngine.cs` (test-only), `BehavioralCorrelationEngine.cs`,
  `BehavioralEventBus.cs`, `BehavioralRuleEngine.cs`, `BehavioralTimeline.cs`, `ProcessAncestry.cs`.
- Rules (5): `EncodedPowerShell`, `LolbinAbuse`, `OfficeSpawnsScript`, `SecurityTamper`,
  `PersistenceAfterDrop`. Monitors (3) under `DataVanger/Behavioral/Monitors/`.
- Runtime: `DataVanger.Engine/Behavioral/Runtime/BehavioralRuntimeBinding.cs` — complete, factory exists,
  **not instantiated** in the service, `PassiveMode=true`.
- Not present in `DataVanger/Engine/EngineComposition.cs` (the nine live modules).

## 5. Current anti-FP bound (must be preserved)
`SanitizeForFinding` forces `CanConfirmMalware=false` and `Strength→High`; this is double-enforced in
`AddEvidence`. Behavioral evidence is on the matrix "never confirm malware alone" list. This order keeps
both enforcements exactly as-is.

## 6. Current live-wiring status
Dormant. The runtime binding is constructed by a factory but never instantiated in
`DataVanger.Service`; no behavioral evidence reaches the live verdict path today.

## 7. Activation goal for this sub-phase
Instantiate `BehavioralRuntimeBinding` in **`PassiveMode`** and route its output to the **local history
store / diagnostics only**, marked report-only. Observe true/false positives in the field. Nothing else.

## 8. Strict scope (allowed)
- Instantiate the runtime binding behind a default-off/report-only flag.
- Emit report-only history/diagnostic entries (`HistoryEventKind.Detection`, report-only marker).
- Add report-only and FP-corpus tests.
- Add a soak-test harness and local telemetry counters.

## 9. Forbidden scope
- No verdict elevation (no `ConfirmedMalware`, no change to `CanConfirmMalware`).
- No remediation/quarantine feed; no `RemediationExecutionGate` wiring.
- No automatic action of any kind from behavioral evidence.
- No real AMSI registration, kernel minifilter, or self-protection.
- No activation of any other engine in this order.

## 10. Feature flag / readiness metadata
Guarded by the existing default-`false` `ActiveRealtimeProtectionRequested` (which already requires
`ServiceAvailable`), plus, if a finer-grained switch is wanted, a **new default-off
`BehavioralReportOnlyRequested`** flag added *in this order* (report-only semantics, validator-downgraded
when its prerequisites are missing). Default state observes nothing until explicitly enabled.

## 11. Evidence model & local telemetry
Behavioral findings are recorded as report-only observations with rule id, correlation window, process
ancestry summary, and a clamped `Strength ≤ High`. Telemetry stays **local** (history/diagnostics); no
network egress. No finding carries `CanConfirmMalware=true`.

## 12. FP-rate target & stop condition (binding)
- Target: an explicit upper bound on report-only behavioral events per benign-machine-day, plus a maximum
  benign-misclassification rate against the FP corpus.
- **Stop condition:** exceed the target in any soak window → engine **stays report-only**; promotion
  halted. (phase MD §14)

## 13. Soak-test corpus & duration
- Corpus: benign developer/admin activity, the LolBins the rules legitimately observe (powershell,
  wscript, office spawns), plus a labeled malicious-behavior set for true-positive observation.
- Duration: ≥ 14 days representative runtime (or equivalent replayed event volume), report-only throughout.

## 14. Performance budget & degradation behavior
- Budget: bounded event-bus throughput and correlation memory; added latency must stay within the runtime
  pipeline's existing envelope.
- Degradation: on budget breach, degrade and **report a degraded state**; never drop to unbounded mode,
  never escalate to action. Non-measurable degradation is itself a stop condition.

## 15. Policy integration criteria (deferred)
No policy feed in this order. A later, explicit gate may allow behavioral evidence to **raise visibility
only** (still `HighRisk`-clamped) after a passing soak under the FP target. Anti-FP contract preserved.

## 16. Remediation integration gate (deferred, forbidden here)
No remediation feed. Any future action gate requires: passing soak, FP target met, journal/rollback
design, IPC ACL security gate, and an explicit policy-gate pass — all out of scope for `09A`.

## 17. Required tests
- Existing `~Behavioral` and `BehavioralRuntimeBinding` tests remain green.
- New: report-only emission test (asserts no `ConfirmedMalware`, no remediation event); FP-corpus test;
  flag-default-off test; degraded-state test.
- `~AntiFalsePositive` must remain green and unchanged.

## 18. Manual validation checklist
- Diagnostics label the engine "report-only / observing", not "protected by".
- No tray/modal threat action is driven by behavioral evidence.
- Report-only events appear in history/diagnostics; no remediation is offered.

## 19. Stop conditions
- Engine activated into action mode; behavioral-only evidence can trigger destructive action; soak FP
  exceeds target; anti-FP tests regress; degradation not measurable; more than this one engine touched.

## 20. Exact success criteria
Behavioral engine runs report-only behind a default-off flag, emits clamped local telemetry, has a soak
+ FP harness with a binding stop condition, and **is not promoted to policy or action**. Explicitly: no
behavioral evidence becomes `ConfirmedMalware`, and no automatic action is possible.
