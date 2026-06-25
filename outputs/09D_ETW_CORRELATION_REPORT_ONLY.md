# Sub-Phase Order — 09D_ETW_CORRELATION_REPORT_ONLY

> **Status: PLANNED order, not yet executed.** This is a later-activation order produced by the Phase 09
> readiness plan. It activates ETW behavioral correlation in **report-only** mode only. It does not
> confirm malware, does not feed remediation, and does not run in Phase 09.

## 1. Title & engine
Bring **ETW behavioral correlation** online in report-only mode: feed real ETW runtime telemetry into the
behavioral engine as report-only evidence. One engine, this order only.

## 2. Dependency / prerequisite
Phase 09 readiness plan accepted; **`09A_BEHAVIORAL_REPORT_ONLY` should land first**, because ETW feeds
the behavioral correlation engine — ETW evidence inherits the behavioral clamp. Phases 02B–05, 07, 08
complete; baseline Alpha remains the regression oracle.

## 3. Reality rule
Report-only first. ETW/AMSI events are telemetry that "never confirm malware alone"; routed through the
behavioral engine they remain `HighRisk`-clamped. They may **never** become `ConfirmedMalware` and may
**never** drive destructive action. A false-positive surge keeps the engine report-only.

## 4. Engine inventory (current state)
- Real provider: `DataVanger.Infrastructure/Etw/WindowsEtwRuntimeProvider.cs` (TraceEvent; Windows-validated
  in Phase 17), `EtwProviderFactory.cs` (4-gate), `NullEtwRuntimeProvider`/`InMemoryEtwRuntimeProvider`
  (fallback). Service host: `DataVanger.Service/Runtime/EtwRuntimeProviderHost.cs`.
- Adapters: `DataVanger/Behavioral/Adapters/EtwBehaviorProvider.cs` and `AmsiBehaviorAdapter.cs` — both
  **Stub** (`IsAvailable => false`). This is the dormancy gap: even with telemetry on, the Stub adapter
  delivers nothing to behavioral correlation.
- Service flag: `DataVangerServiceConfiguration.EnableEtwRuntimeTelemetry` (default false).

## 5. Current anti-FP bound (must be preserved)
ETW/AMSI events are on the matrix "never confirm malware alone" list. Evidence flows only through the
behavioral engine, whose `SanitizeForFinding`/`AddEvidence` force `CanConfirmMalware=false` and
`Strength→High`. The real provider already forces external/runtime evidence non-confirming. This order
keeps all of that exactly as-is.

## 6. Current live-wiring status
Dormant on two counts: the real provider is gated default-`Disabled` (`EtwTelemetryRequested` /
`EnableEtwRuntimeTelemetry` both off), **and** the behavior adapter is a Stub, so no ETW event reaches
behavioral correlation today.

## 7. Activation goal for this sub-phase
Replace the Stub `EtwBehaviorProvider` with a **real, still report-only** ETW→behavioral feed, enabled
only under the existing default-off telemetry flag and only when the provider gates pass. Routed evidence
is **report-only** (behavioral clamp applies) and sinks to local history/diagnostics. AMSI stays Stub
(real AMSI registration is explicitly forbidden).

## 8. Strict scope (allowed)
- Implement a real ETW→behavioral adapter behind `EtwTelemetryRequested` + provider gates.
- Emit report-only behavioral observations sourced from ETW; local telemetry only.
- Add report-only and FP-corpus tests; add a soak harness and local counters.

## 9. Forbidden scope
- No real AMSI provider registration (`AmsiBehaviorAdapter` stays Stub).
- No verdict elevation; no `ConfirmedMalware`; no change to the behavioral clamp.
- No remediation/quarantine feed.
- No kernel minifilter, self-protection, or self-update.
- No activation of any other engine; do not enable the provider by default.

## 10. Feature flag / readiness metadata
Guarded by the existing **default-`false` `EtwTelemetryRequested`** (validator requires
`EtwProviderSupported`, i.e. Windows) plus the service-level `EnableEtwRuntimeTelemetry` (default false)
and the `EtwProviderFactory` 4-gate. Default: off and Null/InMemory fallback. Enabling grants observation
+ reporting only.

## 11. Evidence model & local telemetry
Report-only behavioral observations sourced from ETW carry: provider/event id, correlated rule id,
process context, and the behavioral `Strength ≤ High` clamp. Telemetry is **local**; no egress. No
observation confirms malware.

## 12. FP-rate target & stop condition (binding)
- Target: upper bound on ETW-sourced report-only behavioral events per benign-machine-day; max benign
  misclassification rate against an FP corpus of legitimate process/PowerShell/admin ETW activity.
- **Stop condition:** exceed the target → engine **stays report-only**; promotion halted. (phase MD §14)

## 13. Soak-test corpus & duration
- Corpus: legitimate ETW-heavy activity (admin scripts, package managers, CI agents, scheduled tasks) for
  FP pressure, plus a labeled malicious-runtime set for true-positive observation.
- Duration: ≥ 14 days representative runtime (or equivalent replayed ETW sessions), report-only throughout.

## 14. Performance budget & degradation behavior
- Budget: bounded ETW session throughput and correlation memory; the provider must not destabilize the
  host. Honor the existing provider gates and disposal path.
- Degradation: on session loss or budget breach, **fall back to Null/InMemory and report a degraded
  state**; never escalate to action. Non-measurable degradation is a stop condition.

## 15. Policy integration criteria (deferred)
No policy feed here. A later explicit gate may let ETW-sourced behavioral evidence **raise visibility
only** (still High-clamped) after a passing soak under the FP target. Anti-FP contract preserved.

## 16. Remediation integration gate (deferred, forbidden here)
No remediation feed. Runtime-evidence-driven action is high-risk and explicitly deferred: it requires
passing soak, FP target met, journal/rollback design, IPC ACL security gate, and an explicit policy-gate
pass — all out of scope for `09D`.

## 17. Required tests
- Existing `~Etw` tests (provider, AMSI-stub, service telemetry) remain green.
- New: real-adapter report-only emission test (asserts behavioral clamp, no `ConfirmedMalware`, no
  remediation event); FP-corpus test; flag-default-off + provider-gate test; degraded/fallback-state test.
- `~AntiFalsePositive` remains green and unchanged.

## 18. Manual validation checklist
- Diagnostics label ETW correlation "report-only / observing"; provider state (real vs fallback) is shown
  honestly.
- No tray/modal action is driven by ETW evidence; AMSI remains a stub.
- Report-only events appear in history/diagnostics; no remediation is offered.

## 19. Stop conditions
- Provider enabled by default or activated into action mode; ETW evidence can trigger destructive action;
  real AMSI registered; soak FP exceeds target; behavioral clamp changes; anti-FP tests regress;
  degradation not measurable; more than this one engine touched.

## 20. Exact success criteria
ETW behavioral correlation runs report-only behind the default-off `EtwTelemetryRequested` + provider
gates, feeds the behavioral engine as `HighRisk`-clamped local telemetry, keeps AMSI a stub, has a soak +
FP harness with a binding stop condition, and **is not promoted to policy or action**. Explicitly: no ETW
evidence becomes `ConfirmedMalware`, and no automatic action is possible.
