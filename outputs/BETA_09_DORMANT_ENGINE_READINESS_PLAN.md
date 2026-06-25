# BETA 09 — Dormant-Engine Readiness Plan

Phase: `09_LATER_DORMANT_ENGINE_ACTIVATION` (DataVanger V.Beta Improvement Plan)
Executed: 2026-06-14
Branch/checkpoint: `claude/confident-gates-f355wn`, on the Phase-07-stabilized baseline (HEAD `369032a`).

> **This is a PLANNING / READINESS phase, not an activation phase.** Despite the phase name, no
> dormant engine is activated here. The deliverable is a readiness inventory plus four report-only
> sub-phase orders (`09A`–`09D`) that decompose later activation into one-engine-per-phase,
> report-only-first work with binding soak/FP gates. **Zero production code changed in Phase 09.**
> All four engines remain dormant, all readiness flags remain default-off, and the anti-false-positive
> contract is untouched.

---

## 1. Why this is planning-only (containment rationale)

The repository already ships everything a safe later activation needs, and all of it is already in the
safe position:

- **A default-off readiness flag framework** — `DataVanger.Shared/Settings/DataVangerSettings.cs`
  already declares per-capability request flags (`ActiveRealtimeProtectionRequested`,
  `EtwTelemetryRequested`, `ProtectedFilesActivityRequested`, `AutomaticQuarantineRequested`,
  `AutomaticQuarantineForNonConfirmedMalwareRequested`, `SelfProtectionRequested`), every one of them
  **default `false`**.
- **A fail-safe validator** — `DataVangerSettingsValidator.Validate` downgrades any request that lacks
  its prerequisite (service availability, ETW provider support, runtime event pipeline) and **forces
  `AutomaticQuarantineForNonConfirmedMalwareRequested` off as INVALID**, with the message that it is
  "downgraded to ConfirmedMalware-only".
- **Structural anti-FP ceilings inside each dormant engine** (see §3) so that even if an engine were
  switched on, its evidence cannot reach `ConfirmedMalware` and cannot authorize automatic action.
- **A verdict gate that confirms malware only from a known-malicious hash or a confirmed signature** —
  `ThreatClassificationPolicy.Classify` / `AntiFalsePositivePolicy`.

Because the safe machinery already exists and is already in the off/clamped position, the correct and
lowest-risk way to satisfy this phase is to **write the activation orders, not perform the activation**.
No new feature flag is required (the repo already has the right ones), so none was added. Adding code
now would create activation/FP/build risk for zero phase benefit.

## 2. Dormant-engine inventory

Four engines are "exist + tested but not in the live verdict path". Each is dormant in a different way.

| Engine | Code location | Dormancy mechanism | Readiness flag (default) | Anti-FP ceiling |
|---|---|---|---|---|
| **Behavioral correlation** | `DataVanger/Behavioral/*` (legacy `BehavioralEngine`, `BehavioralCorrelationEngine`, `BehavioralEventBus`, `BehavioralRuleEngine`, `BehavioralTimeline`, `ProcessAncestry`, 5 `Rules/`, 3 `Monitors/`) + `DataVanger.Engine/Behavioral/Runtime/BehavioralRuntimeBinding.cs` | Not in `EngineComposition`; runtime binding is built by a factory but **not instantiated** in the service; `PassiveMode=true` | none dedicated — gated by `ActiveRealtimeProtectionRequested` (false) + runtime not instantiated | `SanitizeForFinding` forces `CanConfirmMalware=false`, `Strength→High`; double-enforced in `AddEvidence` |
| **Anti-ransomware / protected-files** | `DataVanger.Engine/ProtectedFiles/*` (13 files incl. `ProtectedFilesActivityMonitor`, `ActivityScoringPolicy`, `SafeResponsePolicy`, `ProtectedFolderPolicy`, `EntropyDeltaAnalyzer`, `ExtensionTransitionAnalyzer`, `ProtectedFilesEvidenceFactory`) | Not started in the live runtime; constructed only by tests | `ProtectedFilesActivityRequested` (false); validator also requires `RuntimeEventPipelineEnabled` | Severity ceiling `ProtectedActivitySuspected → RuntimeEventSeverity.High`; never `IsConfirmedMalware`; `ProtectedActivitySuspected` requires ≥3 correlated categories |
| **Memory scanner** | `DataVanger/Memory/*` (14 core incl. `IMemoryScanner`, `MemoryCorrelationEngine`, `MemoryEvidenceFactory`, `MemoryFinding`, `MemoryRegionAnalyzer`, `MemoryBehavioralBridge` + 8 rules + 3 readers) | No production caller; exercised only by tests | none dedicated — no live caller; bounded options | `MemoryFinding.CanConfirmMalware => false`; `MemoryEvidenceFactory`/`MemoryCorrelationEngine` set `CanConfirmMalware=false`, `Strength ≤ High`; evidence score clamped ≤ 6 |
| **ETW behavioral correlation** | `DataVanger.Infrastructure/Etw/WindowsEtwRuntimeProvider.cs` (+ `EtwProviderFactory` 4-gate, `Null`/`InMemory` providers), `DataVanger.Service/Runtime/EtwRuntimeProviderHost.cs`, adapters `DataVanger/Behavioral/Adapters/{EtwBehaviorProvider,AmsiBehaviorAdapter}.cs` | Real provider gated default-Disabled; **behavior adapter is a Stub** (`IsAvailable => false`), so even with telemetry on, nothing reaches behavioral correlation | `EtwTelemetryRequested` (false); validator requires `EtwProviderSupported`; service flag `EnableEtwRuntimeTelemetry` (false) | ETW events "never confirm malware alone"; flows only through the behavioral engine, which itself clamps to High |

The active verdict path is unaffected: `DataVanger/Engine/EngineComposition.cs` composes exactly nine
modules — Hash, Heuristic, Script, PE, Archive, Document, BrowserExtension, Yara, Persistence. None of
the four engines above is in that set.

> Note: `docs/MODULE_STATUS_MATRIX.md` is Alpha-era and still lists the HTTP update transport as a
> Stub; Phase 08 superseded that. Its **anti-FP contract section and its memory/behavioral/ETW dormancy
> entries remain accurate** and are the authority used here.

## 3. Anti-false-positive contract (the invariant every sub-phase must preserve)

Source: `DataVanger/Core/ThreatClassificationPolicy.cs` (`Classify`, `AllowsAutomaticAction`) +
`DataVanger/Classification/AntiFalsePositivePolicy.cs`.

- `ConfirmedMalware` **only** from `IsBlacklisted` (known-malicious hash) **or** `HasConfirmedSignature`
  (confirmed YARA). Nothing else.
- Heuristic / behavioral / memory / ETW / AMSI evidence **clamps to `HighRisk` maximum**;
  `CanConfirmMalware=false` is enforced at the evidence boundary of each engine.
- **Automatic action only for `ConfirmedMalware`.** `AutomaticQuarantineForNonConfirmedMalwareRequested`
  is forced off by the validator.
- The matrix's explicit "never confirm malware alone" list includes behavioral correlation, ETW events,
  AMSI events, and memory-scanner evidence.

**Every sub-phase order in this plan inherits this contract verbatim and may not weaken it.** A
report-only engine produces local telemetry/history entries only; it never raises a verdict tier and
never feeds remediation.

## 4. Report-only strategy (applies to all four sub-phases)

1. **Default-off readiness flag.** Each engine's activation is guarded by an existing default-`false`
   flag (or, where one is not yet present, a new default-off/report-only flag added *in that sub-phase*,
   never here). The flag only enables **observation + local reporting**, never action.
2. **Report-only sink.** Engine output is written to the local history store / diagnostics only
   (`HistoryEventKind.Detection` at most, marked report-only), never to the classifier, never to
   `RemediationExecutionGate`.
3. **No verdict elevation.** Report-only evidence keeps `CanConfirmMalware=false` and cannot move a
   finding to `ConfirmedMalware`; the engine cannot author an auto-quarantine.
4. **UI honesty.** Diagnostics label the engine "report-only / observing", never "protected by".
5. **One engine at a time.** `09A`→`09B`→`09C`→`09D` are sequential; no change activates two engines.

## 5. Soak-test strategy (binding before any promotion)

- **Corpus:** a benign/representative workload corpus (clean developer machine activity, common admin
  tooling, the LolBins the rules legitimately observe, large file operations for the protected-files and
  memory budgets) plus a labeled malicious-behavior corpus for true-positive observation. The corpus is
  defined per engine in its sub-phase order.
- **Duration:** a minimum continuous soak window per engine (recommended ≥ 14 days of representative
  runtime, or an equivalent replayed event volume) during which the engine is **report-only**.
- **Exit criterion:** promotion to any higher integration (policy feed, then — much later — action) is
  **blocked** until the soak completes under the FP-rate target with no stop-condition trip.
- Soak runs are observation-only: a soak failure changes the plan, never the user's protection state.

## 6. False-positive rate targets & stop conditions (binding)

- Each sub-phase declares an explicit **FP-rate target** (e.g. an upper bound on report-only events per
  benign-machine-day, and a maximum benign-event misclassification rate against the FP corpus).
- **Stop condition (binding):** if a soak run exceeds the FP-rate target, the engine **stays report-only**
  — it is not promoted, and any in-flight promotion order is halted. This mirrors phase MD §14
  ("Any soak test exceeds FP-rate target" → stop) and §6 ("Ship an engine to automatic action if FP-rate
  target is missed" → forbidden).
- A FP-rate breach is a non-event for the user: the engine was already report-only, so nothing
  regresses; only the promotion is denied.

## 7. Performance budget & degradation behavior

- Each engine carries a measurable budget (CPU %, added scan latency, memory ceiling, event-throughput
  cap). The dormant engines already encode bounds that the sub-phases inherit — e.g. memory scanner
  `MaxProcesses 64`, `MaxBytesPerRegion 256 KB`, `MaxTotalBytes 16 MB`, `OverallTimeout 30 s`;
  protected-files `12000 events/min`, `4096 processes`, `TTL 10 min`.
- **Fail-safe degradation:** if a budget is exceeded the engine must **degrade and report a degraded
  state** (per phase MD §9, §13), never silently drop to an unbounded mode and never escalate to action.
  Degradation is surfaced honestly (the Phase-07 tray model already treats unknown/degraded service
  state as "reduced protection", not "protected").
- **Stop condition:** performance degradation that is **not measurable** is itself a stop condition
  (phase MD §14).

## 8. Policy / remediation integration gates (deferred)

- **No policy feed in report-only.** A report-only engine never reaches `ThreatClassificationPolicy`.
- **Promotion to policy feed** is a later, explicit phase gate, allowed only after a passing soak under
  the FP target, and only as **evidence that still clamps to `HighRisk`** — it can raise visibility, not
  confirm malware.
- **Promotion to remediation/action** is a separate, even-later gate. It is forbidden in Phase 09 and in
  every `09x` report-only sub-phase. It requires: passing soak, FP target met, a journal/rollback design,
  the IPC ACL security gate, and an explicit policy-gate pass. No dormant-engine evidence may feed
  destructive remediation, and no behavioral/heuristic-only evidence may become `ConfirmedMalware`.

## 9. Sub-phase order list

| Order | Engine | First integration step | Promotion gate |
|---|---|---|---|
| `09A_BEHAVIORAL_REPORT_ONLY` | Behavioral correlation | Instantiate runtime binding in `PassiveMode`, sink to history/diagnostics only | soak + FP target → policy-feed gate (later) |
| `09B_PROTECTED_FILES_REPORT_ONLY` | Anti-ransomware / protected-files | Start monitor under `ProtectedFilesActivityRequested`, report `ProtectedActivitySuspected` only | soak + FP target → policy-feed gate (later) |
| `09C_MEMORY_REPORT_ONLY` | Memory scanner | Add a bounded report-only caller, evidence ≤ High, score ≤ 6 | soak + FP target → policy-feed gate (later) |
| `09D_ETW_CORRELATION_REPORT_ONLY` | ETW behavioral correlation | Replace Stub adapter with a real (still report-only) ETW→behavioral feed under `EtwTelemetryRequested` | soak + FP target → policy-feed gate (later) |

Each order is in its own file (`outputs/09A_…` … `outputs/09D_…`) and follows the same 20-point
structure. Later promotion phases (policy feed, then action) are **separate future orders**, not part of
`09x`.

## 10. Explicit statements

- **No dormant engine was activated** in Phase 09. All four remain dormant.
- **No feature flag was changed**; all readiness flags remain default-off.
- **No anti-FP, YARA, classifier, quarantine, policy, or gate semantics were changed.**
- **Phases 07 and 08 are preserved** (this plan sits on the Phase-07-stabilized baseline, Phase-08
  transport untouched).
- **Phase 10 was not started.**
