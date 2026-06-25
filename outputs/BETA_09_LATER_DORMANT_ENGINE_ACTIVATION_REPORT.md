# BETA 09 — LATER DORMANT-ENGINE ACTIVATION (PLANNING/READINESS) REPORT

Phase: `09_LATER_DORMANT_ENGINE_ACTIVATION` (DataVanger V.Beta Improvement Plan)
Executed: 2026-06-14
Branch/checkpoint: `claude/confident-gates-f355wn`, on the Phase-07-stabilized baseline (HEAD `369032a`).

Verdict: **PLANNING/READINESS ONLY. No dormant engine was activated. Zero production code changed.** The
deliverable is a readiness plan plus four report-only sub-phase orders (`09A`–`09D`) that decompose later
activation into one-engine-per-phase, report-only-first work with binding soak/FP gates. All four engines
remain dormant, every readiness flag remains default-off, and the anti-false-positive contract is
untouched.

---

## 1. Phase interpretation (planning, not activation)
Despite the name, this is **later-phase planning/readiness work** (phase MD §3, §5). The phase explicitly
forbids activating all dormant engines, requires one engine per sub-phase, report-only first, with
mandatory soak and FP stop conditions (phase MD §6, §8, §9). The output is "readiness/planning artifacts,
sub-phase orders, feature-flag/readiness metadata if already supported, and validation strategy." That is
exactly what was produced.

## 2. Baseline confirmation
Working tree clean on `claude/confident-gates-f355wn`, HEAD `369032a` (Phase-07-stabilized baseline).
Phases 02B–05 and 07 are complete and stable; Phase 08 (HTTP signed-update transport) is preserved. The
solution still has dormant behavioral, anti-ransomware/protected-files, memory, and ETW behavioral
correlation capabilities, none of which is activated by this phase.

## 3. Why zero code change is the correct, lowest-risk outcome
The repository already ships the safe machinery in the safe position: a **default-off readiness-flag
framework** (`DataVangerSettings`), a **fail-safe validator** (`DataVangerSettingsValidator`) that forces
`AutomaticQuarantineForNonConfirmedMalwareRequested` off, **structural anti-FP ceilings inside every
dormant engine**, and a **verdict gate that confirms malware only from a known-malicious hash or a
confirmed signature**. Because the right flags already exist and are already off, no new flag was added
(phase MD §5 allows them "if strictly necessary"; they are not). Writing the activation orders — rather
than performing activation — gives perfect containment with zero activation/FP/build risk.

## 4. Files changed
- `outputs/BETA_09_DORMANT_ENGINE_READINESS_PLAN.md` (new) — inventory + report-only/soak/FP/perf/policy
  strategies.
- `outputs/09A_BEHAVIORAL_REPORT_ONLY.md` (new) — behavioral sub-phase order (20-point).
- `outputs/09B_PROTECTED_FILES_REPORT_ONLY.md` (new) — protected-files sub-phase order (20-point).
- `outputs/09C_MEMORY_REPORT_ONLY.md` (new) — memory sub-phase order (20-point).
- `outputs/09D_ETW_CORRELATION_REPORT_ONLY.md` (new) — ETW correlation sub-phase order (20-point).
- `DataVanger/ALTERACOES_BETA.md` (appended) — Phase 09 entry (planning/readiness, no activation).
- `outputs/BETA_09_LATER_DORMANT_ENGINE_ACTIVATION_REPORT.md` (new) — this report.

**No `.cs`, `.csproj`, `.sln`, `.xaml`, settings, or test file was modified.** No `bin/`, `obj/`,
`TestResults/`, `Publicar/`, or `.vs/` was created or staged.

## 5. Dormant-engine inventory
| Engine | Location | Dormancy | Readiness flag (default) | Anti-FP ceiling |
|---|---|---|---|---|
| Behavioral | `DataVanger/Behavioral/*` + `DataVanger.Engine/Behavioral/Runtime/BehavioralRuntimeBinding.cs` | not in `EngineComposition`; runtime binding not instantiated; `PassiveMode=true` | `ActiveRealtimeProtectionRequested` (false) | `CanConfirmMalware=false`, `Strength→High` (double-enforced) |
| Protected-files | `DataVanger.Engine/ProtectedFiles/*` (13) | monitor not started in live runtime | `ProtectedFilesActivityRequested` (false) | ceiling `ProtectedActivitySuspected→High`; ≥3 correlated categories; no `IsConfirmedMalware` |
| Memory | `DataVanger/Memory/*` (14+8+3) | no production caller | none yet (no caller) | `MemoryFinding.CanConfirmMalware => false`; `Strength ≤ High`; `score ≤ 6` |
| ETW correlation | `DataVanger.Infrastructure/Etw/WindowsEtwRuntimeProvider.cs` + Stub adapters | provider gated default-Disabled; behavior adapter `IsAvailable => false` | `EtwTelemetryRequested` (false) | ETW/AMSI never confirm alone; flows only via behavioral clamp |

The active verdict path remains the nine composed modules in `DataVanger/Engine/EngineComposition.cs`
(Hash, Heuristic, Script, PE, Archive, Document, BrowserExtension, Yara, Persistence).

## 6. Sub-phase order list
`09A_BEHAVIORAL_REPORT_ONLY`, `09B_PROTECTED_FILES_REPORT_ONLY`, `09C_MEMORY_REPORT_ONLY`,
`09D_ETW_CORRELATION_REPORT_ONLY` — sequential, one engine each, each a 20-point order. Later promotion
phases (policy feed, then action) are separate future orders, not part of `09x`.

## 7. Report-only strategy
Each engine is guarded by a default-off/report-only flag, sinks output to local history/diagnostics only
(never the classifier, never `RemediationExecutionGate`), keeps `CanConfirmMalware=false`, and is labeled
"report-only / observing" in diagnostics. One engine at a time.

## 8. Soak-test strategy
Per-engine benign + labeled-malicious corpora; ≥ 14 days representative runtime (or equivalent replayed
volume) in report-only mode; promotion blocked until the soak completes under the FP target with no
stop-condition trip. Soak failures change the plan, never the user's protection state.

## 9. FP-rate stop conditions (binding)
Each sub-phase declares an explicit FP-rate target. Exceeding it in any soak window keeps the engine
report-only and halts promotion (phase MD §6, §14). Because the engine was already report-only, a breach
regresses nothing for the user.

## 10. Performance budget & degradation
Each engine inherits measurable budgets (memory: `MaxProcesses 64`/`256 KB`/`16 MB`/`30 s`;
protected-files: `12000/min`/`4096 procs`/`10 min TTL`; behavioral/ETW: bounded throughput/memory). On
breach the engine degrades and reports a degraded state — never an unbounded mode, never action.
Non-measurable degradation is itself a stop condition.

## 11. Policy/remediation integration gates
Report-only engines never reach `ThreatClassificationPolicy`. Promotion to a policy feed (visibility only,
still `HighRisk`-clamped) is a later explicit gate after a passing soak. Promotion to remediation/action
is an even-later, separate gate requiring journal/rollback design, the IPC ACL security gate, FP target
met, and an explicit policy-gate pass — forbidden in Phase 09 and in every `09x` report-only order.

## 12. Stabilization Change Review
The phase requires reviewing prior Codex stabilization changes and defaulting to **preserve** validated
work unless there is a strong technical reason to revert. Reviewed the five Phase-07 stabilization
changes carried in this baseline:
- `ScanHistoryRecorder` now records detections for confirmed/high-risk/was-quarantined findings and emits
  auto-quarantine remediation events — **still never marks a remediation verified** (honest). **Preserved.**
- `MainWindow.xaml.cs` `serviceDegraded → serviceImpaired` (covers Unknown/NotInstalled/NotRunning/
  Unreachable/Degraded) — a more honest tray status. **Preserved.**
- The Phase-07 live-wiring fields/methods (`_history`, `_historyRecorder`, `_trayHost`,
  `UpdateTrayStatus`, `ShowAndActivate`, `ShowServiceStatus`, `IsCurrentProcessElevated`) — intact.
  **Preserved.**
All stabilization changes preserve the truthfulness and anti-FP contract; none was reverted.

## 13. Anti-FP Preservation Review
The anti-FP contract is **unchanged**: `ConfirmedMalware` only from `IsBlacklisted` or
`HasConfirmedSignature`; everything else clamps to `HighRisk`; automatic action only for
`ConfirmedMalware`; `AutomaticQuarantineForNonConfirmedMalwareRequested` forced off by the validator.
Verified the structural ceilings remain in code: `MemoryFinding.CanConfirmMalware => false`,
`MemoryEvidenceFactory`/`MemoryCorrelationEngine` `CanConfirmMalware=false`; protected-files
`ProtectedActivitySuspected→High` requiring ≥3 categories; behavioral `SanitizeForFinding`/`AddEvidence`
clamp. **No anti-FP code was touched.** Every sub-phase order inherits this contract verbatim.

## 14. Security Boundary Review
No new privilege, network egress, or destructive capability is introduced. The UI stays non-elevated; no
self-protection, kernel minifilter, real AMSI registration, cloud reputation, or self-update. ETW stays
gated default-off and AMSI stays a Stub. All report-only telemetry in the sub-phase orders is **local**.
The IPC ACL security gate remains a prerequisite for any future privileged remediation.

## 15. Documentation Review
`docs/MODULE_STATUS_MATRIX.md` is Alpha-era and still lists the HTTP transport as Stub (superseded by
Phase 08); its anti-FP contract section and its memory/behavioral/ETW dormancy entries remain accurate and
were used as the authority. `DataVanger/ALTERACOES_BETA.md` received an appended Phase 09 entry (the prior
entries, including the Codex-updated Phase 07 entry, were not rewritten). The readiness plan and four
sub-phase orders were added under `outputs/`.

## 16. Tests run
None executed: there is **no .NET SDK in this environment**, and this phase changed zero code, so there
was nothing to compile or run. The required PowerShell build/test/focused-filter commands (phase MD §12)
and the "existing `~Behavioral`/`~ProtectedFiles`/`~Memory`/`~Etw`/`~AntiFalsePositive` remain green"
checks are deferred to Windows/Codex stabilization. No test was added or changed (correct for a
docs-only planning phase).

## 17. Required invariants
Honored. No empty catch blocks, no `lock(qm)`, no new lock anti-patterns (no code changed). No anti-FP,
YARA, quarantine, classifier, policy, or gate semantics changed. No destructive action added. No
privileged remediation before the IPC ACL gate. No `bin/`/`obj/`/`Publicar/`/`TestResults/` committed.
`DataVanger V.Alpha_STABLE` preserved as the regression oracle. Phase-specific invariants — one engine per
later sub-phase, report-only first, FP-rate stop condition binds, no silent destructive action, no
policy/remediation feed before safe validation — are all encoded in the orders.

## 18. Stop conditions encountered
None. No engine was activated; no soak was run; no FP target exists to breach; no anti-FP test could
regress (no code changed). The phase ran to completion as planning/readiness.

## 19. Forbidden-scope confirmation
Did not: activate any/all dormant engines; feed dormant-engine detections into destructive remediation;
add silent destructive action; treat behavioral/heuristic-only evidence as `ConfirmedMalware`; enable
self-protection/kernel minifilter/real AMSI/cloud reputation/self-update; skip soak design; ship any
engine to automatic action. All remain forbidden in the sub-phase orders too.

## 20. Phases 07 and 08 preservation
Phase 07 (onboarding/tray/history/service UX) and Phase 08 (HTTP signed-update transport) are preserved
unchanged. This phase sits on the Phase-07-stabilized baseline and touched no Phase-07/08 code.

## 21. Phase 10 not started
Phase 10 was not started. Only Phase 09 planning/readiness artifacts were produced.

## 22. No dormant engine silently activated — explicit statement
**No dormant engine was activated, silently or otherwise.** All four engines remain dormant; all readiness
flags remain default-off; the live verdict path is still the nine composed modules; no behavioral,
protected-files, memory, or ETW evidence reaches the classifier or remediation.

## 23. Remaining risks / follow-up
The risk surface is entirely in the *future* report-only activations, which is why each `09x` order front-
loads a default-off flag, a binding FP stop condition, a soak requirement, a fail-safe performance budget,
and deferred policy/remediation gates. Follow-up: execute `09A`→`09D` one at a time, each with Codex
stabilization on Windows, before any later promotion phase.

## 24. Recommendation
Ready for Codex stabilization **as a documentation/planning deliverable** (audit that every sub-phase
stays report-only first, phase MD §18). No build/test is required for this phase because no code changed;
stabilization for the actual engine sub-phases is strongly recommended when each `09x` order is
implemented.

## 25. Final status
**Phase 09 COMPLETE as planning/readiness only.** Later activation is decomposed into one-engine-per-phase
report-only orders; each starts report-only behind a default-off flag; soak tests and FP stop conditions
are mandatory; no silent destructive action is possible; policy/remediation feed is deferred until
validation gates pass. No dormant engine was silently activated, the anti-FP contract is preserved,
Phases 07/08 are preserved, and Phase 10 was not started.
