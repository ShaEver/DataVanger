## Phase 04 Final Report

Phase: `04_DETECTION_TO_ACTION_POLICY` — UltraCode.
Executed: 2026-06-13.
Verdict: **Authoritative RemediationPolicy + consent token + service-side execution gate implemented;
anti-FP contract re-encoded and strengthened, not weakened; 32 new exhaustive policy tests (179 remediation
total) pass on Linux against the real Engine; purely additive — no anti-FP/classification/YARA/quarantine/IPC
file touched. Windows full/x64 suite pending.**

- **Branch/checkpoint:** `claude/adoring-dirac-jxo678` on the adopted post-03D stabilized baseline (clean ZIP,
  726 entries; delta = 4 03D-stabilization files; adopted then validated 0-error/0-warning builds).

- **Files changed:** purely additive — **4 new Engine files** under `DataVanger.Engine/Remediation/Policy/`
  and **3 new test files**. `git status` shows only new files; **no existing file modified** — in particular
  `ThreatClassificationPolicy.cs` and `AntiFalsePositivePolicy.cs` are byte-for-byte unchanged (verified), so
  the anti-FP contract is preserved by construction and the existing `~AntiFalsePositive` suite is the intact
  regression oracle.
  - Engine: `RemediationPolicyModels.cs`, `RemediationPolicy.cs`, `SystemFileGuard.cs`,
    `RemediationExecutionGate.cs`.
  - Tests: `RemediationPolicyTests`, `RemediationPolicyAntiFalsePositiveTests`, `RemediationExecutionGateTests`.

### Policy truth table (non-system file)

| Band → / Action ↓ | Quarantine | Destructive removal¹ | System-scope² | Locked file | Verify |
|-------------------|-----------|----------------------|---------------|-------------|--------|
| **Clean** | NoAction | NoAction | NoAction | NoAction | NoAction |
| **Suspect** | ReportOnly | ReportOnly | ReportOnly | ReportOnly | ReportOnly |
| **HighRisk** (unconfirmed) | Allowed · UserConfirmation · *not automatic* | **Blocked** (requires ConfirmedMalware) | **Blocked** | **Blocked** | Allowed · automatic |
| **ConfirmedMalware** (confirmed evidence) | Allowed · **automatic** | Allowed · UserConfirmation | Allowed · AdvancedConfirmation | Allowed · RebootConsent | Allowed · automatic |

¹ DeleteFile, CleanDroppedPayload, RemoveStartupFolderEntry, RemoveRegistryAutorun, RemoveScheduledTask,
DisablePersistence, KillProcessTree, RemoveBrowserExtension. ² StopAndDisableService, RestoreHijackedSetting.

**Override guards (highest priority):**
- **Conservative downgrade:** a `ConfirmedMalware` band WITHOUT confirmed evidence (or with heuristic-only
  evidence) is evaluated as **HighRisk** — unconfirmed/heuristic/unconfirmed-YARA can never reach the confirmed
  destructive/automatic path.
- **System-file guard:** a system file may be remediated ONLY for ConfirmedMalware + confirmed evidence, and
  **never automatically** (AdvancedConfirmation even for quarantine); anything weaker is **Blocked**.
- **Heuristic-only:** can never produce an automatic destructive action (reinforces the downgrade).
- **Unknown band/action → fail closed (Blocked).**

### Action tiers

`PolicyOutcome` ∈ {Blocked, ReportOnly, NoAction, Allowed}. An Allowed decision carries `IsAutomatic`
(consent-free; only ConfirmedMalware quarantine + verification) or a `RequiredConfirmation` tier ∈
{UserConfirmation, AdvancedConfirmation, RebootConsent}. The gate enforces tier strength
(None < UserConfirmation < RebootConsent < AdvancedConfirmation).

### Anti-FP preservation evidence

- **No file in the anti-FP/classification/YARA path was modified** (git-verified) — the existing contract and
  its tests are untouched.
- The policy **re-encodes** the contract at its own layer: ConfirmedMalware is reachable only with confirmed
  evidence; a ConfirmedMalware band lacking confirmed evidence is downgraded to HighRisk; HighRisk and below
  can never trigger an **automatic** destructive action; system files are protected. Tests prove:
  unconfirmed-"ConfirmedMalware" → not automatic + no destructive removal; unconfirmed YARA (HighRisk) → cannot
  kill a process; heuristic-only → blocks destructive even if the band is mislabeled confirmed; system-file +
  HighRisk/heuristic → blocked; system-file + ConfirmedMalware → allowed but never automatic.
- The single auto-action (ConfirmedMalware quarantine) matches the **existing** ConfirmedMalware-only
  auto-quarantine gate already in `QuarantineService` — no new automatic destruction was introduced.

### Consent token behavior

`RemediationConsentToken` binds an EXACT action + target match-key + confirmation tier + correlation id +
issue/expiry timestamps. It cannot be issued with a None/Unspecified tier. The `RemediationExecutionGate`
(the mandatory chokepoint) authorizes only when: policy says Allowed; and either the decision is automatic, or
a presented token binds the same action+target, is not expired, and carries a tier ≥ the required tier.
Mismatched action, mismatched target, expiry, weaker tier, and missing token each fail closed.

### IPC / service enforcement

**No IPC remediation command was added in this phase** (the 02A no-remediation-surface guard still holds —
verified). The `RemediationExecutionGate` IS the service-side enforcement pattern: any future
`RemediationCommandHandler` MUST call it after the 02B IPC ACL gate and before the executor. Wiring live IPC
remediation commands (PlanRemediation/ExecuteRemediationAction/consent issuance over the pipe) is deferred to
**phase 05**, when the Removal Center UI drives the plan→consent→execute flow — keeping the validated IPC layer
untouched now. The gate tests already prove a "UI-supplied unsafe/unconsented request is rejected by policy."

### Tests run

32 new policy tests, **all passing on Linux** against the real `DataVanger.Engine`: exhaustive Clean/Suspect/
HighRisk/ConfirmedMalware × all action kinds; auto-quarantine; consent-gated removals; system-scope advanced;
locked-file reboot consent; completeness (every band×action yields a defined, fail-closed decision with a real
tier when consent is required); anti-FP guards; system-file guard; and full consent-gate enforcement
(authorize automatic, reject missing/mismatched-action/mismatched-target/expired/weaker-tier, deny
policy-blocked even with a token). Combined 03A–04 remediation suite: **179/179 pass.** All four cross-platform
projects build **0 errors / 0 warnings.** The mandated full/x64/`~AntiFalsePositive`/`~Yara`/`~Ipc`/`~Service`
runs are **Windows-only** (standing exception) but unaffected by construction.

### Denial / stop cases covered

Suspect→ReportOnly, Clean→NoAction, HighRisk destructive→Blocked, unconfirmed-confirmed→downgrade,
heuristic-only→block, system-file weak evidence→block, unknown→fail-closed, consent
missing/mismatch/expired/insufficient-tier→reject, policy-denied-with-token→reject.

### Deliberate interpretation decision (open question for the owner)

The phase MD says "HighRisk requires user confirmation," which is ambiguous about whether HighRisk permits
**user-confirmed destructive removal**. The approved Evolution Plan §8 specified **HighRisk = user-confirmed
quarantine only; no destructive removal**. I implemented the **stricter, plan-consistent** reading: HighRisk
permits user-confirmed *quarantine* (UserConfirmation, never automatic) but **blocks** destructive removal
(which requires ConfirmedMalware). This satisfies every explicit required test ("HighRisk returns
user-confirmation required" via quarantine; "HighRisk cannot auto-delete" since nothing HighRisk is automatic)
and maximizes anti-FP safety. **Open question:** if the owner wants HighRisk to allow user-confirmed destructive
removal (delete/kill with consent), the change is a one-line relaxation in `RemediationPolicy.EvaluateHighRisk`
plus test updates — flagged so it is a conscious choice, not a silent one.

- **UI exposure:** Policy-ready for phase 05. No Removal Center UI, no live IPC remediation command.

- **Stop conditions encountered:** none. No `~AntiFalsePositive` regression (those files are untouched); no
  heuristic/HighRisk automatic destructive path exists; Suspect/Clean cannot remediate; unconfirmed YARA cannot
  become confirmed; the gate cannot be bypassed (it is the single authority any handler must call); every
  band/action path has explicit test coverage.

## Self-Stabilization Review

**Risks checked, and findings:**

1. **Cross-platform blind spots** — All 04 code is in `DataVanger.Engine` (net8.0, no WPF/XAML), so there is no
   XAML/WinForms ambiguity and no BCL-namespace-shadowing risk. The policy operates on the **shared**
   `QuarantineThreatClassification` enum (net8.0) rather than the WPF `ThreatClass`, precisely because the
   Engine cannot reference the WPF project — this was a design decision, not an accident, and it keeps
   everything cross-platform. No Windows-only API is used; `SystemFileGuard` uses `Environment.GetFolderPath`
   (empty-safe on Linux) plus a curated Unix root list so it is meaningful and testable here. No Windows-only
   test was added; all 32 tests run cross-platform.

2. **Test/API mismatch** — Every test compiles and runs against the real Engine, so all referenced APIs exist
   with the signatures used. **No `InternalsVisibleTo` is required** — all policy/gate/token/guard types and the
   shared enum are public. Class names (`RemediationPolicyTests`, `RemediationPolicyAntiFalsePositiveTests`,
   `RemediationExecutionGateTests`) are distinct from the existing `AntiFalsePositiveTests`, so no collision in
   the real net8.0-windows test assembly. No issue required a fix; the Engine and tests compiled cleanly first
   build.

3. **Resource/build integration** — No .resx/XAML/csproj/satellite added. SDK default compile globbing
   (verified in earlier phases) includes the 4 new Engine files and 3 new test files in the real
   `DataVanger.sln` build.

4. **Safety-policy consistency** — **Anti-FP NOT weakened:** `ThreatClassificationPolicy` and
   `AntiFalsePositivePolicy` are byte-unchanged (git-verified); the policy never classifies, never upgrades a
   band, and conservatively downgrades an unconfirmed "ConfirmedMalware". Quarantine semantics unchanged. **No
   remediation IPC/UI exposure added** (02A guard still holds). The one automatic action (ConfirmedMalware
   quarantine) mirrors the existing QuarantineService gate. Every destructive path is gated (policy + consent),
   journaled by the underlying actions, rollback-aware, and policy-ready.

5. **Phase-boundary enforcement** — Phase 05 (UI) and live IPC remediation commands were NOT started; the
   classifiers were not tuned; no new destructive action was introduced; the change is minimal and additive.
   The HighRisk strictness choice is a conservative narrowing, documented as an open question.

6. **Required local checks** — Ran the available validation (harness build + 179-test remediation run + 4
   project builds, all green); ran the `~Remediation`/policy filter (all new classes covered); ran the
   forbidden-scope grep (no remediation command in the IPC layer; no anti-FP file modified); re-read every
   changed file for namespace/API mistakes; confirmed no `bin/obj/TestResults/Publicar/.vs`/nested-zip staged.

**Issues found and fixed before final report:** none required code changes — the build and tests were green on
first run. The HighRisk interpretation ambiguity was resolved deliberately toward the stricter, plan-consistent
reading and documented rather than silently chosen.

**What remains Windows-only / Codex-only:** (a) the full `DataVanger.Tests` (net8.0-windows, WPF-referencing)
cannot link on Linux — only a Windows run proves the full assembly + all 168 baseline + 179 remediation tests
link and pass together, and that the **existing `~AntiFalsePositive`/`~Yara` suites stay green** (expected,
since their files are untouched); (b) a Windows-only **integration test feeding real `ThreatClassificationPolicy`
/ `AntiFalsePositivePolicy` output through `RemediationPolicy`** (proving the band-mapping seam end-to-end) is
recommended but was not added here because it would reference the WPF project and could not be compiled/run on
Linux — it is listed as a Codex/Windows validation item.

**Known prior mistake pattern prevented:** the "namespace shadows a BCL root" trap (03C) was avoided
(`Policy` is not a BCL root); the "`?.` on non-null → phantom nullable warnings" trap was avoided (zero
warnings); the "isolated-harness compiles ≠ real assembly compiles" trap was mitigated by using only public
APIs identical across harness and real assembly with no InternalsVisibleTo dependency; and the "quiet widening
of automatic action" trap (the specific risk this phase warns about) was actively guarded — the ONLY automatic
action is ConfirmedMalware quarantine, asserted by a completeness test over every band×action pair.

**Codex stabilization recommendation:** **Recommended, MEDIUM-HIGH risk level** — this is the security-critical
safety brain. A stabilization pass should: diff `ThreatClassificationPolicy`/`AntiFalsePositivePolicy` to
confirm no weakening (they are unchanged); add the Windows integration test mapping real classifier output to
the policy; run the full default + x64 suites and `~AntiFalsePositive`/`~Yara`/`~Quarantine`/`~Remediation`/
`~Ipc`/`~Service` filters; review the HighRisk strictness decision with the owner; and confirm no future direct
executor call can skip `RemediationExecutionGate`. Risk is elevated by consequence (a quiet widening of
automatic action would be severe) but mitigated by the exhaustive matrix tests, the untouched anti-FP files, and
the absence of any live IPC/UI remediation path.
