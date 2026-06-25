## Phase 04B Final Report

Phase: `04B_REMEDIATION_IPC_SURFACE` — UltraCode (audit + completion of an uploaded draft).
Executed: 2026-06-13.
Verdict: **The uploaded archive already contained a coherent, policy-gated remediation IPC draft. It was
adopted as the new baseline and audited line-by-line against the phase's safety spec. The bridge is
architecturally correct (Shared DTOs are engine-independent; WPF does not reference Engine; every execution
path goes through `RemediationExecutionGate` and `ExecuteAuthorizedAsync`; the execution permit is
server-issued and non-forgeable; policy blocks Suspect/Clean/HighRisk-destructive/heuristic/system-file-auto
even with spoofed consent). Five required negative tests that were missing were added. One HIGH-severity
limitation remains by design (the handler trusts client-asserted threat band + client-supplied consent);
it is bounded today and documented as the headline Codex/Windows must-fix. No Phase 05 UI was started.
HighRisk destructive remediation remains blocked. Builds/tests are Windows-only and could not be run here.**

- **Branch/checkpoint:** `claude/confident-gates-f355wn`, on the adopted archive.

### Baseline replacement result

- **ZIP cleanliness:** no `bin/`, `obj/`, `TestResults/`, `Publicar/`, `.vs/`, no nested zip, no
  `.suo/.user`. 643 files + 97 dirs; doubly-nested wrapper. Extracted tree matched the listing.
- **Replace, not merge:** working tree (except `.git`) deleted and the archive copied in; post-copy
  `diff -rq` against the extracted archive was empty (exact mirror).
- **Exact delta vs previous baseline** (HEAD `4bbe6ba`): **4 new files + 7 modified, 993 insertions /
  9 deletions, 0 removed, no forbidden artifacts.** The archive layered a complete Phase 04B draft on top
  of my previously pushed branch.
- Adopted as commit `447e295`.

### Files changed (this phase)

Adopted from the archive (the 04B draft):
- **New:** `DataVanger.Shared/Remediation/RemediationIpcDtos.cs`,
  `DataVanger.Service/Ipc/RemediationCommandHandler.cs`,
  `DataVanger.Service/Ipc/IRemediationPlanExecutor.cs`, `DataVanger.Tests/RemediationIpcTests.cs`.
- **Modified:** `DataVanger.Shared/Ipc/DataVangerCommandType.cs`,
  `DataVanger.Shared/Ipc/DataVangerCommandCatalog.cs`,
  `DataVanger.Service/Ipc/DataVangerServiceCommandRouter.cs`,
  `DataVanger.Service/Ipc/DataVangerServiceCommandContext.cs`,
  `DataVanger.Engine/Remediation/Policy/RemediationExecutionGate.cs`,
  `DataVanger.Tests/RemediationExecutionGateTests.cs`, `DataVanger.Tests/ServiceActivationReviewTests.cs`.

Added by this audit pass (minimal, surgical):
- **`DataVanger.Tests/RemediationIpcTests.cs`** — 5 required negative tests (see below).
- **`docs/REMEDIATION_IPC_SURFACE_RUNBOOK.md`** — the Phase 05 UI contract + security model + limitations.
- **`outputs/BETA_04B_REMEDIATION_IPC_SURFACE_REPORT.md`** — this report.

### Shared remediation DTOs

`DataVanger.Shared.Remediation` (data-only, no engine reference — proven by
`SharedRemediationDtos_DoNotReferenceEngineAssembly` and by `DataVanger.Shared.csproj` having no Engine
ProjectReference): transport enums `RemediationIpcActionKind`, `RemediationIpcTargetKind`,
`RemediationIpcThreatBand`, `RemediationIpcConfirmationTier`, `RemediationIpcAuthorization`,
`RemediationIpcPolicyOutcome` (all `Unknown = 0`, fail-closed), and records
`RemediationConsentTokenDto`, `RemediationExecutionRequestDto`, `RemediationActionExecutionResultDto`,
`RemediationExecutionResponseDto`.

### IPC commands / catalog

- Added `ExecuteRemediationAction` (the **only** remediation command) and a `Remediation` category in
  `DataVangerCommandCatalog`. `ServiceActivationReviewTests` now asserts the surface exposes exactly that
  one remediation command and no `Kill`/`Disinfect`/`RemoveThreat`/`FixThreat` command.
- Payload allowlist/size: the router runs `IpcSecurityPolicy.ValidateRequest` (allowlist + 64 KiB bound)
  **before** dispatch; oversized/non-allowlisted requests never reach the handler.

### Service handler behavior

`RemediationCommandHandler` (internal): deserializes the DTO (malformed → `BadRequest`); validates
correlation/action/target-kind/identity/band and the target-kind↔action match; enforces `IsSafePath` for
file targets; builds an engine `RemediationConsentToken` from the consent DTO only after full validation;
calls `RemediationExecutionGate.Authorize` for the requested action and, for destructive file actions,
inserts a gate-authorized `QuarantineFile` containment step (quarantine-before-delete); builds the plan and
executes **only** via `IRemediationPlanExecutor.ExecuteAuthorizedAsync` with the gate-issued permits. A null
executor returns `Unsupported`/`RemediationUnavailable` (honest unavailable). Handler exceptions are caught
by the router and returned as `InternalError` — never thrown across the boundary.

### Policy / gate enforcement behavior

The gate is the single chokepoint: any non-`Allowed` policy outcome → `DeniedByPolicy`; automatic actions
(ConfirmedMalware quarantine / verification) authorize without consent; consent-required actions need a
non-expired token binding the exact action + target + correlation and the **exact** confirmation tier. The
draft tightened the gate with `ConsentTierMismatch` (a *different/stronger* tier is now rejected, not just a
weaker one); this is consistent with all existing gate tests (the one stronger-tier case is policy-blocked,
where tier is irrelevant) and is covered by `Gate_RejectsDifferentStrongerConsentTier_ToKeepTierBindingExact`.

### Consent / permit / correlation behavior

`RemediationExecutionPermit` keeps its **internal constructor** — the client can never submit a permit; only
the gate issues one. The consent token binds action + target + tier + expiry + correlation, and the executor
re-checks that each permit matches the exact action + target match-key + correlation before running a step.

### Tests added (this pass) / results

Added to `RemediationIpcTests` (each composed only from symbols already proven to compile in that file, and
grounded in the real policy/gate logic I read in full):
- `CleanBand_Action_IsDeniedByPolicy` (Clean → NoAction → `DeniedByPolicy`, 0 executions).
- `SuspectBand_DestructiveAction_IsDeniedByPolicy` (Suspect → ReportOnly → `DeniedByPolicy`, 0).
- `SystemFile_ConfirmedMalwareQuarantine_IsNotAutomatic_RequiresConsent` (system file → not automatic →
  `ConsentMissing`, 0 — proves no automatic system-file remediation).
- `UnknownTargetKind_IsRejected` (`BadRequest`, 0).
- `TargetKindMismatchedToAction_IsRejected` (target-kind ≠ action's target kind → `BadRequest`, 0).

These close the phase's required-test gaps for Clean, Suspect, system-file-automatic, and target validation.
**They could not be executed here** (no .NET SDK; `DataVanger.Tests` is `net8.0-windows`).

### Validation commands run and results

No .NET SDK / MSBuild / mono in this container; the projects target `net8.0`/`net8.0-windows`. The phase's
`dotnet restore/build/test` (+ `--arch x64`, `~Remediation/~Quarantine/~AntiFalsePositive/~Yara/~Ipc/~Service`)
are **NOT RUNNABLE here** — standing environment exception. Static validation performed:

| Check | Result |
|---|---|
| ZIP cleanliness / exact-mirror replace | PASS |
| Delta vs previous baseline | 4 new + 7 modified, 993/-9 (documented) |
| Invariants on all changed files (empty `catch{}` / `lock(qm)` / CRLF) | 0 / 0 / 0 — PASS |
| WPF `DataVanger.csproj` references only `DataVanger.Shared` (no Engine) | PASS |
| `DataVanger.Shared.csproj` has no Engine reference (DTOs engine-independent) | PASS |
| No Removal Center UI / XAML / nav added | PASS |
| Command surface: exactly one remediation command, `Remediation` category present | PASS (guard test present) |
| Forbidden artifacts staged | none — PASS |

### Bypass / destructive-surface audit

- **No gate bypass:** the only execution call is `ExecuteAuthorizedAsync` through `IRemediationPlanExecutor`;
  the executor requires matching gate permits per step. No direct `ExecuteAsync` call exists in the handler.
- **No client-forged *permit*:** `RemediationExecutionPermit`'s constructor is internal to the Engine.
- **HighRisk destructive remains blocked** (`HighRiskDestructiveRemoval_IsBlocked_EvenWithSpoofedConsent`);
  heuristic-only destructive blocked; Suspect/Clean denied; system-file never automatic.

### UI exposure: None

WPF unchanged; no Removal Center; WPF still does not reference `DataVanger.Engine`.

### Phase 05 readiness

Ready to consume the DTO/command contract documented in `docs/REMEDIATION_IPC_SURFACE_RUNBOOK.md` — **after**
the limitation in the next section is addressed (or explicitly accepted while the engine remains
simulation-only and no real destructive provider is wired).

### Stop conditions encountered

None forced a hard stop. The "any client-supplied DTO can forge execution authorization" stop condition is
**partially implicated** for the ConfirmedMalware destructive path (client-asserted band + client-supplied
consent) and is recorded below as a HIGH-severity limitation rather than a hard stop, because (a) the
execution **permit** itself is non-forgeable and correlation-bound (the literal mitigation the phase names),
(b) the residual risk is bounded (IPC ACL + `IsSafePath` + quarantine-before-delete + **no real destructive
provider exists**), and (c) the phase's own §19 explicitly permits documenting this limitation when durable
server-side correlation storage is not yet available. It is flagged as a must-fix before any real provider
is enabled.

### Remaining risks / follow-up

1. **HIGH — client-asserted band + client-supplied consent.** The handler trusts `ThreatBand`,
   `HasConfirmedEvidence`, `EvidenceIsHeuristicOnly`, `IsSystemFile`, and the consent token from the request.
   **Fix:** derive band/evidence/system-file from a server-side detection record keyed by `CorrelationId`,
   and move to a service-issued consent/permit (preview → consent → execute + correlation-bound permit store
   with a server-bounded short TTL). Until then, keep the engine simulation-only.
2. **Windows-only validation debt** (standing): full + x64 suites and the six focused filters require a
   Windows .NET SDK; they cannot be proven here.
3. **Simulation honesty:** when a real provider lands, ensure unavailable actions return
   `Unavailable`/`Blocked` and never fake success (§19).

### Recommendation

**Ready for Codex (Altissimo) stabilization on Windows, with the HIGH limitation as the first agenda item.**
Codex should: run all builds + the full/x64/`~Remediation/~Quarantine/~AntiFalsePositive/~Yara/~Ipc/~Service`
suites; confirm the five added tests compile and pass; implement server-authoritative band + service-issued
consent/permit store; and re-audit for any direct `ExecuteAsync` path. Risk level: **HIGH** (this is the
privileged UI↔execution bridge), mitigated today by the non-forgeable permit, the ACL, safe-path, and the
absence of a real destructive provider.

---

## Self-Stabilization Review

**Risks checked:**

1. **Cross-platform blind spots.** All 04B production code is in `net8.0` projects (`Shared`, `Service`,
   `Engine`) — no WPF/XAML, so no XAML-compile / WinForms-vs-WPF namespace ambiguity. **But there is no .NET
   SDK here**, so nothing was compiled or run; I treated Linux reasoning as *not* proof of a Windows build.
   The test project is `net8.0-windows`, so the new tests cannot be compiled here — flagged as Windows-only.

2. **Test/API mismatch.** I read the full `RemediationPolicy`, `RemediationExecutionGate`, router,
   `IpcSecurityPolicy`, `IpcOptions`, and the existing `RemediationIpcTests` before writing any test. Every
   added test is composed **only** from symbols already used (and therefore already compiling) in that file,
   and every asserted enum value (`DeniedByPolicy`, `ConsentMissing`, `BadRequest`) was traced through the
   real policy→gate→handler path. No new API surface was introduced by the tests, minimizing the
   "isolated-harness compiles ≠ real assembly compiles" risk. No `InternalsVisibleTo` change was needed:
   the handler is internal but is exercised through the **public** `DataVangerServiceCommandRouter`, and the
   DTOs/gate types the tests touch are public (`InternalsVisibleTo("DataVanger.Tests")` already exists in
   `DataVanger/Properties/AssemblyInfo.cs` for the WPF assembly, which these tests do not depend on).

3. **Resource/build integration.** No `.resx`/XAML/csproj/satellite added. The new `.cs` test file and the
   markdown docs fall under the SDK default compile/none globs; no `BuildAction` or designer concern.

4. **Safety-policy consistency.** Anti-FP, classifier thresholds, YARA, and quarantine semantics are
   **untouched** (the policy/classifier files are not in the delta). The gate change only **tightens**
   (exact-tier consent). Every destructive path is gated, journaled by the existing remediation system,
   rollback-aware (quarantine-before-delete), and policy-ready. The one residual exposure (client-asserted
   band/consent) is documented, not silently accepted, and the engine remains simulation-only.

5. **Phase-boundary enforcement.** No Phase 05 UI, navigation, XAML, dialogs, or ViewModels were added; WPF
   still does not reference `DataVanger.Engine`; no real destructive provider, no auto-reboot, no elevation,
   and no classifier/YARA/quarantine change. I did **not** rewrite the working draft — I audited it, added
   the missing required tests, wrote the runbook, and documented the limitation (minimal, surgical).

6. **Required local checks.** Ran invariant greps (0/0/0), forbidden-scope/artifact greps (clean), the
   phase-boundary reference checks (WPF→Shared only; Shared has no Engine), and re-read every changed file
   for namespace/API correctness.

**Issues found and fixed before final report:** (a) missing required negative tests for Clean, Suspect,
system-file-automatic, and target-kind validation — **added**, grounded in the real policy/gate logic;
(b) the central forged-authorization limitation (client-asserted band + consent) — surfaced as the
HIGH-severity headline finding with a concrete fix, and documented in the runbook (per §19) rather than
patched blind. I deliberately did **not** modify the security-critical handler/gate, because I cannot compile
or test here and an unverifiable edit to that path could regress an otherwise-green upload — the wrong trade
for a security boundary.

**What remains Windows-only / Codex-only:** all `dotnet build`/`test` validation (full + x64 + the six
focused filters); confirmation that the five added tests compile and pass in the real `net8.0-windows`
assembly; and the architectural fix for server-authoritative band + service-issued consent/permit store.

**Known prior mistake pattern prevented:** the "Linux/isolated-harness success mistaken for Windows success"
trap (I compiled nothing and said so); the "test references a non-existent API / wrong overload" trap
(tests reuse only proven symbols and real, traced enum values); the "quiet anti-FP/quarantine weakening"
trap (those files are untouched; the gate only tightened); and the "premature UI exposure" trap (no Phase 05
work). The one trap I explicitly did **not** paper over is the forged-authorization limitation — it is
reported at HIGH severity rather than hidden behind green unit tests that only exercise client-trusted inputs.

**Is Codex stabilization still recommended, and at what risk level:** **Yes — strongly, at HIGH risk
(Altissimo).** This is the privileged UI↔execution bridge; the headline item is to make the threat band and
consent **server-authoritative** before any real destructive provider is enabled, then run the full Windows
build/test matrix. The adopted draft plus this pass are a sound, conservative, well-tested foundation for
that hardening, but must not be shipped with a real destructive provider until the HIGH limitation is closed.
