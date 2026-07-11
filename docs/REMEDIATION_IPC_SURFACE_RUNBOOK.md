# Remediation IPC Surface — Runbook (Phase 04B)

This document is the **UI contract** for the policy-gated remediation IPC surface added in
`04B_REMEDIATION_IPC_SURFACE`. Phase 05 (Removal Center UI) **must consume this bridge** and must
**not** invent its own remediation contract, duplicate engine models, or reference
`DataVanger.Engine` from the WPF process.

## 1. The boundary (no shortcuts)

```
WPF UI  ->  DataVanger.Shared.Remediation DTOs  ->  IPC command catalog
        ->  DataVanger.Service RemediationCommandHandler  ->  RemediationExecutionGate
        ->  RemediationExecutor.ExecuteAuthorizedAsync (gate-issued permits only)
```

- The WPF app references **only** `DataVanger.Shared`. All remediation domain types stay in
  `DataVanger.Engine`; the UI never names them.
- The DTOs in `DataVanger.Shared/Remediation/RemediationIpcDtos.cs` are **data-only** and reference
  no engine assembly (enforced by `RemediationIpcTests.SharedRemediationDtos_DoNotReferenceEngineAssembly`).

## 2. Command

| Command | Category | Allowlisted | Notes |
|---|---|---|---|
| `ExecuteRemediationAction` | `Remediation` | yes | The **only** remediation command. No `Kill*`, `Disinfect`, `RemoveThreat`, `FixThreat`, or arbitrary-method command exists (guarded by `ServiceActivationReviewTests`). |

The router (`DataVangerServiceCommandRouter`) validates **allowlist + bounded size** via
`IpcSecurityPolicy.ValidateRequest` **before** dispatch (default cap 64 KiB, absolute cap 1 MiB).
Oversized or non-allowlisted requests never reach the handler.

## 3. Request DTO — `RemediationExecutionRequestDto`

| Field | Type | Meaning |
|---|---|---|
| `CorrelationId` | string (GUID) | Required, non-empty, parses to a non-`Guid.Empty`. Binds the run. |
| `Action` | `RemediationIpcActionKind` | `Unknown=0` → rejected. Must match the target kind for the action. |
| `TargetKind` | `RemediationIpcTargetKind` | `Unknown=0` → rejected. Must equal `RemediationActionCatalog.TargetKindOf(action)`. |
| `TargetIdentity` | string | Required. For `File` targets, must pass `IpcSecurityPolicy.IsSafePath` (no `..`, no UNC, no invalid chars). |
| `ThreatBand` | `RemediationIpcThreatBand` | `Unknown=0` → rejected. |
| `HasConfirmedEvidence` | bool | Backed by known-malicious hash / confirmed YARA. |
| `EvidenceIsHeuristicOnly` | bool | Heuristic-only evidence can never drive a destructive action. |
| `IsSystemFile` | bool | System files are never remediated automatically. |
| `Consent` | `RemediationConsentTokenDto?` | Required for any non-automatic Allowed action. |

`RemediationConsentTokenDto` binds `Action`, `TargetKind`, `TargetIdentity`, `Tier`, `CorrelationId`,
`IssuedUtc`, `ExpiresUtc`. The service translates it into an engine `RemediationConsentToken` **only
after** validating every field; the gate then requires it to bind the **exact** action + target +
correlation + confirmation tier and to be unexpired.

## 4. Response DTO — `RemediationExecutionResponseDto`

Carries `CorrelationId`, `Authorized`, `Authorization` (`RemediationIpcAuthorization`),
`PolicyOutcome`, `RequiredConfirmation`, `DenialReason`, `Message`, `RequiresReboot`,
`RequiresVerification`, and per-step `Actions` (`RemediationActionExecutionResultDto`:
`Outcome`, `Succeeded`, `NoChange`, `Reason`). The UI renders this verbatim; it must not re-derive
policy.

## 5. Policy truth table the UI will observe (authoritative server-side)

| Band / evidence | Quarantine | Destructive removal | System-scope | Locked file |
|---|---|---|---|---|
| **Clean** | denied (NoAction) | denied | denied | denied |
| **Suspect** | denied (ReportOnly) | denied | denied | denied |
| **HighRisk** | **UserConfirmation** | **Blocked** (needs ConfirmedMalware) | Blocked | Blocked |
| **ConfirmedMalware + confirmed** | **automatic** (no consent) | UserConfirmation | AdvancedConfirmation | RebootConsent |
| ConfirmedMalware **without** confirmed evidence | treated conservatively as **HighRisk** | Blocked | Blocked | Blocked |
| Heuristic-only evidence | n/a | **Blocked** | Blocked | Blocked |
| **System file** | only ConfirmedMalware+confirmed, **AdvancedConfirmation, never automatic** | same | same | same |

`ConfirmedMalware` **quarantine** is the **only** automatic action. A destructive `DeleteFile` /
`HandleLockedFile` / `CleanDroppedPayload` request is automatically preceded by a `QuarantineFile`
containment step (quarantine-before-delete), each step independently gate-authorized.

## 6. Fail-closed contract (every one is covered by `RemediationIpcTests`)

Denied (no execution, `spy.Calls == 0`): malformed payload, unknown action, unknown target kind,
unknown band, target-kind/action mismatch, unsafe file path, missing consent when required, expired
consent, mismatched action/target/correlation, weaker **or** different (non-exact) consent tier,
oversized payload (before dispatch), Clean/Suspect/HighRisk-destructive/heuristic-only, and
system-file automatic.

## 7. Availability / honest unavailable states

- `DataVangerServiceCommandContext.RemediationExecutor` is `null` by default → the handler returns
  `IpcStatusCode.Unsupported` / `"RemediationUnavailable"`. A host opts in by wiring a
  `RemediationPlanExecutorAdapter(new RemediationExecutor(provider, journal, clock, options))`.
- The engine remains **simulation-only** (Phase 03A): `RemediationExecutor` refuses non-simulation
  providers unless `AllowNonSimulationProviders` is set, and no real OS destructive provider exists
  yet. Until a real provider lands, an executing host **simulates**; the UI must present results as
  reported and must not imply real removal occurred.

## 8. What Phase 05 must do

- Build `RemediationExecutionRequestDto` from the user's confirmed choice; send
  `ExecuteRemediationAction`; render `RemediationExecutionResponseDto` honestly (plan, reversibility,
  reboot, verification, per-step outcome, denial reason).
- Default destructive dialogs to the **safe/cancel** action; never lower a confirmation tier.
- Never execute locally; never reference `DataVanger.Engine`.

## 9. Known limitations (MUST be closed before a real destructive provider is enabled)

1. **Client-asserted threat band/evidence.** The handler currently trusts `ThreatBand`,
   `HasConfirmedEvidence`, `EvidenceIsHeuristicOnly`, and `IsSystemFile` from the request. A local
   client that is already past the IPC ACL could assert `ConfirmedMalware + confirmed` and pair it
   with a fabricated consent token to authorize a destructive action on a structurally-safe,
   non-system path. **Required fix:** the service must derive the band/evidence/system-file flags
   from a **server-side detection record** keyed by `CorrelationId`, not from the request.
2. **Client-supplied consent with client-set expiry.** Consent originates in the request. The phase's
   target design is a **service-issued** consent/permit (preview → consent → execute with a
   server-side, correlation-bound permit store and a server-bounded short TTL). Until then, treat the
   consent TTL as advisory and keep it short.

These are bounded today by: the 02B IPC ACL (who may call the pipe), `IsSafePath` (no system/UNC
paths), quarantine-before-delete (reversibility), and the absence of any real destructive provider.
They are **not** sufficient for production and are the headline items for Codex (Altissimo)
stabilization and the future detection-correlation work.
