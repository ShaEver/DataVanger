# BETA 05 — REMOVAL CENTER UI REPORT

Phase: `05_REMOVAL_CENTER_UI` (DataVanger V.Beta Improvement Plan)
Executed: 2026-06-13 (supersedes the earlier "BLOCKED" status of this phase — its prerequisite, the
policy-gated remediation IPC surface, now exists via Phase 04B and its Codex stabilization).
Verdict: **IMPLEMENTED as a WPF-free, testable MVVM Removal Center (consent/visualization surface) plus a
thin Windows-only view, dialog standard, and Threats entry point. It consumes the Shared remediation DTOs
through a typed IPC gateway, never references the engine, and never executes remediation locally. 16 ViewModel
tests added. Honestly scoped: the IPC surface is execute-only (no consent-issuance / journal / rollback /
verify commands and no detection→context registration yet), so the full destructive/rollback/verify manual
journeys are not yet wireable; and this Linux container has no .NET SDK, so nothing was compiled or run here.
Both are flagged as Windows/Codex validation risks.**

- **Branch/checkpoint:** `claude/confident-gates-f355wn`, on the adopted 04B-stabilized baseline.

## Baseline replacement result

- **ZIP cleanliness:** no `bin/`, `obj/`, `TestResults/`, `Publicar/`, `.vs/`, no nested zip. 646 files +
  97 dirs; doubly-nested wrapper; extracted tree matched the listing; post-copy `diff -rq` empty (exact
  mirror, not a merge).
- **Exact delta vs previous baseline** (HEAD `3f250ad`): **1 new file + 4 modified, 393 insertions /
  132 deletions, 0 removed, no forbidden artifacts.** The archive is the **Codex stabilization of Phase
  04B**: it adds `DataVanger.Service/Ipc/RemediationServerContextStore.cs` and rewrites the handler/DTOs/tests
  so the threat band, evidence, system-file status, and consent are **server-authoritative** — the client's
  values are explicit "legacy echo, ignored for authorization", and missing/mismatched server context fails
  closed (`RemediationContextMissing`). This closes the HIGH finding from my 04B report. Adopted as commit
  `0163437`.

## Views / ViewModels added

| File | Role | Platform |
|---|---|---|
| `DataVanger/ViewModels/RemovalCenterViewModel.cs` | WPF-free MVVM brain: state machine, request build, response mapping, safe-default + button-enablement logic | net8.0 logic (testable) |
| `DataVanger/ViewModels/RemovalCenterState.cs` | State enum + threat-context + step-view records | net8.0 |
| `DataVanger/ViewModels/IRemovalCenterService.cs` | Typed IPC gateway (DTO in / DTO out) — the UI's only path to remediation | net8.0 |
| `DataVanger/ViewModels/RemovalCenterService.cs` | Gateway adapter over `IDataVangerServiceClient` (System.Text.Json, Shared-only) | net8.0 |
| `DataVanger/ViewModels/OfflineRemovalCenterService.cs` | Honest "service unavailable" gateway (no concrete client wired yet) | net8.0 |
| `DataVanger/Localization/RemovalCenterLabels.cs` | i18n facade (resource-backed, `{x:Static}`) | net8.0 |
| `DataVanger/Views/RemovalCenterWindow.xaml(.cs)` | Thin host window; renders bound VM state; safe-default confirmation | **WPF (Windows-only)** |
| `DataVanger/MainWindow.xaml(.cs)` | Threats entry point: a "Central de Remoção" button + `OnRemovalCenter` handler | **WPF (Windows-only)** |
| `DataVanger/Localization/UiStrings(.en-US).resx` | 13 pt-BR keys + 4 en-US scaffold keys (fallback) | resource |

## What was implemented

- A **policy-driven Removal Center center** (the "05A" core) with the full required state machine: Empty,
  PlanReady, AwaitingConfirmation, Executing, Succeeded, Failed, RebootRequired, VerificationNeeded.
- **Driven entirely by IPC/policy:** the VM builds a `RemediationExecutionRequestDto`, sends it through the
  gateway (which issues the single `ExecuteRemediationAction` IPC command), and renders the
  `RemediationExecutionResponseDto` — policy outcome, authorization, required confirmation, reboot/verification
  flags, denial reason, and per-step results. It never executes locally and references no engine type.
- **Destructive-dialog standard:** a destructive action moves to `AwaitingConfirmation` before anything is
  sent; the confirm dialog's **safe action (cancel) is the default button and gets focus**, the destructive
  confirm button is never the default. The UI cannot lower a confirmation requirement.
- **Reboot-required / verification / failure honesty:** reboot-required is explicit and never automatic;
  verification-needed and partial/failed states are surfaced with honest messages; IPC failure (null/throw)
  maps to `Failed`.
- **Threats entry point:** a button in the Threats area opens the Removal Center for the selected finding.

## IPC commands consumed

`DataVangerCommandType.ExecuteRemediationAction` (the only remediation command), with the Shared DTOs
`RemediationExecutionRequestDto` / `RemediationExecutionResponseDto` / `RemediationActionExecutionResultDto`.

## Dialog standard implemented

Confirmation gate for destructive actions; safe/cancel is the default and focused; reversible
(quarantine/verify) actions skip the gate but still pass through the server policy.

## What was intentionally NOT implemented (and why)

- **No new IPC command, DTO, handler, or Engine reference** — Phase 05 is UI-only; the IPC surface is consumed,
  not extended (forbidden scope §6; phase-boundary rules).
- **No Removal Center nav-rail section** — to keep the `ShellNavigationTests` "no Removal Center" guard intact,
  the center is reached as a Threats-triggered window (matching the `ReviewFixWindow` pattern), which also
  satisfies "threat-action entry point".
- **Live consent / journal / rollback / verify wiring** — the IPC surface has **no** consent-issuance,
  plan-preview, journal, rollback, or verify command, and consent is server-issued with no IPC trigger; the
  WPF process also has no concrete `IDataVangerServiceClient` wired and the server does not yet register a
  detection context for a UI correlation id. So those journeys are **not yet wireable**. The VM renders all
  those states honestly but the entry point runs against the offline gateway (honest "service unavailable")
  rather than faking success.

## Tests added / results

`DataVanger.Tests/RemovalCenterViewModelTests.cs` — **16 ViewModel tests** with a fake gateway and the real
DTOs: Prepare→PlanReady + context exposure; destructive→requires-confirmation + safe default; quarantine
not-destructive; destructive Proceed→AwaitingConfirmation **without executing**; non-destructive
Proceed→executes; cancel→PlanReady without executing; confirm→executes; confirm-without-state→no-op;
DeniedByPolicy→Failed+reason; ConsentMissing→Failed; RebootRequired→RebootRequired; VerificationRequired→
VerificationNeeded; null IPC response→Failed; gateway throws→Failed; authorized+all-succeeded→Succeeded.
**Could not be executed here** (no .NET SDK; `DataVanger.Tests` is `net8.0-windows` and references the WPF
project).

## Validation commands run and results

No .NET SDK / MSBuild / mono in this container; the phase's `dotnet restore/build/test` (+ `--arch x64`, the
`~Remediation/~AntiFalsePositive/~Ipc/~Service` filters) are **NOT RUNNABLE here** — standing environment
exception. Static validation performed:

| Check | Result |
|---|---|
| ZIP cleanliness / exact-mirror replace | PASS |
| XML well-formedness: `RemovalCenterWindow.xaml`, `MainWindow.xaml`, both `.resx` (xmllint) | PASS |
| ViewModel core is WPF-free (no `System.Windows` in VM/service/state) | PASS |
| Invariants on all new `.cs` (empty `catch{}` / CRLF) | 0 / 0 — PASS |
| WPF `DataVanger.csproj` references only `DataVanger.Shared` (no Engine) — unchanged | PASS |
| New files auto-included by SDK default globbing (`UseWPF=true`, no explicit includes) | PASS |
| Production APIs called exist (`IDataVangerServiceClient.SendAsync/IsAvailable`, `DataVangerRequest.Create`, `DataVangerResponse.PayloadJson`, all consumed DTO members) | PASS (verified against source) |
| Forbidden-API audit on new UI code (`MoveFileEx`/`PendingFileRenameOperations`/`shutdown`/`Process.Start`/Engine/`RemediationExecutor`) | none — PASS |
| `ShellSection` untouched → `NoRemovalCenter` nav guard intact | PASS |

## Manual validation results

**Not performed — Windows-only.** The mandatory WPF journeys (threat→plan→consent→remove→reboot→rollback→
verify, keyboard/focus, non-elevated) require a Windows WPF runtime (absent here) and, for the
destructive/rollback/verify legs, IPC commands that do not yet exist. They are listed as Windows/Codex
validation items.

## Stop conditions encountered

None of the hard stop conditions (UI executes privileged action; UI bypasses policy/consent; default
destructive button unsafe; reboot hidden; engine/policy/IPC tests regress) were hit — verified by audit. The
"manual journeys cannot be completed" condition is **partially** implicated for the destructive/rollback/
verify legs because the IPC surface lacks those commands; this is documented as a remaining increment rather
than a regression, and the implemented surface is honest about it (no faked success).

## Remaining risks / follow-up

1. **IPC surface is execute-only.** To complete the destructive/rollback/verify journeys, add (server side):
   detection→`RemediationServerContextStore.Register` wiring; a consent-issuance command (so the UI's
   confirmation maps to `IssueConsent`); and journal/rollback/verify query commands. The VM already models
   these states and will consume them with minimal change.
2. **No concrete IPC client in WPF.** Inject a real `IDataVangerServiceClient` (the named-pipe client, §7
   "usage only") via app composition so `RemovalCenterService` goes live; the entry point currently uses the
   offline gateway.
3. **Windows-only validation debt (standing):** WPF/XAML compile, the 16 ViewModel tests, the resx/satellite
   generation, and the manual journeys can only be proven on Windows with the SDK.

## Recommendation

**Ready for Codex stabilization (light, as the phase recommends) on Windows** — build the solution, run the
ViewModel tests + the focused filters, eyeball the dialog defaults/focus and policy rendering, and confirm no
accidental direct-action call. The deeper "make it live" work (the three missing IPC commands + detection
context registration + client injection) is a focused server-side increment, not UI rework.

---

## Self-Stabilization Review

**Risks checked:**

1. **Cross-platform blind spots.** Treated no-SDK Linux as *not* proof of Windows success. The testable core
   (`RemovalCenterViewModel` + gateway + state + adapter) is **WPF-free** (verified: no `System.Windows`), so
   the logic carries no XAML/WinForms ambiguity. The project sets `UseWindowsForms=true` **and** `UseWPF=true`,
   so the WPF code-behind (`Window`, `Visibility`) was checked for ambiguity — those types are WPF-only (no
   WinForms `Window`/`Visibility`), and `MainWindow.xaml.cs` additions use **fully-qualified** type names to
   avoid any `using`-level collision. XAML compile, x:Static resolution, and resx/satellite generation remain
   **Windows-only**.

2. **Test/API mismatch.** I read the real `RemediationIpcDtos`, `IDataVangerServiceClient`, `DataVangerRequest`,
   `DataVangerResponse`, policy and gate before writing. Every test and the VM/adapter call only verified
   members; the 16 tests use a fake gateway + real DTOs and were re-read against the production API. No
   `InternalsVisibleTo` reliance — all new VM types are `public`.

3. **Resource/build integration.** `DataVanger.csproj` is SDK-style with `UseWPF=true` and no explicit
   `<Page>`/`<Compile>` includes, so the new `.cs`/`.xaml` are auto-globbed (XAML as Page). The resx edits are
   well-formed (xmllint) and follow the 01B keyed pattern; the `RemovalCenterLabels` facade matches
   `ShellLabels`. The XAML uses the existing `loc:` namespace and `BtnSecondary` style. **Windows-only:** that
   the XAML actually compiles, the satellite (en-US) generates, and `{x:Static}` binds.

4. **Safety-policy consistency.** Anti-FP, YARA, classifier thresholds, and quarantine semantics are
   **untouched** (none in the delta). No destructive behavior, no reboot/`MoveFileEx`/`PendingFileRenameOperations`/
   shutdown, no HighRisk-destructive relaxation, no broadening of automatic actions — the UI only *renders*
   server decisions. ConfirmedMalware automatic behavior remains quarantine-only (server-side; unchanged).

5. **Remediation IPC / policy-gate rules.** `RemediationExecutionGate` is **not** bypassed (the UI never calls
   it; the service does). The UI does **not** execute remediation; it consumes Shared DTOs only over the IPC
   gateway. The WPF project does **not** reference `DataVanger.Engine` (csproj verified). Client-supplied band/
   evidence/system-file/consent are **non-authoritative** (the 04B server store decides) — the VM does not even
   populate them. Execution still uses the server-issued, non-forgeable permit + `ExecuteAuthorizedAsync` on the
   service side.

6. **Phase-boundary enforcement.** No next-phase work, no new IPC surface, no real OS providers, no reboot
   behavior, no Engine reference. Minimal, surgical: a Threats-triggered window (no nav-shell change), reusing
   existing styles and the established WPF-free-VM precedent.

**Issues found and fixed before final report:** (a) the WPF project references only Shared, so the gateway was
designed to serialize with `System.Text.Json` (wire-compatible with the service's IpcSerialization) and depend
on the Shared `IDataVangerServiceClient` interface — avoiding any Engine/Infrastructure reference; (b) the
entry point had no concrete client, so an honest `OfflineRemovalCenterService` was used rather than faking
success; (c) avoided adding a `ShellSection` so the existing "no Removal Center" guard test stays green.

**What remains Windows-only / Codex-only:** WPF/XAML compile + the 16 ViewModel tests + resx satellite
generation + all manual journeys; and the deeper "make it live" increment (three missing IPC commands +
detection context registration + concrete client injection).

**Known prior mistake pattern prevented:** "Linux compile success mistaken for Windows" (compiled nothing,
said so); "test calls a non-existent API" (verified every member against source); "WPF vs WinForms namespace
ambiguity" (WPF-only types + fully-qualified names in code-behind); "premature/forbidden IPC or Engine
exposure" (UI consumes Shared DTOs only, no Engine ref, gate not bypassed); "faking success over an incomplete
surface" (offline gateway is honest).

**Codex stabilization recommended, and at what risk level:** **Recommended, LOW–MEDIUM.** The safety-critical
gate lives server-side and is unchanged; this phase is UI over proven gates. Codex should do the Windows
build/test pass, eyeball dialog defaults/focus + policy rendering, and confirm no direct-action call. Risk is
LOW for the safety surface and MEDIUM only for "does the unverified WPF/XAML compile and bind on Windows".

## Security Boundary Review

- **UI / IPC / service / policy / engine boundaries preserved?** **Yes.** WPF references only
  `DataVanger.Shared` (no Engine — csproj verified). The UI talks to the service exclusively through the
  `IRemovalCenterService` gateway → `IDataVangerServiceClient.SendAsync` → the single
  `ExecuteRemediationAction` command. No new IPC surface; no handler/gate change in this phase.
- **Client-supplied security claims ignored / non-authoritative?** **Yes.** Band, evidence, system-file
  status, and consent are server-authoritative (04B `RemediationServerContextStore`); the request DTO's
  matching fields are explicit "legacy echo, ignored". The VM does not even populate them.
- **Server-authoritative context used where required?** **Yes** — the service resolves context by correlation
  id + target and fails closed (`RemediationContextMissing`) when absent. The UI cannot supply it.
- **`RemediationExecutionGate` mandatory for execution?** **Yes** — every execution path on the service side
  goes through the gate and `ExecuteAuthorizedAsync` with a server-issued, non-forgeable permit. The UI has no
  execution path at all.
- **Any action bypass consent / correlation / permit / policy?** **No.** The UI cannot bypass anything; it only
  sends a request and renders the server's decision. Denials (policy/consent/missing-context) render as
  honest `Failed` states.
- **HighRisk destructive remediation still blocked?** **Yes** (server policy, unchanged; the UI renders the
  block honestly).
- **ConfirmedMalware automatic behavior still quarantine-only?** **Yes** (server policy, unchanged).
- **Anti-FP / YARA / classifier / quarantine behavior unchanged?** **Yes** — none of those files are in the
  delta; this phase adds only UI consuming Shared DTOs.
