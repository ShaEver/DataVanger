# BETA 02B — IPC ACL SECURITY GATE REPORT

Phase: `02B_IPC_ACL_SECURITY_GATE` (DataVanger V.Beta Improvement Plan)
Executed: 2026-06-12
Verdict: **GATE CODE-COMPLETE. Existing DACL model verified; fail-closed required-hardening mode added;
silent Windows-only test passes converted to explicit skips; 23 gate/ACL tests run on Linux
(14 pass, 9 skip-with-reason, 0 fail, 0 warnings). Windows matrix pending (standing exception).**

---

## 0. Baseline replacement (pre-phase requirement)

- **ZIP cleanliness:** PASS — 659 entries, 0 matches for `bin/obj/TestResults/Publicar/.vs/` or nested zips.
- **Replacement:** tree wiped except `.git`, repopulated verbatim; tree-vs-zip diff: 0.
- **Exact delta vs previous committed baseline: ZERO** — the uploaded ZIP is byte-identical to the
  pushed post-02A state (659 = 656 + the three 02A files). Stabilization changed nothing; no adoption
  commit was needed.
- **Baseline validation:** Shared/Engine/Infrastructure/Service build 0 errors. Full sln/tests/x64
  remain Windows-only (standing environment exception).

## Phase 02B Final Report

- **Branch/checkpoint:** `claude/adoring-dirac-jxo678` on the verified post-02A baseline.

- **Files changed:**
  - `DataVanger.Infrastructure/Ipc/IpcOptions.cs` — new `RequireAclHardening` (default false).
  - `DataVanger.Infrastructure/Ipc/NamedPipeDataVangerServiceHost.cs` — fail-closed gate in
    `CreateServerStream` (analyzer-friendly guard; zero CA1416).
  - `DataVanger.Tests/TestSupport/WindowsOnlyFactAttribute.cs` — new `WindowsOnlyFact`/`WindowsOnlyTheory`
    (xUnit `Skip` set at discovery: non-Windows runs report SKIPPED with explicit reason).
  - `DataVanger.Tests/IpcAclTests.cs` — 8 `[Fact]`→`[WindowsOnlyFact]`, 1 `[Theory]`→`[WindowsOnlyTheory]`,
    9 silent `if (!OperatingSystem.IsWindows()) return;` guards removed (assertions untouched).
  - `DataVanger.Tests/IpcAclGateTests.cs` — new (6 tests, `~IpcAclGate` ⊂ `~Ipc` filter).
  - `outputs/BETA_02B_IPC_ACL_SECURITY_GATE_REPORT.md` — this report.

- **Pipe security model (verified, pre-existing from Alpha Phase 16 + completed here):**
  - **Central policy:** `IpcPipeSecurity.Build(IpcOptions)` is the single DACL constructor;
    `IpcPipeSecurity.CreateServerStream` the single ACL'd-pipe factory; the host's
    `CreateServerStream` is the only production creation path and uses them.
  - **Default-deny DACL:** explicit **Deny for Network logon SID** (evaluated before allows);
    Allow FullControl for the creating user and LocalSystem; configured principals
    (`AllowedPrincipalSids`, SDDL or account name) added as **ReadWrite only**; malformed/unresolvable
    entries ignored (never broaden); **Everyone, Anonymous, Network, Guests can never be granted**
    even if explicitly configured (`IsForbiddenPrincipal`).
  - **Fail-closed completion (this phase):** new `IpcOptions.RequireAclHardening` — when set, the host
    **throws instead of ever opening an unrestricted pipe** (hardening disabled → throw; platform
    without pipe security descriptors → throw). ACL-construction failures always propagate; there is
    no catch that could fall back to an insecure pipe. Default false so existing test transports and
    non-Windows unit tests are unchanged; **production service composition (phase 03/04) must set it
    to true** — recorded as a hand-off requirement.
  - Production exposure note: `NamedPipeDataVangerServiceHost` is currently composed **only in tests**
    (verified by search) — the service does not yet start the pipe host, so the gate lands before any
    real surface exists.

- **Command catalog enforcement (verified):** `DataVangerServiceCommandRouter.HandleAsync` calls
  `IpcSecurityPolicy.ValidateRequest` **first** — null envelope → BadRequest; command not in
  `DataVangerCommandCatalog` allowlist → `UnknownCommand`; payload size → `PayloadTooLarge` — all
  before any handler dispatch. Category dispatch falls through to a structured `UnknownCommand`
  (never a default handler). Handler exceptions are contained as `InternalError`. New test proves a
  fuzzed out-of-range enum value (9999) is rejected by the policy before any handler.

- **Payload allowlist / size bounds (verified intact, not weakened):** 64 KiB default,
  **1 MiB hard ceiling that misconfiguration cannot disable** (oversized init clamps down, degenerate
  values fall back to default) — now pinned by test. Framing throws `InvalidDataException` on
  oversized/truncated frames before allocation; serialization remains defensive
  (`TryDeserializeRequest`/`TryDeserializePayload` per-command DTOs). No constant changed.

- **Windows ACL tests:** all 9 DACL tests (Everyone/Anonymous absent, Network denied, creator+
  LocalSystem allowed, configured principal R/W, invalid ignored, forbidden SIDs never granted,
  mixed lists, forbidden-principal classifier, SID resolution) now **skip with an explicit reason**
  on non-Windows instead of silently passing — proven in this run: `Skipped: 9` with reason
  "Windows-only: exercises Windows named-pipe security descriptors (ACL/DACL)". On Windows they run
  unchanged (assertions untouched).

- **Negative tests (new + verified):**
  - `RequireAclHardening` + hardening disabled → host **throws** ("Refusing to open an unrestricted
    pipe"), cross-platform deterministic — PASS.
  - `RequireAclHardening` on a platform without pipe ACLs → **throws**, never a plain pipe — PASS
    (meaningful on Linux; inert by construction on Windows).
  - Out-of-range command id → `UnknownCommand` before dispatch — PASS.
  - Oversized frame end-to-end over a real pipe: host rejects, **does not crash, and provably never
    reaches the inner handler** (handler would throw an exception type the host does not swallow) — PASS.
  - Bounds pinned: ceiling clamp + degenerate fallback — PASS.
  - Pre-existing negatives confirmed in place: unknown command, oversize payload, unsafe path,
    malformed envelope (host returns structured BadRequest), forbidden principals.

- **Manual IPC validation:** PENDING on Windows — §11 checklist (authorized status query, malformed/
  oversized/unknown rejection without crash, no payload leakage in logs, UI non-elevated, no
  remediation command) to be run with the §12 matrix:
  `dotnet test --filter "FullyQualifiedName~Ipc"` / `~Service` plus full default and x64 suites.

- **Remediation allowed to proceed: CONDITIONALLY YES.** The gate is code-complete and
  Linux-verified: central DACL, fail-closed required-hardening mode, catalog-first authority, intact
  bounds, explicit Windows skips. Phases 03/04 may **start** on top of it, with two binding
  conditions: (1) the Windows stabilization run must confirm `~Ipc`/`~Service` plus full/x64 suites
  green before any 03/04 work **ships**, and (2) the phase-04 service composition **must set
  `RequireAclHardening = true`** for the production host — that flag is the contract this phase
  hands forward. No remediation command/DTO/handler exists yet (re-verified by the 02A guard test).

- **Stop conditions encountered:** none — no fail-open path exists (the only non-ACL pipe is the
  explicitly non-required mode used by tests), bounds unchanged, allowlist authoritative, no
  remediation capability added.

## Validation summary

| Check | Result |
|-------|--------|
| Scratch harness (real Infrastructure+Shared projects): `IpcAclGateTests` + converted `IpcAclTests` | **14 passed, 9 skipped (with reason), 0 failed** |
| Builds Shared/Engine/Infrastructure/Service | **0 errors, 0 warnings** (CA1416 found during dev and fixed by inlining the platform guard) |
| Invariants on changed files (empty catch / CRLF / lock patterns) | **0 / 0 / 0** |
| Full sln build, default + x64 suites, `~Ipc`/`~Service` on Windows | **PENDING** (standing environment exception) |

## Recommendation

**Ready for Codex stabilization** (the phase MD recommends it): focus on the §15 checklist — confirm
no pipe host construction bypasses `IpcSecurityPolicy`/`IpcPipeSecurity` (verified here by search),
no frame/payload constants changed (pinned by test), remediation names absent (02A guard test), and
run the Windows ACL tests for real plus the manual §11 smoke. No scope expansion.
