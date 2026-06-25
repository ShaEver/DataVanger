## Phase 03D Final Report

Phase: `03D_LOCKED_FILE_REBOOT_AND_VERIFICATION` — UltraCode.
Executed: 2026-06-13.
Verdict: **Locked-file/reboot state machine + pending-operation journal + cancel + idempotent replay +
post-remediation verification implemented; 33 new fake-backed tests (140 remediation total) pass on Linux
against the real Engine; no real reboot or pending-registry write exists; purely additive. Windows full/x64
suite + real OS provider pending.**

- **Branch/checkpoint:** `claude/adoring-dirac-jxo678` on the adopted post-03C stabilized baseline (clean ZIP,
  714 entries; delta = 9 03C-stabilization files — JSON-serialized backups + token rollback overloads +
  expanded service denylist; adopted then validated 0-error/0-warning builds).

- **Files changed:** purely additive — **6 new Engine files** (`DataVanger.Engine/Remediation/Reboot/` ×5,
  `DataVanger.Engine/Remediation/Verification/` ×1) and **3 new test files**. `git status` shows only new
  files; **no existing file modified**, so anti-FP, quarantine, the 03A/B/C remediation work, scan, YARA, IPC,
  and UI are unchanged by construction.
  - Engine: `RebootModels.cs`, `PendingRebootOperationStore.cs`, `PendingFileOperationProvider.cs`,
    `LockedFileRemediation.cs`, `PendingOperationActions.cs`, `Verification/RemediationVerificationService.cs`.
  - Tests: `LockedFileRebootRemediationTests`, `PendingOperationStoreTests`, `PostRemediationVerificationTests`.

- **Reboot-required state model:** `RebootRequiredState` = NotRequired → Required → Queued → Canceled /
  Replayed → Verified / Failed. A restart can be *required* and *queued* without the product ever rebooting
  automatically.

- **Pending operation journal / cancel model:** `PendingRebootOperation` (id, kind=DeleteOnReboot, target path,
  correlation id, explicit cancel token, quarantine rollback token, before-state ref, status, timestamps) is
  held in `IPendingRebootOperationStore` as an **append-only state-transition log + current-state projection**.
  Allowed transitions are validated (Queued→{Canceled,Replayed,Failed}; Replayed→{Verified,Failed};
  Canceled/Verified/Failed terminal). `CancelPendingOperationAction` cancels a Queued op before reboot
  (clearing the fake OS-deferred delete) and is **blocked once the op has been replayed** — cancellation is a
  pre-reboot-only control.

- **Locked-file escalation:** `LockedFileRemediationAction` never forces a delete and never reboots. It (1)
  quarantines the file first via the unchanged 03B `FileRemediationService` (a reversible, verified copy + a
  quarantine-restore rollback token), (2) if the file is NOT locked, deletes it normally (`RemovedNow`,
  NotRequired), (3) if it IS locked, requires explicit reboot consent — without consent it stops at
  `Required` and queues nothing; with consent it journals the pending operation FIRST, re-validates the safe
  path, then hands the deferred delete to the (fake) OS seam and records it `Queued`. A failed journal write
  blocks the queue (`BlockedJournalFailed`).

- **Replay / idempotency behavior:** `PendingOperationReplayer` runs after a (simulated) restart. For each
  still-`Queued` op it checks target presence: absent → `Queued→Replayed` (deferred delete applied); present →
  `Queued→Failed` (the boot delete did not happen — honest "not removed"). Any op that is no longer Queued is a
  **no-op**, so a service that starts twice after reboot cannot double-apply — proven by a test asserting
  exactly one `Replayed` journal record across two replay passes.

- **Verification behavior:** `RemediationVerificationService` runs targeted checks (FileAbsent, PersistenceGone,
  QuarantineRecordValid, ScanClean) over injected probes and reports **clean ONLY when every requested check
  passes** (and at least one check ran). Any failing probe becomes a visible failing finding describing the
  remaining artifact — verification can never report "clean" while an artifact remains, and an empty check
  list is not clean.

- **Tests run:** 33 new fake-backed tests: locked-with-consent queues + quarantines (original not deleted now),
  locked-without-consent queues nothing, unlocked removes now, journal-before-provider-queue, cancel-before-
  reboot clears the pending delete, cancel-after-replay blocked, replay-applies-once-and-is-idempotent,
  replay-with-present-target marks Failed, store transition validity/idempotency/terminal-state, verification
  clean/dirty per check kind and empty-list-not-clean, plus reflection guards that the only pending-file
  provider is the simulation one and no shutdown/restart type exists in the Reboot namespace. Combined
  03A–03D remediation suite: **140/140 pass** on Linux against the real Engine. All four cross-platform
  projects build **0 errors / 0 warnings**. The mandated full/x64/`~Remediation`/`~Quarantine`/`~Service` runs
  are **Windows-only** (standing exception) but unaffected by construction.

- **Real reboot / pending-operation audit:** `grep` over `Reboot/` + `Verification/` for `MoveFileEx`,
  `PendingFileRenameOperations`, `InitiateSystemShutdown`, `ExitWindows`, `Environment.Exit`, `Process.Start`,
  `Registry`, shutdown/restart → **every match is in an XML-doc comment or a user-facing reason string** (e.g.
  "a restart is required to finish removal"); there is **no real reboot, shutdown, registry write, or
  pending-file API call anywhere**. The only `IPendingFileOperationProvider` implementation is the in-memory
  `SimulationPendingFileOperationProvider`. Invariants: 0 empty catch, 0 `lock(qm)`, 0 CRLF.

- **UI exposure: None.** No Removal Center UI, no `Remediation` IPC, no Detection→Action policy. Presentation
  of reboot-required state and verification results is deferred to phase 05.

- **Intentionally NOT implemented (phase boundary + scope decision):** the real Windows pending-delete provider
  (`MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)` / `PendingFileRenameOperations`) and a real lock detector /
  presence probe are deliberately deferred to a Windows-validated follow-up — keeping the Engine cross-platform
  and ensuring **no real reboot/pending-write exists before phase 05/policy**, exactly matching the phase's
  "no real reboot, fake provider only" Reality Rule. Also not implemented: any UI, IPC, or auto-execution.

- **Stop conditions encountered:** none. No automatic-reboot path exists; no test queues a real reboot or real
  pending delete (fakes only); a pending op cannot be queued without a journal entry; cancel-before-reboot is
  present and tested; replay is idempotent; verification failure is a visible failure, never hidden as success;
  anti-FP/quarantine code is untouched.

## Self-Stabilization Review

**Risks checked, and findings:**

1. **Cross-platform blind spots** — All 03D code is in `DataVanger.Engine` (net8.0, no WPF/XAML), so there is
   no XAML/WinForms ambiguity and (unlike 03C) no namespace-shadowing risk (`Reboot`/`Verification` are not BCL
   roots). No Windows-only API is used: the pending-file provider and probes are abstractions whose only
   implementation here is an in-memory fake; the real `MoveFileEx`/`PendingFileRenameOperations` binding is
   deferred. No Windows-only test was added — all 33 tests run cross-platform (temp files + fakes).

2. **Test/API mismatch** — Every test compiles and runs against the real Engine, so all referenced APIs exist
   with the signatures used (the locked-file test composes the real `FileRemediationService` exactly as 03B/03C
   do). **No `InternalsVisibleTo` is required** — every type/member the tests touch is public. No issue found
   that needed a fix here; the build was clean on first compile after the Engine build.

3. **Resource/build integration** — No .resx/XAML/csproj/satellite added. Both projects use SDK default compile
   globbing (verified in earlier phases), so the 6 new Engine files and 3 new test files are automatically part
   of the real `DataVanger.sln` build.

4. **Safety-policy consistency** — Anti-FP not weakened (no classification logic; the flow only quarantines via
   the unchanged 03B service and carries classification through). Quarantine semantics unchanged (git confirms
   no quarantine file modified). No remediation IPC/UI exposure. The one destructive-intent path (queue a
   delete-on-reboot) is gated (explicit reboot consent + safe-path revalidation), journaled before the OS seam
   is touched, rollback-aware (quarantine-restore token), cancelable before reboot, and policy-ready (driven
   only by tests).

5. **Phase-boundary enforcement** — Phase 05 (UI) not started; no Removal Center; no Detection→Action policy;
   03A/B/C infrastructure reused (the locked-file flow composes 03B's service), not rewritten; the change is
   minimal and additive. Real OS provider deferral is a conservative narrowing.

6. **Required local checks** — Ran the available validation (harness build + 140-test remediation run + 4
   project builds, all green); ran the `~Remediation`-equivalent filter (every new class is covered);
   ran the forbidden-API/forbidden-scope grep (all matches are comments/strings, no real calls); re-read every
   changed file for namespace/API mistakes; confirmed no `bin/obj/TestResults/Publicar/.vs`/nested-zip is
   staged.

**Issues found and fixed before final report:** none required code changes this phase — the Engine compiled
cleanly on first build and all tests passed first run. (Proactively, the namespaces were chosen to avoid the
BCL-shadowing trap that bit 03C, and `?.`-on-non-null was avoided to prevent the phantom-nullable-warning trap.)

**What remains Windows-only / Codex-only:** (a) the full `DataVanger.Tests` (net8.0-windows, WPF-referencing)
cannot link on Linux — only a Windows run proves the full assembly + all 168 baseline tests + the 140
remediation tests link and pass together; (b) **the real pending-delete provider, lock detector, and presence
probe are not implemented** — the entire state machine, journal, cancel, idempotent replay, and verification
logic are implemented and fake-tested, but the real `MoveFileEx`/`PendingFileRenameOperations` write, real lock
detection (delete-share open), and real verification probes are a Windows deliverable, deferred to avoid
untestable platform-specific surface and to keep the codebase free of any real reboot/pending-write. These
could not be proven here because they require Windows APIs and a real reboot cycle.

**Known prior mistake pattern prevented:** the "namespace shadows a BCL root" trap (which broke the 03C build)
was avoided by choosing `Reboot`/`Verification` names; the "`?.` on non-null members → phantom nullable
warnings" pattern was avoided; and the "isolated-harness compiles ≠ real test assembly compiles" trap was
mitigated by depending only on public APIs identical across harness and real assembly with no InternalsVisibleTo
dependency.

**Codex stabilization recommendation:** **Recommended, MEDIUM risk level.** The state-machine/journal/replay/
verification logic is heavily fake-tested and purely additive, and no real reboot/pending-write exists yet
(which lowers risk). A Windows stabilization pass should: run the full default + x64 suites and the
`~Remediation`/`~Quarantine`/`~Service` filters; and, when the real pending-delete provider is later
implemented, re-audit the `MoveFileEx`/`PendingFileRenameOperations` write and the post-reboot replay against a
real reboot cycle (idempotency under a real double service start; cancel clearing the real registry entry).
Risk is medium (not high) because every gate lives in the tested action/store layer and the providers are inert
fakes today.
