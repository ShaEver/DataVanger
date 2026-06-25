## Phase 03B Final Report

Phase: `03B_FILE_AND_QUARANTINE_REMEDIATION` — UltraCode.
Executed: 2026-06-12.
Verdict: **File/quarantine remediation implemented with quarantine-before-delete enforced at the type
level; 24 new tests (69 remediation total) pass on Linux against the REAL QuarantineService; purely
additive; destructive-API audit clean. Windows full/x64 suite pending (standing environment exception).**

- **Branch/checkpoint:** `claude/adoring-dirac-jxo678` on the adopted post-03A stabilized baseline
  (clean ZIP, 689 entries; delta = 4 remediation-core stabilization files; adopted then validated).

- **Files changed:** purely additive — **6 new Engine files** under `DataVanger.Engine/Remediation/Files/`
  and **2 new test files**. `git status` shows only new files; **no existing file modified**, so quarantine,
  anti-FP, classification, scan, YARA, IPC, and UI behavior are unchanged by construction.
  - Engine: `FileRemediationAbstractions.cs` (FileHashValue, IFileHashProvider, IFileSystemRemediationOperations),
    `RemediationSafePathPolicy.cs` (ISafePathPolicy + conservative default), `QuarantineRemediationGateway.cs`
    (IQuarantineRemediationGateway + adapter over IQuarantineService, IQuarantineStoreCleanup + store adapter),
    `FileRemediationModels.cs` (request/reference/result/outcome types), `SystemFileRemediationOperations.cs`
    (real SHA-256 + the single gated File.Delete), `FileRemediationService.cs` (the orchestrator).
  - Tests: `RemediationFileTests.cs` (17), `RemediationSafePathPolicyTests.cs` (7).

- **Quarantine-before-delete enforcement (two independent layers):**
  1. **Type level:** the only way to delete an original is `DeleteOriginalAsync(VerifiedQuarantineReference)`.
     `VerifiedQuarantineReference` has an **internal-only constructor** and is produced solely by a successful,
     verified `QuarantineAsync`. There is no `DeleteOriginalAsync(string path)` overload. A delete therefore
     cannot even be expressed before a verified quarantine exists. (Proven by reflection tests.)
  2. **Control flow:** `QuarantineAndDeleteAsync` runs delete only when quarantine returned `Quarantined`;
     any blocked quarantine returns without attempting deletion.

- **Hash / safe-path behavior:**
  - **Hash (TOCTOU):** `QuarantineAsync` records the hash of the content actually quarantined
    (`record.OriginalSha256`). `DeleteOriginalAsync` **re-hashes the on-disk file immediately before deleting**
    and returns `BlockedHashMismatch` (no delete, quarantine copy retained) if it no longer matches — proven by
    a test that swaps the file content between quarantine and delete.
  - **Safe path:** `RemediationSafePathPolicy` refuses empty/relative/non-absolute paths, traversal (`..`),
    invalid chars, ADS suffixes, directories, and any path under a protected system root (Windows + System32 +
    Program Files via `Environment.GetFolderPath`, plus a curated Unix root list so the gate is testable on
    every platform; extra roots injectable). Reparse points/symlinks are refused at delete time via
    `IsReparsePoint` (fail-safe: unreadable attributes are treated as a reparse point).

- **Store-delete distinction:** `DeleteQuarantineStoreRecordAsync(QuarantineStoreDeleteRequest)` removes only
  the encrypted payload via `IQuarantineStore.DeletePayloadAsync`. `QuarantineStoreDeleteRequest` exposes
  **only a `QuarantineId`** (no path member — proven by reflection), so store cleanup can never target an
  original file. A test confirms it removes the payload while leaving the original on disk; an unknown id
  returns `StoreRecordNotFound`.

- **Rollback behavior:** `RestoreAsync(RollbackToken)` accepts only a `QuarantineRestore` token and delegates
  to the **unchanged** `IQuarantineService.RestoreAsync`, preserving its strong warnings and integrity checks.
  A test deletes a real file then restores it byte-for-byte through quarantine; a non-quarantine token is
  refused.

- **Tests run:** 24 new (17 file + 7 safe-path), **all passing on Linux** compiled against the real
  `DataVanger.Engine` (which links the real `QuarantineService`, `InMemoryQuarantineStore`,
  `QuarantineCryptoProvider`, `InMemoryQuarantineKeyProtector`). Combined 03A+03B remediation suite: **69/69
  pass.** All four cross-platform projects build **0 errors / 0 warnings.** The mandated full/x64/`~Quarantine`/
  `~AntiFalsePositive` runs are **Windows-only** (standing exception) but **unaffected by construction** —
  this phase modified no existing file.

- **Destructive API audit:** `grep` over `DataVanger.Engine/Remediation/Files/` for `File.Delete/Move`,
  `Directory.Delete`, `Process.Kill`, `Registry`, `ServiceController`, `schtasks`, `MoveFileEx`,
  `PendingFileRename`, `InitiateSystemShutdown` → **exactly one match**: `SystemFileRemediationOperations.DeleteOriginal`,
  reached only after the quarantine/hash/safe-path/journal gates. Invariants: 0 empty catch, 0 `lock(qm)`,
  0 CRLF.

- **Intentionally NOT implemented (phase boundary):** process kill, service stop/disable, registry autorun
  removal, scheduled-task removal (all `03C`); locked-file / reboot / `PendingFileRenameOperations` (`03D`);
  Removal Center UI; any `Remediation` IPC command/handler; any change to restore semantics,
  `AutoQuarantineKnownMalware`, or anti-FP. No real provider was wired into the 03A simulation-only executor,
  so 03A's "no real provider reachable via the executor" guarantee is preserved; the FileRemediationService is
  a directly-driven service that phase 04's Detection→Action policy will orchestrate.

- **Stop conditions encountered:** none. No path deletes before verified quarantine; hash verification is
  mandatory and unbypassable; safe-path policy is present and tested; quarantine semantics untouched; store
  cleanup cannot delete arbitrary originals; anti-FP code untouched; no UI/IPC removal exposure.

## Self-Stabilization Review

**Risks checked, and findings:**

1. **Cross-platform blind spots** — All 03B code is in `DataVanger.Engine` (net8.0, no WPF/XAML), so there is
   no XAML compile risk and no WPF-vs-WinForms type ambiguity. Windows-only APIs were audited: `AesGcm`,
   `SHA256.ComputeHashAsync`, `File.GetAttributes(...).HasFlag(ReparsePoint)`, and
   `Environment.GetFolderPath(SpecialFolder.Windows)` are all cross-platform; the latter returns empty on
   Linux and empty roots are skipped. No Windows-only test was added, so none can silently pass on Linux
   (all 24 new tests execute and pass on Linux). **Found & avoided:** the safe-path denylist would have been
   a no-op (and thus untested) on Linux if it only used Windows special folders — I added a curated Unix root
   list and an injectable extra-roots ctor so system-path refusal is proven on this platform too.

2. **Test/API mismatch** — Every test compiles and runs against the real Engine + Shared assemblies, so all
   referenced APIs exist with the signatures used (`QuarantineResult.Stored/Failure`,
   `QuarantineRestoreResult.Failure`, `QuarantineIntegrityResult` init-props, `IQuarantineStore.PayloadExistsAsync/
   DeletePayloadAsync`, `IQuarantineService.ListAsync/VerifyAsync/GetAsync`, the InMemory ctors). **No
   InternalsVisibleTo is required:** the only internal member (`VerifiedQuarantineReference`'s constructor) is
   never constructed by tests — they obtain the reference from `QuarantineAsync`, and the reflection test
   asserts the *absence* of a public constructor (which needs no internal access). **Found & fixed:** a garbled
   leftover assertion line in the first test (`result.Reason + result.Outcome is not null ? ...`) was removed
   before validation.

3. **Resource/build integration** — No .resx/XAML/csproj/satellite added. Verified both `DataVanger.Engine`
   and `DataVanger.Tests` use SDK **default compile globbing** (no `EnableDefaultCompileItems=false`, no explicit
   `<Compile>` list), so the 6 new Engine files and 2 new test files are automatically part of the real
   `DataVanger.sln` build — they are not orphaned isolated-harness files.

4. **Safety-policy consistency** — Anti-FP not weakened: classification is carried, never derived; automatic
   quarantine remains the quarantine service's ConfirmedMalware-only decision. Quarantine semantics unchanged —
   **git confirms no quarantine/classification/anti-FP file was modified**; I only added wrapper adapters. No
   remediation IPC/UI exposure. The one new destructive action (file delete) is gated (verified quarantine +
   hash match + safe path), journaled (intent-before-delete via the 03A journal), and rollback-aware
   (QuarantineRestore token).

5. **Phase-boundary enforcement** — 03C (process/service/registry/task) and 03D (locked-file/reboot) were not
   started; no Removal Center UI; the validated quarantine infrastructure was wrapped, not rewritten; changes
   are minimal and surgical (additive only).

6. **Required local checks** — Ran the available validation (harness build + 69-test remediation run + 4
   project builds, all green); ran the `~Remediation`-equivalent filter (all new classes carry "Remediation");
   ran a forbidden-API/forbidden-scope grep (one expected gated `File.Delete`); re-read every changed file for
   namespace/API mistakes; confirmed no `bin/obj/TestResults/Publicar/.vs`/nested-zip is staged.

**What remains Windows-only / Codex-only:** The full `dotnet test DataVanger.Tests` (and `--arch x64`) cannot
run here because the test project references the net8.0-windows WPF project; only a Windows run can prove the
**full** test assembly links and that all 168 baseline + new tests pass together. Residual risk is low — the
new tests depend only on Engine/Shared/xunit/System.* (identical between harness and the real assembly) and
use unique class names with no WPF/WinForms type collisions — but it is not zero and must be closed on Windows.
Real reparse-point behavior on Windows (junctions) is exercised only via the faked `IsReparsePoint` here; a
Windows manual check against a real junction is advisable.

**Known prior mistake pattern prevented:** the recurring "passes in an isolated same-assembly harness but the
real test project doesn't compile" trap was mitigated by (a) verifying SDK default globbing includes the files
in the real build, (b) avoiding any InternalsVisibleTo dependency, and (c) keeping test dependencies to types
that are identical across harness and real assembly. The "Windows-only test silently passes on Linux" trap was
avoided by making every new test cross-platform-meaningful.

**Codex stabilization recommendation:** **Recommended, MEDIUM risk level.** The logic is heavily tested and
purely additive, but this is the first real destructive capability, so a Windows stabilization pass should:
run the full default + x64 suites and `~Quarantine`/`~AntiFalsePositive`/`~Remediation` filters; re-audit the
single `File.Delete` against its gates; verify reparse handling against a real Windows junction; and confirm no
quarantine regression. Risk is medium (not high) because deletion is impossible without a verified quarantine by
type, and no existing file was changed.
