# BETA 11 — HEURISTIC NOISE & SYSTEM-FILE FALSE-POSITIVE REDUCTION (PLANNING/JUDGMENT) REPORT

Phase: `BETA_11_HEURISTIC_NOISE_AND_SYSTEM_FILE_FP_REDUCTION` (DataVanger V.Beta Improvement Plan)
Executed: 2026-06-15
Branch: `claude/bold-albattani-7o16j4`, on the latest stable DataVanger Beta baseline.

Verdict: **PLANNING / JUDGMENT ONLY. No code changed. No scan behavior, detection threshold, anti-false-
positive policy, YARA, quarantine, remediation, IPC, signed-update, or service behavior changed. No dormant
engine activated.** Deliverable = root-cause analysis of heuristic noise / system-file false positives in a
real Full Scan, plus an anti-FP strategy, sub-phase breakdown, recommended order, and effort estimates.

---

## 1. Source data (uploaded Full Scan report)

`DataVanger v3.1-alpha`, profile **Full**, 14/06/2026 20:21, 5,758s:

- Files analyzed: **119,298**; HighRisk (ALTO RISCO): **6,213**; Suspect (SUSPEITO): **4,960**;
  Confirmed malware (CRÍTICO): **0**; Known-malware hits: **0**.
- Signatures loaded: **0 hashes, 0 lightweight YARA, 0 real-YARA rules** (so every verdict is heuristic).
- Authenticode checks performed: 27,079; Entropy checked: 74,142; ADS: 119,298; Scripts: 36,208.

Report mining (tag-stripped row parse):

- **HighRisk in `C:\Windows\WinSxS`: 3,910.** **HighRisk in `C:\Windows\System32`: 947.**
  → **4,857 ≈ 78% of all HighRisk are Windows OS files.**
- **Validly signed binaries still HighRisk: 166** (e.g. `claude.exe` signed `CN="Anthropic, PBC"`,
  `Netmarble Launcher.exe`, `libcef.dll`).
- Representative system-file HighRisk: `kerberos.dll`, `tlscsp.dll`, `localkdcsvc.dll` — each flagged
  **"PE sem assinatura Authenticode válida"** plus generic PE import evidence and
  **"Timestamp de compilação anômalo: 2032/2086/2097"**.

---

## 2. Findings & root-cause analysis

### RC-1 — Catalog-signature blind spot (dominant cause)
`DataVanger/Core/WinTrust.cs` `VerifyFile` sets `dwUnionChoice = WTD_CHOICE_FILE` → verifies **embedded
Authenticode only**, never Windows security **catalogs** (`WTD_CHOICE_CATALOG` /
`CryptCATAdminCalcHashFromFileHandle` / `CryptCATAdminEnumCatalogFromHash`). Windows system DLLs are
**catalog-signed**, so they return `isSigned=false` → "PE sem assinatura Authenticode válida".
`GetSignerSubject` reads only the embedded cert. This misclassifies kerberos.dll/tlscsp.dll/etc. as
unsigned.

### RC-2 — The blind spot disables every existing relief path
Because `isSigned=false` for system DLLs (`DataVanger/Core/ScanEngine.cs`, `AnalyzeSingleFileAsync`):
- the `−6` untrusted-signed relief never applies (`score = ... Math.Max(0, score - 6)`);
- the trusted-publisher early-exit never fires;
- `DataVanger/Reputation/ReputationEngine.cs`'s **`−12` "trusted signer"** relief — which requires
  `IsSigned && IsTrustedPublisher` — never fires.
The agent confirmed that *with* signing these reliefs pull a Microsoft DLL to Clean
(`+9 imports − 12 trusted-signer → 0`); the blind spot is what blocks it.

### RC-3 — No system-path context on Full/Deep
`ScanEngine.IndexEligibleFilesAsync` applies path trust only as `if (!deep && PathTaxonomy.IsTrustedPath(...))
{ SkippedTrustedPath++; continue; }`. It is (a) a **skip, not a score relief**, (b) **disabled on Deep/Full**
(`deep == true`), and (c) `PathTaxonomy.IsTrustedPath` does **not** include `System32`/`SysWOW64`. On a Full
scan, System32/WinSxS therefore receive **zero** location-based relief.

### RC-4 — PE import heuristics overweighted and uncapped
`DataVanger/Detection/PE/PeImportAnalyzer.cs` + `PeCorrelationEngine.cs`:
injection imports **+4 (High)**, network+exec **+3**, DPAPI **+2**, dynamic-API (LoadLibrary+GetProcAddress)
**+2**, persistence/services **+1/+2**, anti-debug **+1**; "Correlação PE moderada **+2**" at a loose
**2-signal** threshold; "Recurso contém payload MZ **+4**". These APIs are normal in OS DLLs, CEF/Electron
runtimes and installers. A benign API-heavy DLL can reach **+14 from imports alone**; the PE category has
**no cap** and **no signature/path/trust gating** — unlike `DataVanger/Detection/HeuristicAnalyzer.cs`, which
already suppresses path heuristics in protected directories. HighRisk (≥9) is trivially crossed
(`+4 injection +3 net/proc +2 correlation = +9`).

### RC-5 — Reproducible-build timestamps misread
`DataVanger/Detection/PE/PeHeaderAnalyzer.cs` flags compile time `> now + 2 days` as
"Timestamp de compilação anômalo" (+1). Modern Windows DLLs use deterministic/hashed PE timestamps (report
shows 2032/2086/2097), so this fires on legitimate OS files.

### RC-6 — Publisher trust underweighted and name-only
`DataVanger/Core/PublisherIdentity.cs` default mode is **Substring** name match. A **valid** Authenticode
chain from a publisher not in `DataVanger/Core/AppSettings.cs` `DefaultTrustedPublishers` gets only **−6**
(e.g. Anthropic, Netmarble). The default list lacks Anthropic and common OEMs; no chain/thumbprint
validation runs in the active path.

### RC-7 — Actionable vs informational not separated at the tier level
`DataVanger/Core/ThreatClassificationPolicy.cs` `Classify` keys purely on summed `ScoreDelta`
(Suspect ≥ 6, High ≥ 9, Critical ≥ 14, `RiskThresholds` in `Models.cs`). `EvidenceStrength` labels confidence
but does **not** affect the tier, so a pile of Low/Medium evidence with **no single corroborating actionable
signal** still reaches HighRisk.

### What already works — must be preserved
The anti-FP **clamp** (`score ≥ Critical && !confirmed → High`, `Classification/AntiFalsePositivePolicy.cs`
+ `ScanEngine`); **automatic action only for ConfirmedMalware** (blacklist hash / confirmed YARA);
reputation **prevalence relief** (−4/−8) and **trusted-signer −12**; the **persistence gate**;
`HeuristicAnalyzer` protected-path suppression; Info/0 descriptive evidence (PE arch/sections/subsystem).

---

## 3. Judgments

| Question | Verdict |
|---|---|
| System32/WinSxS as HighRisk | **Architecturally flawed** (RC-1/RC-3), not expected. |
| Signed binaries reaching HighRisk | **Overly aggressive** (RC-2/RC-6). |
| Publisher trust weighting | **Underweighted** — name-only; −6 for any valid untrusted signature; missing OEMs/Anthropic; no catalog signer. |
| PE import heuristics weighting | **Overweighted** — uncapped, loose correlation, no trust/path gating. |
| System32/WinSxS context | **Missing** on Full/Deep. |
| Reputation effectiveness | Effective *when it can fire*, but blocked by RC-1 for the files that need it. |
| Risk-tier calibration | Numeric thresholds + Critical clamp **appropriate, keep them**; missing an actionable-corroboration requirement and a trust/system context feeding the score. |

---

## 4. Recommended architecture & anti-FP strategy

1. **Single `TrustContext` per file** computed once and shared by scoring:
   `{ EmbeddedSigned, CatalogSigned, SignerSubject, PublisherTrust (Untrusted/Valid/Trusted),
   SystemPath (System32/SysWOW64/WinSxS/servicing) }`. Replaces the scattered relief in `ScanEngine`.
2. **Trust-aware attenuation, not suppression.** PE/heuristic weights are *attenuated* when the file is
   catalog/embedded-signed-valid and/or in a real system path, while security-relevant signals (RWX section,
   entry-point outside sections, packer, masquerade, embedded MZ in a user-writable path) keep full weight.
3. **Actionable-corroboration rule.** A signed-and-trusted or genuine-system file must not reach HighRisk on
   summed Low/Medium import evidence alone; it needs ≥1 corroborating *actionable* signal — implemented
   **without** moving the numeric thresholds or the Critical clamp.
4. **Strategy invariants (forbidden).** Do not weaken the Critical clamp; do not bypass known-malicious-hash
   or confirmed-YARA; do not auto-quarantine beyond ConfirmedMalware; do not silently exclude risky file
   types/paths; relief flows **only** from positive trust evidence (valid catalog/embedded chain, real system
   path), never from the mere absence of evidence.

---

## 5. Sub-phase breakdown, recommended order & effort

Recommended order: **11A → 11B → 11D → 11C → 11E → 11F** (front-load the biggest, safest reducer; defer the
riskiest weight changes until trust/context exist).

| # | Sub-phase | Scope | Effort | Risk | FP impact |
|---|---|---|---|---|---|
| **11A** | `CATALOG_SIGNATURE_VERIFICATION` | Extend `WinTrust` to verify via security catalogs (`WTD_CHOICE_CATALOG` + `CryptCATAdmin*`); extract catalog signer subject. Catalog-signed → `isSigned=true`, unlocking the existing Microsoft trusted-publisher/reputation relief. | M (native interop, Windows-validate) | Med (native) | **Highest** — most of the 4,857 system-file HighRisk |
| **11B** | `SYSTEM_PATH_CONTEXT` | `TrustContext.SystemPath` for System32/SysWOW64/WinSxS/servicing; **score relief (not skip)** that applies on Deep/Full; keep masquerade checks. Safety net where 11A cannot confirm. | S–M | Low | High |
| **11D** | `PUBLISHER_TRUST_HARDENING` | Catalog signer subject; graduated relief for *valid* chains (valid-untrusted > −6, < trusted); optional chain/thumbprint mode; expand default OEM list (Anthropic opt-in). | S–M | Low–Med | Medium (signed-app FPs incl. claude.exe/Netmarble) |
| **11C** | `PE_IMPORT_RECALIBRATION` | Cap PE-category contribution; gate import deltas by `TrustContext` (signed/system/trusted → informational); tighten "Correlação PE" to **3 signals** for Medium; reproducible-build timestamp tolerance; separate "informativo técnico" from "risco acionável". | M | Med (weights) | Medium (API-heavy benign apps) |
| **11E** | `TIER_ACTIONABLE_SEPARATION` | Require ≥1 actionable corroboration for HighRisk on trusted/system files; keep Suspect/High/Critical numbers + clamp; optional "review" bucket / report calibration. | S–M | Med | Medium (tail) |
| **11F** | `FP_REGRESSION_CORPUS` | Tests: catalog-signed System32 DLL → not HighRisk; embedded-signed trusted app → Clean; API-heavy benign DLL → not HighRisk on imports alone; **and** planted known-malicious-hash / confirmed-YARA still → ConfirmedMalware (no anti-FN regression). Woven through 11A–11E, finalized last. | M | Low | Guards all of the above |

**Total effort:** Medium–Large (11A and 11C are the M anchors; the rest S–M).

**Risk analysis:** the principal danger is over-correcting into **false negatives**. Mitigations in every
sub-phase: relief only from positive trust evidence; preserve masquerade/RWX/packer/embedded-payload weight;
never touch known-malicious-hash or confirmed-YARA; preserve the Critical clamp and ConfirmedMalware-only
quarantine; the 11F corpus asserts detection still fires.

---

## 6. Recommended implementation order (relative to other work)

`BETA_11` is a detection-quality phase, independent of the dormant-engine `09x` series and the `BETA_10`
performance phase. It should run when FP quality is prioritized; 11A alone yields the largest single
reduction. Each sub-phase is one PR with Windows `dotnet build`/`dotnet test` and focused filters
`~AntiFalsePositive`, `~Publisher`, `~Reputation`, `~Scan`, `~Pe`/`~Detection`.

---

## 7. Required statements

- **No dormant engine was activated**, silently or otherwise.
- **No scan behavior, detection threshold, anti-FP policy, YARA, quarantine, remediation, IPC, signed-update,
  or service behavior was changed.** This phase is documentation/planning only; no code changes were required.
- **Files reviewed:** `WinTrust.cs`, `ScanEngine.cs`, `PathTaxonomy.cs`, `HeuristicAnalyzer.cs`,
  `Detection/PE/*` (PeImportAnalyzer, PeSectionAnalyzer, PeResourceAnalyzer, PeOverlayAnalyzer,
  PeHeaderAnalyzer, PeMetadataAnalyzer, PeSignatureAnalyzer, PeCorrelationEngine), `PeDetectionModule.cs`,
  `Reputation/ReputationEngine.cs` (+ LocalReputationDatabase), `Core/PublisherIdentity.cs`,
  `Core/AppSettings.cs`, `Core/ThreatClassificationPolicy.cs`, `Classification/AntiFalsePositivePolicy.cs`,
  `Core/Models.cs`, and the uploaded HTML report.
- **Files changed:** `outputs/BETA_11_HEURISTIC_NOISE_AND_SYSTEM_FILE_FP_REDUCTION.md` (new),
  `DataVanger/ALTERACOES_BETA.md` (appended).

## 8. Risks and open questions

- Catalog verification (11A) is native Win32 interop and **must be validated on Windows**; behavior cannot be
  exercised in the current Linux/no-SDK environment.
- The exact attenuation factors (11B/11C) and the graduated valid-signature relief (11D) need an empirical
  pass against a labeled benign+malicious corpus before numbers are fixed — 11F's corpus is the gate.
- 11C is the highest-regression-risk step; it must land only after trust/context (11A/11B/11D) so attenuation
  is anchored on positive trust, not on lowered weights alone.

## 9. Final recommendation / status

**Proceed with `BETA_11_HEURISTIC_NOISE_AND_SYSTEM_FILE_FP_REDUCTION`** as a planning deliverable, sub-phases
in order **11A → 11B → 11D → 11C → 11E → 11F**. Current behavior is **architecturally flawed for system
files** (catalog blind spot) and **overly aggressive for signed/API-heavy binaries**, not expected. The
numeric risk tiers and the anti-FP clamp are sound and must be preserved; the fix is to give scoring a
trust/system context and to separate actionable risk from informational evidence. No dormant engine
activated; no scan behavior changed.
