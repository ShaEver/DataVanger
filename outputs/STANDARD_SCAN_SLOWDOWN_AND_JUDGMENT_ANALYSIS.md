# Standard Scan — mid-scan slowdown root cause + judgment analysis

Analysis of a real **Standard** scan (`DataVanger_Report.csv`, 1.085 findings). Two issues: (A) the scan
becomes very slow a bit before halfway, on every profile; (B) the result is dominated by false-positive
noise. The performance fix in this commit addresses (A); (B) is documented here as a remediation roadmap.

## A. Why it slows down mid-scan — ROOT CAUSE (fixed in this commit)

**Catalog signature verification ran per file with no result cache** (a BETA 11A regression).

- `ScanProfileRegistry.SignatureCheckThreshold(Standard) = 6`, so **any file with pre-score ≥ 6 enters the
  trust gate** — common for DLLs/EXEs with a couple of PE-import evidences. Many more files cross the gate
  than appear in the report (they are relieved below 6 *after* paying the cost).
- The gate called `WinTrust.VerifySignature`, which tried embedded Authenticode first and, for the majority
  of files (no embedded signature), fell through to `VerifyViaCatalog`: **per file** it acquired a catalog
  context, **re-read+hashed the entire file** (`CryptCATAdminCalcHashFromFileHandle`), and searched the OS
  catalog store — only to fail. There was **no signature/trust cache** (only the SHA-256 hash cache existed).
- **83 % of findings are in `AppData\Local`** (Wondershare, CapCut, Git, Store Packages, Electron apps…),
  which are **never catalog-signed**. Standard walks small folders first, then the dense `AppData\Local`
  region — so throughput collapses right around the middle. Deep/Full (threshold 4) hit it even harder →
  "independente do nível".

### Fix shipped
1. **Catalog probe is now gated to genuine system locations** (`PathTaxonomy.ClassifySystemPath != None`).
   Non-system/third-party files skip the catalog probe entirely (they are never catalog-signed). Embedded
   Authenticode is still checked for every file, so third-party embedded-signed apps are still recognized.
   This removes the dominant per-file cost and is correctness-aligned.
2. **Persistent signature-trust cache** (`SignatureTrustCache`, `trust_cache.json`) keyed by
   `(path, last-write, length)` + a trust fingerprint (OS catalog-store stamp). Unchanged files are not
   re-verified → repeat scans are fast.
3. Catalog admin context is intentionally **still acquired per call** (per-thread safety under the parallel
   worker pool); items 1–2 already eliminate the bulk of the cost.

Secondary costs noted but not changed here (lower impact): multiple full-file reads per file (SHA-256, PE
parse, entropy, embedded WinVerifyTrust twice), `lock(MetricLock)` on ~10–18 metric increments per file,
`LocalReputationDatabase` lock + growth, and `CpuThrottleDelayMs` (per-file `Task.Delay` if set > 0).

## B. Judgment problems in the result (remediation roadmap — not changed here)

Distribution: **853 SUSPEITO + 232 ALTO RISCO, 0 CRÍTICO; 0 blacklist, 0 confirmed.** Scores cluster at the
floor (6 = 494, 7 = 233, 8 = 126; 9+ = 242). **83 % in `AppData\Local`.**

- **J-1 (highest leverage): no signature/YARA database is loaded.** Zero confirmed / zero known-hash / zero
  YARA → the scanner is running **blind** and can only emit heuristic Suspect/HighRisk; every finding is
  unconfirmable. This recurs in every report. Action (config/data, not classification): load a signature +
  YARA feed (or ship a default) and surface a prominent "0 assinaturas / 0 YARA carregadas" warning so the
  operator knows results are heuristic-only.
- **J-2: AppData benign-app FP flood.** The bulk are legitimate installed apps (Wondershare 368, CapCut 163,
  Store `Packages` 226, Git 50, GitHub Desktop 32, Netmarble 25, Minecraft 18…) flagged for "em AppData" +
  "sem assinatura em local gravável" + "DLL fora de pasta de sistema" + common imports. Action: extend the
  benign-container notion (`PathTaxonomy.IsKnownBenignScriptContainer`) to common app-install containers
  (Electron `resources\app`, Windows Store `Packages`, per-vendor app folders) and/or raise
  `MinScoreToReport` so the score-6 marginal tail is not surfaced.
- **J-3: validly-signed third-party vendors flagged.** Wondershare (335), ByteDance/CapCut (79), Brave,
  Netmarble, GitHub, Telegram, OBS, Ollama, Perplexity, McAfee… all carry **valid Authenticode** but are
  untrusted → BETA 11D grants only −6, so they land Suspect and **61 reach ALTO RISCO**. A valid CA-issued
  chain is meaningfully exculpatory; recommend a "valid signature, untrusted publisher" handling with more
  relief (or a quieter tier) than an unsigned file. *(Trusted-publisher relief IS working — no Microsoft/
  Google findings.)*
- **J-4: "actionable" PE signals over-fire on benign apps.** "Recurso contém payload com cabeçalho MZ" (70)
  and "Correlação PE forte" (75) push installers/Electron/game launchers to ALTO RISCO. Recommend that
  embedded-MZ alone (in a signed or known-app-container context) not count as actionable corroboration — an
  11C/11E tuning.
- **J-5: "Metadados alegam Microsoft fora de caminho comum" (259)** fires on genuine Microsoft components in
  AppData (.NET, Store apps, Teams/VS Code). Recommend suppressing it when the file is embedded-signed by a
  trusted publisher.

J-2…J-5 are FP-tuning follow-ons to BETA 11 (candidate sub-phases). J-1 is the single highest-leverage item
and is data/config.

## Validation

No .NET SDK here (Linux; solution is `net8.0-windows`) — Windows validation required:
`dotnet build DataVanger.sln`; `dotnet test ... --filter "FullyQualifiedName~Signature|~Catalog|~Scan|~Pe|~AntiFalsePositive"`.
Performance check: re-run a Standard scan with a large `AppData\Local`; confirm mid-scan throughput no longer
collapses (catalog skipped for AppData) and a **second** scan is fast (trust-cache hits in the telemetry).
Confirm catalog-signed System32/WinSxS components are still recognized as signed (BETA 11A/F catalog tests).
Preserved: ConfirmedMalware, Critical clamp, ConfirmedMalware-only auto-quarantine, and all BETA 11 behavior.
