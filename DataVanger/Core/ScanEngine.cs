using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Classification;
using DataVanger.Core.Abstractions;
using DataVanger.Core.Domain;
using DataVanger.Detection;
using DataVanger.Engine;
using DataVanger.Infrastructure;
using DataVanger.Reporting;
using DataVanger.Reputation;
using DataVanger.Shared.Quarantine;

namespace DataVanger.Core;

/// <summary>
/// Top-level scan orchestrator. Implements <see cref="IScanEngine"/> and
/// retains the original public surface so the WPF UI and CLI need no changes.
///
/// What this class does:
///   - exposes well-known paths (settings, reports, quarantine, etc.),
///   - builds the per-scan <see cref="ScanContext"/>,
///   - walks the target tree, indexes eligible files,
///   - drives the <see cref="DetectionPipeline"/> for every file in parallel,
///   - applies cross-cutting concerns the pipeline must not touch
///     (Authenticode trust gate, anti-FP clamp, quarantine triggering),
///   - persists reports, bounded cache observations and local reputation.
///
/// What this class does NOT do:
///   - it does not contain detection rules; those live in
///     <see cref="DataVanger.Detection"/>,
///   - it does not decide a verdict; that lives in
///     <see cref="ThreatClassificationPolicy"/> /
///     <see cref="ThreatClassifier"/>,
///   - it does not render reports; that lives in
///     <see cref="ReportGenerator"/>.
/// </summary>
public class ScanEngine : IScanEngine
{
    public string MgRoot         { get; }
    public string QuarantineRoot { get; }
    public string SignatureRoot  { get; }
    public string YaraRulesRoot  => Path.Combine(SignatureRoot, "yara_rules");
    public string SettingsPath   => Path.Combine(MgRoot, "appsettings.json");
    public string LogCsvPath     => Path.Combine(MgRoot, "DataVanger_Report.csv");
    public string LogCsvPrevPath => Path.Combine(MgRoot, "DataVanger_Report_Previous.csv");
    public string LogTxtPath     => Path.Combine(MgRoot, "DataVanger_Summary.txt");
    public string LogHtmlPath    => Path.Combine(MgRoot, "DataVanger_Report.html");
    public string LogJsonPath    => Path.Combine(MgRoot, "DataVanger_Report.json");
    public string PersistTxtPath => Path.Combine(MgRoot, "Persistence_Report.txt");
    public string ReputationPath => Path.Combine(MgRoot, "local_reputation.json");
    public string WhitelistPath  => Path.Combine(MgRoot, "whitelist_sha256.txt");
    public string BlacklistPath  => Path.Combine(MgRoot, "blacklist_sha256.txt");
    public string HashCachePath  => Path.Combine(MgRoot, "hash_cache.json");
    public string TrustCachePath => Path.Combine(MgRoot, "trust_cache.json");
    public QuarantineRuntime Quarantine { get; }

    private AppSettings _settings = new();
    private SignatureDatabase _signatures = new();

    // Extensions that make a file eligible for scanning. Anything outside
    // these sets is skipped during indexing, matching v3.0 behaviour exactly.
    private static readonly HashSet<string> DangerExt = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".scr", ".com", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".ps1", ".psm1", ".msi", ".lnk", ".iso", ".img", ".dll", ".sys", ".hta" };

    private static readonly HashSet<string> ArchiveExt = new(StringComparer.OrdinalIgnoreCase)
        { ".zip", ".jar", ".war", ".ear", ".docm", ".xlsm", ".pptm", ".docx", ".xlsx", ".pptx", ".xlam", ".xla", ".hta", ".chm" };

    private static readonly HashSet<string> DocumentExt = new(StringComparer.OrdinalIgnoreCase)
        { ".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx", ".ppt", ".pptm", ".pptx", ".pdf", ".xlam" };

    private static readonly HashSet<string> PeExt = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".dll", ".sys", ".scr", ".com", ".ocx", ".cpl" };

    private static readonly HashSet<string> ScriptExt = new(StringComparer.OrdinalIgnoreCase)
        { ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".ps1", ".psm1", ".hta" };

    private static readonly HashSet<string> ExeExt = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".scr", ".com" };

    private static readonly HashSet<string> EntropyExt = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".scr", ".com", ".dll", ".sys" };


    public ScanEngine(QuarantineRuntime? quarantineRuntime = null)
    {
        MgRoot         = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "DataVanger");
        QuarantineRoot = Path.Combine(MgRoot, "Quarantine");
        SignatureRoot  = Path.Combine(MgRoot, "Signatures");
        Directory.CreateDirectory(MgRoot);
        Directory.CreateDirectory(QuarantineRoot);
        Directory.CreateDirectory(SignatureRoot);
        Directory.CreateDirectory(YaraRulesRoot);
        Quarantine = quarantineRuntime ?? QuarantineCompositionRoot.CreateForCurrentUser(MgRoot, QuarantineRoot);
        if (!File.Exists(WhitelistPath)) File.WriteAllText(WhitelistPath, "");
        if (!File.Exists(BlacklistPath)) File.WriteAllText(BlacklistPath, "");

        // Seed the bundled default detection pack (EICAR baseline) so the scanner is not
        // blind out of the box. Idempotent + additive — never overwrites user-edited lists.
        DefaultSignaturePack.EnsureSeeded(SignatureRoot);
    }

    public async Task<(List<ScanFinding> findings, ScanMetrics metrics)> RunAsync(
        ScanOptions options, Action<string> log, CancellationToken ct,
        Action<int, int>? onProgress = null,
        Action<ScanProgressInfo>? onProgressInfo = null)
    {
        var swTotal = Stopwatch.StartNew();

        // FASE 2 — when a Deep-scan layer config is supplied, project its analysis
        // layers onto the per-scan flags the detection modules already gate on
        // (Archive/Document/BrowserExtension Supports() read options.Scan*), so the
        // user's Deep customization is honored without touching each module. Target
        // scope (user/system/program folders) is honored separately in
        // TargetDiscovery.ResolveTargets via options.DeepLayerConfig.
        if (options.DeepLayerConfig is { } dc)
        {
            options.ScanArchives          = dc.AnalyzeArchives;
            options.ScanDocuments         = dc.AnalyzeDocuments;
            options.ScanBrowserExtensions = dc.AnalyzeBrowserExtensions;
        }

        var state = LoadConfiguration(log);
        try
        {
            var context = await CollectGlobalContextAsync(options, state, log, onProgressInfo, ct).ConfigureAwait(false);
            var files = await IndexEligibleFilesAsync(options, state, log, onProgress, onProgressInfo, ct).ConfigureAwait(false);
            var findingsBag = await RunDetectionPhaseAsync(options, state, context, files, swTotal, log, onProgress, onProgressInfo, ct).ConfigureAwait(false);
            return await CommitResultsAsync(options, state, findingsBag, swTotal, log).ConfigureAwait(false);
        }
        finally
        {
            if (state.Deps.Yara is IDisposable disposableYara)
                disposableYara.Dispose();
        }
    }

    // Phase-scoped configuration/services/metrics produced by LoadConfiguration and
    // consumed by the later phases. Secure Quarantine V2 is application-scoped
    // and composed once by the constructor, not recreated per detection phase.
    private sealed record ScanState(
        AppSettings Settings,
        SignatureDatabase Signatures,
        LightweightYaraDatabase YaraDb,
        EngineComposition.EngineDependencies Deps,
        DetectionPipeline Pipeline,
        Sha256HashService HashService,
        LocalReputationDatabase Reputation,
        ReputationEngine ReputationEngine,
        HashSet<string> PrevHashes,
        DelegateScanLogger Logger,
        ScanMetrics Metrics,
        object MetricLock,
        ScanStageProfiler Profiler,
        SignatureTrustCache TrustCache)
    {
        public void Inc(Action<ScanMetrics> update) { lock (MetricLock) update(Metrics); }
    }

    private ScanState LoadConfiguration(Action<string> log)
    {
        // --- 1. Load configuration and signature data ------------------------
        _settings = AppSettings.Load(SettingsPath);
        _signatures = SignatureDatabase.Load(SignatureRoot, BlacklistPath, WhitelistPath);
        var yaraDb = _settings.EnableYaraRules ? LightweightYaraDatabase.Load(SignatureRoot) : new LightweightYaraDatabase();
        var metrics = new ScanMetrics();
        metrics.SignatureHashesLoaded = _signatures.TotalHashes;

        // --- 2. Build service graph ------------------------------------------
        var logger = new DelegateScanLogger(log);
        var hashService = new Sha256HashService(HashCachePath);
        if (hashService.Health.IsDegraded) metrics.CacheDegradationEvents++;
        var deps = EngineComposition.BuildDefault(hashService, _signatures, yaraDb, _settings, logger, YaraRulesRoot);
        // Report the rule count of the ACTIVE engine (real libyara when available),
        // not the lightweight fallback db — otherwise this reads 0 while YaraScanned>0.
        metrics.YaraRulesLoaded = deps.Yara.RuleCount;
        var pipeline = new DetectionPipeline(deps.Modules, deps.Classifier, logger);
        var reputation = new LocalReputationDatabase(ReputationPath);
        var reputationEngine = new ReputationEngine(_signatures, _settings);
        var prevHashes = LoadPreviousHashes();

        var trustCache = new SignatureTrustCache(TrustCachePath);
        if (trustCache.Health.IsDegraded) metrics.CacheDegradationEvents++;

        return new ScanState(_settings, _signatures, yaraDb, deps, pipeline, hashService, reputation, reputationEngine, prevHashes, logger, metrics, new object(), new ScanStageProfiler(), trustCache);
    }

    private async Task<ScanContext> CollectGlobalContextAsync(
        ScanOptions options, ScanState state, Action<string> log,
        Action<ScanProgressInfo>? onProgressInfo, CancellationToken ct)
    {
        var metrics = state.Metrics;

        // --- 3. Collect global context (persistence + running processes) ----
        log("[Scan] Coletando persistências (startup, registro, tarefas, serviços e WMI)...");
        onProgressInfo?.Invoke(new ScanProgressInfo { Phase = "Coletando persistências...", IsIndeterminate = true });
        var profPersist = state.Profiler.Measure("PersistenceCollection");
        var persistRaw = await Task.Run(PersistenceCollector.Collect, ct).ConfigureAwait(false);
        profPersist.Dispose();
        var persistExact = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in persistRaw)
        {
            var c = PersistenceCollector.ExtractPath(p);
            if (c != null) persistExact.Add(c);
        }
        var persistBlob = string.Join("\n", persistRaw).ToLowerInvariant();
        metrics.PersistenceItems = persistRaw.Count;
        try { File.WriteAllLines(PersistTxtPath, persistRaw, Encoding.UTF8); }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Persistence snapshot failed to write - make observable without aborting the scan.
            System.Diagnostics.Debug.WriteLine($"[DataVanger] Failed to write persistence snapshot '{PersistTxtPath}': {ex.Message}");
        }

        log("[Scan] Coletando processos em execução...");
        onProgressInfo?.Invoke(new ScanProgressInfo { Phase = "Coletando processos em execução...", IsIndeterminate = true });
        var profProc = state.Profiler.Measure("ProcessCollection");
        var runningPaths = await Task.Run(GetRunningProcessPaths, ct).ConfigureAwait(false);
        profProc.Dispose();
        metrics.RunningProcesses = runningPaths.Count;

        var context = new ScanContext(options, _settings, runningPaths, persistExact, persistBlob);

        return context;
    }

    private Task<List<FileInfo>> IndexEligibleFilesAsync(
        ScanOptions options, ScanState state, Action<string> log,
        Action<int, int>? onProgress, Action<ScanProgressInfo>? onProgressInfo, CancellationToken ct)
    {
        var deps = state.Deps;
        var metrics = state.Metrics;
        void Inc(Action<ScanMetrics> action) => state.Inc(action);

        // --- 4. Resolve scan targets ----------------------------------------
        bool deep = options.Profile == ScanProfile.Deep;

        var targets = TargetDiscovery.ResolveTargets(options.Profile, _settings, options.DeepLayerConfig).ToList();
        if (!string.IsNullOrWhiteSpace(options.Target))
        {
            try
            {
                var target = Environment.ExpandEnvironmentVariables(options.Target);
                if (Directory.Exists(target)) targets.Add(Path.GetFullPath(target));
                else if (File.Exists(target)) targets.Add(Path.GetFullPath(Path.GetDirectoryName(target)!));
            }
            catch (Exception ex) when (ex is not OutOfMemoryException
                                       and not StackOverflowException
                                       and not AccessViolationException
                                       and not System.Threading.ThreadAbortException)
            {
                // Invalid user-supplied target path - skip it and preserve the rest of the target set.
            }
        }
        // Beta 10 — collapse redundant targets (e.g. C:\ subsumes C:\Users\…\Downloads)
        // so overlapping subtrees are walked once instead of twice. No coverage is lost.
        targets = TargetDiscovery.RemoveContainedPaths(targets);
        metrics.Targets = targets.Count;
        log($"[Scan] {targets.Count} pastas alvo. Perfil: {options.Profile}");
        if (deep) log("[Scan] Perfil Deep ativo: análise abrangente; pode demorar e consumir CPU/disco.");
        log($"[Scan] Assinaturas carregadas: {metrics.SignatureHashesLoaded} hash(es), {metrics.YaraRulesLoaded} regra(s) YARA.");

        // --- 5. Index eligible files ----------------------------------------
        log("[Scan] Indexando arquivos elegíveis para progresso real...");
        onProgressInfo?.Invoke(new ScanProgressInfo { Phase = "Indexando arquivos elegíveis...", IsIndeterminate = true });
        var indexProgressSw = Stopwatch.StartNew();
        var profEnum = state.Profiler.Measure("Enumeration");
        var files = new List<FileInfo>();
        foreach (var target in targets)
        {
            ct.ThrowIfCancellationRequested();
            log($"[Scan] Indexando: {target}");
            foreach (var file in deps.FileSystem.EnumerateFiles(target, ct, _ => Inc(m => m.AccessDenied++)))
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    bool archiveEligible = ScanProfileRegistry.ScansArchives(options.Profile, _settings, options) && ArchiveExt.Contains(file.Extension);
                    bool documentEligible = ScanProfileRegistry.ScansDocuments(options.Profile, _settings, options) && DocumentExt.Contains(file.Extension);
                    bool browserEligible = ScanProfileRegistry.ScansBrowserExtensions(options.Profile, _settings, options)
                        && file.Name.Equals("manifest.json", StringComparison.OrdinalIgnoreCase);
                    if (!DangerExt.Contains(file.Extension) && !archiveEligible && !documentEligible && !browserEligible && !PeExt.Contains(file.Extension))
                        continue;

                    string fullLow = file.FullName.ToLowerInvariant();
                    if (TargetDiscovery.IsExcludedPath(fullLow, _settings)) { Inc(m => m.SkippedExcludedPath++); continue; }
                    if (PathTaxonomy.IsKnownVendorLocation(fullLow)) Inc(m => m.AnalyzedKnownVendorLocation++);

                    files.Add(file);
                    if (indexProgressSw.ElapsedMilliseconds >= 350)
                    {
                        indexProgressSw.Restart();
                        onProgressInfo?.Invoke(new ScanProgressInfo
                        {
                            Phase = $"Indexando arquivos elegíveis... {files.Count:N0} encontrado(s)",
                            Current = files.Count,
                            IsIndeterminate = true,
                            CurrentFile = file.FullName
                        });
                    }
                }
                catch (System.Exception) { Inc(m => m.Errors++); }
            }
        }
        profEnum.Dispose();

        metrics.TotalEstimate = Math.Max(files.Count, 1);
        onProgress?.Invoke(0, metrics.TotalEstimate);
        onProgressInfo?.Invoke(new ScanProgressInfo { Current = 0, Total = metrics.TotalEstimate });

        return Task.FromResult(files);
    }

    private async Task<ScanFinding?> AnalyzeSingleFileAsync(
        FileInfo file, CancellationToken token, ScanState state, ScanContext context,
        ScanOptions options, int minPreScore, int sigThreshold, int persThreshold, int reportThreshold,
        DetectionModuleSet modulesToRun)
    {
        var hashService = state.HashService;
        var reputation = state.Reputation;
        var reputationEngine = state.ReputationEngine;
        var pipeline = state.Pipeline;
        var prevHashes = state.PrevHashes;
        var runningPaths = context.RunningProcessPaths;
        var deep = context.Deep;
        void Inc(Action<ScanMetrics> action) => state.Inc(action);

        Inc(m => m.Eligible++);
        string ext = file.Extension.ToLowerInvariant();
        if (options.MaxFileSizeMB > 0 && file.Length > options.MaxFileSizeMB * 1_048_576L)
        {
            Inc(m => m.HashSkippedLarge++);
            return null;
        }

        RecordExtensionMetrics(state, ext, deep);

        var target = new ScanTarget(file);

        // ---- 6a. Hash + known-safe / known-malicious short-circuit
        var profHash = state.Profiler.Measure("Hashing");
        var (hash, previousReputation, knownSafeHash) = ResolveKnownState(state, options, file, target);
        profHash.Dispose();
        state.Profiler.RecordItemMetrics("Hashing", profHash.ElapsedTicks, (int)file.Length);

        // ---- 6b. Cross-reference running processes (cheap context for modules)
        string fullLow = target.FullPathLower;
        if (runningPaths.Contains(fullLow)) target.IsRunning = true;

        // Telemetry: which modules will run on this target.
        RecordModuleSupportTelemetry(state, target, context);

        // ---- 6c. Run detection pipeline
        var profPipe = state.Profiler.Measure("DetectionPipeline");
        var outcome = await pipeline.AnalyzeAsync(target, context, token, modulesToRun).ConfigureAwait(false);
        profPipe.Dispose();
        state.Profiler.RecordItemMetrics("DetectionPipeline", profPipe.ElapsedTicks, (int)file.Length);

        RecordPipelineHitTelemetry(state, outcome, target);

        bool isKnownMalware = target.IsKnownMalicious;
        bool hasConfirmedSignature = outcome.Evidence.Any(e =>
            e.CanConfirmMalware && string.Equals(e.Category, "Signature", StringComparison.OrdinalIgnoreCase));

        // ---- 6d. Persistence threshold gate
        // v3.0 contract: persistence bonus is added ONLY when the rest of
        // the score already crosses persThreshold. The PersistenceDetectionModule
        // emits its evidence unconditionally; the engine gates the score delta here
        // so the boost cannot, by itself, push a low-confidence file into HighRisk.
        int persistenceDelta = outcome.Evidence
            .Where(e => string.Equals(e.Category, "Persistence", StringComparison.OrdinalIgnoreCase))
            .Sum(e => e.ScoreDelta);
        int nonPersistenceScore = outcome.AggregatedScore - persistenceDelta;
        int preScore = outcome.AggregatedScore;
        if (nonPersistenceScore < persThreshold && persistenceDelta > 0 && !isKnownMalware && !hasConfirmedSignature)
        {
            var persistenceOnly = outcome.Evidence
                .Where(e => string.Equals(e.Category, "Persistence", StringComparison.OrdinalIgnoreCase))
                .ToList();
            foreach (var p in persistenceOnly) outcome.Evidence.Remove(p);
            preScore = nonPersistenceScore;
        }

        // ---- 6e. Below-pre-threshold skip (saves Authenticode + report I/O)
        if (!isKnownMalware && !hasConfirmedSignature && knownSafeHash)
        {
            Inc(m => m.SkippedKnownSafe++);
            hashService.TouchScore(file.FullName, 0, knownSafe: true);
            if (hash != null) reputation.ObserveFile(hash, file.FullName, file.Length / 1024, file.LastWriteTimeUtc, "KnownSafe");
            return null;
        }

        if (!isKnownMalware && !hasConfirmedSignature && preScore < minPreScore)
        {
            Inc(m => m.SkippedLowScore++);
            hashService.TouchScore(file.FullName, preScore, knownSafe: false);
            if (hash != null) reputation.ObserveFile(hash, file.FullName, file.Length / 1024, file.LastWriteTimeUtc);
            return null;
        }

        // ---- 6f. Authenticode trust gate
        var profAuth = state.Profiler.Measure("Authenticode");
        bool isSigned = false;
        string publisher = "";
        PublisherTrustLevel trustLevel = PublisherTrustLevel.Unsigned;
        bool trustedPublisher = false;
        if (isKnownMalware || hasConfirmedSignature || preScore >= sigThreshold)
        {
            Inc(m => m.SigChecked++);
            // Performance: the OS catalog only covers genuine system components, so skip the
            // expensive catalog probe (a full file re-read + catalog-store search) for non-system
            // files — they are never catalog-signed. Embedded Authenticode is still checked for
            // every file. Results are memoized across scans by (path,mtime,size)+fingerprint, so
            // unchanged files are not re-verified.
            bool allowCatalog = PathTaxonomy.ClassifySystemPath(fullLow) != SystemPathKind.None;
            // Signature data is never reused from disk. Verify the current file here.
            var sig = GetSigInfo(file.FullName, allowCatalog);
            state.TrustCache.Observe(file, sig);
            isSigned = sig.IsSigned;
            publisher = sig.IsSigned ? sig.SignerSubject : "";
            if (sig.Source == SignatureSource.Catalog) Inc(m => m.CatalogSignatureHits++);
            target.IsSigned = isSigned;
            target.Publisher = publisher;

            // BETA 11D — graduated, spoof-resistant publisher trust. Trusted publishers
            // (incl. catalog-signed Windows components) receive strong relief; valid-but-
            // untrusted gets measured relief below; confirmed malware always overrides.
            trustLevel = PublisherIdentity.EvaluatePublisherTrust(sig, _settings);
            trustedPublisher = trustLevel is PublisherTrustLevel.Trusted or PublisherTrustLevel.TrustedWindowsComponent;
            if (trustLevel == PublisherTrustLevel.TrustedWindowsComponent) Inc(m => m.TrustedWindowsComponentHits++);

        }
        profAuth.Dispose();
        state.Profiler.RecordItemMetrics("Authenticode", profAuth.ElapsedTicks, (int)file.Length);

        int score = preScore;

        // ---- BETA 11C + 11B. Trust-aware PE import recalibration and protected-location context.
        // Applied BEFORE publisher/reputation relief so reductions cannot stack into immunity for
        // severe/actionable evidence. Common-import noise is capped/demoted first; signer/system
        // context may then quiet remaining non-actionable noise, but RWX/packer/embedded payload,
        // entry-point and strong PE correlation keep their score.
        var systemKind = PathTaxonomy.ClassifySystemPath(fullLow);
        if (!isKnownMalware && !hasConfirmedSignature)
        {
            int peReduction = DataVanger.Detection.PE.PeImportRecalibration.Apply(outcome.Evidence, trustLevel, systemKind);
            if (peReduction > 0)
            {
                score = Math.Max(0, score - peReduction);
                Inc(m => m.PeImportsAttenuated++);
            }
        }

        // FASE 6: For trusted publishers, suppress weak heuristics before evaluating actionable evidence
        if (!isKnownMalware && !hasConfirmedSignature && isSigned && trustedPublisher)
        {
            SuppressWeakHeuristicsForTrustedPublisher(outcome.Evidence);
        }

        bool hasActionableEvidence = HasActionableEvidenceAfterTrustRecalibration(outcome.Evidence);
        if (!isKnownMalware && !hasConfirmedSignature && isSigned)
        {
            score = ApplySignedPublisherRelief(score, trustedPublisher, hasActionableEvidence);
            if (!string.IsNullOrWhiteSpace(publisher))
                outcome.Evidence.Add(new Evidence
                {
                    Category = "Signature",
                    Description = $"Assinado por: {publisher} [{trustLevel}]",
                    Strength = EvidenceStrength.Info,
                    ScoreDelta = 0
                });

            if (trustedPublisher && !hasActionableEvidence && score == 0)
            {
                hashService.TouchScore(file.FullName, 0, knownSafe: true);
                if (hash != null) reputation.ObserveFile(hash, file.FullName, file.Length / 1024, file.LastWriteTimeUtc, "TrustedSigner", publisher);
                return null;
            }
        }

        if (!isKnownMalware && !hasConfirmedSignature)
        {
            if (score > 0)
            {
                int relief = PathTaxonomy.SystemPathRelief(systemKind);
                if (relief > 0)
                {
                    int reduced = Math.Max(0, score - relief);
                    if (reduced < score)
                    {
                        outcome.Evidence.Add(new Evidence
                        {
                            Category = "SystemPath",
                            Description = $"Localização protegida do Windows ({systemKind}): contexto de sistema reduz ruído heurístico",
                            Strength = EvidenceStrength.Info,
                            ScoreDelta = reduced - score,
                        });
                        score = reduced;
                        Inc(m => m.SystemPathContextApplied++);
                    }
                }
            }
        }

        // ---- 6g. Reputation scoring and anti-FP clamp.
        var profReputation = state.Profiler.Measure("ReputationEval");
        var reputationEvaluation = reputationEngine.Evaluate(new ReputationSubject
        {
            Sha256 = hash,
            Path = file.FullName,
            Extension = ext,
            SizeKB = file.Length / 1024,
            LastWriteUtc = file.LastWriteTimeUtc,
            BaseScore = score,
            IsSigned = isSigned,
            Publisher = publisher,
            PublisherTrusted = trustedPublisher,
            HasConfirmedEvidence = isKnownMalware || hasConfirmedSignature || outcome.AnyConfirmedEvidence,
            IsKnownMalicious = isKnownMalware,
            IsKnownSafe = knownSafeHash,
            IsUserAllowlisted = hash != null && _signatures.UserWhitelist.Contains(hash),
            IsUserBlocklisted = hash != null && _signatures.UserBlacklist.Contains(hash),
            Evidence = outcome.Evidence,
        }, previousReputation);
        profReputation.Dispose();
        state.Profiler.RecordItemMetrics("ReputationEval", profReputation.ElapsedTicks, (int)file.Length);

        foreach (var ev in reputationEvaluation.Evidence)
        {
            if (ev.CanConfirmMalware && isKnownMalware && outcome.Evidence.Any(e => e.CanConfirmMalware)) continue;
            outcome.Evidence.Add(ev);
        }
        score = reputationEvaluation.AdjustedScore;

        // Anti-FP clamp: heuristics never reach Critical.
        if (!isKnownMalware && !hasConfirmedSignature && score >= RiskThresholds.Critical)
            score = RiskThresholds.High;

        if (target.IsRunning) Inc(m => m.RunningProcessHits++);

        if (!isKnownMalware && !hasConfirmedSignature && score < reportThreshold)
        {
            hashService.TouchScore(file.FullName, score, knownSafe: false);
            if (hash != null) reputation.ObserveFile(hash, file.FullName, file.Length / 1024, file.LastWriteTimeUtc, reputationEvaluation.SignerStatus, publisher);
            return null;
        }

        // ---- BETA 11E. Trusted/system tier-gate context (evaluated by ThreatClassificationPolicy).
        // A trusted-publisher or genuine-system file needs an actionable corroborating signal to be
        // ALTO RISCO; otherwise the tier is gated to SUSPEITO. This changes no score, threshold, or
        // clamp, and never applies to unsigned/user-writable/suspicious-path files.
        bool trustedOrSystemContext = trustedPublisher || systemKind != SystemPathKind.None;
        if (trustedOrSystemContext && !hasActionableEvidence && score >= RiskThresholds.High)
            outcome.Evidence.Add(new Evidence
            {
                Category = "TierGate",
                Description = "Tier limitado a SUSPEITO: arquivo confiável/sistema sem sinal acionável corroborante (imports comuns/metadados técnicos não bastam para ALTO RISCO)",
                Strength = EvidenceStrength.Info,
                ScoreDelta = 0,
            });

        // ---- 6h. Build finding
        bool isNew = hash != null && !prevHashes.Contains(hash);
        if (isNew) Inc(m => m.NewFindings++);

        string yaraNames = ComputeYaraNames(outcome);
        var reasons = BuildReasons(outcome);

        var finding = new ScanFinding
        {
            Path = file.FullName,
            Extension = ext,
            SizeKB = file.Length / 1024,
            SHA256 = hash,
            IsSigned = isSigned,
            Publisher = publisher,
            Score = score,
            Reasons = reasons.Count == 0 ? "Sem motivo específico" : string.Join("; ", reasons),
            LastWrite = file.LastWriteTime,
            IsNew = isNew,
            IsBlacklisted = isKnownMalware,
            HasConfirmedSignature = hasConfirmedSignature,
            SignatureName = yaraNames,
            TrustedOrSystemContext = trustedOrSystemContext,
            HasActionableCorroboration = hasActionableEvidence,
            Evidence = outcome.Evidence.ToList(),
            ReputationState = reputationEvaluation.TrustState,
            ReputationScore = reputationEvaluation.Score,
            ReputationScoreDelta = reputationEvaluation.ScoreDelta,
            ReputationSeenCount = reputationEvaluation.SeenCount,
            ReputationFirstSeenUtc = reputationEvaluation.FirstSeenUtc,
            ReputationLastSeenUtc = reputationEvaluation.LastSeenUtc,
            ReputationSignerStatus = reputationEvaluation.SignerStatus,
            ReputationUserDecision = reputationEvaluation.UserDecision.ToString(),
            ReputationReasons = reputationEvaluation.Reasons.ToList(),
        };

        return finding;
    }

    // ── Phase 21: behaviour-identical move-only helpers extracted from
    // AnalyzeSingleFileAsync. Each is a verbatim move of a contiguous block —
    // telemetry side effects, known-state resolution, or output projection. The
    // anti-FP decision spine (persistence gate, below-threshold skips, Authenticode
    // trust gate, reputation + clamp, report gate) deliberately stays inline in
    // AnalyzeSingleFileAsync; no conditions, order, scoring, or evidence changed.

    private static void RecordExtensionMetrics(ScanState state, string ext, bool deep)
    {
        if (EntropyExt.Contains(ext)) state.Inc(m => m.EntropyChecked++);
        if (ExeExt.Contains(ext)) { state.Inc(m => m.FakeIconChecked++); state.Inc(m => m.AppendChecked++); }
        if (deep) state.Inc(m => m.AdsChecked++);
        if (ScriptExt.Contains(ext)) state.Inc(m => m.ScriptInspected++);
    }

    private (string? Hash, LocalReputationEntry? PreviousReputation, bool KnownSafeHash) ResolveKnownState(
        ScanState state, ScanOptions options, FileInfo file, ScanTarget target)
    {
        string? hash = null;
        LocalReputationEntry? previousReputation = null;
        bool knownSafeHash = false;
        bool cacheHit = false;
        if (!(options.MaxHashSizeMB > 0 && file.Length > options.MaxHashSizeMB * 1_048_576L))
        {
            hash = state.HashService.ComputeSha256(file, out cacheHit);
            if (hash != null)
            {
                target.Sha256 = hash;
                previousReputation = state.Reputation.Get(hash);
                state.Inc(m => m.HashComputed++);

                if (_signatures.IsKnownMalicious(hash))
                {
                    target.IsKnownMalicious = true;
                    target.TrustState = FileTrustState.KnownMalicious;
                }
                else if (_signatures.IsKnownSafe(hash))
                {
                    knownSafeHash = true;
                    target.TrustState = FileTrustState.KnownSafe;
                }
            }
        }
        else
        {
            state.Inc(m => m.HashSkippedLarge++);
        }
        return (hash, previousReputation, knownSafeHash);
    }

    private static void RecordModuleSupportTelemetry(ScanState state, ScanTarget target, ScanContext context)
    {
        var deps = state.Deps;
        bool archiveSupported = deps.Modules.Find("Archive")?.Supports(target, context) == true;
        bool documentSupported = deps.Modules.Find("Document")?.Supports(target, context) == true;
        bool browserSupported = deps.Modules.Find("BrowserExtension")?.Supports(target, context) == true;
        bool yaraSupported = deps.Modules.Find("Yara")?.Supports(target, context) == true;
        if (archiveSupported) state.Inc(m => m.ArchiveChecked++);
        if (documentSupported) state.Inc(m => m.DocumentChecked++);
        if (browserSupported) state.Inc(m => m.BrowserExtensionChecked++);
        if (yaraSupported) state.Inc(m => m.YaraScanned++);
    }

    private static void RecordPipelineHitTelemetry(ScanState state, PipelineOutcome outcome, ScanTarget target)
    {
        if (outcome.Modules.Any(r => string.Equals(r.ModuleName, "Yara", StringComparison.OrdinalIgnoreCase))) state.Inc(m => m.YaraHits++);
        if (outcome.Modules.Any(r => string.Equals(r.ModuleName, "Archive", StringComparison.OrdinalIgnoreCase))) state.Inc(m => m.ArchiveHits++);
        if (outcome.Modules.Any(r => string.Equals(r.ModuleName, "Document", StringComparison.OrdinalIgnoreCase))) state.Inc(m => m.DocumentHits++);
        if (outcome.Modules.Any(r => string.Equals(r.ModuleName, "BrowserExtension", StringComparison.OrdinalIgnoreCase))) state.Inc(m => m.BrowserExtensionHits++);
        if (target.IsKnownMalicious) state.Inc(m => m.KnownMalwareHits++);
    }

    private static string ComputeYaraNames(PipelineOutcome outcome) =>
        string.Join(", ",
            outcome.Modules
                .Where(r => string.Equals(r.ModuleName, "Yara", StringComparison.OrdinalIgnoreCase))
                .SelectMany(r => r.Evidence)
                .Select(e => ExtractYaraName(e.Description))
                .Where(n => !string.IsNullOrEmpty(n))
                .Distinct());

    private static List<string> BuildReasons(PipelineOutcome outcome) =>
        outcome.Evidence
            .Select(e => e.Description)
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private async Task<ConcurrentBag<ScanFinding>> RunDetectionPhaseAsync(
        ScanOptions options, ScanState state, ScanContext context, List<FileInfo> files,
        Stopwatch swTotal, Action<string> log, Action<int, int>? onProgress,
        Action<ScanProgressInfo>? onProgressInfo, CancellationToken ct)
    {
        var findingsBag = new ConcurrentBag<ScanFinding>();
        var deps = state.Deps;
        var hashService = state.HashService;
        var reputation = state.Reputation;
        var logger = state.Logger;
        var metrics = state.Metrics;
        void Inc(Action<ScanMetrics> action) => state.Inc(action);
        int minPreScore = ScanProfileRegistry.MinPreScore(options.Profile);
        int sigThreshold = ScanProfileRegistry.SignatureCheckThreshold(options.Profile);
        int persThreshold = ScanProfileRegistry.PersistenceThreshold(options.Profile);
        int reportThreshold = Math.Max(0, _settings.MinScoreToReport);
        var modulesToRun = ScanProfileRegistry.ModulesToRun(options.Profile);

        // --- 6. Run pipeline in parallel ------------------------------------
        var swScan = Stopwatch.StartNew();
        int processed = 0;
        // Profile-aware default: per-file work is I/O-bound, so the lightweight Quick profile
        // gets the most workers (see ScanProfileRegistry.RecommendedDegreeOfParallelism). A
        // caller-supplied positive value still wins. This covers CLI/scheduled scans that leave
        // MaxDegreeOfParallelism unset, matching what the GUI now requests.
        int maxDop = options.MaxDegreeOfParallelism > 0
            ? options.MaxDegreeOfParallelism
            : ScanProfileRegistry.RecommendedDegreeOfParallelism(options.Profile, Environment.ProcessorCount);

        log($"[Scan] Engine paralela ativa: {maxDop} thread(s), {files.Count} arquivo(s) elegíveis.");

        await Parallel.ForEachAsync(files, new ParallelOptions
        {
            CancellationToken = ct,
            MaxDegreeOfParallelism = maxDop
        }, async (file, token) =>
        {
            token.ThrowIfCancellationRequested();
            try
            {
                var finding = await AnalyzeSingleFileAsync(file, token, state, context, options, minPreScore, sigThreshold, persThreshold, reportThreshold, modulesToRun).ConfigureAwait(false);
                if (finding == null) return;

                if (options.AutoQuarantine
                    && _settings.AutoQuarantineKnownMalware
                    && deps.Classifier.AllowsAutomaticAction(finding)
                    && finding.Score >= Math.Max(RiskThresholds.High, _settings.MinScoreToQuarantine))
                {
                    var request = QuarantineRequestFactory.Create(
                        finding, QuarantineRequestOrigin.Automatic, "ScanEngine");
                    var quarantine = await Quarantine.Service
                        .QuarantineAsync(request, token)
                        .ConfigureAwait(false);
                    if (quarantine.Status == QuarantineStatus.Success &&
                        quarantine.Record?.RecordState == QuarantineRecordState.Verified)
                    {
                        finding.WasQuarantined = true;
                        Inc(m => m.AutoQuarantined++);
                    }
                }

                findingsBag.Add(finding);
                reputation.Observe(finding);
                Inc(m => m.Findings++);
                hashService.TouchScore(file.FullName, finding.Score, knownSafe: false);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                Inc(m => m.Errors++);
                logger.Error($"Falha analisando {file.FullName}", ex);
            }
            finally
            {
                ReportProgress(file.FullName);
                if (options.CpuThrottleDelayMs > 0)
                    await Task.Delay(options.CpuThrottleDelayMs, token).ConfigureAwait(false);
            }
        }).ConfigureAwait(false);

        void ReportProgress(string currentFile)
        {
            int cur = Interlocked.Increment(ref processed);
            int total = Math.Max(metrics.TotalEstimate, cur);
            if (cur % 5 != 0 && cur != total) return;
            double fps = swScan.Elapsed.TotalSeconds <= 0 ? 0 : cur / swScan.Elapsed.TotalSeconds;
            var eta = fps <= 0 ? TimeSpan.Zero : TimeSpan.FromSeconds(Math.Max(0, total - cur) / fps);
            onProgress?.Invoke(cur, total);
            onProgressInfo?.Invoke(new ScanProgressInfo
            {
                Current = cur,
                Total = total,
                FilesPerSecond = fps,
                Eta = eta,
                CurrentFile = currentFile
            });
        }

        swScan.Stop();
        swTotal.Stop();

        onProgress?.Invoke(Math.Max(metrics.TotalEstimate, metrics.Eligible), Math.Max(metrics.TotalEstimate, metrics.Eligible));
        onProgressInfo?.Invoke(new ScanProgressInfo
        {
            Current = Math.Max(metrics.TotalEstimate, metrics.Eligible),
            Total = Math.Max(metrics.TotalEstimate, metrics.Eligible),
            FilesPerSecond = metrics.FilesPerSecond,
            Eta = TimeSpan.Zero
        });
        metrics.ScanTime = swScan.Elapsed;
        return findingsBag;
    }

    private Task<(List<ScanFinding>, ScanMetrics)> CommitResultsAsync(
        ScanOptions options, ScanState state, ConcurrentBag<ScanFinding> findingsBag,
        Stopwatch swTotal, Action<string> log)
    {
        var metrics = state.Metrics;
        var hashService = state.HashService;
        var reputation = state.Reputation;

        var findings = findingsBag.OrderByDescending(f => f.Score).ThenByDescending(f => f.LastWrite).ToList();
        metrics.TotalTime = swTotal.Elapsed;
        foreach (var s in state.Profiler.Snapshot())
            metrics.StageSeconds[s.Stage] = Math.Round(s.Elapsed.TotalSeconds, 3);
        bool hashCacheWasDegraded = hashService.Health.IsDegraded;
        bool trustCacheWasDegraded = state.TrustCache.Health.IsDegraded;
        hashService.Persist();
        state.TrustCache.Persist();
        if (!hashCacheWasDegraded && hashService.Health.IsDegraded) state.Inc(m => m.CacheDegradationEvents++);
        if (!trustCacheWasDegraded && state.TrustCache.Health.IsDegraded) state.Inc(m => m.CacheDegradationEvents++);
        reputation.Save();
        WriteCsv(findings);
        WriteTxt(findings, metrics, options);
        ReportGenerator.WriteHtml(LogHtmlPath, findings, metrics, options, DateTime.Now);
        ReportGenerator.WriteJson(LogJsonPath, findings, metrics, options, DateTime.Now);

        // Phase 11 — detailed telemetry export (opt-in via AppSettings)
        if (state.Settings.EnableDetailedTelemetry)
        {
            metrics.Profile = options.Profile.ToString();

            // Populate per-stage breakdown with percentiles
            foreach (var st in state.Profiler.Snapshot())
            {
                var snapshot = state.Profiler.GetPerItemSnapshot(st.Stage);
                if (snapshot.HasValue)
                {
                    metrics.StageBreakdown[st.Stage] = new StageTelemetryBreakdown
                    {
                        Total = snapshot.Value.Total,
                        Count = snapshot.Value.Count,
                        P50 = snapshot.Value.P50,
                        P95 = snapshot.Value.P95,
                        Max = snapshot.Value.Max,
                        AvgFileSize = snapshot.Value.AvgFileSize,
                    };
                }
            }

            // Write structured telemetry JSON
            string telemetryPath = Path.Combine(MgRoot, "DataVanger_Telemetry.json");
            TelemetryReportGenerator.WriteTelemetryJson(
                telemetryPath,
                metrics,
                state.Profiler.Snapshot(),
                metrics.StageBreakdown,
                DateTime.Now);
            state.Logger.Info($"Telemetria escrita: {telemetryPath}");
        }

        log($"[Scan] Concluído — {findings.Count} achados, {metrics.Errors} erros, {metrics.AccessDenied} acesso(s) negado(s). Tempo: {swTotal.Elapsed.TotalSeconds:F1}s");
        return Task.FromResult<(List<ScanFinding>, ScanMetrics)>((findings, metrics));
    }

    // ----- Helpers -----------------------------------------------------------

    internal static int ApplySignedPublisherRelief(int score, bool trustedPublisher, bool hasActionableEvidence)
    {
        if (score <= 0) return 0;
        if (trustedPublisher)
            return hasActionableEvidence ? score : 0;
        return Math.Max(0, score - 6);
    }

    internal static bool HasActionableEvidenceAfterTrustRecalibration(IReadOnlyList<Evidence> evidence) =>
        evidence.Any(e =>
            e.ScoreDelta > 0
            && (e.CanConfirmMalware
                || e.Strength == EvidenceStrength.Confirmed
                || DataVanger.Detection.PE.PeImportRecalibration.IsSevereStructuralEvidence(e)));

    /// <summary>
    /// FASE 6: Suppress weak heuristics (entropy, dynamic imports, anti-debug patterns) on trusted signed files.
    /// Strong evidence (confirmed malware, structural anomalies, persistence) is retained.
    /// This reduces false positives for legitimate signed software while preserving security.
    /// </summary>
    internal static void SuppressWeakHeuristicsForTrustedPublisher(List<Evidence> evidence)
    {
        if (evidence == null || evidence.Count == 0) return;

        var toRemove = evidence
            .Where(e =>
                e.Category.Contains("Entropy", StringComparison.OrdinalIgnoreCase) ||
                e.Category.Contains("DynamicImport", StringComparison.OrdinalIgnoreCase) ||
                e.Category.Contains("AntiDebug", StringComparison.OrdinalIgnoreCase) ||
                e.Category.Contains("AntiVM", StringComparison.OrdinalIgnoreCase) ||
                (e.Category.Contains("Import", StringComparison.OrdinalIgnoreCase) && !e.CanConfirmMalware))
            .ToList();

        foreach (var weak in toRemove) evidence.Remove(weak);
    }

    private static HashSet<string> GetRunningProcessPaths()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in Process.GetProcesses())
        {
            try { if (p.MainModule?.FileName is string fn) set.Add(fn.ToLowerInvariant()); }
            catch (Exception)
            {
                // MainModule throws Win32Exception/InvalidOperationException/NotSupportedException for
                // protected or exited processes - skip this process and continue enumeration.
            }
            finally { p.Dispose(); }
        }
        return set;
    }

    // BETA 11A/11D — catalog-aware signature verification. Embedded Authenticode is
    // tried first; catalog-signed OS components (System32/WinSxS) report as signed with
    // their catalog signer subject. The full result (incl. source and present-but-invalid
    // state) feeds the graduated publisher-trust model. Trust is never fabricated on failure.
    private static SignatureVerificationResult GetSigInfo(string path, bool allowCatalog)
    {
        try { return WinTrust.VerifySignature(path, allowCatalog); }
        catch (System.Exception) { return SignatureVerificationResult.Unsigned; }
    }

    private static string ExtractYaraName(string description)
    {
        // YaraDetectionModule formats as "Regra YARA leve: NAME (...)" — pull NAME out.
        const string prefix = "Regra YARA leve: ";
        int idx = description.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return "";
        int start = idx + prefix.Length;
        int paren = description.IndexOf(" (", start, StringComparison.Ordinal);
        return paren < 0 ? description[start..] : description[start..paren];
    }

    private HashSet<string> LoadPreviousHashes()
    {
        var prevHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!File.Exists(LogCsvPath)) return prevHashes;
        try { File.Copy(LogCsvPath, LogCsvPrevPath, overwrite: true); }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Could not snapshot previous CSV log - make observable; new/seen detection degrades gracefully.
            System.Diagnostics.Debug.WriteLine($"[DataVanger] Failed to copy previous CSV log '{LogCsvPath}': {ex.Message}");
        }
        try
        {
            bool headerParsed = false;
            int sha256Index = -1;
            foreach (var line in ReadCsvRecords(LogCsvPrevPath))
            {
                if (!headerParsed)
                {
                    // Build a column-name -> index map from the header so SHA256 is
                    // located by name (RFC 4180-aware) instead of a fragile fixed index.
                    var header = ParseCsvLine(line);
                    var columnMap = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                    for (int i = 0; i < header.Count; i++) columnMap[header[i]] = i;
                    if (!columnMap.TryGetValue("SHA256", out sha256Index)) return prevHashes;
                    headerParsed = true;
                    continue;
                }

                var cols = ParseCsvLine(line);
                if (sha256Index < cols.Count)
                {
                    var h = cols[sha256Index].Trim('"').Trim().ToUpperInvariant();
                    if (h.Length == 64) prevHashes.Add(h);
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            // Previous-log unreadable - return hashes collected so far.
        }
        catch (IOException)
        {
            // Previous-log locked/unreadable - return hashes collected so far.
        }
        return prevHashes;
    }

    private void WriteCsv(List<ScanFinding> findings)
    {
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("FileName,Risk,Type,SHA256,Signature,Path,RecommendedAction,Ext,SizeKB,Signed,Publisher,Score,Reasons,LastWrite,IsNew,IsBlacklisted,HasConfirmedSignature,WasQuarantined,ReputationState,ReputationScore,ReputationDelta,ReputationSeenCount,ReputationSignerStatus,ReputationUserDecision,ReputationReasons");
            foreach (var f in findings)
            {
                // Phase 07 — CSV export hardening: route attacker-influenceable string
                // fields through CsvSafe (formula-injection + RFC 4180 quoting). The
                // SHA256 column (hex, never formula-leading) is unaffected, so the
                // LoadPreviousHashes round-trip that keys off SHA256 is preserved.
                sb.AppendLine(string.Join(",", new[]
                {
                    CsvSafe.Field(f.FileName),
                    CsvSafe.Field(f.RiskLabel),
                    CsvSafe.Field(f.Extension),
                    CsvSafe.Field(f.SHA256 ?? ""),
                    CsvSafe.Field(f.SignatureName),
                    CsvSafe.Field(f.Path),
                    CsvSafe.Field(f.RecommendedAction),
                    CsvSafe.Field(f.Extension),
                    f.SizeKB.ToString(),
                    f.IsSigned.ToString(),
                    CsvSafe.Field(f.Publisher),
                    f.Score.ToString(),
                    CsvSafe.Field(f.Reasons),
                    f.LastWrite.ToString("o"),
                    f.IsNew.ToString(),
                    f.IsBlacklisted.ToString(),
                    f.HasConfirmedSignature.ToString(),
                    f.WasQuarantined.ToString(),
                    CsvSafe.Field(f.ReputationState.ToString()),
                    f.ReputationScore.ToString(),
                    f.ReputationScoreDelta.ToString(),
                    f.ReputationSeenCount.ToString(),
                    CsvSafe.Field(f.ReputationSignerStatus),
                    CsvSafe.Field(f.ReputationUserDecision),
                    CsvSafe.Field(string.Join("; ", f.ReputationReasons)),
                }));
            }
            File.WriteAllText(LogCsvPath, sb.ToString(), Encoding.UTF8);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // CSV report failed to persist - make observable without aborting the scan.
            System.Diagnostics.Debug.WriteLine($"[DataVanger] Failed to write CSV log '{LogCsvPath}': {ex.Message}");
        }
    }

    private static string EscCsv(string? value) => (value ?? "").Replace("\"", "\"\"");

    // RFC 4180-ish record reader. File.ReadLines is not enough because valid CSV
    // fields may contain embedded CR/LF once quoted by CsvSafe; accumulate physical
    // lines until quoted fields are balanced so previous-hash loading keeps working.
    private static IEnumerable<string> ReadCsvRecords(string path)
    {
        var sb = new StringBuilder();
        foreach (var physicalLine in File.ReadLines(path))
        {
            if (sb.Length > 0) sb.Append('\n');
            sb.Append(physicalLine);

            if (!IsCsvRecordComplete(sb.ToString())) continue;
            yield return sb.ToString();
            sb.Clear();
        }

        if (sb.Length > 0)
            yield return sb.ToString();
    }

    private static bool IsCsvRecordComplete(string record)
    {
        bool inQuotes = false;
        for (int i = 0; i < record.Length; i++)
        {
            if (record[i] != '"') continue;
            if (inQuotes && i + 1 < record.Length && record[i + 1] == '"')
            {
                i++;
                continue;
            }
            inQuotes = !inQuotes;
        }
        return !inQuotes;
    }

    // RFC 4180 CSV parser. Splits on commas only outside quoted fields,
    // unescapes doubled double-quotes ("" -> ") inside quoted fields, and strips
    // the surrounding quotes from returned values.
    private static List<string> ParseCsvLine(string line)
    {
        var fields = new List<string>();
        var sb = new System.Text.StringBuilder();
        bool inQuotes = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (inQuotes)
            {
                if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; } // escaped double-quote
                    else inQuotes = false; // closing quote
                }
                else sb.Append(c);
            }
            else
            {
                if (c == '"') inQuotes = true;
                else if (c == ',') { fields.Add(sb.ToString()); sb.Clear(); }
                else sb.Append(c);
            }
        }
        fields.Add(sb.ToString());
        return fields;
    }

    private void WriteTxt(List<ScanFinding> findings, ScanMetrics m, ScanOptions opts)
    {
        try
        {
            int crit = findings.Count(f => f.IsConfirmedMalware);
            int high = findings.Count(f => !f.IsConfirmedMalware && f.Score >= RiskThresholds.High);
            int susp = findings.Count(f => !f.IsConfirmedMalware && f.Score >= RiskThresholds.Suspect && f.Score < RiskThresholds.High);
            int low = Math.Max(0, m.Eligible - findings.Count);

            var topReasons = findings
                .SelectMany(f => f.Reasons.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                .GroupBy(x => x, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(g => g.Count())
                .Take(8)
                .Select(g => $"- {g.Key}: {g.Count()}")
                .ToList();

            var sb = new StringBuilder();
            sb.AppendLine($"{VersionInfo.DisplayName} ({opts.Profile}) - {DateTime.Now:dd/MM/yyyy HH:mm:ss}");
            sb.AppendLine($"Achados: {findings.Count} | Malware confirmado: {crit} | Alto risco heurístico: {high} | Suspeitos: {susp} | Limpos/baixa confiança: {low} | Novos: {m.NewFindings} | Erros: {m.Errors}");
            sb.AppendLine();
            sb.AppendLine("----- Resumo profissional -----");
            sb.AppendLine($"Total de arquivos analisados       : {m.Eligible}");
            sb.AppendLine($"Total ignorado por acesso negado   : {m.AccessDenied}");
            sb.AppendLine($"Tempo de scan                      : {m.ScanTime.TotalSeconds:F2}s");
            sb.AppendLine($"Velocidade média                   : {m.FilesPerSecond:F2} arquivos/segundo");
            sb.AppendLine($"Hashes de assinatura carregados    : {m.SignatureHashesLoaded}");
            sb.AppendLine($"Regras YARA carregadas             : {m.YaraRulesLoaded}");
            sb.AppendLine($"Arquivos checados por YARA         : {m.YaraScanned}");
            sb.AppendLine($"Hits de YARA                       : {m.YaraHits}");
            sb.AppendLine($"Arquivos compactados checados      : {m.ArchiveChecked}");
            sb.AppendLine($"Hits em compactados                : {m.ArchiveHits}");
            sb.AppendLine($"Documentos Office/PDF checados     : {m.DocumentChecked}");
            sb.AppendLine($"Hits em documentos                 : {m.DocumentHits}");
            sb.AppendLine($"Manifestos de extensões checados   : {m.BrowserExtensionChecked}");
            sb.AppendLine($"Hits em extensões                  : {m.BrowserExtensionHits}");
            sb.AppendLine($"Hits de malware conhecido          : {m.KnownMalwareHits}");
            sb.AppendLine($"Autoquarentenados                  : {m.AutoQuarantined}");
            sb.AppendLine();
            sb.AppendLine("----- Top motivos de detecção -----");
            if (topReasons.Count == 0) sb.AppendLine("- Nenhum motivo registrado.");
            else foreach (var line in topReasons) sb.AppendLine(line);
            sb.AppendLine();
            sb.AppendLine("----- Telemetria v3.1 -----");
            sb.AppendLine($"Targets                : {m.Targets}");
            sb.AppendLine($"Eligible               : {m.Eligible}");
            sb.AppendLine($"TotalEstimate          : {m.TotalEstimate}");
            sb.AppendLine($"AccessDenied           : {m.AccessDenied}");
            sb.AppendLine($"SkippedExcludedPath    : {m.SkippedExcludedPath}");
            sb.AppendLine($"KnownVendorLocationAnalyzed: {m.AnalyzedKnownVendorLocation}");
            sb.AppendLine($"SkippedKnownSafe       : {m.SkippedKnownSafe}");
            sb.AppendLine($"SkippedLowScore        : {m.SkippedLowScore}");
            sb.AppendLine($"HashComputed           : {m.HashComputed}");
            sb.AppendLine($"HashSkippedLarge       : {m.HashSkippedLarge}");
            sb.AppendLine($"YaraRulesLoaded        : {m.YaraRulesLoaded}");
            sb.AppendLine($"YaraScanned            : {m.YaraScanned}");
            sb.AppendLine($"YaraHits               : {m.YaraHits}");
            sb.AppendLine($"ArchiveChecked         : {m.ArchiveChecked}");
            sb.AppendLine($"ArchiveHits            : {m.ArchiveHits}");
            sb.AppendLine($"DocumentChecked        : {m.DocumentChecked}");
            sb.AppendLine($"DocumentHits           : {m.DocumentHits}");
            sb.AppendLine($"BrowserExtensionChecked: {m.BrowserExtensionChecked}");
            sb.AppendLine($"BrowserExtensionHits   : {m.BrowserExtensionHits}");
            sb.AppendLine($"SigChecked             : {m.SigChecked}");
            sb.AppendLine($"CatalogSignatureHits   : {m.CatalogSignatureHits}");
            sb.AppendLine($"CacheDegradationEvents : {m.CacheDegradationEvents}");
            sb.AppendLine($"TrustedWindowsComponent: {m.TrustedWindowsComponentHits}");
            sb.AppendLine($"SystemPathContextApplied: {m.SystemPathContextApplied}");
            sb.AppendLine($"PeImportsAttenuated    : {m.PeImportsAttenuated}");
            sb.AppendLine($"EntropyChecked         : {m.EntropyChecked}");
            sb.AppendLine($"FakeIconChecked        : {m.FakeIconChecked}");
            sb.AppendLine($"AppendChecked          : {m.AppendChecked}");
            sb.AppendLine($"AdsChecked             : {m.AdsChecked}");
            sb.AppendLine($"ScriptInspected        : {m.ScriptInspected}");
            sb.AppendLine($"Findings               : {m.Findings}");
            sb.AppendLine($"NewFindings            : {m.NewFindings}");
            sb.AppendLine($"RunningProcessHits     : {m.RunningProcessHits}");
            sb.AppendLine($"RunningProcesses       : {m.RunningProcesses}");
            sb.AppendLine($"PersistenceItems       : {m.PersistenceItems}");
            sb.AppendLine($"Errors                 : {m.Errors}");
            sb.AppendLine($"Tempo scan             : {m.ScanTime.TotalSeconds:F2}s");
            sb.AppendLine($"Tempo total            : {m.TotalTime.TotalSeconds:F2}s");
            sb.AppendLine();
            sb.AppendLine("----- Profiling por estágio (Beta 10) -----");
            if (m.StageSeconds.Count == 0)
            {
                sb.AppendLine("- Sem dados de profiling.");
            }
            else
            {
                foreach (var kv in m.StageSeconds.OrderByDescending(k => k.Value))
                    sb.AppendLine($"{kv.Key,-22}: {kv.Value:F2}s");
            }
            File.WriteAllText(LogTxtPath, sb.ToString(), Encoding.UTF8);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // TXT report failed to persist - make observable without aborting the scan.
            System.Diagnostics.Debug.WriteLine($"[DataVanger] Failed to write TXT log '{LogTxtPath}': {ex.Message}");
        }
    }
}
