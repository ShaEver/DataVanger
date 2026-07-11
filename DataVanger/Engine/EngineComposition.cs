using System.Collections.Generic;
using DataVanger.Classification;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Detection;
using DataVanger.Infrastructure;

namespace DataVanger.Engine;

/// <summary>
/// Lightweight composition root for the engine.
///
/// Keeps the wiring of services and modules in one place so it can be:
///   - audited (one file shows the full module list and order),
///   - swapped in tests (callers can pass a custom registry),
///   - extended by future PRs (add modules here; nothing else changes).
///
/// We deliberately avoid taking a dependency on a full DI container; the
/// project ships as a desktop binary and the runtime cost of resolving a
/// few singletons by hand is negligible.
/// </summary>
public static class EngineComposition
{
    public sealed class EngineDependencies
    {
        public required IHashService Hash { get; init; }
        public required ISignatureService Signatures { get; init; }
        public required IYaraEngine Yara { get; init; }
        public required IThreatClassifier Classifier { get; init; }
        public required DetectionModuleRegistry Modules { get; init; }
        public required IScanLogger Logger { get; init; }
        public required IFileSystemService FileSystem { get; init; }
    }

    public static EngineDependencies BuildDefault(
        IHashService hash,
        SignatureDatabase signatureDb,
        LightweightYaraDatabase yaraDb,
        AppSettings settings,
        IScanLogger logger,
        string? yaraRulesDirectory = null)
    {
        var signatures = new SignatureService(signatureDb);

        // YARA engine selection. The LightweightYaraDatabase adapter is the
        // guaranteed fallback and is ALWAYS valid. When real YARA is enabled and a
        // rules directory is supplied, attempt the optional LibyaraEngine; it only
        // activates when compiled with YARA_REAL + a verified dnYara package,
        // otherwise TryCreate returns null and we keep the lightweight fallback.
        var fallbackYara = new YaraEngineAdapter(yaraDb);
        IYaraEngine yara = fallbackYara;
        if (settings.EnableYaraRules && !string.IsNullOrWhiteSpace(yaraRulesDirectory))
        {
            var real = LibyaraEngine.TryCreate(yaraRulesDirectory!, logger.Warn);
            if (real is { RuleCount: > 0 })
                yara = real;
            else
                real?.Dispose();
        }

        var classifier = new ThreatClassifier();

        // Module order — see DetectionModuleRegistry docs.
        var modules = new List<IDetectionModule>
        {
            new HashDetectionModule(signatures),
            new HeuristicDetectionModule(),
            new ScriptDetectionModule(),
            new PeDetectionModule(),
            new ArchiveDetectionModule(),
            new DocumentDetectionModule(),
            new BrowserExtensionDetectionModule(),
            new YaraDetectionModule(yara, new YaraDetectionModule.YaraOptions(settings.EnableYaraRules, settings.YaraMaxScanSizeMB)),
            new PersistenceDetectionModule(),
        };

        return new EngineDependencies
        {
            Hash = hash,
            Signatures = signatures,
            Yara = yara,
            Classifier = classifier,
            Modules = new DetectionModuleRegistry(modules),
            Logger = logger,
            FileSystem = new ResilientFileSystemService(),
        };
    }
}
