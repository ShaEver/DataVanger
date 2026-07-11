using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Core.Domain;

namespace DataVanger.Detection;

/// <summary>
/// Runs the configured YARA engine over the file's content. Each match
/// becomes one piece of evidence; rules explicitly marked
/// <c>confirmed = true</c> raise <see cref="Evidence.CanConfirmMalware"/>.
/// </summary>
public sealed class YaraDetectionModule : DetectionModuleBase
{
    private readonly IYaraEngine _engine;
    private readonly YaraOptions _options;

    public YaraDetectionModule(IYaraEngine engine, YaraOptions options)
    {
        _engine = engine;
        _options = options;
    }

    public override string Name => "Yara";
    public override DetectionModuleCapabilities Capabilities =>
        DetectionModuleCapabilities.NeedsContent | DetectionModuleCapabilities.CanConfirmMalware;

    public override bool Supports(ScanTarget target, ScanContext context)
    {
        if (!_options.Enabled || _engine.RuleCount == 0) return false;
        // Skip archives: archive bytes are compressed and YARA on them is mostly
        // noise. The ArchiveDetectionModule unpacks selectively when needed.
        if (ArchiveAnalyzer.IsArchiveExtension(target.Extension)) return false;
        long maxBytes = Math.Max(1, _options.MaxScanSizeMB) * 1_048_576L;
        return target.File.Length > 0 && target.File.Length <= maxBytes;
    }

    protected override IReadOnlyList<Evidence> Analyze(ScanTarget target, ScanContext context, CancellationToken cancellationToken)
    {
        var hits = _engine.Scan(target.FullPath, _options.MaxScanSizeMB);
        if (hits.Count == 0) return Array.Empty<Evidence>();

        var capped = hits.Take(5).ToList();
        var evidence = new List<Evidence>(capped.Count);
        foreach (var hit in capped)
        {
            evidence.Add(new Evidence
            {
                Category = "Signature",
                Description = $"Regra YARA leve: {hit.RuleName} ({hit.Description})",
                Strength = hit.Confirmed ? EvidenceStrength.Confirmed : EvidenceStrength.High,
                CanConfirmMalware = hit.Confirmed,
                ScoreDelta = hit.Score,
            });
        }
        return evidence;
    }

    public sealed record YaraOptions(bool Enabled, int MaxScanSizeMB);
}
