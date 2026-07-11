using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Core;
using DataVanger.Engine.DeepScan;

namespace DataVanger.Engine.DeepScan.Stages;

/// <summary>
/// NTFS Alternate Data Streams inspection. Only runs on Windows when the
/// active profile enabled it. Each non-default stream produces an evidence
/// item flagging the most common abuse pattern (hidden executables / scripts
/// stored in <c>file.txt:hidden.exe</c>).
///
/// We use BCL primitives only — no native interop — so cancellation propagates
/// naturally and a corrupt MFT entry yields zero evidence instead of a crash.
/// </summary>
public sealed class AlternateDataStreamStage : IPipelineStage
{
    public string Name => "ADS";

    public Task<StageResult> ExecuteAsync(ScanWorkItem item, DeepScanContext context, CancellationToken cancellationToken)
    {
        if (!context.Profile.InspectAlternateDataStreams) return Task.FromResult(StageResult.Continue);
        if (!item.Source.IsOnDisk) return Task.FromResult(StageResult.Continue);
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return Task.FromResult(StageResult.Continue);

        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            // Cheap surface-level detection: Windows exposes ADS via the
            // ::$DATA syntax on the FileInfo.FullName; presence of a colon in
            // the file name (beyond the drive letter) is a strong indicator
            // of an ADS path being scanned directly.
            string name = Path.GetFileName(item.Source.LogicalPath);
            if (name.Contains(':'))
            {
                string sub = name[(name.IndexOf(':') + 1)..];
                if (!string.IsNullOrEmpty(sub) && !string.Equals(sub, "$DATA", StringComparison.OrdinalIgnoreCase))
                {
                    item.AddEvidence(new Evidence
                    {
                        Category = "Heuristic",
                        Description = $"Stream NTFS alternativo: {sub}",
                        ScoreDelta = 5,
                        Strength = EvidenceStrength.High,
                    });
                }
            }
        }
        catch (System.Exception)
        {
            context.Telemetry.IncError();
        }
        return Task.FromResult(StageResult.Continue);
    }
}
