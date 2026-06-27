using System;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Core;
using DataVanger.Engine.DeepScan;

namespace DataVanger.Engine.DeepScan.Stages;

/// <summary>
/// Magic-byte file type identification. Adds evidence when the sniffed type
/// disagrees with the declared extension (classic disguised-payload pattern).
/// Skipped entirely when the active profile disables real-type resolution.
/// </summary>
public sealed class FileTypeIdentificationStage : IPipelineStage
{
    public string Name => "FileType";

    public async Task<StageResult> ExecuteAsync(ScanWorkItem item, DeepScanContext context, CancellationToken cancellationToken)
    {
        if (!context.Profile.ResolveRealFileType) return StageResult.Continue;
        cancellationToken.ThrowIfCancellationRequested();

        SniffedFileType sniffed = SniffedFileType.Unknown;
        try
        {
            await using var stream = item.Source.OpenRead();
            sniffed = FileTypeSniffer.Sniff(stream);
        }
        catch (System.Exception)
        {
            context.Telemetry.IncError();
        }

        item.SniffedType = sniffed;
        context.Telemetry.IncTypeIdentified();

        string ext = item.Target?.Extension ?? System.IO.Path.GetExtension(item.Source.LogicalPath).ToLowerInvariant();
        if (FileTypeSniffer.IsSpoofed(sniffed, ext))
        {
            item.AddEvidence(new Evidence
            {
                Category = "Heuristic",
                Description = $"Conteúdo real ({sniffed}) não coincide com a extensão ({ext})",
                ScoreDelta = 4,
                Strength = EvidenceStrength.High,
            });
        }

        return StageResult.Continue;
    }
}
