using System;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Core;
using DataVanger.Engine.DeepScan;

namespace DataVanger.Engine.DeepScan.Stages;

/// <summary>
/// Recursive archive expansion stage.
///
/// When the work item looks like an archive container (by extension OR by
/// magic bytes), this stage walks its entries through
/// <see cref="ArchiveTraversal"/> and enqueues each admitted entry back into
/// the orchestrator's bounded channel as a new <see cref="ScanWorkItem"/>.
///
/// Safety:
///   - Every root archive owns one <see cref="ZipBombGuard"/> and one
///     <see cref="RecursionGuard"/>; nested entries share them so the budgets
///     are cumulative across the whole tree.
///   - The walk runs inside a linked CTS bounded by
///     <see cref="DeepScanProfileSettings.PerArchiveTimeout"/>.
///   - Bomb/recursion aborts are reported as evidence on the root archive,
///     never as crashes.
/// </summary>
public sealed class ArchiveExpansionStage : IPipelineStage
{
    public string Name => "ArchiveExpansion";

    public async Task<StageResult> ExecuteAsync(ScanWorkItem item, DeepScanContext context, CancellationToken cancellationToken)
    {
        if (!context.Profile.InspectArchives || context.Profile.MaxArchiveDepth == 0)
            return StageResult.Continue;

        cancellationToken.ThrowIfCancellationRequested();

        bool looksLikeArchive = LooksLikeArchive(item);
        if (!looksLikeArchive) return StageResult.Continue;

        // Each root archive gets its own zip-bomb / recursion budgets. Nested
        // archives inherit the parent guards via the same item chain so the
        // budgets are cumulative across one root tree.
        var (recursionGuard, zipBombGuard) = ResolveGuards(item, context);

        if (!recursionGuard.DepthAllowed(item.Depth + 1))
        {
            context.Telemetry.IncRecursionAbort();
            item.AddEvidence(new Evidence
            {
                Category = "Archive",
                Description = $"Recursão de archive abortada (depth >= {recursionGuard.MaxDepth})",
                ScoreDelta = 1,
                Strength = EvidenceStrength.Low,
            });
            return StageResult.Continue;
        }
        if (item.Depth > 0 && !recursionGuard.TryRegisterNestedArchive())
        {
            context.Telemetry.IncRecursionAbort();
            item.AddEvidence(new Evidence
            {
                Category = "Archive",
                Description = $"Orçamento de archives aninhados esgotado (>{recursionGuard.MaxNestedArchives})",
                ScoreDelta = 1,
                Strength = EvidenceStrength.Low,
            });
            return StageResult.Continue;
        }

        // Cycle protection: skip the archive entirely if we've already seen
        // its content in this same tree.
        string fingerprint = item.Sha256 ?? item.Source.LogicalPath;
        if (!recursionGuard.TryVisit(fingerprint))
        {
            context.Telemetry.IncRecursionAbort();
            return StageResult.Continue;
        }

        context.Telemetry.IncArchiveExpansion();
        context.Telemetry.NoteRecursionDepth(item.Depth + 1);

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (context.Profile.PerArchiveTimeout > TimeSpan.Zero) timeoutCts.CancelAfter(context.Profile.PerArchiveTimeout);

        long entries = 0;
        try
        {
            await using var rootStream = item.Source.OpenRead();
            foreach (var descriptor in ArchiveTraversal.Walk(
                         rootStream,
                         item.Source.LogicalPath,
                         currentDepth: item.Depth,
                         profile: context.Profile,
                         recursionGuard: recursionGuard,
                         zipBombGuard: zipBombGuard,
                         cancellationToken: timeoutCts.Token))
            {
                if (descriptor.IsAbort)
                {
                    RecordAbort(item, descriptor.AbortReason, context);
                    break;
                }
                if (descriptor.IsSuspicious)
                {
                    item.AddEvidence(new Evidence
                    {
                        Category = "Archive",
                        Description = $"Entry com path traversal: {descriptor.EntryName}",
                        ScoreDelta = 6,
                        Strength = EvidenceStrength.High,
                    });
                    continue;
                }
                entries++;

                // Only enqueue real bytes for further analysis if we managed to
                // buffer them within the per-entry budget. Anything bigger
                // becomes evidence on the parent and stops here.
                if (descriptor.Buffer is null)
                {
                    if (descriptor.UncompressedBytes > context.Profile.MaxInMemoryEntryBytes)
                    {
                        item.AddEvidence(new Evidence
                        {
                            Category = "Archive",
                            Description = $"Entry maior que o budget de memória: {descriptor.EntryName}",
                            ScoreDelta = 0,
                            Strength = EvidenceStrength.Info,
                        });
                    }
                    continue;
                }
                if (descriptor.Truncated)
                {
                    item.AddEvidence(new Evidence
                    {
                        Category = "Archive",
                        Description = $"Entry truncada para análise: {descriptor.EntryName}",
                        ScoreDelta = 0,
                        Strength = EvidenceStrength.Info,
                    });
                }

                var childSource = new MemoryContentSource(descriptor.EntryName, descriptor.Buffer, item.Source.LogicalPath);
                var childItem = new ScanWorkItem(childSource, depth: item.Depth + 1, parent: item)
                {
                    Target = null,
                };
                ScanWorkItemGuards.Attach(childItem, recursionGuard, zipBombGuard);

                context.Pending.Enqueued();
                bool written = context.QueueWriter.TryWrite(childItem);
                if (written)
                {
                    context.Telemetry.IncQueueDepth();
                }
                else
                {
                    childSource.Dispose();
                    context.Pending.Completed();
                    context.Telemetry.IncSkipped();
                    item.AddEvidence(new Evidence
                    {
                        Category = "Archive",
                        Description = $"Entry não expandida porque a fila de análise está cheia: {descriptor.EntryName}",
                        ScoreDelta = 0,
                        Strength = EvidenceStrength.Info,
                    });
                }
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            context.Telemetry.IncTimeout();
            RecordAbort(item, ArchiveAbortReason.Timeout, context);
        }
        catch (Exception ex)
        {
            context.Telemetry.IncError();
            context.Logger.ModuleFailure("ArchiveExpansion", item.Source.LogicalPath, ex);
        }
        finally
        {
            context.Telemetry.AddArchiveEntries(entries);
        }
        return StageResult.Continue;
    }

    private static (RecursionGuard, ZipBombGuard) ResolveGuards(ScanWorkItem item, DeepScanContext context)
    {
        // Walk up the parent chain looking for an existing guard pair —
        // this is how nested archives inherit the root budget.
        for (var cursor = item; cursor != null; cursor = cursor.Parent)
        {
            if (ScanWorkItemGuards.TryGet(cursor, out var rg, out var zg)) return (rg!, zg!);
        }
        var profile = context.Profile;
        var newRg = new RecursionGuard(profile.MaxArchiveDepth, profile.MaxNestedArchives);
        var newZg = new ZipBombGuard(profile.MaxTotalDecompressedBytes, profile.MaxArchiveEntries, profile.MaxCompressionRatio);
        ScanWorkItemGuards.Attach(item, newRg, newZg);
        return (newRg, newZg);
    }

    private static void RecordAbort(ScanWorkItem item, ArchiveAbortReason reason, DeepScanContext context)
    {
        if (reason == ArchiveAbortReason.None) return;
        int delta = reason switch
        {
            ArchiveAbortReason.DecompressedSizeExceeded => 6,
            ArchiveAbortReason.CompressionRatioExceeded => 6,
            ArchiveAbortReason.TooManyEntries => 3,
            _ => 1,
        };
        if (reason is ArchiveAbortReason.DecompressedSizeExceeded
                    or ArchiveAbortReason.CompressionRatioExceeded)
            context.Telemetry.IncZipBombAbort();

        item.AddEvidence(new Evidence
        {
            Category = "Archive",
            Description = $"Análise de archive abortada: {reason}",
            ScoreDelta = delta,
            Strength = EvidenceStrength.Medium,
        });
    }

    private static bool LooksLikeArchive(ScanWorkItem item)
    {
        if (item.SniffedType != SniffedFileType.Unknown && FileTypeSniffer.IsArchiveContainer(item.SniffedType))
            return true;
        string ext = System.IO.Path.GetExtension(item.Source.LogicalPath).ToLowerInvariant();
        return Detection.ArchiveAnalyzer.IsArchiveExtension(ext);
    }
}
