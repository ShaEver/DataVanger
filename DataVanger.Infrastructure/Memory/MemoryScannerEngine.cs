using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using DataVanger.Memory.Readers;
using DataVanger.Memory.Rules;

namespace DataVanger.Memory;

/// <summary>
/// Concrete <see cref="IMemoryScanner"/> implementation. Walks each
/// process the reader can show us, applies the configured rules and
/// returns an aggregated, bounded result. All limits in
/// <see cref="MemoryScannerOptions"/> are enforced strictly.
/// </summary>
public sealed class MemoryScannerEngine : IMemoryScanner
{
    private readonly IMemoryReader _reader;
    private readonly MemoryRegionAnalyzer _analyzer;
    private readonly Action<string>? _diagnostics;

    public MemoryScannerEngine(
        IMemoryReader reader,
        IEnumerable<IMemoryRule>? rules = null,
        Action<string>? diagnostics = null)
    {
        _reader = reader ?? NullMemoryReader.Instance;
        _diagnostics = diagnostics;
        _analyzer = new MemoryRegionAnalyzer(rules ?? DefaultRules(), diagnostics);
    }

    public static IEnumerable<IMemoryRule> DefaultRules() => new IMemoryRule[]
    {
        new RwxRegionRule(),
        new AnonymousExecutableRule(),
        new ReflectivePeIndicatorRule(),
        new ShellcodeLikePatternRule(),
        new HighEntropyExecutableRule(),
        new SuspiciousModulePathRule(),
        new HollowingIndicatorRule(),
    };

    public bool IsSupported => _reader.IsSupported;

    public MemoryScanResult Scan(MemoryScannerOptions options, CancellationToken cancellationToken)
    {
        options ??= new MemoryScannerOptions();
        if (!options.Enabled)
            return MemoryScanResult.Empty(MemoryScanDegradationReason.DisabledByConfiguration);
        if (!_reader.IsSupported)
            return MemoryScanResult.Empty(MemoryScanDegradationReason.PlatformUnsupported);

        using var overallCts = options.OverallTimeout > TimeSpan.Zero
            ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken)
            : CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (options.OverallTimeout > TimeSpan.Zero) overallCts.CancelAfter(options.OverallTimeout);
        var ct = overallCts.Token;

        var findings = new List<MemoryFinding>(capacity: 64);
        int processesSeen = 0;
        int processesScanned = 0;
        int processesInaccessible = 0;
        int regionsExamined = 0;
        long bytesExamined = 0;
        var degradation = MemoryScanDegradationReason.None;
        string degradationDetail = "";
        bool limitsTripped = false;

        var startedAt = Stopwatch.StartNew();
        try
        {
            IEnumerable<ProcessSnapshot> snapshots;
            try { snapshots = _reader.EnumerateProcesses(ct); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _diagnostics?.Invoke($"memory: process enumeration failed: {ex.GetType().Name}");
                return MemoryScanResult.Empty(MemoryScanDegradationReason.InsufficientPrivileges,
                                              ex.GetType().Name);
            }

            foreach (var process in snapshots)
            {
                if (ct.IsCancellationRequested) break;
                processesSeen++;
                if (processesScanned >= options.MaxProcesses)
                {
                    limitsTripped = true;
                    break;
                }
                if (process is null) continue;
                if (!process.IsAccessible) { processesInaccessible++; continue; }
                if (options.SkipProtectedProcesses && process.IsSystemProtected) continue;

                if (ScanOneProcess(process, options, ref regionsExamined, ref bytesExamined, findings, ct,
                                   out bool perProcLimitsTripped))
                {
                    processesScanned++;
                }
                if (perProcLimitsTripped) limitsTripped = true;
                if (findings.Count >= options.MaxFindings) { limitsTripped = true; break; }
                if (bytesExamined >= options.MaxTotalBytes) { limitsTripped = true; break; }
            }
        }
        catch (OperationCanceledException)
        {
            degradation = cancellationToken.IsCancellationRequested
                ? MemoryScanDegradationReason.Cancelled
                : MemoryScanDegradationReason.Timeout;
            degradationDetail = degradation == MemoryScanDegradationReason.Timeout
                ? $"elapsed {startedAt.Elapsed}"
                : "";
        }
        catch (Exception ex)
        {
            _diagnostics?.Invoke($"memory: scan aborted: {ex.GetType().Name}");
            degradation = MemoryScanDegradationReason.InsufficientPrivileges;
            degradationDetail = ex.GetType().Name;
        }

        if (degradation == MemoryScanDegradationReason.None && limitsTripped)
            degradation = MemoryScanDegradationReason.LimitsExceeded;

        return new MemoryScanResult(
            findings: findings,
            processesEnumerated: processesSeen,
            processesScanned: processesScanned,
            processesInaccessible: processesInaccessible,
            regionsExamined: regionsExamined,
            bytesExamined: bytesExamined,
            degradation: degradation,
            degradationDetail: degradationDetail);
    }

    private bool ScanOneProcess(
        ProcessSnapshot process,
        MemoryScannerOptions options,
        ref int regionsExamined,
        ref long bytesExamined,
        List<MemoryFinding> findings,
        CancellationToken outerCt,
        out bool limitsTripped)
    {
        limitsTripped = false;
        using var perProcCts = options.PerProcessTimeout > TimeSpan.Zero
            ? CancellationTokenSource.CreateLinkedTokenSource(outerCt)
            : CancellationTokenSource.CreateLinkedTokenSource(outerCt);
        if (options.PerProcessTimeout > TimeSpan.Zero) perProcCts.CancelAfter(options.PerProcessTimeout);

        IEnumerable<MemoryRegion> regions;
        try { regions = _reader.EnumerateRegions(process, perProcCts.Token); }
        catch (OperationCanceledException) { return false; }
        catch (Exception ex)
        {
            _diagnostics?.Invoke($"memory: enumerate regions for pid={process.ProcessId} failed: {ex.GetType().Name}");
            return false;
        }

        int regionsInThisProcess = 0;
        foreach (var region in regions)
        {
            if (perProcCts.IsCancellationRequested) break;
            if (region is null) continue;
            if (regionsInThisProcess >= options.MaxRegionsPerProcess)
            {
                limitsTripped = true;
                break;
            }
            regionsInThisProcess++;
            regionsExamined++;

            int readCap = (int)Math.Min(options.MaxBytesPerRegion, Math.Max(0, region.Size));
            if (bytesExamined + readCap > options.MaxTotalBytes)
            {
                readCap = (int)Math.Max(0, options.MaxTotalBytes - bytesExamined);
                if (readCap <= 0) { limitsTripped = true; break; }
            }

            IReadOnlyList<MemoryFinding> emitted;
            try
            {
                emitted = _analyzer.Analyze(process, region, _reader, readCap, perProcCts.Token);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _diagnostics?.Invoke($"memory: analyzer threw for pid={process.ProcessId}: {ex.GetType().Name}");
                continue;
            }
            bytesExamined += readCap;

            foreach (var f in emitted)
            {
                if (f is null) continue;
                findings.Add(f);
                if (findings.Count >= options.MaxFindings) { limitsTripped = true; break; }
            }
            if (findings.Count >= options.MaxFindings) break;
        }
        return true;
    }
}
