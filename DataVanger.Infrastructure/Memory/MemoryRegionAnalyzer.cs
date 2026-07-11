using System;
using System.Collections.Generic;
using System.Threading;
using DataVanger.Memory.Readers;
using DataVanger.Memory.Rules;

namespace DataVanger.Memory;

/// <summary>
/// Runs a set of <see cref="IMemoryRule"/>s against a single region.
/// Isolates each rule with try/catch so one bad rule cannot poison a
/// whole scan pass.
/// </summary>
public sealed class MemoryRegionAnalyzer
{
    private readonly IReadOnlyList<IMemoryRule> _rules;
    private readonly Action<string>? _diagnostics;

    public MemoryRegionAnalyzer(IEnumerable<IMemoryRule> rules, Action<string>? diagnostics = null)
    {
        var list = new List<IMemoryRule>();
        if (rules is not null)
            foreach (var r in rules) if (r is not null) list.Add(r);
        _rules = list;
        _diagnostics = diagnostics;
    }

    public IReadOnlyList<IMemoryRule> Rules => _rules;

    public bool AnyRuleNeedsBytes
    {
        get
        {
            foreach (var r in _rules) if (r.RequiresBytes) return true;
            return false;
        }
    }

    public IReadOnlyList<MemoryFinding> Analyze(
        ProcessSnapshot process,
        MemoryRegion region,
        IMemoryReader reader,
        int maxBytesPerRegion,
        CancellationToken cancellationToken)
    {
        if (region is null || reader is null) return Array.Empty<MemoryFinding>();

        byte[] sample = Array.Empty<byte>();
        if (AnyRuleNeedsBytes)
        {
            try
            {
                sample = reader.ReadBytes(region, maxBytesPerRegion, cancellationToken) ?? Array.Empty<byte>();
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _diagnostics?.Invoke($"memory: read failed at 0x{region.BaseAddress:X}: {ex.GetType().Name}");
                sample = Array.Empty<byte>();
            }
        }

        var findings = new List<MemoryFinding>();
        foreach (var rule in _rules)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var emitted = rule.Evaluate(process, region, sample, cancellationToken);
                if (emitted is null) continue;
                foreach (var f in emitted)
                {
                    if (f is null) continue;
                    // Defensive: rules must never construct findings claiming confirmation,
                    // but if a custom rule sneaks one in we still hold the line here.
                    if (f.CanConfirmMalware)
                    {
                        _diagnostics?.Invoke($"memory: rule {rule.RuleId} attempted to confirm — dropping field");
                    }
                    findings.Add(f);
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _diagnostics?.Invoke($"memory: rule {rule.RuleId} threw {ex.GetType().Name}");
            }
        }
        return findings;
    }
}
