using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Engine.Remediation.Journal;
using DataVanger.Engine.Remediation.Rollback;

namespace DataVanger.Engine.Remediation.SystemScope;

/// <summary>A process to neutralize. The expected image/name (when supplied) is
/// re-checked against the live identity to refuse a recycled PID.</summary>
public sealed record ProcessRemediationTarget
{
    public required int Pid { get; init; }
    public string? ExpectedImagePath { get; init; }
    public string? ExpectedName { get; init; }
}

/// <summary>The live identity of a process, as reported by the provider.</summary>
public sealed record ProcessIdentitySnapshot(int Pid, string Name, string? ImagePath);

/// <summary>OS seam for process remediation. The only place a real kill happens.</summary>
public interface IProcessRemediationProvider
{
    int CurrentProcessId { get; }
    ProcessIdentitySnapshot? GetIdentity(int pid);

    /// <summary>Direct children of <paramref name="pid"/> (not recursive).</summary>
    IReadOnlyList<int> GetChildren(int pid);

    void Kill(int pid);
}

/// <summary>
/// Conservative refusal policy for process kills. Refuses, by default:
///   - PID 0 (System Idle) and PID 4 (System), and any non-positive PID;
///   - the current process;
///   - a curated denylist of critical Windows image names (smss, csrss, wininit,
///     winlogon, services, lsass, lsaiso, fontdrvhost, dwm, svchost, …);
///   - any process whose identity is unknown.
/// Extra critical names are injectable; the policy never *removes* a default.
/// </summary>
public sealed class CriticalProcessPolicy
{
    private static readonly string[] DefaultCriticalNames =
    {
        "system", "registry", "memory compression", "idle",
        "smss", "csrss", "wininit", "winlogon", "services",
        "lsass", "lsaiso", "lsm", "fontdrvhost", "dwm", "svchost",
        "wininit.exe", "csrss.exe", "smss.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "svchost.exe",
    };

    private readonly HashSet<string> _critical;

    public CriticalProcessPolicy(IEnumerable<string>? additionalCriticalNames = null)
    {
        _critical = new HashSet<string>(DefaultCriticalNames, StringComparer.OrdinalIgnoreCase);
        if (additionalCriticalNames is not null)
            foreach (var n in additionalCriticalNames)
                if (!string.IsNullOrWhiteSpace(n)) _critical.Add(n.Trim());
    }

    public bool IsCriticalPid(int pid) => pid <= 4;

    public bool IsCriticalIdentity(ProcessIdentitySnapshot identity)
    {
        if (IsCriticalPid(identity.Pid)) return true;
        return IsCriticalName(identity.Name) || IsCriticalName(LastPathSegment(identity.ImagePath));
    }

    private bool IsCriticalName(string? value)
    {
        var name = value?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(name)) return false;
        if (_critical.Contains(name)) return true;
        var bare = name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
        return _critical.Contains(bare);
    }

    private static string? LastPathSegment(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var slash = path.LastIndexOf('/');
        var backslash = path.LastIndexOf('\\');
        var index = Math.Max(slash, backslash);
        return index >= 0 && index + 1 < path.Length ? path[(index + 1)..] : path;
    }
}

/// <summary>
/// Kills a malicious process tree, refusing critical/protected/unknown targets and
/// the current process. The kill is IRREVERSIBLE (explicitly classified), so it
/// produces an irreversible rollback token, never a recoverable one. Journaled
/// before any kill.
/// </summary>
public sealed class KillProcessTreeAction
{
    private readonly IProcessRemediationProvider _provider;
    private readonly CriticalProcessPolicy _policy;
    private readonly IRemediationClock _clock;
    private const int MaxTreeNodes = 1024; // bound the walk

    public KillProcessTreeAction(IProcessRemediationProvider provider, CriticalProcessPolicy? policy = null, IRemediationClock? clock = null)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _policy = policy ?? new CriticalProcessPolicy();
        _clock = clock ?? SystemRemediationClock.Instance;
    }

    public Task<SystemRemediationResult> ExecuteAsync(
        ProcessRemediationTarget target,
        IRemediationJournal journal,
        RemediationCorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        if (target is null) throw new ArgumentNullException(nameof(target));
        if (journal is null) throw new ArgumentNullException(nameof(journal));

        var matchKey = $"Process:{target.Pid}";

        if (_policy.IsCriticalPid(target.Pid))
            return Block(SystemRemediationOutcome.BlockedCriticalTarget, $"PID {target.Pid} is a critical/system PID.");

        if (target.Pid == _provider.CurrentProcessId)
            return Block(SystemRemediationOutcome.BlockedCriticalTarget, "Refusing to kill the current process.");

        var identity = _provider.GetIdentity(target.Pid);
        if (identity is null)
            return Block(SystemRemediationOutcome.BlockedUnknownIdentity, $"PID {target.Pid} has no resolvable identity.");

        // Identity drift: a recycled PID whose image/name no longer matches the plan.
        if (!string.IsNullOrEmpty(target.ExpectedName) &&
            !string.Equals(target.ExpectedName, identity.Name, StringComparison.OrdinalIgnoreCase))
            return Block(SystemRemediationOutcome.BlockedUnknownIdentity, "Process name no longer matches the planned target (recycled PID).");
        if (!string.IsNullOrEmpty(target.ExpectedImagePath) &&
            !string.Equals(target.ExpectedImagePath, identity.ImagePath, StringComparison.OrdinalIgnoreCase))
            return Block(SystemRemediationOutcome.BlockedUnknownIdentity, "Process image path no longer matches the planned target (recycled PID).");

        // Collect the tree (root + descendants), refusing the WHOLE kill if any
        // node is critical — never partially kill a tree that contains a critical
        // process.
        var (tree, truncated) = CollectTree(target.Pid);
        if (truncated)
            return Block(SystemRemediationOutcome.BlockedUnknownIdentity, $"Process tree exceeds the {MaxTreeNodes} node safety bound; refusing partial kill.");

        var affected = new List<ProcessIdentitySnapshot>();
        foreach (var pid in tree)
        {
            if (_policy.IsCriticalPid(pid) || pid == _provider.CurrentProcessId)
                return Block(SystemRemediationOutcome.BlockedCriticalTarget, $"Process tree contains a critical/self process (PID {pid}); refusing the entire kill.");

            var snap = _provider.GetIdentity(pid);
            if (snap is null)
                return Block(SystemRemediationOutcome.BlockedUnknownIdentity, $"Process tree contains a process with unknown identity (PID {pid}); refusing the entire kill.");

            if (_policy.IsCriticalIdentity(snap))
                return Block(SystemRemediationOutcome.BlockedCriticalTarget, $"Process tree contains a critical/self process (PID {pid}); refusing the entire kill.");
            affected.Add(snap);
        }

        SystemRemediationJournal.Intent(journal, correlationId, RemediationActionKind.KillProcessTree, matchKey, _clock,
            RollbackTokenKind.None, $"tree:[{string.Join(",", tree)}]");

        try
        {
            // Kill leaves first (reverse of the discovery order, which is parents-first).
            foreach (var pid in Enumerable.Reverse(tree))
                _provider.Kill(pid);
        }
        catch (Exception ex)
        {
            SystemRemediationJournal.Outcome(journal, correlationId, RemediationActionKind.KillProcessTree, matchKey, _clock, $"Failed: {ex.GetType().Name}");
            return Task.FromResult(new SystemRemediationResult
            {
                Outcome = SystemRemediationOutcome.Failed,
                Reason = $"Kill failed: {ex.GetType().Name}: {ex.Message}",
                TargetId = matchKey,
            });
        }

        SystemRemediationJournal.Outcome(journal, correlationId, RemediationActionKind.KillProcessTree, matchKey, _clock, "Succeeded");

        return Task.FromResult(new SystemRemediationResult
        {
            Outcome = SystemRemediationOutcome.Succeeded,
            Reason = $"Killed {affected.Count} process(es).",
            TargetId = matchKey,
            RollbackToken = RollbackToken.Irreversible(correlationId), // a kill cannot be undone
            AffectedIdentities = affected.Select(a => $"{a.Pid}:{a.Name}").ToArray(),
        });
    }

    private (List<int> Tree, bool Truncated) CollectTree(int rootPid)
    {
        var order = new List<int>();
        var seen = new HashSet<int>();
        var queue = new Queue<int>();
        queue.Enqueue(rootPid);
        seen.Add(rootPid);
        var truncated = false;
        while (queue.Count > 0)
        {
            if (order.Count >= MaxTreeNodes)
            {
                truncated = true;
                break;
            }

            var pid = queue.Dequeue();
            order.Add(pid);
            foreach (var child in _provider.GetChildren(pid))
            {
                if (seen.Add(child)) queue.Enqueue(child);
            }
        }
        return (order, truncated || queue.Count > 0);
    }

    private static Task<SystemRemediationResult> Block(SystemRemediationOutcome outcome, string reason)
        => Task.FromResult(new SystemRemediationResult { Outcome = outcome, Reason = reason });
}
