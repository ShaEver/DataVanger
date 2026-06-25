using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Engine.Remediation.Journal;
using DataVanger.Engine.Remediation.Rollback;

namespace DataVanger.Engine.Remediation.SystemScope;

/// <summary>A Windows service to stop/disable, identified by its CANONICAL service
/// name (never the display name).</summary>
public sealed record ServiceRemediationTarget
{
    public required string ServiceName { get; init; }
}

/// <summary>The recorded prior state of a service, used to roll back.</summary>
public sealed record ServiceStateBackup(string ServiceName, string StartType, bool WasRunning);

/// <summary>OS seam for service remediation.</summary>
public interface IServiceRemediationProvider
{
    /// <summary>Returns the current start type + running state, or null if the
    /// service does not exist.</summary>
    ServiceStateBackup? ReadState(string serviceName);

    void Stop(string serviceName);
    void Disable(string serviceName);

    /// <summary>Restores a previously backed-up start type / running state.</summary>
    void Restore(ServiceStateBackup backup);
}

/// <summary>
/// Conservative refusal policy for service stop/disable. Refuses a curated denylist
/// of critical Windows services by canonical name, plus missing/blank names. Extra
/// critical names are injectable; defaults are never removed.
/// </summary>
public sealed class CriticalServicePolicy
{
    private static readonly string[] DefaultCriticalServices =
    {
        "wininit", "winlogon", "services", "rpcss", "dcomlaunch", "lsass",
        "samss", "eventlog", "plugplay", "power", "schedule", "bfe",
        "mpssvc", "windefend", "wscsvc", "wuauserv", "trustedinstaller",
        "dnscache", "nsi", "netprofm", "profsvc", "termservice", "cryptsvc",
        "bits", "gpsvc", "lanmanserver", "lanmanworkstation",
        "rpceptmapper", "eventsystem", "winmgmt", "keyiso", "appinfo",
        "nlasvc", "dhcp", "netlogon", "usermanager", "brokerinfrastructure",
        "coremessagingregistrar", "sgrmbroker", "securityhealthservice",
        "sense", "wdnissvc",
    };

    private readonly HashSet<string> _critical;

    public CriticalServicePolicy(IEnumerable<string>? additionalCriticalServices = null)
    {
        _critical = new HashSet<string>(DefaultCriticalServices, StringComparer.OrdinalIgnoreCase);
        if (additionalCriticalServices is not null)
            foreach (var s in additionalCriticalServices)
                if (!string.IsNullOrWhiteSpace(s)) _critical.Add(s.Trim());
    }

    public bool IsCritical(string? serviceName)
        => string.IsNullOrWhiteSpace(serviceName) || _critical.Contains(serviceName.Trim());
}

/// <summary>
/// Stops and disables a malicious service. Refuses critical services and missing
/// identities; backs up the prior start type / running state BEFORE mutating; and
/// produces a ServiceConfigBackup rollback token so the change is reversible.
/// </summary>
public sealed class StopDisableServiceAction
{
    private readonly IServiceRemediationProvider _provider;
    private readonly CriticalServicePolicy _policy;
    private readonly IRemediationClock _clock;

    public StopDisableServiceAction(IServiceRemediationProvider provider, CriticalServicePolicy? policy = null, IRemediationClock? clock = null)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _policy = policy ?? new CriticalServicePolicy();
        _clock = clock ?? SystemRemediationClock.Instance;
    }

    public Task<SystemRemediationResult> ExecuteAsync(
        ServiceRemediationTarget target,
        IRemediationJournal journal,
        RemediationCorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        if (target is null) throw new ArgumentNullException(nameof(target));
        if (journal is null) throw new ArgumentNullException(nameof(journal));

        var serviceName = target.ServiceName?.Trim();

        if (_policy.IsCritical(serviceName))
            return Block(SystemRemediationOutcome.BlockedCriticalTarget, $"Service '{target.ServiceName}' is critical or has no canonical name.");

        var matchKey = $"Service:{serviceName!.ToLowerInvariant()}";

        var backup = _provider.ReadState(serviceName);
        if (backup is null)
            return Block(SystemRemediationOutcome.BlockedTargetNotFound, $"Service '{serviceName}' does not exist.");

        var backupRef = $"start={backup.StartType};running={backup.WasRunning}";
        SystemRemediationJournal.Intent(journal, correlationId, RemediationActionKind.StopAndDisableService, matchKey, _clock,
            RollbackTokenKind.ServiceConfigBackup, backupRef);

        try
        {
            _provider.Stop(serviceName);
            _provider.Disable(serviceName);
        }
        catch (Exception ex)
        {
            SystemRemediationJournal.Outcome(journal, correlationId, RemediationActionKind.StopAndDisableService, matchKey, _clock, $"Failed: {ex.GetType().Name}");
            return Task.FromResult(new SystemRemediationResult
            {
                Outcome = SystemRemediationOutcome.Failed,
                Reason = $"Stop/disable failed: {ex.GetType().Name}: {ex.Message}. Prior state recorded for rollback.",
                TargetId = matchKey,
                BackupRef = backupRef,
                RollbackToken = RollbackToken.For(RollbackTokenKind.ServiceConfigBackup, SerializeBackup(backup), correlationId),
            });
        }

        SystemRemediationJournal.Outcome(journal, correlationId, RemediationActionKind.StopAndDisableService, matchKey, _clock, "Succeeded", RollbackTokenKind.ServiceConfigBackup);

        return Task.FromResult(new SystemRemediationResult
        {
            Outcome = SystemRemediationOutcome.Succeeded,
            Reason = "Service stopped and disabled; prior start type captured for rollback.",
            TargetId = matchKey,
            BackupRef = backupRef,
            RollbackToken = RollbackToken.For(RollbackTokenKind.ServiceConfigBackup, SerializeBackup(backup), correlationId),
        });
    }

    /// <summary>Restores a service to its backed-up start type / running state.</summary>
    public SystemRemediationResult Rollback(ServiceStateBackup backup)
    {
        try
        {
            _provider.Restore(backup);
            return new SystemRemediationResult { Outcome = SystemRemediationOutcome.RolledBack, Reason = "Service start type restored.", TargetId = $"Service:{backup.ServiceName.ToLowerInvariant()}" };
        }
        catch (Exception ex)
        {
            return new SystemRemediationResult { Outcome = SystemRemediationOutcome.RollbackFailed, Reason = $"Rollback failed: {ex.GetType().Name}: {ex.Message}" };
        }
    }

    /// <summary>Restores a service from a self-contained ServiceConfigBackup token.</summary>
    public SystemRemediationResult Rollback(RollbackToken token)
    {
        if (token is null) throw new ArgumentNullException(nameof(token));
        if (token.Kind != RollbackTokenKind.ServiceConfigBackup || string.IsNullOrWhiteSpace(token.Payload))
            return new SystemRemediationResult { Outcome = SystemRemediationOutcome.RollbackFailed, Reason = "Rollback token is not a service-config backup token." };

        try
        {
            var backup = JsonSerializer.Deserialize<ServiceStateBackup>(token.Payload);
            return backup is null
                ? new SystemRemediationResult { Outcome = SystemRemediationOutcome.RollbackFailed, Reason = "Service rollback token payload could not be decoded." }
                : Rollback(backup);
        }
        catch (JsonException ex)
        {
            return new SystemRemediationResult { Outcome = SystemRemediationOutcome.RollbackFailed, Reason = $"Service rollback token payload is invalid: {ex.Message}" };
        }
    }

    internal static string SerializeBackup(ServiceStateBackup b) => JsonSerializer.Serialize(b);

    private static Task<SystemRemediationResult> Block(SystemRemediationOutcome outcome, string reason)
        => Task.FromResult(new SystemRemediationResult { Outcome = outcome, Reason = reason });
}
