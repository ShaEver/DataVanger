using System;

namespace DataVanger.Behavioral;

/// <summary>
/// Immutable behavioral telemetry event.
///
/// Events flow from monitors -&gt; event bus -&gt; rule engine
/// -&gt; correlation engine. They carry the bare minimum needed for
/// downstream rules to make a decision:
///
///   - <see cref="Kind"/>            : what kind of event this is
///   - <see cref="Pid"/>             : process id of the actor
///   - <see cref="ParentPid"/>       : parent pid (0 when unknown)
///   - <see cref="ProcessName"/>     : leaf executable name lower-cased
///   - <see cref="ImagePath"/>       : full executable path (best-effort)
///   - <see cref="CommandLine"/>     : raw command line (best-effort; may be empty)
///   - <see cref="TargetPath"/>      : the file/key the actor touched (e.g. dropped exe, run key)
///   - <see cref="ExtraTag"/>        : free-form tag for rules (e.g. "encodedcommand", "amsi-bypass")
///   - <see cref="Severity"/>        : the monitor's initial guess (rules may upgrade)
///   - <see cref="Description"/>     : human-readable explanation
///   - <see cref="TimestampUtc"/>    : monotonically increasing per bus
///
/// Events are intentionally heuristic — no field can confirm malware on
/// its own. The classifier still owns the final verdict.
/// </summary>
public sealed class BehavioralEvent
{
    public BehavioralEvent(
        BehavioralEventKind kind,
        int pid,
        int parentPid,
        string processName,
        string imagePath,
        string commandLine,
        string targetPath,
        string extraTag,
        BehavioralSeverity severity,
        string description,
        DateTime timestampUtc)
    {
        Kind = kind;
        Pid = pid;
        ParentPid = parentPid;
        ProcessName = processName ?? "";
        ImagePath = imagePath ?? "";
        CommandLine = commandLine ?? "";
        TargetPath = targetPath ?? "";
        ExtraTag = extraTag ?? "";
        Severity = severity;
        Description = description ?? "";
        TimestampUtc = timestampUtc == default ? DateTime.UtcNow : timestampUtc.ToUniversalTime();
    }

    public BehavioralEventKind Kind { get; }
    public int Pid { get; }
    public int ParentPid { get; }
    public string ProcessName { get; }
    public string ImagePath { get; }
    public string CommandLine { get; }
    public string TargetPath { get; }
    public string ExtraTag { get; }
    public BehavioralSeverity Severity { get; }
    public string Description { get; }
    public DateTime TimestampUtc { get; }

    public override string ToString()
        => $"[{TimestampUtc:HH:mm:ss.fff}] {Kind} pid={Pid} parent={ParentPid} {ProcessName} {ExtraTag} :: {Description}";
}
