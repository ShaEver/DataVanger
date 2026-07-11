namespace DataVanger.Shared.RuntimeEvents;

/// <summary>
/// Lightweight pointer to evidence produced elsewhere (a file path, a
/// SHA-256, a YARA rule id, a registry path, a process id, ...).
///
/// IMPORTANT:
///   Evidence references MUST NOT carry large binary payloads, full
///   file contents, or secrets. They are pointers, not exfiltration
///   surfaces.
///
/// Suggested values for <see cref="Type"/> (free-form to avoid coupling
/// the pipeline to a closed enum of evidence kinds):
///
///   FilePath, Sha256, ProcessId, CommandLine, YaraRule, RegistryPath,
///   Url, ExtensionId, EtwProvider, TestCase
/// </summary>
public sealed class RuntimeEvidenceReference
{
    public string Type { get; init; } = string.Empty;
    public string Value { get; init; } = string.Empty;
    public string? Description { get; init; }
}
