using System;

namespace DataVanger.Core.Domain;

/// <summary>
/// Capability bitmap describing what a detection module needs and produces.
///
/// The orchestrator uses these flags to skip modules whose inputs are not
/// available (for example, skip the YARA module when the file is too large)
/// and to record telemetry per category.
/// </summary>
[Flags]
public enum DetectionModuleCapabilities
{
    None = 0,

    /// <summary>Module inspects the file path / name only.</summary>
    NeedsPath = 1 << 0,

    /// <summary>Module needs the SHA-256 hash to be precomputed.</summary>
    NeedsHash = 1 << 1,

    /// <summary>Module reads the file contents.</summary>
    NeedsContent = 1 << 2,

    /// <summary>Module performs PE-format parsing.</summary>
    PeAware = 1 << 3,

    /// <summary>Module parses script text.</summary>
    ScriptAware = 1 << 4,

    /// <summary>Module parses Office / PDF containers.</summary>
    DocumentAware = 1 << 5,

    /// <summary>Module parses ZIP-like archives.</summary>
    ArchiveAware = 1 << 6,

    /// <summary>Module inspects browser-extension manifests.</summary>
    BrowserExtensionAware = 1 << 7,

    /// <summary>Module uses persistence registry/scheduled-task context.</summary>
    PersistenceAware = 1 << 8,

    /// <summary>Module is capable of producing evidence that confirms malware.</summary>
    CanConfirmMalware = 1 << 9,
}
