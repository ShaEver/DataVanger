using System.Collections.Generic;

namespace DataVanger.Shared.Quarantine;

/// <summary>
/// Request to move a file into secure quarantine. The caller (scan/response
/// pipeline or UI) is responsible for classification; the quarantine service
/// never classifies. For <see cref="QuarantineRequestOrigin.Automatic"/>
/// requests the service only proceeds when
/// <see cref="Classification"/> is <see cref="QuarantineThreatClassification.ConfirmedMalware"/>.
/// </summary>
public sealed class QuarantineRequest
{
    public string SourcePath { get; set; } = string.Empty;

    public QuarantineRequestOrigin Origin { get; set; } = QuarantineRequestOrigin.ManualUserApproved;
    public QuarantineThreatClassification Classification { get; set; } = QuarantineThreatClassification.Clean;
    public QuarantineRequestedAction RequestedAction { get; set; } = QuarantineRequestedAction.Quarantine;

    public string DetectionSummary { get; set; } = string.Empty;
    public string ActionReason { get; set; } = string.Empty;
    public string SourceModule { get; set; } = string.Empty;
    public List<string> EvidenceIds { get; set; } = new();

    /// <summary>
    /// SHA-256 already computed by the detection caller. When supplied, V2
    /// refuses the operation if the bytes read for quarantine do not match it.
    /// This binds the decision to the content that was classified.
    /// </summary>
    public string? ExpectedSha256 { get; set; }

    /// <summary>
    /// When true, the service attempts to remove the original AFTER the
    /// encrypted payload is stored and verified. A failed deletion is reported
    /// (OriginalDeleteFailed) but never crashes the operation. Defaults to
    /// false so development/test callers never lose their source files
    /// unintentionally.
    /// </summary>
    public bool DeleteOriginalAfterStore { get; set; }
}

/// <summary>Request to restore a previously quarantined file. Restore always requires explicit intent.</summary>
public sealed class QuarantineRestoreRequest
{
    public string QuarantineId { get; set; } = string.Empty;

    /// <summary>
    /// Destination path. When null/empty the original path from the record is
    /// used (subject to the same path-safety validation).
    /// </summary>
    public string? DestinationPath { get; set; }

    /// <summary>Restore refuses to overwrite an existing file unless this is explicitly set.</summary>
    public bool AllowOverwrite { get; set; }
}
