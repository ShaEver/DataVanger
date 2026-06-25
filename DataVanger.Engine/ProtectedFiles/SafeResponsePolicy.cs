using DataVanger.Shared.ProtectedFiles;

namespace DataVanger.Engine.ProtectedFiles;

/// <summary>
/// Describes the passive, development-safe response the monitor is
/// permitted to take for a piece of evidence. Every field here is
/// non-destructive.
/// </summary>
public sealed class SafeResponse
{
    /// <summary>Always allowed: hand the evidence to the configured sink.</summary>
    public bool EmitEvidence { get; init; }

    /// <summary>Allowed in AlertOnly/Passive when republish is enabled: emit reporting telemetry.</summary>
    public bool EmitReportTelemetry { get; init; }

    /// <summary>Always allowed: update the health snapshot counters.</summary>
    public bool UpdateHealth { get; init; } = true;

    /// <summary>A non-destructive recommendation string (review/investigate only).</summary>
    public string RecommendedAction { get; init; } =
        "Review the activity. Protected-file activity evidence only — does not confirm malware.";

    /// <summary>Human-readable label of the response mode for evidence/reporting.</summary>
    public string ModeLabel { get; init; } = "Passive";
}

/// <summary>
/// Computes the passive response for the Protected Files Activity Monitor
/// (Phase 2 / Step 07).
///
/// EXTREMELY IMPORTANT:
///   This policy NEVER authorizes a destructive or active response. There
///   is no process kill, no suspend, no write-block, no quarantine, no
///   rollback, no recovery/backup command. Even when
///   <see cref="ProtectedFilesActivityOptions.EnableActiveResponseHooks"/>
///   is set, the only effect is a slightly stronger RECOMMENDATION label —
///   the monitor still takes no action. Active response remains a future
///   roadmap concern and is intentionally not implemented here.
/// </summary>
public sealed class SafeResponsePolicy
{
    private readonly ProtectedFilesActivityOptions _options;

    public SafeResponsePolicy(ProtectedFilesActivityOptions options)
    {
        _options = (options ?? ProtectedFilesActivityOptions.DevelopmentSafe()).WithSafeDefaults();
    }

    public SafeResponse Decide(ProtectedFilesActivitySeverity severity)
    {
        if (_options.Mode == ProtectedFilesActivityMode.Disabled)
        {
            return new SafeResponse
            {
                EmitEvidence = false,
                EmitReportTelemetry = false,
                UpdateHealth = true,
                ModeLabel = "Disabled",
                RecommendedAction = "Monitoring disabled.",
            };
        }

        var recommendation = severity switch
        {
            ProtectedFilesActivitySeverity.ProtectedActivitySuspected => RecommendSuspected(),
            ProtectedFilesActivitySeverity.HighRisk =>
                "Investigate this process and its recent file activity. Protected-file activity evidence only — does not confirm malware; no automatic action was taken.",
            _ => "Review the activity. Protected-file activity evidence only — does not confirm malware.",
        };

        return new SafeResponse
        {
            EmitEvidence = true,
            // Reporting telemetry only when explicitly enabled; it is still
            // non-destructive (a DetectionEvidence/RansomwareSuspicion event).
            EmitReportTelemetry = _options.RepublishEvidenceToPipeline,
            UpdateHealth = true,
            ModeLabel = _options.Mode.ToString(),
            RecommendedAction = recommendation,
        };
    }

    private string RecommendSuspected()
        => _options.EnableActiveResponseHooks
            ? "Recommend (passive): isolate and scan the implicated process image and review affected folders. NOTE: no active response is performed in this phase — this is a recommendation only and does not confirm malware."
            : "Recommend: review the implicated process and affected protected folders and run a scan. Protected-file activity evidence only — does not confirm malware; no automatic action was taken.";
}
