using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// Orchestrates the signed-update workflow: fetch → deserialize → reconstruct
/// canonical payload → verify signature → anti-downgrade check → fetch and
/// validate packages → stage → commit → record state → publish telemetry.
///
/// Every public method returns a structured result and degrades gracefully;
/// update problems are never fatal and never produce a malware verdict.
/// </summary>
public interface ISignedUpdateService
{
    /// <summary>Fetch, verify, stage, and (when permitted) commit an update.</summary>
    UpdateApplyResult CheckAndApply();

    /// <summary>Fetch and verify only (no staging/commit); used for passive checks.</summary>
    UpdateVerificationResult CheckOnly();

    /// <summary>Restore the last-known-good update set, or report none available.</summary>
    UpdateApplyResult Rollback();

    /// <summary>Cheap read-only health snapshot.</summary>
    UpdateHealthSnapshot GetHealth();
}
