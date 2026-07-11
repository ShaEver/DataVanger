using System;
using System.Collections.Generic;
using System.Linq;

namespace DataVanger.Engine.Remediation.Verification;

/// <summary>The kind of post-remediation check to run.</summary>
public enum VerificationCheckKind
{
    /// <summary>The remediated file must be ABSENT.</summary>
    FileAbsent = 0,

    /// <summary>A persistence identity (autorun/task/service) must be GONE.</summary>
    PersistenceGone,

    /// <summary>The quarantine record for the removed item must still be VALID.</summary>
    QuarantineRecordValid,

    /// <summary>A targeted re-scan/check of the location must be CLEAN.</summary>
    ScanClean,
}

/// <summary>A requested check: kind + the target it applies to.</summary>
public sealed record VerificationCheck(VerificationCheckKind Kind, string Target);

/// <summary>The result of one check.</summary>
public sealed record VerificationFinding(VerificationCheckKind Kind, string Target, bool Passed, string Detail);

/// <summary>
/// Aggregate post-remediation verification result. It is "clean" ONLY when every
/// requested check passed — a single failing check yields an honest "not fully
/// removed" state with the remaining artifact described.
/// </summary>
public sealed record PostRebootVerificationResult
{
    public required IReadOnlyList<VerificationFinding> Findings { get; init; }

    public bool IsClean => Findings.Count > 0 && Findings.All(f => f.Passed);
    public bool HasRemainingArtifact => Findings.Any(f => !f.Passed);
    public IReadOnlyList<VerificationFinding> Failures => Findings.Where(f => !f.Passed).ToArray();
}

/// <summary>Probes used by verification. Abstracted so verification never touches
/// the real filesystem/registry/scanner in tests.</summary>
public interface IFileAbsenceProbe { bool IsAbsent(string path); }
public interface IPersistenceAbsenceProbe { bool IsGone(string identity); }
public interface IQuarantineValidityProbe { bool IsValid(string quarantineId); }
public interface IScanCleanProbe { bool IsClean(string target); }

/// <summary>
/// Runs targeted, conservative post-remediation checks and aggregates them. Cannot
/// report "clean" while any artifact remains: each probe failure becomes a visible
/// failing finding. It performs no remediation and no broad scan tuning.
/// </summary>
public sealed class RemediationVerificationService
{
    private readonly IFileAbsenceProbe _fileAbsence;
    private readonly IPersistenceAbsenceProbe _persistence;
    private readonly IQuarantineValidityProbe _quarantine;
    private readonly IScanCleanProbe _scan;

    public RemediationVerificationService(
        IFileAbsenceProbe fileAbsence,
        IPersistenceAbsenceProbe persistence,
        IQuarantineValidityProbe quarantine,
        IScanCleanProbe scan)
    {
        _fileAbsence = fileAbsence ?? throw new ArgumentNullException(nameof(fileAbsence));
        _persistence = persistence ?? throw new ArgumentNullException(nameof(persistence));
        _quarantine = quarantine ?? throw new ArgumentNullException(nameof(quarantine));
        _scan = scan ?? throw new ArgumentNullException(nameof(scan));
    }

    public PostRebootVerificationResult Verify(IReadOnlyList<VerificationCheck> checks)
    {
        if (checks is null) throw new ArgumentNullException(nameof(checks));

        var findings = new List<VerificationFinding>(checks.Count);
        foreach (var check in checks)
        {
            var (passed, detail) = check.Kind switch
            {
                VerificationCheckKind.FileAbsent =>
                    (_fileAbsence.IsAbsent(check.Target), "file should be absent"),
                VerificationCheckKind.PersistenceGone =>
                    (_persistence.IsGone(check.Target), "persistence should be gone"),
                VerificationCheckKind.QuarantineRecordValid =>
                    (_quarantine.IsValid(check.Target), "quarantine record should be valid"),
                VerificationCheckKind.ScanClean =>
                    (_scan.IsClean(check.Target), "targeted scan should be clean"),
                _ => (false, "unknown check kind"),
            };

            findings.Add(new VerificationFinding(
                check.Kind, check.Target, passed,
                passed ? $"OK: {detail}" : $"FAIL: {detail} — artifact remains"));
        }

        return new PostRebootVerificationResult { Findings = findings };
    }
}
