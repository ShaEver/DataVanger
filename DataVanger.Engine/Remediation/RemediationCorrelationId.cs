using System;

namespace DataVanger.Engine.Remediation;

/// <summary>
/// Correlates every step, journal record and result of a single remediation run.
/// An opaque, typed wrapper over a GUID so it cannot be confused with another
/// string identifier.
/// </summary>
public readonly record struct RemediationCorrelationId(Guid Value)
{
    public static RemediationCorrelationId New() => new(Guid.NewGuid());

    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("N");
}
