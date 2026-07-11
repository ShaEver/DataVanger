using System;
using System.Collections.Generic;

namespace DataVanger.SelfProtection;

/// <summary>
/// Tick-driven configuration integrity monitor.
///
/// Wraps an <see cref="Sha256IntegrityValidator"/> around a baseline
/// snapshot. Each call to <see cref="Verify"/> validates every path in
/// the snapshot and emits a <see cref="TamperEvent"/> for every
/// observed mismatch or missing file.
///
/// The monitor itself does not run any background work — the caller
/// decides when to verify. This keeps the development loop (build,
/// test, rebuild) free of long-running file watchers and avoids holding
/// any handles to monitored files.
/// </summary>
public sealed class ConfigurationIntegrityMonitor
{
    private readonly Sha256IntegrityValidator _validator;
    private readonly IntegritySnapshot _baseline;
    private readonly ITamperEventSink _sink;
    private readonly string _component;

    public ConfigurationIntegrityMonitor(
        IntegritySnapshot baseline,
        ITamperEventSink sink,
        Sha256IntegrityValidator? validator = null,
        string component = "configuration")
    {
        _baseline = baseline ?? IntegritySnapshot.Empty;
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        _validator = validator ?? new Sha256IntegrityValidator();
        _component = string.IsNullOrWhiteSpace(component) ? "configuration" : component;
    }

    /// <summary>
    /// Run one validation pass. Returns the raw result so callers can
    /// inspect/forward it further. Any mismatch/missing entry is also
    /// published to the configured tamper sink.
    /// </summary>
    public IntegrityValidationResult Verify(DateTime? nowUtc = null)
    {
        var result = _validator.Validate(_baseline);
        if (result.Mismatched.Count == 0 && result.Missing.Count == 0) return result;

        var stamp = nowUtc?.ToUniversalTime() ?? DateTime.UtcNow;
        foreach (var mismatch in result.Mismatched)
        {
            _sink.Publish(new TamperEvent(
                kind: TamperKind.ConfigurationModified,
                severity: TamperSeverity.Medium,
                component: _component,
                targetPath: mismatch.Path,
                description: $"Conteúdo divergiu da baseline (expected={Trim(mismatch.ExpectedHash)}, actual={Trim(mismatch.ActualHash)}).",
                timestampUtc: stamp));
        }
        foreach (var missing in result.Missing)
        {
            _sink.Publish(new TamperEvent(
                kind: TamperKind.ConfigurationMissing,
                severity: TamperSeverity.Medium,
                component: _component,
                targetPath: missing,
                description: "Arquivo monitorado não encontrado.",
                timestampUtc: stamp));
        }
        return result;
    }

    private static string Trim(string hash)
        => string.IsNullOrEmpty(hash) || hash.Length <= 12 ? hash : hash.Substring(0, 12) + "...";
}
