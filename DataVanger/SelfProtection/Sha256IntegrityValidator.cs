using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace DataVanger.SelfProtection;

/// <summary>
/// SHA256-based integrity validator.
///
/// Compares the current SHA256 of each path listed in an
/// <see cref="IntegritySnapshot"/> against the expected value. The
/// validator NEVER throws — all I/O exceptions are converted into an
/// <see cref="IntegrityFailure"/> entry so callers can decide whether
/// to emit a tamper event.
///
/// The validator is purely functional and stateless; it does not retain
/// computed hashes, does not write to disk and is safe to call multiple
/// times from any thread.
/// </summary>
public sealed class Sha256IntegrityValidator
{
    /// <summary>
    /// Optional override used by tests to inject content for paths that
    /// don't exist on disk. When supplied and the path is found in the
    /// override map, the validator hashes the in-memory bytes instead of
    /// opening the file.
    /// </summary>
    private readonly Func<string, byte[]?>? _readOverride;

    public Sha256IntegrityValidator(Func<string, byte[]?>? readOverride = null)
    {
        _readOverride = readOverride;
    }

    public IntegrityValidationResult Validate(IntegritySnapshot snapshot)
    {
        if (snapshot is null || snapshot.Count == 0) return IntegrityValidationResult.Empty;

        var matched = new List<string>();
        var mismatched = new List<IntegrityMismatch>();
        var missing = new List<string>();
        var failures = new List<IntegrityFailure>();

        foreach (var path in snapshot.Paths)
        {
            if (!snapshot.TryGetHash(path, out var expected)) continue;

            byte[]? bytes = TryReadBytes(path, out var failureReason);
            if (bytes is null)
            {
                if (failureReason == "missing") missing.Add(path);
                else failures.Add(new IntegrityFailure(path, failureReason ?? "unknown"));
                continue;
            }

            string actual;
            try { actual = Convert.ToHexString(SHA256.HashData(bytes)); }
            catch (Exception ex)
            {
                failures.Add(new IntegrityFailure(path, $"hash: {ex.GetType().Name}"));
                continue;
            }

            if (string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
                matched.Add(path);
            else
                mismatched.Add(new IntegrityMismatch(path, expected, actual));
        }

        return new IntegrityValidationResult(matched, mismatched, missing, failures);
    }

    /// <summary>
    /// Compute the SHA256 of a path on disk (or via the in-memory
    /// override). Returns <c>null</c> on failure; callers typically use
    /// this to build a baseline snapshot.
    /// </summary>
    public string? ComputeSha256(string path)
    {
        var bytes = TryReadBytes(path, out _);
        if (bytes is null) return null;
        try { return Convert.ToHexString(SHA256.HashData(bytes)); }
        catch (System.Exception) { return null; }
    }

    private byte[]? TryReadBytes(string path, out string? failureReason)
    {
        failureReason = null;
        if (string.IsNullOrWhiteSpace(path)) { failureReason = "empty-path"; return null; }
        if (_readOverride is not null)
        {
            try
            {
                var injected = _readOverride(path);
                if (injected is not null) return injected;
            }
            catch (Exception ex)
            {
                failureReason = $"override: {ex.GetType().Name}";
                return null;
            }
        }
        try
        {
            if (!File.Exists(path)) { failureReason = "missing"; return null; }
            return File.ReadAllBytes(path);
        }
        catch (FileNotFoundException) { failureReason = "missing"; return null; }
        catch (DirectoryNotFoundException) { failureReason = "missing"; return null; }
        catch (UnauthorizedAccessException) { failureReason = "access-denied"; return null; }
        catch (IOException ex) { failureReason = $"io: {ex.GetType().Name}"; return null; }
        catch (Exception ex) { failureReason = ex.GetType().Name; return null; }
    }
}
