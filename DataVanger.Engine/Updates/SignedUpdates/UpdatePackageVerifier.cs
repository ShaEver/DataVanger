using System;
using System.Security.Cryptography;
using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// Validates fetched package content against its authenticated manifest entry.
/// Order of checks: relative-path safety → kind → size → SHA-256. Never loads,
/// parses-as-code, or executes package content.
/// </summary>
public sealed class UpdatePackageVerifier : IUpdatePackageVerifier
{
    public UpdatePackageValidationResult Validate(UpdatePackageEntry entry, byte[]? content, UpdatePolicy policy)
    {
        if (entry is null)
            return UpdatePackageValidationResult.Invalid(string.Empty, UpdateResultKind.PackageKindRejected, "Package entry is null.");
        if (policy is null)
            return UpdatePackageValidationResult.Invalid(entry.Id, UpdateResultKind.PackageKindRejected, "Policy is null.");

        var id = entry.Id ?? string.Empty;

        // 1. Relative-path safety (traversal / absolute / drive / UNC).
        if (!IsSafeRelativePath(entry.RelativePath))
            return UpdatePackageValidationResult.Invalid(id, UpdateResultKind.PackagePathRejected, $"Unsafe package relative path '{entry.RelativePath}'.");

        // 2. Recognized + allowed kind.
        if (!policy.IsKindAllowed(entry.Kind))
            return UpdatePackageValidationResult.Invalid(id, UpdateResultKind.PackageKindRejected, $"Package kind '{entry.Kind}' is unknown or not allowed.");

        // 3. Content presence.
        if (content is null)
            return UpdatePackageValidationResult.Invalid(id, UpdateResultKind.PackageMissing, "Package content is missing.");

        // 4. Size limits (declared and actual).
        if (entry.SizeBytes < 0)
            return UpdatePackageValidationResult.Invalid(id, UpdateResultKind.PackageOversized, "Declared package size is negative.");
        if (entry.SizeBytes > policy.MaxPackageSizeBytes)
            return UpdatePackageValidationResult.Invalid(id, UpdateResultKind.PackageOversized, "Declared package size exceeds the configured limit.");
        if (content.LongLength > policy.MaxPackageSizeBytes)
            return UpdatePackageValidationResult.Invalid(id, UpdateResultKind.PackageOversized, "Package content exceeds the configured size limit.");
        if (entry.SizeBytes > 0 && content.LongLength != entry.SizeBytes)
            return UpdatePackageValidationResult.Invalid(id, UpdateResultKind.PackageHashMismatch, "Package content size does not match the manifest entry.");

        // 5. SHA-256 match against the authenticated manifest entry.
        var actualSha256 = ComputeSha256Hex(content);
        if (string.IsNullOrWhiteSpace(entry.Sha256)
            || !string.Equals(actualSha256, entry.Sha256.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return UpdatePackageValidationResult.Invalid(id, UpdateResultKind.PackageHashMismatch, "Package SHA-256 does not match the manifest entry.");
        }

        return UpdatePackageValidationResult.Valid(id);
    }

    /// <summary>
    /// True only for a safe, contained, forward relative path. Rejects empty
    /// paths, "..", rooted/absolute paths, drive letters, and UNC prefixes.
    /// </summary>
    public static bool IsSafeRelativePath(string? relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath)) return false;

        var path = relativePath.Trim();

        // Drive letter (e.g. "C:..."), or any volume separator.
        if (path.IndexOf(':') >= 0) return false;

        // UNC / absolute-style prefixes.
        if (path.StartsWith("\\", StringComparison.Ordinal) || path.StartsWith("/", StringComparison.Ordinal))
            return false;
        if (path.StartsWith("\\\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal))
            return false;

        // Rooted per the runtime's own rules.
        if (System.IO.Path.IsPathRooted(path)) return false;

        // Normalize separators and inspect each segment for traversal.
        var normalized = path.Replace('\\', '/');
        foreach (var segment in normalized.Split('/'))
        {
            if (segment.Length == 0) continue; // tolerate doubled separators
            if (segment == "..") return false;
            if (segment == ".") return false;
        }

        return true;
    }

    public static string ComputeSha256Hex(byte[] content)
    {
        var hash = SHA256.HashData(content);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
