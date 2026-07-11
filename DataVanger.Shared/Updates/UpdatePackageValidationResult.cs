namespace DataVanger.Shared.Updates;

/// <summary>
/// Structured result of validating a single package's content (hash, size,
/// kind, and relative-path safety) against its authenticated manifest entry.
/// Never a malware verdict.
/// </summary>
public sealed class UpdatePackageValidationResult
{
    public bool IsValid { get; init; }

    public UpdateResultKind Kind { get; init; } = UpdateResultKind.None;

    public string PackageId { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;

    public static UpdatePackageValidationResult Valid(string packageId)
        => new() { IsValid = true, Kind = UpdateResultKind.Accepted, PackageId = packageId };

    public static UpdatePackageValidationResult Invalid(string packageId, UpdateResultKind kind, string message)
        => new() { IsValid = false, Kind = kind, PackageId = packageId, Message = message };
}
