using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// Validates a single package's fetched content against its authenticated
/// manifest entry: relative-path safety, size limit, recognized/allowed kind,
/// and SHA-256 match. Never executes or loads package content.
/// </summary>
public interface IUpdatePackageVerifier
{
    UpdatePackageValidationResult Validate(UpdatePackageEntry entry, byte[]? content, UpdatePolicy policy);
}
