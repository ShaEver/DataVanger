using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// Thrown when a manifest cannot be turned into a canonical payload safely
/// (null required field, or a field that would make the encoding ambiguous).
/// The verifier maps this to <see cref="UpdateResultKind.CanonicalizationFailed"/>.
/// </summary>
public sealed class CanonicalizationException : Exception
{
    public CanonicalizationException(string message) : base(message) { }
}

/// <summary>
/// Produces the deterministic byte sequence that is signed/verified for an
/// <see cref="UpdateManifest"/>.
///
/// DESIGN — explicit, fixed field ordering (NOT derived from JSON serializer
/// reflection order). The canonical text is line-oriented (LF only) and starts
/// with a fixed version header. Every field is emitted in a hard-coded order:
///
///   line 0 : DATAVANGER-UPDATE-CANONICAL-V1
///   line 1 : schemaVersion=&lt;int&gt;
///   line 2 : feedId=&lt;string&gt;
///   line 3 : sequence=&lt;long&gt;
///   line 4 : publishedUtc=&lt;string&gt;
///   line 5 : minimumSupportedClientVersion=&lt;string&gt;
///   line 6 : packages=&lt;count&gt;
///   line 7+: package=&lt;id&gt;|&lt;kind&gt;|&lt;version&gt;|&lt;sha256&gt;|&lt;sizeBytes&gt;|&lt;relativePath&gt;|&lt;required&gt;
///
/// Within a package line the fields appear in this exact order:
///   id | kind | version | sha256 | sizeBytes | relativePath | required
///
/// - The signature envelope is deliberately EXCLUDED (the signature covers the
///   payload, not itself).
/// - Integers use invariant-culture decimal formatting; <c>kind</c> uses the
///   enum NAME; <c>required</c> is "true"/"false".
/// - To keep the encoding unambiguous WITHOUT escaping, the separators '\n' and
///   '|' are FORBIDDEN inside any string field. A field containing one throws
///   <see cref="CanonicalizationException"/>. This keeps the bytes stable across
///   serializer versions while staying simple and independently testable.
/// - Output is UTF-8 with NO byte-order mark.
/// </summary>
public static class UpdateCanonicalPayloadBuilder
{
    public const string Header = "DATAVANGER-UPDATE-CANONICAL-V1";
    private const char FieldSeparator = '|';
    private const char LineSeparator = '\n';

    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    /// <summary>Builds the canonical payload string for a manifest.</summary>
    public static string BuildString(UpdateManifest manifest)
    {
        if (manifest is null) throw new CanonicalizationException("Manifest is null.");

        var sb = new StringBuilder(256);
        sb.Append(Header).Append(LineSeparator);
        sb.Append("schemaVersion=").Append(manifest.SchemaVersion.ToString(CultureInfo.InvariantCulture)).Append(LineSeparator);
        sb.Append("feedId=").Append(Field(manifest.FeedId, nameof(manifest.FeedId))).Append(LineSeparator);
        sb.Append("sequence=").Append(manifest.Sequence.ToString(CultureInfo.InvariantCulture)).Append(LineSeparator);
        sb.Append("publishedUtc=").Append(Field(manifest.PublishedUtc, nameof(manifest.PublishedUtc))).Append(LineSeparator);
        sb.Append("minimumSupportedClientVersion=")
          .Append(Field(manifest.MinimumSupportedClientVersion, nameof(manifest.MinimumSupportedClientVersion)))
          .Append(LineSeparator);

        var packages = manifest.Packages ?? throw new CanonicalizationException("Packages collection is null.");
        sb.Append("packages=").Append(packages.Count.ToString(CultureInfo.InvariantCulture)).Append(LineSeparator);

        foreach (var package in packages)
        {
            if (package is null) throw new CanonicalizationException("Package entry is null.");
            sb.Append("package=")
              .Append(Field(package.Id, nameof(package.Id))).Append(FieldSeparator)
              .Append(package.Kind.ToString()).Append(FieldSeparator)
              .Append(Field(package.Version, nameof(package.Version))).Append(FieldSeparator)
              .Append(Field(package.Sha256, nameof(package.Sha256))).Append(FieldSeparator)
              .Append(package.SizeBytes.ToString(CultureInfo.InvariantCulture)).Append(FieldSeparator)
              .Append(Field(package.RelativePath, nameof(package.RelativePath))).Append(FieldSeparator)
              .Append(package.Required ? "true" : "false")
              .Append(LineSeparator);
        }

        return sb.ToString();
    }

    /// <summary>Builds the canonical payload bytes (UTF-8, no BOM).</summary>
    public static byte[] Build(UpdateManifest manifest)
        => Utf8NoBom.GetBytes(BuildString(manifest));

    /// <summary>Lower-case hex SHA-256 of the canonical payload.</summary>
    public static string ComputeCanonicalSha256(UpdateManifest manifest)
    {
        var bytes = Build(manifest);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string Field(string? value, string fieldName)
    {
        if (value is null)
            throw new CanonicalizationException($"Field '{fieldName}' is null.");
        if (value.IndexOf(FieldSeparator) >= 0 || value.IndexOf(LineSeparator) >= 0 || value.IndexOf('\r') >= 0)
            throw new CanonicalizationException($"Field '{fieldName}' contains a reserved separator character.");
        return value;
    }
}
