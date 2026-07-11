using System;
using System.IO;

namespace DataVanger.Service.Hosting;

/// <summary>
/// Fail-closed release gate for system-wide activation. Reopening this gate is
/// intentionally a source change that must accompany a reviewed secure
/// installer; runtime configuration cannot weaken it.
/// </summary>
public static class PrivilegedActivationGate
{
    public static bool SecureInstallerAvailable => false;
    public const int ExitSecureInstallerUnavailable = 7;

    public const string ServiceInstallMessage =
        "--install is unavailable until a secure installer is implemented and reviewed. " +
        "No service was registered, copied, elevated, or started.";

    public const string AmsiRegistrationMessage =
        "--register-amsi-provider is unavailable until a secure installer and signed native build are implemented and reviewed. " +
        "No provider was registered, copied, elevated, or loaded.";
}

public enum InstallationArtifactKind
{
    ServiceExecutable,
    AmsiProviderDll,
    Configuration,
}

/// <summary>
/// Environment-dependent facts used by the future installer policy. Production
/// probes are deliberately not supplied in this P0: having the policy does not
/// imply that installation is safe or enabled.
/// </summary>
public interface IInstallationSecurityProbes
{
    bool FileExists(string path);
    bool IsProtectedInstallationRoot(string rootPath);
    bool HasReparsePoint(string path);
    bool IsWritableByUnprivilegedUsers(string path);
    bool HasExpectedSignature(string path, string expectedPublisher, string expectedThumbprint);
}

/// <summary>
/// Pure, fail-closed policy contract for a future secure installer. All security
/// facts are injected so adversarial cases can be tested without touching ACLs,
/// Authenticode, HKLM, or the Service Control Manager.
/// </summary>
public sealed class PrivilegedInstallationSecurityPolicy
{
    private readonly string _installationRoot;
    private readonly string _rootWithSeparator;
    private readonly string _expectedPublisher;
    private readonly string _expectedThumbprint;
    private readonly IInstallationSecurityProbes _probes;

    public PrivilegedInstallationSecurityPolicy(
        string installationRoot,
        string expectedPublisher,
        string expectedThumbprint,
        IInstallationSecurityProbes probes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(installationRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedPublisher);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedThumbprint);
        ArgumentNullException.ThrowIfNull(probes);

        if (!Path.IsPathFullyQualified(installationRoot) || IsUnc(installationRoot) || ContainsTraversal(installationRoot))
            throw new ArgumentException("Installation root must be an absolute local path without traversal.", nameof(installationRoot));

        _installationRoot = TrimEndingSeparators(Path.GetFullPath(installationRoot));
        _rootWithSeparator = _installationRoot + Path.DirectorySeparatorChar;
        _expectedPublisher = expectedPublisher;
        _expectedThumbprint = NormalizeThumbprint(expectedThumbprint);
        _probes = probes;
    }

    public bool TryValidate(string? path, InstallationArtifactKind kind, out string reason)
    {
        if (string.IsNullOrWhiteSpace(path))
            return Reject("Path is empty.", out reason);

        string candidate = path.Trim();
        if (!Path.IsPathFullyQualified(candidate))
            return Reject("Path must be absolute.", out reason);
        if (IsUnc(candidate))
            return Reject("UNC paths are not allowed.", out reason);
        if (ContainsTraversal(candidate))
            return Reject("Path traversal is not allowed.", out reason);
        if (ContainsAlternateDataStream(candidate))
            return Reject("Alternate data stream paths are not allowed.", out reason);

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(candidate);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return Reject("Path is invalid.", out reason);
        }

        if (!fullPath.StartsWith(_rootWithSeparator, StringComparison.OrdinalIgnoreCase))
            return Reject("Path is outside the configured protected installation root.", out reason);
        if (!_probes.IsProtectedInstallationRoot(_installationRoot))
            return Reject("Configured installation root is not protected.", out reason);
        if (!_probes.FileExists(fullPath))
            return Reject("File does not exist.", out reason);
        if (_probes.HasReparsePoint(_installationRoot) || _probes.HasReparsePoint(fullPath))
            return Reject("Installation root or artifact contains a reparse point.", out reason);
        if (_probes.IsWritableByUnprivilegedUsers(_installationRoot) || _probes.IsWritableByUnprivilegedUsers(fullPath))
            return Reject("Installation root or artifact is writable by an unprivileged user.", out reason);

        if (kind != InstallationArtifactKind.Configuration &&
            !_probes.HasExpectedSignature(fullPath, _expectedPublisher, _expectedThumbprint))
        {
            return Reject("Artifact signature, publisher, or thumbprint is not trusted.", out reason);
        }

        reason = "";
        return true;
    }

    private static bool Reject(string value, out string reason)
    {
        reason = value;
        return false;
    }

    private static bool IsUnc(string path) => path.StartsWith("\\\\", StringComparison.Ordinal);

    private static bool ContainsTraversal(string path)
    {
        var segments = path.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
        return Array.Exists(segments, segment => segment == "..");
    }

    private static bool ContainsAlternateDataStream(string path)
    {
        int colon = path.IndexOf(':');
        if (colon < 0) return false;
        int allowedDriveColon = path.Length >= 2 && char.IsLetter(path[0]) && path[1] == ':' ? 1 : -1;
        return colon != allowedDriveColon || path.IndexOf(':', colon + 1) >= 0;
    }

    private static string TrimEndingSeparators(string path)
        => path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    private static string NormalizeThumbprint(string thumbprint)
        => thumbprint.Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();
}
