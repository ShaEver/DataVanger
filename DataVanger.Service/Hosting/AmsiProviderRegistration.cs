using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32;

namespace DataVanger.Service.Hosting;

/// <summary>
/// A single registry command to run (always <c>reg.exe</c> with an explicit
/// argument list — never a shell string). Exposed so the register / unregister
/// plans can be unit-tested without touching the registry or executing anything.
/// </summary>
public sealed record RegistryCommand(string FileName, IReadOnlyList<string> Arguments);

/// <summary>Injectable recovery-only registry boundary used by cleanup tests.</summary>
public interface IAmsiRegistrationRecoveryOperations
{
    bool IsSupportedPlatform { get; }
    bool IsElevated { get; }
    RecoveryOperationResult RemoveRegistration(string providerClsid);
}

/// <summary>
/// Explicit, reversible, operator-invoked COM registration for the native
/// DataVanger AMSI provider (<c>DataVanger.AmsiProvider.dll</c>).
///
/// Registering an AMSI provider makes <c>amsi.dll</c> load the native shim INTO
/// every third-party process that calls AMSI (PowerShell, wscript, Office, …).
/// That is a high-impact, system-wide change, so this type follows exactly the
/// same safety model as <see cref="WindowsServiceInstaller"/>:
///   - Nothing here runs during normal app launch — only via the explicit
///     <c>--register-amsi-provider</c> / <c>--unregister-amsi-provider</c> CLI
///     commands.
///   - Windows-only and administrator-gated (HKLM writes). There is NO silent
///     elevation; a non-elevated caller is told to re-run elevated and the
///     operation fails with a clear exit code.
///   - Uses <c>reg.exe</c> with a structured argument list and
///     <c>UseShellExecute=false</c> — no shell, no injection surface.
///   - Registration is separate from installing the service and never starts or
///     enables anything on its own. The service still only OBSERVES what the
///     provider forwards; it never blocks, quarantines, or decides.
///
/// This type changes operational lifecycle only. It does not alter detection,
/// realtime authorization, quarantine, or any verdict path.
/// </summary>
public static class AmsiProviderRegistration
{
    /// <summary>
    /// Stable CLSID for the native provider's COM class. MUST match the GUID the
    /// native <c>DataVanger.AmsiProvider.dll</c> implements and the value under
    /// <c>HKLM\SOFTWARE\Microsoft\AMSI\Providers</c>. Do not change without
    /// re-issuing the native DLL.
    /// </summary>
    public const string ProviderClsid = "{6D6D9F2E-3A7C-4C1E-9B3A-2F5D8E1A4C90}";

    public const string DisplayName = "DataVanger AMSI Provider";

    public const string ProviderDllName = "DataVanger.AmsiProvider.dll";

    // Registry roots. AMSI resolves the provider CLSID against the COM registry
    // in the bitness of the calling host; we register the 64-bit view here and
    // document 32-bit registration in docs/AMSI_PROVIDER.md.
    private const string ClsidRoot = @"HKLM\SOFTWARE\Classes\CLSID";
    private const string AmsiProvidersRoot = @"HKLM\SOFTWARE\Microsoft\AMSI\Providers";

    // Exit codes surfaced to the operator (mirrors WindowsServiceInstaller).
    public const int ExitOk = 0;
    public const int ExitUnsupportedPlatform = 3;
    public const int ExitNotElevated = 4;
    public const int ExitCommandFailed = 5;
    public const int ExitInvalidProviderPath = 6;
    public const int ExitSecureInstallerUnavailable = PrivilegedActivationGate.ExitSecureInstallerUnavailable;

    /// <summary>
    /// Resolves the native provider DLL path. Prefers an explicit override,
    /// otherwise looks for <see cref="ProviderDllName"/> next to the entry
    /// assembly. Returns the composed path even if it does not exist so the
    /// caller can validate and report a precise reason.
    /// </summary>
    public static string ResolveProviderDllPath(string? overridePath = null)
    {
        if (!string.IsNullOrWhiteSpace(overridePath))
        {
            try { return Path.GetFullPath(overridePath.Trim()); }
            catch (ArgumentException) { return overridePath.Trim(); }
            catch (NotSupportedException) { return overridePath.Trim(); }
            catch (PathTooLongException) { return overridePath.Trim(); }
        }

        var entryDll = Assembly.GetEntryAssembly()?.Location;
        var directory = string.IsNullOrEmpty(entryDll) ? null : Path.GetDirectoryName(entryDll);
        return string.IsNullOrEmpty(directory)
            ? ProviderDllName
            : Path.Combine(directory, ProviderDllName);
    }

    /// <summary>
    /// A COM provider must point at an absolute, existing DLL. Refuses a
    /// relative or PATH-resolved path (a hijack surface). Pure apart from the
    /// final existence probe; exposed for testing.
    /// </summary>
    public static bool TryValidateProviderDllPath(string? dllPath, out string reason)
    {
        if (string.IsNullOrWhiteSpace(dllPath))
        {
            reason = "Provider DLL path is empty.";
            return false;
        }

        if (!Path.IsPathFullyQualified(dllPath))
        {
            reason = $"Provider DLL path is not absolute: '{dllPath}'. " +
                     "Refusing to register a relative or PATH-resolved provider path.";
            return false;
        }

        if (!File.Exists(dllPath))
        {
            reason = $"Provider DLL not found: '{dllPath}'.";
            return false;
        }

        reason = "";
        return true;
    }

    /// <summary>
    /// The ordered set of <c>reg.exe</c> commands that register the COM class
    /// (InprocServer32 → native DLL, ThreadingModel=Both) and list the CLSID
    /// under the AMSI providers key. Pure and side-effect free.
    /// </summary>
    public static IReadOnlyList<RegistryCommand> BuildRegisterPlan(string clsid, string providerDllPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clsid);
        ArgumentException.ThrowIfNullOrWhiteSpace(providerDllPath);

        var clsidKey = $@"{ClsidRoot}\{clsid}";
        var inprocKey = $@"{clsidKey}\InprocServer32";
        var amsiKey = $@"{AmsiProvidersRoot}\{clsid}";

        return new[]
        {
            RegAdd(clsidKey, valueName: null, value: DisplayName),
            RegAdd(inprocKey, valueName: null, value: providerDllPath),
            RegAdd(inprocKey, valueName: "ThreadingModel", value: "Both"),
            RegAdd(amsiKey, valueName: null, value: DisplayName),
        };
    }

    /// <summary>
    /// The ordered set of <c>reg.exe</c> commands that remove the AMSI provider
    /// listing and the COM class. Pure and side-effect free.
    /// </summary>
    public static IReadOnlyList<RegistryCommand> BuildUnregisterPlan(string clsid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clsid);

        var clsidKey = $@"{ClsidRoot}\{clsid}";
        var amsiKey = $@"{AmsiProvidersRoot}\{clsid}";

        return new[]
        {
            RegDelete(amsiKey),
            RegDelete(clsidKey),
        };
    }

    /// <summary>
    /// Registers the native provider (explicit, admin-gated, Windows-only).
    /// Never starts anything. Returns a clear exit code on every failure path.
    /// </summary>
    public static int Register(TextWriter output, TextWriter error, string? providerDllPath = null)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        // P0 safety gate: fail before platform/elevation/path checks and before
        // any registry command can be built or executed.
        if (!PrivilegedActivationGate.SecureInstallerAvailable)
        {
            error.WriteLine(PrivilegedActivationGate.AmsiRegistrationMessage);
            return ExitSecureInstallerUnavailable;
        }

        if (!OperatingSystem.IsWindows())
        {
            error.WriteLine("--register-amsi-provider is supported only on Windows. Nothing was registered.");
            return ExitUnsupportedPlatform;
        }

        return RegisterWindows(output, error, providerDllPath);
    }

    /// <summary>
    /// Removes the native provider registration (explicit, admin-gated,
    /// Windows-only).
    /// </summary>
    public static int Unregister(TextWriter output, TextWriter error)
        => Unregister(output, error, new WindowsAmsiRegistrationRecoveryOperations());

    /// <summary>
    /// Testable recovery path. Removing an already absent registration is
    /// successful, while the administrator requirement remains fail-closed.
    /// </summary>
    public static int Unregister(
        TextWriter output,
        TextWriter error,
        IAmsiRegistrationRecoveryOperations operations)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(operations);

        if (!operations.IsSupportedPlatform)
        {
            error.WriteLine("--unregister-amsi-provider is supported only on Windows. Nothing to remove.");
            return ExitUnsupportedPlatform;
        }

        if (!operations.IsElevated)
        {
            error.WriteLine(
                "--unregister-amsi-provider requires administrator privileges (HKLM). " +
                "Re-run from an elevated prompt. (No silent elevation is performed.)");
            return ExitNotElevated;
        }

        var result = operations.RemoveRegistration(ProviderClsid);
        if (result == RecoveryOperationResult.Failed)
        {
            error.WriteLine("AMSI provider removal failed.");
            return ExitCommandFailed;
        }

        output.WriteLine(result == RecoveryOperationResult.NotFound
            ? $"AMSI provider '{DisplayName}' was already absent (CLSID {ProviderClsid})."
            : $"AMSI provider '{DisplayName}' unregistered (CLSID {ProviderClsid}).");
        return ExitOk;
    }

    [SupportedOSPlatform("windows")]
    private static int RegisterWindows(TextWriter output, TextWriter error, string? providerDllPath)
    {
        if (!IsElevated())
        {
            error.WriteLine(
                "--register-amsi-provider requires administrator privileges (HKLM). " +
                "Re-run from an elevated prompt. (No silent elevation is performed.)");
            return ExitNotElevated;
        }

        var dllPath = ResolveProviderDllPath(providerDllPath);
        if (!TryValidateProviderDllPath(dllPath, out var invalidReason))
        {
            error.WriteLine($"--register-amsi-provider aborted: {invalidReason} Nothing was registered.");
            return ExitInvalidProviderPath;
        }

        foreach (var command in BuildRegisterPlan(ProviderClsid, dllPath))
        {
            int code = RunCommand(command, output, error);
            if (code != 0)
            {
                error.WriteLine($"AMSI provider registration step failed (reg {command.Arguments[0]}) with exit code {code}.");
                return ExitCommandFailed;
            }
        }

        output.WriteLine(
            $"AMSI provider '{DisplayName}' registered (CLSID {ProviderClsid}).");
        output.WriteLine(
            "  It will be loaded by amsi.dll into processes that call AMSI. The service " +
            "only OBSERVES forwarded content; it never blocks or quarantines.");
        output.WriteLine(
            "  Note: this registers the 64-bit COM view. For 32-bit hosts, register a " +
            "32-bit provider DLL as well — see docs/AMSI_PROVIDER.md.");
        return ExitOk;
    }

    private static RegistryCommand RegAdd(string key, string? valueName, string value)
    {
        var args = new List<string> { "add", key };
        if (string.IsNullOrEmpty(valueName))
            args.Add("/ve");
        else
        {
            args.Add("/v");
            args.Add(valueName);
        }
        args.Add("/t");
        args.Add("REG_SZ");
        args.Add("/d");
        args.Add(value);
        args.Add("/f");
        args.Add("/reg:64");
        return new RegistryCommand("reg.exe", args);
    }

    private static RegistryCommand RegDelete(string key)
        => new("reg.exe", new[] { "delete", key, "/f", "/reg:64" });

    [SupportedOSPlatform("windows")]
    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    [SupportedOSPlatform("windows")]
    private static int RunCommand(RegistryCommand command, TextWriter output, TextWriter error)
    {
        var psi = new ProcessStartInfo
        {
            FileName = command.FileName,
            UseShellExecute = false, // no shell — no injection surface
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var argument in command.Arguments)
            psi.ArgumentList.Add(argument);

        using var process = Process.Start(psi);
        if (process is null)
        {
            error.WriteLine($"Failed to start '{command.FileName}'.");
            return -1;
        }

        string stdout = process.StandardOutput.ReadToEnd();
        string stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (!string.IsNullOrWhiteSpace(stdout)) output.WriteLine(stdout.Trim());
        if (!string.IsNullOrWhiteSpace(stderr)) error.WriteLine(stderr.Trim());
        return process.ExitCode;
    }

    private sealed class WindowsAmsiRegistrationRecoveryOperations : IAmsiRegistrationRecoveryOperations
    {
        public bool IsSupportedPlatform => OperatingSystem.IsWindows();
        public bool IsElevated
        {
            get
            {
                if (!OperatingSystem.IsWindows()) return false;
                return AmsiProviderRegistration.IsElevated();
            }
        }

        [SupportedOSPlatform("windows")]
        public RecoveryOperationResult RemoveRegistration(string providerClsid)
        {
            try
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                bool found = DeleteIfPresent(hklm, $@"SOFTWARE\Microsoft\AMSI\Providers\{providerClsid}");
                found |= DeleteIfPresent(hklm, $@"SOFTWARE\Classes\CLSID\{providerClsid}");
                return found ? RecoveryOperationResult.Success : RecoveryOperationResult.NotFound;
            }
            catch (UnauthorizedAccessException)
            {
                return RecoveryOperationResult.Failed;
            }
            catch (System.Security.SecurityException)
            {
                return RecoveryOperationResult.Failed;
            }
            catch (IOException)
            {
                return RecoveryOperationResult.Failed;
            }
        }

        [SupportedOSPlatform("windows")]
        private static bool DeleteIfPresent(RegistryKey hklm, string subKey)
        {
            using var existing = hklm.OpenSubKey(subKey, writable: false);
            if (existing is null) return false;
            hklm.DeleteSubKeyTree(subKey, throwOnMissingSubKey: false);
            return true;
        }
    }
}
