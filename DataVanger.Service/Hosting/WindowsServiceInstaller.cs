using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace DataVanger.Service.Hosting;

/// <summary>
/// A single service-control command to run (always <c>sc.exe</c> with an
/// explicit argument list — never a shell string). Exposed so the install /
/// uninstall / recovery plans can be unit-tested without executing anything.
/// </summary>
public sealed record ServiceControlCommand(string FileName, IReadOnlyList<string> Arguments);

/// <summary>
/// Explicit, reversible, operator-invoked Windows service registration for the
/// DataVanger service host.
///
/// Safety model:
///   - Nothing here runs during normal app launch — only via the explicit
///     <c>--install</c> / <c>--uninstall</c> CLI commands.
///   - Windows-only and administrator-gated. There is NO silent elevation; a
///     non-elevated caller is told to re-run from an elevated prompt and the
///     operation fails with a clear exit code.
///   - Uses <c>sc.exe</c> with a structured argument list and
///     <c>UseShellExecute=false</c> — no shell, no injection surface.
///   - The service is registered with <c>start= demand</c> (manual start). It
///     is never auto-started by installation.
///   - Recovery is restart-on-failure, configured only as part of install.
///
/// This type changes operational lifecycle only. It does not alter detection,
/// realtime authorization, quarantine, or any verdict path.
/// </summary>
public static class WindowsServiceInstaller
{
    public const string ServiceName = "DataVangerService";
    public const string DisplayName = "DataVanger Security Service";
    public const string Description =
        "DataVanger resident service host (on-demand scanning remains UI-driven). " +
        "Does not widen automatic actions.";

    // Exit codes surfaced to the operator.
    public const int ExitOk = 0;
    public const int ExitUnsupportedPlatform = 3;
    public const int ExitNotElevated = 4;
    public const int ExitCommandFailed = 5;
    public const int ExitInvalidServicePath = 6;

    /// <summary>
    /// Builds the command line stored as the service ImagePath. Prefers a real
    /// application-host executable next to the entry assembly so the Service
    /// Control Manager tracks and controls the actual service process directly;
    /// only falls back to the <c>dotnet</c> muxer form when no apphost is present.
    /// Returned as a single string because <c>sc create binPath=</c> takes one
    /// value that the SCM later re-parses with the standard command-line rules.
    /// </summary>
    public static string ResolveServiceBinPath(string? configPath = null)
    {
        var hostPath = Environment.ProcessPath;
        var entryDll = Assembly.GetEntryAssembly()?.Location;
        var appHost = ResolveAppHostPath(entryDll);
        return BuildBinPath(appHost, hostPath, entryDll, NormalizeConfigPath(configPath));
    }

    /// <summary>
    /// Pure binPath composition (no I/O), exposed for testing.
    ///
    /// Priority:
    ///   1. A real application-host executable — registered directly so the SCM
    ///      controls the service process itself. Running the service via the
    ///      shared <c>dotnet.exe</c> muxer is what made <c>sc stop</c> fail with
    ///      1061 ("cannot accept control messages"): the control handshake must
    ///      target the actual hosting process, not the muxer.
    ///   2. The dotnet muxer form (<c>dotnet &lt;dll&gt; --service</c>) when no
    ///      apphost exists (e.g. a stripped framework-dependent layout).
    ///   3. Whatever host launched the process, with <c>--service</c>.
    ///
    /// When <paramref name="configPath"/> is supplied, <c>--config "&lt;path&gt;"</c>
    /// is appended so the INSTALLED service loads that configuration (e.g. to
    /// turn on the opt-in ETW runtime-telemetry gate). Without it, the service
    /// runs with safe defaults (gate OFF) — preserving default-off behavior.
    /// </summary>
    public static string BuildBinPath(string? appHostPath, string? hostPath, string? entryDll, string? configPath = null)
        => AppendConfig(BuildCoreBinPath(appHostPath, hostPath, entryDll), configPath);

    private static string BuildCoreBinPath(string? appHostPath, string? hostPath, string? entryDll)
    {
        if (!string.IsNullOrEmpty(appHostPath))
            return $"{Quote(appHostPath!)} --service";

        bool launchedViaMuxer =
            !string.IsNullOrEmpty(hostPath)
            && !string.IsNullOrEmpty(entryDll)
            && IsDotnetMuxer(hostPath!)
            && !string.Equals(
                Path.GetFileNameWithoutExtension(hostPath),
                Path.GetFileNameWithoutExtension(entryDll),
                StringComparison.OrdinalIgnoreCase);

        if (launchedViaMuxer)
            return $"{Quote(hostPath!)} {Quote(entryDll!)} --service";

        if (!string.IsNullOrEmpty(hostPath))
            return $"{Quote(hostPath!)} --service";

        return entryDll is null ? "--service" : $"dotnet {Quote(entryDll)} --service";
    }

    private static string AppendConfig(string binPath, string? configPath)
        => string.IsNullOrWhiteSpace(configPath) ? binPath : $"{binPath} --config {Quote(configPath!)}";

    /// <summary>
    /// Normalizes a caller-supplied config path to an absolute path (the SCM
    /// starts the service with a System32 working directory, so a relative path
    /// would silently fail to load and the gate would stay off). Best-effort:
    /// returns the trimmed original if the path cannot be normalized.
    /// </summary>
    private static string? NormalizeConfigPath(string? configPath)
    {
        if (string.IsNullOrWhiteSpace(configPath)) return null;
        var trimmed = configPath.Trim();
        try { return Path.GetFullPath(trimmed); }
        catch (ArgumentException) { return trimmed; }
        catch (NotSupportedException) { return trimmed; }
        catch (PathTooLongException) { return trimmed; }
    }

    /// <summary>
    /// Returns the path to the application-host executable that sits next to the
    /// entry assembly (e.g. <c>DataVanger.Service.exe</c> beside
    /// <c>DataVanger.Service.dll</c>), or null when it does not exist. The
    /// apphost is produced when <c>UseAppHost=true</c>.
    /// </summary>
    public static string? ResolveAppHostPath(string? entryDll)
    {
        if (string.IsNullOrEmpty(entryDll)) return null;
        var directory = Path.GetDirectoryName(entryDll);
        if (string.IsNullOrEmpty(directory)) return null;

        var baseName = Path.GetFileNameWithoutExtension(entryDll);
        if (string.IsNullOrEmpty(baseName)) return null;

        var candidate = Path.Combine(
            directory,
            OperatingSystem.IsWindows() ? baseName + ".exe" : baseName);

        return File.Exists(candidate) ? candidate : null;
    }

    /// <summary>
    /// Extracts the executable component (first token) from a composed binPath:
    /// the quoted segment when the path is quoted, otherwise the first
    /// whitespace-delimited token. Pure; exposed for testing.
    /// </summary>
    public static string? ExtractBinPathExecutable(string? binPath)
    {
        if (string.IsNullOrWhiteSpace(binPath)) return null;
        var trimmed = binPath.TrimStart();

        if (trimmed.StartsWith('"'))
        {
            int closing = trimmed.IndexOf('"', 1);
            if (closing <= 1) return null;
            return trimmed.Substring(1, closing - 1);
        }

        int space = trimmed.IndexOf(' ');
        return space < 0 ? trimmed : trimmed[..space];
    }

    /// <summary>
    /// Phase 02A guard: a service registration must point at an absolute,
    /// existing executable. The SCM resolves relative paths against System32
    /// and a bare name (e.g. the PATH-resolved <c>dotnet</c> fallback) is a
    /// hijack surface — install ABORTS instead of registering a guessed path.
    /// Pure apart from the final existence probe; exposed for testing.
    /// </summary>
    public static bool TryValidateServiceBinPath(string? binPath, out string reason)
    {
        var executable = ExtractBinPathExecutable(binPath);
        if (string.IsNullOrWhiteSpace(executable))
        {
            reason = "Service binPath has no executable component.";
            return false;
        }

        if (!Path.IsPathFullyQualified(executable))
        {
            reason = $"Service executable path is not absolute: '{executable}'. " +
                     "Refusing to register a relative or PATH-resolved service path.";
            return false;
        }

        if (!File.Exists(executable))
        {
            reason = $"Service executable not found: '{executable}'.";
            return false;
        }

        reason = "";
        return true;
    }

    /// <summary>
    /// The ordered set of <c>sc.exe</c> commands that register the service and
    /// configure restart-on-failure recovery. Pure and side-effect free.
    /// </summary>
    public static IReadOnlyList<ServiceControlCommand> BuildInstallPlan(string binPath, string serviceName = ServiceName)
    {
        return new[]
        {
            new ServiceControlCommand("sc.exe", new[]
            {
                "create", serviceName,
                "binPath=", binPath,
                "start=", "demand",
                "DisplayName=", DisplayName,
            }),
            new ServiceControlCommand("sc.exe", new[]
            {
                "description", serviceName, Description,
            }),
            // Restart on the 1st/2nd/3rd failure (60s apart); reset the failure
            // counter after one day. Bounded, no infinite in-process loop.
            new ServiceControlCommand("sc.exe", new[]
            {
                "failure", serviceName,
                "reset=", "86400",
                "actions=", "restart/60000/restart/60000/restart/60000",
            }),
        };
    }

    /// <summary>
    /// The ordered set of <c>sc.exe</c> commands that stop (best-effort) and
    /// remove the service. Pure and side-effect free.
    /// </summary>
    public static IReadOnlyList<ServiceControlCommand> BuildUninstallPlan(string serviceName = ServiceName)
    {
        return new[]
        {
            new ServiceControlCommand("sc.exe", new[] { "stop", serviceName }),
            new ServiceControlCommand("sc.exe", new[] { "delete", serviceName }),
        };
    }

    /// <summary>
    /// Registers the service (explicit, admin-gated, Windows-only). Never starts
    /// the service. Returns a clear exit code on every failure path. When
    /// <paramref name="configPath"/> is supplied (from <c>--install --config &lt;path&gt;</c>),
    /// the registered service loads that configuration — e.g. to enable the
    /// opt-in ETW runtime-telemetry gate. Without it, the service runs with safe
    /// defaults (gate OFF).
    /// </summary>
    public static int Install(TextWriter output, TextWriter error, string? configPath = null)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        if (!OperatingSystem.IsWindows())
        {
            error.WriteLine("--install is supported only on Windows. No service was registered.");
            return ExitUnsupportedPlatform;
        }

        return InstallWindows(output, error, configPath);
    }

    /// <summary>
    /// Stops (best-effort) and removes the service (explicit, admin-gated,
    /// Windows-only).
    /// </summary>
    public static int Uninstall(TextWriter output, TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        if (!OperatingSystem.IsWindows())
        {
            error.WriteLine("--uninstall is supported only on Windows. Nothing to remove.");
            return ExitUnsupportedPlatform;
        }

        return UninstallWindows(output, error);
    }

    [SupportedOSPlatform("windows")]
    private static int InstallWindows(TextWriter output, TextWriter error, string? configPath)
    {
        if (!IsElevated())
        {
            error.WriteLine(
                "--install requires administrator privileges. Re-run from an elevated prompt. " +
                "(No silent elevation is performed.)");
            return ExitNotElevated;
        }

        var binPath = ResolveServiceBinPath(configPath);
        if (!TryValidateServiceBinPath(binPath, out var invalidReason))
        {
            error.WriteLine($"--install aborted: {invalidReason} No service was registered.");
            return ExitInvalidServicePath;
        }

        foreach (var command in BuildInstallPlan(binPath))
        {
            int code = RunCommand(command, output, error);
            if (code != 0)
            {
                error.WriteLine($"Service install step failed (sc {command.Arguments[0]}) with exit code {code}.");
                return ExitCommandFailed;
            }
        }

        output.WriteLine(
            $"Service '{ServiceName}' installed (start=demand, restart-on-failure recovery). " +
            "It was NOT started; start it explicitly via the Service Control Manager.");
        if (!string.IsNullOrWhiteSpace(configPath))
        {
            output.WriteLine($"  config: the service will load '{NormalizeConfigPath(configPath)}' on start.");
        }
        return ExitOk;
    }

    [SupportedOSPlatform("windows")]
    private static int UninstallWindows(TextWriter output, TextWriter error)
    {
        if (!IsElevated())
        {
            error.WriteLine(
                "--uninstall requires administrator privileges. Re-run from an elevated prompt. " +
                "(No silent elevation is performed.)");
            return ExitNotElevated;
        }

        var plan = BuildUninstallPlan();
        // Stop is best-effort: a not-running service is not an error.
        _ = RunCommand(plan[0], output, error);

        int deleteCode = RunCommand(plan[1], output, error);
        if (deleteCode != 0)
        {
            error.WriteLine($"Service removal failed (sc delete) with exit code {deleteCode}.");
            return ExitCommandFailed;
        }

        output.WriteLine($"Service '{ServiceName}' removed.");
        return ExitOk;
    }

    [SupportedOSPlatform("windows")]
    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    [SupportedOSPlatform("windows")]
    private static int RunCommand(ServiceControlCommand command, TextWriter output, TextWriter error)
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

    private static bool IsDotnetMuxer(string hostPath)
    {
        var name = Path.GetFileNameWithoutExtension(hostPath);
        return string.Equals(name, "dotnet", StringComparison.OrdinalIgnoreCase);
    }

    private static string Quote(string value) => $"\"{value}\"";
}
