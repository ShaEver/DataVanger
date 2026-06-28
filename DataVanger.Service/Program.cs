using System;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Service.Configuration;
using DataVanger.Service.Hosting;
using DataVanger.Service.Runtime;
using DataVanger.Shared.Service;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace DataVanger.Service;

/// <summary>
/// Safe entry point for the DataVanger.Service host introduced in
/// Phase 2 Step 02 (Windows Service Host).
///
/// Supported command-line modes (all opt-in, none aggressive):
///   (default)         — print a short banner and exit. Safe for builds,
///                       tests, and accidental execution.
///   --console         — start the runtime in interactive console mode
///                       and stop on Ctrl-C / SIGTERM.
///   --status          — instantiate the runtime, print a status snapshot,
///                       and exit. No persistent loop.
///   --validate-config — load configuration with safe defaults and print
///                       the resulting warnings, then exit.
///   --service         — run as a Windows service host: the generic host hosts
///                       the runtime and maps SCM start/stop (or Ctrl-C when run
///                       interactively) to runtime start/stop. AddWindowsService
///                       only activates the service lifetime when launched by the
///                       SCM; otherwise it runs as a console host (graceful
///                       degradation). Running does NOT install anything.
///   --install         — register the Windows service (explicit, admin-gated,
///                       Windows-only). Never starts it. Never runs implicitly.
///   --uninstall       — stop (best-effort) and remove the Windows service
///                       (explicit, admin-gated, Windows-only).
///   --help / -h / -?  — print usage.
///
/// Development safety guarantees:
///   - install/uninstall happen ONLY via the explicit flags above, never on a
///     default/console/status launch, and never with silent elevation
///   - no background thread or timer unless --console / --service is explicitly used
///   - tests never reach this entry point and never spin up a host
/// </summary>
internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        try
        {
            var mode = ParseMode(args);

            switch (mode)
            {
                case CliMode.Help:
                    PrintUsage();
                    return 0;

                case CliMode.Install:
                    // Propagate any --config so the INSTALLED service loads it (e.g. to
                    // enable the opt-in ETW runtime-telemetry gate). No --config => the
                    // service runs with safe defaults (gate OFF).
                    return WindowsServiceInstaller.Install(Console.Out, Console.Error, ParseConfigPath(args));

                case CliMode.Uninstall:
                    return WindowsServiceInstaller.Uninstall(Console.Out, Console.Error);

                case CliMode.Default:
                    Console.WriteLine("DataVanger.Service host.");
                    Console.WriteLine("No resident runtime is started in default mode.");
                    Console.WriteLine("Use --help to list available modes.");
                    return 0;
            }

            var configPath = ParseConfigPath(args);
            var configLoad = ServiceConfigurationLoader.LoadFromFile(configPath);

            switch (mode)
            {

                case CliMode.ValidateConfig:
                    return RunValidateConfig(configLoad);

                case CliMode.Status:
                    return RunStatus(configLoad);

                case CliMode.Service:
                    return await RunServiceAsync(args, configLoad).ConfigureAwait(false);

                case CliMode.Console:
                    return await RunConsoleAsync(configLoad).ConfigureAwait(false);

                default:
                    return 2;
            }
        }
        catch (Exception ex)
        {
            // Defensive: never crash the host with an unhandled exception.
            // Surface the failure as an exit code + readable message.
            Console.Error.WriteLine($"DataVanger.Service: unhandled error: {ex.GetType().Name}: {ex.Message}");
            return 2;
        }
    }

    private enum CliMode
    {
        Default,
        Help,
        Console,
        Status,
        ValidateConfig,
        Service,
        Install,
        Uninstall,
    }

    private static CliMode ParseMode(string[] args)
    {
        if (args is null || args.Length == 0) return CliMode.Default;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--help":
                case "-h":
                case "-?":
                case "/?":
                    return CliMode.Help;
                case "--console":
                    return CliMode.Console;
                case "--status":
                    return CliMode.Status;
                case "--validate-config":
                    return CliMode.ValidateConfig;
                case "--service":
                    return CliMode.Service;
                case "--install":
                    return CliMode.Install;
                case "--uninstall":
                    return CliMode.Uninstall;
            }
        }
        return CliMode.Default;
    }

    private static string? ParseConfigPath(string[] args)
    {
        if (args is null) return null;
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == "--config") return args[i + 1];
        }
        return null;
    }

    private static int RunValidateConfig(ServiceConfigurationLoadResult load)
    {
        Console.WriteLine("DataVanger.Service: configuration validation");
        Console.WriteLine($"  loaded-from-source : {load.LoadedFromSource}");
        Console.WriteLine($"  service-enabled    : {load.Configuration.ServiceEnabled}");
        Console.WriteLine($"  force-dev-mode     : {load.Configuration.ForceDevelopmentMode}");
        Console.WriteLine($"  etw-runtime-telem  : {load.Configuration.EnableEtwRuntimeTelemetry}");
        Console.WriteLine($"  etw-command-line   : {load.Configuration.CaptureEtwCommandLine}");
        Console.WriteLine($"  etw-powershell     : {load.Configuration.CaptureEtwPowerShellSignals}");
        Console.WriteLine($"  memory-scan-pass   : {load.Configuration.EnableMemoryScanPass}");
        Console.WriteLine($"  warning-count      : {load.Warnings.Count}");
        for (int i = 0; i < load.Warnings.Count; i++)
        {
            Console.WriteLine($"  warning[{i}]: {load.Warnings[i]}");
        }
        return load.HasWarnings ? 1 : 0;
    }

    private static int RunStatus(ServiceConfigurationLoadResult load)
    {
        using var runtime = new DataVangerServiceRuntime(
            load.Configuration, DataVangerRuntimeMode.Development, load.Warnings);
        runtime.StartAsync(CancellationToken.None).GetAwaiter().GetResult();
        var snapshot = runtime.GetStatusSnapshot();
        PrintSnapshot(snapshot);
        runtime.StopAsync(CancellationToken.None).GetAwaiter().GetResult();
        return 0;
    }

    /// <summary>
    /// Runs as a Windows service host. The generic host owns the lifetime;
    /// <see cref="DataVangerServiceWorker"/> maps host start/stop onto the
    /// runtime's start/stop. <c>AddWindowsService</c> activates the Windows
    /// service lifetime ONLY when the process is launched by the Service Control
    /// Manager; when run interactively (or on non-Windows) it degrades to a
    /// console host that stops on Ctrl-C. This entry never installs anything.
    /// </summary>
    private static async Task<int> RunServiceAsync(string[] args, ServiceConfigurationLoadResult load)
    {
        // Registered as a singleton instance and disposed by the host on shutdown
        // (Dispose is idempotent). Service mode is requested; ForceDevelopmentMode
        // in config still overrides it inside the runtime.
        var runtime = new DataVangerServiceRuntime(
            load.Configuration, DataVangerRuntimeMode.Service, load.Warnings);

        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddWindowsService(options => options.ServiceName = WindowsServiceInstaller.ServiceName);
        builder.Services.AddSingleton<IDataVangerServiceRuntime>(runtime);
        builder.Services.AddHostedService<DataVangerServiceWorker>();

        using var host = builder.Build();
        await host.RunAsync().ConfigureAwait(false);
        return 0;
    }

    private static async Task<int> RunConsoleAsync(ServiceConfigurationLoadResult load)
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        using var runtime = new DataVangerServiceRuntime(
            load.Configuration,
            DataVangerRuntimeMode.Console,
            load.Warnings);

        await runtime.StartAsync(cts.Token).ConfigureAwait(false);
        PrintSnapshot(runtime.GetStatusSnapshot());
        Console.WriteLine("DataVanger.Service: console mode running. Press Ctrl-C to stop.");

        try
        {
            await Task.Delay(Timeout.Infinite, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown path.
        }

        await runtime.StopAsync(CancellationToken.None).ConfigureAwait(false);
        Console.WriteLine("DataVanger.Service: console mode stopped cleanly.");
        return 0;
    }

    private static void PrintSnapshot(DataVangerServiceStatus snapshot)
    {
        Console.WriteLine("DataVanger.Service: status snapshot");
        Console.WriteLine($"  state              : {snapshot.State}");
        Console.WriteLine($"  mode               : {snapshot.Mode}");
        Console.WriteLine($"  development-mode   : {snapshot.IsDevelopmentMode}");
        Console.WriteLine($"  started-at-utc     : {snapshot.StartedAtUtc?.ToString("o") ?? "<not started>"}");
        Console.WriteLine($"  last-updated-utc   : {snapshot.LastUpdatedUtc:o}");
        Console.WriteLine($"  has-active-protect : {snapshot.HasActiveProtection}");
        Console.WriteLine($"  warning-count      : {snapshot.Warnings.Count}");
        for (int i = 0; i < snapshot.Warnings.Count; i++)
        {
            Console.WriteLine($"  warning[{i}]: {snapshot.Warnings[i]}");
        }
        Console.WriteLine($"  modules ({snapshot.Modules.Count}):");
        for (int i = 0; i < snapshot.Modules.Count; i++)
        {
            var m = snapshot.Modules[i];
            Console.WriteLine($"    - {m.Name}: {m.Availability} (active-protection={m.IsActiveProtection})");
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine("DataVanger.Service host");
        Console.WriteLine("Usage: DataVanger.Service [mode] [--config <path>]");
        Console.WriteLine();
        Console.WriteLine("Modes:");
        Console.WriteLine("  (none)             Print banner and exit (safe default).");
        Console.WriteLine("  --console          Run runtime interactively; Ctrl-C stops cleanly.");
        Console.WriteLine("  --status           Start runtime, print a status snapshot, stop.");
        Console.WriteLine("  --validate-config  Load configuration and print warnings.");
        Console.WriteLine("  --service          Run as a Windows service host (no install side effects).");
        Console.WriteLine("  --install [--config <path>]  Register the Windows service (admin; Windows-only).");
        Console.WriteLine("  --uninstall        Stop and remove the Windows service (admin; Windows-only).");
        Console.WriteLine("  --help, -h, -?     Print this message.");
    }
}
