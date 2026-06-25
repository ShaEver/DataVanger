using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Core.Abstractions;
using Microsoft.Win32;

namespace DataVanger.Engine;

/// <summary>
/// Concrete <see cref="IPersistenceCollector"/> that reads Windows Run keys,
/// services, scheduled tasks, startup folders and WMI persistence in one
/// pass. Each input source is best-effort — failures are swallowed so a
/// missing registry key never aborts the scan.
/// </summary>
public sealed class PersistenceCollector : IPersistenceCollector
{
    public Task<IReadOnlyCollection<string>> CollectAsync(CancellationToken cancellationToken)
        => Task.Run(() => (IReadOnlyCollection<string>)Collect(), cancellationToken);

    public static HashSet<string> Collect()
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var startups = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Start Menu\Programs\Startup"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\Start Menu\Programs\Startup"),
        };
        foreach (var sf in startups)
        {
            try
            {
                if (Directory.Exists(sf))
                    foreach (var f in Directory.EnumerateFiles(sf))
                        paths.Add(f.ToLowerInvariant());
            }
            catch (UnauthorizedAccessException)
            {
                // Protected startup folder - skip and continue.
            }
            catch (IOException)
            {
                // Unreadable startup folder - skip and continue.
            }
        }

        foreach (var rk in new[]
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            @"Software\Microsoft\Windows NT\CurrentVersion\Windows"
        })
            ReadRegValues(Registry.CurrentUser, rk, paths);

        foreach (var rk in new[]
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            @"Software\Microsoft\Windows NT\CurrentVersion\Windows",
            @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            @"System\CurrentControlSet\Services"
        })
            ReadRegValues(Registry.LocalMachine, rk, paths);

        AddCommandOutput(paths, "schtasks.exe", "/query /fo csv /v", "schtasks");
        AddCommandOutput(paths, "sc.exe", "query state= all", "services");
        AddCommandOutput(paths, "powershell.exe",
            "-NoProfile -ExecutionPolicy Bypass -Command \"Get-CimInstance -Namespace root/subscription -Class __EventFilter,__EventConsumer, __FilterToConsumerBinding -ErrorAction SilentlyContinue | Out-String -Width 500\"",
            "wmi");
        return paths;
    }

    public static string? ExtractPath(string entry)
    {
        if (string.IsNullOrWhiteSpace(entry)) return null;
        try { entry = Environment.ExpandEnvironmentVariables(entry); }
        catch (Exception)
        {
            // Best-effort environment expansion - keep the original entry on failure.
        }
        var quoted = Regex.Match(entry, @"""([^""]+\.(exe|dll|scr|com|bat|cmd|vbs|js|jse|wsf|ps1|psm1|msi|lnk|hta|sys))""", RegexOptions.IgnoreCase);
        if (quoted.Success) return quoted.Groups[1].Value.ToLowerInvariant();
        var bare = Regex.Match(entry, @"([a-zA-Z]:\\[^\s""]+\.(exe|dll|scr|com|bat|cmd|vbs|js|jse|wsf|ps1|psm1|msi|lnk|hta|sys))", RegexOptions.IgnoreCase);
        if (bare.Success) return bare.Groups[1].Value.ToLowerInvariant();
        return null;
    }

    private static void AddCommandOutput(HashSet<string> target, string fileName, string arguments, string prefix)
    {
        try
        {
            var psi = new ProcessStartInfo(fileName, arguments)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return;
            if (!p.WaitForExit(2500)) { try { p.Kill(); } catch (Exception) { /* Kill may throw Win32Exception/InvalidOperationException if the process already exited - ignore. */ } return; }
            var output = p.StandardOutput.ReadToEnd();
            if (!string.IsNullOrWhiteSpace(output)) target.Add($"[{prefix}] {output}".ToLowerInvariant());
        }
        catch (Exception)
        {
            // Helper tool missing or process inspection failed (Win32Exception/InvalidOperationException etc.) - skip this source.
        }
    }

    private static void ReadRegValues(RegistryKey hive, string subKey, HashSet<string> target)
    {
        try
        {
            using var key = hive.OpenSubKey(subKey);
            if (key == null) return;
            foreach (var name in key.GetValueNames())
                if (key.GetValue(name) is string val) target.Add(val.ToLowerInvariant());
        }
        catch (Exception)
        {
            // Registry hive/key inaccessible (SecurityException/UnauthorizedAccessException/IOException) - skip this key.
        }
    }
}
