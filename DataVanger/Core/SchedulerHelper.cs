using System;
using System.Diagnostics;
using System.IO;

namespace DataVanger.Core;

/// <summary>
/// Registers / removes a weekly Windows Scheduled Task using schtasks.exe.
/// No PowerShell dependency — schtasks.exe is native to Windows since XP.
/// </summary>
public static class SchedulerHelper
{
    public const string TaskName = "DataVanger_WeeklyScan";

    /// <summary>
    /// Registers a weekly scan task (Sunday 08:00) that launches this executable.
    /// Returns (success, message).
    /// </summary>
    public static (bool ok, string msg) Register(string exePath)
    {
        // /SC WEEKLY /D SUN /ST 08:00 — runs every Sunday at 08:00
        string args =
            $"/Create /F /TN \"{TaskName}\" " +
            $"/TR \"\\\"{exePath}\\\" --silent\" " +
            $"/SC WEEKLY /D SUN /ST 08:00 " +
            $"/RL LIMITED";

        return RunSchtasks(args);
    }


    /// <summary>
    /// Registers a one-time scan task at the selected date/time.
    /// The scan profile is passed to the CLI so scheduled scans can be Quick/Standard/Deep.
    /// </summary>
    public static (bool ok, string msg) RegisterOnce(string exePath, DateTime when, ScanProfile profile)
    {
        string sd = when.ToString("dd/MM/yyyy");
        string st = when.ToString("HH:mm");
        string profileArg = profile.ToString().ToLowerInvariant();

        string args =
            $"/Create /F /TN \"{TaskName}\" " +
            $"/TR \"\\\"{exePath}\\\" --silent --profile {profileArg}\" " +
            $"/SC ONCE /SD {sd} /ST {st} " +
            $"/RL LIMITED";

        return RunSchtasks(args);
    }

    /// <summary>
    /// Registers a weekly scan task at the selected day/time.
    /// dayOfWeek accepts schtasks abbreviations: MON,TUE,WED,THU,FRI,SAT,SUN.
    /// </summary>
    public static (bool ok, string msg) RegisterWeekly(string exePath, string dayOfWeek, TimeSpan time, ScanProfile profile)
    {
        string st = DateTime.Today.Add(time).ToString("HH:mm");
        string profileArg = profile.ToString().ToLowerInvariant();
        string day = string.IsNullOrWhiteSpace(dayOfWeek) ? "SUN" : dayOfWeek.Trim().ToUpperInvariant();

        string args =
            $"/Create /F /TN \"{TaskName}\" " +
            $"/TR \"\\\"{exePath}\\\" --silent --profile {profileArg}\" " +
            $"/SC WEEKLY /D {day} /ST {st} " +
            $"/RL LIMITED";

        return RunSchtasks(args);
    }

    public static (bool ok, string msg) RegisterRecurring(string exePath, string friendlyName, string schedule, DateTime when, string dayOfWeek, ScanProfile profile)
    {
        string taskName = MakeTaskName(friendlyName, profile, schedule);
        string profileArg = profile.ToString().ToLowerInvariant();
        string st = when.ToString("HH:mm");
        string sd = when.ToString("dd/MM/yyyy");
        string day = string.IsNullOrWhiteSpace(dayOfWeek) ? "SUN" : dayOfWeek.Trim().ToUpperInvariant();
        string sc = schedule.ToUpperInvariant();
        string trigger = sc switch
        {
            "DAILY" => $"/SC DAILY /ST {st}",
            "WEEKLY" => $"/SC WEEKLY /D {day} /ST {st}",
            "MONTHLY" => $"/SC MONTHLY /D {Math.Clamp(when.Day, 1, 28)} /ST {st}",
            "ONSTART" => "/SC ONSTART",
            "ONLOGON" => "/SC ONLOGON",
            "ONIDLE" => "/SC ONIDLE /I 10",
            _ => $"/SC ONCE /SD {sd} /ST {st}"
        };

        string args =
            $"/Create /F /TN \"{taskName}\" " +
            $"/TR \"\\\"{exePath}\\\" --silent --profile {profileArg} --report all\" " +
            $"{trigger} /RL LIMITED";

        return RunSchtasks(args);
    }

    public static (bool ok, string msg) Unregister(string taskName)
    {
        if (string.IsNullOrWhiteSpace(taskName)) taskName = TaskName;
        return RunSchtasks($"/Delete /F /TN \"{taskName}\"");
    }

    public static string MakeTaskName(string friendlyName, ScanProfile profile, string schedule)
    {
        string raw = string.IsNullOrWhiteSpace(friendlyName)
            ? $"DataVanger_{profile}_{schedule}"
            : friendlyName.Trim();
        raw = string.Concat(raw.Select(ch => char.IsLetterOrDigit(ch) || ch is '_' or '-' ? ch : '_'));
        return raw.StartsWith("DataVanger_", StringComparison.OrdinalIgnoreCase) ? raw : "DataVanger_" + raw;
    }

    /// <summary>Removes the scheduled task.</summary>
    public static (bool ok, string msg) Unregister()
    {
        return RunSchtasks($"/Delete /F /TN \"{TaskName}\"");
    }

    /// <summary>Returns true if the task already exists.</summary>
    public static bool Exists()
    {
        var (ok, _) = RunSchtasks($"/Query /TN \"{TaskName}\"");
        return ok;
    }

    private static (bool ok, string msg) RunSchtasks(string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName               = "schtasks.exe",
                Arguments              = arguments,
                UseShellExecute        = false,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                CreateNoWindow         = true,
            };
            using var proc = Process.Start(psi)!;
            string stdout = proc.StandardOutput.ReadToEnd();
            string stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit();
            bool ok  = proc.ExitCode == 0;
            string msg = ok ? stdout.Trim() : stderr.Trim();
            return (ok, msg);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }
}
