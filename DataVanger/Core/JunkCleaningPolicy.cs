using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace DataVanger.Core;

public sealed class JunkLocation
{
    public string Category { get; init; } = "";
    public string Path { get; init; } = "";
    public string Risk { get; init; } = "Baixo";
    public string Impact { get; init; } = "Seguro";
    public TimeSpan MinimumAge { get; init; } = TimeSpan.Zero;
    public bool IncludeExecutableInstallers { get; init; }
}

public sealed class JunkMeasure
{
    public long Bytes { get; set; }
    public int Count { get; set; }
    public DateTime? OldestLastWrite { get; set; }
    public DateTime? NewestLastWrite { get; set; }
    public bool HasFilesInUse { get; set; }
}

public static class JunkCleaningPolicy
{
    private static readonly HashSet<string> SafeExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".tmp", ".temp", ".log", ".bak", ".old", ".dmp", ".mdmp", ".etl", ".chk", ".gid" };

    private static readonly HashSet<string> ExecutableInstallers = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".msi", ".msix", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta" };

    public static IEnumerable<JunkLocation> GetDefaultLocations()
    {
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        yield return new() { Category = "Arquivos temporários do usuário", Path = Path.GetTempPath(), Risk = "Baixo", Impact = "Arquivos em uso são preservados", MinimumAge = TimeSpan.FromDays(7) };
        yield return new() { Category = "Windows Temp", Path = Path.Combine(windows, "Temp"), Risk = "Médio", Impact = "Pode exigir administrador; arquivos em uso são preservados", MinimumAge = TimeSpan.FromDays(7) };
        yield return new() { Category = "Logs antigos", Path = Path.Combine(user, "DataVanger", "Logs"), Risk = "Baixo", Impact = "Mantém logs recentes", MinimumAge = TimeSpan.FromDays(14) };
        yield return new() { Category = "Mini dumps", Path = Path.Combine(windows, "Minidump"), Risk = "Baixo", Impact = "Remove dumps antigos de falhas", MinimumAge = TimeSpan.FromDays(7) };
        yield return new() { Category = "Crash dumps", Path = Path.Combine(local, "CrashDumps"), Risk = "Baixo", Impact = "Remove dumps antigos de aplicativos", MinimumAge = TimeSpan.FromDays(7) };
        yield return new() { Category = "Shader cache", Path = Path.Combine(local, "D3DSCache"), Risk = "Baixo", Impact = "Cache gráfico será recriado", MinimumAge = TimeSpan.FromDays(7) };
        yield return new() { Category = "Thumbnails", Path = Path.Combine(local, "Microsoft", "Windows", "Explorer"), Risk = "Baixo", Impact = "Miniaturas serão recriadas", MinimumAge = TimeSpan.FromDays(7) };
        yield return new() { Category = "Windows Update cache", Path = Path.Combine(windows, "SoftwareDistribution", "Download"), Risk = "Médio", Impact = "Pode exigir novo download de updates pendentes", MinimumAge = TimeSpan.FromDays(14) };
        yield return new() { Category = "Cache de instaladores", Path = Path.Combine(local, "Package Cache"), Risk = "Revisar", Impact = "Pode afetar reparo/desinstalação de alguns apps", MinimumAge = TimeSpan.FromDays(30) };

        foreach (var browser in BrowserCacheLocations(local))
            yield return browser;
    }

    public static bool IsCriticalPath(string path)
    {
        try
        {
            var full = Path.GetFullPath(path).TrimEnd('\\').ToLowerInvariant();
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\').ToLowerInvariant();
            string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).TrimEnd('\\').ToLowerInvariant();
            string pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).TrimEnd('\\').ToLowerInvariant();
            string user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).TrimEnd('\\').ToLowerInvariant();

            return full == windows || full == pf || full == pf86 || full == user
                || full.EndsWith("\\system32") || full.Contains("\\system32\\")
                || full.EndsWith("\\syswow64") || full.Contains("\\syswow64\\")
                || full.EndsWith("\\winsxs") || full.Contains("\\winsxs\\")
                || full.StartsWith(pf + "\\") || full.StartsWith(pf86 + "\\");
        }
        catch { return true; }
    }

    /// <summary>
    /// Cheap, read-only cleanability gate: existence, critical/system/age/extension and
    /// cache/safe-extension checks. Does NOT open the file, so the measurement pass can size
    /// every candidate without taking an exclusive lock on each one. Whether the file can be
    /// deleted right now (not held by another process) is a separate, delete-time concern —
    /// see <see cref="IsDeletableNow"/>.
    /// </summary>
    public static bool IsCleanableCandidate(string path, JunkLocation location)
    {
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists || IsCriticalPath(fi.FullName)) return false;
            if ((fi.Attributes & FileAttributes.System) != 0) return false;
            if ((fi.Attributes & FileAttributes.Directory) != 0) return false;
            if (DateTime.Now - fi.LastWriteTime < location.MinimumAge) return false;
            if (ExecutableInstallers.Contains(fi.Extension) && !location.IncludeExecutableInstallers) return false;

            bool knownCache = IsKnownCachePath(fi.FullName);
            bool safeExt = SafeExtensions.Contains(fi.Extension);
            return knownCache || safeExt;
        }
        catch { return false; }
    }

    /// <summary>
    /// Delete-time lock test: true only if the file can be opened exclusively (i.e. it is not
    /// held open by another process). Done once, immediately before deletion, instead of on
    /// every file during the read-only measurement pass.
    /// </summary>
    public static bool IsDeletableNow(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            return true;
        }
        catch { return false; }
    }

    /// <summary>
    /// Backwards-compatible combined check (candidate gates + the lock test). Prefer
    /// <see cref="IsCleanableCandidate"/> for sizing and <see cref="IsDeletableNow"/> at
    /// delete time so the measurement pass never opens files exclusively.
    /// </summary>
    public static bool IsCleanableFile(string path, JunkLocation location, out bool inUse)
    {
        inUse = false;
        if (!IsCleanableCandidate(path, location)) return false;
        if (!IsDeletableNow(path)) { inUse = true; return false; }
        return true;
    }

    private static IEnumerable<JunkLocation> BrowserCacheLocations(string local)
    {
        yield return new() { Category = "Cache Chrome", Path = Path.Combine(local, "Google", "Chrome", "User Data", "Default", "Cache"), Risk = "Baixo", Impact = "Sites podem carregar um pouco mais devagar", MinimumAge = TimeSpan.FromDays(7) };
        yield return new() { Category = "Cache Edge", Path = Path.Combine(local, "Microsoft", "Edge", "User Data", "Default", "Cache"), Risk = "Baixo", Impact = "Sites podem carregar um pouco mais devagar", MinimumAge = TimeSpan.FromDays(7) };
        yield return new() { Category = "Cache Brave", Path = Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Cache"), Risk = "Baixo", Impact = "Sites podem carregar um pouco mais devagar", MinimumAge = TimeSpan.FromDays(7) };
        yield return new() { Category = "Cache Firefox", Path = Path.Combine(local, "Mozilla", "Firefox", "Profiles"), Risk = "Baixo", Impact = "Sites podem carregar um pouco mais devagar", MinimumAge = TimeSpan.FromDays(7) };
    }

    private static bool IsKnownCachePath(string path)
    {
        string full = path.ToLowerInvariant();
        return full.Contains("\\cache\\")
            || full.Contains("\\code cache\\")
            || full.Contains("\\gpucache\\")
            || full.Contains("\\d3dscache\\")
            || full.Contains("\\crashdumps\\")
            || full.Contains("\\minidump\\")
            || full.Contains("\\softwaredistribution\\download\\")
            || full.Contains("\\windows\\explorer\\thumbcache");
    }
}
