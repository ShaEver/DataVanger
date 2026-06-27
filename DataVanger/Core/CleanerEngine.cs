using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Core;

public sealed class CleanerEngine
{
    // Keep only the most recent pre-delete backup sets; older ones are pruned on each clean
    // so the CleanerBackup folder cannot grow without bound and become junk itself.
    private const int MaxRetainedBackups = 5;

    public Task<List<CleanerItem>> AnalyzeAsync(CancellationToken ct = default) =>
        Task.Run(() => Analyze(ct), ct);

    public Task<CleanerResult> CleanAsync(IEnumerable<CleanerItem> items, bool createBackup, CancellationToken ct = default) =>
        Task.Run(() => Clean(items, createBackup, ct), ct);

    private static List<CleanerItem> Analyze(CancellationToken ct)
    {
        var result = new List<CleanerItem>();
        foreach (var location in JunkCleaningPolicy.GetDefaultLocations())
        {
            ct.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(location.Path) || !Directory.Exists(location.Path)) continue;

            var measure = Measure(location, ct);
            result.Add(new CleanerItem
            {
                Category = location.Category,
                Path = location.Path,
                Bytes = measure.Bytes,
                FileCount = measure.Count,
                Risk = location.Risk,
                Impact = measure.HasFilesInUse ? location.Impact + "; há arquivos em uso que serão ignorados" : location.Impact,
                OldestLastWrite = measure.OldestLastWrite,
                NewestLastWrite = measure.NewestLastWrite,
                HasFilesInUse = measure.HasFilesInUse,
                Selected = measure.Bytes > 0 && !location.Risk.Equals("Revisar", StringComparison.OrdinalIgnoreCase)
            });
        }

        return result
            .OrderByDescending(x => x.Bytes)
            .ThenBy(x => x.Category, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static CleanerResult Clean(IEnumerable<CleanerItem> items, bool createBackup, CancellationToken ct)
    {
        var res = new CleanerResult();
        string? backupRoot = null;
        if (createBackup)
        {
            string backupParent = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "DataVanger", "CleanerBackup");
            backupRoot = Path.Combine(backupParent, DateTime.Now.ToString("yyyyMMdd_HHmmss"));
            Directory.CreateDirectory(backupRoot);
            // Retention: the pre-delete backups are themselves disposable — keep only the most
            // recent few so CleanerBackup does not grow without bound and become junk itself.
            PruneOldBackups(backupParent, MaxRetainedBackups);
        }

        foreach (var item in items.Where(i => i.Selected))
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(item.Path) || JunkCleaningPolicy.IsCriticalPath(item.Path))
            {
                res.Messages.Add($"Ignorado por segurança: {item.Path}");
                continue;
            }

            var location = JunkCleaningPolicy.GetDefaultLocations()
                .FirstOrDefault(x => x.Path.Equals(item.Path, StringComparison.OrdinalIgnoreCase))
                ?? new JunkLocation { Category = item.Category, Path = item.Path, Risk = item.Risk, Impact = item.Impact, MinimumAge = TimeSpan.FromDays(30) };

            foreach (var file in EnumerateFilesSafe(item.Path, ct))
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    if (!JunkCleaningPolicy.IsCleanableFile(file, location, out _))
                    {
                        res.SkippedFiles++;
                        continue;
                    }

                    if (backupRoot != null)
                        TryBackup(file, item.Path, Path.Combine(backupRoot, SanitizeFileName(item.Category)));

                    long len = 0;
                    try { len = new FileInfo(file).Length; }
                    catch (UnauthorizedAccessException) { /* Protected file - length unknown, keep 0. */ }
                    catch (IOException) { /* Locked/unreadable file - length unknown, keep 0. */ }
                    File.Delete(file);
                    res.DeletedFiles++;
                    res.DeletedBytes += len;
                }
                catch (System.Exception)
                {
                    res.SkippedFiles++;
                }
            }

            DeleteEmptyDirectories(item.Path, ct);
        }

        if (backupRoot != null)
            res.Messages.Add($"Backup temporário criado em: {backupRoot}");

        return res;
    }

    private static JunkMeasure Measure(JunkLocation location, CancellationToken ct)
    {
        var result = new JunkMeasure();
        foreach (var file in EnumerateFilesSafe(location.Path, ct))
        {
            try
            {
                var fi = new FileInfo(file);
                // Measurement is read-only: use the cheap candidate gate (no exclusive open).
                // The lock test happens once at delete time in Clean(), not per file here.
                if (JunkCleaningPolicy.IsCleanableCandidate(file, location))
                {
                    result.Bytes += fi.Length;
                    result.Count++;
                    result.OldestLastWrite = result.OldestLastWrite == null || fi.LastWriteTime < result.OldestLastWrite ? fi.LastWriteTime : result.OldestLastWrite;
                    result.NewestLastWrite = result.NewestLastWrite == null || fi.LastWriteTime > result.NewestLastWrite ? fi.LastWriteTime : result.NewestLastWrite;
                }
            }
            catch (UnauthorizedAccessException)
            {
                // Protected file - skip from measure and preserve flow.
            }
            catch (IOException)
            {
                // Locked/unreadable file - skip from measure and preserve flow.
            }
        }
        return result;
    }

    private static IEnumerable<string> EnumerateFilesSafe(string root, CancellationToken ct)
    {
        var dirs = new Stack<string>();
        if (!Directory.Exists(root)) yield break;
        dirs.Push(root);

        while (dirs.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var dir = dirs.Pop();
            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir); }
            catch (UnauthorizedAccessException) { /* Protected directory - skip its files. */ }
            catch (IOException) { /* Unreadable directory - skip its files. */ }
            foreach (var f in files) yield return f;

            string[] subs = Array.Empty<string>();
            try { subs = Directory.GetDirectories(dir); }
            catch (UnauthorizedAccessException) { /* Protected directory - skip its subdirectories. */ }
            catch (IOException) { /* Unreadable directory - skip its subdirectories. */ }
            foreach (var sub in subs)
            {
                if (!JunkCleaningPolicy.IsCriticalPath(sub)) dirs.Push(sub);
            }
        }
    }

    private static void TryBackup(string file, string root, string backupRoot)
    {
        try
        {
            var rel = Path.GetRelativePath(root, file);
            var dest = Path.Combine(backupRoot, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            File.Copy(file, dest, overwrite: true);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Best-effort pre-delete backup - make the failure observable but do not abort cleaning.
            System.Diagnostics.Debug.WriteLine($"[DataVanger] Failed to back up '{file}' before deletion: {ex.Message}");
        }
    }

    private static void DeleteEmptyDirectories(string root, CancellationToken ct)
    {
        try
        {
            foreach (var dir in Directory.GetDirectories(root, "*", SearchOption.AllDirectories).OrderByDescending(x => x.Length))
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    if (!Directory.EnumerateFileSystemEntries(dir).Any()) Directory.Delete(dir, false);
                }
                catch (UnauthorizedAccessException) { /* Protected directory - leave in place and continue. */ }
                catch (IOException) { /* Directory busy/non-empty - leave in place and continue. */ }
            }
        }
        catch (UnauthorizedAccessException) { /* Protected root - nothing further to prune. */ }
        catch (IOException) { /* Unreadable root - nothing further to prune. */ }
    }

    /// <summary>
    /// Deletes all but the <paramref name="keep"/> most recent backup subdirectories under
    /// <paramref name="backupParent"/> (ordered by creation time, newest kept). Best-effort:
    /// a busy/protected backup is left in place and never aborts cleaning.
    /// </summary>
    public static void PruneOldBackups(string backupParent, int keep)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(backupParent) || !Directory.Exists(backupParent)) return;
            var stale = Directory.GetDirectories(backupParent)
                .OrderByDescending(GetCreationTimeSafe)
                .Skip(Math.Max(0, keep))
                .ToList();
            foreach (var dir in stale)
            {
                try { Directory.Delete(dir, recursive: true); }
                catch (UnauthorizedAccessException) { /* Protected backup - leave in place. */ }
                catch (IOException) { /* Backup busy/in use - leave in place. */ }
            }
        }
        catch (UnauthorizedAccessException) { /* Cannot enumerate backups - skip pruning. */ }
        catch (IOException) { /* Cannot enumerate backups - skip pruning. */ }
    }

    private static DateTime GetCreationTimeSafe(string dir)
    {
        try { return Directory.GetCreationTimeUtc(dir); }
        catch (UnauthorizedAccessException) { return DateTime.MinValue; }
        catch (IOException) { return DateTime.MinValue; }
    }

    private static string SanitizeFileName(string value)
    {
        foreach (var c in Path.GetInvalidFileNameChars()) value = value.Replace(c, '_');
        return value;
    }
}
