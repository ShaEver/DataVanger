using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Core;

public sealed class CleanerEngine
{
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
            backupRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "DataVanger", "CleanerBackup", DateTime.Now.ToString("yyyyMMdd_HHmmss"));
            Directory.CreateDirectory(backupRoot);
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
                catch
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
                if (JunkCleaningPolicy.IsCleanableFile(file, location, out bool inUse))
                {
                    result.Bytes += fi.Length;
                    result.Count++;
                    result.OldestLastWrite = result.OldestLastWrite == null || fi.LastWriteTime < result.OldestLastWrite ? fi.LastWriteTime : result.OldestLastWrite;
                    result.NewestLastWrite = result.NewestLastWrite == null || fi.LastWriteTime > result.NewestLastWrite ? fi.LastWriteTime : result.NewestLastWrite;
                }
                if (inUse) result.HasFilesInUse = true;
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

    private static string SanitizeFileName(string value)
    {
        foreach (var c in Path.GetInvalidFileNameChars()) value = value.Replace(c, '_');
        return value;
    }
}
