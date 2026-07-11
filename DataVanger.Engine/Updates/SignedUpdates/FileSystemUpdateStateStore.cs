using System;
using System.IO;
using System.Text.Json;
using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// File-system backed anti-downgrade state store. Persists per-feed "current"
/// and "last-known-good" snapshots as small JSON files inside a state
/// directory. No network access; intended for a service-controlled or
/// temp/test-controlled directory.
///
/// Reads are defensive: a missing or corrupt state file is treated as "no
/// state" rather than throwing, so a damaged record degrades to a fresh/empty
/// state instead of breaking local protection.
/// </summary>
public sealed class FileSystemUpdateStateStore : IUpdateStateStore
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = false };

    private readonly string _stateDirectory;
    private readonly object _gate = new();

    public FileSystemUpdateStateStore(string stateDirectory)
    {
        if (string.IsNullOrWhiteSpace(stateDirectory)) throw new ArgumentException("State directory is required.", nameof(stateDirectory));
        _stateDirectory = Path.GetFullPath(stateDirectory);
        Directory.CreateDirectory(_stateDirectory);
    }

    public UpdateStateSnapshot GetCurrent(string feedId)
    {
        lock (_gate)
        {
            return ReadSnapshot(CurrentPath(feedId)) ?? UpdateStateSnapshot.Empty(feedId);
        }
    }

    public UpdateStateSnapshot? GetLastKnownGood(string feedId)
    {
        lock (_gate)
        {
            return ReadSnapshot(LastKnownGoodPath(feedId));
        }
    }

    public void Commit(UpdateStateSnapshot newState)
    {
        if (newState is null) throw new ArgumentNullException(nameof(newState));
        lock (_gate)
        {
            var previous = ReadSnapshot(CurrentPath(newState.FeedId));
            if (previous is not null && previous.HasState)
                WriteSnapshot(LastKnownGoodPath(newState.FeedId), previous);
            WriteSnapshot(CurrentPath(newState.FeedId), newState);
        }
    }

    public bool TryRollback(string feedId, out UpdateStateSnapshot restored)
    {
        lock (_gate)
        {
            var lastKnownGood = ReadSnapshot(LastKnownGoodPath(feedId));
            if (lastKnownGood is not null)
            {
                WriteSnapshot(CurrentPath(feedId), lastKnownGood);
                TryDelete(LastKnownGoodPath(feedId));
                restored = lastKnownGood;
                return true;
            }

            restored = ReadSnapshot(CurrentPath(feedId)) ?? UpdateStateSnapshot.Empty(feedId);
            return false;
        }
    }

    private string CurrentPath(string feedId) => Path.Combine(_stateDirectory, SafeFeedFileName(feedId) + ".current.json");
    private string LastKnownGoodPath(string feedId) => Path.Combine(_stateDirectory, SafeFeedFileName(feedId) + ".lkg.json");

    private static UpdateStateSnapshot? ReadSnapshot(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<UpdateStateSnapshot>(json, Options);
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            // Corrupt/unreadable state degrades to "no state".
            return null;
        }
    }

    private static void WriteSnapshot(string path, UpdateStateSnapshot snapshot)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(snapshot, Options));
        var temp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(temp)) File.Delete(temp); }
            catch (IOException) { /* best effort */ }
            catch (UnauthorizedAccessException) { /* best effort */ }
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (IOException) { /* best effort */ }
        catch (UnauthorizedAccessException) { /* best effort */ }
    }

    private static string SafeFeedFileName(string feedId)
    {
        if (string.IsNullOrWhiteSpace(feedId)) return "_feed";
        var chars = feedId.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            var c = chars[i];
            if (!char.IsLetterOrDigit(c) && c != '-' && c != '_') chars[i] = '_';
        }
        return new string(chars);
    }
}
