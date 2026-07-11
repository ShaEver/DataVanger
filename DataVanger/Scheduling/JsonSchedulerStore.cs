using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using DataVanger.Scheduling.Abstractions;
using DataVanger.Scheduling.Models;

namespace DataVanger.Scheduling;

/// <summary>
/// Plain-JSON scheduler store. Splits jobs, status and history into
/// independent files so a single corrupted artifact never wipes the
/// others. Every read is wrapped in try/catch — corrupted files yield an
/// empty list instead of a fatal exception, satisfying the
/// "must survive corrupted scheduler data" contract.
/// </summary>
public sealed class JsonSchedulerStore : ISchedulerStore
{
    private readonly string _root;
    private readonly object _gate = new();
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
    };

    public string JobsPath => Path.Combine(_root, "scheduler_jobs.json");
    public string StatusPath => Path.Combine(_root, "scheduler_status.json");
    public string HistoryPath => Path.Combine(_root, "scheduler_history.json");

    public int HistoryLimit { get; init; } = 200;

    public JsonSchedulerStore(string rootDirectory)
    {
        _root = rootDirectory ?? throw new ArgumentNullException(nameof(rootDirectory));
        try { Directory.CreateDirectory(_root); } catch (System.Exception) { /* read-only env: keep going */ }
    }

    public IReadOnlyList<ScheduledJobDefinition> LoadJobs()
        => ReadList<ScheduledJobDefinition>(JobsPath);

    public IReadOnlyList<ScheduledJobStatus> LoadStatus()
        => ReadList<ScheduledJobStatus>(StatusPath);

    public IReadOnlyList<ScheduledJobExecution> LoadHistory()
        => ReadList<ScheduledJobExecution>(HistoryPath);

    public void SaveJobs(IReadOnlyList<ScheduledJobDefinition> jobs)
        => WriteList(JobsPath, jobs);

    public void SaveStatus(IReadOnlyList<ScheduledJobStatus> statuses)
        => WriteList(StatusPath, statuses);

    public void AppendHistory(ScheduledJobExecution execution)
    {
        lock (_gate)
        {
            try
            {
                var current = new List<ScheduledJobExecution>(ReadList<ScheduledJobExecution>(HistoryPath));
                current.Add(execution);

                int limit = Math.Max(0, HistoryLimit);
                if (limit == 0)
                {
                    current.Clear();
                }
                else
                {
                    int excess = current.Count - limit;
                    if (excess > 0) current.RemoveRange(0, Math.Min(excess, current.Count));
                }

                WriteList(HistoryPath, current);
            }
            catch (System.Exception)
            {
                // History persistence must not crash the scheduler.
            }
        }
    }

    private List<T> ReadList<T>(string path)
    {
        lock (_gate)
        {
            try
            {
                if (!File.Exists(path)) return new List<T>();
                var raw = File.ReadAllText(path);
                if (string.IsNullOrWhiteSpace(raw)) return new List<T>();
                var parsed = JsonSerializer.Deserialize<List<T>>(raw, JsonOptions);
                return parsed ?? new List<T>();
            }
            catch (System.Exception)
            {
                // Corrupted/malformed payload — never bubble up as fatal.
                return new List<T>();
            }
        }
    }

    private void WriteList<T>(string path, IReadOnlyList<T> items)
    {
        lock (_gate)
        {
            string? tmp = null;
            try
            {
                var dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

                tmp = path + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(items, JsonOptions));

                if (File.Exists(path))
                {
                    var backup = path + ".bak";
                    File.Replace(tmp, path, backup, ignoreMetadataErrors: true);
                    TryDelete(backup);
                }
                else
                {
                    File.Move(tmp, path);
                }
            }
            catch (System.Exception)
            {
                // Persistence failure must not crash the scheduler.
                // If replacement fails, the existing valid file is preserved.
            }
            finally
            {
                if (tmp != null) TryDelete(tmp);
            }
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch (System.Exception)
        {
            // best-effort cleanup only
        }
    }
}
