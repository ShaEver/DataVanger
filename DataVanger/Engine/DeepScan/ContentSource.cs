using System;
using System.IO;

namespace DataVanger.Engine.DeepScan;

/// <summary>
/// Abstract source of bytes for a scan target. Hides the difference between
/// "real file on disk" and "in-memory entry extracted from an archive" so
/// pipeline stages (hashing, file-type sniffing, content modules) can treat
/// both uniformly. Streams returned from <see cref="OpenRead"/> are owned by
/// the caller and must be disposed.
/// </summary>
public abstract class ContentSource : IDisposable
{
    public abstract string LogicalPath { get; }
    public abstract long Length { get; }
    public abstract bool IsOnDisk { get; }

    public abstract Stream OpenRead();

    public virtual void Dispose() { GC.SuppressFinalize(this); }
}

/// <summary>Content backed by a real file on disk.</summary>
public sealed class FileContentSource : ContentSource
{
    public FileInfo File { get; }

    public FileContentSource(FileInfo file)
    {
        File = file ?? throw new ArgumentNullException(nameof(file));
    }

    public override string LogicalPath => File.FullName;
    public override long Length => SafeLength(File);
    public override bool IsOnDisk => true;

    public override Stream OpenRead() =>
        new FileStream(File.FullName, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 81_920, useAsync: true);

    private static long SafeLength(FileInfo f)
    {
        try { return f.Exists ? f.Length : 0; } catch (System.Exception) { return 0; }
    }
}

/// <summary>Content backed by bytes already buffered in memory (typical for archive entries).</summary>
public sealed class MemoryContentSource : ContentSource
{
    private readonly byte[] _buffer;
    public string Origin { get; }

    public MemoryContentSource(string logicalPath, byte[] buffer, string origin)
    {
        _buffer = buffer ?? throw new ArgumentNullException(nameof(buffer));
        LogicalPath = logicalPath ?? "";
        Origin = origin ?? "";
    }

    public override string LogicalPath { get; }
    public override long Length => _buffer.LongLength;
    public override bool IsOnDisk => false;

    public override Stream OpenRead() => new MemoryStream(_buffer, writable: false);
}
