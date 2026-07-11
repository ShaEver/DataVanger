using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace DataVanger.Engine.Quarantine;

public readonly record struct QuarantineFileIdentity(ulong VolumeSerial, ulong FileId, long Length, long LastWriteUtcTicks);

public sealed class QuarantineSourceHandle : IDisposable
{
    internal QuarantineSourceHandle(FileStream stream, QuarantineFileIdentity identity) { Stream = stream; Identity = identity; }
    public FileStream Stream { get; }
    public QuarantineFileIdentity Identity { get; }
    public void Dispose() => Stream.Dispose();
}

/// <summary>Single abstraction for path/reparse/identity-sensitive file operations.</summary>
public interface IQuarantineFileOperations
{
    bool HasReparsePointInPath(string path);
    QuarantineSourceHandle OpenSource(string path);
    bool PathReferencesIdentity(string path, QuarantineFileIdentity identity);
    void DeleteOpenedSource(QuarantineSourceHandle source, string path);
}

public sealed class SystemQuarantineFileOperations : IQuarantineFileOperations
{
    private const uint GenericRead = 0x80000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint ShareRead = 0x00000001;
    private const uint ShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint SequentialScan = 0x08000000;
    private const uint OpenReparsePoint = 0x00200000;
    private const int FileDispositionInfo = 4;

    public bool HasReparsePointInPath(string path)
    {
        string full = Path.GetFullPath(path);
        string? current = File.Exists(full) ? full : Path.GetDirectoryName(full);
        while (!string.IsNullOrWhiteSpace(current))
        {
            if (File.Exists(current) || Directory.Exists(current))
            {
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) return true;
            }
            string? parent = Path.GetDirectoryName(current.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            if (string.Equals(parent, current, StringComparison.OrdinalIgnoreCase)) break;
            current = parent;
        }
        return false;
    }

    public QuarantineSourceHandle OpenSource(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            var handle = CreateFileW(path, GenericRead | DeleteAccess, ShareRead | ShareDelete, IntPtr.Zero,
                OpenExisting, SequentialScan | OpenReparsePoint, IntPtr.Zero);
            if (handle.IsInvalid) throw new IOException("Could not open source with stable Windows handle.", Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error()));
            var stream = new FileStream(handle, FileAccess.Read, 81_920, isAsync: false);
            return new QuarantineSourceHandle(stream, GetIdentity(stream));
        }

        var portable = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81_920, FileOptions.Asynchronous | FileOptions.SequentialScan);
        return new QuarantineSourceHandle(portable, GetIdentity(portable));
    }

    public bool PathReferencesIdentity(string path, QuarantineFileIdentity identity)
    {
        try
        {
            using var current = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return GetIdentity(current) == identity;
        }
        catch { return false; }
    }

    public void DeleteOpenedSource(QuarantineSourceHandle source, string path)
    {
        if (!PathReferencesIdentity(path, source.Identity)) throw new QuarantineSourceConflictException("Source path no longer references the quarantined file identity.");
        if (OperatingSystem.IsWindows())
        {
            var disposition = new FileDisposition { DeleteFile = true };
            if (!SetFileInformationByHandle(source.Stream.SafeFileHandle, FileDispositionInfo, ref disposition, Marshal.SizeOf<FileDisposition>()))
                throw new IOException("Could not mark the opened source for deletion.", Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error()));
            return;
        }
        File.Delete(path);
    }

    private static QuarantineFileIdentity GetIdentity(FileStream stream)
    {
        if (OperatingSystem.IsWindows() && GetFileInformationByHandle(stream.SafeFileHandle, out var info))
        {
            ulong id = ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow;
            long length = ((long)info.FileSizeHigh << 32) | info.FileSizeLow;
            long write = ((long)info.LastWriteTimeHigh << 32) | info.LastWriteTimeLow;
            return new QuarantineFileIdentity(info.VolumeSerialNumber, id, length, write);
        }
        return new QuarantineFileIdentity(0, 0, stream.Length, File.GetLastWriteTimeUtc(stream.Name).Ticks);
    }

    [StructLayout(LayoutKind.Sequential)] private struct FileDisposition { [MarshalAs(UnmanagedType.Bool)] public bool DeleteFile; }
    [StructLayout(LayoutKind.Sequential)] private struct ByHandleFileInformation
    {
        public uint FileAttributes; public uint CreationTimeLow; public uint CreationTimeHigh; public uint LastAccessTimeLow; public uint LastAccessTimeHigh;
        public uint LastWriteTimeLow; public uint LastWriteTimeHigh; public uint VolumeSerialNumber; public uint FileSizeHigh; public uint FileSizeLow;
        public uint NumberOfLinks; public uint FileIndexHigh; public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation info);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetFileInformationByHandle(SafeFileHandle file, int infoClass, ref FileDisposition info, int size);
}

public sealed class QuarantineSourceConflictException : IOException
{
    public QuarantineSourceConflictException(string message) : base(message) { }
}
