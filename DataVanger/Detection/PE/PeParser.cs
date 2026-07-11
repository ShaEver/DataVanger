using System;
using System.IO;
using System.Text;
using DataVanger.Core;

namespace DataVanger.Detection.PE;

public static class PeParser
{
    private const int MaxSections = 96;

    public static bool IsPeFile(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            return IsPeFile(fs);
        }
        catch (System.Exception) { return false; }
    }

    public static bool IsPeFile(Stream stream)
    {
        try
        {
            if (stream is null || !stream.CanSeek || stream.Length < 0x40) return false;
            long old = stream.Position;
            try
            {
                return ReadUInt16(stream, 0, out var mz) && mz == 0x5A4D
                    && ReadInt32(stream, 0x3C, out var peOffset)
                    && peOffset > 0 && peOffset <= stream.Length - 4 && peOffset < 16 * 1024 * 1024
                    && ReadUInt32(stream, peOffset, out var sig) && sig == 0x00004550;
            }
            finally { stream.Position = old; }
        }
        catch (System.Exception) { return false; }
    }

    public static PeAnalysisResult Parse(string path)
    {
        string safePath = path ?? "";
        var result = new PeAnalysisResult { LogicalPath = safePath };
        if (string.IsNullOrWhiteSpace(safePath)) return result;
        try
        {
            using var fs = new FileStream(safePath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 81_920, useAsync: false);
            Parse(fs, safePath, result);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Malformed PE or unreadable file - return the partial result unchanged; fatal CLR exceptions are not swallowed.
        }
        return result;
    }

    public static PeAnalysisResult Parse(Stream stream, string logicalPath)
    {
        string safePath = logicalPath ?? "";
        var result = new PeAnalysisResult { LogicalPath = safePath };
        try { Parse(stream, safePath, result); }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Malformed PE stream - return the partial result unchanged; fatal CLR exceptions are not swallowed.
        }
        return result;
    }
    private static void Parse(Stream stream, string logicalPath, PeAnalysisResult result)
    {
        if (stream is null || !stream.CanSeek || stream.Length < 0x40) return;
        long old = stream.Position;
        try
        {
            if (!ReadUInt16(stream, 0, out var mz) || mz != 0x5A4D) return;
            result.IsPe = true;
            if (!ReadInt32(stream, 0x3C, out var peOffset) || peOffset <= 0 || peOffset > stream.Length - 24 || peOffset > 16 * 1024 * 1024)
            {
                result.Add("Cabeçalho PE aponta para offset inválido", 1, EvidenceStrength.Low);
                return;
            }
            if (!ReadUInt32(stream, peOffset, out var sig) || sig != 0x00004550) return;

            if (!ReadUInt16(stream, peOffset + 4, out var machine) ||
                !ReadUInt16(stream, peOffset + 6, out var sectionCount) ||
                !ReadUInt32(stream, peOffset + 8, out var timestamp) ||
                !ReadUInt16(stream, peOffset + 20, out var optionalSize) ||
                !ReadUInt16(stream, peOffset + 22, out var characteristics)) return;

            var pe = new PeFile
            {
                Length = stream.Length,
                LogicalPath = logicalPath ?? "",
                Machine = machine,
                Timestamp = timestamp,
                Characteristics = characteristics,
                Architecture = machine switch
                {
                    0x014c => "x86",
                    0x8664 => "x64",
                    0x01c4 => "ARM",
                    0xaa64 => "ARM64",
                    _ => $"machine-0x{machine:X4}",
                }
            };

            if (sectionCount == 0 || sectionCount > MaxSections)
            {
                result.Add($"Número de seções anômalo: {sectionCount}", 2, EvidenceStrength.Medium);
                sectionCount = Math.Min(sectionCount, (ushort)MaxSections);
            }

            long opt = peOffset + 24;
            if (optionalSize < 96 || opt + optionalSize > stream.Length)
            {
                result.Add("Optional header PE ausente ou truncado", 1, EvidenceStrength.Low);
                return;
            }
            if (!ReadUInt16(stream, opt, out var magic) || (magic != 0x10b && magic != 0x20b)) return;
            pe.Is64Bit = magic == 0x20b;
            if (ReadUInt32(stream, opt + 16, out var ep)) pe.EntryPointRva = ep;
            pe.ImageBase = pe.Is64Bit && ReadUInt64(stream, opt + 24, out var ib64) ? ib64 : (ReadUInt32(stream, opt + 28, out var ib32) ? ib32 : 0);
            if (ReadUInt32(stream, opt + 32, out var sectionAlignment)) pe.SectionAlignment = sectionAlignment;
            if (ReadUInt32(stream, opt + 36, out var fileAlignment)) pe.FileAlignment = fileAlignment;
            if (ReadUInt32(stream, opt + 60, out var sizeOfHeaders)) pe.SizeOfHeaders = sizeOfHeaders;
            if (ReadUInt16(stream, opt + 68, out var subsystem)) pe.Subsystem = subsystem;

            long dd = opt + (pe.Is64Bit ? 112 : 96);
            if (dd + 16 * 8 <= opt + optionalSize)
            {
                pe.ImportDirectory = ReadDirectory(stream, dd, 1);
                pe.ResourceDirectory = ReadDirectory(stream, dd, 2);
                pe.SecurityDirectory = ReadDirectory(stream, dd, 4);
                pe.TlsDirectory = ReadDirectory(stream, dd, 9);
            }

            long sectionOffset = opt + optionalSize;
            for (int i = 0; i < sectionCount && sectionOffset + 40 <= stream.Length; i++, sectionOffset += 40)
            {
                string name = Encoding.ASCII.GetString(ReadBytes(stream, sectionOffset, 8)).TrimEnd('\0', ' ');
                ReadUInt32(stream, sectionOffset + 8, out var virtualSize);
                ReadUInt32(stream, sectionOffset + 12, out var virtualAddress);
                ReadUInt32(stream, sectionOffset + 16, out var rawSize);
                ReadUInt32(stream, sectionOffset + 20, out var rawPointer);
                ReadUInt32(stream, sectionOffset + 36, out var flags);
                pe.Sections.Add(new PeSection
                {
                    Name = string.IsNullOrWhiteSpace(name) ? $"section{i}" : name,
                    VirtualSize = virtualSize,
                    VirtualAddress = virtualAddress,
                    RawSize = rawSize,
                    RawPointer = rawPointer,
                    Characteristics = flags,
                });
            }

            if (pe.Sections.Count == 0) return;
            result.File = pe;
            result.ParsedSuccessfully = true;
        }
        finally { try { stream.Position = old; } catch (Exception) { /* Best-effort restore of stream position - ignore. */ } }
    }

    private static PeDataDirectory ReadDirectory(Stream stream, long dd, int index)
    {
        long offset = dd + index * 8L;
        ReadUInt32(stream, offset, out var rva);
        ReadUInt32(stream, offset + 4, out var size);
        return new PeDataDirectory(rva, size);
    }

    internal static bool ReadUInt16(Stream stream, long offset, out ushort value)
    {
        value = 0;
        var b = ReadBytes(stream, offset, 2);
        if (b.Length != 2) return false;
        value = BitConverter.ToUInt16(b, 0);
        return true;
    }

    internal static bool ReadUInt32(Stream stream, long offset, out uint value)
    {
        value = 0;
        var b = ReadBytes(stream, offset, 4);
        if (b.Length != 4) return false;
        value = BitConverter.ToUInt32(b, 0);
        return true;
    }

    internal static bool ReadUInt64(Stream stream, long offset, out ulong value)
    {
        value = 0;
        var b = ReadBytes(stream, offset, 8);
        if (b.Length != 8) return false;
        value = BitConverter.ToUInt64(b, 0);
        return true;
    }

    internal static bool ReadInt32(Stream stream, long offset, out int value)
    {
        value = 0;
        var b = ReadBytes(stream, offset, 4);
        if (b.Length != 4) return false;
        value = BitConverter.ToInt32(b, 0);
        return true;
    }

    internal static byte[] ReadBytes(Stream stream, long offset, int count)
    {
        if (count <= 0 || offset < 0) return Array.Empty<byte>();
        long length;
        try { length = stream.Length; } catch (System.Exception) { return Array.Empty<byte>(); }
        if (offset >= length) return Array.Empty<byte>();
        int safeCount = (int)Math.Min(count, length - offset);
        var buffer = new byte[safeCount];
        stream.Position = offset;
        int read = 0;
        while (read < safeCount)
        {
            int chunk = stream.Read(buffer, read, safeCount - read);
            if (chunk <= 0) break;
            read += chunk;
        }
        if (read == safeCount) return buffer;
        Array.Resize(ref buffer, read);
        return buffer;
    }

    internal static string ReadAsciiZ(Stream stream, long offset, int max)
    {
        var bytes = ReadBytes(stream, offset, max);
        int end = Array.IndexOf(bytes, (byte)0);
        if (end < 0) end = bytes.Length;
        return end <= 0 ? "" : Encoding.ASCII.GetString(bytes, 0, end).Trim();
    }
}


