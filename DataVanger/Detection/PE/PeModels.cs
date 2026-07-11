using System;
using System.Collections.Generic;
using System.Linq;

namespace DataVanger.Detection.PE;

public readonly record struct PeDataDirectory(uint Rva, uint Size);

public sealed class PeFile
{
    public long Length { get; init; }
    public string LogicalPath { get; init; } = "";
    public ushort Machine { get; set; }
    public ushort Characteristics { get; set; }
    public uint Timestamp { get; set; }
    public bool Is64Bit { get; set; }
    public string Architecture { get; set; } = "unknown";
    public uint EntryPointRva { get; set; }
    public ulong ImageBase { get; set; }
    public uint SectionAlignment { get; set; }
    public uint FileAlignment { get; set; }
    public uint SizeOfHeaders { get; set; }
    public ushort Subsystem { get; set; }
    public PeDataDirectory ImportDirectory { get; set; }
    public PeDataDirectory ResourceDirectory { get; set; }
    public PeDataDirectory SecurityDirectory { get; set; }
    public PeDataDirectory TlsDirectory { get; set; }
    public List<PeSection> Sections { get; } = new();
    public HashSet<string> Imports { get; } = new(StringComparer.OrdinalIgnoreCase);
    public int PackerSectionCount { get; set; }
    public int HighEntropyExecutableSectionCount { get; set; }
    public int ImportCount { get; set; }
    public long OverlaySize { get; set; }
    public bool OverlayPayload { get; set; }
    public bool ResourcePayload { get; set; }

    public PeSection? SectionForRva(uint rva) => Sections.FirstOrDefault(s =>
        rva >= s.VirtualAddress && rva < s.VirtualAddress + Math.Max(s.VirtualSize, s.RawSize));

    public bool TryRvaToOffset(uint rva, out long offset)
    {
        offset = 0;
        if (rva < SizeOfHeaders)
        {
            offset = rva;
            return offset >= 0 && offset < Length;
        }
        var section = SectionForRva(rva);
        if (section is null || !section.RawRangeValid(Length)) return false;
        offset = section.RawPointer + (rva - section.VirtualAddress);
        return offset >= 0 && offset < Length;
    }

    public long SectionRawEnd() => Sections
        .Where(s => s.RawRangeValid(Length))
        .Select(s => (long)s.RawPointer + s.RawSize)
        .DefaultIfEmpty(0)
        .Max();
}

public sealed class PeSection
{
    public const uint Execute = 0x20000000;
    public const uint Read = 0x40000000;
    public const uint Write = 0x80000000;

    public string Name { get; init; } = "";
    public uint VirtualSize { get; init; }
    public uint VirtualAddress { get; init; }
    public uint RawSize { get; init; }
    public uint RawPointer { get; init; }
    public uint Characteristics { get; init; }
    public double Entropy { get; set; }
    public bool Executable => (Characteristics & Execute) != 0;
    public bool Writable => (Characteristics & Write) != 0;
    public bool Readable => (Characteristics & Read) != 0;

    public bool RawRangeValid(long length) =>
        RawSize == 0 || (RawPointer > 0 && RawPointer < length && RawSize <= length - RawPointer);

    public bool OverlapsRaw(PeSection other)
    {
        if (RawSize == 0 || other.RawSize == 0) return false;
        ulong a0 = RawPointer, a1 = a0 + RawSize, b0 = other.RawPointer, b1 = b0 + other.RawSize;
        return a0 < b1 && b0 < a1;
    }
}
