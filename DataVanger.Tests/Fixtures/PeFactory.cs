using System;
using System.Collections.Generic;
using System.IO;

namespace DataVanger.Tests.Fixtures;

// Deterministic test-data builders moved verbatim from the legacy Program.cs
// top-level runner. Behavior is unchanged; only the enclosing form changed
// (top-level local functions -> public static methods).
public static class PeFactory
{
    public static byte[] CreateZip(params (string Name, byte[] Content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var entry in entries)
            {
                var zipEntry = zip.CreateEntry(entry.Name, System.IO.Compression.CompressionLevel.Optimal);
                using var s = zipEntry.Open();
                s.Write(entry.Content, 0, entry.Content.Length);
            }
        }
        return ms.ToArray();
    }


    public static byte[] CreateTestPe((string Name, uint Flags, byte[] Data, uint VirtualSize)[] sections, byte[]? overlay = null, uint entryPointRva = 0x1000, uint timestamp = 1_700_000_000)
    {
        const int peOffset = 0x80;
        const int optionalSize = 224;
        const int headerSize = 0x400;
        const uint sectionAlignment = 0x1000;
        const uint fileAlignment = 0x200;
        static int Align(int value, int alignment) => ((value + alignment - 1) / alignment) * alignment;

        int rawCursor = headerSize;
        var layouts = new List<(string Name, uint Flags, byte[] Data, uint VirtualSize, uint Va, uint RawPtr, uint RawSize)>();
        for (int i = 0; i < sections.Length; i++)
        {
            var s = sections[i];
            uint rawSize = (uint)Align(Math.Max(1, s.Data.Length), (int)fileAlignment);
            layouts.Add((s.Name, s.Flags, s.Data, s.VirtualSize == 0 ? rawSize : s.VirtualSize, (uint)(0x1000 + i * 0x1000), (uint)rawCursor, rawSize));
            rawCursor += (int)rawSize;
        }

        var pe = new byte[rawCursor + (overlay?.Length ?? 0)];
        void W16(int o, ushort v) => BitConverter.GetBytes(v).CopyTo(pe, o);
        void W32(int o, uint v) => BitConverter.GetBytes(v).CopyTo(pe, o);
        void ASCII(int o, string value, int len)
        {
            var b = System.Text.Encoding.ASCII.GetBytes(value);
            Array.Copy(b, 0, pe, o, Math.Min(len, b.Length));
        }

        W16(0, 0x5A4D);
        W32(0x3C, peOffset);
        ASCII(peOffset, "PE\0\0", 4);
        W16(peOffset + 4, 0x014c);
        W16(peOffset + 6, (ushort)layouts.Count);
        W32(peOffset + 8, timestamp);
        W16(peOffset + 20, optionalSize);
        W16(peOffset + 22, 0x010F);

        int opt = peOffset + 24;
        W16(opt, 0x10b);
        W32(opt + 16, entryPointRva);
        W32(opt + 28, 0x400000);
        W32(opt + 32, sectionAlignment);
        W32(opt + 36, fileAlignment);
        W32(opt + 56, (uint)(0x1000 + layouts.Count * 0x1000));
        W32(opt + 60, headerSize);
        W16(opt + 68, 2);
        W32(opt + 92, 16);

        int sh = opt + optionalSize;
        foreach (var s in layouts)
        {
            ASCII(sh, s.Name, 8);
            W32(sh + 8, s.VirtualSize);
            W32(sh + 12, s.Va);
            W32(sh + 16, s.RawSize);
            W32(sh + 20, s.RawPtr);
            W32(sh + 36, s.Flags);
            Array.Copy(s.Data, 0, pe, s.RawPtr, s.Data.Length);
            sh += 40;
        }

        if (overlay is not null) Array.Copy(overlay, 0, pe, rawCursor, overlay.Length);
        return pe;
    }

    public static byte[] PatternBytes(int length)
    {
        var bytes = new byte[length];
        for (int i = 0; i < bytes.Length; i++) bytes[i] = (byte)(i & 0xFF);
        return bytes;
    }

    // Runtime-concat helper for fragments of attacker-shaped script samples used by
    // the analyzer tests below. Keeping the literal full payload out of the compiled
    // assembly avoids Windows Defender flagging DataVanger.Tests.dll on load
    // (0x800700E1 / ERROR_VIRUS_INFECTED) when the test runner is started. The
    // analyzers still see the full reconstructed string at call time, so test
    // outcomes are unchanged.
    public static string J(params string[] parts) => string.Concat(parts);
}
