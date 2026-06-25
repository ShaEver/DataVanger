using System;
using System.IO;
using DataVanger.Core;

namespace DataVanger.Detection.PE;

public static class PeResourceAnalyzer
{
    private const int MaxResourceBytes = 2 * 1024 * 1024;

    public static void Analyze(Stream stream, PeAnalysisResult result)
    {
        var pe = result.File;
        if (pe is null) return;
        var rsrc = pe.Sections.Find(s => s.Name.Equals(".rsrc", StringComparison.OrdinalIgnoreCase));
        if (rsrc is null || !rsrc.RawRangeValid(pe.Length) || rsrc.RawSize == 0) return;

        var bytes = PeParser.ReadBytes(stream, rsrc.RawPointer, (int)Math.Min(rsrc.RawSize, MaxResourceBytes));
        if (PeByteSearch.IndexOf(bytes, new byte[] { (byte)'M', (byte)'Z' }, 16) >= 0)
        {
            pe.ResourcePayload = true;
            result.Add("Recurso contém payload com cabeçalho MZ", 4, EvidenceStrength.High);
        }
        if (PeByteSearch.ContainsAscii(bytes, "powershell") || PeByteSearch.ContainsAscii(bytes, "cmd.exe") || PeByteSearch.ContainsAscii(bytes, "wscript.shell"))
            result.Add("Recurso contém indicadores de script/shell", 2, EvidenceStrength.Medium);
        if (PeByteSearch.IndexOf(bytes, new byte[] { (byte)'P', (byte)'K', 3, 4 }, 0) >= 0)
            result.Add("Recurso contém arquivo ZIP embutido", 2, EvidenceStrength.Medium);

        double entropy = PeEntropyAnalyzer.Calculate(bytes);
        if (bytes.Length >= 4096 && entropy >= 7.6)
            result.Add($"Alta entropia em recursos: {entropy:F2}", 1, EvidenceStrength.Low);
    }
}
