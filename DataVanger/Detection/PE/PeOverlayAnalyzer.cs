using System;
using System.IO;
using DataVanger.Core;

namespace DataVanger.Detection.PE;

public static class PeOverlayAnalyzer
{
    public static void Analyze(Stream stream, PeAnalysisResult result)
    {
        var pe = result.File;
        if (pe is null) return;

        long sectionEnd = pe.SectionRawEnd();
        long certEnd = pe.SecurityDirectory.Rva > 0 && pe.SecurityDirectory.Size > 0
            ? (long)pe.SecurityDirectory.Rva + pe.SecurityDirectory.Size
            : 0;
        long overlayStart = Math.Max(sectionEnd, certEnd);
        if (overlayStart <= 0 || overlayStart >= pe.Length) return;

        long overlaySize = pe.Length - overlayStart;
        pe.OverlaySize = overlaySize;
        var sample = PeParser.ReadBytes(stream, overlayStart, (int)Math.Min(overlaySize, 256 * 1024));
        bool embeddedPe = PeByteSearch.IndexOf(sample, new byte[] { (byte)'M', (byte)'Z' }, 0) >= 0;
        bool embeddedZip = PeByteSearch.IndexOf(sample, new byte[] { (byte)'P', (byte)'K', 3, 4 }, 0) >= 0;
        double ratio = pe.Length <= 0 ? 0 : overlaySize / (double)pe.Length;

        if (overlaySize > 256 * 1024 || ratio > 0.10)
            result.Add($"Overlay grande anexado ao PE: {overlaySize / 1024} KB", 3, EvidenceStrength.Medium);
        else if (overlaySize > 4096)
            result.Add($"Overlay anexado ao PE: {overlaySize / 1024} KB", 1, EvidenceStrength.Low);

        if (embeddedPe)
        {
            pe.OverlayPayload = true;
            result.Add("Overlay contém possível payload PE embutido", 4, EvidenceStrength.High);
        }
        if (embeddedZip)
        {
            pe.OverlayPayload = true;
            result.Add("Overlay contém arquivo compactado embutido", 2, EvidenceStrength.Medium);
        }
    }
}
