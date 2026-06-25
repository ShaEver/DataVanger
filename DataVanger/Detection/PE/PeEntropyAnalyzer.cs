using System;

namespace DataVanger.Detection.PE;

public static class PeEntropyAnalyzer
{
    public static double Calculate(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty) return 0;
        Span<int> counts = stackalloc int[256];
        foreach (byte b in bytes) counts[b]++;
        double entropy = 0;
        double length = bytes.Length;
        for (int i = 0; i < counts.Length; i++)
        {
            if (counts[i] == 0) continue;
            double p = counts[i] / length;
            entropy -= p * Math.Log(p, 2);
        }
        return entropy;
    }
}
