using System;
using System.Text;

namespace DataVanger.Detection.PE;

internal static class PeByteSearch
{
    public static int IndexOf(byte[] haystack, byte[] needle, int start)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length) return -1;
        for (int i = Math.Max(0, start); i <= haystack.Length - needle.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { ok = false; break; }
            }
            if (ok) return i;
        }
        return -1;
    }

    public static bool ContainsAscii(byte[] bytes, string token) =>
        bytes.Length > 0 && Encoding.ASCII.GetString(bytes).Contains(token, StringComparison.OrdinalIgnoreCase);
}
