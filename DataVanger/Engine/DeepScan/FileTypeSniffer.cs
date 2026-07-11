using System;
using System.IO;
using System.Text;

namespace DataVanger.Engine.DeepScan;

/// <summary>
/// Magic-byte based file type identification. Used by the file-type stage so
/// the deep pipeline does not rely solely on the extension a sample claims.
///
/// The sniffer reads at most <see cref="PeekBytes"/> bytes from the start of
/// a stream and rewinds the stream when it is seekable. Heap allocations are
/// kept to a single rented buffer per call.
/// </summary>
public static class FileTypeSniffer
{
    public const int PeekBytes = 32;

    public static SniffedFileType Sniff(Stream stream)
    {
        if (stream is null) return SniffedFileType.Unknown;
        Span<byte> head = stackalloc byte[PeekBytes];
        int read = 0;
        long start = stream.CanSeek ? stream.Position : 0;
        try
        {
            int chunk;
            while (read < head.Length && (chunk = stream.Read(head[read..])) > 0) read += chunk;
        }
        catch (System.Exception)
        {
            return SniffedFileType.Unknown;
        }
        finally
        {
            if (stream.CanSeek) try { stream.Position = start; } catch (Exception) { /* Best-effort restore of stream position - ignore. */ }
        }
        return SniffMagic(head[..read]);
    }

    public static SniffedFileType SniffMagic(ReadOnlySpan<byte> head)
    {
        if (head.Length >= 2 && head[0] == 'M' && head[1] == 'Z') return SniffedFileType.Pe;
        if (head.Length >= 4 && head[0] == 'P' && head[1] == 'K' && (head[2] == 3 || head[2] == 5 || head[2] == 7))
            return SniffedFileType.ZipFamily;
        if (head.Length >= 7 && head[0] == 'R' && head[1] == 'a' && head[2] == 'r' && head[3] == '!') return SniffedFileType.Rar;
        if (head.Length >= 6 && head[0] == '7' && head[1] == 'z' && head[2] == 0xBC && head[3] == 0xAF) return SniffedFileType.SevenZ;
        if (head.Length >= 3 && head[0] == 0x1F && head[1] == 0x8B) return SniffedFileType.Gzip;
        if (head.Length >= 4 && head[0] == '%' && head[1] == 'P' && head[2] == 'D' && head[3] == 'F') return SniffedFileType.Pdf;
        if (head.Length >= 5 && head[0] == '{' /* { */)
        {
            string text = Encoding.ASCII.GetString(head);
            if (text.Contains("\\rtf", StringComparison.OrdinalIgnoreCase)) return SniffedFileType.Rtf;
        }
        if (head.Length >= 4 && head[0] == 0xD0 && head[1] == 0xCF && head[2] == 0x11 && head[3] == 0xE0)
            return SniffedFileType.OfficeOle;
        if (head.Length >= 4 && head[0] == 'I' && head[1] == 'T' && head[2] == 'S' && head[3] == 'F') return SniffedFileType.Chm;
        if (head.Length >= 4 && head[0] == 'M' && head[1] == 'S' && head[2] == 'C' && head[3] == 'F') return SniffedFileType.Cab;
        if (LooksLikeText(head)) return SniffedFileType.Text;
        return SniffedFileType.Unknown;
    }

    private static bool LooksLikeText(ReadOnlySpan<byte> head)
    {
        if (head.IsEmpty) return false;
        int printable = 0;
        for (int i = 0; i < head.Length; i++)
        {
            byte b = head[i];
            if (b == 0) return false;
            if (b == 9 || b == 10 || b == 13 || (b >= 32 && b < 127)) printable++;
        }
        return printable * 4 >= head.Length * 3;
    }

    /// <summary>True when the sniffed type behaves like an archive container the pipeline can recurse into.</summary>
    public static bool IsArchiveContainer(SniffedFileType type) => type switch
    {
        SniffedFileType.ZipFamily => true,
        SniffedFileType.Gzip      => true,
        SniffedFileType.SevenZ    => true,
        SniffedFileType.Rar       => true,
        SniffedFileType.Cab       => true,
        _ => false,
    };

    /// <summary>True when the actual content type contradicts the declared extension.</summary>
    public static bool IsSpoofed(SniffedFileType sniffed, string extension)
    {
        if (sniffed == SniffedFileType.Unknown) return false;
        extension ??= "";
        return sniffed switch
        {
            SniffedFileType.Pe        => !MatchesPe(extension),
            SniffedFileType.ZipFamily => !MatchesZipFamily(extension),
            SniffedFileType.Pdf       => !extension.Equals(".pdf", StringComparison.OrdinalIgnoreCase),
            SniffedFileType.OfficeOle => !MatchesOleOffice(extension),
            _ => false,
        };
    }

    private static bool MatchesPe(string ext) => ext.Length == 0 || ext switch
    {
        ".exe" or ".dll" or ".sys" or ".scr" or ".com" or ".ocx" or ".cpl" or ".efi" or ".drv" => true,
        _ => false,
    };

    private static bool MatchesZipFamily(string ext) => ext switch
    {
        ".zip" or ".jar" or ".war" or ".ear" or ".docx" or ".xlsx" or ".pptx"
            or ".docm" or ".xlsm" or ".pptm" or ".xlam" or ".xla"
            or ".odt" or ".ods" or ".odp" or ".apk" or ".ipa" or ".epub" or ".xpi" or ".crx" => true,
        _ => false,
    };

    private static bool MatchesOleOffice(string ext) => ext switch
    {
        ".doc" or ".xls" or ".ppt" or ".msi" or ".msg" => true,
        _ => false,
    };
}

public enum SniffedFileType
{
    Unknown,
    Pe,
    ZipFamily,
    Rar,
    SevenZ,
    Gzip,
    Cab,
    Pdf,
    Rtf,
    OfficeOle,
    Chm,
    Text,
}
