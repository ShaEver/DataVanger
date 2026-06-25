using System;

namespace DataVanger.Reporting;

/// <summary>
/// Shared CSV field hardening for every CSV exporter (Phase 07). Two layers:
///
/// 1. <b>Spreadsheet formula-injection neutralization.</b> A field whose first
///    character is a formula/command trigger (<c>= + - @</c>, TAB, or CR) is
///    prefixed with a single quote, so Excel / Google Sheets / LibreOffice render
///    it as literal text instead of evaluating it (CSV/formula injection, CWE-1236).
///
/// 2. <b>RFC 4180 quoting.</b> A field containing a comma, double-quote, CR, or LF,
///    or with leading/trailing whitespace, is wrapped in double-quotes with inner
///    quotes doubled, so structure-breaking and whitespace-mangling inputs survive.
///
/// Pure, deterministic, and allocation-light; never throws. Apply it to
/// attacker-influenceable string fields (file names, paths, reasons, publishers).
/// Program-generated numeric/boolean columns do not need it and are left as-is so
/// they keep their numeric form in spreadsheets.
/// </summary>
public static class CsvSafe
{
    private static readonly char[] QuoteTriggers = { ',', '"', '\n', '\r' };

    /// <summary>Neutralize formula injection, then RFC 4180-quote as needed.</summary>
    public static string Field(string? value)
        => Quote(NeutralizeFormula(value ?? string.Empty));

    /// <summary>Prefix a single quote when the value starts with a formula trigger.</summary>
    public static string NeutralizeFormula(string value)
    {
        if (string.IsNullOrEmpty(value)) return value;
        char first = value[0];
        return first is '=' or '+' or '-' or '@' or '\t' or '\r'
            ? "'" + value
            : value;
    }

    private static string Quote(string value)
    {
        bool needsQuote =
            value.IndexOfAny(QuoteTriggers) >= 0 ||
            (value.Length > 0 && (char.IsWhiteSpace(value[0]) || char.IsWhiteSpace(value[^1])));

        return needsQuote
            ? "\"" + value.Replace("\"", "\"\"") + "\""
            : value;
    }
}
