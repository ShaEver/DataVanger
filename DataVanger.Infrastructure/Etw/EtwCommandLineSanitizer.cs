using System;
using System.Text.RegularExpressions;

namespace DataVanger.Infrastructure.Etw;

/// <summary>
/// Centralized boundary for command-line sanitization introduced in
/// Phase 2 Step 05 (ETW Real Provider).
///
/// The ETW provider stores process command lines as part of normalized
/// runtime events. Command lines frequently contain tokens, passwords,
/// connection strings, and other secrets that MUST NOT be propagated
/// verbatim to reports, telemetry sinks, or future cloud surfaces.
///
/// This class is the single point where the runtime event mapper
/// (<see cref="EtwRuntimeEventMapper"/>) and the InMemory provider
/// pass command lines through redaction. A future redaction policy
/// upgrade only needs to change this file — no caller has to be
/// rewritten.
///
/// Sanitizer principles:
///   - Detection-relevant flags MUST be preserved:
///     -enc / -encodedcommand, -w hidden, -windowstyle hidden,
///     -ep bypass, -executionpolicy bypass, IEX, frombase64string(...
///   - Obvious password/token argument values MUST be redacted when
///     the pattern is unambiguous (e.g. /password=..., -token ...).
///   - Over-redaction is worse than under-redaction here because it
///     breaks downstream behavioral correlation. Default behavior is
///     conservative.
///   - The sanitizer NEVER classifies. It NEVER returns "this is
///     malware". It returns a string.
///   - The sanitizer NEVER throws on null/empty input.
/// </summary>
public static class EtwCommandLineSanitizer
{
    /// <summary>Hard cap to prevent a noisy provider from ballooning runtime events.</summary>
    public const int MaxCommandLineLength = 4 * 1024;

    private const string RedactedToken = "[REDACTED]";

    // Conservative password/token redaction. Matches argument styles
    // that unambiguously carry secrets:
    //   /password=...   -password ...  --password=...
    //   /pwd=...        /token=...     -api-key ...
    // Stops at whitespace or the next leading dash/slash to avoid
    // swallowing later arguments.
    private static readonly Regex SecretArgumentRx = new(
        @"(?<prefix>(?<![A-Za-z0-9])(?:--?|/)(?:password|pwd|passwd|secret|token|apikey|api[-_]?key|client[-_]?secret|bearer)\b)" +
        @"(?<sep>[\s=:]\s*)" +
        @"(?<value>(?:""[^""]*""|'[^']*'|[^\s]+))",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Conservative URL-with-embedded-credentials redaction:
    //   http(s)://user:secret@host/path  ->  http(s)://user:[REDACTED]@host/path
    private static readonly Regex UrlCredentialsRx = new(
        @"(?<scheme>\bhttps?://)(?<user>[^:/@\s]+):(?<pwd>[^@\s]+)@",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// Returns a sanitized, length-bounded copy of <paramref name="commandLine"/>.
    /// Null/empty input returns empty string. Never throws.
    /// </summary>
    public static string Sanitize(string? commandLine)
    {
        if (string.IsNullOrEmpty(commandLine)) return string.Empty;

        string working = commandLine!;

        try
        {
            working = SecretArgumentRx.Replace(working, m =>
                $"{m.Groups["prefix"].Value}{m.Groups["sep"].Value}{RedactedToken}");
            working = UrlCredentialsRx.Replace(working, m =>
                $"{m.Groups["scheme"].Value}{m.Groups["user"].Value}:{RedactedToken}@");
        }
        catch
        {
            // Sanitizer NEVER crashes the provider. On failure, fall
            // back to a hard-redacted form so secrets cannot leak even
            // when regex evaluation is interrupted.
            working = RedactedToken;
        }

        if (working.Length > MaxCommandLineLength)
        {
            working = working.Substring(0, MaxCommandLineLength);
        }

        return working;
    }
}
