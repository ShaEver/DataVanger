namespace DataVanger.BrowserIntelligence;

/// <summary>
/// Browser families recognised by the intelligence engine. Used purely
/// for evidence/explainability and trust-aware path heuristics — never
/// for confirming malware.
/// </summary>
public enum BrowserKind
{
    Unknown = 0,
    Chrome,
    Edge,
    Brave,
    Opera,
    Vivaldi,
    Chromium,
    Helium,
    Firefox,
}
