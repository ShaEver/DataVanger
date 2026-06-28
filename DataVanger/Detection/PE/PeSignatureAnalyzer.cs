using System;
using System.Diagnostics;
using System.IO;
using DataVanger.Core;

namespace DataVanger.Detection.PE;

public static class PeSignatureAnalyzer
{
    public static void Analyze(string path, PeAnalysisResult result)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return;
        try
        {
            if (WinTrust.VerifyFile(path))
            {
                string signer = WinTrust.GetSignerSubject(path);
                result.Add(string.IsNullOrWhiteSpace(signer)
                    ? "Assinatura Authenticode válida"
                    : $"Assinatura Authenticode válida: {signer}", -1, EvidenceStrength.Info);
            }
            else
            {
                result.Add("PE sem assinatura Authenticode válida", 0, EvidenceStrength.Info);
            }
        }
        catch (System.Exception)
        {
            result.Add("Falha ao validar assinatura Authenticode", 0, EvidenceStrength.Info);
        }
    }
}

public static class PeMetadataAnalyzer
{
    public static void Analyze(string path, PeAnalysisResult result)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return;
        try
        {
            var info = FileVersionInfo.GetVersionInfo(path);
            bool claimsMicrosoft = Contains(info.CompanyName, "Microsoft") || Contains(info.ProductName, "Microsoft") || Contains(info.FileDescription, "Microsoft");
            bool normalMicrosoftPath = path.Contains("\\Windows\\", StringComparison.OrdinalIgnoreCase) || path.Contains("\\Program Files\\", StringComparison.OrdinalIgnoreCase);
            // Legit Microsoft tooling (Build Tools, NuGet packages, VS Code bits) lives under
            // dev/Electron containers and vendor dirs — don't treat that as masquerading.
            string pathLower = path.ToLowerInvariant();
            bool benign = PathTaxonomy.IsKnownBenignScriptContainer(pathLower) || PathTaxonomy.IsTrustedPath(pathLower);
            if (claimsMicrosoft && !normalMicrosoftPath && !benign)
                result.Add("Metadados alegam Microsoft fora de caminho comum do sistema", 1, EvidenceStrength.Low);

            if (string.IsNullOrWhiteSpace(info.CompanyName) && string.IsNullOrWhiteSpace(info.FileDescription) && string.IsNullOrWhiteSpace(info.ProductName))
                result.Add("PE sem metadados de versão descritivos", 0, EvidenceStrength.Info);
        }
        catch (UnauthorizedAccessException)
        {
            // Protected file - skip version-metadata heuristic and preserve scan flow.
        }
        catch (IOException)
        {
            // Locked/unreadable file - skip version-metadata heuristic and preserve scan flow.
        }
    }

    private static bool Contains(string? text, string token) =>
        !string.IsNullOrWhiteSpace(text) && text.Contains(token, StringComparison.OrdinalIgnoreCase);
}
