using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace DataVanger.Core;

public static class ReportGenerator
{
    public static void WriteHtml(
        string path,
        List<ScanFinding> findings,
        ScanMetrics metrics,
        ScanOptions options,
        DateTime scanDate)
    {
        int crit = findings.Count(f => f.IsConfirmedMalware);
        int high = findings.Count(f => !f.IsConfirmedMalware && f.Score >= RiskThresholds.High);
        int susp = findings.Count(f => !f.IsConfirmedMalware && f.Score >= RiskThresholds.Suspect && f.Score < RiskThresholds.High);
        int clean = Math.Max(0, metrics.Eligible - findings.Count);

        var rows = new StringBuilder();
        if (findings.Count == 0)
        {
            rows.Append("<tr><td colspan=\"9\" style=\"text-align:center;color:#44bb44;padding:30px;font-size:16px\">" +
                        "&#10003; Nenhum item suspeito encontrado</td></tr>");
        }
        else
        {
            foreach (var r in findings)
            {
                string newBadge = r.IsNew
                    ? "<span style=\"background:#ff4444;color:#fff;padding:1px 6px;border-radius:3px;font-size:11px;margin-left:4px\">NOVO</span>"
                    : "";

                rows.Append($@"
<tr>
  <td>{Esc(r.FileName)} {newBadge}</td>
  <td style=""text-align:center;font-weight:bold;color:{r.RiskColor}"">{r.RiskLabel}</td>
  <td style=""font-size:11px;color:#bbb"">{Esc(r.ReputationSummary)}</td>
  <td style=""text-align:center"">{Esc(r.Extension)}</td>
  <td><code>{Esc(r.SHA256 ?? "")}</code></td>
  <td>{Esc(string.IsNullOrWhiteSpace(r.SignatureName) ? "-" : r.SignatureName)}</td>
  <td><code>{Esc(r.Path)}</code></td>
  <td>{Esc(r.RecommendedAction)}</td>
  <td style=""font-size:11px;color:#aaa""><details><summary>{Esc(r.Evidence.Count == 0 ? r.Reasons : $"{r.Evidence.Count} evidência(s)")}</summary>{EvidenceHtml(r)}</details></td>
  <td style=""font-size:11px;color:#888"">{r.LastWrite:dd/MM/yyyy HH:mm}</td>
</tr>");
            }
        }

        string newCardClass = metrics.NewFindings > 0 ? "red" : "green";

        // Phase 11 — Stage Performance Breakdown (when telemetry is enabled)
        string stageBreakdownSection = "";
        if (metrics.StageBreakdown.Count > 0)
        {
            var stageRows = new StringBuilder();
            foreach (var kvp in metrics.StageBreakdown.OrderByDescending(s => s.Value.Total.TotalSeconds))
            {
                var breakdown = kvp.Value;
                string p95Color = breakdown.P95.TotalMilliseconds > breakdown.Max.TotalMilliseconds * 0.8
                    ? "#ff8844"  // High tail skew (P95 near Max)
                    : "#88dd44"; // Healthy distribution

                stageRows.Append($@"
<tr>
  <td><b>{Esc(kvp.Key)}</b></td>
  <td style=""text-align:center"">{breakdown.Total.TotalSeconds:F2}s</td>
  <td style=""text-align:center"">{breakdown.Count}</td>
  <td style=""text-align:center"">{breakdown.FilesPerSecond:F2}</td>
  <td style=""text-align:center;font-size:11px;color:#aaa"">{breakdown.P50.TotalMilliseconds:F0}ms</td>
  <td style=""text-align:center;font-size:11px;color:{p95Color}"">{breakdown.P95.TotalMilliseconds:F0}ms</td>
  <td style=""text-align:center;font-size:11px;color:#ff6666"">{breakdown.Max.TotalMilliseconds:F0}ms</td>
  <td style=""text-align:center;font-size:11px;color:#bbb"">{breakdown.AvgFileSize / 1024.0:F0}KB</td>
</tr>");
            }

            stageBreakdownSection = $@"
<h2 style=""font-size:16px;color:#00ccff;margin-top:28px;margin-bottom:12px"">⏱ Análise de Performance por Stage</h2>
<p style=""font-size:12px;color:#888;margin-bottom:12px"">Distribuição de tempo por arquivo em cada estágio. P50 = mediana, P95 = percentil 95, Max = arquivo mais lento.</p>
<table style=""font-size:12px"">
  <thead>
    <tr><th>Stage</th><th>Tempo Total</th><th>Arquivos</th><th>Arquivos/s</th><th>P50</th><th>P95</th><th>Max</th><th>Tam. Médio</th></tr>
  </thead>
  <tbody>{stageRows}</tbody>
</table>";
        }

        string html = $@"<!DOCTYPE html>
<html lang=""pt-BR"">
<head>
<meta charset=""UTF-8"">
<meta name=""viewport"" content=""width=device-width,initial-scale=1.0"">
<title>{VersionInfo.DisplayName} — Relatório</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0d0d0d;color:#e0e0e0;font-family:'Segoe UI',sans-serif;padding:24px}}
  h1{{font-size:22px;color:#00ccff;margin-bottom:4px}}
  h2{{font-size:16px;color:#00ccff;margin-bottom:8px}}
  .sub{{color:#888;font-size:13px;margin-bottom:24px}}
  .cards{{display:flex;gap:16px;margin-bottom:28px;flex-wrap:wrap}}
  .card{{background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:16px 24px;min-width:140px}}
  .card .val{{font-size:32px;font-weight:bold}}
  .card .lbl{{font-size:12px;color:#888;margin-top:2px}}
  .card.red .val{{color:#ff4444}} .card.orange .val{{color:#ff8800}} .card.yellow .val{{color:#ffcc00}} .card.green .val{{color:#44bb44}} .card.blue .val{{color:#00ccff}}
  .toolbar{{display:flex;gap:12px;align-items:center;margin-bottom:16px;flex-wrap:wrap}}
  .toolbar input,.toolbar select{{background:#1a1a1a;border:1px solid #333;color:#ddd;padding:7px 12px;border-radius:6px;font-size:13px}}
  .toolbar input{{width:260px}}
  #rowcount{{font-size:12px;color:#777;margin-left:auto}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  thead th{{background:#1a1a2e;color:#00ccff;padding:10px 12px;text-align:left;font-size:12px;text-transform:uppercase;border-bottom:2px solid #00ccff44;cursor:pointer;user-select:none}}
  thead th:hover{{background:#1e1e3a}}
  tbody tr{{border-bottom:1px solid #222}}
  tbody tr:hover{{background:#1a1a1a}}
  tbody td{{padding:9px 12px;vertical-align:middle}}
  tbody tr.hidden{{display:none}}
  code{{font-size:11px;word-break:break-all;color:#ddd}}
  .tele{{background:#111;border:1px solid #333;border-radius:6px;padding:14px 18px;margin-top:28px;font-size:12px;color:#888;columns:2;column-gap:32px}}
  .tele span{{color:#ccc}}
  .footer{{margin-top:28px;color:#555;font-size:11px;text-align:center}}
</style>
<script>
function applyFilters(){{
  var q = document.getElementById('search').value.toLowerCase();
  var risk = document.getElementById('riskFilter').value;
  var rows = document.querySelectorAll('tbody tr');
  var vis = 0;
  rows.forEach(function(r){{
    if (r.cells.length < 2) return;
    var blob = r.textContent.toLowerCase();
    var label = (r.cells[1]?.textContent||'').trim();
    var show = (!q || blob.includes(q)) && (!risk || label === risk);
    r.classList.toggle('hidden', !show);
    if(show) vis++;
  }});
  document.getElementById('rowcount').textContent = vis + ' arquivo(s)';
}}
function sortTable(col){{
  var tbody = document.querySelector('tbody');
  var rows = Array.from(tbody.rows).filter(r=>r.cells.length>1);
  var asc = tbody.dataset.sortCol == col && tbody.dataset.sortDir !== 'asc';
  tbody.dataset.sortCol = col; tbody.dataset.sortDir = asc ? 'asc' : 'desc';
  rows.sort(function(a,b){{
    var av = (a.cells[col]?.textContent||'').trim();
    var bv = (b.cells[col]?.textContent||'').trim();
    var an = parseFloat(av), bn = parseFloat(bv);
    var cmp = isNaN(an)||isNaN(bn) ? av.localeCompare(bv) : an-bn;
    return asc ? cmp : -cmp;
  }});
  rows.forEach(function(r){{ tbody.appendChild(r); }});
}}
window.onload = function(){{
  document.querySelectorAll('thead th').forEach(function(th,i){{ th.onclick = function(){{ sortTable(i); }}; }});
  applyFilters();
}};
</script>
</head>
<body>
<h1>&#x1F6E1; {VersionInfo.DisplayName}</h1>
<div class=""sub"">Relatório de auditoria &mdash; {scanDate:dd/MM/yyyy HH:mm:ss} &mdash; Perfil: {options.Profile} &mdash; Tempo: {metrics.TotalTime.TotalSeconds:F2}s</div>
<div class=""cards"">
  <div class=""card red""><div class=""val"">{crit}</div><div class=""lbl"">Malware confirmado</div></div>
  <div class=""card orange""><div class=""val"">{high}</div><div class=""lbl"">Alto risco heurístico</div></div>
  <div class=""card yellow""><div class=""val"">{susp}</div><div class=""lbl"">Suspeitos/revisão</div></div>
  <div class=""card green""><div class=""val"">{clean}</div><div class=""lbl"">Limpo/Baixo</div></div>
  <div class=""card {newCardClass}""><div class=""val"">{metrics.NewFindings}</div><div class=""lbl"">Novos</div></div>
  <div class=""card blue""><div class=""val"">{metrics.Eligible}</div><div class=""lbl"">Arquivos analisados</div></div>
</div>
<div style=""background:#111;border:1px solid #333;border-left:4px solid #00ccff;border-radius:8px;padding:12px 16px;margin:-12px 0 18px 0;color:#bbb;font-size:13px"">
  <b>Modo rigoroso:</b> &quot;CRÍTICO&quot; significa malware confirmado por assinatura/hash conhecido. Heurísticas fortes aparecem como alto risco para revisão, sem quarentena automática.
</div>
<div class=""toolbar"">
  <input id=""search"" type=""text"" placeholder=""Buscar por nome, hash, caminho..."" oninput=""applyFilters()""/>
  <select id=""riskFilter"" onchange=""applyFilters()"">
    <option value="""">Todos os riscos</option>
    <option value=""CRÍTICO"">Crítico</option>
    <option value=""ALTO RISCO"">Alto Risco</option>
    <option value=""SUSPEITO"">Suspeito</option>
    <option value=""LIMPO"">Limpo</option>
  </select>
  <span id=""rowcount""></span>
</div>
<table>
  <thead>
    <tr><th>Nome do arquivo</th><th>Risco</th><th>Reputação</th><th>Tipo</th><th>Hash</th><th>Assinatura</th><th>Caminho</th><th>Ação recomendada</th><th>Motivos</th><th>Modificado</th></tr>
  </thead>
  <tbody>{rows}</tbody>
</table>
<div class=""tele"">
  <div><span>Targets varridos:</span> {metrics.Targets}</div>
  <div><span>Arquivos elegíveis:</span> {metrics.Eligible}</div>
  <div><span>Estimativa de progresso:</span> {metrics.TotalEstimate}</div>
  <div><span>Acesso negado:</span> {metrics.AccessDenied}</div>
  <div><span>Ignorados por cache limpo:</span> {metrics.SkippedCacheClean}</div>
  <div><span>Hashes calculados:</span> {metrics.HashComputed}</div>
  <div><span>Hits de cache SHA256:</span> {metrics.HashCacheHits}</div>
  <div><span>Hashes de assinatura:</span> {metrics.SignatureHashesLoaded}</div>
  <div><span>Regras YARA leves:</span> {metrics.YaraRulesLoaded}</div>
  <div><span>Arquivos checados por YARA:</span> {metrics.YaraScanned}</div>
  <div><span>Hits de YARA:</span> {metrics.YaraHits}</div>
  <div><span>Compactados checados:</span> {metrics.ArchiveChecked}</div>
  <div><span>Hits em compactados:</span> {metrics.ArchiveHits}</div>
  <div><span>Documentos checados:</span> {metrics.DocumentChecked}</div>
  <div><span>Hits em documentos:</span> {metrics.DocumentHits}</div>
  <div><span>Manifestos de extensões:</span> {metrics.BrowserExtensionChecked}</div>
  <div><span>Hits em extensões:</span> {metrics.BrowserExtensionHits}</div>
  <div><span>Malware conhecido:</span> {metrics.KnownMalwareHits}</div>
  <div><span>Autoquarentena:</span> {metrics.AutoQuarantined}</div>
  <div><span>Assinaturas verificadas:</span> {metrics.SigChecked}</div>
  <div><span>Entropia verificada:</span> {metrics.EntropyChecked}</div>
  <div><span>ADS verificados:</span> {metrics.AdsChecked}</div>
  <div><span>Scripts inspecionados:</span> {metrics.ScriptInspected}</div>
  <div><span>Processos cruzados:</span> {metrics.RunningProcesses}</div>
  <div><span>Achados com processo ativo:</span> {metrics.RunningProcessHits}</div>
  <div><span>Persistências:</span> {metrics.PersistenceItems}</div>
  <div><span>Erros:</span> {metrics.Errors}</div>
  <div><span>Tempo scan:</span> {metrics.ScanTime.TotalSeconds:F2}s</div>
  <div><span>Velocidade média:</span> {metrics.FilesPerSecond:F2} arquivos/s</div>
</div>
{stageBreakdownSection}
<div class=""footer"">{VersionInfo.DisplayName} &mdash; Ferramenta de auditoria pessoal &mdash; {scanDate:dd/MM/yyyy HH:mm:ss}</div>
</body></html>";

        File.WriteAllText(path, html, Encoding.UTF8);
    }

    public static void WriteJson(
        string path,
        List<ScanFinding> findings,
        ScanMetrics metrics,
        ScanOptions options,
        DateTime scanDate)
    {
        try
        {
            var payload = new
            {
                product = VersionInfo.ProductName,
                version = VersionInfo.Version,
                fullVersion = VersionInfo.FullVersion,
                scanDate,
                profile = options.Profile.ToString(),
                durationSeconds = metrics.TotalTime.TotalSeconds,
                metrics,
                counts = new
                {
                    confirmed = findings.Count(f => f.IsConfirmedMalware),
                    highRisk = findings.Count(f => !f.IsConfirmedMalware && f.Score >= RiskThresholds.High),
                    suspicious = findings.Count(f => !f.IsConfirmedMalware && f.Score >= RiskThresholds.Suspect && f.Score < RiskThresholds.High),
                    cleanOrLowRisk = Math.Max(0, metrics.Eligible - findings.Count)
                },
                topRiskCategories = findings
                    .SelectMany(f => f.Evidence)
                    .GroupBy(e => e.Category, StringComparer.OrdinalIgnoreCase)
                    .OrderByDescending(g => g.Count())
                    .Take(10)
                    .Select(g => new { category = g.Key, count = g.Count() }),
                findings = findings.Select(f => new
                {
                    path = f.Path,
                    fileName = f.FileName,
                    extension = f.Extension,
                    sizeKB = f.SizeKB,
                    sha256 = f.SHA256,
                    classification = f.RiskLabel,
                    score = f.Score,
                    reputation = new
                    {
                        state = f.ReputationState.ToString(),
                        score = f.ReputationScore,
                        delta = f.ReputationScoreDelta,
                        seenCount = f.ReputationSeenCount,
                        firstSeenUtc = f.ReputationFirstSeenUtc,
                        lastSeenUtc = f.ReputationLastSeenUtc,
                        signerStatus = f.ReputationSignerStatus,
                        userDecision = f.ReputationUserDecision,
                        reasons = f.ReputationReasons
                    },
                    isSigned = f.IsSigned,
                    publisher = f.Publisher,
                    signatureName = f.SignatureName,
                    isNew = f.IsNew,
                    isBlacklisted = f.IsBlacklisted,
                    hasConfirmedSignature = f.HasConfirmedSignature,
                    wasQuarantined = f.WasQuarantined,
                    recommendedAction = f.RecommendedAction,
                    evidence = f.Evidence.Count == 0 ? EvidenceService.FromReasons(f.Reasons.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)) : f.Evidence,
                    lastWrite = f.LastWrite
                })
            };

            var opts = new JsonSerializerOptions { WriteIndented = true };
            File.WriteAllText(path, JsonSerializer.Serialize(payload, opts), Encoding.UTF8);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Report artifact failed to persist - make the failure observable without aborting the scan.
            System.Diagnostics.Debug.WriteLine($"[DataVanger] Failed to write JSON report '{path}': {ex.Message}");
        }
    }

    private static string Esc(string? s) =>
        (s ?? "").Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");

    private static string EvidenceHtml(ScanFinding finding)
    {
        var evidence = finding.Evidence.Count == 0
            ? EvidenceService.FromReasons(finding.Reasons.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            : finding.Evidence;
        if (evidence.Count == 0) return Esc(finding.Reasons);
        var sb = new StringBuilder("<ul style=\"margin:6px 0 0 16px;padding:0\">");
        foreach (var e in evidence)
            sb.Append($"<li><b>{Esc(e.Category)}</b>: {Esc(e.Description)} <span style=\"color:#777\">{e.Strength}, {e.ScoreDelta:+#;-#;0}</span></li>");
        sb.Append("</ul>");
        return sb.ToString();
    }
}
