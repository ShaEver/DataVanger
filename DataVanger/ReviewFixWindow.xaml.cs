using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using DataVanger.Core;
using DataVanger.Reputation;
using Clipboard = System.Windows.Clipboard;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;
using MessageBoxResult = System.Windows.MessageBoxResult;

namespace DataVanger;

public partial class ReviewFixWindow : Window
{
    private readonly ScanEngine _engine;
    private readonly ObservableCollection<ReviewRow> _rows = new();

    /// <summary>True quando alguma ação (quarentena/whitelist) foi efetivamente aplicada.</summary>
    public bool ChangesApplied { get; private set; }

    public IReadOnlyList<string> ActionOptions => ReviewActionLabels.All;

    public ReviewFixWindow(IEnumerable<ScanFinding> findings, ScanEngine engine)
    {
        InitializeComponent();
        _engine = engine;
        DataContext = this;

        foreach (var f in findings.Where(f => !f.WasQuarantined)
                                   .OrderByDescending(f => f.Score))
            _rows.Add(new ReviewRow(f));

        DgReview.ItemsSource = _rows;

        BtnApply.Click += OnApply;
        BtnClose.Click += (_, _) => Close();
        BtnOpenLocation.Click += OnOpenLocation;
        BtnCopyHash.Click += OnCopyHash;
        BtnDetails.Click += OnDetails;
    }

    private ReviewRow? Current => DgReview.SelectedItem as ReviewRow;

    private void OnOpenLocation(object sender, RoutedEventArgs e)
    {
        var row = Current;
        if (row == null) { MessageBox.Show("Selecione um item.", "DataVanger", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        try
        {
            if (File.Exists(row.Finding.Path))
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{row.Finding.Path}\"") { UseShellExecute = true });
            else
                MessageBox.Show("O arquivo não existe mais nesse caminho.", "DataVanger", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Não foi possível abrir o local: {ex.Message}", "DataVanger", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnCopyHash(object sender, RoutedEventArgs e)
    {
        var row = Current;
        if (row == null) { MessageBox.Show("Selecione um item.", "DataVanger", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        if (string.IsNullOrWhiteSpace(row.Finding.SHA256))
        {
            MessageBox.Show("Este item não possui hash SHA256 calculado.", "DataVanger", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        try { Clipboard.SetText(row.Finding.SHA256!); }
        catch (System.Exception) { /* clipboard pode falhar em sessões sem área de transferência */ }
    }

    private void OnDetails(object sender, RoutedEventArgs e)
    {
        var row = Current;
        if (row == null) { MessageBox.Show("Selecione um item.", "DataVanger", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        var f = row.Finding;
        var sb = new StringBuilder();
        sb.AppendLine($"Arquivo   : {f.FileName}");
        sb.AppendLine($"Caminho   : {f.Path}");
        sb.AppendLine($"Risco     : {f.RiskLabel} (score {f.Score})");
        sb.AppendLine($"SHA256    : {f.SHA256 ?? "(não calculado)"}");
        sb.AppendLine($"Assinado  : {(f.IsSigned ? "sim" : "não")}");
        sb.AppendLine($"Publisher : {(string.IsNullOrWhiteSpace(f.Publisher) ? "(nenhum)" : f.Publisher)}");
        sb.AppendLine($"Tamanho   : {f.SizeKB} KB");
        sb.AppendLine($"Modificado: {f.LastWrite:dd/MM/yyyy HH:mm}");
        sb.AppendLine($"Ação reco.: {f.RecommendedAction}");
        sb.AppendLine($"Reputação : {f.ReputationSummary}");
        sb.AppendLine();
        sb.AppendLine("Motivos:");
        foreach (var reason in f.Reasons.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            sb.AppendLine($"  - {reason}");
        new TextViewerWindow("DataVanger — Detalhes do achado", sb.ToString()) { Owner = this }.ShowDialog();
    }

    private void OnApply(object sender, RoutedEventArgs e)
    {
        var selected = _rows.Where(r => r.Selected).ToList();
        if (selected.Count == 0)
        {
            MessageBox.Show("Marque ao menos um item na coluna 'Aplicar'.", "DataVanger", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        int toQuarantine = selected.Count(r => ReviewActionLabels.FromLabel(r.Action) == ReviewAction.Quarantine);
        int toWhitelist  = selected.Count(r => ReviewActionLabels.FromLabel(r.Action) == ReviewAction.Whitelist);
        int toIgnore     = selected.Count - toQuarantine - toWhitelist;

        var confirm = MessageBox.Show(
            $"Aplicar ações em {selected.Count} item(ns)?\n\n" +
            $"  • Quarentenar : {toQuarantine}\n" +
            $"  • Whitelist   : {toWhitelist}\n" +
            $"  • Ignorar     : {toIgnore}\n\n" +
            "Itens quarentenados podem ser restaurados depois. Nada é apagado definitivamente agora.",
            "DataVanger — Confirmar Ações", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        var qm = new QuarantineManager(_engine.QuarantineRoot, _engine.QIndexPath);
        int quarantined = 0, whitelisted = 0, failed = 0;
        var whitelistHashes = new List<string>();

        foreach (var row in selected)
        {
            switch (ReviewActionLabels.FromLabel(row.Action))
            {
                case ReviewAction.Quarantine:
                    if (qm.Quarantine(row.Finding) != null)
                    {
                        row.Finding.WasQuarantined = true;
                        quarantined++;
                    }
                    else failed++;
                    break;

                case ReviewAction.Whitelist:
                    if (!string.IsNullOrWhiteSpace(row.Finding.SHA256))
                    {
                        whitelistHashes.Add(row.Finding.SHA256!.Trim().ToUpperInvariant());
                        whitelisted++;
                    }
                    else failed++;
                    break;
            }
        }

        if (whitelistHashes.Count > 0)
        {
            AppendWhitelist(whitelistHashes);
            var reputation = new LocalReputationDatabase(_engine.ReputationPath);
            foreach (var h in whitelistHashes)
                reputation.MarkUserDecision(h, ReputationUserDecision.Allowed, "Usuário adicionou à whitelist pela Central de Ações");
            reputation.Save();
        }

        if (quarantined > 0 || whitelisted > 0) ChangesApplied = true;

        foreach (var done in selected.Where(r =>
                     r.Finding.WasQuarantined ||
                     ReviewActionLabels.FromLabel(r.Action) == ReviewAction.Whitelist).ToList())
            _rows.Remove(done);

        MessageBox.Show(
            $"Concluído.\n\nQuarentenados: {quarantined}\nAdicionados à whitelist: {whitelisted}\nFalhas: {failed}",
            "DataVanger", MessageBoxButton.OK, MessageBoxImage.Information);

        if (_rows.Count == 0) Close();
    }

    private void AppendWhitelist(IEnumerable<string> hashes)
    {
        try
        {
            string path = Path.Combine(_engine.SignatureRoot, "user_whitelist_sha256.txt");
            var existing = File.Exists(path)
                ? new HashSet<string>(File.ReadAllLines(path).Select(l => l.Trim().ToUpperInvariant()), StringComparer.OrdinalIgnoreCase)
                : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var fresh = hashes.Where(h => h.Length == 64 && existing.Add(h)).ToList();
            if (fresh.Count > 0) File.AppendAllLines(path, fresh, Encoding.UTF8);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Não foi possível gravar a whitelist: {ex.Message}", "DataVanger", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}

/// <summary>Linha editável da Central de Ações: envolve um achado e sua ação sugerida.</summary>
public sealed class ReviewRow
{
    public ReviewRow(ScanFinding finding)
    {
        Finding = finding;
        Action = ReviewActionLabels.ToLabel(ThreatClassificationPolicy.SuggestedReviewAction(finding));
        Selected = finding.Classification is ThreatClass.ConfirmedMalware or ThreatClass.HighRisk;
    }

    public ScanFinding Finding { get; }
    public bool Selected { get; set; }
    public string Action { get; set; }

    public string FileName => Finding.FileName;
    public string RiskLabel => Finding.RiskLabel;
    public int Score => Finding.Score;
    public string Path => Finding.Path;
}
