using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using DataVanger.Core;
using DataVanger.Shared.Quarantine;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;
using MessageBoxResult = System.Windows.MessageBoxResult;

namespace DataVanger;

// Phase 19 — operator-confirmed, integrity-verified, audited restore UX over the
// existing Quarantine flow. UX only: this window never decrypts/copies/writes payloads
// itself — it always calls the existing QuarantineManager.Restore(...) which owns the
// integrity/HMAC/hash/path verification. It only displays metadata, requires explicit
// confirmation, maps the result to a safe message, and shows recent session operations.
public partial class QuarantineWindow : Window
{
    private readonly QuarantineManager _qm;
    private readonly List<string> _recentOps = new();
    public string? RestoredId   { get; private set; }
    public string? RestoredPath { get; private set; }

    private record QRow(
        string Id, string OriginalPath, string QuarantinedAt, int Score, string Reasons,
        string? Sha256, long OriginalSize);

    public QuarantineWindow(QuarantineManager qm)
    {
        InitializeComponent();
        _qm = qm;

        BtnRestore.Click += OnRestore;
        BtnClose.Click   += (_, _) => Close();  // DialogResult permanece null = cancelado
        LvQuarantine.SelectionChanged += OnSelectionChanged;

        Refresh();
    }

    private void Refresh()
    {
        var index = _qm.List();
        LvQuarantine.ItemsSource = index
            .Select(kv => new QRow(
                kv.Key,
                kv.Value.OriginalPath,
                kv.Value.QuarantinedAt.ToString("dd/MM/yyyy HH:mm"),
                kv.Value.Score,
                kv.Value.Reasons,
                kv.Value.SHA256,
                kv.Value.OriginalSize))
            .OrderByDescending(r => r.Score)
            .ToList();
    }

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        TxtDetail.Text = LvQuarantine.SelectedItem is QRow row
            ? DescribeRecord(row)
            : "Selecione um item para ver os detalhes.";
    }

    // Read-only metadata for the selected record. Never exposes the internal quarantine
    // storage path, keys, or payload content — only operator-relevant, already-safe fields.
    private static string DescribeRecord(QRow row)
    {
        var sb = new StringBuilder();
        sb.Append("ID: ").AppendLine(row.Id);
        sb.Append("Caminho original: ").AppendLine(row.OriginalPath);
        sb.Append("SHA-256 original: ").AppendLine(string.IsNullOrWhiteSpace(row.Sha256) ? "Indisponível" : row.Sha256);
        sb.Append("Em quarentena em: ").AppendLine(row.QuarantinedAt);
        sb.Append("Score: ").Append(row.Score)
          .Append("    Tamanho original: ").Append(row.OriginalSize).AppendLine(" bytes");
        sb.Append("Razões: ").Append(string.IsNullOrWhiteSpace(row.Reasons) ? "—" : row.Reasons);
        return sb.ToString();
    }

    private void AppendRecentOp(string id, string result)
    {
        _recentOps.Insert(0, $"{DateTime.Now:HH:mm:ss}  Restaurar  {id}  ->  {result}");
        if (_recentOps.Count > 20) _recentOps.RemoveAt(_recentOps.Count - 1);
        TxtRecentOps.Text = string.Join("\n", _recentOps);
    }

    private void OnRestore(object sender, RoutedEventArgs e)
    {
        if (LvQuarantine.SelectedItem is not QRow row)
        {
            MessageBox.Show("Selecione um item para restaurar.", "DataVanger",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        // Explicit, non-alarming confirmation that states the restore is manual and that
        // the existing restore flow enforces integrity/path/hash verification.
        var confirm = MessageBox.Show(
            "Você está prestes a restaurar este item de quarentena para o caminho original:\n\n" +
            row.OriginalPath + "\n\n" +
            "A restauração grava o arquivo de volta no disco. As verificações de integridade, " +
            "caminho e hash são aplicadas pelo fluxo de restauração da Quarentena. A restauração " +
            "é manual — nunca automática.\n\n" +
            "Detalhes do item:\n" + DescribeRecord(row) + "\n\n" +
            "Deseja continuar?",
            "DataVanger — Confirmar Restauração",
            MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        bool ok;
        try
        {
            // The service is the authority: it verifies integrity/HMAC/hash/path and only
            // then restores. A false/failed result leaves the item quarantined.
            ok = _qm.Restore(row.Id);
        }
        catch (Exception)
        {
            AppendRecentOp(row.Id, "Erro inesperado");
            MessageBox.Show("Falha inesperada na restauração. O item permanece em quarentena.",
                "DataVanger", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        AppendRecentOp(row.Id, ok ? "Sucesso" : "Recusada/Falha (item mantido em quarentena)");

        if (ok)
        {
            RestoredId   = row.Id;
            RestoredPath = row.OriginalPath;
            MessageBox.Show(QuarantineRestoreMessages.DescribeBool(true), "DataVanger",
                MessageBoxButton.OK, MessageBoxImage.Information);
            DialogResult = true;  // fecha automaticamente no ShowDialog()
        }
        else
        {
            MessageBox.Show(QuarantineRestoreMessages.DescribeBool(false), "DataVanger",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            Refresh();
        }
    }
}

/// <summary>
/// Phase 19 — pure, secret-free mapping from a restore outcome to a safe operator message.
/// No I/O, no security decisions: it only describes a result the Quarantine service already
/// produced. Failure descriptions always state the item remains quarantined and never expose
/// keys, HMAC material, plaintext, internal paths, or exception details/stack traces.
/// </summary>
public static class QuarantineRestoreMessages
{
    /// <summary>Maps a Quarantine V2 <see cref="QuarantineStatus"/> to a safe message.</summary>
    public static string Describe(QuarantineStatus status) => status switch
    {
        QuarantineStatus.Success
            => "Restauração concluída com sucesso.",
        QuarantineStatus.IntegrityCheckFailed
            => "Restauração recusada: a verificação de integridade do conteúdo em quarentena falhou. O item permanece em quarentena.",
        QuarantineStatus.AuthenticationFailed
            => "Restauração recusada: a autenticação criptográfica do item falhou. O item permanece em quarentena.",
        QuarantineStatus.MetadataTampered
            => "Restauração recusada: os metadados do item foram adulterados. O item permanece em quarentena.",
        QuarantineStatus.HashFailed
            => "Restauração recusada: o hash não corresponde ao hash original registrado. O item permanece em quarentena.",
        QuarantineStatus.RestorePathInvalid
            => "Restauração recusada: o caminho de destino falhou na validação de segurança. O item permanece em quarentena.",
        QuarantineStatus.RestoreTargetExists
            => "Restauração recusada: já existe um arquivo no caminho de destino. O item permanece em quarentena.",
        QuarantineStatus.RecordNotFound
            => "Restauração recusada: o registro de quarentena não foi encontrado.",
        QuarantineStatus.PayloadMissing
            => "Restauração recusada: o conteúdo em quarentena não foi encontrado. O item permanece em quarentena.",
        QuarantineStatus.PolicyDenied
            => "Restauração recusada pela política de quarentena.",
        QuarantineStatus.Cancelled
            => "Restauração cancelada. O item permanece em quarentena.",
        QuarantineStatus.UnsupportedPlatform
            => "Restauração indisponível nesta plataforma. O item permanece em quarentena.",
        _   => "Falha na restauração. Consulte os detalhes de auditoria. O item permanece em quarentena.",
    };

    /// <summary>
    /// The current window uses QuarantineManager.Restore(id) -> bool; map that boolean to
    /// the same safe vocabulary. A failure always keeps the item quarantined.
    /// </summary>
    public static string DescribeBool(bool success) => success
        ? Describe(QuarantineStatus.Success)
        : "Restauração não concluída: o item permanece em quarentena. As verificações de integridade, caminho e hash são aplicadas pelo fluxo de restauração da Quarentena; consulte os detalhes/auditoria.";
}
