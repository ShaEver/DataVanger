using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using DataVanger.Infrastructure;
using DataVanger.Shared.Quarantine;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;
using MessageBoxResult = System.Windows.MessageBoxResult;

namespace DataVanger;

/// <summary>Asynchronous, operator-confirmed restore UX over Secure Quarantine V2.</summary>
public partial class QuarantineWindow : Window
{
    private readonly IQuarantineService _service;
    private readonly IQuarantineIndex _index;
    private readonly LegacyQuarantineInventory _legacyInventory;
    private readonly CancellationTokenSource _lifetimeCts = new();
    private readonly List<string> _recentOps = new();

    public string? RestoredId { get; private set; }
    public string? RestoredPath { get; private set; }

    private sealed record QRow(
        string Id,
        string OriginalPath,
        string QuarantinedAt,
        string Classification,
        string State,
        string Reasons,
        string? Sha256,
        long OriginalSize,
        bool IsAuthenticated);

    public QuarantineWindow(
        IQuarantineService service,
        IQuarantineIndex index,
        LegacyQuarantineInventory legacyInventory)
    {
        InitializeComponent();
        _service = service ?? throw new ArgumentNullException(nameof(service));
        _index = index ?? throw new ArgumentNullException(nameof(index));
        _legacyInventory = legacyInventory ?? throw new ArgumentNullException(nameof(legacyInventory));

        BtnRestore.Click += OnRestore;
        BtnClose.Click += (_, _) => Close();
        LvQuarantine.SelectionChanged += OnSelectionChanged;
        Loaded += OnLoaded;
        Closed += (_, _) =>
        {
            _lifetimeCts.Cancel();
            _lifetimeCts.Dispose();
        };
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        var legacy = _legacyInventory.Inspect();
        if (legacy.HasUnauthenticatedItems)
        {
            MessageBox.Show(
                $"Foram encontrados artefatos da quarentena legada não autenticada " +
                $"({legacy.PayloadCount} payload(s); índice presente: {(legacy.IndexPresent ? "sim" : "não")}).\n\n" +
                "Eles não podem ser restaurados automaticamente nem para o caminho original. " +
                "Mantenha-os isolados e faça remoção manual após revisão; somente itens V2 autenticados aparecem na lista restaurável.",
                "DataVanger — Quarentena legada não confiável",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }

        await RefreshAsync();
    }

    private async Task RefreshAsync()
    {
        BtnRestore.IsEnabled = false;
        try
        {
            var entries = await _index.ListAsync(_lifetimeCts.Token);
            var rows = new List<QRow>(entries.Count);
            foreach (var entry in entries)
            {
                _lifetimeCts.Token.ThrowIfCancellationRequested();
                var record = await _service.GetAsync(entry.QuarantineId, _lifetimeCts.Token);
                rows.Add(record is null
                    ? new QRow(entry.QuarantineId, "(metadados não autenticados)", entry.CreatedUtc.ToString("dd/MM/yyyy HH:mm"),
                        entry.ThreatClassification.ToString(), QuarantineRecordState.Corrupt.ToString(),
                        "Registro recusado pela verificação de autenticidade.", entry.OriginalSha256, 0, false)
                    : new QRow(record.QuarantineId, record.OriginalPath, record.CreatedUtc.ToString("dd/MM/yyyy HH:mm"),
                        record.ThreatClassification.ToString(), record.RecordState.ToString(), record.DetectionSummary,
                        record.OriginalSha256, record.OriginalSize, true));
            }

            LvQuarantine.ItemsSource = rows
                .OrderByDescending(row => row.QuarantinedAt)
                .ToList();
        }
        catch (OperationCanceledException)
        {
            // Closing the window cancels pending store reads.
        }
        finally
        {
            BtnRestore.IsEnabled = LvQuarantine.SelectedItem is QRow { IsAuthenticated: true };
        }
    }

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var row = LvQuarantine.SelectedItem as QRow;
        TxtDetail.Text = row is null ? "Selecione um item para ver os detalhes." : DescribeRecord(row);
        BtnRestore.IsEnabled = row?.IsAuthenticated == true;
    }

    private static string DescribeRecord(QRow row)
    {
        var sb = new StringBuilder();
        sb.Append("ID: ").AppendLine(row.Id);
        sb.Append("Caminho original: ").AppendLine(row.OriginalPath);
        sb.Append("SHA-256 original: ").AppendLine(string.IsNullOrWhiteSpace(row.Sha256) ? "Indisponível" : row.Sha256);
        sb.Append("Em quarentena em: ").AppendLine(row.QuarantinedAt);
        sb.Append("Classificação: ").Append(row.Classification)
            .Append("    Estado: ").AppendLine(row.State);
        sb.Append("Tamanho original: ").Append(row.OriginalSize).AppendLine(" bytes");
        sb.Append("Razões: ").Append(string.IsNullOrWhiteSpace(row.Reasons) ? "—" : row.Reasons);
        return sb.ToString();
    }

    private void AppendRecentOp(string id, QuarantineStatus status)
    {
        _recentOps.Insert(0, $"{DateTime.Now:HH:mm:ss}  Restaurar  {id}  ->  {status}");
        if (_recentOps.Count > 20) _recentOps.RemoveAt(_recentOps.Count - 1);
        TxtRecentOps.Text = string.Join("\n", _recentOps);
    }

    private async void OnRestore(object sender, RoutedEventArgs e)
    {
        if (LvQuarantine.SelectedItem is not QRow { IsAuthenticated: true } row)
        {
            MessageBox.Show("Selecione um item V2 autenticado para restaurar.", "DataVanger",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var confirm = MessageBox.Show(
            "Você está prestes a restaurar este item para o caminho original, sem sobrescrever arquivos existentes:\n\n" +
            row.OriginalPath + "\n\n" + DescribeRecord(row) + "\n\nDeseja continuar?",
            "DataVanger — Confirmar Restauração",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        BtnRestore.IsEnabled = false;
        QuarantineRestoreResult result;
        try
        {
            result = await _service.RestoreAsync(new QuarantineRestoreRequest
            {
                QuarantineId = row.Id,
                DestinationPath = null,
                AllowOverwrite = false,
            }, _lifetimeCts.Token);
        }
        catch (OperationCanceledException)
        {
            result = QuarantineRestoreResult.Failure(QuarantineStatus.Cancelled, "Operation cancelled.", row.Id);
        }
        catch (Exception)
        {
            result = QuarantineRestoreResult.Failure(QuarantineStatus.Unknown, "Unexpected restore failure.", row.Id);
        }

        AppendRecentOp(row.Id, result.Status);
        MessageBox.Show(
            QuarantineRestoreMessages.Describe(result.Status),
            "DataVanger",
            MessageBoxButton.OK,
            result.Status == QuarantineStatus.Success ? MessageBoxImage.Information : MessageBoxImage.Warning);

        if (result.Status == QuarantineStatus.Success && !string.IsNullOrWhiteSpace(result.RestoredPath))
        {
            RestoredId = row.Id;
            RestoredPath = result.RestoredPath;
            DialogResult = true;
            return;
        }

        await RefreshAsync();
    }
}

/// <summary>Pure mapping from structured V2 status to truthful operator text.</summary>
public static class QuarantineRestoreMessages
{
    public static string Describe(QuarantineStatus status) => status switch
    {
        QuarantineStatus.Success => "Restauração concluída com sucesso.",
        QuarantineStatus.IntegrityCheckFailed => "Restauração recusada: a integridade do conteúdo falhou. O item permanece em quarentena.",
        QuarantineStatus.AuthenticationFailed => "Restauração recusada: a autenticação criptográfica falhou. O item permanece em quarentena.",
        QuarantineStatus.MetadataTampered => "Restauração recusada: os metadados não são autênticos. O item permanece em quarentena.",
        QuarantineStatus.HashFailed => "Restauração recusada: o hash não corresponde ao registro autenticado. O item permanece em quarentena.",
        QuarantineStatus.RestorePathInvalid => "Restauração recusada: o destino falhou na política de caminhos. O item permanece em quarentena.",
        QuarantineStatus.RestoreTargetExists => "Restauração recusada: o destino já existe e não será sobrescrito. O item permanece em quarentena.",
        QuarantineStatus.RecordNotFound => "Restauração recusada: o registro autenticado não foi encontrado.",
        QuarantineStatus.PayloadMissing => "Restauração recusada: o payload está ausente. O item permanece em quarentena.",
        QuarantineStatus.PolicyDenied => "Restauração recusada pela política de quarentena. O item permanece em quarentena.",
        QuarantineStatus.Cancelled => "Restauração cancelada. O item permanece em quarentena.",
        QuarantineStatus.UnsupportedPlatform => "Restauração indisponível nesta plataforma. O item permanece em quarentena.",
        QuarantineStatus.RestoreFailed => "Restauração falhou ao gravar o destino. O item permanece em quarentena.",
        _ => "Restauração não concluída. O item permanece em quarentena; consulte a auditoria estruturada.",
    };
}
