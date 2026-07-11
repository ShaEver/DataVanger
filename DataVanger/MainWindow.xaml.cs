using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Threading;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;
using MessageBoxResult = System.Windows.MessageBoxResult;
using DataVanger.Core;
using DataVanger.Engine;
using DataVanger.Infrastructure;
using DataVanger.Shell;
using DataVanger.Shared.Quarantine;

namespace DataVanger;

public partial class MainWindow : Window
{
    private readonly ScanEngine _engine = new();
    private readonly CleanerEngine _cleaner = new();
    private readonly RealtimeMonitor _monitor = new();
    private readonly Services.ServiceConnectionViewModel _serviceConnection = new();
    private readonly ObservableCollection<ScanFinding> _threats = new();
    private readonly ObservableCollection<CleanerItem> _cleanerItems = new();

    private CancellationTokenSource? _cts;
    private readonly CancellationTokenSource _quarantineLifetimeCts = new();
    private DispatcherTimer? _timer;
    private DispatcherTimer? _resourceTimer;
    private DateTime _scanStart;
    private DateTime _lastCpuSampleAt = DateTime.Now;
    private TimeSpan _lastCpuTime = TimeSpan.Zero;
    private List<ScanFinding> _lastFindings = new();
    private readonly object _progressUiLock = new();

    // Phase 07 live wiring: persistent history + tray status. Initialized in the
    // constructor (after _engine) since field initializers cannot reference _engine.
    private DataVanger.Shared.History.HistoryStore? _history;
    private Services.ScanHistoryRecorder? _historyRecorder;
    private Services.TrayIconHost? _trayHost;
    private DateTime _lastProgressUiUpdate = DateTime.MinValue;
    private int _scanRunId;

    // Shell Beta 01A — estado de navegação (estrutural apenas; nenhum
    // comportamento de engine/serviço/quarentena muda por navegação).
    private readonly ShellNavigationViewModel _shellNav = new();
    private Dictionary<ShellSection, System.Windows.Controls.Button> _navButtons = new();
    private static readonly System.Windows.Media.Brush NavSelectedBrush =
        new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x16, 0x24, 0x2c));
    private static readonly System.Windows.Media.Brush NavIdleBrush =
        System.Windows.Media.Brushes.Transparent;

    // Theme Toggle State
    private bool _isDarkMode = false;


    public MainWindow()
    {
        InitializeComponent();

        if (CmbProfile.Items.Count == 0)
        {
            CmbProfile.Items.Add("Fast Scan");
            CmbProfile.Items.Add("Deep Scan");
        }
        CmbProfile.SelectedIndex = 1;

        DgThreats.ItemsSource = _threats;
        DgCleaner.ItemsSource = _cleanerItems;

        BtnScan.Click += OnScan;
        BtnStop.Click += OnStop;
        BtnRestore.Click += OnRestore;
        BtnSchedule.Click += OnSchedule;
        BtnViewPersist.Click += OnViewPersist;
        BtnUpdateSignatures.Click += OnUpdateSignatures;
        BtnSettings.Click += OnSettings;
        BtnModuleStatus.Click += OnModuleStatus;
        BtnDiagnostics.Click += OnDiagnostics;
        BtnOpenFolder.Click += OnOpenFolder;
        BtnOpenReport.Click += OnOpenReport;
        BtnClearLog.Click += (_, _) => TxtLog.Clear();
        BtnAnalyzeClean.Click += OnAnalyzeClean;
        BtnRunClean.Click += OnRunClean;
        BtnToggleRealtime.Click += OnToggleRealtime;
        BtnReviewFix.Click += OnReviewFix;
        BtnRemovalCenter.Click += OnRemovalCenter;
        BtnThemeToggle.Click += OnThemeToggle;
        CmbRiskFilter.SelectionChanged += (_, _) => ApplyThreatFilter();

        _monitor.SuspiciousFileCreated += OnRealtimeSuspiciousFile;
        Closed += (_, _) =>
        {
            _trayHost?.Dispose();
            _monitor.Dispose();
            _resourceTimer?.Stop();
            _timer?.Stop();
            _cts?.Cancel();
            _cts?.Dispose();
            _quarantineLifetimeCts.Cancel();
            _quarantineLifetimeCts.Dispose();
        };

        InitializeShellNavigation();

        UpdateCounters();
        UpdateLastScan();
        StartResourceTimer();
        InitializeServiceConnectionIndicator();

        // Phase 07 live wiring: persistent history + a single, honest tray status icon.
        _history = new DataVanger.Shared.History.HistoryStore(System.IO.Path.Combine(_engine.MgRoot, "history.json"));
        _historyRecorder = new Services.ScanHistoryRecorder(_history);
        _trayHost = Services.TrayIconHost.TryCreate(ShowAndActivate, ShowServiceStatus, () => Close());
        UpdateTrayStatus();

        AppendLog("[GUI] Pronto. Escolha o perfil e clique em Iniciar Scan.");
    }

    /// <summary>
    /// Shell Beta 01A: liga a barra de navegação aos fluxos Alpha existentes.
    /// Itens "Hosted" trocam a região de conteúdo (Home/painéis finos); itens
    /// "Launcher" abrem as mesmas janelas modais pelos manipuladores originais.
    /// Os botões originais do painel continuam funcionando sem alteração.
    /// </summary>
    private void InitializeShellNavigation()
    {
        _navButtons = new Dictionary<ShellSection, System.Windows.Controls.Button>
        {
            [ShellSection.Dashboard]   = NavDashboard,
            [ShellSection.Scan]        = NavScan,
            [ShellSection.Protection]  = NavProtection,
            [ShellSection.Threats]     = NavThreats,
            [ShellSection.Quarantine]  = NavQuarantine,
            [ShellSection.Reports]     = NavReports,
            [ShellSection.Updates]     = NavUpdates,
            [ShellSection.Settings]    = NavSettings,
            [ShellSection.Diagnostics] = NavDiagnostics,
        };

        foreach (var pair in _navButtons)
        {
            var section = pair.Key;
            pair.Value.Click += (_, _) => NavigateToSection(section);
        }

        _shellNav.LauncherRequested += OnShellLauncherRequested;

        // Painéis finos: mesmos manipuladores dos botões já existentes.
        BtnNavOpenFolder.Click += OnOpenFolder;
        BtnNavOpenReport.Click += OnOpenReport;
        BtnNavViewPersist.Click += OnViewPersist;
        BtnNavUpdateSignatures.Click += OnUpdateSignatures;
        BtnNavModuleStatus.Click += OnModuleStatus;
        BtnNavDiagnostics.Click += OnDiagnostics;

        ApplyShellSelection();
    }

    private void NavigateToSection(ShellSection section)
    {
        if (_shellNav.TrySelect(section))
            ApplyShellSelection();
    }

    private void OnShellLauncherRequested(ShellSection section)
    {
        // Mesmo caminho de código dos botões da coluna AÇÕES — o shell não
        // adiciona comportamento novo.
        switch (section)
        {
            case ShellSection.Quarantine:
                OnRestore(this, new RoutedEventArgs());
                break;
            case ShellSection.Settings:
                OnSettings(this, new RoutedEventArgs());
                break;
        }
    }

    private void ApplyShellSelection()
    {
        var section = _shellNav.SelectedSection;

        bool homeVisible = section is ShellSection.Dashboard or ShellSection.Scan
                                      or ShellSection.Protection or ShellSection.Threats;
        ViewHome.Visibility        = homeVisible ? Visibility.Visible : Visibility.Collapsed;
        ViewReports.Visibility     = section == ShellSection.Reports ? Visibility.Visible : Visibility.Collapsed;
        ViewUpdates.Visibility     = section == ShellSection.Updates ? Visibility.Visible : Visibility.Collapsed;
        ViewDiagnostics.Visibility = section == ShellSection.Diagnostics ? Visibility.Visible : Visibility.Collapsed;

        // Selection highlight pulls from the active theme so it stays legible in
        // both light and dark modes (BrushBgTertiary is a subtle, theme-aware tint).
        var appResources = System.Windows.Application.Current?.Resources ?? Resources;
        var selectedBrush = appResources["BrushBgTertiary"] as System.Windows.Media.Brush ?? NavSelectedBrush;
        foreach (var pair in _navButtons)
            pair.Value.Background = pair.Key == section ? selectedBrush : NavIdleBrush;

        // Foco de conveniência dentro da visão Home (apenas foco — nenhuma ação).
        switch (section)
        {
            case ShellSection.Scan:
                BtnScan.Focus();
                break;
            case ShellSection.Protection:
                BtnToggleRealtime.BringIntoView();
                BtnToggleRealtime.Focus();
                break;
            case ShellSection.Threats:
                DgThreats.BringIntoView();
                DgThreats.Focus();
                break;
        }
    }

    /// <summary>
    /// Phase 11: surface the resident-service connection state honestly. The
    /// desktop process does not bind an IPC transport to a running service in
    /// this phase, so the service is reported as Not running. Manual scanning
    /// and all existing in-process tools remain fully available; service-owned
    /// runtime protection is never shown as active while the service is
    /// unavailable.
    /// </summary>
    private void InitializeServiceConnectionIndicator()
    {
        _serviceConnection.Refresh(DataVanger.Shared.Ipc.ServiceConnectionStatus.NotRunning);
        TxtServiceStatus.Text = _serviceConnection.StatusText;
        TxtServiceStatus.ToolTip = _serviceConnection.StatusDetail;
    }

    private void OnThemeToggle(object sender, RoutedEventArgs e) => ApplyTheme(!_isDarkMode);

    /// <summary>
    /// Applies the light or dark palette by mutating the application-scoped brush
    /// resources in place. Because every control binds these via DynamicResource
    /// (and other windows resolve them up the tree to Application scope), updating
    /// each brush's Color propagates instantly across the whole app without a
    /// restart and without replacing brush instances (so live references — e.g. the
    /// nav-selection background — stay valid).
    /// </summary>
    private void ApplyTheme(bool isDarkMode)
    {
        _isDarkMode = isDarkMode;

        // brush key -> (R, G, B) for the requested theme.
        var palette = _isDarkMode
            ? new Dictionary<string, (byte R, byte G, byte B)>
            {
                ["BrushPrimary"]       = (0x42, 0xA5, 0xF5), // Bright Blue
                ["BrushSuccess"]       = (0x66, 0xBB, 0x6A), // Bright Green
                ["BrushWarning"]       = (0xFF, 0xA7, 0x26), // Bright Orange
                ["BrushDanger"]        = (0xEF, 0x53, 0x50), // Bright Red
                ["BrushInfo"]          = (0x64, 0xB5, 0xF6), // Light Blue
                ["BrushBg"]            = (0x12, 0x12, 0x12), // Very Dark Gray
                ["BrushBgSecondary"]   = (0x1E, 0x1E, 0x1E), // Dark Gray
                ["BrushBgTertiary"]    = (0x2A, 0x2A, 0x2A), // Medium Dark Gray
                ["BrushText"]          = (0xE0, 0xE0, 0xE0), // Light Gray Text
                ["BrushTextSecondary"] = (0xB0, 0xB0, 0xB0), // Medium Gray
                ["BrushTextTertiary"]  = (0x80, 0x80, 0x80), // Dark Gray
                ["BrushBorder"]        = (0x3A, 0x3A, 0x3A), // Dark Border
                ["BrushCardBg"]        = (0x1A, 0x1A, 0x1A), // Card Dark
                ["BrushNavBg"]         = (0x15, 0x15, 0x15), // Nav Dark
                ["BrushHeaderBg"]      = (0x1F, 0x1F, 0x1F), // Header Dark
            }
            : new Dictionary<string, (byte R, byte G, byte B)>
            {
                ["BrushPrimary"]       = (0x0D, 0x6C, 0xB8), // Electric Blue
                ["BrushSuccess"]       = (0x2E, 0x7D, 0x32), // Forest Green
                ["BrushWarning"]       = (0xF5, 0x7C, 0x00), // Deep Orange
                ["BrushDanger"]        = (0xC6, 0x28, 0x28), // Deep Red
                ["BrushInfo"]          = (0x15, 0x65, 0xC0), // Indigo
                ["BrushBg"]            = (0xFF, 0xFF, 0xFF), // Pure White
                ["BrushBgSecondary"]   = (0xF5, 0xF5, 0xF5), // Light Gray
                ["BrushBgTertiary"]    = (0xEE, 0xEE, 0xEE), // Lighter Gray
                ["BrushText"]          = (0x21, 0x21, 0x21), // Dark Charcoal
                ["BrushTextSecondary"] = (0x66, 0x66, 0x66), // Medium Gray
                ["BrushTextTertiary"]  = (0x99, 0x99, 0x99), // Light Gray
                ["BrushBorder"]        = (0xDD, 0xDD, 0xDD), // Border Gray
                ["BrushCardBg"]        = (0xFA, 0xFA, 0xFA), // Off-white
                ["BrushNavBg"]         = (0xFF, 0xFF, 0xFF), // Nav white
                ["BrushHeaderBg"]      = (0xF8, 0xF8, 0xF8), // Header light
            };

        var appResources = System.Windows.Application.Current?.Resources ?? Resources;

        foreach (var entry in palette)
        {
            var color = System.Windows.Media.Color.FromRgb(entry.Value.R, entry.Value.G, entry.Value.B);
            if (appResources[entry.Key] is System.Windows.Media.SolidColorBrush brush && !brush.IsFrozen)
                brush.Color = color;
            else
                appResources[entry.Key] = new System.Windows.Media.SolidColorBrush(color);
        }

        BtnThemeToggle.Content = _isDarkMode ? "☀️  Modo Claro" : "🌙  Modo Escuro";
    }

    private void AppendLog(string msg) =>
        Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
        {
            TxtLog.AppendText(msg + "\n");
            ScrollLog.ScrollToBottom();
        }));

    private void SetStatus(string msg) =>
        Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() => TxtStatus.Text = msg));

    private void SetScanRunning(bool running)
    {
        BtnScan.IsEnabled = !running;
        BtnStop.IsEnabled = running;
        BtnRestore.IsEnabled = !running;
        BtnSchedule.IsEnabled = !running;
        BtnAnalyzeClean.IsEnabled = !running;
        BtnRunClean.IsEnabled = !running && _cleanerItems.Any(i => i.Selected && i.Bytes > 0);
        PbProgress.IsIndeterminate = false;
    }

    private void StartTimer()
    {
        _scanStart = DateTime.Now;
        _timer?.Stop();
        _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        _timer.Tick += (_, _) =>
        {
            double s = (DateTime.Now - _scanStart).TotalSeconds;
            TxtProgressTime.Text = $"Tempo: {s:N0}s";
        };
        _timer.Start();
    }

    private void StopTimer()
    {
        _timer?.Stop();
        _timer = null;
    }

    private void StartResourceTimer()
    {
        _lastCpuSampleAt = DateTime.Now;
        try { _lastCpuTime = Process.GetCurrentProcess().TotalProcessorTime; }
        catch (Exception)
        {
            // TotalProcessorTime may throw Win32Exception/NotSupportedException on some platforms - leave the baseline unset.
        }

        _resourceTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _resourceTimer.Tick += (_, _) => UpdateResourceUsage();
        _resourceTimer.Start();
        UpdateResourceUsage();
    }

    private void UpdateResourceUsage()
    {
        try
        {
            using var process = Process.GetCurrentProcess();
            var now = DateTime.Now;
            var cpuNow = process.TotalProcessorTime;
            double elapsedMs = Math.Max(1, (now - _lastCpuSampleAt).TotalMilliseconds);
            double cpuMs = (cpuNow - _lastCpuTime).TotalMilliseconds;
            double cpu = Math.Clamp(cpuMs / (elapsedMs * Math.Max(1, Environment.ProcessorCount)) * 100.0, 0, 100);
            double ram = process.WorkingSet64 / 1024.0 / 1024.0;
            TxtCpuRam.Text = $"{cpu:F0}% / {ram:F0} MB";
            _lastCpuSampleAt = now;
            _lastCpuTime = cpuNow;
        }
        catch (System.Exception)
        {
            TxtCpuRam.Text = "—";
        }
    }

    private void UpdateCounters()
    {
        var data = _lastFindings;
        TxtCritCount.Text = data.Count(f => f.IsConfirmedMalware).ToString();
        TxtHighCount.Text = data.Count(f => !f.IsConfirmedMalware && f.Score >= RiskThresholds.High).ToString();
        TxtSuspCount.Text = data.Count(f => !f.IsConfirmedMalware && f.Score >= RiskThresholds.Suspect && f.Score < RiskThresholds.High).ToString();
        TxtNewCount.Text = data.Count(f => f.IsNew).ToString();
        TxtThreatTotal.Text = data.Count.ToString();
    }

    private void UpdateLastScan()
    {
        if (!File.Exists(_engine.LogTxtPath))
        {
            TxtDashboardLastScan.Text = "Nenhum";
            return;
        }

        try
        {
            var line = File.ReadLines(_engine.LogTxtPath).FirstOrDefault(l => l.Contains("DataVanger v", StringComparison.OrdinalIgnoreCase));
            if (line != null)
            {
                var display = line.Length > 70 ? line[..70] + "…" : line;
                TxtLastScan.Text = display;
                TxtDashboardLastScan.Text = display;
            }
        }
        catch (UnauthorizedAccessException)
        {
            // Log unreadable - leave the last-scan label unchanged.
        }
        catch (IOException)
        {
            // Log locked/unreadable - leave the last-scan label unchanged.
        }
    }

    private ScanProfile SelectedProfile()
    {
        var text = CmbProfile.SelectedItem?.ToString() ?? "Deep";
        if (text.Contains("Fast", StringComparison.OrdinalIgnoreCase)) return ScanProfile.Fast;
        return ScanProfile.Deep;
    }

    private async void OnScan(object sender, RoutedEventArgs e)
    {
        var profile = SelectedProfile();
        int.TryParse(TxtMaxHash.Text, out int maxHash);
        bool interactive = ChkInteractive.IsChecked == true;

        TxtLog.Clear();
        DgThreats.ItemsSource = null;
        _threats.Clear();
        _lastFindings.Clear();
        UpdateCounters();
        AppendLog($"[GUI] Iniciando scan — Perfil: {profile}");
        _historyRecorder?.RecordScanStarted(profile.ToString());

        SetScanRunning(true);
        SetStatus($"Scan em andamento ({profile})...");
        TxtProgressLabel.Text = "Scan em execução...";
        TxtFilesRemaining.Text = "Restantes: calculando...";
        TxtCurrentFile.Text = "Arquivo: —";
        TxtScanStats.Text = "0%";
        TxtEta.Text = "—";
        TxtScanSpeed.Text = "0 arq/s";
        PbProgress.Value = 0;

        _cts = new CancellationTokenSource();
        StartTimer();

        var options = new ScanOptions
        {
            Profile = profile,
            MaxHashSizeMB = maxHash,
            Interactive = interactive,
            // Paralelismo por perfil centralizado em ScanProfileRegistry: o trabalho por arquivo é
            // dominado por I/O (hashing + módulos relendo conteúdo), então o perfil Fast (leve) recebe
            // mais workers, enquanto Deep (pesado, com archive/document parsing) usa cores/2 pareado com
            // um pequeno CpuThrottleDelayMs para evitar saturação.
            MaxDegreeOfParallelism = ScanProfileRegistry.RecommendedDegreeOfParallelism(profile, Environment.ProcessorCount),
            CpuThrottleDelayMs = profile is ScanProfile.Deep ? 1 : 0
        };

        try
        {
            _lastProgressUiUpdate = DateTime.MinValue;
            int runId = Interlocked.Increment(ref _scanRunId);
            var token = _cts.Token;
            var (findings, metrics) = await Task.Run(async () =>
                await _engine.RunAsync(options, AppendLog, token,
                    onProgress: null,
                    onProgressInfo: info => QueueProgressUpdate(runId, info)).ConfigureAwait(false), token);

            _lastFindings = findings;
            RefreshThreatTable(findings);
            UpdateCounters();
            UpdateLastScan();
            _historyRecorder?.RecordScanCompleted(findings, metrics);
            UpdateTrayStatus();

            string elapsed = $"{metrics.TotalTime.TotalSeconds:F1}s";
            TxtProgressLabel.Text = "Concluído";
            TxtFilesRemaining.Text = "Restantes: 0";
            TxtEta.Text = "0s";
            TxtScanSpeed.Text = $"{metrics.FilesPerSecond:F1} arq/s";
            TxtScanStats.Text = "100%";
            PbProgress.Value = 100;
            AppendLog($"\n[GUI] Scan concluído em {elapsed}.");
            SetStatus($"Concluído em {elapsed}. {findings.Count} achados.");

            if (interactive && findings.Any(f => f.IsConfirmedMalware && !f.WasQuarantined))
                await PromptQuarantineAsync(findings, token);
        }
        catch (OperationCanceledException)
        {
            AppendLog("[GUI] Scan cancelado pelo usuário.");
            TxtProgressLabel.Text = "Interrompido";
            SetStatus("Interrompido.");
        }
        catch (Exception ex)
        {
            AppendLog($"[ERRO] {ex.Message}");
            SetStatus("Erro durante o scan.");
        }
        finally
        {
            StopTimer();
            SetScanRunning(false);
            Interlocked.Increment(ref _scanRunId);
            _cts?.Dispose();
            _cts = null;
        }
    }

    private void QueueProgressUpdate(int runId, ScanProgressInfo info)
    {
        bool shouldPost;
        lock (_progressUiLock)
        {
            var now = DateTime.UtcNow;
            bool final = info.Percent >= 100 || info.Current >= info.Total;
            shouldPost = final || (now - _lastProgressUiUpdate).TotalMilliseconds >= 250;
            if (shouldPost) _lastProgressUiUpdate = now;
        }

        if (!shouldPost) return;

        Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
        {
            if (runId != _scanRunId) return;
            if (_cts?.IsCancellationRequested == true && info.Percent < 100) return;
            UpdateProgress(info);
        }));
    }

    private void UpdateProgress(ScanProgressInfo info)
    {
        if (info.IsIndeterminate || info.Total <= 0)
        {
            PbProgress.IsIndeterminate = true;
            TxtProgressLabel.Text = string.IsNullOrWhiteSpace(info.Phase) ? "Preparando scan..." : info.Phase;
            TxtFilesRemaining.Text = info.Current > 0 ? $"Encontrados: {info.Current:N0}" : "Restantes: calculando...";
            TxtScanSpeed.Text = "—";
            TxtEta.Text = "—";
            TxtScanStats.Text = "Indexando";
            if (!string.IsNullOrWhiteSpace(info.CurrentFile))
                TxtCurrentFile.Text = "Arquivo: " + ShortenPath(info.CurrentFile, 72);
            return;
        }

        PbProgress.IsIndeterminate = false;
        PbProgress.Value = info.Percent;
        TxtProgressLabel.Text = $"Analisando... {info.Current}/{info.Total} arquivos";
        TxtFilesRemaining.Text = $"Restantes: {info.Remaining}";
        TxtScanSpeed.Text = $"{info.FilesPerSecond:F1} arq/s";
        TxtEta.Text = info.Eta <= TimeSpan.Zero ? "—" : FormatTime(info.Eta);
        TxtScanStats.Text = $"{info.Percent:F1}%";
        if (!string.IsNullOrWhiteSpace(info.CurrentFile))
            TxtCurrentFile.Text = "Arquivo: " + ShortenPath(info.CurrentFile, 72);
    }

    private static string FormatTime(TimeSpan t)
    {
        if (t.TotalHours >= 1) return $"{(int)t.TotalHours}h {t.Minutes}m";
        if (t.TotalMinutes >= 1) return $"{(int)t.TotalMinutes}m {t.Seconds}s";
        return $"{Math.Max(0, t.Seconds)}s";
    }

    private static string ShortenPath(string path, int max)
    {
        if (path.Length <= max) return path;
        return "…" + path[^Math.Min(max - 1, path.Length)..];
    }

    private void RefreshThreatTable(List<ScanFinding> findings)
    {
        // Evita congelar a UI adicionando milhares de linhas uma a uma em ObservableCollection.
        // A lista pronta é vinculada de uma vez e o DataGrid aplica virtualização/filtro.
        DgThreats.ItemsSource = findings;
        ApplyThreatFilter();
    }

    private void ApplyThreatFilter()
    {
        if (DgThreats.ItemsSource == null) return;
        ICollectionView view = CollectionViewSource.GetDefaultView(DgThreats.ItemsSource);
        var selected = (CmbRiskFilter.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Todos";
        view.Filter = obj =>
        {
            if (obj is not ScanFinding f) return false;
            return selected switch
            {
                "Crítico" => f.IsConfirmedMalware,
                "Alto" => !f.IsConfirmedMalware && f.Score >= RiskThresholds.High,
                "Suspeito" => !f.IsConfirmedMalware && f.Score >= RiskThresholds.Suspect && f.Score < RiskThresholds.High,
                "Limpo" => f.Score < RiskThresholds.Suspect,
                _ => true
            };
        };
        view.Refresh();
    }

    private void OnStop(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
        BtnStop.IsEnabled = false;
        TxtProgressLabel.Text = "Cancelando...";
        AppendLog("[GUI] Cancelamento solicitado. Aguardando o scanner finalizar com segurança...");
        SetStatus("Cancelando scan...");
    }

    private async Task PromptQuarantineAsync(List<ScanFinding> findings, CancellationToken cancellationToken)
    {
        var candidates = findings.Where(f => f.IsConfirmedMalware && !f.WasQuarantined).ToList();
        if (candidates.Count == 0) return;

        var result = MessageBox.Show(
            $"Foram encontrados {candidates.Count} arquivo(s) de alto risco não assinados.\n\nMover para quarentena agora?",
            "DataVanger — Quarentena", MessageBoxButton.YesNo, MessageBoxImage.Warning);

        if (result != MessageBoxResult.Yes) return;

        int count = 0;
        foreach (var f in candidates)
        {
            var request = QuarantineRequestFactory.Create(
                f, QuarantineRequestOrigin.ManualUserApproved, "MainWindow.PromptQuarantine");
            var quarantine = await _engine.Quarantine.Service
                .QuarantineAsync(request, cancellationToken);
            if (quarantine.Status == QuarantineStatus.Success &&
                quarantine.Record?.RecordState == QuarantineRecordState.Verified)
            {
                f.WasQuarantined = true;
                count++;
                AppendLog($"  [Q] Movido: {f.Path}");
                // History: a quarantine action is recorded as done — NOT verified.
                _historyRecorder?.RecordQuarantine(f);
            }
        }
        AppendLog($"[GUI] {count} arquivo(s) em quarentena.");
        DgThreats.Items.Refresh();
        UpdateTrayStatus();
    }

    private async void OnRestore(object sender, RoutedEventArgs e)
    {
        try
        {
            var index = await _engine.Quarantine.Index.ListAsync(_quarantineLifetimeCts.Token);
            var legacy = _engine.Quarantine.LegacyInventory.Inspect();
            if (index.Count == 0 && !legacy.HasUnauthenticatedItems)
            {
                MessageBox.Show("Nenhum arquivo em quarentena.", "DataVanger", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dlg = new QuarantineWindow(
                _engine.Quarantine.Service,
                _engine.Quarantine.Index,
                _engine.Quarantine.LegacyInventory) { Owner = this };
            if (dlg.ShowDialog() == true && dlg.RestoredId != null)
            {
                AppendLog($"[GUI] Restaurado: {dlg.RestoredPath}");
                SetStatus("Arquivo restaurado.");
            }
        }
        catch (OperationCanceledException)
        {
            // Window is closing; do not surface a stale dialog.
        }
        catch (Exception)
        {
            MessageBox.Show("Não foi possível consultar a Quarentena V2.", "DataVanger",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnSchedule(object sender, RoutedEventArgs e)
    {
        var win = new ScheduledScanWindow { Owner = this };
        if (win.ShowDialog() != true) return;

        if (win.RemoveRequested)
        {
            var rem = SchedulerHelper.Unregister();
            AppendLog(rem.ok ? "[GUI] Tarefa agendada removida." : $"[ERRO] Falha ao remover agendamento: {rem.msg}");
            SetStatus(rem.ok ? "Agendamento removido." : "Erro ao remover agendamento.");
            return;
        }

        string exePath = Process.GetCurrentProcess().MainModule?.FileName ?? "";
        (bool ok, string info) result = SchedulerHelper.RegisterRecurring(
            exePath,
            $"DataVanger_{win.Profile}_{win.ScheduleMode}",
            win.ScheduleMode,
            win.ScheduledAt,
            win.WeekDay,
            win.Profile);

        AppendLog(result.ok
            ? $"[GUI] Varredura agendada: {win.ScheduleMode} — perfil {win.Profile} — {win.ScheduledAt:dd/MM/yyyy HH:mm}"
            : $"[ERRO] Agendamento falhou: {result.info}");
        SetStatus(result.ok ? "Agendamento atualizado." : "Erro no agendamento.");
    }

    private async void OnUpdateSignatures(object sender, RoutedEventArgs e)
    {
        var settings = AppSettings.Load(_engine.SettingsPath);

        var configuration = SignedFeedUpdateRunner.InspectConfiguration(settings);
        if (!configuration.CanContactNetwork)
        {
            AppendLog("[Update] " + configuration.Message);
            SetStatus(configuration.State == SignedFeedConfigurationState.Disabled
                ? "Atualizações assinadas desativadas."
                : "Feed assinado não configurado.");
            MessageBox.Show(configuration.Message,
                "DataVanger — Atualização assinada", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        SetStatus("Atualizando assinaturas (manifesto assinado)...");
        AppendLog("[Update] " + configuration.Message);
        var run = await Task.Run(() => SignedFeedUpdateRunner.Run(
            settings, _engine.SignatureRoot, Path.Combine(_engine.MgRoot, "UpdateState")));
        bool ok = run.Succeeded;
        AppendLog(ok ? "[Update] Manifesto e pacotes verificados e aplicados." : "[Update] Recusado: " + run.Message);
        SetStatus(ok ? "Assinaturas assinadas atualizadas." : "Atualização assinada recusada.");
        MessageBox.Show(ok ? "Feed assinado verificado e aplicado com sucesso." : "Atualização assinada recusada: " + run.Message,
            "DataVanger — Assinaturas", MessageBoxButton.OK, ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
    }

    private void OnSettings(object sender, RoutedEventArgs e)
    {
        // Phase 06 — the grouped, reveal-gated, confirm-on-disable settings window.
        // The legacy flat SettingsWindow remains in the codebase as a fallback.
        var win = new DataVanger.Views.SettingsRedesignWindow(_engine.SettingsPath) { Owner = this };
        if (win.ShowDialog() == true)
        {
            AppendLog("[GUI] Configurações salvas. O próximo scan usará os novos valores.");
            SetStatus("Configurações salvas.");
        }
    }

    // Phase 18 — opens the read-only honest module-status panel. Read-only: it does not
    // activate modules, write settings, start services, or trigger scans/updates.
    private void OnModuleStatus(object sender, RoutedEventArgs e)
    {
        new ModuleStatusWindow { Owner = this }.ShowDialog();
    }

    private void OnDiagnostics(object sender, RoutedEventArgs e)
    {
        var settings = AppSettings.Load(_engine.SettingsPath);
        var signatures = SignatureDatabase.Load(_engine.SignatureRoot, _engine.BlacklistPath, _engine.WhitelistPath);
        var yaraDb = settings.EnableYaraRules ? LightweightYaraDatabase.Load(_engine.SignatureRoot) : new LightweightYaraDatabase();
        var sb = new StringBuilder();
        sb.AppendLine("DataVanger — Sobre / Diagnóstico");
        sb.AppendLine();
        sb.AppendLine($"Versão do DataVanger : v{VersionInfo.Version}");
        sb.AppendLine($"Versão do .NET       : {Environment.Version}");
        sb.AppendLine($"Sistema              : {Environment.OSVersion}");
        sb.AppendLine($"Pasta de dados       : {_engine.MgRoot}");
        sb.AppendLine($"Pasta de logs        : {Path.Combine(_engine.MgRoot, "Logs")}");
        sb.AppendLine($"Log de startup       : {App.StartupCrashLogPath}");
        sb.AppendLine($"Configurações        : {_engine.SettingsPath}");
        sb.AppendLine($"Pasta de assinaturas : {_engine.SignatureRoot}");
        sb.AppendLine($"Pasta YARA leve      : {_engine.YaraRulesRoot}");
        sb.AppendLine($"Hashes carregados    : {signatures.TotalHashes}");
        sb.AppendLine($"Maliciosos conhecidos: {signatures.KnownMalicious.Count + signatures.UserBlacklist.Count}");
        sb.AppendLine($"Confiáveis conhecidos: {signatures.KnownSafe.Count + signatures.UserWhitelist.Count}");
        sb.AppendLine($"Regras YARA leves    : {yaraDb.Count} ({(settings.EnableYaraRules ? "ativadas" : "desativadas")})");
        var sigStatus = DefaultSignaturePack.Describe(signatures, yaraDb);
        if (sigStatus.IsBlind)
            sb.AppendLine("Estado da detecção   : ⚠ SEM ASSINATURAS — detecção apenas heurística (não confirma malware).");
        else if (sigStatus.IsBaselineOnly)
            sb.AppendLine("Estado da detecção   : somente baseline/teste (EICAR) — adicione um feed real para cobertura.");
        else
            sb.AppendLine("Estado da detecção   : assinaturas carregadas.");
        sb.AppendLine($"Scan de compactados  : {(settings.DeepScanArchives ? "ativado no perfil Deep" : "desativado")}");
        var updateConfiguration = SignedFeedUpdateRunner.InspectConfiguration(settings);
        sb.AppendLine($"Atualização assinada : {updateConfiguration.State}");
        sb.AppendLine($"Confiança do feed    : {(updateConfiguration.State == SignedFeedConfigurationState.ReadyOperatorManaged ? "development/operator (não é trust root de produção)" : "nenhuma")}");
        if (updateConfiguration.MissingRequirements.Count > 0)
            sb.AppendLine($"Configuração faltante: {string.Join(", ", updateConfiguration.MissingRequirements)}");
        sb.AppendLine($"Monitor em tempo real: {(_monitor.IsRunning ? "ativo" : "inativo")}");
        sb.AppendLine($"Último scan          : {TxtLastScan.Text}");
        sb.AppendLine();
        if (File.Exists(App.StartupCrashLogPath))
        {
            var lines = File.ReadLines(App.StartupCrashLogPath).Reverse().Take(20).Reverse();
            sb.AppendLine("Últimas linhas do startup_crash.log:");
            foreach (var line in lines) sb.AppendLine(line);
        }
        else
        {
            sb.AppendLine("Nenhum startup_crash.log encontrado.");
        }

        var win = new TextViewerWindow("DataVanger — Sobre / Diagnóstico", sb.ToString()) { Owner = this };
        win.ShowDialog();
    }

    private void OnViewPersist(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(_engine.PersistTxtPath))
        {
            MessageBox.Show("Execute um scan primeiro para gerar o relatório de persistências.",
                "DataVanger", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        string content = File.ReadAllText(_engine.PersistTxtPath);
        if (string.IsNullOrWhiteSpace(content)) content = "(Vazio)";
        var win = new TextViewerWindow("DataVanger — Persistências", content) { Owner = this };
        win.ShowDialog();
    }

    private void OnRemovalCenter(object sender, RoutedEventArgs e)
    {
        var actionable = _lastFindings.Where(f => !f.WasQuarantined).ToList();
        if (actionable.Count == 0)
        {
            MessageBox.Show(
                _lastFindings.Count == 0
                    ? "Execute um scan primeiro para gerar achados para a Central de Remoção."
                    : "Não há achados pendentes de ação.",
                "DataVanger", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var finding = actionable[0];
        var context = new DataVanger.ViewModels.RemovalCenterThreatContext
        {
            CorrelationId = Guid.NewGuid().ToString("N"),
            Action = DataVanger.Shared.Remediation.RemediationIpcActionKind.QuarantineFile,
            TargetKind = DataVanger.Shared.Remediation.RemediationIpcTargetKind.File,
            TargetIdentity = finding.Path,
            Title = finding.FileName,
            RiskText = $"Pontuação {finding.Score}",
        };

        // The Removal Center drives all remediation through the service over IPC.
        // The concrete IPC client is not yet wired into the WPF process, so the
        // offline gateway reports the service honestly as unavailable.
        var vm = new DataVanger.ViewModels.RemovalCenterViewModel(
            new DataVanger.ViewModels.OfflineRemovalCenterService());
        vm.Prepare(context);

        var win = new DataVanger.Views.RemovalCenterWindow(vm) { Owner = this };
        win.ShowDialog();
    }

    private void OnReviewFix(object sender, RoutedEventArgs e)
    {
        var actionable = _lastFindings.Where(f => !f.WasQuarantined).ToList();
        if (actionable.Count == 0)
        {
            MessageBox.Show(
                _lastFindings.Count == 0
                    ? "Execute um scan primeiro para gerar achados para revisar."
                    : "Não há achados pendentes de ação.",
                "DataVanger", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var win = new ReviewFixWindow(actionable, _engine) { Owner = this };
        win.ShowDialog();

        if (win.ChangesApplied)
        {
            RefreshThreatTable(_lastFindings);
            UpdateCounters();
            AppendLog("[GUI] Ações de revisão aplicadas (quarentena/whitelist).");
            SetStatus("Ações de revisão aplicadas.");
        }
    }

    private async void OnAnalyzeClean(object sender, RoutedEventArgs e)
    {
        BtnAnalyzeClean.IsEnabled = false;
        BtnRunClean.IsEnabled = false;
        SetStatus("Analisando lixo seguro...");
        AppendLog("[Cleaner] Analisando locais seguros de limpeza...");

        try
        {
            var items = await _cleaner.AnalyzeAsync();
            _cleanerItems.Clear();
            foreach (var item in items) _cleanerItems.Add(item);
            long total = items.Where(i => i.Selected).Sum(i => i.Bytes);
            int count = items.Sum(i => i.FileCount);
            AppendLog($"[Cleaner] Análise concluída: {count} arquivo(s), {FormatBytes(total)} selecionados.");
            SetStatus($"Limpeza analisada: {FormatBytes(total)} selecionados.");
            BtnRunClean.IsEnabled = total > 0;
        }
        catch (Exception ex)
        {
            AppendLog($"[Cleaner][ERRO] {ex.Message}");
            SetStatus("Erro ao analisar limpeza.");
        }
        finally
        {
            BtnAnalyzeClean.IsEnabled = true;
        }
    }

    private async void OnRunClean(object sender, RoutedEventArgs e)
    {
        var selected = _cleanerItems.Where(i => i.Selected && i.Bytes > 0).ToList();
        if (selected.Count == 0)
        {
            MessageBox.Show("Nenhum item selecionado para limpeza.", "DataVanger — Cleaner", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        long total = selected.Sum(i => i.Bytes);
        var res = MessageBox.Show(
            $"Excluir com segurança {selected.Count} categoria(s), liberando aproximadamente {FormatBytes(total)}?\n\nArquivos em uso, críticos e de sistema serão ignorados.",
            "DataVanger — Confirmar Limpeza", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (res != MessageBoxResult.Yes) return;

        BtnAnalyzeClean.IsEnabled = false;
        BtnRunClean.IsEnabled = false;
        SetStatus("Executando limpeza segura...");
        AppendLog("[Cleaner] Executando limpeza segura...");

        try
        {
            var result = await _cleaner.CleanAsync(selected, ChkCleanerBackup.IsChecked == true);
            foreach (var line in result.Messages) AppendLog("[Cleaner] " + line);
            AppendLog($"[Cleaner] Concluído: {result.DeletedFiles} arquivo(s), {FormatBytes(result.DeletedBytes)} liberados, {result.SkippedFiles} ignorados.");
            SetStatus($"Limpeza concluída: {FormatBytes(result.DeletedBytes)} liberados.");
            await OnAnalyzeCleanAsyncSilent();
        }
        catch (Exception ex)
        {
            AppendLog($"[Cleaner][ERRO] {ex.Message}");
            SetStatus("Erro na limpeza.");
        }
        finally
        {
            BtnAnalyzeClean.IsEnabled = true;
            BtnRunClean.IsEnabled = _cleanerItems.Any(i => i.Selected && i.Bytes > 0);
        }
    }

    private async Task OnAnalyzeCleanAsyncSilent()
    {
        var items = await _cleaner.AnalyzeAsync();
        _cleanerItems.Clear();
        foreach (var item in items) _cleanerItems.Add(item);
    }

    private void OnToggleRealtime(object sender, RoutedEventArgs e)
    {
        if (_monitor.IsRunning)
        {
            _monitor.Stop();
            BtnToggleRealtime.Content = "🛰  Ativar monitor local (UI)";
            SetStatus("Monitor local da interface desativado; não havia proteção residente.");
            AppendLog("[Realtime] Monitor desativado.");
            UpdateTrayStatus();
            return;
        }

        _monitor.Start();
        BtnToggleRealtime.Content = "🛰  Desativar monitor local (UI)";
        SetStatus("Monitor local da interface ativo: detecta eventos enquanto esta janela estiver aberta; não bloqueia preventivamente.");
        AppendLog("[Realtime] Monitor local (UI) observando Downloads, Desktop, Temp, Startup e AppData; não é proteção residente.");
        UpdateTrayStatus();
    }

    // ── Phase 07: tray status + service-status surface (non-elevated, honest) ──────────

    /// <summary>Derive the tray status from REAL app state and push it to the tray
    /// (if a tray icon exists). Never fakes protection: realtime/service state come
    /// from the live monitor + service connection.</summary>
    private void UpdateTrayStatus()
    {
        if (_trayHost is null) return;

        bool realtimeActive = _monitor.IsRunning;
        bool pendingThreats = _lastFindings.Any(f =>
            !f.WasQuarantined && (f.IsConfirmedMalware || f.Score >= RiskThresholds.High));
        bool serviceImpaired = _serviceConnection.Status is
            DataVanger.Shared.Ipc.ServiceConnectionStatus.Unknown or
            DataVanger.Shared.Ipc.ServiceConnectionStatus.NotInstalled or
            DataVanger.Shared.Ipc.ServiceConnectionStatus.NotRunning or
            DataVanger.Shared.Ipc.ServiceConnectionStatus.Unreachable or
            DataVanger.Shared.Ipc.ServiceConnectionStatus.Degraded;

        var status = ViewModels.TrayStatusModel.Derive(
            realtimeActive: realtimeActive,
            pendingThreats: pendingThreats,
            serviceDegraded: serviceImpaired,
            updateAvailable: false,
            remediationInProgress: false);

        _trayHost.Update(status);
    }

    private void ShowAndActivate()
    {
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
        Show();
        Activate();
    }

    /// <summary>Honest service-registration status + elevation guidance. Never installs,
    /// never elevates; just explains. The UI itself requires no administrator rights.</summary>
    private void ShowServiceStatus()
    {
        var vm = new ViewModels.ServiceRegistrationViewModel(_serviceConnection.Status, IsCurrentProcessElevated());
        MessageBox.Show(
            this,
            $"{vm.StatusSummary}\n\n{vm.ElevationInstructions}",
            "DataVanger — Estado do serviço",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    private static bool IsCurrentProcessElevated()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch (Exception)
        {
            return false; // assume non-elevated if it cannot be determined
        }
    }

    private void OnRealtimeSuspiciousFile(string path)
    {
        Dispatcher.BeginInvoke(new Action(async () =>
        {
            AppendLog($"[Realtime][ALERTA] Arquivo sensível criado/modificado: {path}");
            SetStatus("Monitor em tempo real detectou arquivo sensível.");

            bool quarantined = await TryAutoQuarantineKnownRealtimeThreatAsync(
                path, _quarantineLifetimeCts.Token);
            string action = quarantined
                ? "O hash já estava na blacklist/base conhecida, então o arquivo foi movido para quarentena automaticamente."
                : "Execute um Quick Scan para avaliar o risco antes de abrir.";

            MessageBox.Show($"Arquivo sensível detectado pelo monitor em tempo real:\n\n{path}\n\n{action}",
                "DataVanger — Alerta em Tempo Real", MessageBoxButton.OK, MessageBoxImage.Warning);
        }));
    }

    private async Task<bool> TryAutoQuarantineKnownRealtimeThreatAsync(
        string path,
        CancellationToken cancellationToken)
    {
        try
        {
            if (!File.Exists(path)) return false;
            await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.Read, 81920, useAsync: true);
            string hash = Convert.ToHexString(await SHA256.HashDataAsync(fs, cancellationToken));
            var signatures = SignatureDatabase.Load(_engine.SignatureRoot, _engine.BlacklistPath, _engine.WhitelistPath);
            if (!signatures.IsKnownMalicious(hash)) return false;

            var fi = new FileInfo(path);
            var finding = new ScanFinding
            {
                Path = path,
                Extension = fi.Extension,
                SizeKB = fi.Length / 1024,
                SHA256 = hash,
                Score = RiskThresholds.Critical + 10,
                Reasons = "Monitor em tempo real: hash encontrado na base de malware conhecido",
                LastWrite = fi.LastWriteTime,
                IsBlacklisted = true,
                IsNew = true
            };

            var request = QuarantineRequestFactory.Create(
                finding, QuarantineRequestOrigin.Automatic, "MainWindow.RealtimeMonitor");
            var quarantine = await _engine.Quarantine.Service
                .QuarantineAsync(request, cancellationToken);
            if (quarantine.Status != QuarantineStatus.Success ||
                quarantine.Record?.RecordState != QuarantineRecordState.Verified) return false;
            AppendLog($"[Realtime][Q] Conhecido malicioso movido para quarentena: {path}");
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        catch (System.Exception)
        {
            return false;
        }
    }

    private void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(_engine.MgRoot);
        Process.Start(new ProcessStartInfo("explorer.exe", _engine.MgRoot) { UseShellExecute = true });
    }

    private void OnOpenReport(object sender, RoutedEventArgs e)
    {
        if (File.Exists(_engine.LogHtmlPath))
            Process.Start(new ProcessStartInfo(_engine.LogHtmlPath) { UseShellExecute = true });
        else
            MessageBox.Show("Execute um scan primeiro.", "DataVanger", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024L * 1024L * 1024L) return $"{bytes / 1024.0 / 1024.0:F1} MB";
        return $"{bytes / 1024.0 / 1024.0 / 1024.0:F2} GB";
    }
}
