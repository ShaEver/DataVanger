using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using DataVanger.Core;
using DataVanger.ViewModels;
using WpfApplication = System.Windows.Application;
using WpfMessageBox = System.Windows.MessageBox;
using WpfMessageBoxButton = System.Windows.MessageBoxButton;
using WpfMessageBoxImage = System.Windows.MessageBoxImage;

namespace DataVanger;

// "Application" é ambíguo quando UseWindowsForms=true (System.Windows.Forms.Application vs System.Windows.Application).
// A qualificação explícita abaixo evita conflito enquanto o NotifyIcon do Windows Forms continuar em uso.
public partial class App : WpfApplication
{
    private static Mutex? _mutex;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Beta 01B: idioma de UI determinístico — pt-BR por padrão,
        // independentemente da cultura do SO. Opt-in explícito (sem elevação)
        // via "--ui-culture <nome>" ou DATAVANGER_UI_CULTURE. Aplicado antes
        // de qualquer janela ser criada.
        Localization.LocalizationService.ApplyStartupCulture(e.Args);

        DispatcherUnhandledException += (_, args) =>
        {
            WriteStartupCrashLog(args.Exception);
            args.Handled = true;

            WpfMessageBox.Show(
                "O DataVanger encontrou um erro inesperado. O erro foi salvo no log.",
                "DataVanger",
                WpfMessageBoxButton.OK,
                WpfMessageBoxImage.Error);
        };

        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception ex)
                WriteStartupCrashLog(ex);
        };

        if (!EnsureSingleInstance())
        {
            WpfMessageBox.Show(
                "O DataVanger já está em execução.",
                "DataVanger",
                WpfMessageBoxButton.OK,
                WpfMessageBoxImage.Information);
            Shutdown(0);
            return;
        }

        try
        {
            if (e.Args.Contains("--silent", StringComparer.OrdinalIgnoreCase))
            {
                int exitCode = await RunSilentScanAsync(e.Args);
                Shutdown(exitCode);
                return;
            }

            if (e.Args.Contains("--update-signatures", StringComparer.OrdinalIgnoreCase))
            {
                await RunSignatureUpdateAsync();
                Shutdown(0);
                return;
            }

            // Modo normal: abre a janela principal com proteção de startup.
            var window = new MainWindow();
            MainWindow = window;

            // Fase 07: onboarding de primeira execução ANTES do painel. Conservador;
            // só liga proteções, nunca desliga. Se pulado/fechado, nada muda.
            TryShowFirstRunOnboarding();

            window.Show();
        }
        catch (Exception ex)
        {
            WriteStartupCrashLog(ex);
            WpfMessageBox.Show(
                "O DataVanger falhou ao iniciar. Verifique o arquivo startup_crash.log em sua pasta de usuário/DataVanger/Logs.",
                "DataVanger — Erro de inicialização",
                WpfMessageBoxButton.OK,
                WpfMessageBoxImage.Error);
            Shutdown(1);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try { _mutex?.ReleaseMutex(); _mutex?.Dispose(); }
        catch (Exception)
        {
            // Mutex release/dispose may throw on shutdown if never owned or already disposed - ignore.
        }
        base.OnExit(e);
    }

    private static bool EnsureSingleInstance()
    {
        _mutex = new Mutex(true, "DataVanger.SingleInstance", out bool createdNew);
        return createdNew;
    }

    // Fase 07: mostra o onboarding apenas na primeira execução (arquivo-marcador).
    // Aplicar persiste as opções escolhidas (somente liga proteções); Pular não muda
    // nada. O marcador é gravado em ambos os casos para que o onboarding apareça uma vez.
    private static void TryShowFirstRunOnboarding()
    {
        try
        {
            string root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "DataVanger");
            string markerPath = Path.Combine(root, "onboarding.done");
            if (!OnboardingViewModel.IsFirstRun(markerPath)) return;

            string settingsPath = Path.Combine(root, "appsettings.json");
            var settings = AppSettings.Load(settingsPath);
            var viewModel = new OnboardingViewModel(settings);
            new Views.OnboardingWindow(viewModel, settingsPath).ShowDialog();

            OnboardingViewModel.MarkOnboardingComplete(markerPath);
        }
        catch (Exception ex)
        {
            // Onboarding é não-crítico: nunca deve impedir a inicialização.
            WriteStartupCrashLog(ex);
        }
    }

    internal static string StartupCrashLogPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        "DataVanger",
        "Logs",
        "startup_crash.log");

    internal static void WriteStartupCrashLog(Exception ex)
    {
        try
        {
            string dir = Path.GetDirectoryName(StartupCrashLogPath)!
                ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "DataVanger", "Logs");

            Directory.CreateDirectory(dir);
            File.AppendAllText(StartupCrashLogPath,
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}]\n{ex}\n\n");
        }
        catch
        {
            // Nunca deixar o logger quebrar o app.
        }
    }

    private static async Task<int> RunSilentScanAsync(string[] args)
    {
        var engine  = new ScanEngine();
        var profile = ParseProfileArg(args);
        var options = ParseScanOptions(args, profile);
        try
        {
            var (findings, _) = await engine.RunAsync(options, _ => { }, CancellationToken.None);

            int critical = findings.Count(f => f.IsConfirmedMalware);
            if (critical > 0)
                ShowTrayAlert(
                    "DataVanger — Malware Confirmado",
                    $"{critical} arquivo(s) confirmado(s) por hash/assinatura. Abra o DataVanger para revisar.");

            if (critical > 0) return 2;
            if (findings.Any(f => f.Score >= RiskThresholds.Suspect)) return 1;
            return 0;
        }
        catch (OperationCanceledException)
        {
            return 4;
        }
        catch (Exception ex)
        {
            WriteStartupCrashLog(ex);
            return 3;
        }
    }


    private static ScanProfile ParseProfileArg(string[] args)
    {
        try
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (!args[i].Equals("--profile", StringComparison.OrdinalIgnoreCase)) continue;
                if (i + 1 >= args.Length) break;
                string value = args[i + 1];
                if (value.Equals("fast", StringComparison.OrdinalIgnoreCase)) return ScanProfile.Fast;
                if (value.Equals("quick", StringComparison.OrdinalIgnoreCase)) return ScanProfile.Fast;
                if (value.Equals("deep", StringComparison.OrdinalIgnoreCase)) return ScanProfile.Deep;
                if (value.Equals("standard", StringComparison.OrdinalIgnoreCase)) return ScanProfile.Deep;
                if (value.Equals("full", StringComparison.OrdinalIgnoreCase)) return ScanProfile.Deep;
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Malformed command-line arguments - fall back to the default profile; fatal CLR exceptions are not swallowed.
        }
        return ScanProfile.Fast;
    }

    private static ScanOptions ParseScanOptions(string[] args, ScanProfile profile)
    {
        var options = new ScanOptions { Profile = profile };
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            string Next() => i + 1 < args.Length ? args[++i] : "";
            if (arg.Equals("--target", StringComparison.OrdinalIgnoreCase)) options.Target = Next();
            else if (arg.Equals("--report", StringComparison.OrdinalIgnoreCase)) options.ReportFormat = Next();
            else if (arg.Equals("--no-auto-quarantine", StringComparison.OrdinalIgnoreCase)) options.AutoQuarantine = false;
            else if (arg.Equals("--scan-archives", StringComparison.OrdinalIgnoreCase)) options.ScanArchives = ParseBool(Next(), true);
            else if (arg.Equals("--scan-browser-extensions", StringComparison.OrdinalIgnoreCase)) options.ScanBrowserExtensions = ParseBool(Next(), true);
            else if (arg.Equals("--scan-documents", StringComparison.OrdinalIgnoreCase)) options.ScanDocuments = ParseBool(Next(), true);
            else if (arg.Equals("--max-archive-depth", StringComparison.OrdinalIgnoreCase) && int.TryParse(Next(), out var depth)) options.MaxArchiveDepth = Math.Max(0, depth);
            else if (arg.Equals("--max-archive-entries", StringComparison.OrdinalIgnoreCase) && int.TryParse(Next(), out var entries)) options.MaxArchiveEntries = Math.Max(1, entries);
            else if (arg.Equals("--max-file-size-mb", StringComparison.OrdinalIgnoreCase) && int.TryParse(Next(), out var maxFile)) options.MaxFileSizeMB = Math.Max(0, maxFile);
        }
        return options;
    }

    private static bool ParseBool(string value, bool fallback)
    {
        if (bool.TryParse(value, out var parsed)) return parsed;
        if (value.Equals("1", StringComparison.OrdinalIgnoreCase) || value.Equals("yes", StringComparison.OrdinalIgnoreCase)) return true;
        if (value.Equals("0", StringComparison.OrdinalIgnoreCase) || value.Equals("no", StringComparison.OrdinalIgnoreCase)) return false;
        return fallback;
    }

    private static async Task RunSignatureUpdateAsync()
    {
        var engine = new ScanEngine();
        var settings = AppSettings.Load(engine.SettingsPath);
        if (string.IsNullOrWhiteSpace(settings.SignatureUpdateUrl)) return;

        string destination = Path.Combine(engine.SignatureRoot, "known_malicious_sha256.txt");
        bool ok = await UpdateManager.UpdateSignaturesAsync(settings.SignatureUpdateUrl, destination);
        if (!ok)
            WriteStartupCrashLog(new InvalidOperationException("Falha ao atualizar assinaturas pelo modo CLI."));
    }

    private static void ShowTrayAlert(string title, string message)
    {
        try
        {
            using var notif = new System.Windows.Forms.NotifyIcon
            {
                Visible = true,
                Icon    = System.Drawing.SystemIcons.Warning,
            };
            notif.ShowBalloonTip(6000, title, message, System.Windows.Forms.ToolTipIcon.Warning);
            Thread.Sleep(6500);
        }
        catch (Exception)
        {
            // Best-effort fallback notification - must never throw back into startup error handling.
        }
    }
}
