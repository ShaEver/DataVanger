using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using DataVanger.Core;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;

namespace DataVanger;

public partial class SettingsWindow : Window
{
    private readonly string _settingsPath;
    private readonly AppSettings _settings;

    public SettingsWindow(string settingsPath)
    {
        InitializeComponent();
        _settingsPath = settingsPath;
        _settings = AppSettings.Load(settingsPath);

        TxtExtraTargets.Text = string.Join(Environment.NewLine, _settings.ExtraTargets);
        TxtExcludedPaths.Text = string.Join(Environment.NewLine, _settings.ExcludedPaths);
        TxtTrustedPublishers.Text = string.Join(Environment.NewLine, _settings.ExtraTrustedPublishers);
        TxtMinScoreReport.Text = _settings.MinScoreToReport.ToString();
        TxtMinScoreQuarantine.Text = _settings.MinScoreToQuarantine.ToString();
        TxtSignatureUpdateUrl.Text = _settings.SignatureUpdateUrl;
        TxtSignedUpdateFeedUrl.Text = _settings.SignedUpdateFeedUrl;
        TxtSignedUpdateKeyId.Text = _settings.SignedUpdateKeyId;
        TxtSignedUpdateAlgorithm.Text = _settings.SignedUpdateAlgorithm;
        TxtSignedUpdateFeedId.Text = _settings.SignedUpdateFeedId;
        TxtSignedUpdatePublicKeyPem.Text = _settings.SignedUpdatePublicKeyPem;
        TxtYaraMaxScanSizeMB.Text = _settings.YaraMaxScanSizeMB.ToString();
        TxtArchiveMaxEntries.Text = _settings.ArchiveMaxEntries.ToString();
        TxtArchiveMaxDepth.Text = _settings.ArchiveMaxDepth.ToString();
        TxtArchiveMaxDecompressedMB.Text = _settings.ArchiveMaxDecompressedMB.ToString();

        ChkAutoQuarantineKnownMalware.IsChecked = _settings.AutoQuarantineKnownMalware;
        ChkSuppressAccessDeniedLog.IsChecked = _settings.SuppressAccessDeniedLog;
        ChkScanDownloads.IsChecked = _settings.ScanDownloads;
        ChkScanDesktop.IsChecked = _settings.ScanDesktop;
        ChkScanDocuments.IsChecked = _settings.ScanDocuments;
        ChkScanAppData.IsChecked = _settings.ScanAppData;
        ChkScanStartupLocations.IsChecked = _settings.ScanStartupLocations;
        ChkEnableYaraRules.IsChecked = _settings.EnableYaraRules;
        ChkDeepScanArchives.IsChecked = _settings.DeepScanArchives;
        ChkAnalyzeDocuments.IsChecked = _settings.AnalyzeDocuments;
        ChkAnalyzeBrowserExtensions.IsChecked = _settings.AnalyzeBrowserExtensions;
        ChkAnalyzeAds.IsChecked = _settings.AnalyzeAlternateDataStreams;
        ChkIncludeRemovableDrives.IsChecked = _settings.IncludeRemovableDrives;
        ChkAdvancedPersistenceChecks.IsChecked = _settings.AdvancedPersistenceChecks;
        ChkAnalyzeServicesAndDrivers.IsChecked = _settings.AnalyzeServicesAndDrivers;
        ChkAnalyzeScheduledTasks.IsChecked = _settings.AnalyzeScheduledTasks;
        ChkUseSafeCache.IsChecked = _settings.UseSafeCache;
        ChkEnableTrayProtection.IsChecked = _settings.EnableTrayProtection;

        BtnSave.Click += OnSave;
        BtnCancel.Click += (_, _) => Close();
    }

    private void OnSave(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(TxtMinScoreReport.Text.Trim(), out int minReport) || minReport < 0)
        {
            MessageBox.Show("Score mínimo para relatório inválido.", "DataVanger", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!int.TryParse(TxtMinScoreQuarantine.Text.Trim(), out int minQuarantine) || minQuarantine < 0)
        {
            MessageBox.Show("Score mínimo para quarentena inválido.", "DataVanger", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!int.TryParse(TxtYaraMaxScanSizeMB.Text.Trim(), out int yaraMaxMb) || yaraMaxMb < 1 || yaraMaxMb > 512)
        {
            MessageBox.Show("Tamanho máximo para YARA deve ficar entre 1 e 512 MB.", "DataVanger", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!int.TryParse(TxtArchiveMaxEntries.Text.Trim(), out int archiveMaxEntries) || archiveMaxEntries < 50 || archiveMaxEntries > 5000)
        {
            MessageBox.Show("Máximo de entradas por arquivo compactado deve ficar entre 50 e 5000.", "DataVanger", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!int.TryParse(TxtArchiveMaxDepth.Text.Trim(), out int archiveMaxDepth) || archiveMaxDepth < 0 || archiveMaxDepth > 8)
        {
            MessageBox.Show("Profundidade máxima de compactados deve ficar entre 0 e 8.", "DataVanger", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!int.TryParse(TxtArchiveMaxDecompressedMB.Text.Trim(), out int archiveMaxDecompressedMb) || archiveMaxDecompressedMb < 16 || archiveMaxDecompressedMb > 4096)
        {
            MessageBox.Show("Limite descompactado deve ficar entre 16 e 4096 MB.", "DataVanger", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _settings.ExtraTargets = SplitLines(TxtExtraTargets.Text);
        _settings.ExcludedPaths = SplitLines(TxtExcludedPaths.Text);
        _settings.ExtraTrustedPublishers = SplitLines(TxtTrustedPublishers.Text);
        _settings.MinScoreToReport = minReport;
        _settings.MinScoreToQuarantine = minQuarantine;
        _settings.SignatureUpdateUrl = TxtSignatureUpdateUrl.Text.Trim();
        _settings.SignedUpdateFeedUrl = TxtSignedUpdateFeedUrl.Text.Trim();
        _settings.SignedUpdateKeyId = TxtSignedUpdateKeyId.Text.Trim();
        _settings.SignedUpdateAlgorithm = TxtSignedUpdateAlgorithm.Text.Trim();
        _settings.SignedUpdateFeedId = TxtSignedUpdateFeedId.Text.Trim();
        _settings.SignedUpdatePublicKeyPem = TxtSignedUpdatePublicKeyPem.Text.Trim();
        _settings.YaraMaxScanSizeMB = yaraMaxMb;
        _settings.ArchiveMaxEntries = archiveMaxEntries;
        _settings.ArchiveMaxDepth = archiveMaxDepth;
        _settings.ArchiveMaxDecompressedMB = archiveMaxDecompressedMb;
        _settings.AutoQuarantineKnownMalware = ChkAutoQuarantineKnownMalware.IsChecked == true;
        _settings.SuppressAccessDeniedLog = ChkSuppressAccessDeniedLog.IsChecked == true;
        _settings.ScanDownloads = ChkScanDownloads.IsChecked == true;
        _settings.ScanDesktop = ChkScanDesktop.IsChecked == true;
        _settings.ScanDocuments = ChkScanDocuments.IsChecked == true;
        _settings.ScanAppData = ChkScanAppData.IsChecked == true;
        _settings.ScanStartupLocations = ChkScanStartupLocations.IsChecked == true;
        _settings.EnableYaraRules = ChkEnableYaraRules.IsChecked == true;
        _settings.DeepScanArchives = ChkDeepScanArchives.IsChecked == true;
        _settings.AnalyzeDocuments = ChkAnalyzeDocuments.IsChecked == true;
        _settings.AnalyzeBrowserExtensions = ChkAnalyzeBrowserExtensions.IsChecked == true;
        _settings.AnalyzeAlternateDataStreams = ChkAnalyzeAds.IsChecked == true;
        _settings.IncludeRemovableDrives = ChkIncludeRemovableDrives.IsChecked == true;
        _settings.AdvancedPersistenceChecks = ChkAdvancedPersistenceChecks.IsChecked == true;
        _settings.AnalyzeServicesAndDrivers = ChkAnalyzeServicesAndDrivers.IsChecked == true;
        _settings.AnalyzeScheduledTasks = ChkAnalyzeScheduledTasks.IsChecked == true;
        _settings.UseSafeCache = ChkUseSafeCache.IsChecked == true;
        _settings.EnableTrayProtection = ChkEnableTrayProtection.IsChecked == true;

        _settings.Save(_settingsPath);
        DialogResult = true;
    }

    private static List<string> SplitLines(string text) =>
        text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
            .Select(x => x.Trim())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
}
