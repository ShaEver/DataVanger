using System;
using System.Collections.Generic;
using DataVanger.Engine.Updates.SignedUpdates;
using DataVanger.Shared.Updates;

namespace DataVanger.Core;

public enum SignedFeedConfigurationState
{
    Disabled,
    NotConfigured,
    ReadyOperatorManaged,
}

public sealed record SignedFeedConfigurationStatus(
    SignedFeedConfigurationState State,
    IReadOnlyList<string> MissingRequirements)
{
    public bool CanContactNetwork => State == SignedFeedConfigurationState.ReadyOperatorManaged;

    public string Message
    {
        get
        {
            string missing = MissingRequirements.Count == 0
                ? string.Empty
                : " Elementos ausentes/inválidos: " + string.Join(", ", MissingRequirements) + ".";
            return State switch
            {
                SignedFeedConfigurationState.Disabled =>
                    "Atualizações assinadas estão desativadas." + missing +
                    " Nenhuma solicitação de rede ou escrita foi realizada.",
                SignedFeedConfigurationState.NotConfigured =>
                    "Feed assinado não configurado." + missing +
                    " Nenhuma solicitação de rede ou escrita foi realizada.",
                _ => "Feed assinado configurado em modo development/operator. A chave do appsettings do usuário não é uma raiz de confiança de produção.",
            };
        }
    }
}

public sealed record SignedFeedRunResult(
    int ExitCode,
    SignedFeedConfigurationStatus Configuration,
    UpdateApplyResult? ApplyResult,
    string Message)
{
    public const int ExitSuccess = 0;
    public const int ExitDisabled = 20;
    public const int ExitNotConfigured = 21;
    public const int ExitRejectedOrFailed = 22;

    public bool Succeeded => ExitCode == ExitSuccess && ApplyResult is { Succeeded: true };
}

/// <summary>
/// The only UI/CLI composition path for signature updates. It is fail-closed:
/// incomplete configuration returns before constructing a transport, and no
/// unsigned fallback exists. User-supplied PEM is explicitly operator/development
/// trust, never a vendor production trust root.
/// </summary>
public static class SignedFeedUpdateRunner
{
    public static SignedFeedConfigurationStatus InspectConfiguration(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var missing = new List<string>();

        if (!Uri.TryCreate(settings.SignedUpdateFeedUrl?.Trim(), UriKind.Absolute, out var feedUri) ||
            !string.Equals(feedUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            missing.Add("URL HTTPS válida");
        if (string.IsNullOrWhiteSpace(settings.SignedUpdateFeedId)) missing.Add("feed id");
        if (string.IsNullOrWhiteSpace(settings.SignedUpdateKeyId)) missing.Add("key id");
        if (!IsSupportedAlgorithm(settings.SignedUpdateAlgorithm)) missing.Add("algoritmo suportado");
        if (string.IsNullOrWhiteSpace(settings.SignedUpdatePublicKeyPem)) missing.Add("chave pública pinada (PEM)");

        if (!settings.EnableHttpSignedUpdates)
            return new SignedFeedConfigurationStatus(SignedFeedConfigurationState.Disabled, missing);
        if (missing.Count > 0)
            return new SignedFeedConfigurationStatus(SignedFeedConfigurationState.NotConfigured, missing);
        return new SignedFeedConfigurationStatus(SignedFeedConfigurationState.ReadyOperatorManaged, Array.Empty<string>());
    }

    public static SignedFeedRunResult Run(
        AppSettings settings,
        string signatureRoot,
        string stateDirectory,
        Func<HttpUpdateTransportOptions, IUpdateTransport>? transportFactory = null)
    {
        var configuration = InspectConfiguration(settings);
        if (!configuration.CanContactNetwork)
        {
            int code = configuration.State == SignedFeedConfigurationState.Disabled
                ? SignedFeedRunResult.ExitDisabled
                : SignedFeedRunResult.ExitNotConfigured;
            return new SignedFeedRunResult(code, configuration, null, configuration.Message);
        }

        IUpdateTransport? transport = null;
        try
        {
            string algorithm = settings.SignedUpdateAlgorithm.Trim();
            var pinned = new[]
            {
                new PinnedPublicKey(settings.SignedUpdateKeyId.Trim(), algorithm, settings.SignedUpdatePublicKeyPem),
            };
            var httpOptions = HttpUpdateTransportOptions.Create(
                enabled: true,
                feedUrl: settings.SignedUpdateFeedUrl,
                timeoutSeconds: settings.SignedUpdateHttpTimeoutSeconds,
                maxManifestSizeKB: settings.SignedUpdateMaxManifestSizeKB,
                maxPackageSizeMB: settings.SignedUpdateMaxPackageSizeMB);
            var policy = new UpdatePolicy
            {
                Mode = UpdateMode.AutoApplyFeedsOnly,
                FeedId = settings.SignedUpdateFeedId.Trim(),
            };

            transport = transportFactory?.Invoke(httpOptions) ?? new HttpUpdateTransport(httpOptions);
            var service = SignedFeedUpdater.Create(policy, pinned, transport, signatureRoot, stateDirectory);
            var apply = service.CheckAndApply();
            int exit = apply.Succeeded ? SignedFeedRunResult.ExitSuccess : SignedFeedRunResult.ExitRejectedOrFailed;
            return new SignedFeedRunResult(exit, configuration, apply, apply.Message);
        }
        catch (Exception)
        {
            const string message = "Atualização assinada falhou de forma contida; assinaturas existentes foram preservadas.";
            return new SignedFeedRunResult(
                SignedFeedRunResult.ExitRejectedOrFailed, configuration, null, message);
        }
        finally
        {
            if (transport is IDisposable disposable) disposable.Dispose();
        }
    }

    private static bool IsSupportedAlgorithm(string? algorithm) =>
        string.Equals(algorithm?.Trim(), SignedManifestVerifier.AlgorithmRsaPss, StringComparison.Ordinal) ||
        string.Equals(algorithm?.Trim(), SignedManifestVerifier.AlgorithmEcdsaP256, StringComparison.Ordinal);
}
