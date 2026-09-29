using LinkSafetyChecker.Interfaces;
using LinkSafetyChecker.Security;
using LinkSafetyChecker.Services;
using LinkSafetyChecker.Services.Reputation;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace LinkSafetyChecker.Configuration;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddLinkSafetyServices(this IServiceCollection services, IConfiguration configuration)
    {
        // Bind configuration sections
        var apiKeysConfig = new ApiKeysConfig();
        configuration.GetSection("ApiKeys").Bind(apiKeysConfig);
        services.AddSingleton(apiKeysConfig);

        var securitySettings = new SecuritySettingsConfig();
        configuration.GetSection("SecuritySettings").Bind(securitySettings);
        services.AddSingleton(securitySettings);

        // Core security & network
        services.AddSingleton<ISsrfValidator, SsrfValidator>();
        services.AddSingleton<ISafeHttpClientService, SafeHttpClientService>();

        // Heuristics & DOM inspection
        services.AddSingleton<IDomInspectionChecker, DomInspectionChecker>();
        services.AddSingleton<IHeuristicChecker, UrlHeuristicChecker>();

        // API Configuration Service
        services.AddHttpClient<ApiConfigurationService>(client =>
        {
            client.Timeout = TimeSpan.FromSeconds(10);
        });
        services.AddSingleton<IApiConfigurationService, ApiConfigurationService>(sp =>
            new ApiConfigurationService(
                sp.GetRequiredService<ApiKeysConfig>(),
                sp.GetRequiredService<IHttpClientFactory>().CreateClient(nameof(ApiConfigurationService)),
                sp.GetRequiredService<ILogger<ApiConfigurationService>>()));

        // External reputation checkers
        services.AddHttpClient<GoogleSafeBrowsingChecker>(client =>
        {
            client.Timeout = TimeSpan.FromSeconds(10);
        });
        services.AddHttpClient<VirusTotalChecker>(client =>
        {
            client.Timeout = TimeSpan.FromSeconds(10);
        });
        services.AddHttpClient<WhoisChecker>(client =>
        {
            client.Timeout = TimeSpan.FromSeconds(10);
        });

        services.AddSingleton<IReputationApiChecker, GoogleSafeBrowsingChecker>(sp =>
            new GoogleSafeBrowsingChecker(
                sp.GetRequiredService<IApiConfigurationService>(),
                sp.GetRequiredService<IHttpClientFactory>().CreateClient(nameof(GoogleSafeBrowsingChecker)),
                sp.GetRequiredService<ILogger<GoogleSafeBrowsingChecker>>()));

        services.AddSingleton<IReputationApiChecker, VirusTotalChecker>(sp =>
            new VirusTotalChecker(
                sp.GetRequiredService<IApiConfigurationService>(),
                sp.GetRequiredService<IHttpClientFactory>().CreateClient(nameof(VirusTotalChecker)),
                sp.GetRequiredService<ILogger<VirusTotalChecker>>()));

        services.AddSingleton<IReputationApiChecker, WhoisChecker>(sp =>
            new WhoisChecker(
                sp.GetRequiredService<ApiKeysConfig>(),
                sp.GetRequiredService<IHttpClientFactory>().CreateClient(nameof(WhoisChecker)),
                sp.GetRequiredService<ILogger<WhoisChecker>>()));

        // Central scoring & orchestrator
        services.AddSingleton<IScoringEngine, ScoringEngine>();
        services.AddSingleton<IUrlAnalyzerService, UrlAnalyzerService>();
        services.AddSingleton<IDesktopIpcHandler, DesktopIpcHandler>();
        services.AddSingleton<IStaticAssetManager, StaticAssetManager>();

        return services;
    }
}
