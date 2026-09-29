using LinkSafetyChecker.Models;

namespace LinkSafetyChecker.Interfaces;

public interface IApiConfigurationService
{
    ApiConfigDto GetConfigDto();
    string GetRawKey(string provider);
    Task<bool> SaveConfigAsync(SaveApiConfigRequest request);
    Task<TestApiKeyResponse> TestKeyAsync(TestApiKeyRequest request, CancellationToken cancellationToken = default);

    bool IsVirusTotalEnabled { get; }
    string VirusTotalKey { get; }

    bool IsGoogleSafeBrowsingEnabled { get; }
    string GoogleSafeBrowsingKey { get; }

    string WhoisXmlKey { get; }
}
