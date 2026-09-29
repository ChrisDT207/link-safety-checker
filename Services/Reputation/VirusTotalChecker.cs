using System.Text;
using System.Text.Json.Nodes;
using LinkSafetyChecker.Configuration;
using LinkSafetyChecker.Interfaces;
using LinkSafetyChecker.Models;
using Microsoft.Extensions.Logging;

namespace LinkSafetyChecker.Services.Reputation;

public class VirusTotalChecker : IReputationApiChecker
{
    private readonly IApiConfigurationService _configService;
    private readonly HttpClient _httpClient;
    private readonly ILogger<VirusTotalChecker> _logger;

    public string ProviderName => "VirusTotal";
    public bool IsConfigured => _configService.IsVirusTotalEnabled && !string.IsNullOrWhiteSpace(_configService.VirusTotalKey);

    public VirusTotalChecker(
        IApiConfigurationService configService,
        HttpClient httpClient,
        ILogger<VirusTotalChecker> logger)
    {
        _configService = configService;
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<ReputationResult> CheckAsync(Uri uri, CancellationToken cancellationToken = default)
    {
        var result = new ReputationResult
        {
            ProviderName = ProviderName
        };

        if (!_configService.IsVirusTotalEnabled)
        {
            result.IsChecked = false;
            result.StatusMessage = "Disabled in settings";
            return result;
        }

        if (!IsConfigured)
        {
            result.IsChecked = false;
            result.StatusMessage = "Skipped (API Key not configured in appsettings.json or environment)";
            return result;
        }

        try
        {
            var apiKey = _configService.VirusTotalKey;
            // VirusTotal v3 URL identifier is Base64 of the URL without '=' padding
            var urlBytes = Encoding.UTF8.GetBytes(uri.ToString());
            var urlId = Convert.ToBase64String(urlBytes).TrimEnd('=');

            using var request = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/urls/{urlId}");
            request.Headers.Add("x-apikey", apiKey);

            using var response = await _httpClient.SendAsync(request, cancellationToken);

            // Handle HTTP 404 (NotFound): URL has not been previously scanned or indexed in VirusTotal
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                result.IsChecked = true;
                result.IsMalicious = false;
                result.ThreatType = "UNKNOWN";
                result.StatusMessage = "No threats detected (URL not previously indexed in VirusTotal).";
                result.Details["Status"] = "Unindexed";
                result.Details["Indexed"] = "Not previously indexed in VirusTotal";
                return result;
            }

            if (!response.IsSuccessStatusCode)
            {
                result.IsChecked = false;
                result.StatusMessage = $"API response: HTTP {(int)response.StatusCode} ({response.ReasonPhrase})";
                return result;
            }

            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            var root = JsonNode.Parse(content);
            var stats = root?["data"]?["attributes"]?["last_analysis_stats"];

            if (stats != null)
            {
                var malicious = stats["malicious"]?.GetValue<int>() ?? 0;
                var suspicious = stats["suspicious"]?.GetValue<int>() ?? 0;
                var harmless = stats["harmless"]?.GetValue<int>() ?? 0;
                var undetected = stats["undetected"]?.GetValue<int>() ?? 0;

                result.IsChecked = true;
                result.IsMalicious = (malicious + suspicious) > 0;
                result.Details["MaliciousEngines"] = malicious.ToString();
                result.Details["SuspiciousEngines"] = suspicious.ToString();
                result.Details["HarmlessEngines"] = harmless.ToString();
                result.Details["UndetectedEngines"] = undetected.ToString();

                if (result.IsMalicious)
                {
                    result.ThreatType = malicious > 0 ? "MALWARE / PHISHING" : "SUSPICIOUS";
                    result.StatusMessage = $"Flagged by {malicious} security vendor(s) on VirusTotal ({suspicious} suspicious).";
                }
                else
                {
                    result.ThreatType = "CLEAN";
                    result.StatusMessage = $"Clean: 0/{malicious + suspicious + harmless + undetected} security engines flagged this URL.";
                }
            }
            else
            {
                result.IsChecked = true;
                result.IsMalicious = false;
                result.ThreatType = "UNKNOWN";
                result.StatusMessage = "No recent analysis stats available on VirusTotal.";
                result.Details["Status"] = "No Stats Available";
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "VirusTotal check failed.");
            result.IsChecked = false;
            result.StatusMessage = $"Check failed: {ex.Message}";
        }

        return result;
    }
}
