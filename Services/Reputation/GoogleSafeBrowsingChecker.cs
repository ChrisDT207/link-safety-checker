using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using LinkSafetyChecker.Configuration;
using LinkSafetyChecker.Interfaces;
using LinkSafetyChecker.Models;
using Microsoft.Extensions.Logging;

namespace LinkSafetyChecker.Services.Reputation;

public class GoogleSafeBrowsingChecker : IReputationApiChecker
{
    private readonly IApiConfigurationService _configService;
    private readonly HttpClient _httpClient;
    private readonly ILogger<GoogleSafeBrowsingChecker> _logger;

    public string ProviderName => "Google Safe Browsing";
    public bool IsConfigured => _configService.IsGoogleSafeBrowsingEnabled && !string.IsNullOrWhiteSpace(_configService.GoogleSafeBrowsingKey);

    public GoogleSafeBrowsingChecker(
        IApiConfigurationService configService,
        HttpClient httpClient,
        ILogger<GoogleSafeBrowsingChecker> logger)
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

        if (!_configService.IsGoogleSafeBrowsingEnabled)
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
            var apiKey = _configService.GoogleSafeBrowsingKey;
            var endpoint = $"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={apiKey}";
            var payload = new
            {
                client = new { clientId = "LinkSafetyCheckerDesktop", clientVersion = "1.0.0" },
                threatInfo = new
                {
                    threatTypes = new[] { "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION" },
                    platformTypes = new[] { "ANY_PLATFORM" },
                    threatEntryTypes = new[] { "URL" },
                    threatEntries = new[] { new { url = uri.ToString() } }
                }
            };

            using var response = await _httpClient.PostAsJsonAsync(endpoint, payload, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                result.IsChecked = false;
                result.StatusMessage = $"API error: HTTP {(int)response.StatusCode}";
                return result;
            }

            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            var root = JsonNode.Parse(content);
            var matches = root?["matches"]?.AsArray();

            result.IsChecked = true;
            if (matches != null && matches.Count > 0)
            {
                result.IsMalicious = true;
                var threatType = matches[0]?["threatType"]?.ToString() ?? "MALICIOUS";
                result.ThreatType = threatType;
                result.StatusMessage = $"Flagged by Google Safe Browsing as {threatType}";
                result.Details["ThreatType"] = threatType;
                result.Details["Platform"] = matches[0]?["platformType"]?.ToString() ?? "ANY";
            }
            else
            {
                result.IsMalicious = false;
                result.StatusMessage = "No threats found in Google Safe Browsing database.";
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Google Safe Browsing check failed.");
            result.IsChecked = false;
            result.StatusMessage = $"Check failed: {ex.Message}";
        }

        return result;
    }
}
