using System.Text.Json.Nodes;
using LinkSafetyChecker.Configuration;
using LinkSafetyChecker.Interfaces;
using LinkSafetyChecker.Models;
using Microsoft.Extensions.Logging;

namespace LinkSafetyChecker.Services.Reputation;

public class WhoisChecker : IReputationApiChecker
{
    private readonly string _apiKey;
    private readonly HttpClient _httpClient;
    private readonly ILogger<WhoisChecker> _logger;

    public string ProviderName => "WHOIS / RDAP Registration";
    public bool IsConfigured => true; // Always operational via open RDAP protocol, enhanced with WhoisXml if provided

    public WhoisChecker(
        ApiKeysConfig apiKeys,
        HttpClient httpClient,
        ILogger<WhoisChecker> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
        _apiKey = !string.IsNullOrWhiteSpace(apiKeys.WhoisXml)
            ? apiKeys.WhoisXml
            : Environment.GetEnvironmentVariable("URLCHECKER_WHOISXML_KEY") ?? string.Empty;
    }

    public async Task<ReputationResult> CheckAsync(Uri uri, CancellationToken cancellationToken = default)
    {
        var result = new ReputationResult
        {
            ProviderName = ProviderName
        };

        var host = uri.Host.ToLowerInvariant();
        var domain = ExtractRootDomain(host);

        try
        {
            // If WhoisXml key provided, use their REST endpoint, otherwise use open RDAP
            string requestUrl = !string.IsNullOrWhiteSpace(_apiKey)
                ? $"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={_apiKey}&domainName={domain}&outputFormat=JSON"
                : $"https://rdap.org/domain/{domain}";

            using var request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
            request.Headers.Add("Accept", "application/json");

            using var response = await _httpClient.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                result.IsChecked = true;
                result.StatusMessage = $"Registration data query completed with HTTP {(int)response.StatusCode}";
                result.Details["Domain"] = domain;
                return result;
            }

            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            var root = JsonNode.Parse(content);

            result.IsChecked = true;
            result.Details["Domain"] = domain;

            // Parse RDAP events for registration date
            DateTime? createdDate = null;
            var events = root?["events"]?.AsArray();
            if (events != null)
            {
                foreach (var evt in events)
                {
                    var action = evt?["eventAction"]?.ToString();
                    if (string.Equals(action, "registration", StringComparison.OrdinalIgnoreCase))
                    {
                        if (DateTime.TryParse(evt?["eventDate"]?.ToString(), out var dt))
                        {
                            createdDate = dt;
                            break;
                        }
                    }
                }
            }

            // Fallback to WhoisXml schema if present
            if (createdDate == null)
            {
                var createdStr = root?["WhoisRecord"]?["createdDate"]?.ToString();
                if (!string.IsNullOrEmpty(createdStr) && DateTime.TryParse(createdStr, out var parsedCreated))
                {
                    createdDate = parsedCreated;
                }
            }

            if (createdDate.HasValue)
            {
                var ageDays = (int)(DateTime.UtcNow - createdDate.Value.ToUniversalTime()).TotalDays;
                result.Details["CreatedDate"] = createdDate.Value.ToString("yyyy-MM-dd");
                result.Details["DomainAgeDays"] = ageDays.ToString();

                if (ageDays < 30)
                {
                    result.IsMalicious = false;
                    result.ThreatType = "NEWLY_REGISTERED_DOMAIN";
                    result.StatusMessage = $"Newly registered domain: created {ageDays} days ago ({createdDate.Value:yyyy-MM-dd}). High correlation with disposable phishing/malware campaigns.";
                }
                else
                {
                    result.StatusMessage = $"Established domain: created {createdDate.Value:yyyy-MM-dd} (Age: {ageDays / 365} yr, {ageDays % 365} days).";
                }
            }
            else
            {
                result.StatusMessage = $"Domain registration records active for '{domain}'.";
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "WHOIS / RDAP lookup failed for domain: {Domain}", domain);
            result.IsChecked = false;
            result.StatusMessage = $"WHOIS query skipped: {ex.Message}";
        }

        return result;
    }

    private static string ExtractRootDomain(string host)
    {
        var parts = host.Split('.');
        if (parts.Length <= 2)
        {
            return host;
        }
        return $"{parts[^2]}.{parts[^1]}";
    }
}
