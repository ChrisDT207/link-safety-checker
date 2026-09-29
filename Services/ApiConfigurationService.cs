using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using LinkSafetyChecker.Configuration;
using LinkSafetyChecker.Interfaces;
using LinkSafetyChecker.Models;
using Microsoft.Extensions.Logging;

namespace LinkSafetyChecker.Services;

public class ApiConfigurationService : IApiConfigurationService
{
    private readonly ApiKeysConfig _config;
    private readonly HttpClient _httpClient;
    private readonly ILogger<ApiConfigurationService> _logger;
    private readonly object _lock = new();

    public ApiConfigurationService(
        ApiKeysConfig config,
        HttpClient httpClient,
        ILogger<ApiConfigurationService> logger)
    {
        _config = config;
        _httpClient = httpClient;
        _logger = logger;

        // Check environment variable fallbacks if not already set
        if (string.IsNullOrWhiteSpace(_config.VirusTotal))
        {
            var envVt = Environment.GetEnvironmentVariable("URLCHECKER_VIRUSTOTAL_KEY");
            if (!string.IsNullOrWhiteSpace(envVt)) _config.VirusTotal = envVt.Trim();
        }

        if (string.IsNullOrWhiteSpace(_config.GoogleSafeBrowsing))
        {
            var envGsb = Environment.GetEnvironmentVariable("URLCHECKER_GOOGLE_SAFE_BROWSING_KEY");
            if (!string.IsNullOrWhiteSpace(envGsb)) _config.GoogleSafeBrowsing = envGsb.Trim();
        }

        if (string.IsNullOrWhiteSpace(_config.WhoisXml))
        {
            var envWhois = Environment.GetEnvironmentVariable("URLCHECKER_WHOISXML_KEY");
            if (!string.IsNullOrWhiteSpace(envWhois)) _config.WhoisXml = envWhois.Trim();
        }
    }

    public bool IsVirusTotalEnabled => _config.VirusTotalEnabled;
    public string VirusTotalKey => _config.VirusTotal;

    public bool IsGoogleSafeBrowsingEnabled => _config.GoogleSafeBrowsingEnabled;
    public string GoogleSafeBrowsingKey => _config.GoogleSafeBrowsing;

    public string WhoisXmlKey => _config.WhoisXml;

    public ApiConfigDto GetConfigDto()
    {
        lock (_lock)
        {
            return new ApiConfigDto
            {
                VirusTotalKeyMasked = MaskKey(_config.VirusTotal),
                VirusTotalHasKey = !string.IsNullOrWhiteSpace(_config.VirusTotal),
                VirusTotalEnabled = _config.VirusTotalEnabled,

                GoogleSafeBrowsingKeyMasked = MaskKey(_config.GoogleSafeBrowsing),
                GoogleSafeBrowsingHasKey = !string.IsNullOrWhiteSpace(_config.GoogleSafeBrowsing),
                GoogleSafeBrowsingEnabled = _config.GoogleSafeBrowsingEnabled,

                WhoisXmlKeyMasked = MaskKey(_config.WhoisXml),
                WhoisXmlHasKey = !string.IsNullOrWhiteSpace(_config.WhoisXml)
            };
        }
    }

    public string GetRawKey(string provider)
    {
        lock (_lock)
        {
            if (string.Equals(provider, "VirusTotal", StringComparison.OrdinalIgnoreCase))
            {
                return _config.VirusTotal;
            }

            if (string.Equals(provider, "GoogleSafeBrowsing", StringComparison.OrdinalIgnoreCase))
            {
                return _config.GoogleSafeBrowsing;
            }

            if (string.Equals(provider, "WhoisXml", StringComparison.OrdinalIgnoreCase))
            {
                return _config.WhoisXml;
            }

            return string.Empty;
        }
    }

    public async Task<bool> SaveConfigAsync(SaveApiConfigRequest request)
    {
        lock (_lock)
        {
            // Sanitize & Update VirusTotal
            _config.VirusTotalEnabled = request.VirusTotalEnabled;
            if (request.VirusTotalKey != null && !IsMasked(request.VirusTotalKey))
            {
                _config.VirusTotal = SanitizeKey(request.VirusTotalKey);
            }

            // Sanitize & Update Google Safe Browsing
            _config.GoogleSafeBrowsingEnabled = request.GoogleSafeBrowsingEnabled;
            if (request.GoogleSafeBrowsingKey != null && !IsMasked(request.GoogleSafeBrowsingKey))
            {
                _config.GoogleSafeBrowsing = SanitizeKey(request.GoogleSafeBrowsingKey);
            }

            // Update optional WhoisXml if provided
            if (request.WhoisXmlKey != null && !IsMasked(request.WhoisXmlKey))
            {
                _config.WhoisXml = SanitizeKey(request.WhoisXmlKey);
            }
        }

        // Persist to appsettings.json dynamically on disk
        return await PersistToAppSettingsAsync();
    }

    public async Task<TestApiKeyResponse> TestKeyAsync(TestApiKeyRequest request, CancellationToken cancellationToken = default)
    {
        var provider = request.Provider?.Trim() ?? string.Empty;
        string keyToTest;

        lock (_lock)
        {
            if (string.Equals(provider, "VirusTotal", StringComparison.OrdinalIgnoreCase))
            {
                keyToTest = !string.IsNullOrWhiteSpace(request.Key) && !IsMasked(request.Key)
                    ? SanitizeKey(request.Key)
                    : _config.VirusTotal;
            }
            else if (string.Equals(provider, "GoogleSafeBrowsing", StringComparison.OrdinalIgnoreCase))
            {
                keyToTest = !string.IsNullOrWhiteSpace(request.Key) && !IsMasked(request.Key)
                    ? SanitizeKey(request.Key)
                    : _config.GoogleSafeBrowsing;
            }
            else
            {
                return new TestApiKeyResponse
                {
                    Success = false,
                    Provider = provider,
                    StatusMessage = $"Unsupported provider: '{provider}'."
                };
            }
        }

        if (string.IsNullOrWhiteSpace(keyToTest))
        {
            return new TestApiKeyResponse
            {
                Success = false,
                Provider = provider,
                StatusMessage = "No API key was entered or currently saved to test."
            };
        }

        try
        {
            if (string.Equals(provider, "VirusTotal", StringComparison.OrdinalIgnoreCase))
            {
                return await TestVirusTotalKeyAsync(keyToTest, cancellationToken);
            }

            return await TestGoogleSafeBrowsingKeyAsync(keyToTest, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to test {Provider} API key.", provider);
            return new TestApiKeyResponse
            {
                Success = false,
                Provider = provider,
                StatusMessage = $"Connection failed: {ex.Message}"
            };
        }
    }

    private async Task<TestApiKeyResponse> TestVirusTotalKeyAsync(string apiKey, CancellationToken cancellationToken)
    {
        using var testRequest = new HttpRequestMessage(HttpMethod.Get, "https://www.virustotal.com/api/v3/domains/google.com");
        testRequest.Headers.Add("x-apikey", apiKey);

        using var response = await _httpClient.SendAsync(testRequest, cancellationToken);

        if (response.IsSuccessStatusCode)
        {
            return new TestApiKeyResponse
            {
                Success = true,
                Provider = "VirusTotal",
                StatusMessage = "Online: VirusTotal v3 API key authenticated successfully (HTTP 200)."
            };
        }

        if ((int)response.StatusCode == 401 || (int)response.StatusCode == 403)
        {
            return new TestApiKeyResponse
            {
                Success = false,
                Provider = "VirusTotal",
                StatusMessage = $"Invalid API key: Unauthorized (HTTP {(int)response.StatusCode}). Check that your key is correct."
            };
        }

        if ((int)response.StatusCode == 429)
        {
            return new TestApiKeyResponse
            {
                Success = true,
                Provider = "VirusTotal",
                StatusMessage = "Key authenticated, but VirusTotal rate limit was hit (HTTP 429)."
            };
        }

        return new TestApiKeyResponse
        {
            Success = false,
            Provider = "VirusTotal",
            StatusMessage = $"VirusTotal responded with HTTP {(int)response.StatusCode} ({response.ReasonPhrase})."
        };
    }

    private async Task<TestApiKeyResponse> TestGoogleSafeBrowsingKeyAsync(string apiKey, CancellationToken cancellationToken)
    {
        var endpoint = $"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={apiKey}";
        var payload = new
        {
            client = new { clientId = "LinkSafetyChecker", clientVersion = "1.0.0" },
            threatInfo = new
            {
                threatTypes = new[] { "MALWARE" },
                platformTypes = new[] { "ANY_PLATFORM" },
                threatEntryTypes = new[] { "URL" },
                threatEntries = new[] { new { url = "https://google.com" } }
            }
        };

        using var response = await _httpClient.PostAsJsonAsync(endpoint, payload, cancellationToken);

        if (response.IsSuccessStatusCode)
        {
            return new TestApiKeyResponse
            {
                Success = true,
                Provider = "Google Safe Browsing",
                StatusMessage = "Online: Google Safe Browsing API key authenticated successfully (HTTP 200)."
            };
        }

        if ((int)response.StatusCode == 400 || (int)response.StatusCode == 403)
        {
            return new TestApiKeyResponse
            {
                Success = false,
                Provider = "Google Safe Browsing",
                StatusMessage = $"Validation failed: HTTP {(int)response.StatusCode}. Verify key and confirm 'Safe Browsing API' is enabled in Google Cloud Console."
            };
        }

        return new TestApiKeyResponse
        {
            Success = false,
            Provider = "Google Safe Browsing",
            StatusMessage = $"Google Safe Browsing responded with HTTP {(int)response.StatusCode} ({response.ReasonPhrase})."
        };
    }

    private async Task<bool> PersistToAppSettingsAsync()
    {
        var targetPaths = new List<string>
        {
            Path.Combine(AppContext.BaseDirectory, "appsettings.json"),
            Path.Combine(Directory.GetCurrentDirectory(), "appsettings.json")
        }.Distinct();

        var success = false;

        foreach (var path in targetPaths)
        {
            try
            {
                JsonNode root;
                if (File.Exists(path))
                {
                    var text = await File.ReadAllTextAsync(path);
                    root = JsonNode.Parse(text) ?? new JsonObject();
                }
                else
                {
                    root = new JsonObject();
                }

                if (root["ApiKeys"] == null)
                {
                    root["ApiKeys"] = new JsonObject();
                }

                var apiKeysNode = root["ApiKeys"]!;
                lock (_lock)
                {
                    apiKeysNode["VirusTotal"] = _config.VirusTotal;
                    apiKeysNode["VirusTotalEnabled"] = _config.VirusTotalEnabled;
                    apiKeysNode["GoogleSafeBrowsing"] = _config.GoogleSafeBrowsing;
                    apiKeysNode["GoogleSafeBrowsingEnabled"] = _config.GoogleSafeBrowsingEnabled;
                    apiKeysNode["WhoisXml"] = _config.WhoisXml;
                }

                var options = new JsonSerializerOptions { WriteIndented = true };
                var updatedJson = root.ToJsonString(options);
                await File.WriteAllTextAsync(path, updatedJson);

                _logger.LogInformation("Persisted updated API configuration to: {Path}", path);
                success = true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to persist API configuration to {Path}", path);
            }
        }

        return success;
    }

    public static string MaskKey(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return string.Empty;
        }

        var trimmed = key.Trim();
        if (trimmed.Length <= 8)
        {
            return new string('•', trimmed.Length);
        }

        return $"{trimmed[..4]}••••••••{trimmed[^4..]}";
    }

    private static bool IsMasked(string key)
    {
        return key.Contains('•') || key.Contains('*');
    }

    private static string SanitizeKey(string key)
    {
        if (string.IsNullOrWhiteSpace(key)) return string.Empty;
        var sanitized = key.Trim();
        // Remove newlines and control characters
        sanitized = new string(sanitized.Where(c => !char.IsControl(c)).ToArray());
        return sanitized.Length > 256 ? sanitized[..256] : sanitized;
    }
}
