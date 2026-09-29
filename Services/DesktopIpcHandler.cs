using System.Text.Json;
using System.Text.Json.Nodes;
using LinkSafetyChecker.Interfaces;
using LinkSafetyChecker.Models;
using Microsoft.Extensions.Logging;
using Photino.NET;

namespace LinkSafetyChecker.Services;

public class DesktopIpcHandler : IDesktopIpcHandler
{
    private readonly IUrlAnalyzerService _analyzerService;
    private readonly IApiConfigurationService _apiConfigService;
    private readonly ILogger<DesktopIpcHandler> _logger;
    private PhotinoWindow? _window;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    public DesktopIpcHandler(
        IUrlAnalyzerService analyzerService,
        IApiConfigurationService apiConfigService,
        ILogger<DesktopIpcHandler> logger)
    {
        _analyzerService = analyzerService;
        _apiConfigService = apiConfigService;
        _logger = logger;
    }

    public void Attach(PhotinoWindow window)
    {
        _window = window;
        _window.RegisterWebMessageReceivedHandler(OnWebMessageReceived);
    }

    private void OnWebMessageReceived(object? sender, string message)
    {
        // 1. Input sanitization & size limit check
        if (string.IsNullOrWhiteSpace(message) || message.Length > 32768)
        {
            _logger.LogWarning("Rejected oversized or empty IPC message (Length: {Length})", message?.Length ?? 0);
            SendMessage(new { type = "ERROR", message = "Payload rejected: message is empty or exceeds 32KB limit." });
            return;
        }

        _logger.LogInformation("Processing IPC message: {Summary}", message.Length > 120 ? message[..120] + "..." : message);

        Task.Run(async () =>
        {
            try
            {
                var root = JsonNode.Parse(message);
                var type = root?["type"]?.ToString();

                if (string.Equals(type, "ANALYZE_URL", StringComparison.OrdinalIgnoreCase))
                {
                    var url = root?["url"]?.ToString() ?? string.Empty;

                    // Notify frontend analysis has started
                    SendMessage(new { type = "ANALYSIS_STARTED", url });

                    var result = await _analyzerService.AnalyzeUrlAsync(url);

                    // Send complete analysis result
                    SendMessage(new { type = "ANALYSIS_RESULT", data = result });
                }
                else if (string.Equals(type, "GET_API_CONFIG", StringComparison.OrdinalIgnoreCase))
                {
                    var config = _apiConfigService.GetConfigDto();
                    SendMessage(new { type = "API_CONFIG_DATA", data = config });
                }
                else if (string.Equals(type, "GET_RAW_API_KEY", StringComparison.OrdinalIgnoreCase))
                {
                    var provider = root?["provider"]?.ToString() ?? string.Empty;
                    var rawKey = _apiConfigService.GetRawKey(provider);
                    SendMessage(new { type = "RAW_API_KEY_DATA", provider, key = rawKey });
                }
                else if (string.Equals(type, "SAVE_API_CONFIG", StringComparison.OrdinalIgnoreCase))
                {
                    var request = new SaveApiConfigRequest
                    {
                        VirusTotalKey = root?["virusTotalKey"]?.ToString(),
                        VirusTotalEnabled = root?["virusTotalEnabled"]?.GetValue<bool>() ?? true,
                        GoogleSafeBrowsingKey = root?["googleSafeBrowsingKey"]?.ToString(),
                        GoogleSafeBrowsingEnabled = root?["googleSafeBrowsingEnabled"]?.GetValue<bool>() ?? true,
                        WhoisXmlKey = root?["whoisXmlKey"]?.ToString()
                    };

                    var success = await _apiConfigService.SaveConfigAsync(request);
                    var updatedConfig = _apiConfigService.GetConfigDto();
                    SendMessage(new { type = "API_CONFIG_SAVED", success, data = updatedConfig });
                }
                else if (string.Equals(type, "TEST_API_KEY", StringComparison.OrdinalIgnoreCase))
                {
                    var testReq = new TestApiKeyRequest
                    {
                        Provider = root?["provider"]?.ToString() ?? string.Empty,
                        Key = root?["key"]?.ToString()
                    };

                    var testResult = await _apiConfigService.TestKeyAsync(testReq);
                    SendMessage(new { type = "TEST_API_KEY_RESULT", data = testResult });
                }
                else if (string.Equals(type, "PING", StringComparison.OrdinalIgnoreCase))
                {
                    SendMessage(new { type = "PONG", timestamp = DateTime.UtcNow });
                }
                else
                {
                    SendMessage(new { type = "ERROR", message = $"Unknown action type: '{type}'" });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing IPC message.");
                SendMessage(new { type = "ERROR", message = $"Backend processing error: {ex.Message}" });
            }
        });
    }

    private void SendMessage(object payload)
    {
        if (_window == null) return;

        try
        {
            var json = JsonSerializer.Serialize(payload, JsonOptions);
            _window.SendWebMessage(json);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send IPC message to webview.");
        }
    }
}
