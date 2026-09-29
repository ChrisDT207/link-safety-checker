using System.Net;
using LinkSafetyChecker.Configuration;
using LinkSafetyChecker.Interfaces;
using LinkSafetyChecker.Models;
using LinkSafetyChecker.Services;
using LinkSafetyChecker.Services.Reputation;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace LinkSafetyChecker.Tests;

public class VirusTotalCheckerTests
{
    private class TestHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;

        public TestHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(_handler(request));
        }
    }

    [Fact]
    public async Task CheckAsync_ReturnsCleanUnindexed_WhenVirusTotalReturns404NotFound()
    {
        var config = new ApiKeysConfig
        {
            VirusTotal = "test_valid_api_key_123456",
            VirusTotalEnabled = true
        };

        var configService = new ApiConfigurationService(config, new HttpClient(), NullLogger<ApiConfigurationService>.Instance);

        var testHandler = new TestHttpMessageHandler(req =>
        {
            return new HttpResponseMessage(HttpStatusCode.NotFound)
            {
                Content = new StringContent(@"{""error"": {""code"": ""NotFoundError"", ""message"": ""URL not found""}}")
            };
        });

        var httpClient = new HttpClient(testHandler);
        var checker = new VirusTotalChecker(configService, httpClient, NullLogger<VirusTotalChecker>.Instance);

        var targetUri = new Uri("https://brand-new-domain.com/page?query=example");
        var result = await checker.CheckAsync(targetUri);

        // Crucial bug fix verification:
        // Must be marked as Checked and Valid, Clean (not malicious), and informative status
        Assert.True(result.IsChecked);
        Assert.False(result.IsMalicious);
        Assert.Equal("UNKNOWN", result.ThreatType);
        Assert.Contains("not previously indexed", result.StatusMessage, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("Unindexed", result.Details["Status"]);

        // Verify that ScoringEngine does NOT deduct any points for this
        var scoringEngine = new ScoringEngine();
        var fetchResult = new HttpFetchResult { Success = true, StatusCode = 200 };
        var domResult = new DomInspectionResult { IsAnalyzed = true };
        var heuristicResult = new HeuristicResult();

        var score = scoringEngine.CalculateScore(targetUri, fetchResult, domResult, heuristicResult, [result]);
        Assert.Equal(100, score.Score);
        Assert.Equal("Safe", score.Rating);
        Assert.Empty(score.Deductions);
    }

    [Fact]
    public async Task CheckAsync_ReturnsClean_WhenVirusTotalReturnsZeroMaliciousEngines()
    {
        var config = new ApiKeysConfig
        {
            VirusTotal = "test_valid_api_key_123456",
            VirusTotalEnabled = true
        };

        var configService = new ApiConfigurationService(config, new HttpClient(), NullLogger<ApiConfigurationService>.Instance);

        var testHandler = new TestHttpMessageHandler(req =>
        {
            var json = @"{
                ""data"": {
                    ""attributes"": {
                        ""last_analysis_stats"": {
                            ""malicious"": 0,
                            ""suspicious"": 0,
                            ""harmless"": 72,
                            ""undetected"": 18
                        }
                    }
                }
            }";
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json)
            };
        });

        var httpClient = new HttpClient(testHandler);
        var checker = new VirusTotalChecker(configService, httpClient, NullLogger<VirusTotalChecker>.Instance);

        var targetUri = new Uri("https://trusted-site.org");
        var result = await checker.CheckAsync(targetUri);

        Assert.True(result.IsChecked);
        Assert.False(result.IsMalicious);
        Assert.Contains("Clean: 0/90", result.StatusMessage);
    }

    [Fact]
    public async Task CheckAsync_ReturnsMalicious_WhenVirusTotalReturnsMaliciousEngines()
    {
        var config = new ApiKeysConfig
        {
            VirusTotal = "test_valid_api_key_123456",
            VirusTotalEnabled = true
        };

        var configService = new ApiConfigurationService(config, new HttpClient(), NullLogger<ApiConfigurationService>.Instance);

        var testHandler = new TestHttpMessageHandler(req =>
        {
            var json = @"{
                ""data"": {
                    ""attributes"": {
                        ""last_analysis_stats"": {
                            ""malicious"": 12,
                            ""suspicious"": 3,
                            ""harmless"": 30,
                            ""undetected"": 40
                        }
                    }
                }
            }";
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json)
            };
        });

        var httpClient = new HttpClient(testHandler);
        var checker = new VirusTotalChecker(configService, httpClient, NullLogger<VirusTotalChecker>.Instance);

        var targetUri = new Uri("https://malware-drop-site.com");
        var result = await checker.CheckAsync(targetUri);

        Assert.True(result.IsChecked);
        Assert.True(result.IsMalicious);
        Assert.Equal("MALWARE / PHISHING", result.ThreatType);
        Assert.Contains("Flagged by 12 security vendor(s)", result.StatusMessage);
    }

    [Fact]
    public async Task CheckAsync_ReturnsUnchecked_WhenDisabled()
    {
        var config = new ApiKeysConfig
        {
            VirusTotal = "test_key",
            VirusTotalEnabled = false
        };

        var configService = new ApiConfigurationService(config, new HttpClient(), NullLogger<ApiConfigurationService>.Instance);
        var checker = new VirusTotalChecker(configService, new HttpClient(), NullLogger<VirusTotalChecker>.Instance);

        var result = await checker.CheckAsync(new Uri("https://example.com"));

        Assert.False(result.IsChecked);
        Assert.Contains("Disabled in settings", result.StatusMessage);
    }
}
