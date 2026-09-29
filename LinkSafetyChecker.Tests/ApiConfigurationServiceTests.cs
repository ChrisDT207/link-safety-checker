using LinkSafetyChecker.Configuration;
using LinkSafetyChecker.Models;
using LinkSafetyChecker.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace LinkSafetyChecker.Tests;

public class ApiConfigurationServiceTests
{
    private readonly ApiKeysConfig _config;
    private readonly HttpClient _httpClient;
    private readonly ApiConfigurationService _service;

    public ApiConfigurationServiceTests()
    {
        _config = new ApiKeysConfig
        {
            VirusTotal = "abcdef1234567890abcdef",
            VirusTotalEnabled = true,
            GoogleSafeBrowsing = "AIzaSyD-GSB-Key12345678",
            GoogleSafeBrowsingEnabled = true,
            WhoisXml = "at_whoiskey123456"
        };

        _httpClient = new HttpClient();
        _service = new ApiConfigurationService(_config, _httpClient, NullLogger<ApiConfigurationService>.Instance);
    }

    [Fact]
    public void MaskKey_ReturnsEmpty_WhenNullOrWhitespace()
    {
        Assert.Equal(string.Empty, ApiConfigurationService.MaskKey(null!));
        Assert.Equal(string.Empty, ApiConfigurationService.MaskKey(""));
        Assert.Equal(string.Empty, ApiConfigurationService.MaskKey("   "));
    }

    [Fact]
    public void MaskKey_ReturnsDots_WhenKeyIsShort()
    {
        var shortKey = "secret";
        var masked = ApiConfigurationService.MaskKey(shortKey);

        Assert.Equal("••••••", masked);
        Assert.Equal(shortKey.Length, masked.Length);
    }

    [Fact]
    public void MaskKey_MasksMiddle_WhenKeyIsStandardLength()
    {
        var key = "33139876543210de3";
        var masked = ApiConfigurationService.MaskKey(key);

        Assert.StartsWith("3313", masked);
        Assert.EndsWith("0de3", masked);
        Assert.Contains("••••••••", masked);
        Assert.Equal("3313••••••••0de3", masked);
    }

    [Fact]
    public void GetConfigDto_ReturnsMaskedKeysAndFlags()
    {
        var dto = _service.GetConfigDto();

        Assert.True(dto.VirusTotalHasKey);
        Assert.True(dto.VirusTotalEnabled);
        Assert.StartsWith("abcd", dto.VirusTotalKeyMasked);
        Assert.EndsWith("cdef", dto.VirusTotalKeyMasked);
        Assert.Contains("••••••••", dto.VirusTotalKeyMasked);

        Assert.True(dto.GoogleSafeBrowsingHasKey);
        Assert.True(dto.GoogleSafeBrowsingEnabled);
        Assert.StartsWith("AIza", dto.GoogleSafeBrowsingKeyMasked);
        Assert.EndsWith("5678", dto.GoogleSafeBrowsingKeyMasked);

        Assert.True(dto.WhoisXmlHasKey);
    }

    [Fact]
    public void GetRawKey_ReturnsExpectedRawKeys()
    {
        Assert.Equal("abcdef1234567890abcdef", _service.GetRawKey("VirusTotal"));
        Assert.Equal("AIzaSyD-GSB-Key12345678", _service.GetRawKey("GoogleSafeBrowsing"));
        Assert.Equal("at_whoiskey123456", _service.GetRawKey("WhoisXml"));
        Assert.Equal(string.Empty, _service.GetRawKey("NonExistentProvider"));
    }

    [Fact]
    public async Task SaveConfigAsync_UpdatesKeysAndEnabledStatus()
    {
        var request = new SaveApiConfigRequest
        {
            VirusTotalEnabled = false,
            VirusTotalKey = "new_vt_key_99999999",
            GoogleSafeBrowsingEnabled = true,
            GoogleSafeBrowsingKey = "new_gsb_key_88888888"
        };

        var saved = await _service.SaveConfigAsync(request);

        Assert.True(saved);
        Assert.False(_service.IsVirusTotalEnabled);
        Assert.Equal("new_vt_key_99999999", _service.VirusTotalKey);
        Assert.True(_service.IsGoogleSafeBrowsingEnabled);
        Assert.Equal("new_gsb_key_88888888", _service.GoogleSafeBrowsingKey);
    }

    [Fact]
    public async Task SaveConfigAsync_DoesNotOverwriteWithMaskedKey()
    {
        var originalVtKey = _service.VirusTotalKey;

        var request = new SaveApiConfigRequest
        {
            VirusTotalEnabled = true,
            VirusTotalKey = "abcd••••••••cdef", // User sent back the masked key without editing
            GoogleSafeBrowsingEnabled = false,
            GoogleSafeBrowsingKey = null
        };

        await _service.SaveConfigAsync(request);

        // VirusTotal key must remain intact, not replaced by the masked string
        Assert.Equal(originalVtKey, _service.VirusTotalKey);
        Assert.False(_service.IsGoogleSafeBrowsingEnabled);
    }

    [Fact]
    public async Task TestKeyAsync_ReturnsError_WhenKeyIsEmpty()
    {
        var emptyConfig = new ApiKeysConfig();
        var emptyService = new ApiConfigurationService(emptyConfig, _httpClient, NullLogger<ApiConfigurationService>.Instance);

        var request = new TestApiKeyRequest
        {
            Provider = "VirusTotal",
            Key = ""
        };

        var result = await emptyService.TestKeyAsync(request);

        Assert.False(result.Success);
        Assert.Contains("No API key was entered", result.StatusMessage);
    }

    [Fact]
    public async Task TestKeyAsync_ReturnsError_WhenProviderIsUnsupported()
    {
        var request = new TestApiKeyRequest
        {
            Provider = "UnknownProvider",
            Key = "some_key"
        };

        var result = await _service.TestKeyAsync(request);

        Assert.False(result.Success);
        Assert.Contains("Unsupported provider", result.StatusMessage);
    }
}
