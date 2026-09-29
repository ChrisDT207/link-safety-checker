using LinkSafetyChecker.Services;
using Xunit;

namespace LinkSafetyChecker.Tests;

public class UrlHeuristicCheckerTests
{
    private readonly UrlHeuristicChecker _checker = new();

    [Fact]
    public void Analyze_DetectsPunycodeHomoglyph()
    {
        var uri = new Uri("https://xn--pple-43d.com/signin");
        var result = _checker.Analyze(uri);

        Assert.True(result.IsPunycodeOrHomoglyph);
        Assert.NotEmpty(result.Warnings);
    }

    [Fact]
    public void Analyze_DetectsRawIpHost()
    {
        var uri = new Uri("http://185.220.101.5/payload.exe");
        var result = _checker.Analyze(uri);

        Assert.True(result.IsRawIpHost);
        Assert.NotEmpty(result.Warnings);
    }

    [Fact]
    public void Analyze_DetectsHighRiskTld()
    {
        var uri = new Uri("https://free-crypto-giveaway.top");
        var result = _checker.Analyze(uri);

        Assert.True(result.HasSuspiciousTld);
    }

    [Fact]
    public void Analyze_DetectsBrandSpoofingInSubdomain()
    {
        var uri = new Uri("https://paypal.com.verify-account.attackerdomain.com/login");
        var result = _checker.Analyze(uri);

        Assert.True(result.HasBrandKeywordsInSubdomain);
    }

    [Fact]
    public void Analyze_CleanForLegitimateDomain()
    {
        var uri = new Uri("https://www.paypal.com/signin");
        var result = _checker.Analyze(uri);

        Assert.False(result.IsPunycodeOrHomoglyph);
        Assert.False(result.IsRawIpHost);
        Assert.False(result.HasSuspiciousTld);
        Assert.False(result.HasBrandKeywordsInSubdomain);
    }
}
