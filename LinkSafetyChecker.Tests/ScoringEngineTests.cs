using LinkSafetyChecker.Models;
using LinkSafetyChecker.Services;
using Xunit;

namespace LinkSafetyChecker.Tests;

public class ScoringEngineTests
{
    private readonly ScoringEngine _engine = new();

    [Fact]
    public void CalculateScore_Returns100Safe_WhenNoThreats()
    {
        var uri = new Uri("https://legitimate.org");
        var fetchResult = new HttpFetchResult { Success = true, StatusCode = 200 };
        var domResult = new DomInspectionResult { IsAnalyzed = true };
        var heuristicResult = new HeuristicResult();
        var reputationResults = new List<ReputationResult>();

        var score = _engine.CalculateScore(uri, fetchResult, domResult, heuristicResult, reputationResults);

        Assert.Equal(100, score.Score);
        Assert.Equal("Safe", score.Rating);
        Assert.Empty(score.Deductions);
    }

    [Fact]
    public void CalculateScore_PenalizesDeceptiveLinksAndPhishingForms()
    {
        var uri = new Uri("https://phishing.xyz/login");
        var fetchResult = new HttpFetchResult { Success = true, StatusCode = 200 };
        var domResult = new DomInspectionResult
        {
            IsAnalyzed = true,
            DeceptiveAnchorsFound = 1,
            RiskyFormsFound = 1,
            Findings =
            [
                new DomFinding
                {
                    FindingType = "CREDENTIAL_STEALING_FORM",
                    Severity = RiskSeverity.Critical,
                    Title = "Credential Stealing Form",
                    Description = "Submits to external domain"
                },
                new DomFinding
                {
                    FindingType = "DECEPTIVE_ANCHOR_SPOOFING",
                    Severity = RiskSeverity.Critical,
                    Title = "Deceptive Link",
                    Description = "Spoofs brand domain"
                }
            ]
        };
        var heuristicResult = new HeuristicResult { HasSuspiciousTld = true };
        var reputationResults = new List<ReputationResult>();

        var score = _engine.CalculateScore(uri, fetchResult, domResult, heuristicResult, reputationResults);

        // 100 - 55 (Form) - 40 (Anchor) - 15 (TLD) = 0 (clamped)
        Assert.True(score.Score <= 20);
        Assert.Equal("Dangerous", score.Rating);
        Assert.NotEmpty(score.Deductions);
    }

    [Fact]
    public void CalculateScore_NeverDropsBelowZero()
    {
        var uri = new Uri("http://192.168.1.1");
        var fetchResult = new HttpFetchResult { Success = false, ErrorMessage = "Security Exception: SSRF" };
        var domResult = new DomInspectionResult { IsAnalyzed = false };
        var heuristicResult = new HeuristicResult { IsRawIpHost = true, IsPunycodeOrHomoglyph = true };
        var reputationResults = new List<ReputationResult>
        {
            new() { ProviderName = "Google Safe Browsing", IsChecked = true, IsMalicious = true }
        };

        var score = _engine.CalculateScore(uri, fetchResult, domResult, heuristicResult, reputationResults);

        Assert.Equal(0, score.Score);
        Assert.Equal("Dangerous", score.Rating);
    }

    [Fact]
    public void CalculateScore_ContextAwareProtectsEducationalDomainWithMinorFindings()
    {
        var uri = new Uri("https://uct.ac.za/research/portal");
        var fetchResult = new HttpFetchResult
        {
            Success = true,
            StatusCode = 200,
            RedirectChain = ["https://uct.ac.za", "https://www.uct.ac.za", "https://uct.ac.za/research", "https://uct.ac.za/research/portal"]
        };
        var domResult = new DomInspectionResult
        {
            IsAnalyzed = true,
            Findings =
            [
                new DomFinding
                {
                    FindingType = "EXTERNAL_FORM_ACTION",
                    Severity = RiskSeverity.Medium,
                    Title = "External Search Form",
                    Description = "Submits to third-party library catalog"
                }
            ]
        };
        var heuristicResult = new HeuristicResult();
        var reputationResults = new List<ReputationResult>();

        var score = _engine.CalculateScore(uri, fetchResult, domResult, heuristicResult, reputationResults);

        // Even with minor deductions (redirects + external form), institutional protection ensures Safe rating
        Assert.True(score.Score >= 85);
        Assert.Equal("Safe", score.Rating);
        Assert.Contains("Trusted educational/governmental domain", score.Summary);
    }

    [Fact]
    public void CalculateScore_ContextAwareStillPenalizesEducationalDomainOnCriticalThreats()
    {
        var uri = new Uri("https://compromised.edu/login");
        var fetchResult = new HttpFetchResult { Success = true, StatusCode = 200 };
        var domResult = new DomInspectionResult
        {
            IsAnalyzed = true,
            Findings =
            [
                new DomFinding
                {
                    FindingType = "CREDENTIAL_STEALING_FORM",
                    Severity = RiskSeverity.Critical,
                    Title = "Credential Stealing Form",
                    Description = "Submits to attacker host"
                }
            ]
        };
        var heuristicResult = new HeuristicResult();
        var reputationResults = new List<ReputationResult>();

        var score = _engine.CalculateScore(uri, fetchResult, domResult, heuristicResult, reputationResults);

        // Critical threats must NOT be excused
        Assert.True(score.Score < 50);
        Assert.Equal("Dangerous", score.Rating);
    }
}

