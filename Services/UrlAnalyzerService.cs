using System.Diagnostics;
using LinkSafetyChecker.Interfaces;
using LinkSafetyChecker.Models;
using Microsoft.Extensions.Logging;

namespace LinkSafetyChecker.Services;

public class UrlAnalyzerService : IUrlAnalyzerService
{
    private readonly ISafeHttpClientService _safeHttpClient;
    private readonly IDomInspectionChecker _domChecker;
    private readonly IHeuristicChecker _heuristicChecker;
    private readonly IEnumerable<IReputationApiChecker> _reputationCheckers;
    private readonly IScoringEngine _scoringEngine;
    private readonly ILogger<UrlAnalyzerService> _logger;

    public UrlAnalyzerService(
        ISafeHttpClientService safeHttpClient,
        IDomInspectionChecker domChecker,
        IHeuristicChecker heuristicChecker,
        IEnumerable<IReputationApiChecker> reputationCheckers,
        IScoringEngine scoringEngine,
        ILogger<UrlAnalyzerService> logger)
    {
        _safeHttpClient = safeHttpClient;
        _domChecker = domChecker;
        _heuristicChecker = heuristicChecker;
        _reputationCheckers = reputationCheckers;
        _scoringEngine = scoringEngine;
        _logger = logger;
    }

    public async Task<AnalysisResult> AnalyzeUrlAsync(string rawUrl, CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();

        var result = new AnalysisResult
        {
            OriginalUrl = rawUrl?.Trim() ?? string.Empty
        };

        if (string.IsNullOrWhiteSpace(result.OriginalUrl))
        {
            result.ErrorMessage = "Please enter a valid URL.";
            result.SafetyScore = new SafetyScore
            {
                Score = 0,
                Rating = "Invalid",
                Summary = "No URL was provided for analysis."
            };
            return result;
        }

        // Require valid http:// or https:// protocol
        if (!result.OriginalUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !result.OriginalUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            result.ErrorMessage = "Invalid URL format: URL must begin with http:// or https:// (e.g., https://example.com).";
            result.SafetyScore = new SafetyScore
            {
                Score = 0,
                Rating = "Invalid",
                Summary = "Invalid URL: Missing http:// or https:// protocol."
            };
            return result;
        }

        if (!Uri.TryCreate(result.OriginalUrl, UriKind.Absolute, out var initialUri) ||
            (initialUri.Scheme != Uri.UriSchemeHttp && initialUri.Scheme != Uri.UriSchemeHttps) ||
            string.IsNullOrWhiteSpace(initialUri.Host) ||
            (!initialUri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) && !initialUri.Host.Contains('.')))
        {
            result.ErrorMessage = "Invalid URL format. Please provide a valid web URL with a hostname and domain.";
            result.SafetyScore = new SafetyScore
            {
                Score = 0,
                Rating = "Invalid",
                Summary = "Invalid URL structure or unsupported protocol."
            };
            return result;
        }

        // Safeguard: detect common source code filenames submitted mistakenly as hosts
        var hostLower = initialUri.Host.ToLowerInvariant();
        if (hostLower.EndsWith(".cs") || hostLower.EndsWith(".cpp") || hostLower.EndsWith(".java") ||
            hostLower.EndsWith(".py") || hostLower.EndsWith(".ts") || hostLower.EndsWith(".js"))
        {
            result.ErrorMessage = "Invalid URL: Source code file name detected instead of a valid web domain.";
            result.SafetyScore = new SafetyScore
            {
                Score = 0,
                Rating = "Invalid",
                Summary = "Invalid domain: Input appears to be a source code filename."
            };
            return result;
        }

        try
        {
            _logger.LogInformation("Starting analysis for URL: {Url}", initialUri);

            // Step 1: Lexical & URL syntax heuristics
            result.Heuristics = _heuristicChecker.Analyze(initialUri);

            // Step 2: Safe HTTP content retrieval (zero execution risk, SSRF protected)
            var fetchResult = await _safeHttpClient.FetchSafelyAsync(initialUri.ToString(), cancellationToken);
            result.FinalUrl = fetchResult.FinalUrl;
            result.StatusCode = fetchResult.StatusCode;
            result.ContentType = fetchResult.ContentType;
            result.ContentSizeBytes = fetchResult.ContentLength;
            result.RedirectChain = fetchResult.RedirectChain;

            var finalUri = Uri.TryCreate(result.FinalUrl, UriKind.Absolute, out var parsedFinal)
                ? parsedFinal
                : initialUri;

            // Step 3: Automated DOM Inspection if HTML is available
            if (fetchResult.Success && !string.IsNullOrEmpty(fetchResult.HtmlContent))
            {
                result.DomInspection = await _domChecker.InspectAsync(fetchResult.HtmlContent, finalUri, cancellationToken);
            }
            else if (!fetchResult.Success)
            {
                result.ErrorMessage = fetchResult.ErrorMessage;
            }

            // Step 4: External Reputation Checkers (in parallel)
            var reputationTasks = _reputationCheckers.Select(c => c.CheckAsync(finalUri, cancellationToken)).ToList();
            var reputationArray = await Task.WhenAll(reputationTasks);
            result.ReputationResults = [.. reputationArray];

            // Step 5: Central Scoring Engine
            result.SafetyScore = _scoringEngine.CalculateScore(
                finalUri,
                fetchResult,
                result.DomInspection,
                result.Heuristics,
                result.ReputationResults);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error analyzing URL: {Url}", rawUrl);
            result.ErrorMessage = $"Analysis failed: {ex.Message}";
            result.SafetyScore = new SafetyScore
            {
                Score = 0,
                Rating = "Error",
                Summary = $"An error occurred during analysis: {ex.Message}"
            };
        }
        finally
        {
            stopwatch.Stop();
            result.ElapsedMilliseconds = stopwatch.ElapsedMilliseconds;
        }

        return result;
    }
}
