using LinkSafetyChecker.Interfaces;
using LinkSafetyChecker.Models;
using LinkSafetyChecker.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace LinkSafetyChecker.Tests;

public class UrlAnalyzerServiceTests
{
    private readonly UrlAnalyzerService _service;

    public UrlAnalyzerServiceTests()
    {
        // Mock dependencies with dummy / null implementations since validation terminates before network calls
        var safeHttpClient = new DummySafeHttpClientService();
        var domChecker = new DummyDomChecker();
        var heuristicChecker = new DummyHeuristicChecker();
        var scoringEngine = new ScoringEngine();

        _service = new UrlAnalyzerService(
            safeHttpClient,
            domChecker,
            heuristicChecker,
            [],
            scoringEngine,
            NullLogger<UrlAnalyzerService>.Instance);
    }

    [Theory]
    [InlineData("otalChecker.cs")]
    [InlineData("Program.cs")]
    [InlineData("main.cpp")]
    [InlineData("script.py")]
    [InlineData("index.js")]
    public async Task AnalyzeUrlAsync_RejectsFilenamesWithoutProtocol(string filename)
    {
        var result = await _service.AnalyzeUrlAsync(filename);

        Assert.NotNull(result.SafetyScore);
        Assert.Equal("Invalid", result.SafetyScore.Rating);
        Assert.Contains("http:// or https://", result.ErrorMessage);
    }

    [Theory]
    [InlineData("https://otalChecker.cs")]
    [InlineData("http://MyCode.cpp")]
    [InlineData("https://backend.py")]
    public async Task AnalyzeUrlAsync_RejectsFilenamesEvenWithProtocol(string fakeUrl)
    {
        var result = await _service.AnalyzeUrlAsync(fakeUrl);

        Assert.NotNull(result.SafetyScore);
        Assert.Equal("Invalid", result.SafetyScore.Rating);
        Assert.Contains("Source code file name detected", result.ErrorMessage);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-url")]
    public async Task AnalyzeUrlAsync_RejectsMalformedInputs(string input)
    {
        var result = await _service.AnalyzeUrlAsync(input);

        Assert.NotNull(result.SafetyScore);
        Assert.Equal("Invalid", result.SafetyScore.Rating);
    }

    private class DummySafeHttpClientService : ISafeHttpClientService
    {
        public Task<HttpFetchResult> FetchSafelyAsync(string url, CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("Network calls should not occur for invalid inputs.");
        }
    }

    private class DummyDomChecker : IDomInspectionChecker
    {
        public Task<DomInspectionResult> InspectAsync(string htmlContent, Uri baseUrl, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new DomInspectionResult());
        }
    }

    private class DummyHeuristicChecker : IHeuristicChecker
    {
        public HeuristicResult Analyze(Uri uri)
        {
            return new HeuristicResult();
        }
    }
}
