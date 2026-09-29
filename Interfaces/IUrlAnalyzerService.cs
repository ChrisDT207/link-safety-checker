using LinkSafetyChecker.Models;

namespace LinkSafetyChecker.Interfaces;

public interface IUrlAnalyzerService
{
    Task<AnalysisResult> AnalyzeUrlAsync(string rawUrl, CancellationToken cancellationToken = default);
}
