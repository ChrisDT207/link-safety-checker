namespace LinkSafetyChecker.Models;

public class AnalysisResult
{
    public required string OriginalUrl { get; set; }
    public string FinalUrl { get; set; } = string.Empty;
    public int StatusCode { get; set; }
    public string? ContentType { get; set; }
    public long ContentSizeBytes { get; set; }
    public long ElapsedMilliseconds { get; set; }
    public List<string> RedirectChain { get; set; } = [];
    public SafetyScore SafetyScore { get; set; } = new();
    public DomInspectionResult DomInspection { get; set; } = new();
    public HeuristicResult Heuristics { get; set; } = new();
    public List<ReputationResult> ReputationResults { get; set; } = [];
    public string? ErrorMessage { get; set; }
}
