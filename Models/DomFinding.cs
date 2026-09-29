namespace LinkSafetyChecker.Models;

public class DomFinding
{
    public required string FindingType { get; set; }
    public RiskSeverity Severity { get; set; }
    public required string Title { get; set; }
    public required string Description { get; set; }
    public string? ElementSnippet { get; set; }
    public string? TargetUrl { get; set; }
}
