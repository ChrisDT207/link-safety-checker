namespace LinkSafetyChecker.Models;

public class ReputationResult
{
    public required string ProviderName { get; set; }
    public bool IsChecked { get; set; }
    public bool IsMalicious { get; set; }
    public string StatusMessage { get; set; } = string.Empty;
    public string? ThreatType { get; set; }
    public Dictionary<string, string> Details { get; set; } = [];
}
