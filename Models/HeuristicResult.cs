namespace LinkSafetyChecker.Models;

public class HeuristicResult
{
    public bool IsPunycodeOrHomoglyph { get; set; }
    public bool IsRawIpHost { get; set; }
    public bool HasSuspiciousTld { get; set; }
    public bool HasExcessiveSubdomains { get; set; }
    public bool HasBrandKeywordsInSubdomain { get; set; }
    public List<string> Warnings { get; set; } = [];
}
