namespace LinkSafetyChecker.Models;

public class DomInspectionResult
{
    public bool IsAnalyzed { get; set; }
    public int TotalAnchorsScanned { get; set; }
    public int DeceptiveAnchorsFound { get; set; }
    public int TotalFormsScanned { get; set; }
    public int RiskyFormsFound { get; set; }
    public int HiddenIframesFound { get; set; }
    public int HiddenInputsFound { get; set; }
    public List<DomFinding> Findings { get; set; } = [];
}
