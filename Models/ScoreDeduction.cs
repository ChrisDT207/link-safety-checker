namespace LinkSafetyChecker.Models;

public class ScoreDeduction
{
    public required string Reason { get; set; }
    public int PointsDeducted { get; set; }
    public RiskSeverity Severity { get; set; }
}
