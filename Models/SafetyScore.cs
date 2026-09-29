namespace LinkSafetyChecker.Models;

public class SafetyScore
{
    public int Score { get; set; } = 100; // 0 to 100
    public string Rating { get; set; } = "Safe"; // Safe, Suspicious, Dangerous
    public string Summary { get; set; } = string.Empty;
    public List<ScoreDeduction> Deductions { get; set; } = [];
}
