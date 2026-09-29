namespace LinkSafetyChecker.Models;

public class TestApiKeyResponse
{
    public bool Success { get; set; }
    public required string Provider { get; set; }
    public required string StatusMessage { get; set; }
    public string? Details { get; set; }
}
