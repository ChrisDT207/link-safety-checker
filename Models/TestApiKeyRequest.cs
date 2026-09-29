namespace LinkSafetyChecker.Models;

public class TestApiKeyRequest
{
    public required string Provider { get; set; }
    public string? Key { get; set; }
}
