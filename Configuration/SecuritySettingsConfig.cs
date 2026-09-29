namespace LinkSafetyChecker.Configuration;

public class SecuritySettingsConfig
{
    public int MaxRedirectHops { get; set; } = 5;
    public int HttpRequestTimeoutSeconds { get; set; } = 8;
    public long MaxResponseSizeBytes { get; set; } = 5 * 1024 * 1024; // 5 MB
    public bool AllowPrivateNetwork { get; set; } = false;
}
