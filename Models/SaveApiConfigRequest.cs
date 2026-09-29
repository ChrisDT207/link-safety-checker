namespace LinkSafetyChecker.Models;

public class SaveApiConfigRequest
{
    public string? VirusTotalKey { get; set; }
    public bool VirusTotalEnabled { get; set; } = true;

    public string? GoogleSafeBrowsingKey { get; set; }
    public bool GoogleSafeBrowsingEnabled { get; set; } = true;

    public string? WhoisXmlKey { get; set; }
}
