namespace LinkSafetyChecker.Models;

public class ApiConfigDto
{
    public string VirusTotalKeyMasked { get; set; } = string.Empty;
    public bool VirusTotalHasKey { get; set; }
    public bool VirusTotalEnabled { get; set; }

    public string GoogleSafeBrowsingKeyMasked { get; set; } = string.Empty;
    public bool GoogleSafeBrowsingHasKey { get; set; }
    public bool GoogleSafeBrowsingEnabled { get; set; }

    public string WhoisXmlKeyMasked { get; set; } = string.Empty;
    public bool WhoisXmlHasKey { get; set; }
}
