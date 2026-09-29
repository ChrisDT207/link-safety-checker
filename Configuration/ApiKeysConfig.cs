namespace LinkSafetyChecker.Configuration;

public class ApiKeysConfig
{
    public string GoogleSafeBrowsing { get; set; } = string.Empty;
    public bool GoogleSafeBrowsingEnabled { get; set; } = true;
    public string VirusTotal { get; set; } = string.Empty;
    public bool VirusTotalEnabled { get; set; } = true;
    public string WhoisXml { get; set; } = string.Empty;
}
