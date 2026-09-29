namespace LinkSafetyChecker.Configuration;

public class AppConfig
{
    public ApiKeysConfig ApiKeys { get; set; } = new();
    public SecuritySettingsConfig SecuritySettings { get; set; } = new();
}
