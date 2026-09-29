using System.Net;
using System.Text.RegularExpressions;
using LinkSafetyChecker.Interfaces;
using LinkSafetyChecker.Models;

namespace LinkSafetyChecker.Services;

public partial class UrlHeuristicChecker : IHeuristicChecker
{
    private static readonly HashSet<string> HighRiskTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        ".top", ".xyz", ".work", ".click", ".gq", ".cf", ".tk", ".ml", ".fit", ".rest", ".monster"
    };

    private static readonly string[] TargetedBrands =
    [
        "paypal", "apple", "microsoft", "google", "netflix", "amazon", "chase", "wellsfargo",
        "bankofamerica", "coinbase", "binance", "metamask", "facebook", "instagram"
    ];

    [GeneratedRegex(@"^(\d{1,3}\.){3}\d{1,3}$")]
    private static partial Regex Ipv4Regex();

    public HeuristicResult Analyze(Uri uri)
    {
        var result = new HeuristicResult();
        var host = uri.Host.ToLowerInvariant();

        // 1. Check for Punycode / IDN Homoglyph attack
        if (host.StartsWith("xn--") || host.Contains(".xn--"))
        {
            result.IsPunycodeOrHomoglyph = true;
            result.Warnings.Add($"Punycode/Internationalized Domain Name detected ({host}). Often used to visually spoof legitimate brand characters.");
        }

        // 2. Check for Raw IP Address Host
        if (IPAddress.TryParse(host, out _) || Ipv4Regex().IsMatch(host))
        {
            result.IsRawIpHost = true;
            result.Warnings.Add($"Host is a raw numerical IP address ({host}) rather than a registered domain name.");
        }

        // 3. Check for Suspicious / High-Abuse TLDs
        foreach (var tld in HighRiskTlds)
        {
            if (host.EndsWith(tld, StringComparison.OrdinalIgnoreCase))
            {
                result.HasSuspiciousTld = true;
                result.Warnings.Add($"Domain uses high-abuse / high-risk TLD '{tld}'.");
                break;
            }
        }

        // 4. Excessive Subdomains (Domain stacking)
        var parts = host.Split('.');
        if (parts.Length >= 5)
        {
            result.HasExcessiveSubdomains = true;
            result.Warnings.Add($"Excessive subdomain nesting ({parts.Length} levels). Common tactic to obscure true destination domain.");
        }

        // 5. Brand Keyword in Subdomain or Path on Unrelated Domain
        var secondLevelDomain = GetRegistrableDomain(host);
        foreach (var brand in TargetedBrands)
        {
            // If the host or path contains the brand, but the main domain is not the brand's official domain
            var containsBrandInSubdomain = host.Contains(brand) && !secondLevelDomain.Contains(brand);
            var containsBrandInPath = uri.AbsolutePath.Contains(brand, StringComparison.OrdinalIgnoreCase) && !secondLevelDomain.Contains(brand);

            if (containsBrandInSubdomain || containsBrandInPath)
            {
                result.HasBrandKeywordsInSubdomain = true;
                result.Warnings.Add($"High-value brand keyword '{brand}' found in {(containsBrandInSubdomain ? "subdomain" : "URL path")} on unrelated root domain '{secondLevelDomain}'.");
                break;
            }
        }

        return result;
    }

    private static string GetRegistrableDomain(string host)
    {
        var parts = host.Split('.');
        if (parts.Length <= 2)
        {
            return host;
        }

        // Return last two segments (e.g. example.com or attacker.net)
        return $"{parts[^2]}.{parts[^1]}";
    }
}
