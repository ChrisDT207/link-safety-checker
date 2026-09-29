using System.Text.RegularExpressions;
using AngleSharp;
using AngleSharp.Dom;
using AngleSharp.Html.Dom;
using LinkSafetyChecker.Interfaces;
using LinkSafetyChecker.Models;
using Microsoft.Extensions.Logging;

namespace LinkSafetyChecker.Services;

public partial class DomInspectionChecker : IDomInspectionChecker
{
    private readonly ILogger<DomInspectionChecker> _logger;

    // Whitelisted legitimate iframe providers (anti-bot captchas, payments, mainstream media, and verified tag managers)
    private static readonly HashSet<string> WhitelistedIframeDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "google.com",
        "recaptcha.net",
        "gstatic.com",
        "hcaptcha.com",
        "cloudflare.com",
        "challenges.cloudflare.com",
        "youtube.com",
        "youtube-nocookie.com",
        "player.vimeo.com",
        "vimeo.com",
        "js.stripe.com",
        "stripe.network",
        "paypal.com",
        "paypalobjects.com",
        "googletagmanager.com",
        "google-analytics.com",
        "analytics.google.com",
        "connect.facebook.net",
        "facebook.com",
        "doubleclick.net",
        "googleadservices.com",
        "googlesyndication.com"
    };

    [GeneratedRegex(@"^(?:https?:\/\/)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})(?::\d+)?(?:\/.*)?$", RegexOptions.IgnoreCase)]
    private static partial Regex DomainLikeTextRegex();

    [GeneratedRegex(@"url=['""]?([^'"";]+)", RegexOptions.IgnoreCase)]
    private static partial Regex MetaRefreshUrlRegex();

    public DomInspectionChecker(ILogger<DomInspectionChecker> logger)
    {
        _logger = logger;
    }

    public async Task<DomInspectionResult> InspectAsync(string htmlContent, Uri baseUrl, CancellationToken cancellationToken = default)
    {
        var result = new DomInspectionResult();

        if (string.IsNullOrWhiteSpace(htmlContent))
        {
            return result;
        }

        try
        {
            // Parse static DOM without executing scripts
            var config = AngleSharp.Configuration.Default;
            var context = BrowsingContext.New(config);
            var document = await context.OpenAsync(req => req.Content(htmlContent), cancellationToken);

            result.IsAnalyzed = true;

            InspectAnchors(document, baseUrl, result);
            InspectForms(document, baseUrl, result);
            InspectIframes(document, baseUrl, result);
            InspectHiddenInputs(document, result);
            InspectMetaRefresh(document, baseUrl, result);
            InspectPanicKeywords(document, result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "DOM inspection encountered an error.");
            result.Findings.Add(new DomFinding
            {
                FindingType = "DOM_PARSER_ERROR",
                Severity = RiskSeverity.Low,
                Title = "DOM Parser Warning",
                Description = $"HTML structure could not be fully evaluated: {ex.Message}"
            });
        }

        return result;
    }

    private static void InspectAnchors(IDocument document, Uri baseUrl, DomInspectionResult result)
    {
        var anchors = document.QuerySelectorAll<IHtmlAnchorElement>("a");
        result.TotalAnchorsScanned = anchors.Count();

        foreach (var anchor in anchors)
        {
            var href = anchor.GetAttribute("href")?.Trim();
            var text = anchor.TextContent?.Trim();

            if (string.IsNullOrEmpty(href) || string.IsNullOrEmpty(text))
            {
                continue;
            }

            // Flag obfuscated script execution in href
            if (href.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase) ||
                href.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
            {
                result.DeceptiveAnchorsFound++;
                result.Findings.Add(new DomFinding
                {
                    FindingType = "OBFUSCATED_ANCHOR_HREF",
                    Severity = RiskSeverity.High,
                    Title = "Suspicious Link Protocol",
                    Description = $"Anchor link uses an executable or encoded protocol: '{href}'",
                    ElementSnippet = anchor.OuterHtml.Length > 200 ? anchor.OuterHtml[..200] : anchor.OuterHtml,
                    TargetUrl = href
                });
                continue;
            }

            // Check for deceptive link text spoofing (e.g. Text says "paypal.com" but href points to "evil.com")
            var match = DomainLikeTextRegex().Match(text);
            if (match.Success)
            {
                var apparentDomain = match.Groups[1].Value.ToLowerInvariant();

                if (Uri.TryCreate(baseUrl, href, out var resolvedHref) &&
                    (resolvedHref.Scheme == Uri.UriSchemeHttp || resolvedHref.Scheme == Uri.UriSchemeHttps))
                {
                    var actualHost = resolvedHref.Host.ToLowerInvariant();

                    if (!IsSameOrSubdomain(apparentDomain, actualHost))
                    {
                        result.DeceptiveAnchorsFound++;
                        result.Findings.Add(new DomFinding
                        {
                            FindingType = "DECEPTIVE_ANCHOR_SPOOFING",
                            Severity = RiskSeverity.Critical,
                            Title = "Deceptive Link Spoofing Detected",
                            Description = $"Anchor text claims to link to '{apparentDomain}', but actual destination is '{actualHost}'.",
                            ElementSnippet = anchor.OuterHtml.Length > 250 ? anchor.OuterHtml[..250] : anchor.OuterHtml,
                            TargetUrl = resolvedHref.ToString()
                        });
                    }
                }
            }
        }
    }

    private static void InspectForms(IDocument document, Uri baseUrl, DomInspectionResult result)
    {
        var forms = document.QuerySelectorAll<IHtmlFormElement>("form");
        result.TotalFormsScanned = forms.Count();

        foreach (var form in forms)
        {
            var hasPassword = form.QuerySelector("input[type='password']") != null;
            var hasCredentialInputs = form.QuerySelectorAll("input").Any(input =>
            {
                var name = (input.GetAttribute("name") ?? "").ToLowerInvariant();
                var id = (input.GetAttribute("id") ?? "").ToLowerInvariant();
                return name.Contains("user") || name.Contains("pass") || name.Contains("login") ||
                       name.Contains("ssn") || name.Contains("card") || id.Contains("user") ||
                       id.Contains("pass") || id.Contains("login");
            });

            var action = form.GetAttribute("action")?.Trim();

            if (string.IsNullOrEmpty(action))
            {
                // Empty action submits to same page - safe standard pattern
                continue;
            }

            if (action.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase) ||
                action.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
            {
                result.RiskyFormsFound++;
                result.Findings.Add(new DomFinding
                {
                    FindingType = "UNSAFE_FORM_ACTION",
                    Severity = RiskSeverity.Critical,
                    Title = "Unsafe Form Action Protocol",
                    Description = $"Form action attribute uses executable/data protocol: '{action}'",
                    ElementSnippet = form.OuterHtml.Length > 200 ? form.OuterHtml[..200] : form.OuterHtml
                });
                continue;
            }

            if (Uri.TryCreate(baseUrl, action, out var resolvedAction))
            {
                var actionHost = resolvedAction.Host.ToLowerInvariant();
                var baseHost = baseUrl.Host.ToLowerInvariant();

                // Credential form submitting to external domain
                if ((hasPassword || hasCredentialInputs) && !IsSameOrSubdomain(baseHost, actionHost))
                {
                    result.RiskyFormsFound++;
                    result.Findings.Add(new DomFinding
                    {
                        FindingType = "CREDENTIAL_STEALING_FORM",
                        Severity = RiskSeverity.Critical,
                        Title = "Phishing Form: External Credential Exfiltration",
                        Description = $"Sensitive login/credential form on '{baseHost}' submits data to unrelated external host '{actionHost}'.",
                        ElementSnippet = form.OuterHtml.Length > 250 ? form.OuterHtml[..250] : form.OuterHtml,
                        TargetUrl = resolvedAction.ToString()
                    });
                }
                // Plain HTTP submission from HTTPS
                else if (baseUrl.Scheme == Uri.UriSchemeHttps && resolvedAction.Scheme == Uri.UriSchemeHttp)
                {
                    result.RiskyFormsFound++;
                    result.Findings.Add(new DomFinding
                    {
                        FindingType = "INSECURE_FORM_SUBMISSION",
                        Severity = RiskSeverity.High,
                        Title = "Insecure Form Action (Cleartext HTTP)",
                        Description = $"Form sends data over unencrypted HTTP: '{resolvedAction}'",
                        TargetUrl = resolvedAction.ToString()
                    });
                }
            }
        }
    }

    private static void InspectIframes(IDocument document, Uri baseUrl, DomInspectionResult result)
    {
        var iframes = document.QuerySelectorAll<IHtmlInlineFrameElement>("iframe");

        foreach (var iframe in iframes)
        {
            var src = iframe.GetAttribute("src")?.Trim() ?? string.Empty;
            var style = iframe.GetAttribute("style")?.ToLowerInvariant() ?? string.Empty;
            var width = iframe.GetAttribute("width")?.Trim() ?? string.Empty;
            var height = iframe.GetAttribute("height")?.Trim() ?? string.Empty;
            var isHiddenAttr = iframe.HasAttribute("hidden");

            // Check if iframe is enclosed in a <noscript> element (standard GTM / Meta Pixel fallback)
            var isInsideNoscript = iframe.ParentElement is { NodeName: "NOSCRIPT" } || iframe.Closest("noscript") != null;

            // Check if iframe matches whitelisted trusted providers (reCAPTCHA, hCaptcha, Turnstile, YouTube, Stripe, PayPal, GTM, Analytics)
            var isWhitelisted = false;
            if (Uri.TryCreate(src, UriKind.Absolute, out var iframeUri))
            {
                isWhitelisted = WhitelistedIframeDomains.Any(domain =>
                    iframeUri.Host.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
                    iframeUri.Host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase));
            }
            else if (!string.IsNullOrEmpty(src) && Uri.TryCreate(baseUrl, src, out var relativeIframeUri))
            {
                isWhitelisted = WhitelistedIframeDomains.Any(domain =>
                    relativeIframeUri.Host.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
                    relativeIframeUri.Host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase));
            }

            // Do not penalize iframes pointing to verified platforms or standard tracking tags inside <noscript>
            if (isWhitelisted)
            {
                continue;
            }

            if (isInsideNoscript && (src.Contains("gtm", StringComparison.OrdinalIgnoreCase) ||
                                     src.Contains("tagmanager", StringComparison.OrdinalIgnoreCase) ||
                                     src.Contains("analytics", StringComparison.OrdinalIgnoreCase) ||
                                     src.Contains("facebook", StringComparison.OrdinalIgnoreCase) ||
                                     IsTrustedInstitutionalDomain(baseUrl.Host)))
            {
                // Standard noscript fallback tracking on institutional or standard site
                continue;
            }

            var isHidden = isHiddenAttr ||
                           style.Contains("display:none") || style.Contains("display: none") ||
                           style.Contains("visibility:hidden") || style.Contains("visibility: hidden") ||
                           style.Contains("opacity:0") || style.Contains("opacity: 0") ||
                           width is "0" or "0px" or "1" or "1px" ||
                           height is "0" or "0px" or "1" or "1px";

            if (isHidden)
            {
                result.HiddenIframesFound++;
                result.Findings.Add(new DomFinding
                {
                    FindingType = "SUSPICIOUS_HIDDEN_IFRAME",
                    Severity = RiskSeverity.High,
                    Title = "Suspicious Hidden IFrame Detected",
                    Description = $"Non-whitelisted iframe hidden via CSS or 0-dimension sizing. Often used in drive-by downloads, clickjacking, or silent token theft. Source: '{src}'",
                    ElementSnippet = iframe.OuterHtml.Length > 250 ? iframe.OuterHtml[..250] : iframe.OuterHtml,
                    TargetUrl = src
                });
            }
        }
    }

    private static void InspectHiddenInputs(IDocument document, DomInspectionResult result)
    {
        var hiddenInputs = document.QuerySelectorAll("input[type='hidden']");
        result.HiddenInputsFound = hiddenInputs.Count();

        foreach (var input in hiddenInputs)
        {
            var value = input.GetAttribute("value") ?? string.Empty;
            var name = input.GetAttribute("name") ?? string.Empty;

            // Flag suspicious URL redirects in hidden fields
            if (value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                if (name.Contains("redirect", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("return", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("target", StringComparison.OrdinalIgnoreCase))
                {
                    result.Findings.Add(new DomFinding
                    {
                        FindingType = "HIDDEN_REDIRECT_TARGET",
                        Severity = RiskSeverity.Medium,
                        Title = "Hidden Form Redirect Target",
                        Description = $"Form contains hidden field '{name}' with external redirect target: '{value}'",
                        TargetUrl = value
                    });
                }
            }
        }
    }

    private static void InspectMetaRefresh(IDocument document, Uri baseUrl, DomInspectionResult result)
    {
        var metaRefresh = document.QuerySelector("meta[http-equiv='refresh' i]");
        if (metaRefresh != null)
        {
            var content = metaRefresh.GetAttribute("content") ?? string.Empty;
            var match = MetaRefreshUrlRegex().Match(content);
            if (match.Success)
            {
                var targetUrl = match.Groups[1].Value;
                if (Uri.TryCreate(baseUrl, targetUrl, out var resolvedTarget) &&
                    !IsSameOrSubdomain(baseUrl.Host, resolvedTarget.Host))
                {
                    result.Findings.Add(new DomFinding
                    {
                        FindingType = "META_REFRESH_EXTERNAL_REDIRECT",
                        Severity = RiskSeverity.High,
                        Title = "Meta Refresh to External Domain",
                        Description = $"Page automatically redirects through <meta http-equiv='refresh'> to external host '{resolvedTarget.Host}'.",
                        TargetUrl = resolvedTarget.ToString()
                    });
                }
            }
        }
    }

    private static void InspectPanicKeywords(IDocument document, DomInspectionResult result)
    {
        var title = document.Title?.ToLowerInvariant() ?? string.Empty;
        var h1Texts = string.Join(" ", document.QuerySelectorAll("h1").Select(h => h.TextContent)).ToLowerInvariant();
        var combinedText = $"{title} {h1Texts}";

        string[] panicTriggers =
        [
            "account suspended", "security alert", "critical breach", "action required immediately",
            "verify your wallet", "unauthorized login attempt", "infected with virus"
        ];

        foreach (var trigger in panicTriggers)
        {
            if (combinedText.Contains(trigger))
            {
                result.Findings.Add(new DomFinding
                {
                    FindingType = "SOCIAL_ENGINEERING_PANIC_LANGUAGE",
                    Severity = RiskSeverity.Medium,
                    Title = "Social Engineering Panic Keyword Detected",
                    Description = $"Page header/title contains urgent social engineering panic text: '{trigger}'"
                });
                break;
            }
        }
    }

    private static bool IsSameOrSubdomain(string baseHost, string otherHost)
    {
        if (string.Equals(baseHost, otherHost, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (otherHost.EndsWith("." + baseHost, StringComparison.OrdinalIgnoreCase) ||
            baseHost.EndsWith("." + otherHost, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    public static bool IsTrustedInstitutionalDomain(string host)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;
        var h = host.ToLowerInvariant();
        return h.EndsWith(".edu") || h.Contains(".edu.") ||
               h.EndsWith(".ac.za") || h.Contains(".ac.") ||
               h.EndsWith(".gov") || h.Contains(".gov.") ||
               h.EndsWith(".mil");
    }
}
