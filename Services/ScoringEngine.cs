using LinkSafetyChecker.Interfaces;
using LinkSafetyChecker.Models;

namespace LinkSafetyChecker.Services;

public class ScoringEngine : IScoringEngine
{
    public SafetyScore CalculateScore(
        Uri uri,
        HttpFetchResult fetchResult,
        DomInspectionResult domResult,
        HeuristicResult heuristicResult,
        IEnumerable<ReputationResult> reputationResults)
    {
        var safetyScore = new SafetyScore();
        int currentScore = 100;
        var deductions = new List<ScoreDeduction>();

        // 1. External Reputation API Checks
        foreach (var rep in reputationResults.Where(r => r.IsChecked))
        {
            if (rep.IsMalicious)
            {
                var penalty = rep.ProviderName.Contains("Google", StringComparison.OrdinalIgnoreCase) ? 75 : 65;
                deductions.Add(new ScoreDeduction
                {
                    Reason = $"Reputation Alert: {rep.StatusMessage}",
                    PointsDeducted = penalty,
                    Severity = RiskSeverity.Critical
                });
                currentScore -= penalty;
            }
            else if (rep.ThreatType == "NEWLY_REGISTERED_DOMAIN")
            {
                deductions.Add(new ScoreDeduction
                {
                    Reason = rep.StatusMessage,
                    PointsDeducted = 15,
                    Severity = RiskSeverity.Medium
                });
                currentScore -= 15;
            }
        }

        // 2. DOM Inspection Findings
        if (domResult.IsAnalyzed)
        {
            foreach (var finding in domResult.Findings)
            {
                int penalty = finding.FindingType switch
                {
                    "CREDENTIAL_STEALING_FORM" => 55,
                    "DECEPTIVE_ANCHOR_SPOOFING" => 40,
                    "UNSAFE_FORM_ACTION" => 35,
                    "SUSPICIOUS_HIDDEN_IFRAME" => 25,
                    "META_REFRESH_EXTERNAL_REDIRECT" => 20,
                    "INSECURE_FORM_SUBMISSION" => 15,
                    "HIDDEN_REDIRECT_TARGET" => 10,
                    "SOCIAL_ENGINEERING_PANIC_LANGUAGE" => 10,
                    _ => 5
                };

                deductions.Add(new ScoreDeduction
                {
                    Reason = $"DOM: {finding.Title} - {finding.Description}",
                    PointsDeducted = penalty,
                    Severity = finding.Severity
                });

                currentScore -= penalty;
            }
        }

        // 3. URL Lexical & Heuristics
        if (heuristicResult.IsPunycodeOrHomoglyph)
        {
            deductions.Add(new ScoreDeduction
            {
                Reason = "Heuristics: Punycode / Internationalized Domain Name detected (homoglyph risk)",
                PointsDeducted = 35,
                Severity = RiskSeverity.High
            });
            currentScore -= 35;
        }

        if (heuristicResult.IsRawIpHost)
        {
            deductions.Add(new ScoreDeduction
            {
                Reason = "Heuristics: Host is a raw IP address instead of a domain name",
                PointsDeducted = 20,
                Severity = RiskSeverity.Medium
            });
            currentScore -= 20;
        }

        if (heuristicResult.HasBrandKeywordsInSubdomain)
        {
            deductions.Add(new ScoreDeduction
            {
                Reason = "Heuristics: Known brand name detected in subdomain/path on unrelated root domain",
                PointsDeducted = 25,
                Severity = RiskSeverity.High
            });
            currentScore -= 25;
        }

        if (heuristicResult.HasSuspiciousTld)
        {
            deductions.Add(new ScoreDeduction
            {
                Reason = "Heuristics: Domain uses a high-abuse / high-risk top-level domain",
                PointsDeducted = 15,
                Severity = RiskSeverity.Medium
            });
            currentScore -= 15;
        }

        if (heuristicResult.HasExcessiveSubdomains)
        {
            deductions.Add(new ScoreDeduction
            {
                Reason = "Heuristics: Excessive subdomain nesting (domain stacking)",
                PointsDeducted = 10,
                Severity = RiskSeverity.Low
            });
            currentScore -= 10;
        }

        // 4. Protocol & Transport Checks
        if (uri.Scheme == Uri.UriSchemeHttp)
        {
            deductions.Add(new ScoreDeduction
            {
                Reason = "Transport: Unencrypted HTTP protocol (no SSL/TLS encryption)",
                PointsDeducted = 10,
                Severity = RiskSeverity.Low
            });
            currentScore -= 10;
        }

        // 5. Redirect Chain Evaluation
        if (fetchResult.RedirectChain.Count > 3)
        {
            deductions.Add(new ScoreDeduction
            {
                Reason = $"Transport: High redirect count ({fetchResult.RedirectChain.Count} hops in chain)",
                PointsDeducted = 10,
                Severity = RiskSeverity.Low
            });
            currentScore -= 10;
        }

        // 6. Network/Fetch Failure
        if (!fetchResult.Success && !string.IsNullOrEmpty(fetchResult.ErrorMessage))
        {
            var isSecurityBlocked = fetchResult.ErrorMessage.Contains("Security Exception", StringComparison.OrdinalIgnoreCase) ||
                                    fetchResult.ErrorMessage.Contains("SSRF", StringComparison.OrdinalIgnoreCase);

            var penalty = isSecurityBlocked ? 60 : 15;
            deductions.Add(new ScoreDeduction
            {
                Reason = $"Connection: {fetchResult.ErrorMessage}",
                PointsDeducted = penalty,
                Severity = isSecurityBlocked ? RiskSeverity.Critical : RiskSeverity.Medium
            });
            currentScore -= penalty;
        }

        // Context-aware institutional protection:
        // Educational (.edu, .ac.za), governmental (.gov), and institutional domains are given context weighting:
        // Standard third-party marketing tags, minor analytics scripts, or benign non-credential forms
        // will not falsely degrade a trusted institutional domain to "Suspicious" unless critical threats are found.
        var isInstitutional = DomInspectionChecker.IsTrustedInstitutionalDomain(uri.Host);
        if (isInstitutional)
        {
            var hasCriticalThreats = deductions.Any(d => d.Severity == RiskSeverity.Critical);
            if (!hasCriticalThreats && currentScore < 85)
            {
                currentScore = 85;
            }
        }

        // Clamp final score between 0 and 100
        safetyScore.Score = Math.Clamp(currentScore, 0, 100);
        safetyScore.Deductions = deductions;

        if (safetyScore.Score >= 85)
        {
            safetyScore.Rating = "Safe";
            if (isInstitutional && deductions.Count > 0)
            {
                safetyScore.Summary = "Trusted educational/governmental domain. Standard analytics and external marketing links contextualized as legitimate.";
            }
            else
            {
                safetyScore.Summary = deductions.Count == 0
                    ? "Clean: No significant phishing signatures, deceptive links, or reputation threats detected."
                    : "Safe with minor advisories: Target link demonstrates high overall trustworthiness.";
            }
        }
        else if (safetyScore.Score >= 50)
        {
            safetyScore.Rating = "Suspicious";
            safetyScore.Summary = "Caution advised: Detected structural anomalies, hidden elements, or newly registered domain signatures.";
        }
        else
        {
            safetyScore.Rating = "Dangerous";
            safetyScore.Summary = "High Risk: Multiple critical phishing indicators, deceptive links, or malicious reputation matches detected.";
        }

        return safetyScore;
    }
}
