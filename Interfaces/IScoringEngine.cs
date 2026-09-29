using LinkSafetyChecker.Models;

namespace LinkSafetyChecker.Interfaces;

public interface IScoringEngine
{
    SafetyScore CalculateScore(
        Uri uri,
        HttpFetchResult fetchResult,
        DomInspectionResult domResult,
        HeuristicResult heuristicResult,
        IEnumerable<ReputationResult> reputationResults);
}
