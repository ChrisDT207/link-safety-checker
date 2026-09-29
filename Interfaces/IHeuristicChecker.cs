using LinkSafetyChecker.Models;

namespace LinkSafetyChecker.Interfaces;

public interface IHeuristicChecker
{
    HeuristicResult Analyze(Uri uri);
}
