using LinkSafetyChecker.Models;

namespace LinkSafetyChecker.Interfaces;

public interface IReputationApiChecker
{
    string ProviderName { get; }
    bool IsConfigured { get; }
    Task<ReputationResult> CheckAsync(Uri uri, CancellationToken cancellationToken = default);
}
