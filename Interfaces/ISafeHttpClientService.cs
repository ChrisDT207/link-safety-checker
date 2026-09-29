using LinkSafetyChecker.Models;

namespace LinkSafetyChecker.Interfaces;

public interface ISafeHttpClientService
{
    Task<HttpFetchResult> FetchSafelyAsync(string url, CancellationToken cancellationToken = default);
}
