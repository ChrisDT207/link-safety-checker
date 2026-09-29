using System.Net;

namespace LinkSafetyChecker.Interfaces;

public interface ISsrfValidator
{
    bool IsIpAllowed(IPAddress ipAddress);
    Task ValidateHostAsync(string host, CancellationToken cancellationToken = default);
}
