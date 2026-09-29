using LinkSafetyChecker.Models;

namespace LinkSafetyChecker.Interfaces;

public interface IDomInspectionChecker
{
    Task<DomInspectionResult> InspectAsync(string htmlContent, Uri baseUrl, CancellationToken cancellationToken = default);
}
