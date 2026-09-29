using System.Net;
using System.Security;
using System.Text;
using LinkSafetyChecker.Configuration;
using LinkSafetyChecker.Interfaces;
using LinkSafetyChecker.Models;
using LinkSafetyChecker.Security;
using Microsoft.Extensions.Logging;

namespace LinkSafetyChecker.Services;

public class SafeHttpClientService : ISafeHttpClientService, IDisposable
{
    private readonly ISsrfValidator _ssrfValidator;
    private readonly SecuritySettingsConfig _settings;
    private readonly ILogger<SafeHttpClientService> _logger;
    private readonly HttpClient _httpClient;
    private bool _disposed;

    public SafeHttpClientService(
        ISsrfValidator ssrfValidator,
        SecuritySettingsConfig settings,
        ILogger<SafeHttpClientService> logger)
    {
        _ssrfValidator = ssrfValidator;
        _settings = settings;
        _logger = logger;

        var handler = SafeSocketsHttpHandlerFactory.Create(_ssrfValidator, _settings, _logger);
        _httpClient = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(_settings.HttpRequestTimeoutSeconds)
        };

        // Realistic standard desktop user-agent for safety checking
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36");
        _httpClient.DefaultRequestHeaders.Accept.ParseAdd("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        _httpClient.DefaultRequestHeaders.AcceptLanguage.ParseAdd("en-US,en;q=0.5");
    }

    public async Task<HttpFetchResult> FetchSafelyAsync(string url, CancellationToken cancellationToken = default)
    {
        var result = new HttpFetchResult
        {
            RequestedUrl = url,
            FinalUrl = url
        };

        if (!Uri.TryCreate(url, UriKind.Absolute, out var currentUri) ||
            (currentUri.Scheme != Uri.UriSchemeHttp && currentUri.Scheme != Uri.UriSchemeHttps))
        {
            result.Success = false;
            result.ErrorMessage = "Invalid or unsupported URL scheme. Only HTTP and HTTPS are permitted.";
            return result;
        }

        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(_settings.HttpRequestTimeoutSeconds));
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

        var hops = 0;
        result.RedirectChain.Add(currentUri.ToString());

        while (hops <= _settings.MaxRedirectHops)
        {
            try
            {
                // Step 1: Pre-flight SSRF validation on the target host
                await _ssrfValidator.ValidateHostAsync(currentUri.Host, linkedCts.Token);

                // Step 2: Make the safe request (zero JS execution, socket checked by ConnectCallback)
                using var request = new HttpRequestMessage(HttpMethod.Get, currentUri);
                using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, linkedCts.Token);

                result.StatusCode = (int)response.StatusCode;
                result.ContentType = response.Content.Headers.ContentType?.MediaType;

                foreach (var header in response.Headers)
                {
                    result.Headers[header.Key] = string.Join(", ", header.Value);
                }

                // Step 3: Handle redirects manually with SSRF checks
                if (IsRedirectStatusCode(response.StatusCode))
                {
                    hops++;
                    if (hops > _settings.MaxRedirectHops)
                    {
                        result.Success = false;
                        result.ErrorMessage = $"Exceeded maximum allowed redirects ({_settings.MaxRedirectHops}). Possible redirect loop.";
                        return result;
                    }

                    var locationHeader = response.Headers.Location;
                    if (locationHeader == null)
                    {
                        result.Success = false;
                        result.ErrorMessage = "Received redirect status code without Location header.";
                        return result;
                    }

                    // Resolve relative redirect URIs
                    var nextUri = locationHeader.IsAbsoluteUri ? locationHeader : new Uri(currentUri, locationHeader);

                    if (nextUri.Scheme != Uri.UriSchemeHttp && nextUri.Scheme != Uri.UriSchemeHttps)
                    {
                        result.Success = false;
                        result.ErrorMessage = $"Blocked redirect to unsafe scheme: {nextUri.Scheme}";
                        return result;
                    }

                    // SSRF check on the redirect destination host
                    await _ssrfValidator.ValidateHostAsync(nextUri.Host, linkedCts.Token);

                    currentUri = nextUri;
                    result.FinalUrl = currentUri.ToString();
                    result.RedirectChain.Add(result.FinalUrl);
                    _logger.LogInformation("Following verified redirect to {NextUri}", nextUri);
                    continue;
                }

                // Step 4: Stream response content safely up to MaxResponseSizeBytes
                result.FinalUrl = currentUri.ToString();
                var contentLength = response.Content.Headers.ContentLength ?? 0;
                if (contentLength > _settings.MaxResponseSizeBytes)
                {
                    result.Success = false;
                    result.ErrorMessage = $"Response size ({contentLength} bytes) exceeds maximum permitted limit ({_settings.MaxResponseSizeBytes} bytes).";
                    return result;
                }

                await using var stream = await response.Content.ReadAsStreamAsync(linkedCts.Token);
                using var memoryStream = new MemoryStream();
                var buffer = new byte[8192];
                int bytesRead;
                long totalRead = 0;

                while ((bytesRead = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), linkedCts.Token)) > 0)
                {
                    totalRead += bytesRead;
                    if (totalRead > _settings.MaxResponseSizeBytes)
                    {
                        result.Success = false;
                        result.ErrorMessage = $"Response exceeded max size limit of {_settings.MaxResponseSizeBytes} bytes during download.";
                        return result;
                    }
                    await memoryStream.WriteAsync(buffer.AsMemory(0, bytesRead), linkedCts.Token);
                }

                result.ContentLength = totalRead;
                memoryStream.Position = 0;

                // Decode raw HTML text
                var charset = response.Content.Headers.ContentType?.CharSet;
                Encoding encoding = Encoding.UTF8;
                if (!string.IsNullOrWhiteSpace(charset))
                {
                    try { encoding = Encoding.GetEncoding(charset); } catch { /* fallback to UTF-8 */ }
                }

                using var reader = new StreamReader(memoryStream, encoding);
                result.HtmlContent = await reader.ReadToEndAsync(linkedCts.Token);
                result.Success = true;
                return result;
            }
            catch (SecurityException secEx)
            {
                _logger.LogWarning("Security check failed for {Url}: {Message}", currentUri, secEx.Message);
                result.Success = false;
                result.ErrorMessage = $"Security Exception: {secEx.Message}";
                return result;
            }
            catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
            {
                result.Success = false;
                result.ErrorMessage = $"Connection timed out after {_settings.HttpRequestTimeoutSeconds} seconds.";
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to fetch URL: {Url}", currentUri);
                result.Success = false;
                result.ErrorMessage = $"Network or connection error: {ex.Message}";
                return result;
            }
        }

        result.Success = false;
        result.ErrorMessage = "Redirect loop limit reached.";
        return result;
    }

    private static bool IsRedirectStatusCode(HttpStatusCode statusCode)
    {
        return statusCode is HttpStatusCode.MovedPermanently or
               HttpStatusCode.Found or
               HttpStatusCode.SeeOther or
               HttpStatusCode.TemporaryRedirect or
               (HttpStatusCode)308;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _httpClient.Dispose();
            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }
}
