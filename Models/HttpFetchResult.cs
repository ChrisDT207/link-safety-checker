namespace LinkSafetyChecker.Models;

public class HttpFetchResult
{
    public bool Success { get; set; }
    public string? HtmlContent { get; set; }
    public int StatusCode { get; set; }
    public string? ContentType { get; set; }
    public long ContentLength { get; set; }
    public string RequestedUrl { get; set; } = string.Empty;
    public string FinalUrl { get; set; } = string.Empty;
    public List<string> RedirectChain { get; set; } = [];
    public Dictionary<string, string> Headers { get; set; } = [];
    public string? ErrorMessage { get; set; }
}
