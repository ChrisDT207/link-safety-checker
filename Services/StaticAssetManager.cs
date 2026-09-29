using System.Reflection;
using LinkSafetyChecker.Interfaces;
using Microsoft.Extensions.Logging;

namespace LinkSafetyChecker.Services;

public class StaticAssetManager : IStaticAssetManager
{
    private readonly ILogger<StaticAssetManager> _logger;

    public StaticAssetManager(ILogger<StaticAssetManager> logger)
    {
        _logger = logger;
    }

    public string ResolveIndexHtmlPath()
    {
        // 1. Check local output directory adjacent to executable
        var baseDir = AppContext.BaseDirectory;
        var directPath = Path.Combine(baseDir, "wwwroot", "index.html");
        if (File.Exists(directPath))
        {
            _logger.LogInformation("Found static UI at executable directory: {Path}", directPath);
            return directPath;
        }

        // 2. Check current working directory
        var cwdPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "index.html");
        if (File.Exists(cwdPath))
        {
            _logger.LogInformation("Found static UI at working directory: {Path}", cwdPath);
            return cwdPath;
        }

        // 3. Fallback: Extract embedded resources to LocalApplicationData for true single-file portability
        var fallbackDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LinkSafetyChecker",
            "wwwroot");

        try
        {
            var extracted = ExtractEmbeddedAssets(fallbackDir);
            var extractedIndex = Path.Combine(fallbackDir, "index.html");
            if (extracted && File.Exists(extractedIndex))
            {
                _logger.LogInformation("Extracted and resolved embedded UI at: {Path}", extractedIndex);
                return extractedIndex;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to extract embedded static assets to {Dir}", fallbackDir);
        }

        return directPath;
    }

    private bool ExtractEmbeddedAssets(string targetDirectory)
    {
        var assembly = Assembly.GetExecutingAssembly();
        const string prefix = "LinkSafetyChecker.wwwroot.";
        var resourceNames = assembly.GetManifestResourceNames()
            .Where(r => r.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (resourceNames.Count == 0)
        {
            return false;
        }

        Directory.CreateDirectory(targetDirectory);
        var assetsDir = Path.Combine(targetDirectory, "assets");
        Directory.CreateDirectory(assetsDir);

        foreach (var resource in resourceNames)
        {
            var relativeName = resource[prefix.Length..];
            string destinationPath;

            if (relativeName.StartsWith("assets.", StringComparison.OrdinalIgnoreCase))
            {
                var fileName = relativeName["assets.".Length..];
                destinationPath = Path.Combine(assetsDir, fileName);
            }
            else
            {
                destinationPath = Path.Combine(targetDirectory, relativeName);
            }

            using var stream = assembly.GetManifestResourceStream(resource);
            if (stream != null)
            {
                using var fileStream = File.Create(destinationPath);
                stream.CopyTo(fileStream);
            }
        }

        return true;
    }
}
