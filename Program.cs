using System.Drawing;
using LinkSafetyChecker.Configuration;
using LinkSafetyChecker.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Photino.NET;

namespace LinkSafetyChecker;

public static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        // 1. Build Configuration
        var configuration = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
            .AddJsonFile("appsettings.local.json", optional: true, reloadOnChange: true)
            .AddEnvironmentVariables(prefix: "URLCHECKER_")
            .AddEnvironmentVariables()
            .Build();

        // 2. Setup Dependency Injection
        var services = new ServiceCollection();
        services.AddLogging(builder =>
        {
            builder.AddConfiguration(configuration.GetSection("Logging"));
            builder.AddConsole();
        });

        services.AddLinkSafetyServices(configuration);

        using var serviceProvider = services.BuildServiceProvider();
        var logger = serviceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("Program");
        logger.LogInformation("Starting Link Safety Checker Desktop Application...");

        // 3. Resolve HTML Entry Point
        var assetManager = serviceProvider.GetRequiredService<IStaticAssetManager>();
        var indexPath = assetManager.ResolveIndexHtmlPath();

        logger.LogInformation("Loading UI from: {IndexPath} (Exists: {Exists})", indexPath, File.Exists(indexPath));

        // 4. Initialize Photino Native Window
        var window = new PhotinoWindow()
            .SetTitle("Link Safety Checker")
            .SetUseOsDefaultSize(false)
            .SetSize(new Size(1080, 820))
            .Center();

        // 5. Attach Desktop IPC Bridge
        var ipcHandler = serviceProvider.GetRequiredService<IDesktopIpcHandler>();
        ipcHandler.Attach(window);

        // 6. Navigate to React UI or Fallback
        if (File.Exists(indexPath))
        {
            window.Load(indexPath);
        }
        else
        {
            // Diagnostic fallback if wwwroot has not been compiled yet
            window.LoadRawString(@"
<!DOCTYPE html>
<html>
<head>
  <title>Link Safety Checker - Setup</title>
  <style>
    body { font-family: sans-serif; padding: 40px; background: #0f172a; color: #f8fafc; }
    .card { background: #1e293b; padding: 24px; border-radius: 8px; border: 1px solid #334155; }
    h1 { color: #38bdf8; }
    code { background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #facc15; }
  </style>
</head>
<body>
  <div class='card'>
    <h1>Link Safety Checker</h1>
    <p>React frontend build not found in <code>wwwroot/index.html</code>.</p>
    <p>Please run <code>npm run build</code> in the <code>client/</code> directory.</p>
  </div>
</body>
</html>");
        }

        // 7. Run Native Desktop Loop
        window.WaitForClose();
    }
}
