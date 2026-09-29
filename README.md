# Secure Desktop URL Link Checker with DOM Analysis

A native, high-performance desktop security application built with **C# (.NET 9 / Photino.NET)** and a lightweight **React** frontend. It analyzes target URLs for phishing, scams, deceptive link spoofing, credential theft, and hidden iframes using zero-execution static inspection.

---

## Key Features

1. **Zero Execution Risk & Hardened Networking**:
   - The target URL is fetched purely as static text via `HttpClient`.
   - Never evaluates JavaScript from target web pages, preventing drive-by exploits.
   - Built-in stream size limiter (5 MB) and strict 8-second request timeouts.
   - **SSRF Protection with DNS Rebinding Defense**: Uses `SocketsHttpHandler.ConnectCallback` to validate the resolved IP address immediately prior to socket connection. Blocks private IPv4/IPv6 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `::1`), link-local/APIPA (`169.254.0.0/16`), and cloud metadata services (`169.254.169.254`, `metadata.google.internal`).
   - Disables automatic redirects to manually inspect every hop in the redirect chain against SSRF rules.

2. **Automated AngleSharp DOM Heuristics ("Inspect Element")**:
   - **Deceptive Link Spoofing**: Scans `<a>` tags to detect cases where the visible link text claims to be a trusted brand (e.g. `paypal.com`, `apple.com`) while the actual `href` navigates to an unrelated host.
   - **Credential Harvesting Form Detection**: Inspects `<form>` tags containing password or login credential fields. Flags forms whose `action` attribute submits sensitive credentials to external untrusted domains.
   - **Hidden IFrames & Overlay Detection**: Scans for iframes with `display:none`, `visibility:hidden`, `opacity:0`, or zero dimensions commonly used in clickjacking or silent payloads. Whitelists legitimate anti-bot providers (reCAPTCHA, hCaptcha, Turnstile, Stripe, PayPal).
   - **Meta Refresh Redirects & Social Engineering Language**: Identifies non-standard meta refresh redirects and urgency panic keywords in headers/titles.

3. **URL Lexical Heuristics**:
   - Punycode / Cyrillic IDN homoglyph spoofing (`xn--`).
   - Numerical raw IP hostnames.
   - High-abuse / disposable TLD tracking (`.top`, `.xyz`, `.work`, `.click`, `.gq`, etc.).
   - Brand keyword spoofing in subdomains or path segments.

4. **External Threat Intelligence & RDAP/WHOIS**:
   - **Google Safe Browsing v4**: Detects known malware, social engineering, and unwanted software.
   - **VirusTotal v3**: Aggregates multi-vendor security verdicts.
   - **RDAP / WHOIS Registration**: Identifies newly registered domains (<30 days old) without requiring paid API keys.
   - Graceful degradation: If API keys are omitted, the app clearly marks them as skipped and completes all DOM and heuristic analyses.

5. **Strict Object-Oriented Architecture**:
   - Every class, interface, and model resides in its own file.
   - Dependency Injection via `Microsoft.Extensions.DependencyInjection`.
   - Clean folder structure: `/Models`, `/Interfaces`, `/Services`, `/Security`, `/Configuration`.

6. **One-Click Double-Clickable Desktop Executable**:
   - MSBuild triggers Vite production compilation (`npm run build`) automatically before building C#.
   - Published as a self-contained single `.exe` file (`publish\LinkSafetyChecker.exe`).
   - Static React assets are embedded as assembly resources, ensuring the executable launches seamlessly from any location without dependencies.

---

## Quick Start (How to Launch)

### 1. Launch the Pre-Built Executable
The single-file executable is accessible immediately from either of these locations:
- **Directly on your Desktop**: `C:\Users\chris\OneDrive\Desktop\LinkSafetyChecker.exe`
- **In the Project Root Folder**: `LinkSafetyChecker.exe`

No terminal commands or dev servers required! Simply double-click it.

### 2. (Optional) Configuring API Keys
Copy `appsettings.example.json` to `appsettings.json` (or edit `publish\appsettings.json`):
```json
{
  "ApiKeys": {
    "GoogleSafeBrowsing": "YOUR_GOOGLE_SAFE_BROWSING_API_KEY",
    "VirusTotal": "YOUR_VIRUSTOTAL_API_KEY",
    "WhoisXml": "YOUR_OPTIONAL_WHOISXML_KEY"
  }
}
```
*Note: `appsettings.json` is automatically ignored by `.gitignore` to keep your credentials safe.*

Alternatively, set environment variables:
- `URLCHECKER_GOOGLE_SAFE_BROWSING_KEY`
- `URLCHECKER_VIRUSTOTAL_KEY`

---

## Development & Building

### Running Unit Tests
```bash
dotnet test
```
*(36 automated tests covering SSRF, AngleSharp DOM analysis, iframe whitelisting, heuristics, and scoring)*

### Rebuilding the Single-File Executable
Run the included build script:
```cmd
publish.bat
```
Or execute via .NET CLI:
```bash
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish
```
