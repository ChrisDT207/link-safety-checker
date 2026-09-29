using System.Net;
using System.Net.Sockets;
using System.Security;
using LinkSafetyChecker.Configuration;
using LinkSafetyChecker.Interfaces;
using Microsoft.Extensions.Logging;

namespace LinkSafetyChecker.Security;

public class SsrfValidator : ISsrfValidator
{
    private readonly SecuritySettingsConfig _settings;
    private readonly ILogger<SsrfValidator> _logger;

    private static readonly HashSet<string> BlockedHostnames = new(StringComparer.OrdinalIgnoreCase)
    {
        "localhost",
        "metadata.google.internal",
        "instance-data",
        "169.254.169.254"
    };

    public SsrfValidator(SecuritySettingsConfig settings, ILogger<SsrfValidator> logger)
    {
        _settings = settings;
        _logger = logger;
    }

    public bool IsIpAllowed(IPAddress ipAddress)
    {
        if (_settings.AllowPrivateNetwork)
        {
            return true;
        }

        // Map IPv4 mapped to IPv6 if needed
        if (ipAddress.IsIPv4MappedToIPv6)
        {
            ipAddress = ipAddress.MapToIPv4();
        }

        if (IPAddress.IsLoopback(ipAddress))
        {
            return false;
        }

        if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] bytes = ipAddress.GetAddressBytes();

            // 0.0.0.0/8 (Broadcast/Current network)
            if (bytes[0] == 0) return false;

            // 10.0.0.0/8 (Private)
            if (bytes[0] == 10) return false;

            // 100.64.0.0/10 (Carrier-Grade NAT)
            if (bytes[0] == 100 && (bytes[1] >= 64 && bytes[1] <= 127)) return false;

            // 127.0.0.0/8 (Loopback)
            if (bytes[0] == 127) return false;

            // 169.254.0.0/16 (Link Local / Cloud Metadata APIPA)
            if (bytes[0] == 169 && bytes[1] == 254) return false;

            // 172.16.0.0/12 (Private)
            if (bytes[0] == 172 && (bytes[1] >= 16 && bytes[1] <= 31)) return false;

            // 192.0.0.0/24 (IETF Protocol Assignments)
            if (bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 0) return false;

            // 192.168.0.0/16 (Private)
            if (bytes[0] == 192 && bytes[1] == 168) return false;

            // 198.18.0.0/15 (Benchmarking)
            if (bytes[0] == 198 && (bytes[1] == 18 || bytes[1] == 19)) return false;

            // 224.0.0.0/4 (Multicast)
            if (bytes[0] >= 224 && bytes[0] <= 239) return false;

            // 240.0.0.0/4 (Reserved)
            if (bytes[0] >= 240) return false;

            // 255.255.255.255 (Limited Broadcast)
            if (bytes[0] == 255 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 255) return false;

            return true;
        }

        if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // ::1 Loopback
            if (IPAddress.IPv6Loopback.Equals(ipAddress)) return false;

            // :: Any
            if (IPAddress.IPv6Any.Equals(ipAddress)) return false;

            // Link-local: fe80::/10
            if (ipAddress.IsIPv6LinkLocal) return false;

            // Multicast: ff00::/8
            if (ipAddress.IsIPv6Multicast) return false;

            // Site-local: fec0::/10 (deprecated but reserved)
            if (ipAddress.IsIPv6SiteLocal) return false;

            // Unique Local: fc00::/7
            byte[] bytes = ipAddress.GetAddressBytes();
            if ((bytes[0] & 0xFE) == 0xFC) return false;

            return true;
        }

        return false;
    }

    public async Task ValidateHostAsync(string host, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            throw new ArgumentException("Host cannot be empty.", nameof(host));
        }

        if (BlockedHostnames.Contains(host.Trim()))
        {
            _logger.LogWarning("Blocked explicitly restricted host: {Host}", host);
            throw new SecurityException($"Access to host '{host}' is prohibited (SSRF prevention).");
        }

        if (IPAddress.TryParse(host, out var parsedIp))
        {
            if (!IsIpAllowed(parsedIp))
            {
                _logger.LogWarning("Blocked private or reserved IP address: {Ip}", parsedIp);
                throw new SecurityException($"Access to IP address '{parsedIp}' is prohibited (SSRF prevention).");
            }
            return;
        }

        try
        {
            var addresses = await Dns.GetHostAddressesAsync(host, cancellationToken);
            if (addresses.Length == 0)
            {
                throw new SecurityException($"Unable to resolve DNS for host '{host}'.");
            }

            foreach (var addr in addresses)
            {
                if (!IsIpAllowed(addr))
                {
                    _logger.LogWarning("Host {Host} resolved to prohibited IP address {Ip}", host, addr);
                    throw new SecurityException($"Host '{host}' resolves to prohibited IP address '{addr}' (SSRF prevention).");
                }
            }
        }
        catch (SocketException ex)
        {
            _logger.LogWarning(ex, "DNS resolution failed for host: {Host}", host);
            throw new SecurityException($"Failed to resolve host '{host}': {ex.Message}", ex);
        }
    }
}
