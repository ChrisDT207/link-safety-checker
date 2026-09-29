using System.Net;
using System.Net.Sockets;
using System.Security;
using LinkSafetyChecker.Configuration;
using LinkSafetyChecker.Interfaces;
using Microsoft.Extensions.Logging;

namespace LinkSafetyChecker.Security;

public static class SafeSocketsHttpHandlerFactory
{
    public static SocketsHttpHandler Create(
        ISsrfValidator ssrfValidator,
        SecuritySettingsConfig settings,
        ILogger logger)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false, // Disable auto redirects to inspect each hop with SSRF checks
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
            ConnectTimeout = TimeSpan.FromSeconds(Math.Min(settings.HttpRequestTimeoutSeconds, 5)),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            MaxConnectionsPerServer = 4
        };

        // ConnectCallback prevents DNS Rebinding (TOCTOU) attacks
        // by verifying the IP immediately before the socket connection is established.
        handler.ConnectCallback = async (context, cancellationToken) =>
        {
            var host = context.DnsEndPoint.Host;
            var port = context.DnsEndPoint.Port;

            IPAddress[] addresses;

            if (IPAddress.TryParse(host, out var directIp))
            {
                addresses = [directIp];
            }
            else
            {
                try
                {
                    addresses = await Dns.GetHostAddressesAsync(host, cancellationToken);
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "DNS resolution failed in ConnectCallback for host: {Host}", host);
                    throw new SecurityException($"DNS resolution failed for '{host}': {ex.Message}", ex);
                }
            }

            if (addresses.Length == 0)
            {
                throw new SecurityException($"No IP addresses found for host '{host}'.");
            }

            // Verify every resolved IP against SSRF rules
            foreach (var address in addresses)
            {
                if (!ssrfValidator.IsIpAllowed(address))
                {
                    logger.LogWarning("ConnectCallback blocked prohibited IP {Ip} for host {Host}", address, host);
                    throw new SecurityException($"DNS Rebinding / SSRF detected: Host '{host}' resolves to disallowed address '{address}'.");
                }
            }

            // Connect using the validated IP address
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true
            };

            try
            {
                await socket.ConnectAsync(addresses, port, cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        };

        return handler;
    }
}
