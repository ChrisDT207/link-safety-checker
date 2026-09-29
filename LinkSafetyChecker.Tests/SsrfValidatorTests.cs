using System.Net;
using System.Security;
using LinkSafetyChecker.Configuration;
using LinkSafetyChecker.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace LinkSafetyChecker.Tests;

public class SsrfValidatorTests
{
    private readonly SsrfValidator _validator;

    public SsrfValidatorTests()
    {
        var settings = new SecuritySettingsConfig { AllowPrivateNetwork = false };
        _validator = new SsrfValidator(settings, NullLogger<SsrfValidator>.Instance);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.0.0.2")]
    [InlineData("10.0.0.1")]
    [InlineData("10.255.255.255")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.0.1")]
    [InlineData("192.168.1.100")]
    [InlineData("169.254.169.254")] // AWS/GCP/Azure instance metadata
    [InlineData("0.0.0.0")]
    [InlineData("224.0.0.1")] // Multicast
    public void IsIpAllowed_ShouldBlockPrivateAndReservedIpv4(string ipStr)
    {
        var ip = IPAddress.Parse(ipStr);
        Assert.False(_validator.IsIpAllowed(ip));
    }

    [Theory]
    [InlineData("::1")] // IPv6 loopback
    [InlineData("fe80::1")] // Link-local
    [InlineData("fc00::1")] // Unique local
    public void IsIpAllowed_ShouldBlockPrivateAndReservedIpv6(string ipStr)
    {
        var ip = IPAddress.Parse(ipStr);
        Assert.False(_validator.IsIpAllowed(ip));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("93.184.216.34")]
    public void IsIpAllowed_ShouldAllowPublicIpv4(string ipStr)
    {
        var ip = IPAddress.Parse(ipStr);
        Assert.True(_validator.IsIpAllowed(ip));
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.169.254")]
    [InlineData("metadata.google.internal")]
    public async Task ValidateHostAsync_ShouldThrowSecurityException_ForBlockedHosts(string host)
    {
        await Assert.ThrowsAsync<SecurityException>(() => _validator.ValidateHostAsync(host));
    }
}
