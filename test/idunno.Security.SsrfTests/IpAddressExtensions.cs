// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;

namespace idunno.Security.SsrfTests;

public class IPAddressExtensions
{
    [Fact]
    public void IsIPv4CompatibleIPv6_ReturnsTrueForIPv4CompatibleIPv6Address()
    {
        var ipAddress = IPAddress.Parse("::192.0.2.1");

        bool result = ipAddress.IsIPv4CompatibleIPv6;

        Assert.True(result);
    }

    [Fact]
    public void IsIPv4CompatibleIPv6_ReturnsFalseForNonIPv4CompatibleIPv6Address()
    {
        var ipAddress = IPAddress.Parse("2606:4700:10::6814:179a");

        bool result = ipAddress.IsIPv4CompatibleIPv6;

        Assert.False(result);
    }

    [Fact]
    public void IsIPv4CompatibleIPv6_ReturnsFalseForIPv6Localhost()
    {
        var ipAddress = IPAddress.Parse("::1");

        bool result = ipAddress.IsIPv4CompatibleIPv6;

        Assert.False(result);
    }

    [Fact]
    public void IsIPv4CompatibleIPv6_ReturnsFalseForIPv6EmptyNetwork()
    {
        var ipAddress = IPAddress.Parse("::");

        bool result = ipAddress.IsIPv4CompatibleIPv6;

        Assert.False(result);
    }


    [Fact]
    public void MapIPv6CompatibleToIPv4_ReturnsMappedIPv4Address()
    {
        var ipAddress = IPAddress.Parse("::129.0.2.1");

        var result = ipAddress.MapIPv6CompatibleToIPv4();

        Assert.Equal(IPAddress.Parse("129.0.2.1"), result);
    }

    [Fact]
    public void MapIPv6CompatibleToIPv4_ReturnsOriginalIPAddressForNonIPv4CompatibleIPv6Address()
    {
        var ipAddress = IPAddress.Parse("2606:4700:10::6814:179a");
        var result = ipAddress.MapIPv6CompatibleToIPv4();
        Assert.Equal(ipAddress, result);
    }

    [Fact]
    public void IsIPv6ToIPv4Mapped_ReturnsTrueForIPv6ToIPv4MappedAddress()
    {
        var ipAddress = IPAddress.Parse("2002:C000:022A::1");

        var result = ipAddress.Is6to4;
        Assert.True(result);
    }

    [Fact]
    public void IsIPv6ToIPv4Mapped_ReturnsFalseForNonIPv6ToIPv4MappedAddress()
    {
        var ipAddress = IPAddress.Parse("2606:4700:10::6814:179a");

        var result = ipAddress.Is6to4;
        Assert.False(result);
    }

    [InlineData("2002:C000:022A::1", "192.0.2.42")]
    [InlineData("2002:c0a8:6301::1", "192.168.99.1")]
    [Theory]
    public void MapIPv6ToIPv4Tunnel_ReturnsMappedIPv4Address(string ipV6, string ipV4)
    {
        var ipAddress = IPAddress.Parse(ipV6);
        var result = ipAddress.Map6to4TunnelToIPv4();
        Assert.Equal(IPAddress.Parse(ipV4), result);
    }

    [Fact]
    public void MapIPv6ToIPv4Tunnel_ReturnsOriginalIPAddressForNon6to4Addresses()
    {
        var ipAddress = IPAddress.Parse("2606:4700:10::6814:179a");
        var result = ipAddress.Map6to4TunnelToIPv4();
        Assert.Equal(ipAddress, result);
    }

    [Fact]
    public void IsISATAP_ReturnsTrueForISATAPAddress()
    {
        var ipAddress = IPAddress.Parse("2001:DB8:1234:5678:0000:5EFE:0AAD:8108");
        var result = ipAddress.IsISATAP;
        Assert.True(result);
    }

    [Fact]
    public void IsISATAP_ReturnsTrueForISATAPAddressWithUBitSet()
    {
        var ipAddress = IPAddress.Parse("2001:DB8:1234:5678:0200:5EFE:0AAD:8108");

        Assert.True(ipAddress.IsISATAP);
    }

    [Theory]
    [InlineData("2001:DB8:1234:5678:00ff:5EFE:0AAD:8108")] // byte 9 non-zero
    [InlineData("2001:DB8:1234:5678:0100:5EFE:0AAD:8108")] // byte 8 not 0x00 or 0x02
    [InlineData("2001:DB8:1234:5678:0300:5EFE:0AAD:8108")] // byte 8 not 0x00 or 0x02
    public void IsISATAP_ReturnsFalseForInvalidIdentifier(string ipAddressAsString)
    {
        var ipAddress = IPAddress.Parse(ipAddressAsString);

        Assert.False(ipAddress.IsISATAP);
    }

    [Fact]
    public void IsISATAP_ReturnsFalseForNonISATAPAddress()
    {
        var ipAddress = IPAddress.Parse("2606:4700:10::6814:179a");
        var result = ipAddress.IsISATAP;
        Assert.False(result);
    }

    [Fact]
    public void MapISATAPToIPv4_ReturnsMappedIPv4Address()
    {
        var ipAddress = IPAddress.Parse("2001:DB8:1234:5678:0000:5EFE:0AAD:8108");
        var result = ipAddress.MapISATAPToIPv4();
        Assert.Equal(IPAddress.Parse("10.173.129.8"), result);
    }

    [Fact]
    public void MapISATAPToIPv4_ReturnsOriginalIPAddressForNonISATAPAddress()
    {
        var ipAddress = IPAddress.Parse("2606:4700:10::6814:179a");
        var result = ipAddress.MapISATAPToIPv4();
        Assert.Equal(ipAddress, result);
    }

    [Fact]
    public void IsNAT64_ReturnsTrueForNAT64Address()
    {
        var ipAddress = IPAddress.Parse("64:ff9b::10.0.0.1");
        var result = ipAddress.IsNAT64;
        Assert.True(result);
    }

    [Fact]
    public void IsNAT64_ReturnsFalseForNonNAT64Address()
    {
        var ipAddress = IPAddress.Parse("2606:4700:10::6814:179a");
        var result = ipAddress.IsNAT64;
        Assert.False(result);
    }

    [Fact]
    public void MapNAT64ToIPv4_ReturnsMappedIPv4Address()
    {
        var ipAddress = IPAddress.Parse("64:ff9b::10.0.0.1");
        var result = ipAddress.MapNAT64ToIPv4();
        Assert.Equal(IPAddress.Parse("10.0.0.1"), result);
    }

    [Fact]
    public void MapNAT64ToIPv4_ReturnsOriginalIPAddressForNonNAT64Address()
    {
        var ipAddress = IPAddress.Parse("2606:4700:10::6814:179a");
        var result = ipAddress.MapNAT64ToIPv4();
        Assert.Equal(ipAddress, result);
    }

    [Fact]
    public void MapTeredoToIPv4_ReturnsMappedIPv4Address()
    {
        var ipAddress = IPAddress.Parse("2001:0:4136:e378:8000:63bf:3fff:fdd2");
        var result = ipAddress.MapTeredoToIPv4();
        Assert.Equal(IPAddress.Parse("192.0.2.45"), result);
    }

    [Fact]
    public void MapTeredoToIPv4_ReturnsOriginalIPForNonTeredoAddress()
    {
        var ipAddress = IPAddress.Parse("2606:4700:10::6814:179a");
        var result = ipAddress.MapTeredoToIPv4();
        Assert.Equal(ipAddress, result);
    }

    [Theory]
    [InlineData("64:ff9b::10.0.0.1")]
    public void IsNAT64_ReturnsTrueForWellKnownPrefix(string ipAddressAsString)
    {
        var ipAddress = IPAddress.Parse(ipAddressAsString);

        Assert.True(ipAddress.IsNAT64);
    }

    [Theory]
    [InlineData("64:ff9b:1::10.0.0.1")]
    [InlineData("64:ff9b:1::8.8.8.8")]
    public void IsNAT64_ReturnsFalseForLocalUsePrefix(string ipAddressAsString)
    {
        var ipAddress = IPAddress.Parse(ipAddressAsString);

        Assert.False(ipAddress.IsNAT64);
    }

    [Theory]
    [InlineData("64:ff9b:1::10.0.0.1")]
    [InlineData("64:ff9b:1::8.8.8.8")]
    [InlineData("64:ff9b:1:abcd::10.0.0.1")]
    public void IsNAT64LocalUse_ReturnsTrueForLocalUsePrefix(string ipAddressAsString)
    {
        var ipAddress = IPAddress.Parse(ipAddressAsString);

        Assert.True(ipAddress.IsNAT64LocalUse);
    }

    [Theory]
    [InlineData("64:ff9b::10.0.0.1")]
    [InlineData("2606:4700:10::6814:179a")]
    [InlineData("10.0.0.1")]
    public void IsNAT64LocalUse_ReturnsFalseForNonLocalUseAddresses(string ipAddressAsString)
    {
        var ipAddress = IPAddress.Parse(ipAddressAsString);

        Assert.False(ipAddress.IsNAT64LocalUse);
    }

    [Theory]
    [InlineData("64:ff9b::10.0.0.1", "10.0.0.1")]
    public void MapNAT64ToIPv4_ReturnsMappedIPv4AddressForWellKnownPrefix(string ipAddressAsString, string expectedAsString)
    {
        var ipAddress = IPAddress.Parse(ipAddressAsString);
        var expected = IPAddress.Parse(expectedAsString);

        var result = ipAddress.MapNAT64ToIPv4();

        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("::1")]
    [InlineData("::")]
    [InlineData("::ffff:127.0.0.1")]
    public void IsIPv4CompatibleIPv6_ReturnsFalseForBoundaryAddresses(string ipAddressAsString)
    {
        var ipAddress = IPAddress.Parse(ipAddressAsString);

        Assert.False(ipAddress.IsIPv4CompatibleIPv6);
    }

    [Theory]
    [InlineData("::1")]
    [InlineData("::")]
    [InlineData("::ffff:127.0.0.1")]
    public void MapIPv6CompatibleToIPv4_ReturnsOriginalForBoundaryAddresses(string ipAddressAsString)
    {
        var ipAddress = IPAddress.Parse(ipAddressAsString);

        var result = ipAddress.MapIPv6CompatibleToIPv4();

        Assert.Equal(ipAddress, result);
    }

    [Theory]
    [InlineData("127.0.0.1", "127.0.0.1")]
    [InlineData("::1", "::1")]
    [InlineData("::", "::")]
    [InlineData("::ffff:127.0.0.1", "127.0.0.1")]
    [InlineData("::192.0.2.1", "192.0.2.1")]
    [InlineData("2002:c000:022a::1", "192.0.2.42")]
    [InlineData("2002:7f00:0001::", "127.0.0.1")]
    [InlineData("64:ff9b::10.0.0.1", "10.0.0.1")]
    // RFC 8215 NAT64 local-use /48 is deliberately not normalized: the operator's local NAT64 gateway
    // is internal infrastructure, so these addresses are blocked at the range level by Ssrf.IsUnsafeIpAddress
    // regardless of the embedded IPv4, including public IPv4 addresses.
    [InlineData("64:ff9b:1::10.0.0.1", "64:ff9b:1::10.0.0.1")]
    [InlineData("64:ff9b:1::8.8.8.8", "64:ff9b:1::8.8.8.8")]
    [InlineData("2600:abcd::5efe:0a00:0001", "10.0.0.1")]
    [InlineData("2001:0:4136:e378:8000:63bf:3fff:fdd2", "192.0.2.45")]
    [InlineData("2606:4700:10::6814:179a", "2606:4700:10::6814:179a")]
    public void NormalizeToIPv4_ReturnsExpectedAddress(string ipAddressAsString, string expectedAsString)
    {
        var ipAddress = IPAddress.Parse(ipAddressAsString);
        var expected = IPAddress.Parse(expectedAsString);

        var result = ipAddress.NormalizeToIPv4();

        Assert.Equal(expected, result);
    }

    [Theory]
    // An address satisfying both IsIPv6Teredo (2001:0000::/32 prefix) and IsISATAP (bytes 8-11 == 02-00-5E-FE)
    // must be normalized via Teredo so the (inverted) Teredo-embedded client IPv4 is evaluated, rather than
    // the raw bytes 12-15 being treated as an ISATAP-embedded IPv4.
    // 2001:0:abcd:1234:0200:5efe:f5ff:fffe -> Teredo decode: ~f5ff:fffe = 10.0.0.1 (unsafe).
    //                                        ISATAP decode:  f5ff:fffe  = 245.255.255.254 (would appear safe).
    [InlineData("2001:0:abcd:1234:0200:5efe:f5ff:fffe")]
    [InlineData("2001:0:abcd:1234:0000:5efe:f5ff:fffe")]
    public void NormalizeToIPv4_PrefersTeredoOverISATAPForAmbiguousAddresses(string ipAddressAsString)
    {
        var ipAddress = IPAddress.Parse(ipAddressAsString);

        var result = ipAddress.NormalizeToIPv4();

        Assert.Equal(IPAddress.Parse("10.0.0.1"), result);
    }

    [Theory]
    [InlineData("2001:0:abcd:1234:0200:5efe:f5ff:fffe")]
    [InlineData("2001:0:abcd:1234:0000:5efe:f5ff:fffe")]
    public void IsUnsafeIpAddress_ReturnsTrueForTeredoAddressWithISATAPShapedIdentifier(string ipAddressAsString)
    {
        var ipAddress = IPAddress.Parse(ipAddressAsString);

        Assert.True(Ssrf.IsUnsafeIpAddress(ipAddress));
    }

    [Theory]
    // ISATAP inside a non-reserved unicast /32 wrapping RFC1918 / loopback / link-local.
    // Without ISATAP normalization none of these are caught by a default unsafe range.
    [InlineData("2600:abcd::5efe:0a00:0001")] // 10.0.0.1
    [InlineData("2600:abcd::5efe:7f00:0001")] // 127.0.0.1
    [InlineData("2600:abcd::5efe:a9fe:a9fe")] // 169.254.169.254
    [InlineData("2600:abcd::5efe:c0a8:0001")] // 192.168.0.1
    // ISATAP with the u-bit set (02-00-5E-FE identifier) wrapping an unsafe IPv4.
    [InlineData("2600:abcd::200:5efe:0a00:0001")] // 10.0.0.1
    // IPv4-compatible IPv6 wrapping unsafe IPv4 addresses.
    [InlineData("::127.0.0.1")]
    [InlineData("::169.254.169.254")]
    [InlineData("::10.0.0.1")]
    // IPv4-mapped IPv6 wrapping unsafe IPv4 addresses.
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("::ffff:169.254.169.254")]
    public void IsUnsafeIpAddress_ReturnsTrueForIPv6WrappedUnsafeIPv4(string ipAddressAsString)
    {
        var ipAddress = IPAddress.Parse(ipAddressAsString);

        Assert.True(Ssrf.IsUnsafeIpAddress(ipAddress));
    }
}
