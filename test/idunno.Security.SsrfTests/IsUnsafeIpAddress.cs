// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;

namespace idunno.Security.SsrfTests;

public class IsUnsafeIpAddress
{
    [Theory]
    [InlineData("104.18.26.120")]
    [InlineData("104.18.27.120")]
    [InlineData("[2620:1ec:bdf::69]")]
    [InlineData("[2620:1ec:46::69]")]
    public void ReturnsFalseForGoodIpAddresses(string ipAddressAsString)
    {
        Assert.False(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("104.18.26.120")]
    [InlineData("104.18.27.120")]
    [InlineData("[2620:1ec:bdf::69]")]
    [InlineData("[2620:1ec:46::69]")]
    public void ReturnsTrueForGoodIpAddressesIfTheyAreInTheSpecifiedAdditionalUnsafeNetworks(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(
            ipAddress: IPAddress.Parse(ipAddressAsString),
            additionalUnsafeIPNetworks:
            [
                IPNetwork.Parse("104.16.0.0/12"),
                IPNetwork.Parse("2620:1ec::/36"),
            ],
            additionalUnsafeIPAddresses: null));
    }

    [Theory]
    [InlineData("104.18.26.120")]
    [InlineData("104.18.27.120")]
    [InlineData("[2620:1ec:bdf::69]")]
    [InlineData("[2620:1ec:46::69]")]
    public void ReturnsTrueForGoodIpAddressesIfTheyAreInTheSpecifiedAdditionalUnsafeIpAddresses(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(
            ipAddress: IPAddress.Parse(ipAddressAsString),
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses:
            [
                IPAddress.Parse("104.18.26.120"),
                IPAddress.Parse("104.18.27.120"),
                IPAddress.Parse("2620:1ec:bdf::69"),
                IPAddress.Parse("2620:1ec:46::69"),
            ]));
    }

    [Theory]
    [InlineData("104.18.26.120")]
    [InlineData("104.18.27.120")]
    [InlineData("[2620:1ec:bdf::69]")]
    [InlineData("[2620:1ec:46::69]")]
    public void ReturnsTrueForGoodIpAddressesIfTheyAreInTheSpecifiedAdditionalUnsafeIpNetworksAndOrIpAddresses(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(
            ipAddress: IPAddress.Parse(ipAddressAsString),
            additionalUnsafeIPNetworks:
            [
                IPNetwork.Parse("104.16.0.0/12"),
                IPNetwork.Parse("2620:1ec::/36"),
            ],
            additionalUnsafeIPAddresses:
            [
                IPAddress.Parse("104.18.26.120"),
                IPAddress.Parse("104.18.27.120"),
                IPAddress.Parse("2620:1ec:bdf::69"),
                IPAddress.Parse("2620:1ec:46::69"),
            ]));
    }

    [Theory]
    [InlineData("::ffff:10.0.0.1")]
    [InlineData("::ffff:172.16.0.1")]
    [InlineData("::ffff:192.168.0.1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("::ffff:169.254.169.254")]
    public void ReturnsTrueForIPv4MappedIPv6AddressesInBuiltInUnsafeRanges(string ipv4MappedIpv6)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipv4MappedIpv6)));
    }

    [Theory]
    [InlineData("10.0.0.1")]
    [InlineData("172.16.0.1")]
    [InlineData("192.168.0.1")]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.0.1")]
    [InlineData("100.64.0.0")]
    [InlineData("0.0.0.1")]
    [InlineData("198.18.0.1")]
    [InlineData("192.0.2.1")]
    [InlineData("198.51.100.1")]
    [InlineData("203.0.113.0")]
    [InlineData("192.0.0.0")]
    [InlineData("224.0.0.1")]
    [InlineData("240.0.0.0")]
    [InlineData("169.254.169.254")]
    [InlineData("fe80::1")]
    [InlineData("fc00::1")]
    [InlineData("fec0::1")]
    [InlineData("2001::1")]
    [InlineData("2001:db8::1")]
    [InlineData("3fff::42")]
    [InlineData("100::1")]
    public void ReturnsTrueForIpAddressesInThePredefinedNetworks(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Fact]
    public void ReturnsTrueForIpv4BroadcastIpAddress()
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Broadcast));
    }

    [Fact]
    public void ReturnsTrueForIpv4AnyIpAddress()
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Any));
    }


    [Fact]
    public void ReturnsTrueForLoopbackIpAddresses()
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Loopback));
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.IPv6Loopback));
    }

    [Fact]
    public void ReturnsTrueForUnspecifiedIpAddresses()
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.None));
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.IPv6None));
    }

    [Theory]
    [InlineData("169.254.255.254")]
    [InlineData("169.254.0.1")]
    public void ReturnsTrueForIPv4LinkLocalAddresses(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    // See https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml
    // Node-Local Scope Multicast Addresses
    [InlineData("ff01:0:0:0:0:0:0:1")]
    [InlineData("ff01:0:0:0:0:0:0:2")]
    [InlineData("ff01:0:0:0:0:0:0:c")]
    [InlineData("ff01:0:0:0:0:0:0:fa")]
    [InlineData("ff01:0:0:0:0:0:0:fb")]
    [InlineData("ff01:0:0:0:0:0:0:fc")]
    [InlineData("ff01:0:0:0:0:0:0:fd")]
    [InlineData("ff01:0:0:0:0:0:0:100")]
    [InlineData("ff01:0:0:0:0:0:0:178")]
    [InlineData("ff01:0:0:0:0:0:0:181")]
    [InlineData("ff01:0:0:0:0:0:0:184")]
    [InlineData("ff01:0:0:0:0:0:0:18c")]
    [InlineData("ff01:0:0:0:0:0:0:201")]
    [InlineData("ff01:0:0:0:0:0:0:202")]
    [InlineData("ff01:0:0:0:0:0:0:204")]
    [InlineData("ff01:0:0:0:0:0:0:2c0")]
    [InlineData("ff01:0:0:0:0:0:0:2ff")]
    [InlineData("ff01:0:0:0:0:0:0:300")]
    [InlineData("ff01:0:0:0:0:0:0:400")]
    [InlineData("ff01:0:0:0:0:0:0:4ff")]
    [InlineData("ff01:0:0:0:0:0:0:3486")]
    [InlineData("ff01:0:0:0:0:0:0:bac0")]
    [InlineData("ff01:0:0:0:0:0:1:1000")]
    [InlineData("ff01:0:0:0:0:0:2:0")]
    [InlineData("ff01:0:0:0:0:0:4:ffff")]
    [InlineData("ff01:0:0:0:0:0:b:0")]
    [InlineData("ff01:0:0:0:0:0:b:ffff")]
    [InlineData("ff01:0:0:0:0:db8::")]
    [InlineData("ff01:0:0:0:0:0:ee10:0")]
    [InlineData("ff01:0:0:0:0:0:ee10:1f")]

    // Link-Local Scope Multicast Addresses
    [InlineData("ff02:0:0:0:0:0:0:1")]
    [InlineData("ff02:0:0:0:0:0:0:2")]
    [InlineData("ff02:0:0:0:0:0:0:3")]
    [InlineData("ff02:0:0:0:0:0:0:4")]
    [InlineData("ff02:0:0:0:0:0:0:5")]
    [InlineData("ff02:0:0:0:0:0:0:6")]
    [InlineData("ff02:0:0:0:0:0:0:7")]
    [InlineData("ff02:0:0:0:0:0:0:8")]
    [InlineData("ff02:0:0:0:0:0:0:9")]
    [InlineData("ff02:0:0:0:0:0:0:a")]
    [InlineData("ff02:0:0:0:0:0:0:b")]
    [InlineData("ff02:0:0:0:0:0:0:c")]
    [InlineData("ff02:0:0:0:0:0:0:d")]
    [InlineData("ff02:0:0:0:0:0:0:e")]
    [InlineData("ff02:0:0:0:0:0:0:f")]
    [InlineData("ff02:0:0:0:0:0:0:10")]
    [InlineData("ff02:0:0:0:0:0:0:11")]
    [InlineData("ff02:0:0:0:0:0:0:12")]
    [InlineData("ff02:0:0:0:0:0:0:13")]
    [InlineData("ff02:0:0:0:0:0:0:14")]
    [InlineData("ff02:0:0:0:0:0:0:16")]
    [InlineData("ff02:0:0:0:0:0:0:1a")]
    [InlineData("ff02:0:0:0:0:0:0:6a")]
    [InlineData("ff02:0:0:0:0:0:0:6b")]
    [InlineData("ff02:0:0:0:0:0:0:6c")]
    [InlineData("ff02:0:0:0:0:0:0:6d")]
    [InlineData("ff02:0:0:0:0:0:0:6e")]
    [InlineData("ff02:0:0:0:0:0:0:6f")]
    [InlineData("ff02:0:0:0:0:0:0:fa")]
    [InlineData("ff02:0:0:0:0:0:0:fb")]
    [InlineData("ff02:0:0:0:0:0:0:fc")]
    [InlineData("ff02:0:0:0:0:0:0:fd")]
    [InlineData("ff02:0:0:0:0:0:0:100")]
    [InlineData("ff02:0:0:0:0:0:0:178")]
    [InlineData("ff02:0:0:0:0:0:0:181")]
    [InlineData("ff02:0:0:0:0:0:0:184")]
    [InlineData("ff02:0:0:0:0:0:0:18c")]
    [InlineData("ff02:0:0:0:0:0:0:201")]
    [InlineData("ff02:0:0:0:0:0:0:204")]
    [InlineData("ff02:0:0:0:0:0:0:2c0")]
    [InlineData("ff02:0:0:0:0:0:0:300")]
    [InlineData("ff02:0:0:0:0:0:0:400")]
    [InlineData("ff02:0:0:0:0:0:0:4ff")]
    [InlineData("ff02:0:0:0:0:0:0:3486")]
    [InlineData("ff02:0:0:0:0:0:0:a1f7")]
    [InlineData("ff02:0:0:0:0:0:0:bac0")]
    [InlineData("ff02:0:0:0:0:0:1:1")]
    [InlineData("ff02:0:0:0:0:0:1:2")]
    [InlineData("ff02:0:0:0:0:0:1:3")]
    [InlineData("ff02:0:0:0:0:0:1:4")]
    [InlineData("ff02:0:0:0:0:0:1:5")]
    [InlineData("ff02:0:0:0:0:0:1:6")]
    [InlineData("ff02:0:0:0:0:0:1:7")]
    [InlineData("ff02:0:0:0:0:0:1:1000")]
    [InlineData("ff02:0:0:0:0:0:2:0")]
    [InlineData("ff02:0:0:0:0:0:4:ffff")]
    [InlineData("ff02:0:0:0:0:0:b:0")]
    [InlineData("ff02:0:0:0:0:0:b:ffff")]
    [InlineData("ff02:0:0:0:0:1:ff00::")]
    [InlineData("ff02:0:0:0:0:2:ff00::")]
    [InlineData("ff02:0:0:0:0:db8::")]
    [InlineData("ff02:0:0:0:0:0:ee10:0")]
    [InlineData("ff02:0:0:0:0:0:ee10:1f")]

    // Site-Local Scope Multicast Addresses
    [InlineData("ff05:0:0:0:0:0:0:2")]
    [InlineData("ff05:0:0:0:0:0:0:c")]
    [InlineData("ff05:0:0:0:0:0:0:fa")]
    [InlineData("ff05:0:0:0:0:0:0:fb")]
    [InlineData("ff05:0:0:0:0:0:0:fc")]
    [InlineData("ff05:0:0:0:0:0:0:fd")]
    [InlineData("ff05:0:0:0:0:0:0:100")]
    [InlineData("ff05:0:0:0:0:0:0:178")]
    [InlineData("ff05:0:0:0:0:0:0:181")]
    [InlineData("ff05:0:0:0:0:0:0:184")]
    [InlineData("ff05:0:0:0:0:0:0:18c")]
    [InlineData("ff05:0:0:0:0:0:0:201")]
    [InlineData("ff05:0:0:0:0:0:0:202")]
    [InlineData("ff05:0:0:0:0:0:0:204")]
    [InlineData("ff05:0:0:0:0:0:0:206")]
    [InlineData("ff05:0:0:0:0:0:0:2c0")]
    [InlineData("ff05:0:0:0:0:0:0:300")]
    [InlineData("ff05:0:0:0:0:0:0:400")]
    [InlineData("ff05:0:0:0:0:0:0:4ff")]
    [InlineData("ff05:0:0:0:0:0:0:3486")]
    [InlineData("ff05:0:0:0:0:0:0:bac0")]
    [InlineData("ff05:0:0:0:0:0:1:3")]
    [InlineData("ff05:0:0:0:0:0:1:4")]
    [InlineData("ff05:0:0:0:0:0:1:5")]
    [InlineData("ff05:0:0:0:0:0:1:1000")]
    [InlineData("ff05:0:0:0:0:0:2:0")]
    [InlineData("ff05:0:0:0:0:0:4:ffff")]
    [InlineData("ff05:0:0:0:0:0:b:0")]
    [InlineData("ff05:0:0:0:0:0:b:ffff")]
    [InlineData("ff05:0:0:0:0:db8::")]
    [InlineData("ff05:0:0:0:0:0:ee10:0")]
    [InlineData("ff05:0:0:0:0:0:ee10:1f")]
    public void ReturnsTrueForKnownIpv6MulticastAddresses(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("fe80::1a2b:3cff:fe4d:5e6f")] // Link-local unicast address
    [InlineData("fec0:0000:0000:0000:0000:0000:0000:0001")] // Site-local unicast address
    [InlineData("fe80::1")] // Link-local unicast address
    public void ReturnsTrueForKnownIpv6KnownLocalAddresses(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("64:ff9b::10.0.0.1")]       // NAT64 well-known prefix embedding private IPv4
    [InlineData("64:ff9b::192.168.1.1")]     // NAT64 well-known prefix embedding private IPv4
    [InlineData("64:ff9b::127.0.0.1")]       // NAT64 well-known prefix embedding loopback
    [InlineData("64:ff9b::169.254.169.254")] // NAT64 well-known prefix embedding link-local
    [InlineData("64:ff9b:1::10.0.0.1")]      // NAT64 local-use prefix embedding private IPv4
    public void ReturnsTrueForInternalMappedNat64Addresses(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("64:ff9b::8.8.8.8")]         // NAT64 well-known prefix embedding public IPv4
    public void ReturnsFalseForPublicMappedNat64Addresses(string ipAddressAsString)
    {
        Assert.False(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("64:ff9b:1::8.8.8.8")]       // NAT64 local-use prefix embedding public IPv4
    public void ReturnsTrueForPublicMappedNat64LocalUseAddresses(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Fact]
    public void ThrowsArgumentNullExceptionIfIpAddressIsNull()
    {
        Assert.Throws<ArgumentNullException>(() => Ssrf.IsUnsafeIpAddress(null!));
    }

    [InlineData("127.0.0.1")]
    [InlineData("127.0.0.2")]
    [InlineData("127.255.255.254")]
    [InlineData("::1")]
    [Theory]
    public void ReturnsFalseForLoopbackIfAllowLoopbackIsTrue(string ipAddressAsString)
    {
        Assert.False(Ssrf.IsUnsafeIpAddress(
            ipAddress: IPAddress.Parse(ipAddressAsString),
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowLoopback: true));
    }


    [Fact]
    public void ReturnsFalseForDefaultUnsafeAddressIfItIsInTheSafeIpAddressesCollection()
    {
        Assert.False(Ssrf.IsUnsafeIpAddress(
            ipAddress: IPAddress.Parse("127.0.0.1"),
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            safeIPNetworks: null,
            safeIPAddresses: [IPAddress.Parse("127.0.0.1")],
            allowLoopback: false));
    }

    [Fact]
    public void ReturnsFalseForDefaultUnsafeAddressIfItIsWithinANetworkSpecifiedInSafeNetworksCollection()
    {
        Assert.False(Ssrf.IsUnsafeIpAddress(
            ipAddress: IPAddress.Parse("127.0.0.1"),
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            safeIPNetworks: [IPNetwork.Parse("127.0.0.0/8")],
            safeIPAddresses: null,
            allowLoopback: false));
    }

    // The following tests match the naming of blocks by the Azure Anti-SSRF team
    // in their code, https://github.com/microsoft/AntiSSRF.
    // While it does duplicate some of the tests above, it also makes for
    // an easier comparison to ensure that all of the same blocks are included in this implementation.

    [Fact]
    public void ReturnsTrueForAzureWireServerIpAddresses()
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse("168.63.129.16")));
    }

    [Theory]
    [InlineData("192.0.0.11")]
    [InlineData("2001:0001:0000:0000:0000:0000:0000:0001")]
    public void ReturnsTrueForNATAnyCast(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("192.52.193.1")]
    [InlineData("192.52.193.254")]
    [InlineData("2001:0003:0000:0000:0000:0000:0000:0001")]
    [InlineData("2001:0003:ffff:ffff:ffff:ffff:ffff:fffe")]
    public void ReturnsTrueForAmt(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("192.31.196.1")]
    [InlineData("192.31.196.254")]
    [InlineData("192.175.48.1")]
    [InlineData("192.175.48.254")]
    [InlineData("2001:4:112::1")]
    [InlineData("2001:4:112::ff")]
    [InlineData("2620:4f:8000::1")]
    [InlineData("2620:4f:8000::ff")]
    public void ReturnsTrueForAS112(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("192.88.99.1")]
    [InlineData("192.88.99.254")]
    [InlineData("2001:10::1")]
    [InlineData("2001:10::ff")]
    public void ReturnsTrueForDeprecatedIpAddresses(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("2001:30::1")]
    [InlineData("2001:30::ff")]
    public void ReturnsTrueForDroneRemoteIDProtocolEntityTagsPrefix(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("100::1")]
    [InlineData("100::ff")]
    public void ReturnsTrueForDiscardOnly(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Fact]
    public void ReturnsTrueForAnyCast()
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse("2001:0001:0000:0000:0000:0000:0000:0003")));
    }

    [Theory]
    [InlineData("192.0.2.1")]
    [InlineData("192.0.2.254")]
    [InlineData("198.51.100.1")]
    [InlineData("198.51.100.254")]
    [InlineData("203.0.113.1")]
    [InlineData("203.0.113.254")]
    [InlineData("2001:db8::1")]
    [InlineData("2001:db8::ff")]
    [InlineData("3fff::1")]
    [InlineData("3fff::ff")]
    public void ReturnsTrueForDocumentationIPAddresses(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("192.0.0.8")]
    [InlineData("100:0:0:1::1")]
    [InlineData("0100:0000:0000:0001:ffff:ffff:ffff:ffff")]
    public void ReturnsTrueForDummyAddresses(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("192.0.0.1")]
    [InlineData("192.0.0.254")]
    [InlineData("2001:0000:0000:0000:0000:0000:0000:0000")]
    [InlineData("2001:01ff:ffff:ffff:ffff:ffff:ffff:ffff")]
    public void ReturnsTrueForProtocolAssignments(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("192.0.0.1")]
    [InlineData("192.0.0.254")]
    [InlineData("2001:0000:0000:0000:0000:0000:0000:0001")]
    [InlineData("2001:01ff:ffff:ffff:ffff:ffff:ffff:fffe")]
    public void ReturnsTrueForIETFProtocolAssignmentAddresses(string ipaddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipaddressAsString)));
    }

    [Fact]
    public void ReturnsTrueForInstanceMetadataService()
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse("169.254.169.254")));
    }

    [Theory]
    [InlineData("0064:ff9b:0000:0000:0000:0000:0000:0001")]
    [InlineData("0064:ff9b:0000:0000:0000:0000:ffff:ffff")]
    [InlineData("0064:ff9b:0001:0000:0000:0000:0000:0000")]
    [InlineData("0064:ff9b:0001:ffff:ffff:ffff:ffff:ffff")]
    public void ReturnsTrueForIPv4IPv6Translated(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("192.0.0.1")]
    [InlineData("192.0.0.6")]
    public void ReturnsTrueForIpv4ContinuityPrefix(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Fact]
    public void ReturnsTrueForLimitedBroadcastAddresses()
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse("255.255.255.255")));
    }

    [Theory]
    [InlineData("169.254.0.1")]
    [InlineData("169.254.255.254")]
    [InlineData("fe80:0000:0000:0000:0000:0000:0000:0000")]
    [InlineData("febf:ffff:ffff:ffff:ffff:ffff:ffff:fffe")]
    public void ReturnsTrueForLinkLocal(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.255.255.254")]
    [InlineData("0000:0000:0000:0000:0000:0000:0000:0001")]
    public void ReturnsTrueForLoopback(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("224.0.0.1")]
    [InlineData("239.255.255.254")]
    [InlineData("ff00:0000:0000:0000:0000:0000:0000:0001")]
    [InlineData("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")]
    public void ReturnsTrueForMulticast(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("192.0.0.170")]
    [InlineData("192.0.0.171")]
    public void ReturnsTrueForNat64Dns64Discovery(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("2001:0020:0000:0000:0000:0000:0000:0001")]
    [InlineData("2001:002f:ffff:ffff:ffff:ffff:ffff:fffe")]
    public void ReturnsTrueForORCHIDv2Addresses(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("192.0.0.9")]
    [InlineData("2001:1::1")]
    public void ReturnsTrueForPCPAnycast(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("10.0.0.1")]
    [InlineData("10.255.255.254")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.254")]
    [InlineData("192.168.0.1")]
    [InlineData("192.168.255.254")]
    public void ReturnsTrueForPrivateUseAddresses(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("240.0.0.1")]
    [InlineData("255.255.255.254")]
    public void ReturnsTrueForReservedAddresses(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("100.64.0.1")]
    [InlineData("100.127.255.254")]
    public void ReturnsTrueForSharedAddressSpace(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("fec0:0000:0000:0000:0000:0000:0000:0001")]
    [InlineData("feff:ffff:ffff:ffff:ffff:ffff:ffff:fffe")]
    public void ReturnsTrueForSiteLocal(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("192.88.99.2")]
    public void ReturnsTrueForSix4aaRelayAnycast(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("2002:0000:0000:0000:0000:0000:0000:0001")]
    [InlineData("2002:ffff:ffff:ffff:ffff:ffff:ffff:fffe")]
    public void ReturnsTrueForSixtoFour(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("5f00:0000:0000:0000:0000:0000:0000:0001")]
    [InlineData("5f00:ffff:ffff:ffff:ffff:ffff:ffff:fffe")]
    public void ReturnsTrueForSegmentRoutingSIDs(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("2001:0000:0000:0000:0000:0000:0000:0001")]
    [InlineData("2001:0000:ffff:ffff:ffff:ffff:ffff:ffff")]
    public void ReturnsTrueForTeredoAddresses(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("fc00:0000:0000:0000:0000:0000:0000:0001")]
    [InlineData("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")]
    public void ReturnsTrueForUniqueLocalUnicast(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("0.0.0.1")]
    [InlineData("0.255.255.254")]
    // Note ::/128 from the AntiSSRF list is not an actual IP address, but rather a network containing only the unspecified IPv6 address.
    public void ReturnsTrueForThisHostUnspecifiedNetwork(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }
}
