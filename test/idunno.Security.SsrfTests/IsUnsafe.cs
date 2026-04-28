// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;

namespace idunno.Security.SsrfTests;

public class IsUnsafe
{
    [Fact]
    public async Task ThrowsArgumentNullExceptionIfUriIsNull()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await Ssrf.IsUnsafe(null!, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("https://example.com")]
    [InlineData("https://www.example.com")]
    [InlineData("https://104.18.26.120")]
    [InlineData("https://104.18.27.120")]
    [InlineData("https://[2620:1ec:bdf::69]")]
    [InlineData("https://[2620:1ec:46::69]")]
    [InlineData("wss://example.com")]
    [InlineData("wss://www.example.com")]
    [InlineData("wss://104.18.26.120")]
    [InlineData("wss://104.18.27.120")]
    [InlineData("wss://[2620:1ec:bdf::69]")]
    [InlineData("wss://[2620:1ec:46::69]")]
    public async Task ReturnsFalseForKnownGoodUris(string uriAsString)
    {
        Uri uri = new(uriAsString);

        Assert.False(await Ssrf.IsUnsafe(
            uri,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("http://example.com")]
    [InlineData("http://www.example.com")]
    [InlineData("http://104.18.26.120")]
    [InlineData("http://104.18.27.120")]
    [InlineData("http://[2620:1ec:bdf::69]")]
    [InlineData("http://[2620:1ec:46::69]")]
    [InlineData("ws://example.com")]
    [InlineData("ws://www.example.com")]
    [InlineData("ws://104.18.26.120")]
    [InlineData("ws://104.18.27.120")]
    [InlineData("ws://[2620:1ec:bdf::69]")]
    [InlineData("ws://[2620:1ec:46::69]")]
    public async Task ReturnsTrueForNonSecureUris(string uriAsString)
    {
        Uri uri = new(uriAsString);

        Assert.True(await Ssrf.IsUnsafe(
            uri,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(@"\\unc\documents")]
    [InlineData(@"\\unc.example\documents")]
    public async Task ReturnsTrueForUncUris(string uriAsString)
    {
        Uri uri = new(uriAsString);
        Assert.True(await Ssrf.IsUnsafe(
            uri,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("example.com")]
    [InlineData("www.example.com")]
    [InlineData("104.18.26.120")]
    [InlineData("104.18.27.120")]
    [InlineData("[2620:1ec:bdf::69]")]
    [InlineData("[2620:1ec:46::69]")]
    public async Task ReturnsFalseForGoodUrisIfTheyMatchTheAllowedSchemes(string host)
    {
        Assert.False(await Ssrf.IsUnsafe(
            new Uri($"https://{host}/"),
            allowedSchemes: ["https", "http", "wss", "ws"],
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.False(await Ssrf.IsUnsafe(
            new Uri($"wss://{host}/"),
            allowedSchemes: ["https", "http", "wss", "ws"],
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.False(await Ssrf.IsUnsafe(
            new Uri($"http://{host}/"),
            allowedSchemes: ["https", "http", "wss", "ws"],
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.False(await Ssrf.IsUnsafe(
            new Uri($"ws://{host}/"),
            allowedSchemes: ["https", "http", "wss", "ws"],
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("/relative/path")]
    [InlineData("/another/path")]
    public async Task ReturnsTrueForRelativeUris(string relativeUri)
    {
        Assert.True(await Ssrf.IsUnsafe(
            new Uri(relativeUri, UriKind.Relative),
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.True(await Ssrf.IsUnsafe(
            new Uri(relativeUri, UriKind.Relative),
            allowedSchemes: ["https", "http", "wss", "ws"],
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("104.18.26.120")]
    [InlineData("104.18.27.120")]
    [InlineData("[2620:1ec:bdf::69]")]
    [InlineData("[2620:1ec:46::69]")]
    public async Task ReturnsFalseForGoodIpAddressesOnSecureProtocols(string ipAddressAsString)
    {
        Assert.False(await Ssrf.IsUnsafe(
            new Uri($"https://{ipAddressAsString}"),
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("104.18.26.120")]
    [InlineData("104.18.27.120")]
    [InlineData("[2620:1ec:bdf::69]")]
    [InlineData("[2620:1ec:46::69]")]
    public async Task ReturnsTrueForGoodIpAddressesOnSecureProtocolsIfTheyAreInTheSpecifiedAdditionalUnsafeNetworks(string ipAddressAsString)
    {
        Assert.True(await Ssrf.IsUnsafe(
            new Uri($"https://{ipAddressAsString}"),
            additionalUnsafeIPNetworks:
            [
                IPNetwork.Parse("104.16.0.0/12"),
                IPNetwork.Parse("2620:1ec::/36"),
            ],
            additionalUnsafeIPAddresses: null,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("104.18.26.120")]
    [InlineData("104.18.27.120")]
    [InlineData("[2620:1ec:bdf::69]")]
    [InlineData("[2620:1ec:46::69]")]
    public async Task ReturnsTrueForGoodIpAddressesIfTheyAreInTheSpecifiedAdditionalUnsafeIpAddresses(string ipAddressAsString)
    {
        Assert.True(await Ssrf.IsUnsafe(
            new Uri($"https://{ipAddressAsString}"),
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses:
            [
                IPAddress.Parse("104.18.26.120"),
                IPAddress.Parse("104.18.27.120"),
                IPAddress.Parse("2620:1ec:bdf::69"),
                IPAddress.Parse("2620:1ec:46::69"),
            ],
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("104.18.26.120")]
    [InlineData("104.18.27.120")]
    [InlineData("[2620:1ec:bdf::69]")]
    [InlineData("[2620:1ec:46::69]")]
    public async Task ReturnsTrueForGoodIpAddressesIfTheyAreInTheSpecifiedAdditionalUnsafeIpNetworksAndOrIpAddresses(string ipAddressAsString)
    {
        Assert.True(await Ssrf.IsUnsafe(
            new Uri($"https://{ipAddressAsString}"),
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
            ],
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("::ffff:10.0.0.1")]
    [InlineData("::ffff:172.16.0.1")]
    [InlineData("::ffff:192.168.0.1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("::ffff:169.254.169.254")]
    public async Task ReturnsTrueForIPv4MappedIPv6AddressesInBuiltInUnsafeRanges(string ipv4MappedIpv6)
    {
        Assert.True(await Ssrf.IsUnsafe(
            new Uri($"https://[{ipv4MappedIpv6}]"),
            cancellationToken: TestContext.Current.CancellationToken));
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
    [InlineData("[fe80::1]")]
    [InlineData("[fc00::1]")]
    [InlineData("[fec0::1]")]
    [InlineData("[2001::1]")]
    [InlineData("[2001:db8::1]")]
    [InlineData("[3fff::42]")]
    public async Task ReturnsTrueForIpAddressesInThePredefinedNetworks(string ipAddressAsString)
    {
        Assert.True(await Ssrf.IsUnsafe(
            new Uri($"https://{ipAddressAsString}"),
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("127.0.0.0")]
    [InlineData("127.0.0.1")]
    [InlineData("[::1]")]
    public async Task ReturnsTrueForLoopbackAddresses(string ipAddressAsString)
    {
        Assert.True(await Ssrf.IsUnsafe(
            new Uri($"https://{ipAddressAsString}"),
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("0.0.0.1")]
    [InlineData("[0:0:0:0:0:0:0:0]")]
    public async Task ReturnsTrueForUnspecifiedAddresses(string ipAddressAsString)
    {
        Assert.True(await Ssrf.IsUnsafe(
            new Uri($"https://{ipAddressAsString}"),
            cancellationToken: TestContext.Current.CancellationToken));
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
    public async Task ReturnsTrueForKnownIpv6MulticastAddresses(string ipAddressAsString)
    {
        Assert.True(await Ssrf.IsUnsafe(
            new Uri($"https://[{ipAddressAsString}]"),
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("fe80::1a2b:3cff:fe4d:5e6f")] // Link-local unicast address
    [InlineData("fec0:0000:0000:0000:0000:0000:0000:0001")] // Site-local unicast address
    [InlineData("fe80::1")] // Link-local unicast address
    public async Task ReturnsTrueForKnownIpv6KnownLocalAddresses(string ipAddressAsString)
    {
        Assert.True(await Ssrf.IsUnsafe(
            new Uri($"https://[{ipAddressAsString}]"),
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("64:ff9b::10.0.0.1")]       // NAT64 well-known prefix embedding private IPv4
    [InlineData("64:ff9b::192.168.1.1")]     // NAT64 well-known prefix embedding private IPv4
    [InlineData("64:ff9b::127.0.0.1")]       // NAT64 well-known prefix embedding loopback
    [InlineData("64:ff9b::169.254.169.254")] // NAT64 well-known prefix embedding link-local
    [InlineData("64:ff9b:1::10.0.0.1")]      // NAT64 local-use prefix embedding private IPv4
    public async Task ReturnsTrueForNat64Addresses(string ipAddressAsString)
    {
        Assert.True(await Ssrf.IsUnsafe(
            new Uri($"https://[{ipAddressAsString}]"),
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("64:ff9b::8.8.8.8")]         // NAT64 well-known prefix embedding public IPv4
    public async Task ReturnsFalseForPublicNat64Addresses(string ipAddressAsString)
    {
        Assert.False(await Ssrf.IsUnsafe(
            new Uri($"https://[{ipAddressAsString}]"),
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("64:ff9b:1::8.8.8.8")]       // NAT64 local-use prefix embedding public IPv4
    public async Task ReturnsTrueForPublicButLocalUseNat64Addresses(string ipAddressAsString)
    {
        Assert.True(await Ssrf.IsUnsafe(
            new Uri($"https://[{ipAddressAsString}]"),
            cancellationToken: TestContext.Current.CancellationToken));
    }


    [Fact]
    public async Task ReturnsTrueWhenDnsResolvesToEmptyAddressList()
    {
        static Task<IPHostEntry> emptyResolver(string host, CancellationToken cancellationToken)
        {
            return Task.FromResult(new IPHostEntry { AddressList = [] });
        }

        Assert.True(await Ssrf.InternalIsUnsafe(
            uri: new Uri("https://example.com"),
            allowLoopback: false,
            allowedSchemes: null,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: null,
            safeIPNetworks: null,
            safeIPAddresses: null,
            hostEntryResolver: emptyResolver,
            metrics: null,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("127.0.0.1")]
    [InlineData("[::1]")]
    public async Task ReturnsFalseForLocalhostAndLoopbackAddressesIfAllowLoopbackIsTrue(string host)
    {
        Assert.False(await Ssrf.InternalIsUnsafe(
            new Uri($"https://{host}/"),
            allowLoopback: true,
            allowedSchemes: null,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: null,
            safeIPNetworks: null,
            safeIPAddresses: null,
            metrics: null,
            hostEntryResolver: null,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("127.0.0.1")]
    [InlineData("[::1]")]
    public async Task ReturnsTrueForLocalhostAndLoopbackAddressesIfAllowLoopbackIsTrueAndAllowedSchemesIsNotSet(string host)
    {
        Assert.True(await Ssrf.InternalIsUnsafe(
            new Uri($"http://{host}/"),
            allowLoopback: true,
            allowedSchemes: null,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: null,
            safeIPNetworks: null,
            safeIPAddresses: null,
            metrics: null,
            hostEntryResolver: null,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ReturnsFalseIfTheUriIsInASafeListedDomainAndHasAnSafeProtocol()
    {
        static Task<IPHostEntry> hostEntryResolver(string host, CancellationToken cancellationToken)
        {
            return Task.FromResult(new IPHostEntry { AddressList =
                [
                    IPAddress.Parse("127.0.0.1"),
                    IPAddress.Parse("::1")
                ] });
        }

        Assert.False(await Ssrf.InternalIsUnsafe(
            new Uri("https://api.example.localhost/"),
            allowLoopback: false,
            allowedSchemes: null,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: ["*.example.localhost"],
            safeIPNetworks: null,
            safeIPAddresses: null,
            metrics: null,
            hostEntryResolver: hostEntryResolver,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ReturnsFalseForDefaultUnsafeAddressIfItIsInTheSafeIpAddressesCollection()
    {
        Assert.False(await Ssrf.IsUnsafe(
            new Uri("https://loopback.ssrf.fail"),
            allowLoopback: false,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: null,
            safeIPAddresses:
            [
                IPAddress.Parse("127.0.0.1"),
                IPAddress.Parse("::1")
            ],
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ReturnsFalseForDefaultUnsafeAddressIfItIsWithinANetworkSpecifiedInSafeNetworksCollection()
    {
        Assert.False(await Ssrf.IsUnsafe(
            new Uri("https://loopback.ssrf.fail"),
            allowLoopback: false,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: null,
            safeIPNetworks:
            [
                IPNetwork.Parse("127.0.0.0/8"),
                IPNetwork.Parse("::1/128")
            ],
            safeIPAddresses: null,
            cancellationToken: TestContext.Current.CancellationToken));
    }
}
