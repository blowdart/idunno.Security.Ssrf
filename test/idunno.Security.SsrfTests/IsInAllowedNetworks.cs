// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;

namespace idunno.Security.SsrfTests;

public class IsInAllowedNetworks
{
    [Fact]
    public void ReturnsTrueWhenIpV4HostIsInAllowedNetworks()
    {
        var allowedNetworks = new IPNetwork[]
        {
            IPNetwork.Parse("127.0.0.0/8")
        };

        Assert.True(Ssrf.IsInAllowedNetworks(IPAddress.Parse("127.0.0.1"), allowedNetworks));
    }

    [Fact]
    public void ReturnsFalseWhenIpV4HostIsNotInAllowedNetworks()
    {
        var allowedNetworks = new IPNetwork[]
        {
            IPNetwork.Parse("1.0.0.0/8")
        };

        Assert.False(Ssrf.IsInAllowedNetworks(IPAddress.Parse("127.0.0.1"), allowedNetworks));
    }

    [Fact]
    public void ReturnsFalseWhenIpV4HostButAllowedNetworksIsNull()
    {
        Assert.False(Ssrf.IsInAllowedNetworks(IPAddress.Parse("127.0.0.1"), null));
    }

    [Fact]
    public void ReturnsFalseWhenIpV4HostButAllowedNetworksIsEmpty()
    {
        Assert.False(Ssrf.IsInAllowedNetworks(IPAddress.Parse("127.0.0.1"), []));
    }

    [Fact]
    public void ReturnsTrueWhenIpV6HostIsInAllowedNetworks()
    {
        var allowedNetworks = new IPNetwork[]
        {
            IPNetwork.Parse("::1/128")
        };

        Assert.True(Ssrf.IsInAllowedNetworks(IPAddress.Parse("::1"), allowedNetworks));
    }

    [Fact]
    public void ReturnsFalseWhenIpV6HostIsNotInAllowedNetworks()
    {
        var allowedNetworks = new IPNetwork[]
        {
            IPNetwork.Parse("2606:4700::/32")
        };

        Assert.False(Ssrf.IsInAllowedNetworks(IPAddress.Parse("::1"), allowedNetworks));
        Assert.False(Ssrf.IsInAllowedNetworks(IPAddress.Parse("2606:4701::1"), allowedNetworks));
    }

    [Fact]
    public void ReturnsFalseWhenIpV6HostButAllowedNetworksIsNull()
    {
        Assert.False(Ssrf.IsInAllowedNetworks(IPAddress.Parse("::1"), null));
    }

    [Fact]
    public void ReturnsFalseWhenIpV6HostButAllowedNetworksIsEmpty()
    {
        Assert.False(Ssrf.IsInAllowedNetworks(IPAddress.Parse("::1"), []));
    }

    [Fact]
    public void ReturnsFalseWhenIpV4HostIsInMixedAllowedNetworks()
    {
        var allowedNetworks = new IPNetwork[]
        {
            IPNetwork.Parse("127.0.0.1/32"),
            IPNetwork.Parse("::1/128")
        };

        Assert.False(Ssrf.IsInAllowedNetworks(IPAddress.Parse("1.1.1.1"), allowedNetworks));
    }

    [Fact]
    public void ReturnsFalseWhenIp64HostIsInMixedAllowedNetworks()
    {
        var allowedNetworks = new IPNetwork[]
        {
            IPNetwork.Parse("127.0.0.1/32"),
            IPNetwork.Parse("::1/128")
        };

        Assert.False(Ssrf.IsInAllowedNetworks(IPAddress.Parse("::2"), allowedNetworks));
    }

}
