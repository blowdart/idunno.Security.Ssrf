// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;

namespace idunno.Security.SsrfTests;

public class IsInAllowedIpAddresses
{
    [Fact]
    public void ReturnsTrueWhenIpV4HostIsInAllowedIpAddresses()
    {
        var allowedIpAddresses = new IPAddress[]
        {
            IPAddress.Parse("10.0.0.1"),
            IPAddress.Parse("10.0.0.2")
        };

        Assert.True(Ssrf.IsInAllowedIpAddresses(IPAddress.Parse("10.0.0.1"), allowedIpAddresses));
    }

    [Fact]
    public void ReturnsFalseWhenIpV4HostIsNotInAllowedIpAddresses()
    {
        var allowedIpAddresses = new IPAddress[]
        {
            IPAddress.Parse("10.0.0.1"),
            IPAddress.Parse("10.0.0.2")
        };

        Assert.False(Ssrf.IsInAllowedIpAddresses(IPAddress.Parse("10.0.0.3"), allowedIpAddresses));
    }

    [Fact]
    public void ReturnsFalseWhenIpV4HostIsPassedButAllowedIpAddressesIsEmpty()
    {
        Assert.False(Ssrf.IsInAllowedIpAddresses(IPAddress.Parse("10.0.0.3"), []));
    }

    [Fact]
    public void ReturnsFalseWhenIpV4HostIsPassedButAllowedIpAddressesIsNull()
    {
        Assert.False(Ssrf.IsInAllowedIpAddresses(IPAddress.Parse("10.0.0.3"), null));
    }


    [Fact]
    public void ReturnsTrueWhenIpV6HostIsInAllowedIpAddresses()
    {
        var allowedIpAddresses = new IPAddress[]
        {
            IPAddress.Parse("::1"),
            IPAddress.Parse("::2")
        };

        Assert.True(Ssrf.IsInAllowedIpAddresses(IPAddress.Parse("::2"), allowedIpAddresses));
    }

    [Fact]
    public void ReturnsFalseWhenIpV6HostIsNotInAllowedIpAddresses()
    {
        var allowedIpAddresses = new IPAddress[]
        {
            IPAddress.Parse("::1"),
            IPAddress.Parse("::2")
        };

        Assert.False(Ssrf.IsInAllowedIpAddresses(IPAddress.Parse("::3"), allowedIpAddresses));
    }

    [Fact]
    public void ReturnsFalseWhenIpV6HostIsPassedButAllowedIpAddressesIsEmpty()
    {
        Assert.False(Ssrf.IsInAllowedIpAddresses(IPAddress.Parse("::3"), []));
    }

    [Fact]
    public void ReturnsFalseWhenIpV6HostIsPassedButAllowedIpAddressesIsNull()
    {
        Assert.False(Ssrf.IsInAllowedIpAddresses(IPAddress.Parse("::3"), null));
    }

    [Fact]
    public void ReturnsTrueWhenIpV4HostIsInAllowedMixedAllowedIpAddresses()
    {
        var allowedIpAddresses = new IPAddress[]
        {
            IPAddress.Parse("10.0.0.1"),
            IPAddress.Parse("::1")
        };

        Assert.True(Ssrf.IsInAllowedIpAddresses(IPAddress.Parse("10.0.0.1"), allowedIpAddresses));
    }

    [Fact]
    public void ReturnsTrueWhenIpV6HostIsInAllowedMixedAllowedIpAddresses()
    {
        var allowedIpAddresses = new IPAddress[]
        {
            IPAddress.Parse("10.0.0.1"),
            IPAddress.Parse("::1")
        };

        Assert.True(Ssrf.IsInAllowedIpAddresses(IPAddress.Parse("::1"), allowedIpAddresses));
    }

    [Fact]
    public void ReturnsFalseWhenIpV4HostIsNotInAllowedMixedAllowedIpAddresses()
    {
        var allowedIpAddresses = new IPAddress[]
        {
            IPAddress.Parse("10.0.0.1"),
            IPAddress.Parse("::1")
        };

        Assert.False(Ssrf.IsInAllowedIpAddresses(IPAddress.Parse("10.0.0.2"), allowedIpAddresses));
    }

    [Fact]
    public void ReturnsFalseWhenIpV6HostIsNotInAllowedMixedAllowedIpAddresses()
    {
        var allowedIpAddresses = new IPAddress[]
        {
            IPAddress.Parse("10.0.0.1"),
            IPAddress.Parse("::1")
        };

        Assert.False(Ssrf.IsInAllowedIpAddresses(IPAddress.Parse("::2"), allowedIpAddresses));
    }

}
