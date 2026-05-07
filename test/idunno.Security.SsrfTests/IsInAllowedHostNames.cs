// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using static Microsoft.ApplicationInsights.MetricDimensionNames.TelemetryContext;

namespace idunno.Security.SsrfTests;

public class IsInAllowedHostNames
{
    [Fact]
    public void ReturnsTrueWhenHostIsInAllowedHostNames()
    {
        var allowedHostNames = new List<string> { "example.com", "test.com" };

        Assert.True(Ssrf.IsInAllowedHostnames(new Uri("https://example.com"), allowedHostNames));
    }

    [Fact]
    public void ReturnsFalseWhenHostIsNotInAllowedHostNames()
    {
        var allowedHostNames = new List<string> { "example.com", "test.com" };

        Assert.False(Ssrf.IsInAllowedHostnames(new Uri("https://example.org"), allowedHostNames));
    }

    [Fact]
    public void ReturnsFalseWhenHostWhenAllowedHostNamesIsEmpty()
    {
        var allowedHostNames = new List<string>();

        Assert.False(Ssrf.IsInAllowedHostnames(new Uri("https://example.org"), allowedHostNames));
    }

    [Fact]
    public void ReturnsFalseWhenHostWhenAllowedHostNamesIsNull()
    {
        Assert.False(Ssrf.IsInAllowedHostnames(new Uri("https://example.org"), null));
    }

    [Fact]
    public void ReturnsFalseWhenHostIsInAllowedHostNamesButHostIsNotAnExactMatch()
    {
        var allowedHostNames = new List<string> { "example.com", "test.com" };

        Assert.False(Ssrf.IsInAllowedHostnames(new Uri("https://www.example.com"), allowedHostNames));
    }

    [Fact]
    public void ReturnsTrueWhenHostIsASubdomainOfAWildcardAllowedHostSuffix()
    {
        var allowedHostNames = new List<string> { "*.example.com", "test.com" };

        Assert.True(Ssrf.IsInAllowedHostnames(new Uri("https://www.example.com"), allowedHostNames));
    }

    [Fact]
    public void ReturnsTrueWhenHostIsASubdomainOfASubdomainOfAWildcardAllowedHostSuffix()
    {
        var allowedHostNames = new List<string> { "*.example.com", "test.com" };

        Assert.True(Ssrf.IsInAllowedHostnames(new Uri("https://dev.www.example.com"), allowedHostNames));
    }

    [Fact]
    public void ReturnsTrueWhenHostIsCoveredByEitherAWildcardOrSpecificAllowedName()
    {
        var allowedHostNames = new List<string> { "*.example.com", "example.com" };

        Assert.True(Ssrf.IsInAllowedHostnames(new Uri("https://example.com"), allowedHostNames));
        Assert.True(Ssrf.IsInAllowedHostnames(new Uri("https://www.example.com"), allowedHostNames));
        Assert.True(Ssrf.IsInAllowedHostnames(new Uri("https://dev.www.example.com"), allowedHostNames));
    }

    [Fact]
    public void ReturnsTrueWhenHostIsCoveredByEitherAWildcardOrSpecificAllowedNameButFalseIfTheHostIsNotInTheWildcard()
    {
        var allowedHostNames = new List<string> { "*.www.example.com", "example.com" };

        Assert.True(Ssrf.IsInAllowedHostnames(new Uri("https://example.com"), allowedHostNames));
        Assert.False(Ssrf.IsInAllowedHostnames(new Uri("https://www.example.com"), allowedHostNames));
        Assert.True(Ssrf.IsInAllowedHostnames(new Uri("https://dev.www.example.com"), allowedHostNames));
    }

    [Fact]
    public void ReturnsFalseWhenHostHasATrailingDotAndNonTrailingHostIsInAllowedHostNames()
    {
        // .NET's Uri.Host historically can preserve a trailing dot (example.com.), in which case attacker.example.com. would
        // NOT match *.example.com.This is fail - closed(good), this test locks the behavior in.

        var allowedHostNames = new List<string> { "example.com", "test.com" };
        Assert.False(Ssrf.IsInAllowedHostnames(new Uri("https://example.com."), allowedHostNames));
    }
}
