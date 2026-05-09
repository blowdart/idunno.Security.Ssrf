// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

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

    [Theory]
    [InlineData("https://127.0.0.1/", "127.0.0.1")]
    [InlineData("https://10.0.0.1/", "10.0.0.1")]
    [InlineData("https://169.254.169.254/", "169.254.169.254")]
    [InlineData("https://[::1]/", "::1")]
    [InlineData("https://[2001:db8::1]/", "2001:db8::1")]
    public void ReturnsFalseWhenUriHostIsAnIPLiteralEvenIfPresentInTheList(string uri, string entry)
    {
        // AllowedHostnames is a hostname allow-list, not an IP allow-list. IP literals must
        // be controlled via SafeIPAddresses / SafeIPNetworks.
        Assert.False(Ssrf.IsInAllowedHostnames(new Uri(uri), [entry]));
    }

    [Theory]
    [InlineData("https://169.254.169.254/", "*.169.254")]
    [InlineData("https://10.0.0.1/", "*.0.0.1")]
    [InlineData("https://192.168.1.1/", "*.1.1")]
    [InlineData("https://127.0.0.1/", "*.0.0.1")]
    public void WildcardWithNumericSuffixDoesNotMatchIPLiteralHost(string uri, string pattern)
    {
        // The textual EndsWith match would otherwise allow an attacker-supplied wildcard like "*.169.254"
        // to bypass the IP unsafe-range check by matching the IP literal as a string.
        Assert.False(Ssrf.IsInAllowedHostnames(new Uri(uri), [pattern]));
    }

    [Theory]
    [InlineData("*.0.0.1")]
    [InlineData("*.169.254")]
    [InlineData("127.0.0.1")]
    [InlineData("*foo.example.com")]
    [InlineData("https://example.com")]
    [InlineData("")]
    [InlineData("*")]
    [InlineData("*.")]
    public void InvalidPatternsAreSkippedSilentlyAtMatchTime(string invalidPattern)
    {
        // Defense-in-depth: even if a malformed entry is somehow re-introduced after construction
        // (e.g. via runtime mutation of the collection), match-time validation refuses to match it.
        Assert.False(Ssrf.IsInAllowedHostnames(
            new Uri("https://anything.example.com/"),
            [invalidPattern]));
    }

    [Fact]
    public void ValidPatternsAroundInvalidEntriesStillMatch()
    {
        var allowedHostNames = new List<string> { "*.0.0.1", "*.example.com", "127.0.0.1" };
        Assert.True(Ssrf.IsInAllowedHostnames(new Uri("https://api.example.com/"), allowedHostNames));
    }
}

public class TryValidateAllowedHostname
{
    [Theory]
    [InlineData("example.com")]
    [InlineData("*.example.com")]
    [InlineData("*.api.example.com")]
    [InlineData("co.uk")]
    [InlineData("*.co.uk")]
    [InlineData("xn--p1ai")]
    [InlineData("*.xn--p1ai")]
    [InlineData("localhost")]
    [InlineData("*.localhost")]
    [InlineData("api1.example.com")]
    [InlineData("my-server.example.com")]
    public void ReturnsTrueForValidDnsPatterns(string pattern)
    {
        Assert.True(Ssrf.TryValidateAllowedHostnamePattern(pattern, out string? error));
        Assert.Null(error);
    }

    [Theory]
    [InlineData("")]
    [InlineData("*")]
    [InlineData("*.")]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.169.254")]
    [InlineData("::1")]
    [InlineData("2001:db8::")]
    [InlineData("*.0.0.1")]
    [InlineData("*.169.254")]
    [InlineData("*.10")]
    [InlineData("*.123")]
    [InlineData("123.456")]
    [InlineData("*.example.*")]
    [InlineData("*foo.example.com")]
    [InlineData("https://example.com")]
    [InlineData("example.com/admin")]
    [InlineData("example.com:8080")]
    [InlineData("user@example.com")]
    [InlineData("with space.example.com")]
    public void ReturnsFalseForInvalidPatterns(string pattern)
    {
        Assert.False(Ssrf.TryValidateAllowedHostnamePattern(pattern, out string? error));
        Assert.NotNull(error);
    }

    [Fact]
    public void ReturnsFalseForNullEntry()
    {
        Assert.False(Ssrf.TryValidateAllowedHostnamePattern(null, out string? error));
        Assert.NotNull(error);
    }
}

public class ValidateAllowedHostname
{
    [Fact]
    public void DoesNotThrowForNullCollection()
    {
        Ssrf.ValidateAllowedHostnamePatterns(null, "test");
    }

    [Fact]
    public void DoesNotThrowForEmptyCollection()
    {
        Ssrf.ValidateAllowedHostnamePatterns([], "test");
    }

    [Fact]
    public void DoesNotThrowForCollectionOfValidPatterns()
    {
        Ssrf.ValidateAllowedHostnamePatterns(
            [
                "example.com",
                "*.example.com",
                "co.uk",
                "*.xn--p1ai"
            ],
            "test");
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("*.0.0.1")]
    [InlineData("*.169.254")]
    [InlineData("::1")]
    [InlineData("")]
    [InlineData("*")]
    [InlineData("*.")]
    [InlineData("user@example.com")]
    [InlineData("!nvalid.com")]
    [InlineData("test.*example.com")]
    [InlineData("*.test.*example.com")]
    [InlineData("_test.example.com")]
    public void ThrowsArgumentExceptionForInvalidEntry(string entry)
    {
        ArgumentException ex = Assert.Throws<ArgumentException>(
            () => Ssrf.ValidateAllowedHostnamePatterns([entry], "test"));
        Assert.Equal("test", ex.ParamName);
    }

    [Fact]
    public void ThrowsForInvalidEntryEvenIfOtherEntriesAreValid()
    {
        Assert.Throws<ArgumentException>(
            () => Ssrf.ValidateAllowedHostnamePatterns(
                [
                    "example.com",
                    "*.0.0.1",
                    "test.com"
                ],
                "test"));
    }
}
