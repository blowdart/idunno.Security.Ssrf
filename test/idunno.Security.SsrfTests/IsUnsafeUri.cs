// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

namespace idunno.Security.SsrfTests;

public class IsUnsafeUri
{
    [Theory]
    [InlineData("example.com")]
    [InlineData("www.example.com")]
    [InlineData("104.18.26.120")]
    [InlineData("104.18.27.120")]
    [InlineData("[2620:1ec:bdf::69]")]
    [InlineData("[2620:1ec:46::69]")]
    public void ReturnsFalseForGoodUris(string host)
    {
        Assert.False(Ssrf.IsUnsafeUri(new Uri($"https://{host}/")));
        Assert.False(Ssrf.IsUnsafeUri(new Uri($"wss://{host}/")));
        Assert.False(Ssrf.IsUnsafeUri(new Uri($"https://{host}/"), allowedSchemes: ["https"]));
        Assert.False(Ssrf.IsUnsafeUri(new Uri($"wss://{host}/"), allowedSchemes: ["https", "wss"]));
    }

    [Theory]
    [InlineData("example.com")]
    [InlineData("www.example.com")]
    [InlineData("104.18.26.120")]
    [InlineData("104.18.27.120")]
    [InlineData("[2620:1ec:bdf::69]")]
    [InlineData("[2620:1ec:46::69]")]
    public void ReturnsTrueForNonSecureUrisIfAllowedSchemesIsNotSpecified(string host)
    {
        Assert.True(Ssrf.IsUnsafeUri(new Uri($"http://{host}/")));
        Assert.True(Ssrf.IsUnsafeUri(new Uri($"ws://{host}/")));
    }

    [Theory]
    [InlineData(@"\\unc\documents")]
    [InlineData(@"\\unc.example\documents")]
    public void ReturnsTrueForUncUris(string uriAsString)
    {
        Uri uri = new(uriAsString);
        Assert.True(Ssrf.IsUnsafeUri(uri));
        Assert.True(Ssrf.IsUnsafeUri(uri, allowedSchemes: ["https", "http", "wss", "ws"]));
    }

    [Theory]
    [InlineData(@"ftp://example.com")]
    [InlineData(@"telnet://exampe.com")]
    [InlineData(@"ms-teams://example.com")]
    public void ReturnsTrueForUnsafeProtocols(string uriAsString)
    {
        Uri uri = new(uriAsString);
        Assert.True(Ssrf.IsUnsafeUri(uri));
        Assert.True(Ssrf.IsUnsafeUri(uri, allowedSchemes: ["https", "http", "wss", "ws"]));
    }

    [Theory]
    [InlineData("example.com")]
    [InlineData("www.example.com")]
    [InlineData("104.18.26.120")]
    [InlineData("104.18.27.120")]
    [InlineData("[2620:1ec:bdf::69]")]
    [InlineData("[2620:1ec:46::69]")]
    public void ReturnsFalseForGoodUrisIfHttpAndWsAllowed(string host)
    {
        Assert.False(Ssrf.IsUnsafeUri(new Uri($"https://{host}/"), allowedSchemes: ["https", "http", "wss", "ws"]));
        Assert.False(Ssrf.IsUnsafeUri(new Uri($"wss://{host}/"), allowedSchemes: ["https", "http", "wss", "ws"]));
        Assert.False(Ssrf.IsUnsafeUri(new Uri($"http://{host}/"), allowedSchemes: ["https", "http", "wss", "ws"]));
        Assert.False(Ssrf.IsUnsafeUri(new Uri($"ws://{host}/"), allowedSchemes: ["https", "http", "wss", "ws"]));
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("127.0.0.1")]
    [InlineData("[::1]")]
    public void ReturnsTrueForLocalhostAndLoopbackAddresses(string host)
    {
        Assert.True(Ssrf.IsUnsafeUri(new Uri($"http://{host}/"), allowedSchemes: ["https", "http", "wss", "ws"]));
        Assert.True(Ssrf.IsUnsafeUri(new Uri($"https://{host}/"), allowedSchemes: ["https", "http", "wss", "ws"]));
        Assert.True(Ssrf.IsUnsafeUri(new Uri($"http://{host}/"), allowedSchemes: ["https", "http", "wss", "ws"]));
        Assert.True(Ssrf.IsUnsafeUri(new Uri($"https://{host}/"), allowedSchemes: ["https", "http", "wss", "ws"]));
    }

    [Theory]
    [InlineData("/relative/path")]
    [InlineData("/another/path")]
    public void ReturnsTrueForRelativeUris(string relativeUri)
    {
        Assert.True(Ssrf.IsUnsafeUri(new Uri(relativeUri, UriKind.Relative)));
        Assert.True(Ssrf.IsUnsafeUri(new Uri(relativeUri, UriKind.Relative), allowedSchemes: ["https", "http", "wss", "ws"]));
    }

    [Fact]
    public void ThrowsArgumentNullExceptionIfUriIsNull()
    {
        Assert.Throws<ArgumentNullException>(() => Ssrf.IsUnsafeUri(null!));
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("127.0.0.1")]
    [InlineData("[::1]")]
    public void ReturnsFalseForLocalhostAndLoopbackAddressesIfAllowLoopbackIsTrueAndSchemesAreAllowed(string host)
    {
        Assert.False(Ssrf.IsUnsafeUri(new Uri($"http://{host}/"), allowedSchemes: ["https", "http", "wss", "ws"], allowLoopback: true));
        Assert.False(Ssrf.IsUnsafeUri(new Uri($"https://{host}/"), allowedSchemes: ["https", "http", "wss", "ws"], allowLoopback: true));
        Assert.False(Ssrf.IsUnsafeUri(new Uri($"http://{host}/"), allowedSchemes: ["https", "http", "wss", "ws"], allowLoopback: true));
        Assert.False(Ssrf.IsUnsafeUri(new Uri($"https://{host}/"), allowedSchemes: ["https", "http", "wss", "ws"], allowLoopback: true));
    }

    [Fact]
    public void SchemelessRelativeIsConsideredUnsafe()
    {
        Assert.True(Ssrf.IsUnsafeUri(new Uri("//example.com")));
        Assert.True(Ssrf.IsUnsafeUri(new Uri("//example.com", UriKind.RelativeOrAbsolute)));
    }

    [Theory]
    [InlineData("example.com")]
    [InlineData("www.example.com")]
    [InlineData("104.18.26.120")]
    [InlineData("104.18.27.120")]
    [InlineData("[2620:1ec:bdf::69]")]
    [InlineData("[2620:1ec:46::69]")]
    public void ReturnsTrueForUrisWithUserInfo(string host)
    {
        Assert.True(Ssrf.IsUnsafeUri(new Uri($"https://username:password@{host}/")));
        Assert.True(Ssrf.IsUnsafeUri(new Uri($"https://username@{host}/"), allowedSchemes: ["https"]));
    }
}
