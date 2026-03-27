// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

namespace idunno.Security.SsrfTests;

public class IsUnsafeUriTests
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
        Assert.False(Ssrf.IsUnsafeUri(new Uri($"https://{host}/"), allowInsecureProtocols: true));
        Assert.False(Ssrf.IsUnsafeUri(new Uri($"wss://{host}/"), allowInsecureProtocols: true));
    }

    [Theory]
    [InlineData("example.com")]
    [InlineData("www.example.com")]
    [InlineData("104.18.26.120")]
    [InlineData("104.18.27.120")]
    [InlineData("[2620:1ec:bdf::69]")]
    [InlineData("[2620:1ec:46::69]")]
    public void ReturnsTrueForNonSecureUris(string host)
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
        Assert.True(Ssrf.IsUnsafeUri(uri, allowInsecureProtocols: true));
    }

    [Theory]
    [InlineData(@"ftp://example.com")]
    [InlineData(@"telnet://exampe.com")]
    [InlineData(@"ms-teams://exampe.com")]
    public void ReturnsTrueForUnsafeProtocols(string uriAsString)
    {
        Uri uri = new(uriAsString);
        Assert.True(Ssrf.IsUnsafeUri(uri));
        Assert.True(Ssrf.IsUnsafeUri(uri, allowInsecureProtocols: true));
    }

    [Theory]
    [InlineData("example.com")]
    [InlineData("www.example.com")]
    [InlineData("104.18.26.120")]
    [InlineData("104.18.27.120")]
    [InlineData("[2620:1ec:bdf::69]")]
    [InlineData("[2620:1ec:46::69]")]
    public void ReturnsFalseForGoodUrisIfInsecureProtocolsAllowed(string host)
    {
        Assert.False(Ssrf.IsUnsafeUri(new Uri($"https://{host}/"), allowInsecureProtocols: true));
        Assert.False(Ssrf.IsUnsafeUri(new Uri($"wss://{host}/"), allowInsecureProtocols: true));
        Assert.False(Ssrf.IsUnsafeUri(new Uri($"http://{host}/"), allowInsecureProtocols: true));
        Assert.False(Ssrf.IsUnsafeUri(new Uri($"ws://{host}/"), allowInsecureProtocols: true));
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("127.0.0.1")]
    [InlineData("[::1]")]
    public void ReturnsTrueForLocalhostAndLoopbackAddresses(string host)
    {
        Assert.True(Ssrf.IsUnsafeUri(new Uri($"http://{host}/")));
        Assert.True(Ssrf.IsUnsafeUri(new Uri($"https://{host}/")));
        Assert.True(Ssrf.IsUnsafeUri(new Uri($"http://{host}/"), allowInsecureProtocols: true));
        Assert.True(Ssrf.IsUnsafeUri(new Uri($"https://{host}/"), allowInsecureProtocols: true));
    }

    [Theory]
    [InlineData("/relative/path")]
    [InlineData("/another/path")]
    public void ReturnsTrueForRelativeUris(string relativeUri)
    {
        Assert.True(Ssrf.IsUnsafeUri(new Uri(relativeUri, UriKind.Relative)));
        Assert.True(Ssrf.IsUnsafeUri(new Uri(relativeUri, UriKind.Relative), allowInsecureProtocols: true));
    }

    [Fact]
    public void ThrowsArgumentNullExceptionIfUriIsNull()
    {
        Assert.Throws<ArgumentNullException>(() => Ssrf.IsUnsafeUri(null!));
    }
}
