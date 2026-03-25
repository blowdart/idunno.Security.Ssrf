// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net.Sockets;

namespace idunno.Security.SsrfTests;

public class HttpClientTests
{
    [Theory]
    [InlineData("http://localhost/")]
    [InlineData("https://localhost/")]
    [InlineData("https://bad.ssrf.fail/")]
    [InlineData("https://bad.ipv4.ssrf.fail/")]
    [InlineData("https://bad.ipv6.ssrf.fail/")]
    public async Task ConnectionThrowsForUnsafeUri(string hostName)
    {
        using HttpClient httpClient = new(SsrfSocketsHttpHanderFactory.Create());
        HttpRequestException ex = await Assert.ThrowsAsync<HttpRequestException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Assert.IsType<SsrfException>(ex.InnerException);
        Assert.Equal(hostName, ((SsrfException)ex.InnerException!).Uri!.ToString());
    }

    [Theory]
    [InlineData("https://mixed.ssrf.fail/")]
    [InlineData("https://mixed.ipv4.ssrf.fail/")]
    [InlineData("https://mixed.ipv6.ssrf.fail/")]
    public async Task ConnectionThrowsForHostsThatReturnAMixOfSafeAndUnsafeIPAddresses(string hostName)
    {
        using HttpClient httpClient = new(SsrfSocketsHttpHanderFactory.Create());
        try
        {
            _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken);
        }
        catch (Exception ex)
        {
            Assert.True(ex is HttpRequestException||
                ex is TimeoutException ||
                ex is OperationCanceledException ||
                ex is SocketException);

            if (ex.InnerException is not null)
            {
                Assert.IsType<SsrfException>(ex.InnerException);
                Assert.Equal(hostName, ((SsrfException)ex.InnerException!).Uri!.ToString());
            }
        }
    }

    [Theory]
    [InlineData("https://mixed.ssrf.fail/")]
    [InlineData("https://mixed.ipv4.ssrf.fail/")]
    [InlineData("https://mixed.ipv6.ssrf.fail/")]
    public async Task ConnectionContinuesForHostsThatReturnAMixOfSafeAndUnsafeIPAddressesIfFailMixedResultsIsFalse(string hostName)
    {
        using HttpClient httpClient = new(SsrfSocketsHttpHanderFactory.Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalNetworks: null,
            connectTimeout: new TimeSpan(0,0,1),
            allowInsecureProtocols: false,
            failMixedResults: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxyUri: null,
            checkCertificateRevocationList: true));

        try
        {
           _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken);
        }
        catch (Exception ex)
        {
            Assert.True((ex is HttpRequestException && ex.InnerException is not SsrfException) ||
                ex is TimeoutException ||
                ex is OperationCanceledException ||
                ex is SocketException);
        }
    }

    [Theory]
    [InlineData("https://example.org/")]
    [InlineData("https://github.com/")]
    public async Task ConnectionSucceedsForSafeUri(string hostName)
    {
        using HttpClient httpClient = new(SsrfSocketsHttpHanderFactory.Create());
        HttpResponseMessage response = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode);
    }

    [Theory]
    [InlineData("http://example.org/")]
    [InlineData("http://github.com/")]
    public async Task ConnectionThrowsForSafeHostButUnsafeProtocol(string hostName)
    {
        using HttpClient httpClient = new(SsrfSocketsHttpHanderFactory.Create());
        HttpRequestException ex = await Assert.ThrowsAsync<HttpRequestException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Assert.IsType<SsrfException>(ex.InnerException);
        Assert.Equal(hostName, ((SsrfException)ex.InnerException!).Uri!.ToString());
    }

    [Theory]
    [InlineData("http://example.org/")]
    [InlineData("http://github.com/")]
    public async Task ConnectionThrowsForSafeHostButUnsafeProtocolIfAllowInsecureProtocolIsTrue(string hostName)
    {
        using HttpClient httpClient = new(SsrfSocketsHttpHanderFactory.Create(
            allowInsecureProtocols: true
            ));
        HttpResponseMessage response = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode || response.StatusCode == System.Net.HttpStatusCode.Redirect || response.StatusCode == System.Net.HttpStatusCode.MovedPermanently);
    }
}
