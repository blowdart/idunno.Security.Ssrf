// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;
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
        using HttpClient httpClient = new(SsrfSocketsHttpHandlerFactory.Create(connectTimeout: new TimeSpan(0,0,5)));
        HttpRequestException ex = await Assert.ThrowsAsync<HttpRequestException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));

        Exception? innermostException = ex;
        while (innermostException.InnerException is not null)
        {
            innermostException = innermostException.InnerException;

            if (innermostException is SsrfException)
            {
                break;
            }
        }

        Assert.IsType<SsrfException>(innermostException);
        Assert.Equal(hostName, ((SsrfException)ex.InnerException!).Uri!.ToString());
    }

    [Theory]
    [InlineData("https://mixed.ssrf.fail/")]
    [InlineData("https://mixed.ipv4.ssrf.fail/")]
    [InlineData("https://mixed.ipv6.ssrf.fail/")]
    public async Task ConnectionThrowsForHostsThatReturnAMixOfSafeAndUnsafeIPAddresses(string hostName)
    {
        using HttpClient httpClient = new(SsrfSocketsHttpHandlerFactory.Create(connectTimeout: new TimeSpan(0, 0, 5)));
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

            Exception? innermostException = ex;
            while (innermostException.InnerException is not null)
            {
                innermostException = innermostException.InnerException;

                if (innermostException is SsrfException)
                {
                    break;
                }
            }

            Assert.IsType<SsrfException>(innermostException);
            Assert.Equal(hostName, ((SsrfException)ex.InnerException!).Uri!.ToString());
        }
    }

    [Theory]
    [InlineData("https://mixed.ssrf.fail/")]
    [InlineData("https://mixed.ipv4.ssrf.fail/")]
    [InlineData("https://mixed.ipv6.ssrf.fail/")]
    public async Task ConnectionContinuesForHostsThatReturnAMixOfSafeAndUnsafeIPAddressesIfFailMixedResultsIsFalse(string hostName)
    {
        using HttpClient httpClient = new(SsrfSocketsHttpHandlerFactory.Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: new TimeSpan(0,0,1),
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null));

        try
        {
           _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken);
        }
        catch (Exception ex)
        {
            Assert.True(ex is HttpRequestException ||
                ex is TimeoutException ||
                ex is OperationCanceledException ||
                ex is SocketException);

            Exception? innermostException = ex;
            while (innermostException.InnerException is not null)
            {
                innermostException = innermostException.InnerException;

                if (innermostException is SsrfException)
                {
                    break;
                }
            }

            // Shouldn't throw an SsrfException because we're allow mixed results, where the IP addresses returned for the host include both safe and unsafe addresses.
            // The connection will end up failing anyway due to a certificate validation if the SSRF handler hasn't gotten in the way.
            Assert.IsNotType<SsrfException>(innermostException);
        }
    }

    [Theory]
    [InlineData("https://example.org/")]
    [InlineData("https://github.com/")]
    public async Task ConnectionSucceedsForSafeUri(string hostName)
    {
        using HttpClient httpClient = new(SsrfSocketsHttpHandlerFactory.Create(connectTimeout: new TimeSpan(0, 0, 5)));
        HttpResponseMessage response = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode);
    }

    [Theory]
    [InlineData("http://example.org/")]
    [InlineData("http://github.com/")]
    public async Task ConnectionThrowsForSafeHostButUnsafeProtocol(string hostName)
    {
        using HttpClient httpClient = new(SsrfSocketsHttpHandlerFactory.Create());
        HttpRequestException ex = await Assert.ThrowsAsync<HttpRequestException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Exception? innermostException = ex;
        while (innermostException.InnerException is not null)
        {
            innermostException = innermostException.InnerException;

            if (innermostException is SsrfException)
            {
                break;
            }
        }

        Assert.IsType<SsrfException>(innermostException);
        Assert.Equal(hostName, ((SsrfException)innermostException).Uri!.ToString());
    }

    [Theory]
    [InlineData("http://example.org/")]
    [InlineData("http://github.com/")]
    public async Task ConnectionThrowsForSafeHostButUnsafeProtocolIfAllowInsecureProtocolIsTrue(string hostName)
    {
        using HttpClient httpClient = new(SsrfSocketsHttpHandlerFactory.Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: new TimeSpan(0, 0, 5),
            allowInsecureProtocols: true,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: null,
            sslOptions: null));
        HttpResponseMessage response = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.Redirect || response.StatusCode == HttpStatusCode.MovedPermanently);
    }

    [Theory]
    [InlineData("https://example.org/")]
    public async Task ConnectionFailsForSafeUriWhichResolveToAdditionalUnsafeIpv4Addresses(string hostName)
    {
        static async Task<IPHostEntry> hostEntryResolver(string uri, CancellationToken cancellationToken)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [IPAddress.Parse("1.2.3.4")]
            };
        }

        using HttpClient httpClient = new(SsrfSocketsHttpHandlerFactory.Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: [IPAddress.Parse("1.2.3.4")],
            connectTimeout: new TimeSpan(0, 0, 5),
            allowInsecureProtocols: true,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: null,
            sslOptions: null,
            hostEntryResolver: hostEntryResolver,
            loggerFactory : null));
        HttpRequestException ex = await Assert.ThrowsAsync<HttpRequestException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Exception? innermostException = ex;
        while (innermostException.InnerException is not null)
        {
            innermostException = innermostException.InnerException;

            if (innermostException is SsrfException)
            {
                break;
            }
        }

        Assert.IsType<SsrfException>(innermostException);
        Assert.Equal(hostName, ((SsrfException)innermostException).Uri!.ToString());
    }

    [Theory]
    [InlineData("https://example.org/")]
    public async Task ConnectionFailsForSafeUriWhichResolveToAdditionalUnsafeIpv6Addresses(string hostName)
    {
        static async Task<IPHostEntry> hostEntryResolver(string uri, CancellationToken cancellationToken)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [IPAddress.Parse("2606:4700::6812:1b78")]
            };
        }

        using HttpClient httpClient = new(SsrfSocketsHttpHandlerFactory.Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: [IPAddress.Parse("2606:4700::6812:1b78")],
            connectTimeout: new TimeSpan(0, 0, 5),
            allowInsecureProtocols: true,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: null,
            sslOptions: null,
            hostEntryResolver: hostEntryResolver,
            loggerFactory: null));
        HttpRequestException ex = await Assert.ThrowsAsync<HttpRequestException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Exception? innermostException = ex;
        while (innermostException.InnerException is not null)
        {
            innermostException = innermostException.InnerException;

            if (innermostException is SsrfException)
            {
                break;
            }
        }

        Assert.IsType<SsrfException>(innermostException);
        Assert.Equal(hostName, ((SsrfException)innermostException).Uri!.ToString());
    }

    [Theory]
    [InlineData("https://example.org/")]
    public async Task ConnectionFailsForSafeUriWhichResolveToIPWithinAdditionalUnsafeIpv4Networks(string hostName)
    {
        static async Task<IPHostEntry> hostEntryResolver(string uri, CancellationToken cancellationToken)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [IPAddress.Parse("1.2.3.4")]
            };
        }

        using HttpClient httpClient = new(SsrfSocketsHttpHandlerFactory.Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: [IPNetwork.Parse("1.2.3.0/24")],
            additionalUnsafeIpAddresses: null,
            connectTimeout: new TimeSpan(0, 0, 5),
            allowInsecureProtocols: true,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: null,
            sslOptions: null,
            hostEntryResolver: hostEntryResolver,
            loggerFactory: null));
        HttpRequestException ex = await Assert.ThrowsAsync<HttpRequestException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Exception? innermostException = ex;
        while (innermostException.InnerException is not null)
        {
            innermostException = innermostException.InnerException;

            if (innermostException is SsrfException)
            {
                break;
            }
        }

        Assert.IsType<SsrfException>(innermostException);
        Assert.Equal(hostName, ((SsrfException)innermostException).Uri!.ToString());
    }

    [Theory]
    [InlineData("https://example.org/")]
    public async Task ConnectionFailsForSafeUriWhichResolveToIPWithinAdditionalUnsafeIpv6Networks(string hostName)
    {
        static async Task<IPHostEntry> hostEntryResolver(string uri, CancellationToken cancellationToken)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [IPAddress.Parse("[2620:1ec:bdf::69]")]
            };
        }

        using HttpClient httpClient = new(SsrfSocketsHttpHandlerFactory.Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: [IPNetwork.Parse("2620:1ec::/36")],
            additionalUnsafeIpAddresses: null,
            connectTimeout: new TimeSpan(0, 0, 5),
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: null,
            sslOptions: null,
            hostEntryResolver: hostEntryResolver,
            loggerFactory: null));
        HttpRequestException ex = await Assert.ThrowsAsync<HttpRequestException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Exception? innermostException = ex;
        while (innermostException.InnerException is not null)
        {
            innermostException = innermostException.InnerException;

            if (innermostException is SsrfException)
            {
                break;
            }
        }

        Assert.IsType<SsrfException>(innermostException);
        Assert.Equal(hostName, ((SsrfException)innermostException).Uri!.ToString());
    }

    [Fact]
    public async Task ConnectionFailsWhenOptionsAreUsed()
    {
        SsrfOptions options = new()
        {
            ConnectionStrategy = ConnectionStrategy.None,
            AdditionalUnsafeNetworks =
            [
                IPNetwork.Parse("104.18.3.24/30"),
                IPNetwork.Parse("2606:4700:0000:0000::/64")
            ],
            AdditionalUnsafeIpAddresses =
            [
                IPAddress.Parse("2606:4700::6812:218"),
                IPAddress.Parse("2606:4700::6812:318"),
                IPAddress.Parse("104.18.3.24"),
                IPAddress.Parse("104.18.2.24"),
            ],
            ConnectTimeout = new TimeSpan(0, 0, 5),
            AllowInsecureProtocols = false,
            FailMixedResults = true,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.All,
            Proxy = null,
            SslOptions = null
        };

        using HttpClient httpClient = new(SsrfSocketsHttpHandlerFactory.Create(options));
        HttpRequestException ex = await Assert.ThrowsAsync<HttpRequestException>(async () => _ = await httpClient.GetAsync("https://example.org", cancellationToken: TestContext.Current.CancellationToken));
        Exception? innermostException = ex;
        while (innermostException.InnerException is not null)
        {
            innermostException = innermostException.InnerException;

            if (innermostException is SsrfException)
            {
                break;
            }
        }

        Assert.IsType<SsrfException>(innermostException);
        Assert.Equal("https://example.org/", ((SsrfException)innermostException).Uri!.ToString());
    }

    [Fact]
    public async Task ConnectionFailsWhenDnsResolutionReturnsNoIpAddresses()
    {
        string hostName = "https://example.org/";

        static async Task<IPHostEntry> hostEntryResolver(string uri, CancellationToken cancellationToken)
        {
            return new IPHostEntry();
        }

        using HttpClient httpClient = new(SsrfSocketsHttpHandlerFactory.Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: [IPNetwork.Parse("2620:1ec::/36")],
            additionalUnsafeIpAddresses: null,
            connectTimeout: new TimeSpan(0, 0, 5),
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: null,
            sslOptions: null,
            hostEntryResolver: hostEntryResolver,
            loggerFactory: null));

        HttpRequestException ex = await Assert.ThrowsAsync<HttpRequestException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));

        Exception? innermostException = ex;
        while (innermostException.InnerException is not null)
        {
            innermostException = innermostException.InnerException;

            if (innermostException is SsrfException)
            {
                break;
            }
        }

        Assert.IsType<SsrfException>(innermostException);
        Assert.Equal(hostName, ((SsrfException)innermostException).Uri!.ToString());
    }

    [Theory]
    [InlineData("http://localhost/")]
    [InlineData("https://localhost/")]
    [InlineData("http://127.0.0.1/")]
    [InlineData("https://127.0.0.1/")]
    [InlineData("http://127.255.255.254/")]
    [InlineData("https://127.255.255.254/")]
    [InlineData("http://[::1]/")]
    [InlineData("https://[::1]/")]
    public async Task ConnectionDoesNotThrowForLoopbackHostWhenAllowLoopbackIsSet(string hostName)
    {
        using HttpClient httpClient = new(SsrfSocketsHttpHandlerFactory.Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: new TimeSpan(0, 0, 1),
            allowInsecureProtocols: true,
            allowLoopback: true,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: null,
            sslOptions: null,
            loggerFactory: null));

        Exception? ex = await Record.ExceptionAsync(async () => {
            await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken);
        });

        Assert.NotNull(ex);
        Assert.IsNotType<SsrfException>(ex);

        Exception? innermostException = ex;
        while (innermostException.InnerException is not null)
        {
            innermostException = innermostException.InnerException;

            if (innermostException is SsrfException)
            {
                break;
            }
        }

        Assert.IsNotType<SsrfException>(innermostException);
    }

    [Theory]
    [InlineData("http://localhost/")]
    [InlineData("https://localhost/")]
    [InlineData("http://127.0.0.1/")]
    [InlineData("https://127.0.0.1/")]
    [InlineData("http://127.255.255.254/")]
    [InlineData("https://127.255.255.254/")]
    [InlineData("http://[::1]/")]
    [InlineData("https://[::1]/")]
    public async Task ConnectionDoesNotThrowForLoopbackHostWhenAllowLoopbackIsSetInOptions(string hostName)
    {
        SsrfOptions options = new()
        {
            ConnectTimeout = new TimeSpan(0, 0, 1),
            AllowInsecureProtocols = true,
            AllowLoopback = true,
        };

        using HttpClient httpClient = new(SsrfSocketsHttpHandlerFactory.Create(options));

        Exception? ex = await Record.ExceptionAsync(async () => {
            await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken);
        });

        Assert.NotNull(ex);
        Assert.IsNotType<SsrfException>(ex);

        Exception? innermostException = ex;
        while (innermostException.InnerException is not null)
        {
            innermostException = innermostException.InnerException;

            if (innermostException is SsrfException)
            {
                break;
            }
        }

        Assert.IsNotType<SsrfException>(innermostException);
    }

    [Theory]
    [InlineData("http://localhost/")]
    [InlineData("http://127.0.0.1/")]
    [InlineData("http://127.255.255.254/")]
    [InlineData("http://[::1]/")]
    public async Task ConnectionThrowsForInsecureLoopbackHostWhenAllowLoopbackIsSetButAllowInsecureIsFalse(string hostName)
    {
        using HttpClient httpClient = new(SsrfSocketsHttpHandlerFactory.Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: new TimeSpan(0, 0, 1),
            allowInsecureProtocols: false,
            allowLoopback: true,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: null,
            sslOptions: null,
            loggerFactory: null));

        Exception? ex = await Record.ExceptionAsync(async () => {
            await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken);
        });

        Assert.NotNull(ex);
        Assert.IsNotType<SsrfException>(ex);

        Exception? innermostException = ex;
        while (innermostException.InnerException is not null)
        {
            innermostException = innermostException.InnerException;

            if (innermostException is SsrfException)
            {
                break;
            }
        }

        Assert.IsType<SsrfException>(innermostException);
    }

}
