// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;
using System.Net.Sockets;

namespace idunno.Security.SsrfTests;

public class SsrfSocketsHttpHandlerFactory
{
    [Theory]
    [InlineData("http://localhost/")]
    [InlineData("https://localhost/")]
    [InlineData("https://bad.ssrf.fail/")]
    [InlineData("https://bad.ipv4.ssrf.fail/")]
    [InlineData("https://bad.ipv6.ssrf.fail/")]
    public async Task ConnectionThrowsForUnsafeUri(string uri)
    {
        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.Create(connectTimeout: new TimeSpan(0,0,5)));
        HttpRequestException ex = await Assert.ThrowsAsync<HttpRequestException>(async () => _ = await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken));

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
        Assert.Equal(uri, ((SsrfException)ex.InnerException!).Uri!.ToString());
    }

    [Theory]
    [InlineData("https://mixed.ssrf.fail/")]
    [InlineData("https://mixed.ipv4.ssrf.fail/")]
    [InlineData("https://mixed.ipv6.ssrf.fail/")]
    public async Task ConnectionThrowsForHostsThatReturnAMixOfSafeAndUnsafeIPAddresses(string uri)
    {
        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.Create(connectTimeout: new TimeSpan(0, 0, 5)));
        try
        {
            _ = await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
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
            Assert.Equal(uri, ((SsrfException)ex.InnerException!).Uri!.ToString());
        }
    }

    [Theory]
    [InlineData("https://mixed.ssrf.fail/")]
    [InlineData("https://mixed.ipv4.ssrf.fail/")]
    [InlineData("https://mixed.ipv6.ssrf.fail/")]
    public async Task ConnectionContinuesForHostsThatReturnAMixOfSafeAndUnsafeIPAddressesIfFailMixedResultsIsFalse(string uri)
    {
        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            connectTimeout: new TimeSpan(0,0,1),
            allowedSchemes: null,
            allowLoopback: false,
            failMixedResults: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            sslOptions: null));

        try
        {
           _ = await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
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
    public async Task ConnectionSucceedsForSafeUri(string uri)
    {
        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.Create(connectTimeout: new TimeSpan(0, 0, 5)));
        HttpResponseMessage response = await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode);
    }

    [Theory]
    [InlineData("http://example.org/")]
    [InlineData("http://github.com/")]
    public async Task ConnectionThrowsForSafeHostButUnsafeProtocol(string uri)
    {
        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.Create());
        HttpRequestException ex = await Assert.ThrowsAsync<HttpRequestException>(async () => _ = await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken));
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
        Assert.Equal(uri, ((SsrfException)innermostException).Uri!.ToString());
    }

    [Theory]
    [InlineData("http://example.org/")]
    [InlineData("http://github.com/")]
    public async Task ConnectionDoesNotThrowForSafeHostButUnsafeProtocolIfAllowHttpAndWsAreAllowed(string uri)
    {
        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            connectTimeout: new TimeSpan(0, 0, 5),
            allowedSchemes: ["https", "http", "wss", "ws"],
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            sslOptions: null));
        HttpResponseMessage response = await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.Redirect || response.StatusCode == HttpStatusCode.MovedPermanently);
    }

    [Theory]
    [InlineData("https://example.org/")]
    public async Task ConnectionFailsForSafeUriWhichResolveToAdditionalUnsafeIpv4Addresses(string uri)
    {
        static async Task<IPHostEntry> hostEntryResolver(string uri, CancellationToken cancellationToken)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [IPAddress.Parse("1.2.3.4")]
            };
        }

        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: [IPAddress.Parse("1.2.3.4")],
            allowedHostnames: null,
            safeIPNetworks: null,
            safeIPAddresses: null,
            connectTimeout: new TimeSpan(0, 0, 5),
            allowedSchemes: ["https", "http", "wss", "ws"],
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: hostEntryResolver,
            loggerFactory : null,
            meterFactory: null));
        HttpRequestException ex = await Assert.ThrowsAsync<HttpRequestException>(async () => _ = await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken));
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
        Assert.Equal(uri, ((SsrfException)innermostException).Uri!.ToString());
    }

    [Theory]
    [InlineData("https://example.org/")]
    public async Task ConnectionFailsForSafeUriWhichResolveToAdditionalUnsafeIpv6Addresses(string uri)
    {
        static async Task<IPHostEntry> hostEntryResolver(string uri, CancellationToken cancellationToken)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [IPAddress.Parse("2606:4700::6812:1b78")]
            };
        }

        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: [IPAddress.Parse("2606:4700::6812:1b78")],
            allowedHostnames: null,
            safeIPNetworks: null,
            safeIPAddresses: null,
            connectTimeout: new TimeSpan(0, 0, 5),
            allowedSchemes: null,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: hostEntryResolver,
            loggerFactory: null,
            meterFactory: null));
        HttpRequestException ex = await Assert.ThrowsAsync<HttpRequestException>(async () => _ = await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken));
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
        Assert.Equal(uri, ((SsrfException)innermostException).Uri!.ToString());
    }

    [Theory]
    [InlineData("https://example.org/")]
    public async Task ConnectionFailsForSafeUriWhichResolveToIPWithinAdditionalUnsafeIpv4Networks(string uri)
    {
        static async Task<IPHostEntry> hostEntryResolver(string uri, CancellationToken cancellationToken)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [IPAddress.Parse("1.2.3.4")]
            };
        }

        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: [IPNetwork.Parse("1.2.3.0/24")],
            additionalUnsafeIPAddresses: null,
            allowedHostnames: null,
            safeIPNetworks: null,
            safeIPAddresses: null,
            connectTimeout: new TimeSpan(0, 0, 5),
            allowedSchemes: null,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: hostEntryResolver,
            loggerFactory: null,
            meterFactory: null));
        HttpRequestException ex = await Assert.ThrowsAsync<HttpRequestException>(async () => _ = await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken));
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
        Assert.Equal(uri, ((SsrfException)innermostException).Uri!.ToString());
    }

    [Theory]
    [InlineData("https://example.org/")]
    public async Task ConnectionFailsForSafeUriWhichResolveToIPWithinAdditionalUnsafeIpv6Networks(string uri)
    {
        static async Task<IPHostEntry> hostEntryResolver(string uri, CancellationToken cancellationToken)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [IPAddress.Parse("[2620:1ec:bdf::69]")]
            };
        }

        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: [IPNetwork.Parse("2620:1ec::/36")],
            additionalUnsafeIPAddresses: null,
            allowedHostnames: null,
            safeIPNetworks: null,
            safeIPAddresses: null,
            connectTimeout: new TimeSpan(0, 0, 5),
            allowedSchemes: null,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: hostEntryResolver,
            loggerFactory: null,
            meterFactory: null));
        HttpRequestException ex = await Assert.ThrowsAsync<HttpRequestException>(async () => _ = await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken));
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
        Assert.Equal(uri, ((SsrfException)innermostException).Uri!.ToString());
    }

    [Fact]
    public async Task ConnectionFailsWhenOptionsAreUsed()
    {
        static async Task<IPHostEntry> hostEntryResolver(string uri, CancellationToken cancellationToken)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [
                    IPAddress.Parse("2606:4700::6812:218"),
                    IPAddress.Parse("2606:4700::6812:318"),
                    IPAddress.Parse("104.18.3.24"),
                    IPAddress.Parse("104.18.2.24"),
                ]
            };
        }

        SsrfOptions options = new()
        {
            AdditionalUnsafeIPNetworks =
            [
                IPNetwork.Parse("104.18.3.24/30"),
                IPNetwork.Parse("2606:4700:0000:0000::/64")
            ],
            AdditionalUnsafeIPAddresses =
            [
                IPAddress.Parse("2606:4700::6812:218"),
                IPAddress.Parse("2606:4700::6812:318"),
                IPAddress.Parse("104.18.3.24"),
                IPAddress.Parse("104.18.2.24")
            ],
            ConnectTimeout = new TimeSpan(0, 0, 5),
            FailMixedResults = true,
        };

        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.InternalCreate(
            options,
            loggerFactory: null,
            meterFactory: null,
            hostEntryResolver: hostEntryResolver));
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
        string uri = "https://example.org/";

        static async Task<IPHostEntry> hostEntryResolver(string uri, CancellationToken cancellationToken)
        {
            return new IPHostEntry();
        }

        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: [IPNetwork.Parse("2620:1ec::/36")],
            additionalUnsafeIPAddresses: null,
            allowedHostnames: null,
            safeIPNetworks: null,
            safeIPAddresses: null,
            connectTimeout: new TimeSpan(0, 0, 5),
            allowedSchemes: null,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: hostEntryResolver,
            loggerFactory: null,
            meterFactory: null));

        HttpRequestException ex = await Assert.ThrowsAsync<HttpRequestException>(async () => _ = await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken));

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
        Assert.Equal(uri, ((SsrfException)innermostException).Uri!.ToString());
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
    public async Task ConnectionDoesNotThrowForLoopbackHostWhenAllowLoopbackIsSet(string uri)
    {
        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.Create(
            connectTimeout: new TimeSpan(0, 0, 1),
            allowedSchemes: ["https", "http", "wss", "ws"],
            allowLoopback: true,
            automaticDecompression: DecompressionMethods.All));

        Exception? ex = await Record.ExceptionAsync(async () => {
            await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
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
    public async Task ConnectionDoesNotThrowForLoopbackHostWhenAllowLoopbackIsSetInOptions(string uri)
    {
        SsrfOptions options = new()
        {
            ConnectTimeout = new TimeSpan(0, 0, 1),
            AllowedSchemes = ["https", "http", "wss", "ws"],
            AllowLoopback = true,
        };

        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.Create(options));

        Exception? ex = await Record.ExceptionAsync(async () => {
            await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
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
    public async Task ConnectionThrowsForInsecureLoopbackHostWhenAllowLoopbackIsSetAndNoAllowedSchemesAreSet(string uri)
    {
        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            connectTimeout: new TimeSpan(0, 0, 1),
            allowLoopback: true,
            automaticDecompression: DecompressionMethods.All));

        Exception? ex = await Record.ExceptionAsync(async () => {
            await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
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

    [Fact]
    public async Task ConnectionIsAllowedForIndividualAllowedDomainsEvenIfTheyResolveToAnUnsafeIPAddress()
    {
        var uri = new Uri("https://example.com");
        var allowedHostNames = new List<string> { "example.com", "test.com" };

        static async Task<IPHostEntry> hostEntryResolver(string uri, CancellationToken cancellationToken)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [
                    IPAddress.Parse("127.0.0.1"),
                    IPAddress.Parse("::1")
                ]
            };
        }

        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: allowedHostNames,
            safeIPNetworks: null,
            safeIPAddresses: null,
            connectTimeout: new TimeSpan(0, 0, 5),
            allowedSchemes: ["https"],
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: hostEntryResolver,
            loggerFactory: null,
            meterFactory: null));
        {
            // Should time out, because the mock resolver is returning loopback addresses, but it shouldn't throw an SsrfException because the hostname is in the allow list.
            Exception? ex = await Record.ExceptionAsync(async () => {
                await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
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
    }

    [Fact]
    public async Task ConnectionIsAllowedForAWildCardAllowedDomainsEvenIfTheyResolveToAnUnsafeIPAddress()
    {
        var uri = new Uri("https://database.example.localhost");
        var allowedHostNames = new List<string> { "*.localhost" };

        static async Task<IPHostEntry> hostEntryResolver(string uri, CancellationToken cancellationToken)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [
                    IPAddress.Parse("127.0.0.1"),
                    IPAddress.Parse("::1")
                ]
            };
        }

        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: allowedHostNames,
            safeIPNetworks: null,
            safeIPAddresses: null,
            connectTimeout: new TimeSpan(0, 0, 5),
            allowedSchemes: ["https"],
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: hostEntryResolver,
            loggerFactory: null,
            meterFactory: null));
        {
            // Should time out, because the mock resolver is returning loopback addresses, but it shouldn't throw an SsrfException because the hostname is in the allow list.
            Exception? ex = await Record.ExceptionAsync(async () => {
                await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
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
    }

    [Fact]
    public async Task ConnectionIsStoppedAWildCardAllowedDomainsIfTheHostIsNotCoveredByTheWildcard()
    {
        var uri = new Uri("https://example.localhost");
        var allowedHostNames = new List<string> { "*.example.localhost" };

        static async Task<IPHostEntry> hostEntryResolver(string uri, CancellationToken cancellationToken)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [
                    IPAddress.Parse("127.0.0.1"),
                    IPAddress.Parse("::1")
                ]
            };
        }

        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: allowedHostNames,
            safeIPNetworks: null,
            safeIPAddresses: null,
            connectTimeout: new TimeSpan(0, 0, 5),
            allowedSchemes: ["https"],
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: hostEntryResolver,
            loggerFactory: null,
            meterFactory: null));
        {
            Exception? ex = await Record.ExceptionAsync(async () => {
                await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
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

    [Fact]
    public async Task ConnectionIsAllowedWithWildCardAllowedDomainsAndASpecificEntryToCoverTheHostEvenIfTheyResolveToAnUnsafeIPAddress()
    {
        var uri = new Uri("https://example.localhost");
        var allowedHostNames = new List<string> { "*.example.localhost", "example.localhost" };

        static async Task<IPHostEntry> hostEntryResolver(string uri, CancellationToken cancellationToken)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [
                    IPAddress.Parse("127.0.0.1"),
                    IPAddress.Parse("::1")
                ]
            };
        }

        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: allowedHostNames,
            safeIPNetworks: null,
            safeIPAddresses: null,
            connectTimeout: new TimeSpan(0, 0, 5),
            allowedSchemes: ["https"],
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: hostEntryResolver,
            loggerFactory: null,
            meterFactory: null));
        {
            // Should time out, because the mock resolver is returning loopback addresses, but it shouldn't throw an SsrfException because the hostname is in the allow list.
            Exception? ex = await Record.ExceptionAsync(async () => {
                await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
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
    }

    [Fact]
    public async Task ConnectionIsAllowedForIndividualAllowedDomainsInOptionsEvenIfTheyResolveToAnUnsafeIPAddress()
    {
        var uri = new Uri("https://loopback.ssrf.fail");
        var allowedHostNames = new List<string> { "loopback.ssrf.fail"};

        SsrfOptions options = new()
        {
            AllowedHostnames = allowedHostNames,
            ConnectTimeout = new TimeSpan(0, 0, 5),
            AutomaticDecompression = DecompressionMethods.All,
        };

        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.Create(options));
        {
            // Should time out, because the mock resolver is returning loopback addresses, but it shouldn't throw an SsrfException because the hostname is in the allow list.
            Exception? ex = await Record.ExceptionAsync(async () => {
                await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
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
    }

    [Fact]
    public async Task ConnectionIsAllowedForAWildCardAllowedDomainsInOptionsEvenIfTheyResolveToAnUnsafeIPAddress()
    {
        var uri = new Uri("https://loopback.ssrf.fail");
        var allowedHostNames = new List<string> { "*.ssrf.fail" };

        SsrfOptions options = new()
        {
            AllowedHostnames = allowedHostNames,
            ConnectTimeout = new TimeSpan(0, 0, 5),
            AutomaticDecompression = DecompressionMethods.All,
        };


        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.Create(options));
        {
            // Should time out, because the mock resolver is returning loopback addresses, but it shouldn't throw an SsrfException because the hostname is in the allow list.
            Exception? ex = await Record.ExceptionAsync(async () => {
                await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
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
    }

    [Fact]
    public async Task ConnectionIsStoppedWithAWildCardAllowedDomainsInOptionsIfTheHostIsNotCoveredByTheWildcard()
    {
        var uri = new Uri("https://loopback.ssrf.fail");
        var allowedHostNames = new List<string> { "*.loopback.ssrf.fail" };

        SsrfOptions options = new()
        {
            AllowedHostnames = allowedHostNames,
            ConnectTimeout = new TimeSpan(0, 0, 5),
            AutomaticDecompression = DecompressionMethods.All,
        };

        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.Create(options));
        {
            Exception? ex = await Record.ExceptionAsync(async () => {
                await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
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

    [Fact]
    public async Task ConnectionIsAllowedWithWildCardAllowedDomainsAndASpecificEntryToCoverTheHostInOptionsEvenIfTheyResolveToAnUnsafeIPAddress()
    {
        var uri = new Uri("https://loopback.ssrf.fail");
        var allowedHostNames = new List<string> { "*.loopback.ssrf.fail", "loopback.ssrf.fail" };

        SsrfOptions options = new()
        {
            AllowedHostnames = allowedHostNames,
            ConnectTimeout = new TimeSpan(0, 0, 5),
            AutomaticDecompression = DecompressionMethods.All,
        };

        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.Create(options));
        {
            Exception? ex = await Record.ExceptionAsync(async () => {
                await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
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
    }

    [Fact]
    public async Task ConnectionIsAllowedForUnsafeIPAddressIfItIsAlsoInTheSafeIPAddressCollection()
    {
        var uri = new Uri("https://loopback.ssrf.fail");

        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.Create(
            safeIPNetworks: [
                IPNetwork.Parse("127.0.0.0/8"),
                IPNetwork.Parse("::1/128")
            ]));
        {
            Exception? ex = await Record.ExceptionAsync(async () => {
                await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
            });

            Assert.NotNull(ex);
            Assert.IsNotType<SsrfException>(ex);

            while (ex.InnerException is not null)
            {
                ex = ex.InnerException;
                Assert.IsNotType<SsrfException>(ex);
            }
        }
    }

    [Fact]
    public async Task ConnectionIsAllowedForUnsafeIPAddressIfItIsInANetworkInTheSafeIpAddressesCollection()
    {
        var uri = new Uri("https://loopback.ssrf.fail");

        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.Create(
            safeIPAddresses:
            [
                IPAddress.Parse("127.0.0.1"),
                IPAddress.Parse("::1")
            ]));
        {
            Exception? ex = await Record.ExceptionAsync(async () => {
                await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
            });

            Assert.NotNull(ex);
            Assert.IsNotType<SsrfException>(ex);

            while (ex.InnerException is not null)
            {
                ex = ex.InnerException;
                Assert.IsNotType<SsrfException>(ex);
            }
        }
    }

    [Fact]
    public async Task ConnectionIsAllowedForUnsafeIPAddressIfItIsAlsoInTheSafeNetworksCollectionInOptions()
    {
        var uri = new Uri("https://loopback.ssrf.fail");

        var options = new SsrfOptions
        {
            SafeIPNetworks =
            [
                IPNetwork.Parse("127.0.0.0/8"),
                IPNetwork.Parse("::1/128")
            ]
        };

        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.Create(options));
        {
            Exception? ex = await Record.ExceptionAsync(async () => {
                await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
            });

            Assert.NotNull(ex);
            Assert.IsNotType<SsrfException>(ex);

            while (ex.InnerException is not null)
            {
                ex = ex.InnerException;
                Assert.IsNotType<SsrfException>(ex);
            }
        }
    }

    [Fact]
    public async Task ConnectionIsAllowedForUnsafeIPAddressIfItIsAlsoInTheSafeIPAddressCollectionInOptions()
    {
        var uri = new Uri("https://loopback.ssrf.fail");

        var options = new SsrfOptions
        {
            SafeIPAddresses =
            [
                IPAddress.Parse("127.0.0.1"),
                IPAddress.Parse("::1")
            ]
        };

        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.Create(options));
        {
            Exception? ex = await Record.ExceptionAsync(async () => {
                await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
            });

            Assert.NotNull(ex);
            Assert.IsNotType<SsrfException>(ex);

            while (ex.InnerException is not null)
            {
                ex = ex.InnerException;
                Assert.IsNotType<SsrfException>(ex);
            }
        }
    }

    [Fact]
    public void SortIpAddressListByFamilySortsCorrectlyForIpV4Addresses()
    {
        IPAddress[] addresses = [
            IPAddress.Parse("::1"),
            IPAddress.Parse("127.0.0.1")
        ];

        Security.SsrfSocketsHttpHandlerFactory.SortIpAddressListByFamily(addresses, AddressFamily.InterNetwork);

        Assert.Equal(IPAddress.Parse("127.0.0.1"), addresses[0]);
        Assert.Equal(IPAddress.Parse("::1"), addresses[1]);
    }

    [Fact]
    public void SortIpAddressListByFamilySortsCorrectlyForIpV6Addresses()
    {
        IPAddress[] addresses = [
            IPAddress.Parse("::1"),
            IPAddress.Parse("127.0.0.1")
        ];

        Security.SsrfSocketsHttpHandlerFactory.SortIpAddressListByFamily(addresses, AddressFamily.InterNetworkV6);

        Assert.Equal(IPAddress.Parse("::1"), addresses[0]);
        Assert.Equal(IPAddress.Parse("127.0.0.1"), addresses[1]);
    }

    [Fact]
    public void SortIpAddressListByFamilySortsCorrectlyForMultipleIpV4Addresses()
    {
        IPAddress[] addresses = [
            IPAddress.Parse("127.0.0.2"),
            IPAddress.Parse("::1"),
            IPAddress.Parse("127.0.0.1")
        ];

        Security.SsrfSocketsHttpHandlerFactory.SortIpAddressListByFamily(addresses, AddressFamily.InterNetwork);

        Assert.Equal(IPAddress.Parse("::1"), addresses[2]);
    }

    [Fact]
    public void SortIpAddressListByFamilySortsCorrectlyForIpMultipleV6Addresses()
    {
        IPAddress[] addresses = [
            IPAddress.Parse("::1"),
            IPAddress.Parse("127.0.0.1"),
            IPAddress.Parse("::2"),
        ];

        Security.SsrfSocketsHttpHandlerFactory.SortIpAddressListByFamily(addresses, AddressFamily.InterNetworkV6);

        Assert.Equal(IPAddress.Parse("127.0.0.1"), addresses[2]);
    }

    [Fact]
    public void SortIpAddressListByFamilySortsCorrectlyForIpMultipleAddresses()
    {
        IPAddress[] addresses = [
            IPAddress.Parse("::1"),
            IPAddress.Parse("127.0.0.1"),
            IPAddress.Parse("127.0.0.2"),
            IPAddress.Parse("::2"),
        ];

        Security.SsrfSocketsHttpHandlerFactory.SortIpAddressListByFamily(addresses, AddressFamily.InterNetworkV6);

        Assert.Equal(AddressFamily.InterNetworkV6, addresses[0].AddressFamily);
        Assert.Equal(AddressFamily.InterNetworkV6, addresses[1].AddressFamily);
        Assert.Equal(AddressFamily.InterNetwork, addresses[2].AddressFamily);
        Assert.Equal(AddressFamily.InterNetwork, addresses[3].AddressFamily);
    }
}
