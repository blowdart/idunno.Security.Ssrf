// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;

namespace idunno.Security.SsrfTests;

public class ProxiedSsrfDelegatingHandler
{
    [Theory]
    [InlineData("http://localhost/")]
    [InlineData("https://localhost/")]
    [InlineData("https://bad.ssrf.fail/")]
    [InlineData("https://bad.ipv4.ssrf.fail/")]
    [InlineData("https://bad.ipv6.ssrf.fail/")]
    public async Task ConnectionThrowsForUnsafeUri(string hostName)
    {
        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectTimeout: TimeSpan.FromSeconds(1),
            proxy: new WebProxy(new Uri("http://127.0.0.1:9999")));
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);
        SsrfException ex = await Assert.ThrowsAsync<SsrfException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));

        Assert.Equal(hostName, ex.Uri!.ToString());
    }


    [Theory]
    [InlineData("https://mixed.ssrf.fail/")]
    [InlineData("https://mixed.ipv4.ssrf.fail/")]
    [InlineData("https://mixed.ipv6.ssrf.fail/")]
    public async Task ConnectionThrowsForHostsThatReturnAMixOfSafeAndUnsafeIPAddresses(string hostName)
    {
        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectTimeout: TimeSpan.FromSeconds(1),
            proxy: new WebProxy(new Uri("http://127.0.0.1:9999")));
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);
        SsrfException ex = await Assert.ThrowsAsync<SsrfException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));

        Assert.Equal(hostName, ex.Uri!.ToString());
    }

    [Theory]
    [InlineData("https://mixed.ssrf.fail/")]
    [InlineData("https://mixed.ipv4.ssrf.fail/")]
    [InlineData("https://mixed.ipv6.ssrf.fail/")]
    public async Task ConnectionContinuesForHostsThatReturnAMixOfSafeAndUnsafeIPAddressesIfFailMixedResultsIsFalse(string hostName)
    {
        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectTimeout: TimeSpan.FromSeconds(1),
            failMixedResults: false,
            proxy: new WebProxy(new Uri("http://127.0.0.1:9999")));
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);
        Exception? ex = await Record.ExceptionAsync(async () => await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));

        // Windows and Linux (and probably Mac) throw different exceptions, so check for the lack
        // of an SSRF exception which indicates the connection was let through the SSRF checks.
        Assert.NotNull(ex);
        Assert.IsNotType<SsrfException>(ex);

        while (ex.InnerException is not null)
        {
            ex = ex.InnerException;
            Assert.IsNotType<SsrfException>(ex);
        }
    }

    [Theory]
    [InlineData("https://example.org/")]
    [InlineData("https://github.com/")]
    public async Task ConnectionSucceedsForSafeUri(string hostName)
    {
        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectTimeout: TimeSpan.FromSeconds(1),
            proxy: new WebProxy(new Uri("http://127.0.0.1:9999")));
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);
        Exception? ex = await Record.ExceptionAsync(async () => await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));

        // Windows and Linux (and probably Mac) throw different exceptions, so check for the lack
        // of an SSRF exception which indicates the connection was let through the SSRF checks.
        Assert.NotNull(ex);
        Assert.IsNotType<SsrfException>(ex);

        while (ex.InnerException is not null)
        {
            ex = ex.InnerException;
            Assert.IsNotType<SsrfException>(ex);
        }
    }

    [Theory]
    [InlineData("http://example.org/")]
    [InlineData("http://github.com/")]
    public async Task ConnectionThrowsForSafeHostButUnsafeProtocol(string hostName)
    {
        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectTimeout: TimeSpan.FromSeconds(1),
            proxy: new WebProxy(new Uri("http://127.0.0.1:9999")));
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);
        SsrfException ex = await Assert.ThrowsAsync<SsrfException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));

        Assert.Equal(hostName, ex.Uri!.ToString());
    }

    [Theory]
    [InlineData("http://example.org/")]
    [InlineData("http://github.com/")]
    public async Task ConnectionDoesNotThrowForSafeHostButUnsafeProtocolIfAllowInsecureProtocolIsTrue(string hostName)
    {
        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectTimeout: TimeSpan.FromSeconds(1),
            allowInsecureProtocols: true,
            proxy: new WebProxy(new Uri("http://127.0.0.1:9999")));
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);

        Exception? ex = await Record.ExceptionAsync(async () => await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));

        // Windows and Linux (and probably Mac) throw different exceptions, so check for the lack
        // of an SSRF exception which indicates the connection was let through the SSRF checks.
        Assert.NotNull(ex);
        Assert.IsNotType<SsrfException>(ex);

        while (ex.InnerException is not null)
        {
            ex = ex.InnerException;
            Assert.IsNotType<SsrfException>(ex);
        }
    }

    [Theory]
    [InlineData("https://example.org/")]
    public async Task ConnectionFailsForSafeUriWhichResolveToAdditionalUnsafeIpv4Addresses(string hostName)
    {
        static IPHostEntry hostEntryResolver(string uri)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [IPAddress.Parse("1.2.3.4")]
            };
        }

        static async Task<IPHostEntry> asyncHostEntryResolver(string uri, CancellationToken cancellationToken)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [IPAddress.Parse("1.2.3.4")]
            };
        }

        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: [IPAddress.Parse("1.2.3.4")],
            allowedHostnames: null,
            safeIPNetworks: null,
            safeIPAddresses: null,
            connectTimeout: TimeSpan.FromSeconds(1),
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
            sslOptions: null,
            asyncHostEntryResolver: asyncHostEntryResolver,
            hostEntryResolver: hostEntryResolver,
            loggerFactory: null,
            meterFactory: null);
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);

        SsrfException ex = await Assert.ThrowsAsync<SsrfException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(hostName, ex.Uri!.ToString());
    }

    [Theory]
    [InlineData("https://example.org/")]
    public async Task ConnectionFailsForSafeUriWhichResolveToAdditionalUnsafeIpv6Addresses(string hostName)
    {
        static IPHostEntry hostEntryResolver(string uri)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [IPAddress.Parse("2606:4700::6812:1b78")]
            };
        }

        static async Task<IPHostEntry> asyncHostEntryResolver(string uri, CancellationToken cancellationToken)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [IPAddress.Parse("2606:4700::6812:1b78")]
            };
        }

        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: [IPAddress.Parse("2606:4700::6812:1b78")],
            connectTimeout: TimeSpan.FromSeconds(1),
            allowedHostnames: null,
            safeIPNetworks: null,
            safeIPAddresses: null,
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
            sslOptions: null,
            asyncHostEntryResolver: asyncHostEntryResolver,
            hostEntryResolver: hostEntryResolver,
            loggerFactory: null,
            meterFactory: null);
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);

        SsrfException ex = await Assert.ThrowsAsync<SsrfException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(hostName, ex.Uri!.ToString());
    }

    [Theory]
    [InlineData("https://example.org/")]
    public async Task ConnectionFailsForSafeUriWhichResolveToAdditionalUnsafeIpv4Networks(string hostName)
    {
        static IPHostEntry hostEntryResolver(string uri)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [IPAddress.Parse("1.2.3.4")]
            };
        }

        static async Task<IPHostEntry> asyncHostEntryResolver(string uri, CancellationToken cancellationToken)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [IPAddress.Parse("1.2.3.4")]
            };
        }

        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: [IPNetwork.Parse("1.2.3.0/24")],
            additionalUnsafeIPAddresses: null,
            allowedHostnames: null,
            safeIPNetworks: null,
            safeIPAddresses: null,
            connectTimeout: TimeSpan.FromSeconds(1),
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
            sslOptions: null,
            asyncHostEntryResolver: asyncHostEntryResolver,
            hostEntryResolver: hostEntryResolver,
            loggerFactory: null,
            meterFactory: null);
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);

        SsrfException ex = await Assert.ThrowsAsync<SsrfException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(hostName, ex.Uri!.ToString());
    }

    [Theory]
    [InlineData("https://example.org/")]
    public async Task ConnectionFailsForSafeUriWhichResolveToAdditionalUnsafeIpv6Networks(string hostName)
    {
        static IPHostEntry hostEntryResolver(string uri)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [IPAddress.Parse("[2620:1ec:bdf::69]")]
            };
        }

        static async Task<IPHostEntry> asyncHostEntryResolver(string uri, CancellationToken cancellationToken)
        {
            return new IPHostEntry
            {
                HostName = uri,
                AddressList = [IPAddress.Parse("[2620:1ec:bdf::69]")]
            };
        }

        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: [IPNetwork.Parse("2620:1ec::/36")],
            additionalUnsafeIPAddresses: null,
            allowedHostnames: null,
            safeIPNetworks: null,
            safeIPAddresses: null,
            connectTimeout: TimeSpan.FromSeconds(1),
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
            sslOptions: null,
            asyncHostEntryResolver: asyncHostEntryResolver,
            hostEntryResolver: hostEntryResolver,
            loggerFactory: null,
            meterFactory: null);
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);

        SsrfException ex = await Assert.ThrowsAsync<SsrfException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(hostName, ex.Uri!.ToString());
    }

    [Fact]
    public async Task ConnectionFailsWhenOptionsAreUsed()
    {
        static IPHostEntry hostEntryResolver(string uri)
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

        static async Task<IPHostEntry> asyncHostEntryResolver(string uri, CancellationToken cancellationToken)
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

        string hostName = "https://example.org/";

        SsrfOptions options = new()
        {
            ConnectionStrategy = ConnectionStrategy.None,
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
                IPAddress.Parse("104.18.2.24"),
            ],
            ConnectTimeout = new TimeSpan(0, 0, 5),
            AllowInsecureProtocols = false,
            FailMixedResults = true,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.All,
            Proxy = new WebProxy(new Uri("http://127.0.0.1:9999")),
            SslOptions = null
        };

        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            options:options,
            loggerFactory: null,
            meterFactory: null,
            hostEntryResolver: hostEntryResolver,
            asyncHostEntryResolver: asyncHostEntryResolver)
        {
            InnerHandler = Security.SsrfSocketsHttpHandlerFactory.Create(options)
        };
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);

        SsrfException ex = await Assert.ThrowsAsync<SsrfException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(hostName, ex.Uri!.ToString());
    }

    [Fact]
    public async Task ConnectionFailsWhenDnsResolutionReturnsNoIpAddresses()
    {
        string hostName = "https://example.org/";

        static IPHostEntry hostEntryResolver(string uri)
        {
            return new IPHostEntry();
        }

        static async Task<IPHostEntry> asyncHostEntryResolver(string uri, CancellationToken cancellationToken)
        {
            return new IPHostEntry();
        }

        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: null,
            safeIPNetworks: null,
            safeIPAddresses: null,
            connectTimeout: TimeSpan.FromSeconds(1),
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
            sslOptions: null,
            asyncHostEntryResolver: asyncHostEntryResolver,
            hostEntryResolver: hostEntryResolver,
            loggerFactory: null,
            meterFactory: null);
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);

        SsrfException asyncEx = await Assert.ThrowsAsync<SsrfException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(hostName, asyncEx.Uri!.ToString());

        HttpRequestMessage request = new()
        {
            RequestUri = new Uri(hostName),
            Method = HttpMethod.Get,
        };
        SsrfException syncEx = Assert.Throws<SsrfException>(() => _ = httpClient.Send(request, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(hostName, syncEx.Uri!.ToString());
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
        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectionStrategy: ConnectionStrategy.None,
            connectTimeout: TimeSpan.FromSeconds(1),
            allowInsecureProtocols: true,
            allowLoopback: true,
            automaticDecompression: DecompressionMethods.All,
            proxy: new WebProxy(new Uri("http://127.0.0.1:9999")));
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);

        Exception? ex = await Record.ExceptionAsync(async () => await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));

        // Windows and Linux (and probably Mac) throw different exceptions, so check for the lack
        // of an SSRF exception which indicates the connection was let through the SSRF checks.
        Assert.NotNull(ex);
        Assert.IsNotType<SsrfException>(ex);

        while (ex.InnerException is not null)
        {
            ex = ex.InnerException;
            Assert.IsNotType<SsrfException>(ex);
        }
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
            Proxy = new WebProxy(new Uri("http://127.0.0.1:9999")),
        };

        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(options);
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);

        Exception? ex = await Record.ExceptionAsync(async () => await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));

        // Windows and Linux (and probably Mac) throw different exceptions, so check for the lack
        // of an SSRF exception which indicates the connection was let through the SSRF checks.
        Assert.NotNull(ex);
        Assert.IsNotType<SsrfException>(ex);

        while (ex.InnerException is not null)
        {
            ex = ex.InnerException;
            Assert.IsNotType<SsrfException>(ex);
        }
    }

    [Theory]
    [InlineData("http://localhost/")]
    [InlineData("http://127.0.0.1/")]
    [InlineData("http://127.255.255.254/")]
    [InlineData("http://[::1]/")]
    public async Task ConnectionThrowsForInsecureLoopbackHostWhenAllowLoopbackIsSetButAllowInsecureIsFalse(string hostName)
    {
        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: null,
            connectTimeout: TimeSpan.FromSeconds(1),
            allowInsecureProtocols: false,
            allowLoopback: true,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
            sslOptions: null,
            loggerFactory: null);
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);

        SsrfException asyncEx = await Assert.ThrowsAsync<SsrfException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(hostName, asyncEx.Uri!.ToString());
    }

    [Theory]
    [InlineData("https://localhost/")]
    [InlineData("https://127.0.0.1/")]
    [InlineData("https://[::1]/")]
    public async Task LocalHostGetsRejectedEvenWhenProxyUriIsLocalhost(string hostName)
    {
        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: null,
            connectTimeout: TimeSpan.FromSeconds(1),
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: new WebProxy(new Uri("http://localhost:9999")),
            sslOptions: null,
            loggerFactory: null);
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);
        SsrfException ex = await Assert.ThrowsAsync<SsrfException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));

        Assert.Equal(hostName, ex.Uri!.ToString());
    }

    [Theory]
    [InlineData("https://example.org/")]
    public async Task SafeUriProceedsWhenProxyUriIsLocalhost(string hostName)
    {
        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: null,
            connectTimeout: TimeSpan.FromSeconds(1),
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: new WebProxy(new Uri("http://localhost:9999")),
            sslOptions: null,
            loggerFactory: null);
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);
        Exception? ex = await Record.ExceptionAsync(async () => await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));

        // Windows and Linux (and probably Mac) throw different exceptions, so check for the lack
        // of an SSRF exception which indicates the connection was let through the SSRF checks.
        Assert.NotNull(ex);
        Assert.IsNotType<SsrfException>(ex);

        while (ex.InnerException is not null)
        {
            ex = ex.InnerException;
            Assert.IsNotType<SsrfException>(ex);
        }
    }

    /// ---------------
    ///

    [Fact]
    public async Task ConnectionIsAllowedForIndividualAllowedDomainsEvenIfTheyResolveToAnUnsafeIPAddress()
    {
        var uri = new Uri("https://example.com");
        var allowedHostNames = new List<string> { "example.com", "test.com" };

        static async Task<IPHostEntry> asyncHostEntryResolver(string uri, CancellationToken cancellationToken)
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

        static IPHostEntry hostEntryResolver(string uri)
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

        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: allowedHostNames,
            safeIPNetworks: null,
            safeIPAddresses: null,
            connectTimeout: TimeSpan.FromSeconds(1),
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: new WebProxy(new Uri("http://localhost:9999")),
            sslOptions: null,
            asyncHostEntryResolver: asyncHostEntryResolver,
            hostEntryResolver: hostEntryResolver,
            loggerFactory: null,
            meterFactory: null);
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);
        {
            // Should time out, because the mock resolver is returning loopback addresses, but it shouldn't throw an SsrfException because the hostname is in the allow list.
            Exception? ex = await Record.ExceptionAsync(async () => { await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken); });

            Assert.NotNull(ex);
            Assert.IsNotType<SsrfException>(ex);

            while (ex.InnerException is not null)
            {
                Assert.IsNotType<SsrfException>(ex.InnerException);
                ex = ex.InnerException;
            }
        }
    }

    [Fact]
    public async Task ConnectionIsAllowedForAWildCardAllowedDomainsEvenIfTheyResolveToAnUnsafeIPAddress()
    {
        var uri = new Uri("https://database.example.localhost");
        var allowedHostNames = new List<string> { "*.localhost" };

        static async Task<IPHostEntry> asyncHostEntryResolver(string uri, CancellationToken cancellationToken)
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

        static IPHostEntry hostEntryResolver(string uri)
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

        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: allowedHostNames,
            safeIPNetworks: null,
            safeIPAddresses: null,
            connectTimeout: TimeSpan.FromSeconds(1),
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: new WebProxy(new Uri("http://localhost:9999")),
            sslOptions: null,
            asyncHostEntryResolver: asyncHostEntryResolver,
            hostEntryResolver: hostEntryResolver,
            loggerFactory: null,
            meterFactory: null);
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);
        {
            // Should time out, because the mock resolver is returning loopback addresses, but it shouldn't throw an SsrfException because the hostname is in the allow list.
            Exception? ex = await Record.ExceptionAsync(async () => {
                await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
            });

            Assert.NotNull(ex);
            Assert.IsNotType<SsrfException>(ex);

            while (ex.InnerException is not null)
            {
                Assert.IsNotType<SsrfException>(ex.InnerException);
                ex = ex.InnerException;
            }
        }
    }

    [Fact]
    public async Task ConnectionIsStoppedAWildCardAllowedDomainsIfTheHostIsNotCoveredByTheWildcard()
    {
        var uri = new Uri("https://example.localhost");
        var allowedHostNames = new List<string> { "*.example.localhost" };

        static async Task<IPHostEntry> asyncHostEntryResolver(string uri, CancellationToken cancellationToken)
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

        static IPHostEntry hostEntryResolver(string uri)
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

        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: allowedHostNames,
            safeIPNetworks: null,
            safeIPAddresses: null,
            connectTimeout: TimeSpan.FromSeconds(1),
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: new WebProxy(new Uri("http://localhost:9999")),
            sslOptions: null,
            asyncHostEntryResolver: asyncHostEntryResolver,
            hostEntryResolver: hostEntryResolver,
            loggerFactory: null,
            meterFactory: null);
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);
        {
            Exception? ex = await Record.ExceptionAsync(async () => {
                await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
            });

            Assert.NotNull(ex);
            Assert.IsType<SsrfException>(ex);
        }
    }

    [Fact]
    public async Task ConnectionIsAllowedWithWildCardAllowedDomainsAndASpecificEntryToCoverTheHostEvenIfTheyResolveToAnUnsafeIPAddress()
    {
        var uri = new Uri("https://example.localhost");
        var allowedHostNames = new List<string> { "*.example.localhost", "example.localhost" };

        static async Task<IPHostEntry> asyncHostEntryResolver(string uri, CancellationToken cancellationToken)
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

        static IPHostEntry hostEntryResolver(string uri)
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

        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: allowedHostNames,
            safeIPNetworks: null,
            safeIPAddresses: null,
            connectTimeout: TimeSpan.FromSeconds(1),
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: new WebProxy(new Uri("http://localhost:9999")),
            sslOptions: null,
            asyncHostEntryResolver: asyncHostEntryResolver,
            hostEntryResolver: hostEntryResolver,
            loggerFactory: null,
            meterFactory: null);
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);
        {
            // Should time out, because the mock resolver is returning loopback addresses, but it shouldn't throw an SsrfException because the hostname is in the allow list.
            Exception? ex = await Record.ExceptionAsync(async () => {
                await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
            });

            Assert.NotNull(ex);
            Assert.IsNotType<SsrfException>(ex);

            while (ex.InnerException is not null)
            {
                Assert.IsNotType<SsrfException>(ex.InnerException);
                ex = ex.InnerException;
            }
        }
    }

    [Fact]
    public async Task ConnectionIsAllowedForIndividualAllowedDomainsInOptionsEvenIfTheyResolveToAnUnsafeIPAddress()
    {
        var uri = new Uri("https://loopback.ssrf.fail");
        var allowedHostNames = new List<string> { "loopback.ssrf.fail" };

        SsrfOptions options = new()
        {
            AllowedHostnames = allowedHostNames,
            ConnectTimeout = new TimeSpan(0, 0, 5),
            AutomaticDecompression = DecompressionMethods.All,
        };

        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectionStrategy: ConnectionStrategy.None,
            allowedHostnames: allowedHostNames,
            connectTimeout: TimeSpan.FromSeconds(1),
            proxy: new WebProxy(new Uri("http://localhost:9999")));
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);
        {
            // Should time out, because the mock resolver is returning loopback addresses, but it shouldn't throw an SsrfException because the hostname is in the allow list.
            Exception? ex = await Record.ExceptionAsync(async () => {
                await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
            });

            Assert.NotNull(ex);
            Assert.IsNotType<SsrfException>(ex);

            while (ex.InnerException is not null)
            {
                Assert.IsNotType<SsrfException>(ex.InnerException);
                ex = ex.InnerException;
            }
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

        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            allowedHostnames: allowedHostNames,
            connectTimeout: TimeSpan.FromSeconds(1),
            proxy: new WebProxy(new Uri("http://localhost:9999")));
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);
        {
            // Should time out, because the mock resolver is returning loopback addresses, but it shouldn't throw an SsrfException because the hostname is in the allow list.
            Exception? ex = await Record.ExceptionAsync(async () => {
                await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
            });

            Assert.NotNull(ex);
            Assert.IsNotType<SsrfException>(ex);

            while (ex.InnerException is not null)
            {
                Assert.IsNotType<SsrfException>(ex.InnerException);
                ex = ex.InnerException;
            }
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

        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            allowedHostnames: allowedHostNames,
            connectTimeout: TimeSpan.FromSeconds(1),
            proxy: new WebProxy(new Uri("http://localhost:9999")));
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);
        {
            Exception? ex = await Record.ExceptionAsync(async () => {
                await httpClient.GetAsync(uri, cancellationToken: TestContext.Current.CancellationToken);
            });

            Assert.NotNull(ex);
            Assert.IsType<SsrfException>(ex);
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

        using var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            proxy: new WebProxy(new Uri("http://localhost:9999")),
            allowedHostnames: allowedHostNames,
            connectTimeout: TimeSpan.FromSeconds(1));
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);
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

    //TODO: Add tests for allowedNetworks and allowedIpAddresses in constructor and in options
    [Fact]
    public async Task ConnectionIsAllowedForUnsafeIPAddressIfItIsAlsoInTheSafeIPAddressCollection()
    {
        var uri = new Uri("https://loopback.ssrf.fail");

        var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            proxy: new WebProxy(new Uri("http://localhost:9999")),
            safeIPNetworks: [
                IPNetwork.Parse("127.0.0.0/8"),
                IPNetwork.Parse("::1/128")
            ],
            connectTimeout: TimeSpan.FromSeconds(1));
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);
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

        var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            proxy: new WebProxy(new Uri("http://localhost:9999")),
            safeIPAddresses:
            [
                IPAddress.Parse("127.0.0.1"),
                IPAddress.Parse("::1")
            ],
            connectTimeout: TimeSpan.FromSeconds(1));
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);
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
            ],
            ConnectTimeout = TimeSpan.FromSeconds(1),
            Proxy = new WebProxy(new Uri("http://localhost:9999")),
        };

        var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(options);
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);
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
            ],
            ConnectTimeout = TimeSpan.FromSeconds(1),
            Proxy = new WebProxy(new Uri("http://localhost:9999")),
        };

        var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(options);
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);
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
}
