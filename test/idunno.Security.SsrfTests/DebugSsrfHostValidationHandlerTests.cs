// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace idunno.Security.SsrfTests;

public class DebugSsrfHostValidationHandlerTests
{
    [Theory]
    [InlineData("http://localhost/")]
    [InlineData("https://localhost/")]
    [InlineData("https://bad.ssrf.fail/")]
    [InlineData("https://bad.ipv4.ssrf.fail/")]
    [InlineData("https://bad.ipv6.ssrf.fail/")]
    public async Task ConnectionThrowsForUnsafeUri(string hostName)
    {
        using var debugSsrfHostValidationHandler = new DebugSsrfHostValidationHandler(
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true)
        {
            InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
                 connectionStrategy: ConnectionStrategy.None,
                 additionalUnsafeNetworks: null,
                 additionalUnsafeIpAddresses: null,
                 connectTimeout: TimeSpan.FromSeconds(1),
                 allowInsecureProtocols: true,
                 allowLoopback: true,
                 failMixedResults: true,
                 allowAutoRedirect: false,
                 automaticDecompression: DecompressionMethods.All,
                 proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
                 sslOptions: null,
                 loggerFactory: null)
        };
        using HttpClient httpClient = new(debugSsrfHostValidationHandler);
        SsrfException ex = await Assert.ThrowsAsync<SsrfException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));

        Assert.Equal(hostName, ex.Uri!.ToString());
    }


    [Theory]
    [InlineData("https://mixed.ssrf.fail/")]
    [InlineData("https://mixed.ipv4.ssrf.fail/")]
    [InlineData("https://mixed.ipv6.ssrf.fail/")]
    public async Task ConnectionThrowsForHostsThatReturnAMixOfSafeAndUnsafeIPAddresses(string hostName)
    {
        using var debugSsrfHostValidationHandler = new DebugSsrfHostValidationHandler(
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true)
        {
            InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
                 connectionStrategy: ConnectionStrategy.None,
                 additionalUnsafeNetworks: null,
                 additionalUnsafeIpAddresses: null,
                 connectTimeout: TimeSpan.FromSeconds(1),
                 allowInsecureProtocols: true,
                 allowLoopback: true,
                 failMixedResults: true,
                 allowAutoRedirect: false,
                 automaticDecompression: DecompressionMethods.All,
                 proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
                 sslOptions: null,
                 loggerFactory: null)
        };
        using HttpClient httpClient = new(debugSsrfHostValidationHandler);
        SsrfException ex = await Assert.ThrowsAsync<SsrfException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));

        Assert.Equal(hostName, ex.Uri!.ToString());
    }

    [Theory]
    [InlineData("https://mixed.ssrf.fail/")]
    [InlineData("https://mixed.ipv4.ssrf.fail/")]
    [InlineData("https://mixed.ipv6.ssrf.fail/")]
    public async Task ConnectionContinuesForHostsThatReturnAMixOfSafeAndUnsafeIPAddressesIfFailMixedResultsIsFalse(string hostName)
    {
        using var debugSsrfHostValidationHandler = new DebugSsrfHostValidationHandler(
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: false)
        {
            InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
                 connectionStrategy: ConnectionStrategy.None,
                 additionalUnsafeNetworks: null,
                 additionalUnsafeIpAddresses: null,
                 connectTimeout: TimeSpan.FromSeconds(1),
                 allowInsecureProtocols: true,
                 allowLoopback: true,
                 failMixedResults: true,
                 allowAutoRedirect: false,
                 automaticDecompression: DecompressionMethods.All,
                 proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
                 sslOptions: null,
                 loggerFactory: null)
        };
        using HttpClient httpClient = new(debugSsrfHostValidationHandler);

        TaskCanceledException ex = await Assert.ThrowsAsync<TaskCanceledException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Assert.IsType<TimeoutException>(ex.InnerException);
    }

    [Theory]
    [InlineData("https://example.org/")]
    [InlineData("https://github.com/")]
    public async Task ConnectionSucceedsForSafeUri(string hostName)
    {
        using var debugSsrfHostValidationHandler = new DebugSsrfHostValidationHandler(
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true)
        {
            InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
                 connectionStrategy: ConnectionStrategy.None,
                 additionalUnsafeNetworks: null,
                 additionalUnsafeIpAddresses: null,
                 connectTimeout: TimeSpan.FromSeconds(1),
                 allowInsecureProtocols: true,
                 allowLoopback: true,
                 failMixedResults: true,
                 allowAutoRedirect: false,
                 automaticDecompression: DecompressionMethods.All,
                 proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
                 sslOptions: null,
                 loggerFactory: null)
        };
        using HttpClient httpClient = new(debugSsrfHostValidationHandler);
        TaskCanceledException ex = await Assert.ThrowsAsync<TaskCanceledException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Assert.IsType<TimeoutException>(ex.InnerException);
    }

    [Theory]
    [InlineData("http://example.org/")]
    [InlineData("http://github.com/")]
    public async Task ConnectionThrowsForSafeHostButUnsafeProtocol(string hostName)
    {
        using var debugSsrfHostValidationHandler = new DebugSsrfHostValidationHandler(
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true)
        {
            InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
                 connectionStrategy: ConnectionStrategy.None,
                 additionalUnsafeNetworks: null,
                 additionalUnsafeIpAddresses: null,
                 connectTimeout: TimeSpan.FromSeconds(1),
                 allowInsecureProtocols: true,
                 allowLoopback: true,
                 failMixedResults: true,
                 allowAutoRedirect: false,
                 automaticDecompression: DecompressionMethods.All,
                 proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
                 sslOptions: null,
                 loggerFactory: null)
        };
        using HttpClient httpClient = new(debugSsrfHostValidationHandler);
        SsrfException ex = await Assert.ThrowsAsync<SsrfException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));

        Assert.Equal(hostName, ex.Uri!.ToString());
    }

    [Theory]
    [InlineData("http://example.org/")]
    [InlineData("http://github.com/")]
    public async Task ConnectionDoesNotThrowForSafeHostButUnsafeProtocolIfAllowInsecureProtocolIsTrue(string hostName)
    {
        using var debugSsrfHostValidationHandler = new DebugSsrfHostValidationHandler(
            allowInsecureProtocols: true,
            allowLoopback: false,
            failMixedResults: true)
        {
            InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
                 connectionStrategy: ConnectionStrategy.None,
                 additionalUnsafeNetworks: null,
                 additionalUnsafeIpAddresses: null,
                 connectTimeout: TimeSpan.FromSeconds(1),
                 allowInsecureProtocols: true,
                 allowLoopback: true,
                 failMixedResults: true,
                 allowAutoRedirect: false,
                 automaticDecompression: DecompressionMethods.All,
                 proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
                 sslOptions: null,
                 loggerFactory: null)
        };
        using HttpClient httpClient = new(debugSsrfHostValidationHandler);

        TaskCanceledException ex = await Assert.ThrowsAsync<TaskCanceledException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Assert.IsType<TimeoutException>(ex.InnerException);
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

        using var debugSsrfHostValidationHandler = new DebugSsrfHostValidationHandler(
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: [IPAddress.Parse("1.2.3.4")],
            allowInsecureProtocols: true,
            allowLoopback: false,
            failMixedResults: true,
            hostEntryResolver: hostEntryResolver,
            asyncHostEntryResolver : asyncHostEntryResolver,
            loggerFactory: null)
        {
            InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
                 connectionStrategy: ConnectionStrategy.None,
                 additionalUnsafeNetworks: null,
                 additionalUnsafeIpAddresses: null,
                 connectTimeout: TimeSpan.FromSeconds(1),
                 allowInsecureProtocols: true,
                 allowLoopback: true,
                 failMixedResults: true,
                 allowAutoRedirect: false,
                 automaticDecompression: DecompressionMethods.All,
                 proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
                 sslOptions: null,
                 loggerFactory: null)
        };
        using HttpClient httpClient = new(debugSsrfHostValidationHandler);

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

        using var debugSsrfHostValidationHandler = new DebugSsrfHostValidationHandler(
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: [IPAddress.Parse("2606:4700::6812:1b78")],
            allowInsecureProtocols: true,
            allowLoopback: false,
            failMixedResults: true,
            hostEntryResolver: hostEntryResolver,
            asyncHostEntryResolver: asyncHostEntryResolver,
            loggerFactory: null)
        {
            InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
                 connectionStrategy: ConnectionStrategy.None,
                 additionalUnsafeNetworks: null,
                 additionalUnsafeIpAddresses: null,
                 connectTimeout: TimeSpan.FromSeconds(1),
                 allowInsecureProtocols: true,
                 allowLoopback: true,
                 failMixedResults: true,
                 allowAutoRedirect: false,
                 automaticDecompression: DecompressionMethods.All,
                 proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
                 sslOptions: null,
                 loggerFactory: null)
        };
        using HttpClient httpClient = new(debugSsrfHostValidationHandler);

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

        using var debugSsrfHostValidationHandler = new DebugSsrfHostValidationHandler(
            additionalUnsafeNetworks: [IPNetwork.Parse("1.2.3.0/24")],
            additionalUnsafeIpAddresses: null,
            allowInsecureProtocols: true,
            allowLoopback: false,
            failMixedResults: true,
            hostEntryResolver: hostEntryResolver,
            asyncHostEntryResolver: asyncHostEntryResolver,
            loggerFactory: null)
        {
            InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
                 connectionStrategy: ConnectionStrategy.None,
                 additionalUnsafeNetworks: null,
                 additionalUnsafeIpAddresses: null,
                 connectTimeout: TimeSpan.FromSeconds(1),
                 allowInsecureProtocols: true,
                 allowLoopback: true,
                 failMixedResults: true,
                 allowAutoRedirect: false,
                 automaticDecompression: DecompressionMethods.All,
                 proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
                 sslOptions: null,
                 loggerFactory: null)
        };
        using HttpClient httpClient = new(debugSsrfHostValidationHandler);

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

        using var debugSsrfHostValidationHandler = new DebugSsrfHostValidationHandler(
            additionalUnsafeNetworks: [IPNetwork.Parse("2620:1ec::/36")],
            additionalUnsafeIpAddresses: null,
            allowInsecureProtocols: true,
            allowLoopback: false,
            failMixedResults: true,
            hostEntryResolver: hostEntryResolver,
            asyncHostEntryResolver: asyncHostEntryResolver,
            loggerFactory: null)
        {
            InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
                 connectionStrategy: ConnectionStrategy.None,
                 additionalUnsafeNetworks: null,
                 additionalUnsafeIpAddresses: null,
                 connectTimeout: TimeSpan.FromSeconds(1),
                 allowInsecureProtocols: true,
                 allowLoopback: true,
                 failMixedResults: true,
                 allowAutoRedirect: false,
                 automaticDecompression: DecompressionMethods.All,
                 proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
                 sslOptions: null,
                 loggerFactory: null)
        };
        using HttpClient httpClient = new(debugSsrfHostValidationHandler);

        SsrfException ex = await Assert.ThrowsAsync<SsrfException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(hostName, ex.Uri!.ToString());
    }

    [Fact]
    public async Task ConnectionFailsWhenOptionsAreUsed()
    {
        string hostName = "https://example.org/";

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
            Proxy = new WebProxy(new Uri("http://127.0.0.1:9999")),
            SslOptions = null
        };

        using var debugSsrfHostValidationHandler = new DebugSsrfHostValidationHandler(options)
        {
            InnerHandler = SsrfSocketsHttpHandlerFactory.Create(options)
        };
        using HttpClient httpClient = new(debugSsrfHostValidationHandler);

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

        using var debugSsrfHostValidationHandler = new DebugSsrfHostValidationHandler(
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            hostEntryResolver: hostEntryResolver,
            asyncHostEntryResolver: asyncHostEntryResolver,
            loggerFactory: null)
        {
            InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
                 connectionStrategy: ConnectionStrategy.None,
                 additionalUnsafeNetworks: null,
                 additionalUnsafeIpAddresses: null,
                 connectTimeout: TimeSpan.FromSeconds(1),
                 allowInsecureProtocols: true,
                 allowLoopback: true,
                 failMixedResults: true,
                 allowAutoRedirect: false,
                 automaticDecompression: DecompressionMethods.All,
                 proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
                 sslOptions: null,
                 loggerFactory: null)
        };
        using HttpClient httpClient = new(debugSsrfHostValidationHandler);

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
        using var debugSsrfHostValidationHandler = new DebugSsrfHostValidationHandler(
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowInsecureProtocols: true,
            allowLoopback: true,
            failMixedResults: true,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: null)
        {
            InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
                 connectionStrategy: ConnectionStrategy.None,
                 additionalUnsafeNetworks: null,
                 additionalUnsafeIpAddresses: null,
                 connectTimeout: TimeSpan.FromSeconds(1),
                 allowInsecureProtocols: true,
                 allowLoopback: true,
                 failMixedResults: true,
                 allowAutoRedirect: false,
                 automaticDecompression: DecompressionMethods.All,
                 proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
                 sslOptions: null,
                 loggerFactory: null)
        };
        using HttpClient httpClient = new(debugSsrfHostValidationHandler);

        TaskCanceledException ex = await Assert.ThrowsAsync<TaskCanceledException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Assert.IsType<TimeoutException>(ex.InnerException);
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

        using var debugSsrfHostValidationHandler = new DebugSsrfHostValidationHandler(options)
        {
            InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
                 connectionStrategy: ConnectionStrategy.None,
                 additionalUnsafeNetworks: null,
                 additionalUnsafeIpAddresses: null,
                 connectTimeout: TimeSpan.FromSeconds(1),
                 allowInsecureProtocols: true,
                 allowLoopback: true,
                 failMixedResults: true,
                 allowAutoRedirect: false,
                 automaticDecompression: DecompressionMethods.All,
                 proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
                 sslOptions: null,
                 loggerFactory: null)
        };
        using HttpClient httpClient = new(debugSsrfHostValidationHandler);

        TaskCanceledException ex = await Assert.ThrowsAsync<TaskCanceledException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Assert.IsType<TimeoutException>(ex.InnerException);
    }

    [Theory]
    [InlineData("http://localhost/")]
    [InlineData("http://127.0.0.1/")]
    [InlineData("http://127.255.255.254/")]
    [InlineData("http://[::1]/")]
    public async Task ConnectionThrowsForInsecureLoopbackHostWhenAllowLoopbackIsSetButAllowInsecureIsFalse(string hostName)
    {
        using var debugSsrfHostValidationHandler = new DebugSsrfHostValidationHandler(
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowInsecureProtocols: false,
            allowLoopback: true,
            failMixedResults: true,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: null)
        {
            InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
                 connectionStrategy: ConnectionStrategy.None,
                 additionalUnsafeNetworks: null,
                 additionalUnsafeIpAddresses: null,
                 connectTimeout: TimeSpan.FromSeconds(1),
                 allowInsecureProtocols: true,
                 allowLoopback: true,
                 failMixedResults: true,
                 allowAutoRedirect: false,
                 automaticDecompression: DecompressionMethods.All,
                 proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
                 sslOptions: null,
                 loggerFactory: null)
        };
        using HttpClient httpClient = new(debugSsrfHostValidationHandler);

        SsrfException asyncEx = await Assert.ThrowsAsync<SsrfException>(async () => _ = await httpClient.GetAsync(hostName, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(hostName, asyncEx.Uri!.ToString());
    }
}
