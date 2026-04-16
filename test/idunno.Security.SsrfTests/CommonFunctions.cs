// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace idunno.Security.SsrfTests;

public class CommonFunctions
{
    [Fact]
    public void ResolveAndReturnSafeIPAddressesThrowsIfNoUriIsSpecified()
    {
        ILogger logger = NullLoggerFactory.Instance.CreateLogger<SsrfSocketsHttpHandlerFactory>();
        SsrfMetrics metrics = new();

        static IPHostEntry hostEntryResolver(string host)
        {
            return new IPHostEntry
            {
                AddressList =
                [
                    IPAddress.Parse("1.2.3.4")
                ]
            };
        }

        Uri uri = null!;

        ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => Security.CommonFunctions.ResolveAndReturnSafeIPAddresses(
            uri: uri,
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: null,
            safeIPNetworks: null,
            safeIPAddresses: null,
            allowLoopback: false,
            failMixedResults: false,
            logger: logger,
            metrics: metrics,
            hostEntryResolver: hostEntryResolver));
        Assert.Equal("uri", ex.ParamName);
    }


    [Fact]
    public void ResolveAndReturnSafeIPAddressesEarlyExitsIfHostIsInAllowedHostNames()
    {
        IPAddress[] expected =
        [
            IPAddress.Parse("127.0.0.1"),
            IPAddress.Parse("::1")
        ];

        ILogger logger = NullLoggerFactory.Instance.CreateLogger<SsrfSocketsHttpHandlerFactory>();
        SsrfMetrics metrics = new();

        IPHostEntry hostEntryResolver(string host)
        {
            return new IPHostEntry
            {
                AddressList = expected
            };
        }

        IPAddress[] actual = Security.CommonFunctions.ResolveAndReturnSafeIPAddresses(
            uri: new Uri("https://example.com"),
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: ["example.com"],
            safeIPNetworks: null,
            safeIPAddresses: null,
            allowLoopback: false,
            failMixedResults: false,
            logger: logger,
            metrics: metrics,
            hostEntryResolver: hostEntryResolver);

        Assert.Equivalent(expected, actual);
    }

    [Fact]
    public void ResolveAndReturnSafeIPAddressesEarlyExitsIfHostIsMatchedByAWildcardEntryInAllowedHostNames()
    {
        IPAddress[] expected =
        [
            IPAddress.Parse("127.0.0.1"),
            IPAddress.Parse("::1")
        ];

        ILogger logger = NullLoggerFactory.Instance.CreateLogger<SsrfSocketsHttpHandlerFactory>();
        SsrfMetrics metrics = new();

        IPHostEntry hostEntryResolver(string host)
        {
            return new IPHostEntry
            {
                AddressList = expected
            };
        }

        IPAddress[] actual = Security.CommonFunctions.ResolveAndReturnSafeIPAddresses(
            uri: new Uri("https://www.example.com"),
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: ["*.example.com"],
            safeIPNetworks: null,
            safeIPAddresses: null,
            allowLoopback: false,
            failMixedResults: false,
            logger: logger,
            metrics: metrics,
            hostEntryResolver: hostEntryResolver);

        Assert.Equivalent(expected, actual);
    }

    [Fact]
    public void ResolveAndReturnSafeIPAddressesRemovesUnsafeIPAddressesThrowsWhenAllResolvedAddressesAreUnsafe()
    {
        IPAddress[] hostEntries =
        [
            IPAddress.Parse("127.0.0.1"),
            IPAddress.Parse("::1"),
        ];

        ILogger logger = NullLoggerFactory.Instance.CreateLogger<SsrfSocketsHttpHandlerFactory>();
        SsrfMetrics metrics = new();

        IPHostEntry hostEntryResolver(string host)
        {
            return new IPHostEntry
            {
                AddressList = hostEntries
            };
        }

        Assert.Throws<SsrfException>(() => Security.CommonFunctions.ResolveAndReturnSafeIPAddresses(
            uri: new Uri("https://www.example.com"),
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: null,
            safeIPNetworks: null,
            safeIPAddresses: null,
            allowLoopback: false,
            failMixedResults: true,
            logger: logger,
            metrics: metrics,
            hostEntryResolver: hostEntryResolver));
    }

    [Fact]
    public void ResolveAndReturnSafeIPAddressesRemovesUnsafeIPAddressesThrowsWhenFailMixedResultsIsTrueAndResolvedAddressesIsAMix()
    {
        IPAddress[] hostEntries =
        [
            IPAddress.Parse("127.0.0.1"),
            IPAddress.Parse("::1"),
            IPAddress.Parse("1.2.3.4")
        ];

        ILogger logger = NullLoggerFactory.Instance.CreateLogger<SsrfSocketsHttpHandlerFactory>();
        SsrfMetrics metrics = new();

        IPHostEntry hostEntryResolver(string host)
        {
            return new IPHostEntry
            {
                AddressList = hostEntries
            };
        }

        Assert.Throws<SsrfException>(() => Security.CommonFunctions.ResolveAndReturnSafeIPAddresses(
            uri: new Uri("https://www.example.com"),
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: null,
            safeIPNetworks: null,
            safeIPAddresses: null,
            allowLoopback: false,
            failMixedResults: true,
            logger: logger,
            metrics: metrics,
            hostEntryResolver: hostEntryResolver));
    }

    [Fact]
    public void ResolveAndReturnSafeIPAddressesRemovesUnsafeIPAddressesWhenFailMixedResultsIsFalse()
    {
        IPAddress[] hostEntries =
        [
            IPAddress.Parse("127.0.0.1"),
            IPAddress.Parse("::1"),
            IPAddress.Parse("1.2.3.4")
        ];

        ILogger logger = NullLoggerFactory.Instance.CreateLogger<SsrfSocketsHttpHandlerFactory>();
        SsrfMetrics metrics = new();

        IPHostEntry hostEntryResolver(string host)
        {
            return new IPHostEntry
            {
                AddressList = hostEntries
            };
        }

        IPAddress[] actual = Security.CommonFunctions.ResolveAndReturnSafeIPAddresses(
            uri: new Uri("https://www.example.com"),
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: null,
            safeIPNetworks: null,
            safeIPAddresses: null,
            allowLoopback: false,
            failMixedResults: false,
            logger: logger,
            metrics: metrics,
            hostEntryResolver: hostEntryResolver);

        Assert.Single(actual);
        Assert.Equal(IPAddress.Parse("1.2.3.4"), actual[0]);
    }

    [Fact]
    public void ResolveAndReturnSafeIPAddressesNormalizesMappedIpV4AddressesAndThrowsWhenUnsafe()
    {
        ILogger logger = NullLoggerFactory.Instance.CreateLogger<SsrfSocketsHttpHandlerFactory>();
        SsrfMetrics metrics = new();

        static IPHostEntry hostEntryResolver(string host)
        {
            return new IPHostEntry
            {
                AddressList = [IPAddress.Parse("::ffff:127.0.0.1")]
            };
        }

        Assert.Throws<SsrfException>(() => Security.CommonFunctions.ResolveAndReturnSafeIPAddresses(
            uri: new Uri("https://www.example.com"),
            additionalUnsafeIPNetworks: null,
            additionalUnsafeIPAddresses: null,
            allowedHostnames: null,
            safeIPNetworks: null,
            safeIPAddresses: null,
            allowLoopback: false,
            failMixedResults: false,
            logger: logger,
            metrics: metrics,
            hostEntryResolver: hostEntryResolver));
    }

    [Fact]
    public void GetHostEntryAvoidsResolvingTheHostWhenItIsAnIPAddress()
    {
        bool hostEntryResolverCalled = false;

        IPAddress[] hostEntries =
        [
            IPAddress.Parse("2.3.4.5")
        ];

        ILogger logger = NullLoggerFactory.Instance.CreateLogger<SsrfSocketsHttpHandlerFactory>();
        SsrfMetrics metrics = new();

        IPHostEntry hostEntryResolver(string host)
        {
            hostEntryResolverCalled = true;
            return new IPHostEntry
            {
                AddressList = hostEntries
            };
        }

        IPAddress[] actual = Security.CommonFunctions.GetHostEntry(
            uri: new Uri("https://1.2.3.4"),
            logger: logger,
            hostEntryResolver: hostEntryResolver);

        Assert.False(hostEntryResolverCalled);
        Assert.Single(actual);
        Assert.Equal(IPAddress.Parse("1.2.3.4"), actual[0]);
    }

    [Fact]
    public void GetHostEntryThrowsWhenDnsResolutionThrows()
    {
        ILogger logger = NullLoggerFactory.Instance.CreateLogger<SsrfSocketsHttpHandlerFactory>();
        SsrfMetrics metrics = new();

        static IPHostEntry hostEntryResolver(string host)
        {
            throw new NotImplementedException();
        }

        Assert.Throws<SsrfException>(() => Security.CommonFunctions.GetHostEntry(
            uri: new Uri("https://example.com"),
            logger: logger,
            hostEntryResolver: hostEntryResolver));
    }

    [Fact]
    public void GetHostEntryThrowsWhenDnsResolutionReturnsNoEntries()
    {
        ILogger logger = NullLoggerFactory.Instance.CreateLogger<SsrfSocketsHttpHandlerFactory>();
        SsrfMetrics metrics = new();

        static IPHostEntry hostEntryResolver(string host)
        {
            return new IPHostEntry();
        }

        Assert.Throws<SsrfException>(() => Security.CommonFunctions.GetHostEntry(
            uri: new Uri("https://example.com"),
            logger: logger,
            hostEntryResolver: hostEntryResolver));
    }

    [Fact]
    public void GetHostEntryDoesNotWrapOperationCancelledExceptionWhenDnsResolutionThrows()
    {
        ILogger logger = NullLoggerFactory.Instance.CreateLogger<SsrfSocketsHttpHandlerFactory>();
        SsrfMetrics metrics = new();

        static IPHostEntry hostEntryResolver(string host)
        {
            throw new OperationCanceledException();
        }

        Assert.Throws<OperationCanceledException>(() => Security.CommonFunctions.GetHostEntry(
            uri: new Uri("https://example.com"),
            logger: logger,
            hostEntryResolver: hostEntryResolver));
    }

    ///


    [Fact]
    public async Task GetHostEntryAsyncAvoidsResolvingTheHostWhenItIsAnIPAddress()
    {
        bool hostEntryResolverCalled = false;

        IPAddress[] hostEntries =
        [
            IPAddress.Parse("2.3.4.5")
        ];

        ILogger logger = NullLoggerFactory.Instance.CreateLogger<SsrfSocketsHttpHandlerFactory>();
        SsrfMetrics metrics = new();

        async Task<IPHostEntry> asyncHostEntryResolver(string host, CancellationToken cancellationToken    )
        {
            hostEntryResolverCalled = true;
            return new IPHostEntry
            {
                AddressList = hostEntries
            };
        }

        IPAddress[] actual = await Security.CommonFunctions.GetHostEntryAsync(
            uri: new Uri("https://1.2.3.4"),
            logger: logger,
            asyncHostEntryResolver: asyncHostEntryResolver,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(hostEntryResolverCalled);
        Assert.Single(actual);
        Assert.Equal(IPAddress.Parse("1.2.3.4"), actual[0]);
    }

    [Fact]
    public async Task GetHostEntryAsyncThrowsWhenDnsResolutionThrows()
    {
        ILogger logger = NullLoggerFactory.Instance.CreateLogger<SsrfSocketsHttpHandlerFactory>();
        SsrfMetrics metrics = new();

        static async Task<IPHostEntry> asyncHostEntryResolver(string host, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        await Assert.ThrowsAsync<SsrfException>(async () => await Security.CommonFunctions.GetHostEntryAsync(
            uri: new Uri("https://example.com"),
            logger: logger,
            asyncHostEntryResolver: asyncHostEntryResolver,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task GetHostEntryAsyncThrowsWhenDnsResolutionReturnsNoEntries()
    {
        ILogger logger = NullLoggerFactory.Instance.CreateLogger<SsrfSocketsHttpHandlerFactory>();
        SsrfMetrics metrics = new();

        static async Task<IPHostEntry> asyncHostEntryResolver(string host, CancellationToken cancellationToken)
        {
            return new IPHostEntry();
        }

        await Assert.ThrowsAsync<SsrfException>(async () => await Security.CommonFunctions.GetHostEntryAsync(
            uri: new Uri("https://example.com"),
            logger: logger,
            asyncHostEntryResolver: asyncHostEntryResolver,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task GetHostEntryAsyncDoesNotWrapOperationCancelledExceptionWhenDnsResolutionThrows()
    {
        ILogger logger = NullLoggerFactory.Instance.CreateLogger<SsrfSocketsHttpHandlerFactory>();
        SsrfMetrics metrics = new();

        static async Task<IPHostEntry> asyncHostEntryResolver(string host, CancellationToken cancellationToken)
        {
            throw new OperationCanceledException();
        }

        await Assert.ThrowsAsync<OperationCanceledException>(async () => await Security.CommonFunctions.GetHostEntryAsync(
            uri: new Uri("https://example.com"),
            logger: logger,
            asyncHostEntryResolver: asyncHostEntryResolver,
            cancellationToken: TestContext.Current.CancellationToken));
    }

}
