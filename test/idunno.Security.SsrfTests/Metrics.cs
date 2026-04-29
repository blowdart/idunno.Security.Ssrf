// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Diagnostics.Metrics;
using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.Metrics.Testing;

namespace idunno.Security.SsrfTests;

public class Metrics
{
    private const string BlockedRequestsInstrumentName = "idunno.security.ssrf.blocked.requests.total";
    private const string UnsafeUriInstrumentName = "idunno.security.ssrf.unsafe.uri.total";
    private const string UnsafeIPAddressInstrumentName = "idunno.security.ssrf.unsafe.ip_address.total";

    [Fact]
    public void IsUnsafeUriIncrementsMetricsWithHttpUri()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.True(Ssrf.IsUnsafeUri(new Uri($"http://loopback.ssrf.fail/"), metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Single(unsafeUriMeasurements);
        Assert.True(unsafeUriMeasurements[0].ContainsTags("reason"));
        Assert.Equal("unsafe_scheme", unsafeUriMeasurements[0].Tags["reason"]);
        Assert.True(unsafeUriMeasurements[0].ContainsTags("value"));
        Assert.Equal("http", unsafeUriMeasurements[0].Tags["value"]);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeIpAddressMeasurements);
    }

    [Fact]
    public void IsUnsafeUriIncrementsMetricsWithWsUri()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.True(Ssrf.IsUnsafeUri(new Uri($"ws://loopback.ssrf.fail/"), metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Single(unsafeUriMeasurements);
        Assert.True(unsafeUriMeasurements[0].ContainsTags("reason"));
        Assert.Equal("unsafe_scheme", unsafeUriMeasurements[0].Tags["reason"]);
        Assert.True(unsafeUriMeasurements[0].ContainsTags("value"));
        Assert.Equal("ws", unsafeUriMeasurements[0].Tags["value"]);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeIpAddressMeasurements);
    }

    [Fact]
    public void IsUnsafeUriDoesNotIncrementMetricsWithHttpsUri()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.False(Ssrf.IsUnsafeUri(new Uri($"https://loopback.ssrf.fail/"), metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeUriMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeIpAddressMeasurements);
    }

    [Fact]
    public void IsUnsafeUriDoesNotIncrementMetricsWithWssUri()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.False(Ssrf.IsUnsafeUri(new Uri($"wss://loopback.ssrf.fail/"), metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeUriMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeIpAddressMeasurements);
    }

    [Fact]
    public void IsUnsafeUriIncrementsMetricsWithRelativeUri()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.True(Ssrf.IsUnsafeUri(new Uri($"/home", UriKind.Relative), metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Single(unsafeUriMeasurements);
        Assert.True(unsafeUriMeasurements[0].ContainsTags("reason"));
        Assert.Equal("not_absolute_uri", unsafeUriMeasurements[0].Tags["reason"]);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeIpAddressMeasurements);
    }

    [Fact]
    public void IsUnsafeUriIncrementsMetricsWithUnc()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.True(Ssrf.IsUnsafeUri(new Uri($"\\\\server\\path"), metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Single(unsafeUriMeasurements);
        Assert.True(unsafeUriMeasurements[0].ContainsTags("reason"));
        Assert.Equal("unc_uri", unsafeUriMeasurements[0].Tags["reason"]);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeIpAddressMeasurements);
    }

    [Fact]
    public void IsUnsafeUriIncrementsMetricsWithLoopback()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.True(Ssrf.IsUnsafeUri(new Uri($"https://localhost"), metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Single(unsafeUriMeasurements);
        Assert.True(unsafeUriMeasurements[0].ContainsTags("reason"));
        Assert.Equal("loopback_uri", unsafeUriMeasurements[0].Tags["reason"]);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeIpAddressMeasurements);
    }

    [Fact]
    public void IsUnsafeUriIncrementsMetricsWithUnknownAddressFamily()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.True(Ssrf.IsUnsafeUri(new Uri("ms-teams:foo"), metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Single(unsafeUriMeasurements);
        Assert.True(unsafeUriMeasurements[0].ContainsTags("reason"));
        Assert.Equal("unknown_host_name_type", unsafeUriMeasurements[0].Tags["reason"]);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeIpAddressMeasurements);
    }

    [Fact]
    public void IsUnsafeUriIncrementsMetricsWithUnknownScheme()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.True(Ssrf.IsUnsafeUri(new Uri("gopher://example.org"), metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Single(unsafeUriMeasurements);
        Assert.True(unsafeUriMeasurements[0].ContainsTags("reason"));
        Assert.Equal("unsafe_scheme", unsafeUriMeasurements[0].Tags["reason"]);
        Assert.True(unsafeUriMeasurements[0].ContainsTags("value"));
        Assert.Equal("gopher", unsafeUriMeasurements[0].Tags["value"]);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeIpAddressMeasurements);
    }

    [Fact]
    public void IsUnsafeUriIncrementsMetricsWithCredentialContainingUri()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.True(Ssrf.IsUnsafeUri(new Uri("https://user:password@example.org"), metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Single(unsafeUriMeasurements);
        Assert.True(unsafeUriMeasurements[0].ContainsTags("reason"));
        Assert.Equal("user_info_uri", unsafeUriMeasurements[0].Tags["reason"]);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeIpAddressMeasurements);
    }

    [Fact]
    public void IsUnsafeIpAddressDoesNotIncrementMetricsIfUnsafeIpAddressIsInSafeIpAddressCollection()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.False(Ssrf.IsUnsafeIpAddress(IPAddress.Parse("10.0.0.1"), safeIPAddresses: [IPAddress.Parse("10.0.0.1")], metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeUriMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeIpAddressMeasurements);
    }

    [Fact]
    public void IsUnsafeIpAddressDoesNotIncrementMetricsIfUnsafeIpAddressIsInSafeIpNetworksCollection()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.False(Ssrf.IsUnsafeIpAddress(IPAddress.Parse("10.0.0.1"), safeIPNetworks: [IPNetwork.Parse("10.0.0.0/8")], metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeUriMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeIpAddressMeasurements);
    }

    [Fact]
    public void IsUnsafeIpAddressDoesNotIncrementMetricsIfIpv4LoopbackAndLoopbackAllowed()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.False(Ssrf.IsUnsafeIpAddress(IPAddress.Parse("127.0.0.1"), allowLoopback: true, metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeUriMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeIpAddressMeasurements);
    }

    [Fact]
    public void IsUnsafeIpAddressDoesNotIncrementMetricsIfIpv6LoopbackAndLoopbackAllowed()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.False(Ssrf.IsUnsafeIpAddress(IPAddress.Parse("::1"), allowLoopback: true, metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeUriMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeIpAddressMeasurements);
    }

    [Fact]
    public void IsUnsafeIpAddressIncrementsMetricsIfIpAddressIsInAdditionalUnsafeIpAddressCollection()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse("1.2.3.4"), additionalUnsafeIPAddresses: [IPAddress.Parse("1.2.3.4")], metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeUriMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Single(unsafeIpAddressMeasurements);
        Assert.True(unsafeIpAddressMeasurements[0].ContainsTags("reason"));
        Assert.Equal("in_additional_unsafe_ip_addresses", unsafeIpAddressMeasurements[0].Tags["reason"]);
    }

    [Fact]
    public void IsUnsafeIpAddressIncrementsMetricsIfIpAddressIsInAdditionalUnsafeIpNetworkCollection()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse("1.2.3.4"), additionalUnsafeIPNetworks: [IPNetwork.Parse("1.2.0.0/16")], metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeUriMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Single(unsafeIpAddressMeasurements);
        Assert.True(unsafeIpAddressMeasurements[0].ContainsTags("reason"));
        Assert.Equal("in_additional_unsafe_ip_networks", unsafeIpAddressMeasurements[0].Tags["reason"]);
    }

    [InlineData("127.0.0.1")]
    [InlineData("127.0.0.2")]
    [InlineData("::1")]
    [Theory]
    public void IsUnsafeIpAddressIncrementsMetricsIfIpAddressIsLoopback(string ipAddressAsString)
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString), metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeUriMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Single(unsafeIpAddressMeasurements);
        Assert.True(unsafeIpAddressMeasurements[0].ContainsTags("reason"));
        Assert.Equal("loopback", unsafeIpAddressMeasurements[0].Tags["reason"]);
    }

    [Fact]
    public void IsUnsafeIpAddressIncrementsMetricsIfIpAddressIsNone()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.IPv6None, metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeUriMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Single(unsafeIpAddressMeasurements);
        Assert.True(unsafeIpAddressMeasurements[0].ContainsTags("reason"));
        Assert.Equal("ip_none", unsafeIpAddressMeasurements[0].Tags["reason"]);
    }

    [Fact]
    public void IsUnsafeIpAddressIncrementsMetricsIfIpv4AddressInBuiltInUnsafeCollection()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse("10.0.0.1"), metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeUriMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Single(unsafeIpAddressMeasurements);
        Assert.True(unsafeIpAddressMeasurements[0].ContainsTags("reason"));
        Assert.Equal("in_default_blocks", unsafeIpAddressMeasurements[0].Tags["reason"]);
    }

    [Fact]
    public void IsUnsafeIpAddressIncrementsMetricsIfIpv6AddressInBuiltInUnsafeCollection()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse("2001:db8::1"), metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeUriMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Single(unsafeIpAddressMeasurements);
        Assert.True(unsafeIpAddressMeasurements[0].ContainsTags("reason"));
        Assert.Equal("in_default_blocks", unsafeIpAddressMeasurements[0].Tags["reason"]);
    }

    [Fact]
    public void IsUnsafeIpAddressIncrementsMetricsIfIpv6AddressIsMulticast()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse("ff02::1"), metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeUriMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Single(unsafeIpAddressMeasurements);
        Assert.True(unsafeIpAddressMeasurements[0].ContainsTags("reason"));
        Assert.Equal("ipv6_multicast", unsafeIpAddressMeasurements[0].Tags["reason"]);
    }

    [Fact]
    public void IsUnsafeIpAddressIncrementsMetricsIfIpv6AddressIsLocal()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();
        SsrfMetrics metrics = services.GetRequiredService<SsrfMetrics>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);
        var unsafeUriCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeUriInstrumentName);
        var unsafeIpAddressCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, UnsafeIPAddressInstrumentName);

        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Parse("fd12:3456:789a:1::1"), metrics: metrics));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Empty(blockedRequestMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeUriMeasurements = unsafeUriCounter.GetMeasurementSnapshot();
        Assert.Empty(unsafeUriMeasurements);

        IReadOnlyList<CollectedMeasurement<long>> unsafeIpAddressMeasurements = unsafeIpAddressCounter.GetMeasurementSnapshot();
        Assert.Single(unsafeIpAddressMeasurements);
        Assert.True(unsafeIpAddressMeasurements[0].ContainsTags("reason"));
        Assert.Equal("ipv6_local", unsafeIpAddressMeasurements[0].Tags["reason"]);
    }

    [Fact]
    public async Task SsrfSocketsHttpHandlerFactoryIncrementsBlockedRequestsMetric()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);

        using HttpClient httpClient = new(Security.SsrfSocketsHttpHandlerFactory.Create(connectTimeout: new TimeSpan(0, 0, 5), meterFactory: meterFactory));
        HttpRequestException ex = await Assert.ThrowsAsync<HttpRequestException>(
            async () => _ = await httpClient.GetAsync(new Uri("https://loopback.ssrf.fail"), cancellationToken: TestContext.Current.CancellationToken));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Single(blockedRequestMeasurements);
    }

    [Fact]
    public async Task ProxiedSsrfDelegatingHandlerIncrementsBlockedRequestsMetric()
    {
        IServiceProvider services = CreateServiceProvider();
        IMeterFactory meterFactory = services.GetRequiredService<IMeterFactory>();

        var blockedRequestsCounter = new MetricCollector<long>(meterFactory, SsrfMetrics.MeterName, BlockedRequestsInstrumentName);

        var proxiedSsrfDelegatingHandler = new Security.ProxiedSsrfDelegatingHandler(
            connectTimeout: TimeSpan.FromSeconds(1),
            proxy: new WebProxy(new Uri("http://127.0.0.1:9999")),
            meterFactory: meterFactory);
        using HttpClient httpClient = new(proxiedSsrfDelegatingHandler);
        SsrfException ex = await Assert.ThrowsAsync<SsrfException>(async () => _ = await httpClient.GetAsync(new Uri("https://loopback.ssrf.fail"), cancellationToken: TestContext.Current.CancellationToken));

        IReadOnlyList<CollectedMeasurement<long>> blockedRequestMeasurements = blockedRequestsCounter.GetMeasurementSnapshot();
        Assert.Single(blockedRequestMeasurements);
    }

    private static ServiceProvider CreateServiceProvider()
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddMetrics();
        serviceCollection.AddSingleton<SsrfMetrics>();
        return serviceCollection.BuildServiceProvider();
    }
}
