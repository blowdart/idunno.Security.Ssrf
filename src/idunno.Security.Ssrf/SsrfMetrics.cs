// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Metrics;
using System.Net.WebSockets;

namespace idunno.Security;

/// <summary>
/// Metrics for SSRF detection and prevention.
/// </summary>
public sealed class SsrfMetrics
{
    // For non-DI scenarios, see https://learn.microsoft.com/en-us/dotnet/core/diagnostics/metrics-instrumentation#best-practices
    private static readonly Meter s_meter = new(MeterName, MeterVersion);

    private const string ReasonTagName = "reason";
    private const string ValueTagName = "value";

    // Precompute the counter names once. These are derived from the meter name and were previously
    // recomputed (three ToLowerInvariant calls plus three string interpolations) on every handler
    // construction inside CreateCounters.
    [SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "Guidelines suggest all lower case.")]
    private static readonly string s_meterNameLowerInvariant = MeterName.ToLowerInvariant();
    private static readonly string s_blockedRequestsCounterName = $"{s_meterNameLowerInvariant}.blocked.requests.total";
    private static readonly string s_unsafeUriCounterName = $"{s_meterNameLowerInvariant}.unsafe.uri.total";
    private static readonly string s_unsafeIPAddressCounterName = $"{s_meterNameLowerInvariant}.unsafe.ip_address.total";

    private Counter<long> _blockedRequests;
    private Counter<long> _unsafeUri;
    private Counter<long> _unsafeIPAddress;

    /// <summary>
    /// Creates a new instance of <see cref="SsrfMetrics"/>.
    /// </summary>
    /// <param name="meterFactory">The <see cref="IMeterFactory"/> to use to create meters.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="meterFactory"/> is <see langword="null"/>.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = " IMeterFactory automatically manages the lifetime of any Meter objects it creates")]
    public SsrfMetrics(IMeterFactory? meterFactory = null)
    {
        if (meterFactory == null)
        {
            CreateCounters(s_meter);
        }
        else
        {
            CreateCounters(meterFactory.Create(MeterName, MeterVersion));
        }
    }

    /// <summary>
    /// Gets the meter name publishing metrics.
    /// </summary>
    public static string MeterName => "idunno.Security.Ssrf";

    /// <summary>
    /// Gets the current version of the meter.
    /// </summary>
    public static string MeterVersion => "1.0.0";

    internal void IncrementBlockedRequests(int count = 1)
    {
        _blockedRequests.Add(count);
    }

    internal void IncrementUnsafeUri(int count = 1, string? reason = default, string? value = default)
    {
        if (string.IsNullOrEmpty(value))
        {
            _unsafeUri.Add(count, new KeyValuePair<string, object?>(ReasonTagName, reason));
        }
        else
        {
            _unsafeUri.Add(count, new KeyValuePair<string, object?>(ReasonTagName, reason), new KeyValuePair<string, object?>(ValueTagName, value));

        }
    }

    internal void IncrementUnsafeIPAddress(int count = 1, string? reason = default)
    {
        _unsafeIPAddress.Add(count, new KeyValuePair<string, object?>(ReasonTagName, reason));
    }

    [MemberNotNull(nameof(_blockedRequests), nameof(_unsafeUri), nameof(_unsafeIPAddress))]
    private void CreateCounters(Meter meter)
    {
        _blockedRequests = meter.CreateCounter<long>(
            name: s_blockedRequestsCounterName,
            description: "Number of requests blocked due to SSRF detection.",
            unit: "{requests}");

        _unsafeUri = meter.CreateCounter<long>(
            name: s_unsafeUriCounterName,
            description: "Number of unsafe URIs detected.",
            unit: "{uris}");

        _unsafeIPAddress = meter.CreateCounter<long>(
            name: s_unsafeIPAddressCounterName,
            description: "Number of unsafe IP addresses detected.",
            unit: "{ip_addresses}");
    }
}
