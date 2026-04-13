// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Net;

using Microsoft.Extensions.Logging;

namespace idunno.Security;

internal static class CommonFunctions
{
    private static readonly Func<string, CancellationToken, Task<IPHostEntry>> s_defaultAsyncHostEntryResolver = Dns.GetHostEntryAsync;
    private static readonly Func<string, IPHostEntry> s_defaultHostEntryResolver = Dns.GetHostEntry;

    [SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with \"LINQ\" expressions", Justification = "Avoid allocations in a hot path.")]
    [SuppressMessage("Style", "IDE0028:Simplify collection initialization", Justification = "Suggested fix is language preview feature in some versions.")]
    internal static async Task<IPAddress[]> ResolveAndReturnSafeIPAddressesAsync(
        Uri uri,
        ICollection<IPNetwork>? additionalUnsafeIPNetworks,
        ICollection<IPAddress>? additionalUnsafeIPAddresses,
        ICollection<string>? allowedHostnames,
        ICollection<IPNetwork>? safeIPNetworks,
        ICollection<IPAddress>? safeIPAddresses,
        bool allowLoopback,
        bool failMixedResults,
        ILogger logger,
        SsrfMetrics? metrics,
        Func<string, CancellationToken, Task<IPHostEntry>> asyncHostEntryResolver,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(uri);
        IPAddress[] resolvedIpAddresses = await GetHostEntryAsync(uri, logger, asyncHostEntryResolver, cancellationToken).ConfigureAwait(false);

        if (Ssrf.IsInAllowedHostnames(uri, allowedHostnames))
        {
            Log.ChecksBypassedForAllowedHostnames(logger, uri);
            return resolvedIpAddresses;
        }
        else
        {
            return ReduceResolvedIPAddressesToSafeIPAddresses(
                uri: uri,
                resolvedIpAddresses: resolvedIpAddresses,
                additionalUnsafeIPNetworks: additionalUnsafeIPNetworks,
                additionalUnsafeIPAddresses: additionalUnsafeIPAddresses,
                safeIPNetworks: safeIPNetworks,
                safeIPAddresses: safeIPAddresses,
                allowLoopback: allowLoopback,
                failMixedResults: failMixedResults,
                logger: logger,
                metrics: metrics);
        }
    }

    internal static async Task<IPAddress[]> GetHostEntryAsync(
        Uri uri,
        ILogger logger,
        Func<string, CancellationToken, Task<IPHostEntry>> asyncHostEntryResolver,
        CancellationToken cancellationToken)
    {
        asyncHostEntryResolver ??= s_defaultAsyncHostEntryResolver;

        IPAddress[] resolvedIpAddresses = [];

        if (IPAddress.TryParse(uri.Host, out IPAddress? parsedAddress))
        {
            resolvedIpAddresses = [parsedAddress];
        }
        else
        {
            try
            {
                IPHostEntry entry = await asyncHostEntryResolver(uri.Host, cancellationToken).ConfigureAwait(false);

                if (entry.AddressList is not null)
                {
                    resolvedIpAddresses = entry.AddressList;
                }
            }
            catch (Exception ex)
            {
                // Some DNS proxies or internal servers may already strip dangerous lookups, so if the host cannot be resolved, we can treat it as unsafe and block the connection.
                Log.DnsResolutionException(logger, uri, ex);
                throw new SsrfException(uri, $"Connection blocked as host could not be resolved.", inner: ex);
            }
        }

        if (resolvedIpAddresses.Length == 0)
        {
            Log.DnsResolutionFailed(logger, uri);
            throw new SsrfException(uri, $"Connection blocked as host could not be resolved to any IP addresses.");
        }

        return resolvedIpAddresses;
    }

    internal static IPAddress[] GetHostEntry(
        Uri uri,
        ILogger logger,
        Func<string, IPHostEntry> hostEntryResolver)
    {
        hostEntryResolver ??= s_defaultHostEntryResolver;

        IPAddress[] resolvedIpAddresses = [];

        if (IPAddress.TryParse(uri.Host, out IPAddress? parsedAddress))
        {
            resolvedIpAddresses = [parsedAddress];
        }
        else
        {
            try
            {
                IPHostEntry entry = hostEntryResolver(uri.Host);

                if (entry.AddressList is not null)
                {
                    resolvedIpAddresses = entry.AddressList;
                }
            }
            catch (Exception ex)
            {
                // Some DNS proxies or internal servers may already strip dangerous lookups, so if the host cannot be resolved, we can treat it as unsafe and block the connection.
                Log.DnsResolutionException(logger, uri, ex);
                throw new SsrfException(uri, $"Connection blocked as host could not be resolved.", inner: ex);
            }
        }

        if (resolvedIpAddresses.Length == 0)
        {
            Log.DnsResolutionFailed(logger, uri);
            throw new SsrfException(uri, $"Connection blocked as host could not be resolved to any IP addresses.");
        }

        return resolvedIpAddresses;
    }

    internal static IPAddress[] ResolveAndReturnSafeIPAddresses(
        Uri uri,
        ICollection<IPNetwork>? additionalUnsafeIPNetworks,
        ICollection<IPAddress>? additionalUnsafeIPAddresses,
        ICollection<string>? allowedHostnames,
        ICollection<IPNetwork>? safeIPNetworks,
        ICollection<IPAddress>? safeIPAddresses,
        bool allowLoopback,
        bool failMixedResults,
        ILogger logger,
        SsrfMetrics? metrics,
        Func<string, IPHostEntry> hostEntryResolver)
    {
        ArgumentNullException.ThrowIfNull(uri);
        IPAddress[] resolvedIpAddresses = GetHostEntry(uri, logger, hostEntryResolver);

        if (Ssrf.IsInAllowedHostnames(uri, allowedHostnames))
        {
            Log.ChecksBypassedForAllowedHostnames(logger, uri);
            return resolvedIpAddresses;
        }
        else
        {
            return ReduceResolvedIPAddressesToSafeIPAddresses(
                uri: uri,
                resolvedIpAddresses: resolvedIpAddresses,
                additionalUnsafeIPNetworks: additionalUnsafeIPNetworks,
                additionalUnsafeIPAddresses: additionalUnsafeIPAddresses,
                safeIPNetworks: safeIPNetworks,
                safeIPAddresses: safeIPAddresses,
                allowLoopback: allowLoopback,
                failMixedResults: failMixedResults,
                logger: logger,
                metrics: metrics);
        }
    }

    [SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with \"LINQ\" expressions", Justification = "Avoid allocations in a hot path.")]
    [SuppressMessage("Style", "IDE0028:Simplify collection initialization", Justification = "Suggested fix is language preview feature in some versions.")]
    private static IPAddress[] ReduceResolvedIPAddressesToSafeIPAddresses(
        Uri uri,
        IPAddress[] resolvedIpAddresses,
        ICollection<IPNetwork>? additionalUnsafeIPNetworks,
        ICollection<IPAddress>? additionalUnsafeIPAddresses,
        ICollection<IPNetwork>? safeIPNetworks,
        ICollection<IPAddress>? safeIPAddresses,
        bool allowLoopback,
        bool failMixedResults,
        ILogger logger,
        SsrfMetrics? metrics)
    {
        // Specify an initial capacity for the list of safe IP addresses based on the number of resolved addresses
        // to avoid multiple resizes as safe addresses are added to the list.
        List<IPAddress> safeResolvedIPAddresses = new(resolvedIpAddresses.Length);

        foreach (IPAddress ipAddress in resolvedIpAddresses)
        {
            if (Ssrf.IsInAllowedNetworks(ipAddress, safeIPNetworks))
            {
                Log.CheckBypassedForIPAddressAsItIsInSafeNetwork(logger, uri, ipAddress);
                safeResolvedIPAddresses.Add(ipAddress);
            }
            else if (Ssrf.IsInAllowedIpAddresses(ipAddress, safeIPAddresses))
            {
                Log.CheckBypassedForIPAddressAsItIsInSafeIpAddresses(logger, uri, ipAddress);
                safeResolvedIPAddresses.Add(ipAddress);
            }
            else if (!Ssrf.IsUnsafeIpAddress(
                ipAddress: ipAddress,
                additionalUnsafeIPNetworks: additionalUnsafeIPNetworks,
                additionalUnsafeIPAddresses: additionalUnsafeIPAddresses,
                safeIPNetworks: safeIPNetworks,
                safeIPAddresses: safeIPAddresses,
                allowLoopback: allowLoopback,
                metrics: metrics))
            {
                safeResolvedIPAddresses.Add(ipAddress);
            }
        }

        // If no safe IP addresses remain after filtering, block the connection as all resolved addresses are unsafe.
        // If some safe addresses remain but others were filtered out as unsafe, the behavior will depend on the value of the failMixedResults flag.
        if (safeResolvedIPAddresses.Count == 0)
        {
            Log.AllResolvedIpAddressesUnsafe(logger, uri);
            metrics?.IncrementUnsafeIPAddress(1, "all_resolved_addresses_unsafe");
            throw new SsrfException(uri, $"Connection blocked as all resolved addresses are unsafe.");
        }

        // If failMixedResults is set to true, block the connection if any unsafe addresses were found, even if some safe addresses remain.
        // This is a more conservative approach that errs on the side of blocking potentially unsafe connections, but may cause connectivity
        // issues if there are misconfigurations in DNS or the additional unsafe lists.
        if (failMixedResults && safeResolvedIPAddresses.Count != resolvedIpAddresses.Length)
        {
            Log.SomeResolvedIpAddressesUnsafe(logger, uri);
            metrics?.IncrementUnsafeIPAddress(1, "some_resolved_addresses_unsafe");
            throw new SsrfException(uri, $"Connection blocked as some resolved addresses are unsafe.");
        }

        return [.. safeResolvedIPAddresses];
    }
}
