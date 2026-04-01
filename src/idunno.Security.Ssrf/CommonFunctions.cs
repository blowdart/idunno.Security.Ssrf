// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;

using Microsoft.Extensions.Logging;

namespace idunno.Security;

internal static class CommonFunctions
{
    private static readonly Func<string, CancellationToken, Task<IPHostEntry>> s_defaultAsyncHostEntryResolver = Dns.GetHostEntryAsync;
    private static readonly Func<string, IPHostEntry> s_defaultHostEntryResolver = Dns.GetHostEntry;

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with \"LINQ\" expressions", Justification = "Avoid allocations in a hot path.")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE0028:Simplify collection initialization", Justification = "Suggested fix is language preview feature in some versions.")]
    internal static async Task<List<IPAddress>> ResolveAndReturnSafeIPAddressesAsync(
        Uri uri,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        bool allowLoopback,
        bool failMixedResults,
        ILogger logger,
        Func<string, CancellationToken, Task<IPHostEntry>> hostEntryResolver,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(uri);
        IPAddress[] resolvedIpAddresses = await ResolveAsync(uri, logger, hostEntryResolver, cancellationToken).ConfigureAwait(false);
        return GetSafeIPAddresses(uri, resolvedIpAddresses, additionalUnsafeNetworks, additionalUnsafeIpAddresses, allowLoopback, failMixedResults, logger);
    }

    internal static async Task<IPAddress[]> ResolveAsync(
        Uri uri,
        ILogger logger,
        Func<string, CancellationToken, Task<IPHostEntry>> hostEntryResolver,
        CancellationToken cancellationToken)
    {
        hostEntryResolver ??= s_defaultAsyncHostEntryResolver;

        IPAddress[] resolvedIpAddresses = [];

        if (IPAddress.TryParse(uri.Host, out IPAddress? parsedAddress))
        {
            resolvedIpAddresses = [parsedAddress];
        }
        else
        {
            try
            {
                IPHostEntry entry = await hostEntryResolver(uri.Host, cancellationToken).ConfigureAwait(false);

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

    internal static List<IPAddress> ResolveAndReturnSafeIPAddresses(
        Uri uri,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        bool allowLoopback,
        bool failMixedResults,
        ILogger logger,
        Func<string, IPHostEntry> hostEntryResolver)
    {
        ArgumentNullException.ThrowIfNull(uri);
        IPAddress[] resolvedIpAddresses = Resolve(uri, logger, hostEntryResolver);
        return GetSafeIPAddresses(uri, resolvedIpAddresses, additionalUnsafeNetworks, additionalUnsafeIpAddresses, allowLoopback, failMixedResults, logger);
    }

    internal static IPAddress[] Resolve(
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

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with \"LINQ\" expressions", Justification = "Avoid allocations in a hot path.")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE0028:Simplify collection initialization", Justification = "Suggested fix is language preview feature in some versions.")]
    private static List<IPAddress> GetSafeIPAddresses(
        Uri uri,
        IPAddress[] resolvedIpAddresses,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        bool allowLoopback,
        bool failMixedResults,
        ILogger logger)
    {
        List<IPAddress> safeResolvedIPAddresses = new(resolvedIpAddresses.Length);

        foreach (IPAddress ipAddress in resolvedIpAddresses)
        {
            if (!Ssrf.IsUnsafeIpAddress(
                ipAddress: ipAddress,
                additionalUnsafeNetworks: additionalUnsafeNetworks,
                additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
                allowLoopback: allowLoopback))
            {
                safeResolvedIPAddresses.Add(ipAddress);
            }
        }

        // If no safe IP addresses remain after filtering, block the connection as all resolved addresses are unsafe.
        // If some safe addresses remain but others were filtered out as unsafe, the behavior will depend on the value of the failMixedResults flag.
        if (safeResolvedIPAddresses.Count == 0)
        {
            Log.AllResolvedIpAddressesUnsafe(logger, uri);
            throw new SsrfException(uri, $"Connection blocked as all resolved addresses are unsafe.");
        }

        // If failMixedResults is set to true, block the connection if any unsafe addresses were found, even if some safe addresses remain.
        // This is a more conservative approach that errs on the side of blocking potentially unsafe connections, but may cause connectivity
        // issues if there are misconfigurations in DNS or the additional unsafe lists.
        if (failMixedResults && safeResolvedIPAddresses.Count != resolvedIpAddresses.Length)
        {
            Log.SomeResolvedIpAddressesUnsafe(logger, uri);
            throw new SsrfException(uri, $"Connection blocked as some resolved addresses are unsafe.");
        }

        return safeResolvedIPAddresses;
    }
}
