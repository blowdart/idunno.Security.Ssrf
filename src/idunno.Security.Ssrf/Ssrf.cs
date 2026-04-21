// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

namespace idunno.Security;

/// <summary>
/// Provides helper functions for preventing Server-Side Request Forgery (SSRF) vulnerabilities by validating URIs and IP addresses against known unsafe ranges and characteristics.
/// </summary>
public static class Ssrf
{
    private static readonly IPNetwork[] s_ipv4UnsafeRanges =
        [
            // IPv4 private address ranges https://datatracker.ietf.org/doc/html/rfc1918
            new(IPAddress.Parse("10.0.0.0"), 8),
            new(IPAddress.Parse("172.16.0.0"), 12),
            new(IPAddress.Parse("192.168.0.0"), 16),

            // IPv4 loopback https://datatracker.ietf.org/doc/html/rfc1122
            new(IPAddress.Parse("127.0.0.0"), 8),

            // IPv4 link-local https://datatracker.ietf.org/doc/html/rfc3927
            new(IPAddress.Parse("169.254.0.0"), 16),

            // IPv4 carrier-grade NAT https://datatracker.ietf.org/doc/html/rfc6598
            new(IPAddress.Parse("100.64.0.0"), 10),

            // IPv4 "this network" https://datatracker.ietf.org/doc/html/rfc1122
            new(IPAddress.Parse("0.0.0.0"), 8),

            // IPv4 benchmarking https://datatracker.ietf.org/doc/html/rfc2544
            new(IPAddress.Parse("198.18.0.0"), 15),

            // IPv4 documentation/test ranges https://datatracker.ietf.org/doc/html/rfc5737
            new(IPAddress.Parse("192.0.2.0"), 24),
            new(IPAddress.Parse("198.51.100.0"), 24),
            new(IPAddress.Parse("203.0.113.0"), 24),

            // IPv4 IETF protocol assignments https://datatracker.ietf.org/doc/html/rfc6890
            new(IPAddress.Parse("192.0.0.0"), 24),

            // IPv4 multicast https://datatracker.ietf.org/doc/html/rfc1112
            new(IPAddress.Parse("224.0.0.0"), 4),
            // IPv4 reserved https://datatracker.ietf.org/doc/html/rfc1112
            new(IPAddress.Parse("240.0.0.0"), 4)
        ];

    private static readonly IPNetwork[] s_ipv6UnsafeRanges =
        [
            // IPv6 link-local https://datatracker.ietf.org/doc/html/rfc4291
            new(IPAddress.Parse("fe80::"), 10),

            // IPv6 unique local https://datatracker.ietf.org/doc/html/rfc4193
            new(IPAddress.Parse("fc00::"), 7),

            // IPv6 site-local (deprecated but still widely used) https://datatracker.ietf.org/doc/html/rfc4291
            new(IPAddress.Parse("fec0::"), 10),

            // IPv6 6to4 (deprecated) https://datatracker.ietf.org/doc/html/rfc7526
            // 6to4 addresses embed IPv4 addresses and could be used to reach private IPv4 infrastructure.
            new(IPAddress.Parse("2002::"), 16),

            // IETF Protocol Assignments https://datatracker.ietf.org/doc/html/rfc6890
            new (IPAddress.Parse("2001::"), 23),

            // Documentation IPv6 addresses https://datatracker.ietf.org/doc/html/rfc3849
            new (IPAddress.Parse("2001:db8::"), 32),

            // Expanded documentation IPv6 addresses https://datatracker.ietf.org/doc/html/rfc9637
            new (IPAddress.Parse("3fff::"), 20),

            // NAT64 well-known prefix https://datatracker.ietf.org/doc/html/rfc6052
            // NAT64 gateways translate these addresses to their embedded IPv4 equivalents,
            // which could be used to reach private IPv4 infrastructure.
            new (IPAddress.Parse("64:ff9b::"), 96),

            // NAT64 local-use prefix https://datatracker.ietf.org/doc/html/rfc8215
            new (IPAddress.Parse("64:ff9b:1::"), 48),

            // IPv6 discard-only prefix https://datatracker.ietf.org/doc/html/rfc6666
            // while this range silently drops traffic so there is no SSRF risk, blocking it prevents potential connection-hanging probes.
            new (IPAddress.Parse("100::"), 64)
        ];

    /// <summary>
    /// Evaluates the given <paramref name="uri"/> to determine if it is potentially unsafe for use in server-side requests,
    /// based on its host name type, whether it is absolute, loopback, UNC, and its scheme.
    /// </summary>
    /// <param name="uri">The <see cref="Uri"/> to evaluate.</param>
    /// <param name="allowedSchemes">An optional collection of URI schemes that are allowed. This can be used to restrict or allow specific protocols such as "http" or "ws". If <see langword="null"/>, defaults to allow https and wss.</param>
    /// <param name="allowLoopback">Flag indicating whether localhost URIs will be allowed or rejected.</param>
    /// <param name="metrics">Optional <see cref="SsrfMetrics"/> instance to report metrics on unsafe evaluations of <paramref name="uri" />.</param>
    /// <returns><see langword="true"/> if the <paramref name="uri" /> is considered unsafe; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> is <see langword="null"/>.</exception>
    [SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with \"LINQ\" expressions", Justification = "Avoid linq allocations on a hot path.")]
    [SuppressMessage("Documentation", "CSENSE020:Potential ghost parameter reference in documentation", Justification = "Not a ghost reference.")]
    public static bool IsUnsafeUri(
        Uri uri,
        ICollection<string>? allowedSchemes = null,
        bool allowLoopback = false,
        SsrfMetrics? metrics = null)
    {
        ArgumentNullException.ThrowIfNull(uri);

        if (!uri.IsAbsoluteUri)
        {
            metrics?.IncrementUnsafeUri(reason: "not_absolute_uri");
            return true;
        }

        if (uri.IsUnc)
        {
            metrics?.IncrementUnsafeUri(reason: "unc_uri");
            return true;
        }

        if (uri.IsLoopback && !allowLoopback)
        {
            metrics?.IncrementUnsafeUri(reason: "loopback_uri");
            return true;
        }

        if (uri.HostNameType != UriHostNameType.Dns &&
            uri.HostNameType != UriHostNameType.IPv4 &&
            uri.HostNameType != UriHostNameType.IPv6)
        {
            metrics?.IncrementUnsafeUri(reason: "unknown_host_name_type");
            return true;
        }

        bool isUnsafeScheme = true;

        foreach (string allowedScheme in allowedSchemes ?? Defaults.AllowedSchemes)
        {
            if (string.Equals(uri.Scheme, allowedScheme, StringComparison.OrdinalIgnoreCase))
            {
                isUnsafeScheme = false;
                break;
            }
        }

        if (isUnsafeScheme)
        {
            metrics?.IncrementUnsafeUri(reason: "unsafe_scheme", value: uri.Scheme);
        }

        return isUnsafeScheme;
    }

    /// <summary>
    /// Evaluates the given <paramref name="ipAddress"/> to determine if it is potentially unsafe for use in server-side requests, based on its address type, whether it is unspecified, loopback, multicast, link-local, site-local, unique local,
    /// and whether it falls within known unsafe IP network ranges. Optional additional networks can be provided to consider as unsafe beyond the built-in defaults.
    /// </summary>
    /// <param name="ipAddress">The <see cref="IPAddress"/> to evaluate.</param>
    /// <param name="additionalUnsafeIPNetworks">Optional additional networks to consider unsafe.</param>
    /// <param name="additionalUnsafeIPAddresses">Optional additional IP addresses to consider unsafe.</param>
    /// <param name="safeIPNetworks">Optional additional IP networks to consider safe, which can be used to allow specific safe ranges that would otherwise be blocked by the unsafe checks.</param>
    /// <param name="safeIPAddresses">Optional additional IP addresses to consider safe, which can be used to allow specific safe addresses that would otherwise be blocked by the unsafe checks.</param>
    /// <param name="allowLoopback">Indicates whether localhost addresses should be considered safe.</param>
    /// <param name="metrics">Optional <see cref="SsrfMetrics"/> instance to report metrics on unsafe evaluations of <paramref name="ipAddress" />.</param>
    /// <returns><see langword="true"/> if the <paramref name="ipAddress" /> is considered unsafe; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="ipAddress"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// <para>
    ///   Careless use of <paramref name="safeIPNetworks"/> and <paramref name="safeIPAddresses"/> can lead to security vulnerabilities by allowing potentially unsafe IP addresses or networks
    ///   to be considered safe. Use with caution and constrain the values specified to the smallest network range or individual IP addresses possible.
    ///   Safe entries take precedence over both built-in and additional unsafe entries, so if an IP address matches both a safe and unsafe address, it will be considered safe.
    ///</para>
    /// </remarks>
    [SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with \"LINQ\" expressions", Justification = "Avoids delegate allocation on hot path.")]
    public static bool IsUnsafeIpAddress(
        IPAddress ipAddress,
        ICollection<IPNetwork>? additionalUnsafeIPNetworks = null,
        ICollection<IPAddress>? additionalUnsafeIPAddresses = null,
        ICollection<IPNetwork>? safeIPNetworks = null,
        ICollection<IPAddress>? safeIPAddresses = null,
        bool allowLoopback = false,
        SsrfMetrics? metrics = null)
    {
        ArgumentNullException.ThrowIfNull(ipAddress);

        ipAddress = ipAddress.NormalizeToIPv4();

        // Perform safe list checks before unsafe checks so that specific safe addresses or networks can be allowed even if they would normally be blocked by the unsafe checks.
        // This allows for more granular allow-listing of specific safe addresses or ranges without having to allow an entire larger network range that contains unsafe addresses.
        if (safeIPAddresses is not null && safeIPAddresses.Contains(ipAddress))
        {
            return false;
        }

        if (safeIPNetworks is not null)
        {
            foreach (IPNetwork network in safeIPNetworks)
            {
                if (network.Contains(ipAddress))
                {
                    return false;
                }
            }
        }

        // Allow override to consider localhost addresses as safe
        if (allowLoopback && IPAddress.IsLoopback(ipAddress))
        {
            return false;
        }

        if (additionalUnsafeIPAddresses is not null && additionalUnsafeIPAddresses.Contains(ipAddress))
        {
            metrics?.IncrementUnsafeIPAddress(reason: "in_additional_unsafe_ip_addresses");
            return true;
        }

        // Block none addresses 
        if (ipAddress.Equals(IPAddress.None) || ipAddress.Equals(IPAddress.IPv6None))
        {
            metrics?.IncrementUnsafeIPAddress(reason: "ip_none");
            return true;
        }

        // Block loopback: IPv4 127/8 and IPv6 ::1.
        if (IPAddress.IsLoopback(ipAddress))
        {
            metrics?.IncrementUnsafeIPAddress(reason: "loopback");
            return true;
        }

        if (additionalUnsafeIPNetworks is not null)
        {
            foreach (IPNetwork network in additionalUnsafeIPNetworks)
            {
                if (network.Contains(ipAddress))
                {
                    metrics?.IncrementUnsafeIPAddress(reason: "in_additional_unsafe_ip_networks");
                    return true;
                }
            }
        }

        if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
        {

            foreach (IPNetwork network in s_ipv4UnsafeRanges)
            {
                if (network.Contains(ipAddress))
                {
                    metrics?.IncrementUnsafeIPAddress(reason: "in_default_blocks");
                    return true;
                }
            }

            return false;
        }

        if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ipAddress.IsIPv6Multicast)
            {
                metrics?.IncrementUnsafeIPAddress(reason: "ipv6_multicast");
                return true;
            }


            if (ipAddress.IsIPv6LinkLocal ||
                ipAddress.IsIPv6SiteLocal ||
                ipAddress.IsIPv6UniqueLocal)
            {
                metrics?.IncrementUnsafeIPAddress(reason: "ipv6_local");
                return true;
            }


            foreach (IPNetwork network in s_ipv6UnsafeRanges)
            {
                if (network.Contains(ipAddress))
                {
                    metrics?.IncrementUnsafeIPAddress(reason: "in_default_blocks");
                    return true;
                }
            }

            return false;
        }

        // Unknown address family: fail closed.
        metrics?.IncrementUnsafeIPAddress(reason: "unknown_address_family");
        return true;
    }

    /// <summary>
    /// Implements simple SSRF validation on the specified <paramref name="uri"/> by checking 
    /// its protocol (HTTPS only), host name type, whether it is absolute, loopback, UNC, and its scheme, and that
    /// the host resolves to a public IP address which is not in a known unsafe range.
    /// </summary>
    /// <param name="uri">The <see cref="Uri"/> to validate.</param>
    /// <param name="allowedSchemes">An optional collection of URI schemes that are allowed. This can be used to restrict or allow specific protocols such as "http" or "ws". If <see langword="null"/>, defaults to allow https and wss.</param>
    /// <param name="allowLoopback">Flag indicating whether localhost URIs will be allowed or rejected.</param>
    /// <param name="additionalUnsafeIPNetworks">Optional additional networks to consider unsafe.</param>
    /// <param name="additionalUnsafeIPAddresses">Optional additional IP addresses to consider unsafe.</param>
    /// <param name="allowedHostnames">
    ///     Gets or sets an optional collection of hostnames that are allowed to bypass SSRF IP address protections.
    ///     This can be used to allow specific trusted hosts names.
    ///     Wild cards are supported only at the start of the hostname, and must be followed by a dot
    ///     (e.g. "*.example.com" would allow "api.example.com", "test.api.example.com", but not "example.com").
    /// </param>
    /// <param name="safeIPNetworks">Optional additional IP networks to consider safe, which can be used to allow specific safe ranges that would otherwise be blocked by the unsafe checks.</param>
    /// <param name="safeIPAddresses">Optional additional IP addresses to consider safe, which can be used to allow specific safe addresses that would otherwise be blocked by the unsafe checks.</param>
    /// <param name="metrics">Optional <see cref="SsrfMetrics"/> instance to report metrics on unsafe evaluations of <paramref name="uri" /> and related IP address checks.</param>
    /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
    /// <returns><see langword="true" /> if the <paramref name="uri" /> is considered unsafe, otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// <para>
    ///   Careless use of <paramref name="safeIPNetworks"/> and <paramref name="safeIPAddresses"/> can lead to security vulnerabilities by allowing potentially unsafe IP addresses or networks
    ///   to be considered safe. Use with caution and constrain the values specified to the smallest network range or individual IP addresses needed.
    ///   Safe entries take precedence over both built-in and additional unsafe entries, so if an IP address matches both a safe and unsafe address, or is within a safe network,
    ///   it will be considered safe.
    ///</para>
    /// </remarks>
    [SuppressMessage("Documentation", "CSENSE020:Potential ghost parameter reference in documentation", Justification = "Not a ghost reference.")]
    public static Task<bool> IsUnsafe(
        Uri uri,
        ICollection<string>? allowedSchemes = null,
        bool allowLoopback = false,
        ICollection<IPNetwork>? additionalUnsafeIPNetworks = null,
        ICollection<IPAddress>? additionalUnsafeIPAddresses = null,
        ICollection<string>? allowedHostnames = null,
        ICollection<IPNetwork>? safeIPNetworks = null,
        ICollection<IPAddress>? safeIPAddresses = null,
        SsrfMetrics? metrics = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);

        return InternalIsUnsafe(
            uri: uri,
            allowedSchemes: allowedSchemes ?? Defaults.AllowedSchemes,
            allowLoopback: allowLoopback,
            additionalUnsafeIPNetworks: additionalUnsafeIPNetworks,
            additionalUnsafeIPAddresses: additionalUnsafeIPAddresses,
            allowedHostnames: allowedHostnames,
            safeIPNetworks: safeIPNetworks,
            safeIPAddresses: safeIPAddresses,
            metrics: metrics,
            hostEntryResolver: null,
            cancellationToken: cancellationToken);
    }

    [SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with \"LINQ\" expressions", Justification = "Avoids delegate allocation on hot path.")]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Catch any exception to fail close.")]
    internal static async Task<bool> InternalIsUnsafe(
        Uri uri,
        ICollection<string>? allowedSchemes,
        bool allowLoopback,
        ICollection<IPNetwork>? additionalUnsafeIPNetworks,
        ICollection<IPAddress>? additionalUnsafeIPAddresses,
        ICollection<string>? allowedHostnames,
        ICollection<IPNetwork>? safeIPNetworks,
        ICollection<IPAddress>? safeIPAddresses,
        SsrfMetrics? metrics,
        Func<string, CancellationToken, Task<IPHostEntry>>? hostEntryResolver,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(uri);

        hostEntryResolver ??= Defaults.GetHostEntryAsync;

        if (IsUnsafeUri(
            uri: uri,
            allowedSchemes: allowedSchemes ?? Defaults.AllowedSchemes,
            allowLoopback: allowLoopback,
            metrics: metrics))
        {
            return true;
        }

        if (uri.HostNameType == UriHostNameType.IPv4 || uri.HostNameType == UriHostNameType.IPv6)
        {
            var ipAddress = IPAddress.Parse(uri.Host);

            return IsUnsafeIpAddress(
                ipAddress: ipAddress,
                additionalUnsafeIPNetworks: additionalUnsafeIPNetworks,
                additionalUnsafeIPAddresses: additionalUnsafeIPAddresses,
                safeIPNetworks: safeIPNetworks,
                safeIPAddresses: safeIPAddresses,
                allowLoopback: allowLoopback,
                metrics: metrics);
        }

        if (IsInAllowedHostnames(uri, allowedHostnames))
        {
            return false;
        }

        IPHostEntry? hostEntry;
        try
        {
            hostEntry = await hostEntryResolver(uri.Host, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return true;
        }

        if (hostEntry is null || hostEntry.AddressList.Length == 0)
        {
            return true;
        }

        foreach (IPAddress ipAddress in hostEntry.AddressList)
        {
            if (IsUnsafeIpAddress(
                ipAddress: ipAddress,
                additionalUnsafeIPNetworks: additionalUnsafeIPNetworks,
                additionalUnsafeIPAddresses: additionalUnsafeIPAddresses,
                safeIPNetworks: safeIPNetworks,
                safeIPAddresses: safeIPAddresses,
                allowLoopback: allowLoopback,
                metrics: metrics))
            {
                return true;
            }
        }

        return false;
    }

    [SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with \"LINQ\" expressions", Justification = "Avoid allocations in a hot path.")]
    internal static bool IsInAllowedHostnames(Uri uri, IEnumerable<string>? allowedHostnames)
    {
        if (uri is null)
        {
            return false;
        }

        if (allowedHostnames is null)
        {
            return false;
        }

        foreach (string safeHostName in allowedHostnames)
        {
            bool isWildcard = safeHostName.StartsWith("*.", StringComparison.OrdinalIgnoreCase) && safeHostName != "*.";

            if (!isWildcard && string.Equals(uri.Host, safeHostName, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
            else if (isWildcard && uri.Host.EndsWith(safeHostName[1..], StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    [SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with \"LINQ\" expressions", Justification = "Avoid allocations in a hot path.")]
    internal static bool IsInAllowedNetworks(IPAddress ipAddress, IEnumerable<IPNetwork>? allowedIPNetworks)
    {
        if (ipAddress is null)
        {
            return false;
        }

        if (allowedIPNetworks is null)
        {
            return false;
        }

        foreach (IPNetwork network in allowedIPNetworks)
        {
            if (network.Contains(ipAddress))
            {
                return true;
            }
        }

        return false;
    }

    [SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with \"LINQ\" expressions", Justification = "Avoid allocations in a hot path.")]
    internal static bool IsInAllowedIpAddresses(IPAddress ipAddress, IEnumerable<IPAddress>? allowedIPAddresses)
    {
        if (ipAddress is null)
        {
            return false;
        }
        if (allowedIPAddresses is null)
        {
            return false;
        }
        foreach (IPAddress allowedIp in allowedIPAddresses)
        {
            if (ipAddress.Equals(allowedIp))
            {
                return true;
            }
        }
        return false;
    }
}
