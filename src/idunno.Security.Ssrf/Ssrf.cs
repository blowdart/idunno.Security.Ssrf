// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;
using System.Net.Sockets;

namespace idunno.Security;

/// <summary>
/// Provides helper functions for preventing Server-Side Request Forgery (SSRF) vulnerabilities by validating URIs and IP addresses against known unsafe ranges and characteristics.
/// </summary>
public static class Ssrf
{
    private static readonly ICollection<IPNetwork> s_ipv4UnsafeRangeCollection =
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

    private static readonly ICollection<IPAddress> s_ipv4UnsafeAddressCollection =
        [
            IPAddress.Any,
            IPAddress.Broadcast,
            IPAddress.Loopback,

            // Cloud metadata services (e.g. AWS, Azure, GCP)
            IPAddress.Parse("169.254.169.254")
        ];

    private static readonly ICollection<IPNetwork> s_ipv6UnsafeRangeCollection =
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
            new (IPAddress.Parse("2001:db8::"), 32)
        ];

    /// <summary>
    /// Evaluates the given <paramref name="uri"/> to determine if it is potentially unsafe for use in server-side requests,
    /// based on its protocol (HTTPS only), host name type, whether it is absolute, loopback, UNC, and its scheme.
    /// </summary>
    /// <param name="uri">The <see cref="Uri"/> to evaluate.</param>
    /// <returns><see langword="true"/> if the <paramref name="uri" /> is potentially unsafe; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> is <see langword="null"/>.</exception>
    public static bool IsUnsafeUri(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);

        return IsUnsafeUri(uri: uri, allowInsecureProtocols: false);
    }

    /// <summary>
    /// Evaluates the given <paramref name="uri"/> to determine if it is potentially unsafe for use in server-side requests,
    /// based on its host name type, whether it is absolute, loopback, UNC, and its scheme.
    /// </summary>
    /// <param name="uri">The <see cref="Uri"/> to evaluate.</param>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <returns><see langword="true"/> if the <paramref name="uri" /> is potentially unsafe; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> is <see langword="null"/>.</exception>
    public static bool IsUnsafeUri(Uri uri, bool allowInsecureProtocols)
    {
        ArgumentNullException.ThrowIfNull(uri);

        if (!uri.IsAbsoluteUri ||
            uri.IsLoopback ||
            uri.IsUnc)
        {
            return true;
        }

        if (uri.HostNameType != UriHostNameType.Dns &&
            uri.HostNameType != UriHostNameType.IPv4 &&
            uri.HostNameType != UriHostNameType.IPv6)
        {
            return true;
        }

        if (allowInsecureProtocols && Uri.UriSchemeHttp.Equals(uri.Scheme, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        else if (allowInsecureProtocols && Uri.UriSchemeWs.Equals(uri.Scheme, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        else if (Uri.UriSchemeHttps.Equals(uri.Scheme, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        else if (Uri.UriSchemeWss.Equals(uri.Scheme, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        else
        {
            return true;
        }
    }

    /// <summary>
    /// Evaluates the given <paramref name="ipAddress"/> to determine if it is potentially unsafe for use in server-side requests, based on its address type, whether it is unspecified, loopback, multicast, link-local, site-local, unique local,
    /// and whether it falls within known unsafe IP network ranges.
    /// </summary>
    /// <param name="ipAddress">The <see cref="IPAddress"/> to evaluate.</param>
    /// <returns><see langword="true"/> if the <paramref name="ipAddress" /> is potentially unsafe; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="ipAddress"/> is <see langword="null"/>.</exception>
    public static bool IsUnsafeIpAddress(IPAddress ipAddress)
    {
        ArgumentNullException.ThrowIfNull(ipAddress);

        return IsUnsafeIpAddress(ipAddress, additionalUnsafeNetworks: null, additionalUnsafeIpAddresses: null);
    }

    /// <summary>
    /// Evaluates the given <paramref name="ipAddress"/> to determine if it is potentially unsafe for use in server-side requests, based on its address type, whether it is unspecified, loopback, multicast, link-local, site-local, unique local,
    /// and whether it falls within known unsafe IP network ranges. Optional additional networks can be provided to consider as unsafe beyond the built-in defaults.
    /// </summary>
    /// <param name="ipAddress">The <see cref="IPAddress"/> to evaluate.</param>
    /// <param name="additionalUnsafeNetworks">Optional additional networks to consider unsafe.</param>
    /// <param name="additionalUnsafeIpAddresses">Optional additional IP addresses to consider unsafe.</param>
    /// <returns><see langword="true"/> if the <paramref name="ipAddress" /> is potentially unsafe; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="ipAddress"/> is <see langword="null"/>.</exception>
    public static bool IsUnsafeIpAddress(
        IPAddress ipAddress,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses)
    {
        ArgumentNullException.ThrowIfNull(ipAddress);

        // Normalize IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) to IPv4 before range checks.
        if (ipAddress.IsIPv4MappedToIPv6)
        {
            ipAddress = ipAddress.MapToIPv4();
        }

        // Perform checks so that IPv4-mapped IPv6addresses (e.g. ::ffff:1.2.3.4) are correctly matched against their IPv4 equivalents.

        if (additionalUnsafeIpAddresses is not null && additionalUnsafeIpAddresses.Contains(ipAddress))
        {
            return true;
        }

        // Block unspecified addresses (IPv4 0.0.0.0 and IPv6 ::).
        if (ipAddress.Equals(IPAddress.Any) || ipAddress.Equals(IPAddress.IPv6None))
        {
            return true;
        }

        // Block loopback: IPv4 127/8 and IPv6 ::1.
        if (IPAddress.IsLoopback(ipAddress))
        {
            return true;
        }

        if (ipAddress.AddressFamily == AddressFamily.InterNetwork && s_ipv4UnsafeAddressCollection.Contains(ipAddress))
        {
            return true;
        }

        if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            if (additionalUnsafeNetworks is not null && additionalUnsafeNetworks.Any(network =>
                    network.BaseAddress.AddressFamily == AddressFamily.InterNetwork &&
                    network.Contains(ipAddress)))
            {
                return true;
            }

            return s_ipv4UnsafeRangeCollection.Any(network => network.Contains(ipAddress));
        }

        if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ipAddress.IsIPv6Multicast ||
                ipAddress.IsIPv6LinkLocal ||
                ipAddress.IsIPv6SiteLocal ||
                ipAddress.IsIPv6UniqueLocal)
            {
                return true;
            }

            if (additionalUnsafeNetworks is not null && additionalUnsafeNetworks.Any(network =>
                    network.BaseAddress.AddressFamily == AddressFamily.InterNetworkV6 &&
                    network.Contains(ipAddress)))
            {
                return true;
            }

            return s_ipv6UnsafeRangeCollection.Any(network => network.Contains(ipAddress));
        }

        // Unknown address family: fail closed.
        return true;
    }

    /// <summary>
    /// Implements simple SSRF validation on the specified <paramref name="uri"/> by checking 
    /// its protocol (HTTPS only), host name type, whether it is absolute, loopback, UNC, and its scheme, and that
    /// the host resolves to a public IP address which is not in a known unsafe range.
    /// </summary>
    /// <param name="uri">The <see cref="Uri"/> to validate.</param>
    /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
    /// <returns><see langword="true" /> if the <paramref name="uri" /> is considered safe, otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> is <see langword="null"/>.</exception>
    public static async Task<bool> IsUnsafe(Uri uri, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);

        return await IsUnsafe(
            uri: uri,
            allowInsecureProtocols: false,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            hostEntryResolver: null,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Implements simple SSRF validation on the specified <paramref name="uri"/> by checking 
    /// its protocol (HTTPS only), host name type, whether it is absolute, loopback, UNC, and its scheme, and that
    /// the host resolves to a public IP address which is not in a known unsafe range.
    /// </summary>
    /// <param name="uri">The <see cref="Uri"/> to validate.</param>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
    /// <returns><see langword="true" /> if the <paramref name="uri" /> is considered safe, otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> is <see langword="null"/>.</exception>
    public static async Task<bool> IsUnsafe(Uri uri, bool allowInsecureProtocols, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);

        return await IsUnsafe(
            uri: uri,
            allowInsecureProtocols: allowInsecureProtocols,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            hostEntryResolver: null,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Implements simple SSRF validation on the specified <paramref name="uri"/> by checking 
    /// its protocol (HTTPS only), host name type, whether it is absolute, loopback, UNC, and its scheme, and that
    /// the host resolves to a public IP address which is not in a known unsafe range.
    /// </summary>
    /// <param name="uri">The <see cref="Uri"/> to validate.</param>
    /// <param name="additionalUnsafeNetworks">Additional IP networks to consider unsafe.</param>
    /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
    /// <returns><see langword="true" /> if the <paramref name="uri" /> is considered safe, otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> or <paramref name="additionalUnsafeNetworks"/> is <see langword="null"/>.</exception>
    public static async Task<bool> IsUnsafe(Uri uri, ICollection<IPNetwork> additionalUnsafeNetworks, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);
        ArgumentNullException.ThrowIfNull(additionalUnsafeNetworks);

        return await IsUnsafe(
            uri: uri,
            allowInsecureProtocols: false,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: null,
            hostEntryResolver: null,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Implements simple SSRF validation on the specified <paramref name="uri"/> by checking 
    /// its protocol (HTTPS only), host name type, whether it is absolute, loopback, UNC, and its scheme, and that
    /// the host resolves to a public IP address which is not in a known unsafe range.
    /// </summary>
    /// <param name="uri">The <see cref="Uri"/> to validate.</param>
    /// <param name="additionalUnsafeIpAddresses">Additional IP addresses to consider unsafe.</param>
    /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
    /// <returns><see langword="true" /> if the <paramref name="uri" /> is considered safe, otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> or <paramref name="additionalUnsafeIpAddresses"/> is <see langword="null"/>.</exception>
    public static async Task<bool> IsUnsafe(Uri uri, ICollection<IPAddress> additionalUnsafeIpAddresses, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);
        ArgumentNullException.ThrowIfNull(additionalUnsafeIpAddresses);

        return await IsUnsafe(
            uri: uri,
            allowInsecureProtocols: false,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            hostEntryResolver: null,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Implements simple SSRF validation on the specified <paramref name="uri"/> by checking 
    /// its protocol (HTTPS only), host name type, whether it is absolute, loopback, UNC, and its scheme, and that
    /// the host resolves to a public IP address which is not in a known unsafe range.
    /// </summary>
    /// <param name="uri">The <see cref="Uri"/> to validate.</param>
    /// <param name="additionalUnsafeNetworks">Optional additional networks to consider unsafe.</param>
    /// <param name="additionalUnsafeIpAddresses">Optional additional IP addresses to consider unsafe.</param>
    /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
    /// <returns><see langword="true" /> if the <paramref name="uri" /> is considered safe, otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> is <see langword="null"/>.</exception>
    public static async Task<bool> IsUnsafe(
        Uri uri,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);

        return await IsUnsafe(
            uri: uri,
            allowInsecureProtocols: false,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            hostEntryResolver: null,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Implements simple SSRF validation on the specified <paramref name="uri"/> by checking 
    /// its protocol (HTTPS only), host name type, whether it is absolute, loopback, UNC, and its scheme, and that
    /// the host resolves to a public IP address which is not in a known unsafe range.
    /// </summary>
    /// <param name="uri">The <see cref="Uri"/> to validate.</param>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <param name="additionalUnsafeNetworks">Optional additional networks to consider unsafe.</param>
    /// <param name="additionalUnsafeIpAddresses">Optional additional IP addresses to consider unsafe.</param>
    /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
    /// <returns><see langword="true" /> if the <paramref name="uri" /> is considered safe, otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> is <see langword="null"/>.</exception>
    public static async Task<bool> IsUnsafe(
        Uri uri,
        bool allowInsecureProtocols,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);

        return await IsUnsafe(
            uri: uri,
            allowInsecureProtocols: allowInsecureProtocols,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            hostEntryResolver: null,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<bool> IsUnsafe(
        Uri uri,
        bool allowInsecureProtocols,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        Func<string, CancellationToken, Task<IPHostEntry>>? hostEntryResolver = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);

        hostEntryResolver ??= Dns.GetHostEntryAsync;

        if (IsUnsafeUri(uri, allowInsecureProtocols))
        {
            return true;
        }

        if (uri.HostNameType == UriHostNameType.IPv4 || uri.HostNameType == UriHostNameType.IPv6)
        {
            var ipAddress = IPAddress.Parse(uri.Host);

            return IsUnsafeIpAddress(
                ipAddress: ipAddress,
                additionalUnsafeNetworks: additionalUnsafeNetworks,
                additionalUnsafeIpAddresses: additionalUnsafeIpAddresses);
        }
        else
        {
            IPHostEntry? hostEntry = await hostEntryResolver(uri.Host, cancellationToken).ConfigureAwait(false);
            if (hostEntry is null || hostEntry.AddressList is null)
            {
                return true;
            }

            return hostEntry.AddressList.Any(ipAddress => IsUnsafeIpAddress(
                ipAddress: ipAddress,
                additionalUnsafeNetworks: additionalUnsafeNetworks,
                additionalUnsafeIpAddresses: additionalUnsafeIpAddresses));
        }
    }
}
