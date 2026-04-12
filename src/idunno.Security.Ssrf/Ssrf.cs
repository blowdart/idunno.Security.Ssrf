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
    private static readonly Func<string, CancellationToken, Task<IPHostEntry>> s_defaultHostEntryResolver = Dns.GetHostEntryAsync;

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
            // while this range silently drops traffic so there is no SSRF risk, bocking it prevents potential connection-hanging probes.
            new (IPAddress.Parse("100::"), 64)
        ];

    /// <summary>
    /// Evaluates the given <paramref name="uri"/> to determine if it is potentially unsafe for use in server-side requests,
    /// based on its protocol (HTTPS only), host name type, whether it is absolute, loopback, UNC, and its scheme.
    /// </summary>
    /// <param name="uri">The <see cref="Uri"/> to evaluate.</param>
    /// <returns><see langword="true"/> if the <paramref name="uri" /> is considered unsafe; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> is <see langword="null"/>.</exception>
    public static bool IsUnsafeUri(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);

        return IsUnsafeUri(
            uri: uri,
            allowInsecureProtocols: false,
            allowLoopback: false);
    }

    /// <summary>
    /// Evaluates the given <paramref name="uri"/> to determine if it is potentially unsafe for use in server-side requests,
    /// based on its host name type, whether it is absolute, loopback, UNC, and its scheme.
    /// </summary>
    /// <param name="uri">The <see cref="Uri"/> to evaluate.</param>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <returns><see langword="true"/> if the <paramref name="uri" /> is considered unsafe; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> is <see langword="null"/>.</exception>
    public static bool IsUnsafeUri(Uri uri, bool allowInsecureProtocols)
    {
        ArgumentNullException.ThrowIfNull(uri);

        return IsUnsafeUri(
            uri: uri,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: false);
    }

    /// <summary>
    /// Evaluates the given <paramref name="uri"/> to determine if it is potentially unsafe for use in server-side requests,
    /// based on its host name type, whether it is absolute, loopback, UNC, and its scheme.
    /// </summary>
    /// <param name="uri">The <see cref="Uri"/> to evaluate.</param>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <param name="allowLoopback">Flag indicating whether localhost URIs will be allowed or rejected.</param>
    /// <returns><see langword="true"/> if the <paramref name="uri" /> is considered unsafe; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> is <see langword="null"/>.</exception>
    public static bool IsUnsafeUri(Uri uri, bool allowInsecureProtocols, bool allowLoopback)
    {
        ArgumentNullException.ThrowIfNull(uri);

        if (!uri.IsAbsoluteUri ||
            uri.IsUnc)
        {
            return true;
        }

        if (uri.IsLoopback && !allowLoopback)
        {
            return true;
        }

        if (uri.HostNameType != UriHostNameType.Dns &&
            uri.HostNameType != UriHostNameType.IPv4 &&
            uri.HostNameType != UriHostNameType.IPv6)
        {
            return true;
        }

        // Uri class already normalizes scheme to lower case, so we can do a simple ordinal comparison here.
        return uri.Scheme switch
        {
            "https" or "wss" => false,
            "http" or "ws" when allowInsecureProtocols => false,
            _ => true
        };
    }

    /// <summary>
    /// Evaluates the given <paramref name="ipAddress"/> to determine if it is potentially unsafe for use in server-side requests, based on its address type, whether it is unspecified, loopback, multicast, link-local, site-local, unique local,
    /// and whether it falls within known unsafe IP network ranges.
    /// </summary>
    /// <param name="ipAddress">The <see cref="IPAddress"/> to evaluate.</param>
    /// <returns><see langword="true"/> if the <paramref name="ipAddress" /> is considered unsafe; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="ipAddress"/> is <see langword="null"/>.</exception>
    public static bool IsUnsafeIpAddress(IPAddress ipAddress)
    {
        ArgumentNullException.ThrowIfNull(ipAddress);

        return IsUnsafeIpAddress(
            ipAddress: ipAddress,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowLoopback: false);
    }

    /// <summary>
    /// Evaluates the given <paramref name="ipAddress"/> to determine if it is potentially unsafe for use in server-side requests, based on its address type, whether it is unspecified, loopback, multicast, link-local, site-local, unique local,
    /// and whether it falls within known unsafe IP network ranges.
    /// </summary>
    /// <param name="ipAddress">The <see cref="IPAddress"/> to evaluate.</param>
    /// <param name="allowLoopback">Indicates whether localhost addresses should be considered safe.</param>
    /// <returns><see langword="true"/> if the <paramref name="ipAddress" /> is considered unsafe; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="ipAddress"/> is <see langword="null"/>.</exception>
    public static bool IsUnsafeIpAddress(IPAddress ipAddress, bool allowLoopback)
    {
        ArgumentNullException.ThrowIfNull(ipAddress);

        return IsUnsafeIpAddress(
            ipAddress: ipAddress,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowLoopback: allowLoopback);
    }

    /// <summary>
    /// Evaluates the given <paramref name="ipAddress"/> to determine if it is potentially unsafe for use in server-side requests, based on its address type, whether it is unspecified, loopback, multicast, link-local, site-local, unique local,
    /// and whether it falls within known unsafe IP network ranges. Optional additional networks can be provided to consider as unsafe beyond the built-in defaults.
    /// </summary>
    /// <param name="ipAddress">The <see cref="IPAddress"/> to evaluate.</param>
    /// <param name="additionalUnsafeNetworks">Optional additional networks to consider unsafe.</param>
    /// <param name="additionalUnsafeIpAddresses">Optional additional IP addresses to consider unsafe.</param>
    /// <returns><see langword="true"/> if the <paramref name="ipAddress" /> is considered unsafe; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="ipAddress"/> is <see langword="null"/>.</exception>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with \"LINQ\" expressions", Justification = "Avoids delegate allocation on hot path.")]
    public static bool IsUnsafeIpAddress(
        IPAddress ipAddress,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses)
    {
        ArgumentNullException.ThrowIfNull(ipAddress);

        return IsUnsafeIpAddress(
            ipAddress: ipAddress,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowLoopback: false);
    }

    /// <summary>
    /// Evaluates the given <paramref name="ipAddress"/> to determine if it is potentially unsafe for use in server-side requests, based on its address type, whether it is unspecified, loopback, multicast, link-local, site-local, unique local,
    /// and whether it falls within known unsafe IP network ranges. Optional additional networks can be provided to consider as unsafe beyond the built-in defaults.
    /// </summary>
    /// <param name="ipAddress">The <see cref="IPAddress"/> to evaluate.</param>
    /// <param name="additionalUnsafeNetworks">Optional additional networks to consider unsafe.</param>
    /// <param name="additionalUnsafeIpAddresses">Optional additional IP addresses to consider unsafe.</param>
    /// <param name="allowLoopback">Indicates whether localhost addresses should be considered safe.</param>
    /// <returns><see langword="true"/> if the <paramref name="ipAddress" /> is considered unsafe; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="ipAddress"/> is <see langword="null"/>.</exception>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with \"LINQ\" expressions", Justification = "Avoids delegate allocation on hot path.")]
    public static bool IsUnsafeIpAddress(
        IPAddress ipAddress,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        bool allowLoopback)
    {
        ArgumentNullException.ThrowIfNull(ipAddress);

        // Normalize IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) to IPv4 before range checks.
        if (ipAddress.IsIPv4MappedToIPv6)
        {
            ipAddress = ipAddress.MapToIPv4();
        }

        // Allow override to consider localhost addresses as safe
        if (allowLoopback && IPAddress.IsLoopback(ipAddress))
        {
            return false;
        }

        if (additionalUnsafeIpAddresses is not null && additionalUnsafeIpAddresses.Contains(ipAddress))
        {
            return true;
        }

        // Block IPv6 unspecified address (::), IPv4 0.0.0.0 is covered by the 0.0.0.0/8 range.
        if (ipAddress.Equals(IPAddress.IPv6None))
        {
            return true;
        }

        // Block loopback: IPv4 127/8 and IPv6 ::1.
        if (IPAddress.IsLoopback(ipAddress))
        {
            return true;
        }

        if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            if (additionalUnsafeNetworks is not null)
            {
                foreach (IPNetwork network in additionalUnsafeNetworks)
                {
                    if (network.BaseAddress.AddressFamily == AddressFamily.InterNetwork &&
                        network.Contains(ipAddress))
                    {
                        return true;
                    }
                }
            }

            foreach (IPNetwork network in s_ipv4UnsafeRanges)
            {
                if (network.Contains(ipAddress))
                {
                    return true;
                }
            }

            return false;
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

            if (additionalUnsafeNetworks is not null)
            {
                foreach (IPNetwork network in additionalUnsafeNetworks)
                {
                    if (network.BaseAddress.AddressFamily == AddressFamily.InterNetworkV6 &&
                        network.Contains(ipAddress))
                    {
                        return true;
                    }
                }
            }

            foreach (IPNetwork network in s_ipv6UnsafeRanges)
            {
                if (network.Contains(ipAddress))
                {
                    return true;
                }
            }

            return false;
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
    /// <returns><see langword="true" /> if the <paramref name="uri" /> is considered unsafe, otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> is <see langword="null"/>.</exception>
    public static Task<bool> IsUnsafe(Uri uri, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);

        return InternalIsUnsafe(
            uri: uri,
            allowInsecureProtocols: false,
            allowLoopback: false,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            hostEntryResolver: null,
            allowedHostnames: null,
            cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Implements simple SSRF validation on the specified <paramref name="uri"/> by checking 
    /// its protocol (HTTPS only), host name type, whether it is absolute, loopback, UNC, and its scheme, and that
    /// the host resolves to a public IP address which is not in a known unsafe range.
    /// </summary>
    /// <param name="uri">The <see cref="Uri"/> to validate.</param>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
    /// <returns><see langword="true" /> if the <paramref name="uri" /> is considered unsafe, otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> is <see langword="null"/>.</exception>
    public static Task<bool> IsUnsafe(Uri uri, bool allowInsecureProtocols, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);

        return InternalIsUnsafe(
            uri: uri,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: false,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            hostEntryResolver: null,
            cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Implements simple SSRF validation on the specified <paramref name="uri"/> by checking 
    /// its protocol (HTTPS only), host name type, whether it is absolute, loopback, UNC, and its scheme, and that
    /// the host resolves to a public IP address which is not in a known unsafe range.
    /// </summary>
    /// <param name="uri">The <see cref="Uri"/> to validate.</param>
    /// <param name="additionalUnsafeNetworks">Additional IP networks to consider unsafe.</param>
    /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
    /// <returns><see langword="true" /> if the <paramref name="uri" /> is considered unsafe, otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> or <paramref name="additionalUnsafeNetworks"/> is <see langword="null"/>.</exception>
    public static Task<bool> IsUnsafe(Uri uri, ICollection<IPNetwork> additionalUnsafeNetworks, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);
        ArgumentNullException.ThrowIfNull(additionalUnsafeNetworks);

        return InternalIsUnsafe(
            uri: uri,
            allowInsecureProtocols: false,
            allowLoopback: false,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            hostEntryResolver: null,
            cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Implements simple SSRF validation on the specified <paramref name="uri"/> by checking 
    /// its protocol (HTTPS only), host name type, whether it is absolute, loopback, UNC, and its scheme, and that
    /// the host resolves to a public IP address which is not in a known unsafe range.
    /// </summary>
    /// <param name="uri">The <see cref="Uri"/> to validate.</param>
    /// <param name="additionalUnsafeIpAddresses">Additional IP addresses to consider unsafe.</param>
    /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
    /// <returns><see langword="true" /> if the <paramref name="uri" /> is considered unsafe, otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> or <paramref name="additionalUnsafeIpAddresses"/> is <see langword="null"/>.</exception>
    public static Task<bool> IsUnsafe(Uri uri, ICollection<IPAddress> additionalUnsafeIpAddresses, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);
        ArgumentNullException.ThrowIfNull(additionalUnsafeIpAddresses);

        return InternalIsUnsafe(
            uri: uri,
            allowInsecureProtocols: false,
            allowLoopback: false,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowedHostnames: null,
            hostEntryResolver: null,
            cancellationToken: cancellationToken);
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
    /// <returns><see langword="true" /> if the <paramref name="uri" /> is considered unsafe, otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> is <see langword="null"/>.</exception>
    public static Task<bool> IsUnsafe(
        Uri uri,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);

        return InternalIsUnsafe(
            uri: uri,
            allowInsecureProtocols: false,
            allowLoopback: false,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowedHostnames: null,
            hostEntryResolver: null,
            cancellationToken: cancellationToken);
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
    /// <returns><see langword="true" /> if the <paramref name="uri" /> is considered unsafe, otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> is <see langword="null"/>.</exception>
    public static Task<bool> IsUnsafe(
        Uri uri,
        bool allowInsecureProtocols,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);

        return InternalIsUnsafe(
            uri: uri,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: false,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowedHostnames: null,
            hostEntryResolver: null,
            cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Implements simple SSRF validation on the specified <paramref name="uri"/> by checking 
    /// its protocol (HTTPS only), host name type, whether it is absolute, loopback, UNC, and its scheme, and that
    /// the host resolves to a public IP address which is not in a known unsafe range.
    /// </summary>
    /// <param name="uri">The <see cref="Uri"/> to validate.</param>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <param name="allowLoopback">Flag indicating whether localhost URIs will be allowed or rejected.</param>
    /// <param name="additionalUnsafeNetworks">Optional additional networks to consider unsafe.</param>
    /// <param name="additionalUnsafeIpAddresses">Optional additional IP addresses to consider unsafe.</param>
    /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
    /// <returns><see langword="true" /> if the <paramref name="uri" /> is considered unsafe, otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> is <see langword="null"/>.</exception>
    public static Task<bool> IsUnsafe(
        Uri uri,
        bool allowInsecureProtocols,
        bool allowLoopback,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);

        return InternalIsUnsafe(
            uri: uri,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: allowLoopback,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowedHostnames: null,
            hostEntryResolver: null,
            cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Implements simple SSRF validation on the specified <paramref name="uri"/> by checking 
    /// its protocol (HTTPS only), host name type, whether it is absolute, loopback, UNC, and its scheme, and that
    /// the host resolves to a public IP address which is not in a known unsafe range.
    /// </summary>
    /// <param name="uri">The <see cref="Uri"/> to validate.</param>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <param name="allowLoopback">Flag indicating whether localhost URIs will be allowed or rejected.</param>
    /// <param name="additionalUnsafeNetworks">Optional additional networks to consider unsafe.</param>
    /// <param name="additionalUnsafeIpAddresses">Optional additional IP addresses to consider unsafe.</param>
    /// <param name="allowedHostnames">
    ///     Gets or sets an optional collection of hostnames that are allowed to bypass SSRF IP address protections.
    ///     This can be used to allow specific trusted hosts names.
    ///     Wild cards are supported only at the start of the hostname, and must be followed by a dot
    ///     (e.g. "*.example.com" would allow "api.example.com", "test.api.example.com", but not "example.com").
    /// </param>
    /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
    /// <returns><see langword="true" /> if the <paramref name="uri" /> is considered unsafe, otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> is <see langword="null"/>.</exception>
    public static Task<bool> IsUnsafe(
        Uri uri,
        bool allowInsecureProtocols,
        bool allowLoopback,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        ICollection<string>? allowedHostnames,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);

        return InternalIsUnsafe(
            uri: uri,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: allowLoopback,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowedHostnames: allowedHostnames,
            hostEntryResolver: null,
            cancellationToken: cancellationToken);
    }

    [SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with \"LINQ\" expressions", Justification = "Avoids delegate allocation on hot path.")]
    internal static async Task<bool> InternalIsUnsafe(
        Uri uri,
        bool allowInsecureProtocols,
        bool allowLoopback,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        ICollection<string>? allowedHostnames,
        Func<string, CancellationToken, Task<IPHostEntry>>? hostEntryResolver = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);

        hostEntryResolver ??= s_defaultHostEntryResolver;

        if (IsUnsafeUri(
            uri: uri,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: allowLoopback))
        {
            return true;
        }

        if (uri.HostNameType == UriHostNameType.IPv4 || uri.HostNameType == UriHostNameType.IPv6)
        {
            var ipAddress = IPAddress.Parse(uri.Host);

            return IsUnsafeIpAddress(
                ipAddress: ipAddress,
                additionalUnsafeNetworks: additionalUnsafeNetworks,
                additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
                allowLoopback: allowLoopback);
        }

        if (IsInAllowedHostnames(uri, allowedHostnames))
        {
            return false;
        }

        IPHostEntry? hostEntry = await hostEntryResolver(uri.Host, cancellationToken).ConfigureAwait(false);
        if (hostEntry is null || hostEntry.AddressList.Length == 0)
        {
            return true;
        }

        foreach (IPAddress ipAddress in hostEntry.AddressList)
        {
            if (IsUnsafeIpAddress(
                ipAddress: ipAddress,
                additionalUnsafeNetworks: additionalUnsafeNetworks,
                additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
                allowLoopback: allowLoopback))
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
            bool isWildcard = safeHostName.StartsWith("*.", StringComparison.OrdinalIgnoreCase);

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

}
