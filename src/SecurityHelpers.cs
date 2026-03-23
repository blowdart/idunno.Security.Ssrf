using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Linq;

namespace idunno.Security.Ssrf;

/// <summary>
/// Contains helper methods for validating URIs and IP addresses to mitigate SSRF (Server-Side Request Forgery) vulnerabilities.
/// </summary>
public sealed class SecurityHelpers
{
    private SecurityHelpers()
    {
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host. Defaults to <see cref="ConnectionStrategy.None"/> if not specified.</param>
    /// <param name="connectTimeout">The connect timeout, in seconds. Defaults to 30 seconds if not specified.</param>
    /// <param name="proxyUri">An optional proxy <see cref="Uri"/>.</param>
    /// <param name="checkCertificateRevocationList">Flag indicating whether to check the certificate revocation list. Setting this to <see langword="true"/> can introduce security vulnerabilities and should only be enabled if necessary.</param>
    /// <param name="allowAutoRedirect">Flag indicating whether to allow auto-redirects. Setting this to <see langword="true"/> can introduce security vulnerabilities and should only be enabled if necessary.</param>
    /// <returns>A <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5394:Do not use insecure randomness", Justification = "Not a cryptographically secure function.")]
    public static SocketsHttpHandler BuildSSRFHttpHandler(
        ConnectionStrategy connectionStrategy = ConnectionStrategy.None,
        TimeSpan? connectTimeout = null,
        Uri? proxyUri = null,
        bool checkCertificateRevocationList = true,
        bool allowAutoRedirect = false)
    {
        connectTimeout ??= TimeSpan.FromSeconds(30);

        SocketsHttpHandler handler = new()
        {
            AllowAutoRedirect = allowAutoRedirect,
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = connectTimeout.Value,
            EnableMultipleHttp2Connections = true,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
            SslOptions = new System.Net.Security.SslClientAuthenticationOptions
            {
                CertificateRevocationCheckMode = checkCertificateRevocationList
                    ? X509RevocationMode.Online
                    : X509RevocationMode.NoCheck
            },
            UseCookies = false,

            ConnectCallback = async (context, cancellationToken) =>
            {
                ArgumentNullException.ThrowIfNull(context);

                // Do not cache results of DNS resolution to ensure that SSRF protections are applied to each connection attempt, even if the same host is targeted multiple times.
                // This may result in additional latency for connections due to DNS lookups, but is necessary as caching would introduce a TOCTOU (Time of Check to Time of Use)
                // vulnerability where an attacker could change the resolved IP address after validation but before connection.

                IPAddress[] addresses;
                List<IPAddress> safeIPAddresses = [];

                if (IPAddress.TryParse(context.DnsEndPoint.Host, out IPAddress? parsedAddress))
                {
                    addresses = [parsedAddress];
                }
                else
                {
                    IPHostEntry entry = await Dns.GetHostEntryAsync(context.DnsEndPoint.Host, cancellationToken).ConfigureAwait(false);
                    addresses = entry.AddressList;
                }
                safeIPAddresses.AddRange(from IPAddress address in addresses
                                         where !IsUnsafeIpAddress(address)
                                         select address);

                if (connectionStrategy.HasFlag(ConnectionStrategy.Random))
                {
                    Random rng = new();
                    safeIPAddresses = [.. safeIPAddresses.OrderBy(_ => rng.Next())];
                }

                // Reorder the list of safe IP addresses based on the specified connection strategy.
                if (connectionStrategy.HasFlag(ConnectionStrategy.Ipv4Preferred))
                {
                    safeIPAddresses = [.. safeIPAddresses.OrderByDescending(a => a.AddressFamily == AddressFamily.InterNetwork)];
                }
                else if (connectionStrategy.HasFlag(ConnectionStrategy.Ipv6Preferred))
                {
                    safeIPAddresses = [.. safeIPAddresses.OrderByDescending(a => a.AddressFamily == AddressFamily.InterNetworkV6)];
                }

                if (safeIPAddresses.Count > 0)
                {
                    // Attempt to connect to each safe IP address until a successful connection is made.

                    foreach (IPAddress address in safeIPAddresses)
                    {
                        Socket socket = new(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                        try
                        {
                            await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), cancellationToken).ConfigureAwait(false);
                        }
                        catch (SocketException)
                        {
                            socket.Dispose();
                            continue;
                        }

                        return new NetworkStream(socket, ownsSocket: true);
                    }

                    throw new SocketException((int)SocketError.HostUnreachable);
                }

                throw new HttpRequestException($"Connection to {context.DnsEndPoint.Host} blocked as all resolved addresses are unsafe.");
            }
        };

        if (proxyUri is not null)
        {
            handler.Proxy = new WebProxy(proxyUri);
            handler.UseProxy = true;
        }

        return handler;
    }

    /// <summary>
    /// Implements simple SSRF validation on the specified <paramref name="uri"/> by checking if the host resolves to a public IP address.
    /// </summary>
    /// <param name="uri">The <see cref="Uri"/> to validate.</param>
    /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
    /// <returns><see langword="true" /> if the <paramref name="uri" /> is considered safe, otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> is <see langword="null"/>.</exception>
    public static async Task<bool> DefaultDiscoveryUriValidator(Uri uri, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);

        if (IsUnsafeUri(uri))
        {
            return false;
        }

        if (uri.HostNameType == UriHostNameType.IPv4 || uri.HostNameType == UriHostNameType.IPv6)
        {
            var ipAddress = IPAddress.Parse(uri.Host);

            if (IsUnsafeIpAddress(ipAddress))
            {
                return false;
            }
            else
            {
                return true;
            }
        }
        else
        {
            IPHostEntry? hostEntry = await Dns.GetHostEntryAsync(uri.Host, cancellationToken).ConfigureAwait(false);
            if (hostEntry is null || hostEntry.AddressList is null)
            {
                return false;
            }

            bool discoveredUnsafeIPAddress = false;

            foreach (IPAddress entry in hostEntry.AddressList.Where(IsUnsafeIpAddress))
            {
                discoveredUnsafeIPAddress = true;
            }

            return !discoveredUnsafeIPAddress;
        }
    }

    internal static bool IsUnsafeUri(Uri uri)
    {
        if (uri.HostNameType != UriHostNameType.Dns &&
            uri.HostNameType != UriHostNameType.IPv4 &&
            uri.HostNameType != UriHostNameType.IPv6)
        {
            return true;
        }

        if (!uri.IsAbsoluteUri ||
            uri.IsLoopback ||
            uri.IsUnc)
        {
            return true;
        }

        if (!Uri.UriSchemeHttps.Equals(uri.Scheme, StringComparison.OrdinalIgnoreCase) &&
            !Uri.UriSchemeHttp.Equals(uri.Scheme, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        else
        {
            return false;
        }
    }

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
            new(IPAddress.Parse("240.0.0.0"), 4),

            // IPv4 limited broadcast
            new(IPAddress.Parse("255.255.255.255"), 1),

            // Cloud metadata endpoint used by AWS, Azure, and Google Cloud.
            new (IPAddress.Parse("169.254.169.254"), 1)
        ];

    private static readonly ICollection<IPNetwork> s_ipv6UnsafeRangeCollection =
        [
            // IPv6 link-local https://datatracker.ietf.org/doc/html/rfc4291
            new(IPAddress.Parse("fe80::"), 10),

            // IPv6 unique local https://datatracker.ietf.org/doc/html/rfc4193
            new(IPAddress.Parse("fc00::"), 7),

            // IPv6 site-local (deprecated but still widely used) https://datatracker.ietf.org/doc/html/rfc4291
            new(IPAddress.Parse("fec0::"), 10),

            // IETF Protocol Assignments https://datatracker.ietf.org/doc/html/rfc6890
            new (IPAddress.Parse("2001::"), 23),

            // Documentation IPv6 addresses https://datatracker.ietf.org/doc/html/rfc3849
            new (IPAddress.Parse("2001:db8::"), 32)
        ];

    internal static bool IsUnsafeIpAddress(IPAddress ipAddress)
    {
        ArgumentNullException.ThrowIfNull(ipAddress);

        // Normalize IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) to IPv4 before range checks.
        if (ipAddress.IsIPv4MappedToIPv6)
        {
            ipAddress = ipAddress.MapToIPv4();
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

        if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            foreach (IPNetwork network in s_ipv4UnsafeRangeCollection)
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
            else foreach (IPNetwork network in s_ipv6UnsafeRangeCollection)
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
}

/// <summary>
/// Specifies the strategy used to select and attempt connections to resolved IP addresses for a given host.
/// </summary>
/// <remarks><para>Use this enumeration to control how connection attempts are prioritized among available IP addresses,
/// such as preferring IPv4 or IPv6, and randomizing the order to distribute load. The selected
/// strategy can affect connection performance, reliability, and distribution across multiple endpoints.</para></remarks>
[Flags]
public enum ConnectionStrategy
{
    /// <summary>
    /// The default connection strategy which attempts to connect to all resolved IP addresses for a given host and allows the system to determine the best connection.
    /// </summary>
    None = 0,

    /// <summary>
    /// A connection strategy that attempts to connect to IPv4 addresses first, and only falls back to IPv6 if no IPv4 addresses are available or all connection attempts to IPv4 addresses fail.
    /// </summary>
    Ipv4Preferred = 1,

    /// <summary>
    /// A connection strategy that attempts to connect to IPv6 addresses first, and only falls back to IPv4 if no IPv6 addresses are available or all connection attempts to IPv6 addresses fail.
    /// </summary>
    Ipv6Preferred = 2,

    /// <summary>
    /// Randomly shuffle the order of resolved IP addresses, and attempt to connect in that random order. This can be used as a simple strategy to distribute connections across multiple resolved addresses for a given host.
    /// </summary>
    Random = 4
}

