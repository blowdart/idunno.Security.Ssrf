using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace idunno.Security;

/// <summary>
/// Contains helper methods for validating URIs and IP addresses to mitigate SSRF (Server-Side Request Forgery) vulnerabilities.
/// </summary>
public sealed class SsrfSocketsHttpHanderFactory
{
    private SsrfSocketsHttpHanderFactory()
    {
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create()
    {
        return Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalNetworks: null,
            connectTimeout: null,
            allowInsecureProtocols: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxyUri: null,
            checkCertificateRevocationList: true);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ConnectionStrategy connectionStrategy)
    {
        return Create(
            connectionStrategy: connectionStrategy,
            additionalNetworks: null,
            connectTimeout: null,
            allowInsecureProtocols: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxyUri: null,
            checkCertificateRevocationList: true);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectTimeout">The connect timeout, in seconds. Defaults to 30 seconds if not specified.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(TimeSpan connectTimeout)
    {
        return Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalNetworks: null,
            allowInsecureProtocols: false,
            connectTimeout: connectTimeout,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxyUri: null,
            checkCertificateRevocationList: true);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="additionalNetworks">An optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe. This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ICollection<IPNetwork> additionalNetworks)
    {
        return Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalNetworks: additionalNetworks,
            connectTimeout: null,
            allowAutoRedirect: false,
            allowInsecureProtocols: false,
            automaticDecompression: null,
            proxyUri: null,
            checkCertificateRevocationList: true);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="allowHttp">Flag indicating whether http URIs will be allowed or rejected.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(bool allowHttp)
    {
        return Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalNetworks: null,
            connectTimeout: null,
            allowInsecureProtocols: allowHttp,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxyUri: null,
            checkCertificateRevocationList: true);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="connectTimeout">The connect timeout, in seconds. Defaults to 30 seconds if not specified.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ConnectionStrategy connectionStrategy, TimeSpan connectTimeout)
    {
        return Create(
            connectionStrategy: connectionStrategy,
            additionalNetworks: null,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxyUri: null,
            checkCertificateRevocationList: true);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="additionalNetworks">An optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe. This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.</param>
    /// <param name="connectTimeout">The connect timeout, in seconds. Defaults to 30 seconds if not specified.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ICollection<IPNetwork> additionalNetworks, TimeSpan connectTimeout)
    {
        return Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalNetworks: additionalNetworks,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxyUri: null,
            checkCertificateRevocationList: true);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="additionalNetworks">An optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe. This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ConnectionStrategy connectionStrategy, ICollection<IPNetwork> additionalNetworks)
    {
        return Create(
            connectionStrategy: connectionStrategy,
            additionalNetworks: additionalNetworks,
            allowInsecureProtocols: false,
            connectTimeout: null,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxyUri: null,
            checkCertificateRevocationList: true);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="additionalNetworks">An optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe. This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.</param>
    /// <param name="connectTimeout">The connect timeout, in seconds. Defaults to 30 seconds if not specified.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ConnectionStrategy connectionStrategy, ICollection<IPNetwork> additionalNetworks, TimeSpan connectTimeout)
    {
        return Create(
            connectionStrategy: connectionStrategy,
            additionalNetworks: additionalNetworks,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxyUri: null,
            checkCertificateRevocationList: true);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="additionalNetworks">An optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe. This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.</param>
    /// <param name="connectTimeout">The connect timeout, in seconds. Defaults to 30 seconds if not specified.</param>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <param name="allowAutoRedirect">Flag indicating whether to allow auto-redirects. Setting this to <see langword="true"/> can introduce security vulnerabilities and should only be enabled if necessary.</param>
    /// <param name="automaticDecompression">The type of decompression to use for automatic decompression of HTTP content. If <see langword="null"/>, defaults to <see cref="DecompressionMethods.All"/>.</param>
    /// <param name="proxyUri">An optional proxy <see cref="Uri"/>.</param>
    /// <param name="checkCertificateRevocationList">Flag indicating whether to check the certificate revocation list. Setting this to <see langword="true"/> can introduce security vulnerabilities and should only be enabled if necessary.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(
        ConnectionStrategy connectionStrategy,
        ICollection<IPNetwork>? additionalNetworks,
        TimeSpan? connectTimeout,
        bool allowInsecureProtocols,
        bool allowAutoRedirect,
        DecompressionMethods? automaticDecompression,
        Uri? proxyUri,
        bool checkCertificateRevocationList)
    {
        connectTimeout ??= TimeSpan.FromSeconds(30);

        SocketsHttpHandler handler = new()
        {
            AllowAutoRedirect = allowAutoRedirect,
            AutomaticDecompression = automaticDecompression ?? DecompressionMethods.All,
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

                Uri requestedUri = context.InitialRequestMessage.RequestUri ?? throw new InvalidOperationException("The request message must have a RequestUri.");

                if (Ssrf.IsUnsafeUri(requestedUri, allowInsecureProtocols))
                {
                    throw new HttpRequestException($"Connection to {requestedUri} blocked as the uri is considered unsafe.");
                }

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
                                         where !Ssrf.IsUnsafeIpAddress(address, additionalNetworks)
                                         select address);

                if (connectionStrategy.HasFlag(ConnectionStrategy.Random))
                {
                    safeIPAddresses = [.. safeIPAddresses.OrderBy(_ => RandomNumberGenerator.GetInt32(0, safeIPAddresses.Count))];
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
