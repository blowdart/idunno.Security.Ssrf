using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace idunno.Security;

/// <summary>
/// Contains helper methods for validating URIs and IP addresses to mitigate SSRF (Server-Side Request Forgery) vulnerabilities.
/// </summary>
public sealed class SsrfSocketsHttpHanderFactory
{
    [ExcludeFromCodeCoverage]
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
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: null,
            failMixedResults: true,
            allowInsecureProtocols: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null);
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
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: null,
            failMixedResults: true,
            allowInsecureProtocols: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null);
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
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            failMixedResults: true,
            allowInsecureProtocols: false,
            connectTimeout: connectTimeout,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="additionalUnsafeNetworks">An optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe. This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ICollection<IPNetwork> additionalUnsafeNetworks)
    {
        return Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: null,
            connectTimeout: null,
            failMixedResults: true,
            allowAutoRedirect: false,
            allowInsecureProtocols: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(bool allowInsecureProtocols)
    {
        return Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: null,
            failMixedResults: true,
            allowInsecureProtocols: allowInsecureProtocols,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="connectTimeout">The timespan to wait before the connection establishing times out. The default value is <see cref="System.Threading.Timeout.InfiniteTimeSpan"/>.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ConnectionStrategy connectionStrategy, TimeSpan connectTimeout)
    {
        return Create(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            failMixedResults: true,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="additionalUnsafeNetworks">An optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe. This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.</param>
    /// <param name="connectTimeout">The connect timeout, in seconds. Defaults to 30 seconds if not specified.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ICollection<IPNetwork> additionalUnsafeNetworks, TimeSpan connectTimeout)
    {
        return Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: null,
            connectTimeout: connectTimeout,
            failMixedResults: true,
            allowInsecureProtocols: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="additionalUnsafeIpAddresses">An optional collection of additional <see cref="IPAddress"/> addresses to consider unsafe. This can be used to block additional IP addresses beyond the built-in defaults, such as internal application IP addresses or other known unsafe addresses.</param>
    /// <param name="connectTimeout">The connect timeout, in seconds. Defaults to 30 seconds if not specified.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ICollection<IPAddress> additionalUnsafeIpAddresses, TimeSpan connectTimeout)
    {
        return Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            connectTimeout: connectTimeout,
            failMixedResults: true,
            allowInsecureProtocols: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="additionalUnsafeNetworks">An optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe. This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ConnectionStrategy connectionStrategy, ICollection<IPNetwork> additionalUnsafeNetworks)
    {
        return Create(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: null,
            allowInsecureProtocols: false,
            failMixedResults: true,
            connectTimeout: null,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="additionalUnsafeIpAddresses">An optional collection of additional <see cref="IPAddress"/> addresses to consider unsafe. This can be used to block additional IP addresses beyond the built-in defaults, such as internal application IP addresses or other known unsafe addresses.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ConnectionStrategy connectionStrategy, ICollection<IPAddress> additionalUnsafeIpAddresses)
    {
        return Create(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowInsecureProtocols: false,
            failMixedResults: true,
            connectTimeout: null,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="additionalUnsafeNetworks">An optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe. This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.</param>
    /// <param name="additionalUnsafeIpAddresses">An optional collection of additional <see cref="IPAddress"/> addresses to consider unsafe. This can be used to block additional IP addresses beyond the built-in defaults, such as internal application IP addresses or other known unsafe addresses.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ConnectionStrategy connectionStrategy, ICollection<IPNetwork> additionalUnsafeNetworks, ICollection<IPAddress> additionalUnsafeIpAddresses)
    {
        return Create(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowInsecureProtocols: false,
            failMixedResults: true,
            connectTimeout: null,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="additionalUnsafeNetworks">An optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe. This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.</param>
    /// <param name="connectTimeout">The timespan to wait before the connection establishing times out. The default value is <see cref="System.Threading.Timeout.InfiniteTimeSpan"/>.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ConnectionStrategy connectionStrategy, ICollection<IPNetwork> additionalUnsafeNetworks, TimeSpan connectTimeout)
    {
        return Create(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: null,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="options">The <see cref="SsrfOptions"/> to use for configuring the handler.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="options"/> is <see langword="null"/>.</exception>
    public static SocketsHttpHandler Create(SsrfOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return Create(
            connectionStrategy: options.ConnectionStrategy,
            additionalUnsafeNetworks: options.AdditionalUnsafeNetworks,
            additionalUnsafeIpAddresses: options.AdditionalUnsafeIpAddresses,
            connectTimeout: options.ConnectTimeout,
            allowInsecureProtocols: options.AllowInsecureProtocols,
            failMixedResults: options.FailMixedResults,
            allowAutoRedirect: options.AllowAutoRedirect,
            automaticDecompression: options.AutomaticDecompression,
            proxy: options.Proxy,
            sslOptions: options.SslOptions);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="additionalUnsafeNetworks">An optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe. This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.</param>
    /// <param name="additionalUnsafeIpAddresses">An optional collection of additional <see cref="IPAddress"/> addresses to consider unsafe. This can be used to block additional IP addresses beyond the built-in defaults, such as internal application IP addresses or other known unsafe addresses.</param>
    /// <param name="connectTimeout">The timespan to wait before the connection establishing times out. The default value is <see cref="System.Threading.Timeout.InfiniteTimeSpan"/>.</param>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <param name="failMixedResults">Flag indicating whether to fail when a mixture of safe and unsafe addresses is found. Setting this to <see langword="true"/> will reject the connection if any unsafe addresses are found.</param>
    /// <param name="allowAutoRedirect">Flag indicating whether to allow auto-redirects. Setting this to <see langword="true"/> can introduce security vulnerabilities and should only be enabled if necessary.</param>
    /// <param name="automaticDecompression">The type of decompression to use for automatic decompression of HTTP content. If <see langword="null"/>, defaults to <see cref="DecompressionMethods.All"/>.</param>
    /// <param name="proxy">An optional custom proxy to use.</param>
    /// <param name="sslOptions">Any <see cref="SslClientAuthenticationOptions" /> to use for client TLS authentication.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(
        ConnectionStrategy connectionStrategy,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        TimeSpan? connectTimeout,
        bool allowInsecureProtocols,
        bool failMixedResults,
        bool allowAutoRedirect,
        DecompressionMethods? automaticDecompression,
        IWebProxy? proxy,
        SslClientAuthenticationOptions? sslOptions)
    {
        return Create(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: allowInsecureProtocols,
            failMixedResults: failMixedResults,
            allowAutoRedirect: allowAutoRedirect,
            automaticDecompression: automaticDecompression,
            proxy: proxy,
            sslOptions: sslOptions,
            hostEntryResolver: null);
    }

    internal static SocketsHttpHandler Create(
        SsrfOptions options,
        Func<string, CancellationToken, Task<IPHostEntry>>? hostEntryResolver)
    {
        ArgumentNullException.ThrowIfNull(options);
        return Create(
            connectionStrategy: options.ConnectionStrategy,
            additionalUnsafeNetworks: options.AdditionalUnsafeNetworks,
            additionalUnsafeIpAddresses: options.AdditionalUnsafeIpAddresses,
            connectTimeout: options.ConnectTimeout,
            allowInsecureProtocols: options.AllowInsecureProtocols,
            failMixedResults: options.FailMixedResults,
            allowAutoRedirect: options.AllowAutoRedirect,
            automaticDecompression: options.AutomaticDecompression,
            proxy: options.Proxy,
            sslOptions: options.SslOptions,
            hostEntryResolver: hostEntryResolver);
    }

    internal static SocketsHttpHandler Create(
        ConnectionStrategy connectionStrategy,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        TimeSpan? connectTimeout,
        bool allowInsecureProtocols,
        bool failMixedResults,
        bool allowAutoRedirect,
        DecompressionMethods? automaticDecompression,
        IWebProxy? proxy,
        SslClientAuthenticationOptions? sslOptions,
        Func<string, CancellationToken, Task<IPHostEntry>>? hostEntryResolver)
    {
        hostEntryResolver ??= Dns.GetHostEntryAsync;

        SocketsHttpHandler handler = new()
        {
            AllowAutoRedirect = allowAutoRedirect,
            AutomaticDecompression = automaticDecompression ?? DecompressionMethods.All,
            EnableMultipleHttp2Connections = true,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
            UseCookies = false,

            ConnectCallback = async (context, cancellationToken) =>
            {
                ArgumentNullException.ThrowIfNull(context);

                // Do not cache results of DNS resolution to ensure that SSRF protections are applied to each connection attempt, even if the same host is targeted multiple times.
                // This may result in additional latency for connections due to DNS lookups, but is necessary as caching would introduce a TOCTOU (Time of Check to Time of Use)
                // vulnerability where an attacker could change the resolved IP address after validation but before connection.

                IPAddress[] resolvedIpAddresses = [];
                List<IPAddress> safeResolvedIPAddresses = [];

                Uri requestedUri = context.InitialRequestMessage.RequestUri ?? throw new InvalidOperationException("The request message must have a RequestUri.");

                if (Ssrf.IsUnsafeUri(requestedUri, allowInsecureProtocols))
                {
                    throw new SsrfException(requestedUri, $"Connection blocked as the uri is considered unsafe.");
                }

                if (IPAddress.TryParse(context.DnsEndPoint.Host, out IPAddress? parsedAddress))
                {
                    resolvedIpAddresses = [parsedAddress];
                }
                else
                {
                    try
                    {
                        IPHostEntry entry = await hostEntryResolver(context.DnsEndPoint.Host, cancellationToken).ConfigureAwait(false);

                        if (entry.AddressList is not null)
                        {
                            resolvedIpAddresses = entry.AddressList;
                        }
                    }
                    catch (Exception ex)
                    {
                        // Some DNS proxies or internal servers may already strip dangerous lookups, so if the host cannot be resolved, we can treat it as unsafe and block the connection.
                        throw new SsrfException(requestedUri, $"Connection blocked as host could not be resolved.", inner: ex);
                    }
                }

                // If no IP addresses were resolved, early exit and block the connection as this is could be potential SSRF attack where the attacker is attempting to connect to a non-existent or internal host that is not resolvable through DNS.
                if (resolvedIpAddresses.Length == 0)
                {
                    throw new SsrfException(requestedUri, $"Connection blocked as host could not be resolved to any IP addresses.");
                }

                // Pare down the list of resolved IP addresses to just the safe addresses by applying the built-in and additional unsafe IP and network rules.
                safeResolvedIPAddresses.AddRange(from IPAddress address in resolvedIpAddresses
                                                 where !Ssrf.IsUnsafeIpAddress(address, additionalUnsafeNetworks, additionalUnsafeIpAddresses)
                                                 select address);

                // If no safe IP addresses remain after filtering, block the connection as all resolved addresses are unsafe.
                // If some safe addresses remain but others were filtered out as unsafe, the behavior will depend on the value of the failMixedResults flag. 
                if (safeResolvedIPAddresses.Count == 0)
                {
                    throw new SsrfException(requestedUri, $"Connection blocked as all resolved addresses are unsafe.");
                }

                // If failMixedResults is set to true, block the connection if any unsafe addresses were found, even if some safe addresses remain.
                // This is a more conservative approach that errs on the side of blocking potentially unsafe connections, but may cause connectivity
                // issues if there are misconfigurations in DNS or the additional unsafe lists.
                if (failMixedResults && safeResolvedIPAddresses.Count != resolvedIpAddresses.Length)
                {
                    throw new SsrfException(requestedUri, $"Connection blocked as some resolved addresses are unsafe.");
                }

                // Reorder the list of safe IP addresses based on the specified connection strategy, if there are multiple addresses to choose from.
                if (safeResolvedIPAddresses.Count > 1)
                {
                    if (connectionStrategy.HasFlag(ConnectionStrategy.Random))
                    {
                        safeResolvedIPAddresses = [.. safeResolvedIPAddresses.OrderBy(_ => RandomNumberGenerator.GetInt32(0, safeResolvedIPAddresses.Count))];
                    }

                    if (connectionStrategy.HasFlag(ConnectionStrategy.Ipv4Preferred))
                    {
                        safeResolvedIPAddresses = [.. safeResolvedIPAddresses.OrderByDescending(a => a.AddressFamily == AddressFamily.InterNetwork)];
                    }
                    else if (connectionStrategy.HasFlag(ConnectionStrategy.Ipv6Preferred))
                    {
                        safeResolvedIPAddresses = [.. safeResolvedIPAddresses.OrderByDescending(a => a.AddressFamily == AddressFamily.InterNetworkV6)];
                    }
                }

                // Attempt to connect to each safe IP address until a successful connection is made.
                foreach (IPAddress address in safeResolvedIPAddresses)
                {
                    Socket socket = new(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    try
                    {
                        await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), cancellationToken).ConfigureAwait(false);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch (SocketException)
                    {
                        socket.Dispose();
                        continue;
                    }
                    catch
                    {
                        socket.Dispose();
                        throw;
                    }
                }

                throw new SocketException((int)SocketError.HostUnreachable);
            }
        };

        if (connectTimeout is not null)
        {
            handler.ConnectTimeout = connectTimeout.Value;
        }

        if (sslOptions is not null)
        {
            handler.SslOptions = sslOptions;
        }

        if (proxy is not null)
        {
            handler.Proxy = proxy;
            handler.UseProxy = true;
        }

        return handler;
    }
}
