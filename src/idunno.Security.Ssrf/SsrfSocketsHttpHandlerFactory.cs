// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace idunno.Security;

/// <summary>
/// Contains helper methods for validating URIs and IP addresses to mitigate SSRF (Server-Side Request Forgery) vulnerabilities.
/// </summary>
public sealed class SsrfSocketsHttpHandlerFactory
{
    [ExcludeFromCodeCoverage]
    private SsrfSocketsHttpHandlerFactory()
    {
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="additionalUnsafeIPNetworks">An optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe. This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.</param>
    /// <param name="additionalUnsafeIPAddresses">An optional collection of additional <see cref="IPAddress"/> addresses to consider unsafe. This can be used to block additional IP addresses beyond the built-in defaults, such as internal application IP addresses or other known unsafe addresses.</param>
    /// <param name="allowedHostnames">
    ///     An optional collection of hostnames that are allowed to bypass SSRF IP address protections.
    ///     This can be used to allow specific trusted hosts names.
    ///     Wild cards are supported only at the start of the hostname, and must be followed by a dot
    ///     (e.g. "*.example.com" would allow "api.example.com", "test.api.example.com", but not "example.com").
    /// </param>
    /// <param name="safeIPNetworks">Optional additional IP networks to consider safe, which can be used to allow specific safe ranges that would otherwise be blocked by the unsafe checks.</param>
    /// <param name="safeIPAddresses">Optional additional IP addresses to consider safe, which can be used to allow specific safe addresses that would otherwise be blocked by the unsafe checks.</param>
    /// <param name="connectTimeout">The timespan to wait before the connection establishing times out. The default value is <see cref="System.Threading.Timeout.InfiniteTimeSpan"/>.</param>
    /// <param name="allowedSchemes">An optional collection of URI schemes that are allowed. This can be used to restrict or allow specific protocols such as "http" or "ws". If <see langword="null"/>, defaults to allow https and wss.</param>
    /// <param name="allowLoopback">Flag indicating whether loopback addresses will be allowed or rejected.</param>
    /// <param name="failMixedResults">Flag indicating whether to fail when a mixture of safe and unsafe addresses is found. Setting this to <see langword="true"/> will reject the connection if any unsafe addresses are found.</param>
    /// <param name="allowAutoRedirect">Flag indicating whether to allow auto-redirects. Setting this to <see langword="true"/> can introduce security vulnerabilities and should only be enabled if necessary.</param>
    /// <param name="automaticDecompression">The type of decompression to use for automatic decompression of HTTP content. If <see langword="null"/>, defaults to <see cref="DecompressionMethods.All"/>.</param>
    /// <param name="sslOptions">Any <see cref="SslClientAuthenticationOptions" /> to use for client TLS authentication.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <param name="meterFactory">An optional <see cref="IMeterFactory"/> to use for metrics. If not provided, a default <see cref="Meter"/>will be used.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    /// <remarks>
    /// <para>
    ///   Careless use of <paramref name="safeIPNetworks"/> and <paramref name="safeIPAddresses"/> can lead to security vulnerabilities by allowing potentially unsafe IP addresses or networks
    ///   to be considered safe. Use with caution and constrain the values specified to the smallest network range or individual IP addresses needed.
    ///   Safe entries take precedence over both built-in and additional unsafe entries, so if an IP address matches both a safe and unsafe address, or is within a safe network,
    ///   it will be considered safe.
    ///</para>
    /// </remarks>
    public static SocketsHttpHandler Create(
        ConnectionStrategy connectionStrategy = ConnectionStrategy.None,
        ICollection<IPNetwork>? additionalUnsafeIPNetworks = null,
        ICollection<IPAddress>? additionalUnsafeIPAddresses = null,
        ICollection<string>? allowedHostnames = null,
        ICollection<IPNetwork>? safeIPNetworks = null,
        ICollection<IPAddress>? safeIPAddresses = null,
        TimeSpan? connectTimeout = null,
        ICollection<string>? allowedSchemes = null,
        bool allowLoopback = false,
        bool failMixedResults = true,
        bool allowAutoRedirect = false,
        DecompressionMethods? automaticDecompression = null,
        SslClientAuthenticationOptions? sslOptions = null,
        ILoggerFactory? loggerFactory = null,
        IMeterFactory? meterFactory = null)
    {
        return InternalCreate(
            connectionStrategy: connectionStrategy,
            additionalUnsafeIPNetworks: additionalUnsafeIPNetworks,
            additionalUnsafeIPAddresses: additionalUnsafeIPAddresses,
            allowedHostnames: allowedHostnames,
            safeIPNetworks: safeIPNetworks,
            safeIPAddresses: safeIPAddresses,
            connectTimeout: connectTimeout,
            allowedSchemes: allowedSchemes,
            allowLoopback: allowLoopback,
            failMixedResults: failMixedResults,
            allowAutoRedirect: allowAutoRedirect,
            automaticDecompression: automaticDecompression,
            proxy: null,
            sslOptions: sslOptions,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory,
            meterFactory: meterFactory);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="options">The <see cref="SsrfOptions"/> to use for configuring the handler.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <param name="meterFactory">An optional <see cref="IMeterFactory"/> to use for metrics. If not provided, a default <see cref="Meter"/>will be used.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="options"/> is <see langword="null"/>.</exception>
    public static SocketsHttpHandler Create(
        SsrfOptions options,
        ILoggerFactory? loggerFactory = null,
        IMeterFactory? meterFactory = null)
    {
        ArgumentNullException.ThrowIfNull(options);

        return InternalCreate(
            options: options,
            hostEntryResolver: null,
            loggerFactory: loggerFactory,
            meterFactory: meterFactory);
    }

    internal static SocketsHttpHandler InternalCreate(
        SsrfOptions options,
        Func<string, CancellationToken, Task<IPHostEntry>>? hostEntryResolver,
        ILoggerFactory? loggerFactory,
        IMeterFactory? meterFactory)
    {
        ArgumentNullException.ThrowIfNull(options);

        return InternalCreate(
            connectionStrategy: options.ConnectionStrategy,
            additionalUnsafeIPNetworks: options.AdditionalUnsafeIPNetworks,
            additionalUnsafeIPAddresses: options.AdditionalUnsafeIPAddresses,
            allowedHostnames: options.AllowedHostnames,
            safeIPNetworks: options.SafeIPNetworks,
            safeIPAddresses: options.SafeIPAddresses,
            connectTimeout: options.ConnectTimeout,
            allowedSchemes: options.AllowedSchemes,
            failMixedResults: options.FailMixedResults,
            allowAutoRedirect: options.AllowAutoRedirect,
            allowLoopback: options.AllowLoopback,
            automaticDecompression: options.AutomaticDecompression,
            proxy: null,
            sslOptions: options.SslOptions,
            asyncHostEntryResolver: hostEntryResolver,
            loggerFactory: loggerFactory,
            meterFactory: meterFactory);
    }

    internal static SocketsHttpHandler InternalCreate(
        ConnectionStrategy connectionStrategy,
        ICollection<IPNetwork>? additionalUnsafeIPNetworks,
        ICollection<IPAddress>? additionalUnsafeIPAddresses,
        ICollection<string>? allowedHostnames,
        ICollection<IPNetwork>? safeIPNetworks,
        ICollection<IPAddress>? safeIPAddresses,
        TimeSpan? connectTimeout,
        ICollection<string>? allowedSchemes,
        bool allowLoopback,
        bool failMixedResults,
        bool allowAutoRedirect,
        DecompressionMethods? automaticDecompression,
        WebProxy? proxy,
        SslClientAuthenticationOptions? sslOptions,
        Func<string, CancellationToken, Task<IPHostEntry>>? asyncHostEntryResolver,
        ILoggerFactory? loggerFactory,
        IMeterFactory? meterFactory)
    {
        if (proxy is not null && proxy.Address is null)
        { 
            throw new ArgumentException("The WebProxy instance must have a non-null Address property.", nameof(proxy));
        }

        asyncHostEntryResolver ??= Defaults.GetHostEntryAsync;
        loggerFactory ??= NullLoggerFactory.Instance;
        ILogger logger = loggerFactory.CreateLogger<SsrfSocketsHttpHandlerFactory>();
        SsrfMetrics metrics = new(meterFactory);

        ICollection<string> snapshottedAllowedSchemes = allowedSchemes != null ? [.. allowedSchemes] : Defaults.AllowedSchemes;

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

                // If the handler is used directly requestedUri will be the destination URI.
                // If the handler wrapped inside the proxy handler the requestedUri will be the proxy URI.

                Uri requestedUri = context.InitialRequestMessage.RequestUri ?? throw new InvalidOperationException("The request message must have a RequestUri.");
                IPAddress[] resolvedIPAddresses;

                bool requestIsToProxy = proxy?.Address is Uri proxyAddress &&
                    context.DnsEndPoint.Host.Equals(proxyAddress.IdnHost, StringComparison.OrdinalIgnoreCase) &&
                    context.DnsEndPoint.Port == proxyAddress.Port;

                if (requestIsToProxy)
                {
                    Uri connectUri = new UriBuilder(requestedUri.Scheme, context.DnsEndPoint.Host, context.DnsEndPoint.Port).Uri;

                    try
                    {
                        resolvedIPAddresses = await CommonFunctions.GetHostEntryAsync(connectUri, logger, asyncHostEntryResolver, cancellationToken).ConfigureAwait(false);
                    }
                    catch (SsrfException)
                    {
                        Log.DnsResolutionFailed(logger, requestedUri);
                        metrics.IncrementBlockedRequests();
                        throw;
                    }
                }
                else
                {
                    if (Ssrf.IsUnsafeUri(
                        uri: requestedUri,
                        allowedSchemes: snapshottedAllowedSchemes,
                        allowLoopback: allowLoopback,
                        metrics: metrics))
                    {
                        Log.UnsafeUri(logger, requestedUri);
                        metrics.IncrementBlockedRequests();
                        throw new SsrfException(requestedUri, $"Connection blocked as the uri is considered unsafe.");
                    }

                    try
                    {
                        resolvedIPAddresses = await CommonFunctions.ResolveAndReturnSafeIPAddressesAsync(
                            uri: requestedUri,
                            additionalUnsafeIPNetworks: additionalUnsafeIPNetworks,
                            additionalUnsafeIPAddresses: additionalUnsafeIPAddresses,
                            allowedHostnames: allowedHostnames,
                            safeIPNetworks: safeIPNetworks,
                            safeIPAddresses: safeIPAddresses,
                            allowLoopback: allowLoopback,
                            failMixedResults: failMixedResults,
                            logger: logger,
                            metrics: metrics,
                            asyncHostEntryResolver: asyncHostEntryResolver,
                            cancellationToken: cancellationToken).ConfigureAwait(false);
                    }
                    catch (SsrfException)
                    {
                        Log.DnsResolutionFailed(logger, requestedUri);
                        metrics.IncrementBlockedRequests();
                        throw;
                    }
                }

                // Reorder the list of safe IP addresses based on the specified connection strategy, if there are multiple addresses to choose from.
                if (resolvedIPAddresses.Length > 1)
                {
                    if (connectionStrategy.HasFlag(ConnectionStrategy.Random))
                    {
                        // Shuffle in place O(n) in-place vs linq based O(n log n) OrderBy + new list allocation.
                        for (int i = resolvedIPAddresses.Length - 1; i > 0; i--)
                        {
                            int j = RandomNumberGenerator.GetInt32(0, i + 1);
                            (resolvedIPAddresses[i], resolvedIPAddresses[j]) = (resolvedIPAddresses[j], resolvedIPAddresses[i]);
                        }
                    }

                    if (connectionStrategy.HasFlag(ConnectionStrategy.Ipv4Preferred))
                    {
                        SortIpAddressListByFamily(resolvedIPAddresses, AddressFamily.InterNetwork);
                    }
                    else if (connectionStrategy.HasFlag(ConnectionStrategy.Ipv6Preferred))
                    {
                        SortIpAddressListByFamily(resolvedIPAddresses, AddressFamily.InterNetworkV6);
                    }
                }

                // Ensure the Host header is set to the original host from the request URI, as some servers require this and
                // it may not be set if the request URI was modified to use an IP address for connection.
                if (context.InitialRequestMessage.Headers.Host is null)
                {
                    string host = requestedUri.HostNameType switch
                    {
                        UriHostNameType.IPv6 => $"[{requestedUri.Host}]",
                        _ => requestedUri.IdnHost,
                    };
                    context.InitialRequestMessage.Headers.Host = requestedUri.IsDefaultPort
                        ? host
                        : $"{host}:{requestedUri.Port}";
                }

                // Attempt to connect to each safe IP address until a successful connection is made.
                foreach (IPAddress ipAddress in resolvedIPAddresses)
                {
                    Socket socket = new(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    try
                    {
                        try
                        {
                            socket.NoDelay = true;
                        }
                        catch (Exception ex) when (ex is SocketException or PlatformNotSupportedException)
                        {
                            // Best-effort optimization to match SocketsHttpHandler behavior.
                        }
                        await socket.ConnectAsync(new IPEndPoint(ipAddress, context.DnsEndPoint.Port), cancellationToken).ConfigureAwait(false);
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

                Log.HostUnreachable(logger, requestedUri);
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

    /// <summary>
    /// Moves all addresses matching <paramref name="preferredFamily"/> to the front of
    /// the list while preserving relative order within each group.
    /// </summary>
    internal static void SortIpAddressListByFamily(IPAddress[] addresses, AddressFamily preferredFamily)
    {
        int insertIndex = 0;
        for (int i = 0; i < addresses.Length; i++)
        {
            if (addresses[i].AddressFamily == preferredFamily)
            {
                if (i != insertIndex)
                {
                    IPAddress preferred = addresses[i];
                    for (int j = i; j > insertIndex; j--)
                    {
                        addresses[j] = addresses[j - 1];
                    }
                    addresses[insertIndex] = preferred;
                }

                insertIndex++;
            }
        }
    }
}
