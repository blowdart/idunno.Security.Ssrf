// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
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
    private static readonly Func<string, CancellationToken, Task<IPHostEntry>> s_defaultHostEntryResolver = Dns.GetHostEntryAsync;

    [ExcludeFromCodeCoverage]
    private SsrfSocketsHttpHandlerFactory()
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
        return InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            connectTimeout: null,
            failMixedResults: true,
            allowInsecureProtocols: false,
            allowLoopback: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ILoggerFactory? loggerFactory)
    {
        return InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            connectTimeout: null,
            failMixedResults: true,
            allowInsecureProtocols: false,
            allowLoopback: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory);
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
        return InternalCreate(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            connectTimeout: null,
            failMixedResults: true,
            allowInsecureProtocols: false,
            allowLoopback: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ConnectionStrategy connectionStrategy, ILoggerFactory? loggerFactory)
    {
        return InternalCreate(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            connectTimeout: null,
            failMixedResults: true,
            allowInsecureProtocols: false,
            allowLoopback: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory);
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
        return InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            failMixedResults: true,
            allowInsecureProtocols: false,
            allowLoopback: false,
            connectTimeout: connectTimeout,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectTimeout">The connect timeout, in seconds. Defaults to 30 seconds if not specified.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(TimeSpan connectTimeout, ILoggerFactory? loggerFactory)
    {
        return InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            failMixedResults: true,
            allowInsecureProtocols: false,
            allowLoopback: false,
            connectTimeout: connectTimeout,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory);
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
        return InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            connectTimeout: null,
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: null);
    }


    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="additionalUnsafeNetworks">An optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe. This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ICollection<IPNetwork> additionalUnsafeNetworks, ILoggerFactory? loggerFactory)
    {
        return InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            connectTimeout: null,
            failMixedResults: true,
            allowInsecureProtocols: false,
            allowLoopback: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory);
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
        return InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            connectTimeout: null,
            failMixedResults: true,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(bool allowInsecureProtocols, ILoggerFactory? loggerFactory)
    {
        return InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            connectTimeout: null,
            failMixedResults: true,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <param name="allowLoopback">Flag indicating whether localhost and loopback addresses will be allowed or rejected.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(bool allowInsecureProtocols, bool allowLoopback)
    {
        return InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            connectTimeout: null,
            failMixedResults: true,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: allowLoopback,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <param name="allowLoopback">Flag indicating whether localhost and loopback addresses will be allowed or rejected.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(bool allowInsecureProtocols, bool allowLoopback, ILoggerFactory? loggerFactory)
    {
        return InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            connectTimeout: null,
            failMixedResults: true,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: allowLoopback,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory);
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
        return InternalCreate(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            failMixedResults: true,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: false,
            allowLoopback: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="connectTimeout">The timespan to wait before the connection establishing times out. The default value is <see cref="System.Threading.Timeout.InfiniteTimeSpan"/>.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ConnectionStrategy connectionStrategy, TimeSpan connectTimeout, ILoggerFactory? loggerFactory)
    {
        return InternalCreate(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            failMixedResults: true,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: false,
            allowLoopback: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory);
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
        return InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            connectTimeout: connectTimeout,
            failMixedResults: true,
            allowInsecureProtocols: false,
            allowLoopback: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="additionalUnsafeNetworks">An optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe. This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.</param>
    /// <param name="connectTimeout">The connect timeout, in seconds. Defaults to 30 seconds if not specified.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ICollection<IPNetwork> additionalUnsafeNetworks, TimeSpan connectTimeout, ILoggerFactory? loggerFactory)
    {
        return InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            allowedHostnames: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: connectTimeout,
            failMixedResults: true,
            allowInsecureProtocols: false,
            allowLoopback: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory);
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
        return InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowedHostnames: null,
            connectTimeout: connectTimeout,
            failMixedResults: true,
            allowInsecureProtocols: false,
            allowLoopback: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="additionalUnsafeIpAddresses">An optional collection of additional <see cref="IPAddress"/> addresses to consider unsafe. This can be used to block additional IP addresses beyond the built-in defaults, such as internal application IP addresses or other known unsafe addresses.</param>
    /// <param name="connectTimeout">The connect timeout, in seconds. Defaults to 30 seconds if not specified.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ICollection<IPAddress> additionalUnsafeIpAddresses, TimeSpan connectTimeout, ILoggerFactory? loggerFactory)
    {
        return InternalCreate(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowedHostnames: null,
            connectTimeout: connectTimeout,
            failMixedResults: true,
            allowInsecureProtocols: false,
            allowLoopback: false,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory);
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
        return InternalCreate(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            allowInsecureProtocols: false,
            allowLoopback: false,
            allowAutoRedirect: false,
            failMixedResults: true,
            connectTimeout: null,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="additionalUnsafeNetworks">An optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe. This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ConnectionStrategy connectionStrategy, ICollection<IPNetwork> additionalUnsafeNetworks, ILoggerFactory? loggerFactory)
    {
        return InternalCreate(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            connectTimeout: null,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory);
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
        return InternalCreate(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowedHostnames: null,
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            connectTimeout: null,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="additionalUnsafeIpAddresses">An optional collection of additional <see cref="IPAddress"/> addresses to consider unsafe. This can be used to block additional IP addresses beyond the built-in defaults, such as internal application IP addresses or other known unsafe addresses.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(ConnectionStrategy connectionStrategy, ICollection<IPAddress> additionalUnsafeIpAddresses, ILoggerFactory? loggerFactory)
    {
        return InternalCreate(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowedHostnames: null,
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            connectTimeout: null,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory);
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
        return InternalCreate(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowedHostnames: null,
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            connectTimeout: null,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="additionalUnsafeNetworks">An optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe. This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.</param>
    /// <param name="additionalUnsafeIpAddresses">An optional collection of additional <see cref="IPAddress"/> addresses to consider unsafe. This can be used to block additional IP addresses beyond the built-in defaults, such as internal application IP addresses or other known unsafe addresses.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(
        ConnectionStrategy connectionStrategy,
        ICollection<IPNetwork> additionalUnsafeNetworks,
        ICollection<IPAddress> additionalUnsafeIpAddresses,
        ILoggerFactory? loggerFactory)
    {
        return InternalCreate(
            connectionStrategy: connectionStrategy,
            allowedHostnames: null,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            connectTimeout: null,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory);
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
        return InternalCreate(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="additionalUnsafeNetworks">An optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe. This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.</param>
    /// <param name="connectTimeout">The timespan to wait before the connection establishing times out. The default value is <see cref="System.Threading.Timeout.InfiniteTimeSpan"/>.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(
        ConnectionStrategy connectionStrategy,
        ICollection<IPNetwork> additionalUnsafeNetworks,
        TimeSpan connectTimeout,
        ILoggerFactory? loggerFactory)
    {
        return InternalCreate(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: null,
            allowedHostnames: null,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            allowLoopback: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory);
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
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(
        ConnectionStrategy connectionStrategy,
        ICollection<IPNetwork> additionalUnsafeNetworks,
        ICollection<IPAddress> additionalUnsafeIpAddresses,
        TimeSpan connectTimeout)
    {
        return InternalCreate(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowedHostnames: null,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: null);
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
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(
        ConnectionStrategy connectionStrategy,
        ICollection<IPNetwork> additionalUnsafeNetworks,
        ICollection<IPAddress> additionalUnsafeIpAddresses,
        TimeSpan connectTimeout,
        ILoggerFactory? loggerFactory)
    {
        return InternalCreate(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowedHostnames: null,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: null,
            proxy: null,
            sslOptions: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory);
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

        return InternalCreate(
            options: options,
            hostEntryResolver: null,
            loggerFactory: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="options">The <see cref="SsrfOptions"/> to use for configuring the handler.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="options"/> is <see langword="null"/>.</exception>
    public static SocketsHttpHandler Create(SsrfOptions options, ILoggerFactory? loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(options);

        return InternalCreate(
            options: options,
            hostEntryResolver: null,
            loggerFactory: loggerFactory);
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
    /// <param name="allowLoopback">Flag indicating whether loopback addresses will be allowed or rejected.</param>
    /// <param name="failMixedResults">Flag indicating whether to fail when a mixture of safe and unsafe addresses is found. Setting this to <see langword="true"/> will reject the connection if any unsafe addresses are found.</param>
    /// <param name="allowAutoRedirect">Flag indicating whether to allow auto-redirects. Setting this to <see langword="true"/> can introduce security vulnerabilities and should only be enabled if necessary.</param>
    /// <param name="automaticDecompression">The type of decompression to use for automatic decompression of HTTP content. If <see langword="null"/>, defaults to <see cref="DecompressionMethods.All"/>.</param>
    /// <param name="sslOptions">Any <see cref="SslClientAuthenticationOptions" /> to use for client TLS authentication.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(
        ConnectionStrategy connectionStrategy,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        TimeSpan? connectTimeout,
        bool allowInsecureProtocols,
        bool allowLoopback,
        bool failMixedResults,
        bool allowAutoRedirect,
        DecompressionMethods? automaticDecompression,
        SslClientAuthenticationOptions? sslOptions)
    {
        return InternalCreate(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowedHostnames: null,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: allowLoopback,
            failMixedResults: failMixedResults,
            allowAutoRedirect: allowAutoRedirect,
            automaticDecompression: automaticDecompression,
            proxy: null,
            sslOptions: sslOptions,
            asyncHostEntryResolver: null,
            loggerFactory: null);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="additionalUnsafeNetworks">An optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe. This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.</param>
    /// <param name="additionalUnsafeIpAddresses">An optional collection of additional <see cref="IPAddress"/> addresses to consider unsafe. This can be used to block additional IP addresses beyond the built-in defaults, such as internal application IP addresses or other known unsafe addresses.</param>
    /// <param name="allowedHostnames">
    ///     An optional collection of hostnames that are allowed to bypass SSRF IP address protections.
    ///     This can be used to allow specific trusted hosts names.
    ///     Wild cards are supported only at the start of the hostname, and must be followed by a dot
    ///     (e.g. "*.example.com" would allow "api.example.com", "test.api.example.com", but not "example.com").
    /// </param>
    /// <param name="connectTimeout">The timespan to wait before the connection establishing times out. The default value is <see cref="System.Threading.Timeout.InfiniteTimeSpan"/>.</param>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <param name="allowLoopback">Flag indicating whether loopback addresses will be allowed or rejected.</param>
    /// <param name="failMixedResults">Flag indicating whether to fail when a mixture of safe and unsafe addresses is found. Setting this to <see langword="true"/> will reject the connection if any unsafe addresses are found.</param>
    /// <param name="allowAutoRedirect">Flag indicating whether to allow auto-redirects. Setting this to <see langword="true"/> can introduce security vulnerabilities and should only be enabled if necessary.</param>
    /// <param name="automaticDecompression">The type of decompression to use for automatic decompression of HTTP content. If <see langword="null"/>, defaults to <see cref="DecompressionMethods.All"/>.</param>
    /// <param name="sslOptions">Any <see cref="SslClientAuthenticationOptions" /> to use for client TLS authentication.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(
        ConnectionStrategy connectionStrategy,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        ICollection<string>? allowedHostnames,
        TimeSpan? connectTimeout,
        bool allowInsecureProtocols,
        bool allowLoopback,
        bool failMixedResults,
        bool allowAutoRedirect,
        DecompressionMethods? automaticDecompression,
        SslClientAuthenticationOptions? sslOptions)
    {
        return InternalCreate(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowedHostnames: allowedHostnames,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: allowLoopback,
            failMixedResults: failMixedResults,
            allowAutoRedirect: allowAutoRedirect,
            automaticDecompression: automaticDecompression,
            proxy: null,
            sslOptions: sslOptions,
            asyncHostEntryResolver: null,
            loggerFactory: null);
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
    /// <param name="allowLoopback">Flag indicating whether loopback addresses will be allowed or rejected.</param>
    /// <param name="failMixedResults">Flag indicating whether to fail when a mixture of safe and unsafe addresses is found. Setting this to <see langword="true"/> will reject the connection if any unsafe addresses are found.</param>
    /// <param name="allowAutoRedirect">Flag indicating whether to allow auto-redirects. Setting this to <see langword="true"/> can introduce security vulnerabilities and should only be enabled if necessary.</param>
    /// <param name="automaticDecompression">The type of decompression to use for automatic decompression of HTTP content. If <see langword="null"/>, defaults to <see cref="DecompressionMethods.All"/>.</param>
    /// <param name="sslOptions">Any <see cref="SslClientAuthenticationOptions" /> to use for client TLS authentication.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(
        ConnectionStrategy connectionStrategy,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        TimeSpan? connectTimeout,
        bool allowInsecureProtocols,
        bool allowLoopback,
        bool failMixedResults,
        bool allowAutoRedirect,
        DecompressionMethods? automaticDecompression,
        SslClientAuthenticationOptions? sslOptions,
        ILoggerFactory? loggerFactory)
    {
        return InternalCreate(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowedHostnames: null,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: allowLoopback,
            failMixedResults: failMixedResults,
            allowAutoRedirect: allowAutoRedirect,
            automaticDecompression: automaticDecompression,
            proxy: null,
            sslOptions: sslOptions,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory);
    }

    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> with SSRF protections implemented in the
    /// <see cref="SocketsHttpHandler.ConnectCallback"/>. The handler will attempt to resolve the target host to an IP address and validate that each resolved address
    /// is not considered unsafe before allowing a connection to be established.
    /// </summary>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="additionalUnsafeNetworks">An optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe. This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.</param>
    /// <param name="additionalUnsafeIpAddresses">An optional collection of additional <see cref="IPAddress"/> addresses to consider unsafe. This can be used to block additional IP addresses beyond the built-in defaults, such as internal application IP addresses or other known unsafe addresses.</param>
    /// <param name="allowedHostnames">
    ///     An optional collection of hostnames that are allowed to bypass SSRF IP address protections.
    ///     This can be used to allow specific trusted hosts names.
    ///     Wild cards are supported only at the start of the hostname, and must be followed by a dot
    ///     (e.g. "*.example.com" would allow "api.example.com", "test.api.example.com", but not "example.com").
    /// </param>
    /// <param name="connectTimeout">The timespan to wait before the connection establishing times out. The default value is <see cref="System.Threading.Timeout.InfiniteTimeSpan"/>.</param>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <param name="allowLoopback">Flag indicating whether loopback addresses will be allowed or rejected.</param>
    /// <param name="failMixedResults">Flag indicating whether to fail when a mixture of safe and unsafe addresses is found. Setting this to <see langword="true"/> will reject the connection if any unsafe addresses are found.</param>
    /// <param name="allowAutoRedirect">Flag indicating whether to allow auto-redirects. Setting this to <see langword="true"/> can introduce security vulnerabilities and should only be enabled if necessary.</param>
    /// <param name="automaticDecompression">The type of decompression to use for automatic decompression of HTTP content. If <see langword="null"/>, defaults to <see cref="DecompressionMethods.All"/>.</param>
    /// <param name="sslOptions">Any <see cref="SslClientAuthenticationOptions" /> to use for client TLS authentication.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <returns>An new instance of a <see cref="SocketsHttpHandler"/> with SSRF protections.</returns>
    public static SocketsHttpHandler Create(
        ConnectionStrategy connectionStrategy,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        ICollection<string>? allowedHostnames,
        TimeSpan? connectTimeout,
        bool allowInsecureProtocols,
        bool allowLoopback,
        bool failMixedResults,
        bool allowAutoRedirect,
        DecompressionMethods? automaticDecompression,
        SslClientAuthenticationOptions? sslOptions,
        ILoggerFactory? loggerFactory)
    {
        return InternalCreate(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowedHostnames: allowedHostnames,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: allowLoopback,
            failMixedResults: failMixedResults,
            allowAutoRedirect: allowAutoRedirect,
            automaticDecompression: automaticDecompression,
            proxy: null,
            sslOptions: sslOptions,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory);
    }

    internal static SocketsHttpHandler InternalCreate(
        SsrfOptions options,
        Func<string, CancellationToken, Task<IPHostEntry>>? hostEntryResolver,
        ILoggerFactory? loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(options);
        return InternalCreate(
            connectionStrategy: options.ConnectionStrategy,
            additionalUnsafeNetworks: options.AdditionalUnsafeNetworks,
            additionalUnsafeIpAddresses: options.AdditionalUnsafeIpAddresses,
            allowedHostnames: options.AllowedHostnames,
            connectTimeout: options.ConnectTimeout,
            allowInsecureProtocols: options.AllowInsecureProtocols,
            failMixedResults: options.FailMixedResults,
            allowAutoRedirect: options.AllowAutoRedirect,
            allowLoopback: options.AllowLoopback,
            automaticDecompression: options.AutomaticDecompression,
            proxy: options.Proxy,
            sslOptions: options.SslOptions,
            asyncHostEntryResolver: hostEntryResolver,
            loggerFactory: loggerFactory);
    }

    internal static SocketsHttpHandler InternalCreate(
        ConnectionStrategy connectionStrategy,
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        ICollection<string>? allowedHostnames,
        TimeSpan? connectTimeout,
        bool allowInsecureProtocols,
        bool allowLoopback,
        bool failMixedResults,
        bool allowAutoRedirect,
        DecompressionMethods? automaticDecompression,
        IWebProxy? proxy,
        SslClientAuthenticationOptions? sslOptions,
        Func<string, CancellationToken, Task<IPHostEntry>>? asyncHostEntryResolver,
        ILoggerFactory? loggerFactory)
    {
        asyncHostEntryResolver ??= s_defaultHostEntryResolver;
        loggerFactory ??= NullLoggerFactory.Instance;
        ILogger logger = loggerFactory.CreateLogger<SsrfSocketsHttpHandlerFactory>();

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

                Uri requestedUri = context.InitialRequestMessage.RequestUri ?? throw new InvalidOperationException("The request message must have a RequestUri.");

                if (Ssrf.IsUnsafeUri(
                    uri: requestedUri,
                    allowInsecureProtocols: allowInsecureProtocols,
                    allowLoopback: allowLoopback))
                {
                    Log.UnsafeUri(logger, requestedUri);
                    throw new SsrfException(requestedUri, $"Connection blocked as the uri is considered unsafe.");
                }

                IPAddress[] resolvedIpAddresses = await CommonFunctions.ResolveAndReturnSafeIPAddressesAsync(
                        uri: requestedUri,
                        additionalUnsafeNetworks: additionalUnsafeNetworks,
                        additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
                        allowedHostnames: allowedHostnames,
                        allowLoopback: allowLoopback,
                        failMixedResults: failMixedResults,
                        logger: logger,
                        hostEntryResolver: asyncHostEntryResolver,
                        cancellationToken: cancellationToken).ConfigureAwait(false);


                // If no IP addresses were resolved, early exit and block the connection as this is could be potential SSRF attack where the attacker is attempting to connect to a non-existent or internal host that is not resolvable through DNS.
                if (resolvedIpAddresses.Length== 0)
                {
                    Log.DnsResolutionFailed(logger, requestedUri);
                    throw new SsrfException(requestedUri, $"Connection blocked as host could not be resolved to any IP addresses.");
                }

                // Reorder the list of safe IP addresses based on the specified connection strategy, if there are multiple addresses to choose from.
                if (resolvedIpAddresses.Length > 1)
                {
                    if (connectionStrategy.HasFlag(ConnectionStrategy.Random))
                    {
                        // Shuffle in place O(n) in-place vs linq based O(n log n) OrderBy + new list allocation.
                        for (int i = resolvedIpAddresses.Length - 1; i > 0; i--)
                        {
                            int j = RandomNumberGenerator.GetInt32(0, i + 1);
                            (resolvedIpAddresses[i], resolvedIpAddresses[j]) = (resolvedIpAddresses[j], resolvedIpAddresses[i]);
                        }
                    }

                    if (connectionStrategy.HasFlag(ConnectionStrategy.Ipv4Preferred))
                    {
                        SortIpAddressListByFamily(resolvedIpAddresses, AddressFamily.InterNetwork);
                    }
                    else if (connectionStrategy.HasFlag(ConnectionStrategy.Ipv6Preferred))
                    {
                        SortIpAddressListByFamily(resolvedIpAddresses, AddressFamily.InterNetworkV6);
                    }
                }

                // Attempt to connect to each safe IP address until a successful connection is made.
                foreach (IPAddress ipAddress in resolvedIpAddresses)
                {
                    Socket socket = new(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    try
                    {
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
