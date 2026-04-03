// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;
using System.Net.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace idunno.Security;

/// <summary>
/// A <see cref="DelegatingHandler"/> for use with <see cref="SsrfSocketsHttpHandlerFactory"/> configurations involving a proxy.
/// The handler performs SSRF checks on the outgoing request URI, and the IP addresses it resolves to, however
/// this is vulnerable to a Time-of-Check to Time-of-Use (TOCTOU) attack as a recheck as the proxy makes its own connections to
/// the requested host, and may not perform SSRF checks.
/// </summary>
public class ProxiedSsrfDelegatingHandler : DelegatingHandler
{
    private static readonly Func<string, CancellationToken, Task<IPHostEntry>> s_defaultAsyncHostEntryResolver = Dns.GetHostEntryAsync;
    private static readonly Func<string, IPHostEntry> s_defaultHostEntryResolver = Dns.GetHostEntry;

    private readonly ICollection<IPNetwork>? _additionalUnsafeNetworks;
    private readonly ICollection<IPAddress>? _additionalUnsafeIpAddresses;
    private readonly bool _allowInsecureProtocols;
    private readonly bool _allowLoopback;
    private readonly bool _failMixedResults;
    private readonly Func<string, IPHostEntry> _hostEntryResolver;
    private readonly Func<string, CancellationToken, Task<IPHostEntry>> _asyncHostEntryResolver;

    private readonly ILogger _logger;

    /// <summary>
    /// Creates a new instance of <see cref="ProxiedSsrfDelegatingHandler"/> with the specified configuration, with an inner handler created by <see cref="SsrfSocketsHttpHandlerFactory"/>.
    /// The inner handler is configured to allow insecure protocols and loopback connections based on the provided <paramref name="proxy"/> URI.
    /// </summary>
    /// <param name="proxy">The proxy to use.</param>
    /// <exception cref="ArgumentNullException">Thrown if the provided <paramref name="proxy"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if the provided <paramref name="proxy"/> contains an invalid proxy configuration.</exception>
    public ProxiedSsrfDelegatingHandler(IWebProxy proxy) : this(
            proxy: proxy,
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: null,
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: null,
            sslOptions: null,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: null)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        if (proxy is not WebProxy webProxy)
        {
            throw new ArgumentException("Only WebProxy instances are supported for the proxy parameter.", nameof(proxy));
        }
        if (webProxy.Address is null)
        {
            throw new ArgumentException("The WebProxy instance must have a non-null Address property.", nameof(proxy));
        }
    }

    /// <summary>
    /// Creates a new instance of <see cref="ProxiedSsrfDelegatingHandler"/> with the specified configuration, with an inner handler created by <see cref="SsrfSocketsHttpHandlerFactory"/>.
    /// The inner handler is configured to allow insecure protocols and loopback connections based on the provided <paramref name="proxy"/> URI.
    /// </summary>
    /// <param name="proxy">The proxy to use.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <exception cref="ArgumentNullException">Thrown if the provided <paramref name="proxy"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if the provided <paramref name="proxy"/> contains an invalid proxy configuration.</exception>
    public ProxiedSsrfDelegatingHandler(
        IWebProxy proxy,
        ILoggerFactory loggerFactory) : this(
            proxy: proxy,
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: null,
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: null,
            sslOptions: null,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        if (proxy is not WebProxy webProxy)
        {
            throw new ArgumentException("Only WebProxy instances are supported for the proxy parameter.", nameof(proxy));
        }
        if (webProxy.Address is null)
        {
            throw new ArgumentException("The WebProxy instance must have a non-null Address property.", nameof(proxy));
        }
    }

    /// <summary>
    /// Creates a new instance of <see cref="ProxiedSsrfDelegatingHandler"/> with the specified configuration, with an inner handler created by <see cref="SsrfSocketsHttpHandlerFactory"/>.
    /// The inner handler is configured to allow insecure protocols and loopback connections based on the provided <paramref name="proxy"/> URI.
    /// </summary>
    /// <param name="proxy">The proxy to use.</param>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <exception cref="ArgumentNullException">Thrown if the provided <paramref name="proxy"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if the provided <paramref name="proxy"/> contains an invalid proxy configuration.</exception>
    public ProxiedSsrfDelegatingHandler(
        IWebProxy proxy,
        ConnectionStrategy connectionStrategy) : this(
            proxy: proxy,
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: null,
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: null,
            sslOptions: null,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: null)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        if (proxy is not WebProxy webProxy)
        {
            throw new ArgumentException("Only WebProxy instances are supported for the proxy parameter.", nameof(proxy));
        }
        if (webProxy.Address is null)
        {
            throw new ArgumentException("The WebProxy instance must have a non-null Address property.", nameof(proxy));
        }
    }

    /// <summary>
    /// Creates a new instance of <see cref="ProxiedSsrfDelegatingHandler"/> with the specified configuration, with an inner handler created by <see cref="SsrfSocketsHttpHandlerFactory"/>.
    /// The inner handler is configured to allow insecure protocols and loopback connections based on the provided <paramref name="proxy"/> URI.
    /// </summary>
    /// <param name="proxy">The proxy to use.</param>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <exception cref="ArgumentNullException">Thrown if the provided <paramref name="proxy"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if the provided <paramref name="proxy"/> contains an invalid proxy configuration.</exception>
    public ProxiedSsrfDelegatingHandler(
        IWebProxy proxy,
        ConnectionStrategy connectionStrategy,
        ILoggerFactory? loggerFactory) : this(
            proxy: proxy,
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: null,
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: null,
            sslOptions: null,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        if (proxy is not WebProxy webProxy)
        {
            throw new ArgumentException("Only WebProxy instances are supported for the proxy parameter.", nameof(proxy));
        }
        if (webProxy.Address is null)
        {
            throw new ArgumentException("The WebProxy instance must have a non-null Address property.", nameof(proxy));
        }
    }

    /// <summary>
    /// Creates a new instance of <see cref="ProxiedSsrfDelegatingHandler"/> with the specified configuration, with an inner handler created by <see cref="SsrfSocketsHttpHandlerFactory"/>.
    /// The inner handler is configured to allow insecure protocols and loopback connections based on the provided <paramref name="proxy"/> URI.
    /// </summary>
    /// <param name="proxy">The proxy to use.</param>
    /// <param name="connectTimeout">The timespan to wait before the connection establishing times out. The default value is <see cref="System.Threading.Timeout.InfiniteTimeSpan"/>.</param>
    /// <exception cref="ArgumentNullException">Thrown if the provided <paramref name="proxy"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if the provided <paramref name="proxy"/> contains an invalid proxy configuration.</exception>
    public ProxiedSsrfDelegatingHandler(
        IWebProxy proxy,
        TimeSpan connectTimeout) : this(
            proxy: proxy,
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: null,
            sslOptions: null,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: null)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        if (proxy is not WebProxy webProxy)
        {
            throw new ArgumentException("Only WebProxy instances are supported for the proxy parameter.", nameof(proxy));
        }
        if (webProxy.Address is null)
        {
            throw new ArgumentException("The WebProxy instance must have a non-null Address property.", nameof(proxy));
        }
    }

    /// <summary>
    /// Creates a new instance of <see cref="ProxiedSsrfDelegatingHandler"/> with the specified configuration, with an inner handler created by <see cref="SsrfSocketsHttpHandlerFactory"/>.
    /// The inner handler is configured to allow insecure protocols and loopback connections based on the provided <paramref name="proxy"/> URI.
    /// </summary>
    /// <param name="proxy">The proxy to use.</param>
    /// <param name="connectTimeout">The timespan to wait before the connection establishing times out. The default value is <see cref="System.Threading.Timeout.InfiniteTimeSpan"/>.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <exception cref="ArgumentNullException">Thrown if the provided <paramref name="proxy"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if the provided <paramref name="proxy"/> contains an invalid proxy configuration.</exception>
    public ProxiedSsrfDelegatingHandler(
        IWebProxy proxy,
        TimeSpan connectTimeout,
        ILoggerFactory loggerFactory) : this(
            proxy: proxy,
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: null,
            sslOptions: null,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        if (proxy is not WebProxy webProxy)
        {
            throw new ArgumentException("Only WebProxy instances are supported for the proxy parameter.", nameof(proxy));
        }
        if (webProxy.Address is null)
        {
            throw new ArgumentException("The WebProxy instance must have a non-null Address property.", nameof(proxy));
        }
    }

    /// <summary>
    /// Creates a new instance of <see cref="ProxiedSsrfDelegatingHandler"/> with the specified configuration, with an inner handler created by <see cref="SsrfSocketsHttpHandlerFactory"/>.
    /// The inner handler is configured to allow insecure protocols and loopback connections based on the provided <paramref name="proxy"/> URI.
    /// </summary>
    /// <param name="proxy">The proxy to use.</param>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <exception cref="ArgumentNullException">Thrown if the provided <paramref name="proxy"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if the provided <paramref name="proxy"/> contains an invalid proxy configuration.</exception>
    public ProxiedSsrfDelegatingHandler(
        IWebProxy proxy,
        bool allowInsecureProtocols) : this(
            proxy: proxy,
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: null,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: null,
            sslOptions: null,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: null)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        if (proxy is not WebProxy webProxy)
        {
            throw new ArgumentException("Only WebProxy instances are supported for the proxy parameter.", nameof(proxy));
        }

        if (webProxy.Address is null)
        {
            throw new ArgumentException("The WebProxy instance must have a non-null Address property.", nameof(proxy));
        }
    }

    /// <summary>
    /// Creates a new instance of <see cref="ProxiedSsrfDelegatingHandler"/> with the specified configuration, with an inner handler created by <see cref="SsrfSocketsHttpHandlerFactory"/>.
    /// The inner handler is configured to allow insecure protocols and loopback connections based on the provided <paramref name="proxy"/> URI.
    /// </summary>
    /// <param name="proxy">The proxy to use.</param>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <exception cref="ArgumentNullException">Thrown if the provided <paramref name="proxy"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if the provided <paramref name="proxy"/> contains an invalid proxy configuration.</exception>
    public ProxiedSsrfDelegatingHandler(
        IWebProxy proxy,
        bool allowInsecureProtocols,
        ILoggerFactory? loggerFactory) : this(
            proxy: proxy,
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: null,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: null,
            sslOptions: null,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        if (proxy is not WebProxy webProxy)
        {
            throw new ArgumentException("Only WebProxy instances are supported for the proxy parameter.", nameof(proxy));
        }

        if (webProxy.Address is null)
        {
            throw new ArgumentException("The WebProxy instance must have a non-null Address property.", nameof(proxy));
        }
    }

    /// <summary>
    /// Creates a new instance of <see cref="ProxiedSsrfDelegatingHandler"/> with the specified configuration, with an inner handler created by <see cref="SsrfSocketsHttpHandlerFactory"/>.
    /// The inner handler is configured to allow insecure protocols and loopback connections based on the provided <paramref name="proxy"/> URI.
    /// </summary>
    /// <param name="proxy">The proxy to use.</param>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <param name="allowLoopback">Flag indicating whether loopback addresses will be allowed or rejected.</param>
    /// <exception cref="ArgumentNullException">Thrown if the provided <paramref name="proxy"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if the provided <paramref name="proxy"/> contains an invalid proxy configuration.</exception>
    public ProxiedSsrfDelegatingHandler(
        IWebProxy proxy,
        bool allowInsecureProtocols,
        bool allowLoopback) : this(
            proxy: proxy,
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: null,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: allowLoopback,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: null,
            sslOptions: null,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: null)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        if (proxy is not WebProxy webProxy)
        {
            throw new ArgumentException("Only WebProxy instances are supported for the proxy parameter.", nameof(proxy));
        }

        if (webProxy.Address is null)
        {
            throw new ArgumentException("The WebProxy instance must have a non-null Address property.", nameof(proxy));
        }
    }

    /// <summary>
    /// Creates a new instance of <see cref="ProxiedSsrfDelegatingHandler"/> with the specified configuration, with an inner handler created by <see cref="SsrfSocketsHttpHandlerFactory"/>.
    /// The inner handler is configured to allow insecure protocols and loopback connections based on the provided <paramref name="proxy"/> URI.
    /// </summary>
    /// <param name="proxy">The proxy to use.</param>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <param name="allowLoopback">Flag indicating whether loopback addresses will be allowed or rejected.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <exception cref="ArgumentNullException">Thrown if the provided <paramref name="proxy"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if the provided <paramref name="proxy"/> contains an invalid proxy configuration.</exception>
    public ProxiedSsrfDelegatingHandler(
        IWebProxy proxy,
        bool allowInsecureProtocols,
        bool allowLoopback,
        ILoggerFactory loggerFactory) : this(
            proxy: proxy,
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: null,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: allowLoopback,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: null,
            sslOptions: null,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        if (proxy is not WebProxy webProxy)
        {
            throw new ArgumentException("Only WebProxy instances are supported for the proxy parameter.", nameof(proxy));
        }

        if (webProxy.Address is null)
        {
            throw new ArgumentException("The WebProxy instance must have a non-null Address property.", nameof(proxy));
        }
    }

    /// <summary>
    /// Creates a new instance of <see cref="ProxiedSsrfDelegatingHandler"/> with the specified configuration, with an inner handler created by <see cref="SsrfSocketsHttpHandlerFactory"/>.
    /// The inner handler is configured to allow insecure protocols and loopback connections based on the provided <paramref name="proxy"/> URI.
    /// </summary>
    /// <param name="proxy">The proxy to use.</param>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="connectTimeout">The timespan to wait before the connection establishing times out. The default value is <see cref="System.Threading.Timeout.InfiniteTimeSpan"/>.</param>
    /// <exception cref="ArgumentNullException">Thrown if the provided <paramref name="proxy"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if the provided <paramref name="proxy"/> contains an invalid proxy configuration.</exception>
    public ProxiedSsrfDelegatingHandler(
        IWebProxy proxy,
        ConnectionStrategy connectionStrategy,
        TimeSpan? connectTimeout) : this(
            proxy: proxy,
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: null,
            sslOptions: null,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: null)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        if (proxy is not WebProxy webProxy)
        {
            throw new ArgumentException("Only WebProxy instances are supported for the proxy parameter.", nameof(proxy));
        }

        if (webProxy.Address is null)
        {
            throw new ArgumentException("The WebProxy instance must have a non-null Address property.", nameof(proxy));
        }
    }

    /// <summary>
    /// Creates a new instance of <see cref="ProxiedSsrfDelegatingHandler"/> with the specified configuration, with an inner handler created by <see cref="SsrfSocketsHttpHandlerFactory"/>.
    /// The inner handler is configured to allow insecure protocols and loopback connections based on the provided <paramref name="proxy"/> URI.
    /// </summary>
    /// <param name="proxy">The proxy to use.</param>
    /// <param name="connectionStrategy">The strategy to use when attempting to connect to multiple resolved IP addresses for a given host.</param>
    /// <param name="connectTimeout">The timespan to wait before the connection establishing times out. The default value is <see cref="System.Threading.Timeout.InfiniteTimeSpan"/>.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <exception cref="ArgumentNullException">Thrown if the provided <paramref name="proxy"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if the provided <paramref name="proxy"/> contains an invalid proxy configuration.</exception>
    public ProxiedSsrfDelegatingHandler(
        IWebProxy proxy,
        ConnectionStrategy connectionStrategy,
        TimeSpan? connectTimeout,
        ILoggerFactory loggerFactory) : this(
            proxy: proxy,
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: false,
            allowLoopback: false,
            failMixedResults: true,
            allowAutoRedirect: false,
            automaticDecompression: null,
            sslOptions: null,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        if (proxy is not WebProxy webProxy)
        {
            throw new ArgumentException("Only WebProxy instances are supported for the proxy parameter.", nameof(proxy));
        }

        if (webProxy.Address is null)
        {
            throw new ArgumentException("The WebProxy instance must have a non-null Address property.", nameof(proxy));
        }
    }

    /// <summary>
    /// Creates a new instance of <see cref="ProxiedSsrfDelegatingHandler"/> with the specified configuration, with an inner handler created by <see cref="SsrfSocketsHttpHandlerFactory"/>.
    /// The inner handler is configured to allow insecure protocols and loopback connections based on the provided <paramref name="proxy"/> URI.
    /// </summary>
    /// <param name="proxy">The proxy to use.</param>
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
    /// <exception cref="ArgumentNullException">Thrown if the provided <paramref name="proxy"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if the provided <paramref name="proxy"/> contains an invalid proxy configuration.</exception>
    public ProxiedSsrfDelegatingHandler(
        IWebProxy proxy,
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
        ILoggerFactory? loggerFactory) : this(
            proxy: proxy,
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: allowLoopback,
            failMixedResults: failMixedResults,
            allowAutoRedirect: allowAutoRedirect,
            automaticDecompression: automaticDecompression,
            sslOptions: sslOptions,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        if (proxy is not WebProxy webProxy)
        {
            throw new ArgumentException("Only WebProxy instances are supported for the proxy parameter.", nameof(proxy));
        }

        if (webProxy.Address is null)
        {
            throw new ArgumentException("The WebProxy instance must have a non-null Address property.", nameof(proxy));
        }
    }

    /// <summary>
    /// Creates a new instance of <see cref="ProxiedSsrfDelegatingHandler"/> with the specified configuration, with an inner handler created by <see cref="SsrfSocketsHttpHandlerFactory"/>.
    /// </summary>
    /// <param name="options">The <see cref="SsrfOptions"/> containing the configuration for the handler.</param>
    /// <exception cref="ArgumentException">Thrown if the provided <paramref name="options"/> contains an invalid proxy configuration.</exception>
    /// <exception cref="ArgumentNullException">Thrown if the provided <paramref name="options"/> or its Proxy property is <see langword="null"/>.</exception>
    public ProxiedSsrfDelegatingHandler(
        SsrfOptions options) : this(
            options,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.Proxy);

        if (options.Proxy is not WebProxy webProxy)
        {
            throw new ArgumentException("Only WebProxy instances are supported for the options.Proxy property.", nameof(options));
        }
        if (webProxy.Address is null)
        {
            throw new ArgumentException("The WebProxy instance in the options.Proxy property must have a non-null Address property.", nameof(options));
        }
    }

    /// <summary>
    /// Creates a new instance of <see cref="ProxiedSsrfDelegatingHandler"/> with the specified configuration, with an inner handler created by <see cref="SsrfSocketsHttpHandlerFactory"/>.
    /// </summary>
    /// <param name="options">The <see cref="SsrfOptions"/> containing the configuration for the handler.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <exception cref="ArgumentException">Thrown if the provided <paramref name="options"/> contains an invalid proxy configuration.</exception>
    /// <exception cref="ArgumentNullException">Thrown if the provided <paramref name="options"/> or its Proxy property is <see langword="null"/>.</exception>
    public ProxiedSsrfDelegatingHandler(
        SsrfOptions options,
        ILoggerFactory? loggerFactory) : this(
            options,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.Proxy);

        if (options.Proxy is not WebProxy webProxy)
        {
            throw new ArgumentException("Only WebProxy instances are supported for the options.Proxy property.", nameof(options));
        }
        if (webProxy.Address is null)
        {
            throw new ArgumentException("The WebProxy instance in the options.Proxy property must have a non-null Address property.", nameof(options));
        }
    }

    internal ProxiedSsrfDelegatingHandler(
        IWebProxy proxy,
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
        Func<string, IPHostEntry>? hostEntryResolver,
        Func<string, CancellationToken, Task<IPHostEntry>>? asyncHostEntryResolver,
        ILoggerFactory? loggerFactory)
    {
        if (proxy is not WebProxy webProxy)
        {
            throw new ArgumentException("Only WebProxy instances are supported for the proxy parameter.", nameof(proxy));
        }

        if (webProxy.Address is null)
        {
            throw new ArgumentException("The WebProxy instance must have a non-null Address property.", nameof(proxy));
        }

        _additionalUnsafeNetworks = additionalUnsafeNetworks;
        _additionalUnsafeIpAddresses = additionalUnsafeIpAddresses;
        _allowInsecureProtocols = allowInsecureProtocols;
        _allowLoopback = allowLoopback;
        _failMixedResults = failMixedResults;
        _hostEntryResolver = hostEntryResolver ?? s_defaultHostEntryResolver;
        _asyncHostEntryResolver = asyncHostEntryResolver ?? s_defaultAsyncHostEntryResolver;

        loggerFactory ??= NullLoggerFactory.Instance;
        _logger = loggerFactory.CreateLogger<ProxiedSsrfDelegatingHandler>();

        InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
            connectionStrategy: connectionStrategy,
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            connectTimeout: connectTimeout,
            allowInsecureProtocols: webProxy.Address.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase),
            allowLoopback: webProxy.Address.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase),
            failMixedResults: failMixedResults,
            allowAutoRedirect: allowAutoRedirect,
            automaticDecompression: automaticDecompression,
            proxy: proxy,
            sslOptions: sslOptions,
            asyncHostEntryResolver: asyncHostEntryResolver,
            loggerFactory: loggerFactory);
    }

    internal ProxiedSsrfDelegatingHandler(
        SsrfOptions options,
        Func<string, IPHostEntry>? hostEntryResolver,
        Func<string, CancellationToken, Task<IPHostEntry>>? asyncHostEntryResolver,
        ILoggerFactory? loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (options.Proxy is not WebProxy webProxy)
        {
            throw new ArgumentException("Only WebProxy instances are supported for the options.Proxy property.", nameof(options));
        }

        if (webProxy.Address is null)
        {
            throw new ArgumentException("The WebProxy instance in the options.Proxy property must have a non-null Address property.", nameof(options));
        }

        _additionalUnsafeNetworks = options.AdditionalUnsafeNetworks;
        _additionalUnsafeIpAddresses = options.AdditionalUnsafeIpAddresses;
        _allowInsecureProtocols = options.AllowInsecureProtocols;
        _allowLoopback = options.AllowLoopback;
        _failMixedResults = options.FailMixedResults;
        _hostEntryResolver = hostEntryResolver ?? s_defaultHostEntryResolver;
        _asyncHostEntryResolver = asyncHostEntryResolver ?? s_defaultAsyncHostEntryResolver;

        loggerFactory ??= NullLoggerFactory.Instance;
        _logger = loggerFactory.CreateLogger<ProxiedSsrfDelegatingHandler>();

        InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
            connectionStrategy: options.ConnectionStrategy,
            additionalUnsafeNetworks: options.AdditionalUnsafeNetworks,
            additionalUnsafeIpAddresses: options.AdditionalUnsafeIpAddresses,
            connectTimeout: options.ConnectTimeout,
            allowInsecureProtocols: webProxy.Address.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase),
            allowLoopback: webProxy.Address.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase),
            failMixedResults: options.FailMixedResults,
            allowAutoRedirect: options.AllowAutoRedirect,
            automaticDecompression: options.AutomaticDecompression,
            proxy: options.Proxy,
            sslOptions: options.SslOptions,
            asyncHostEntryResolver: asyncHostEntryResolver,
            loggerFactory: loggerFactory);
    }

    /// <summary>Sends an HTTP request to the inner handler to send to the server as an asynchronous operation.</summary>
    /// <param name="request">The HTTP request message to send to the server.</param>
    /// <param name="cancellationToken">A cancellation token to cancel the operation.</param>
    /// <returns>The task object representing the asynchronous operation.</returns>
    /// <exception cref="ArgumentNullException">Thrown when the request is <see langword="null"/>.</exception>
    /// <exception cref="SsrfException">Thrown when the request URI is considered unsafe or when all resolved IP addresses are unsafe.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the request message does not have a RequestUri.</exception>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        Uri requestedUri = request.RequestUri ?? throw new InvalidOperationException("The request message must have a RequestUri.");

        if (Ssrf.IsUnsafeUri(
            uri: request.RequestUri,
            allowInsecureProtocols: _allowInsecureProtocols,
            allowLoopback: _allowLoopback))
        {
            Log.UnsafeUri(_logger, requestedUri);
            throw new SsrfException(requestedUri, $"Connection blocked as the uri is considered unsafe.");
        }

        _ = await CommonFunctions.ResolveAndReturnSafeIPAddressesAsync(
            uri: requestedUri,
            additionalUnsafeNetworks: _additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: _additionalUnsafeIpAddresses,
            allowLoopback: _allowLoopback,
            failMixedResults: _failMixedResults,
            logger: _logger,
            hostEntryResolver: _asyncHostEntryResolver,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Sends an HTTP request to the inner handler to send to the server.</summary>
    /// <param name="request">The HTTP request message to send to the server.</param>
    /// <param name="cancellationToken">A cancellation token to cancel the operation.</param>
    /// <returns>An HTTP response message.</returns>
    /// <exception cref="ArgumentNullException">Thrown when the request is <see langword="null"/>.</exception>
    /// <exception cref="SsrfException">Thrown when the request URI is considered unsafe or when all resolved IP addresses are unsafe.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the request message does not have a RequestUri.</exception>
    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        Uri requestedUri = request.RequestUri ?? throw new InvalidOperationException("The request message must have a RequestUri.");

        if (Ssrf.IsUnsafeUri(
            uri: request.RequestUri,
            allowInsecureProtocols: _allowInsecureProtocols,
            allowLoopback: _allowLoopback))
        {
            Log.UnsafeUri(_logger, requestedUri);
            throw new SsrfException(requestedUri, $"Connection blocked as the uri is considered unsafe.");
        }

        _ = CommonFunctions.ResolveAndReturnSafeIPAddresses(
            uri: requestedUri,
            additionalUnsafeNetworks: _additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: _additionalUnsafeIpAddresses,
            allowLoopback: _allowLoopback,
            failMixedResults: _failMixedResults,
            logger: _logger,
            hostEntryResolver: _hostEntryResolver);

        return base.Send(request, cancellationToken);
    }
}
