// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Diagnostics.Metrics;
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
    private readonly ICollection<IPNetwork>? _additionalUnsafeIPNetworks;
    private readonly ICollection<IPAddress>? _additionalUnsafeIPAddresses;
    private readonly ICollection<string>? _allowedHostnames;
    private readonly ICollection<IPNetwork>? _safeIPNetworks;
    private readonly ICollection<IPAddress>? _safeIPAddresses;
    private readonly ICollection<string>? _allowedSchemes;
    private readonly bool _allowLoopback;
    private readonly bool _failMixedResults;
    private readonly Func<string, IPHostEntry> _hostEntryResolver;
    private readonly Func<string, CancellationToken, Task<IPHostEntry>> _asyncHostEntryResolver;

    private readonly ILogger _logger;
    private readonly SsrfMetrics _metrics;

    /// <summary>
    /// Creates a new instance of <see cref="ProxiedSsrfDelegatingHandler"/> with the specified configuration, with an inner handler created by <see cref="SsrfSocketsHttpHandlerFactory"/>.
    /// The inner handler is configured to allow insecure protocols and loopback connections based on the provided <paramref name="proxy"/> URI.
    /// </summary>
    /// <param name="proxy">The proxy to use. This is assumed to be a trusted proxy configuration. The SSRF protections do not apply to the proxy itself, so it is important to ensure that the proxy is secure and properly configured.</param>
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
    /// <param name="meterFactory">An optional <see cref="IMeterFactory"/> to use for metrics. If not provided, a default <see cref="SsrfMetrics"/> instance will be used with a shared meter.</param>
    /// <exception cref="ArgumentNullException">Thrown if the provided <paramref name="proxy"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if the provided <paramref name="proxy"/> contains an invalid proxy configuration.</exception>
    /// <remarks>
    /// <para>
    ///   Careless use of <paramref name="safeIPNetworks"/> and <paramref name="safeIPAddresses"/> can lead to security vulnerabilities by allowing potentially unsafe IP addresses or networks
    ///   to be considered safe. Use with caution and constrain the values specified to the smallest network range or individual IP addresses needed.
    ///   Safe entries take precedence over both built-in and additional unsafe entries, so if an IP address matches both a safe and unsafe address, or is within a safe network,
    ///   it will be considered safe.
    ///</para>
    /// </remarks>
    public ProxiedSsrfDelegatingHandler(
        WebProxy proxy,
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
        IMeterFactory? meterFactory = null) : this(
            proxy: proxy,
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
            sslOptions: sslOptions,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory,
            meterFactory: meterFactory)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        if (proxy.Address is null)
        {
            throw new ArgumentException("The WebProxy instance must have a non-null Address property.", nameof(proxy));
        }
    }

    /// <summary>
    /// Creates a new instance of <see cref="ProxiedSsrfDelegatingHandler"/> with the specified configuration, with an inner handler created by <see cref="SsrfSocketsHttpHandlerFactory"/>.
    /// </summary>
    /// <param name="options">The <see cref="ProxiedSsrfOptions"/> containing the configuration for the handler.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <param name="meterFactory">An optional <see cref="IMeterFactory"/> to use for metrics. If not provided, a default <see cref="SsrfMetrics"/> instance will be used with a shared meter.</param>
    /// <exception cref="ArgumentNullException">Thrown if the provided <paramref name="options"/>, its Proxy property is <see langword="null"/> or the Proxy's Address property is <see langword="null"/>.</exception>
    public ProxiedSsrfDelegatingHandler(
        ProxiedSsrfOptions options,
        ILoggerFactory? loggerFactory = null,
        IMeterFactory? meterFactory = null) : this(
            options,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory,
            meterFactory: meterFactory)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.Proxy);
        ArgumentNullException.ThrowIfNull(options.Proxy.Address);
    }

    internal ProxiedSsrfDelegatingHandler(
        WebProxy proxy,
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
        SslClientAuthenticationOptions? sslOptions,
        Func<string, IPHostEntry>? hostEntryResolver,
        Func<string, CancellationToken, Task<IPHostEntry>>? asyncHostEntryResolver,
        ILoggerFactory? loggerFactory,
        IMeterFactory? meterFactory)
    {
        ArgumentNullException.ThrowIfNull(proxy);
        if (proxy.Address is null)
        {
            throw new ArgumentException("The WebProxy instance must have a non-null Address property.", nameof(proxy));
        }

        _additionalUnsafeIPNetworks = additionalUnsafeIPNetworks;
        _additionalUnsafeIPAddresses = additionalUnsafeIPAddresses;
        _allowedHostnames = allowedHostnames;
        _safeIPNetworks = safeIPNetworks;
        _safeIPAddresses = safeIPAddresses;
        _allowedSchemes = allowedSchemes != null ? [.. allowedSchemes] : Defaults.AllowedSchemes;
        _allowLoopback = allowLoopback;
        _failMixedResults = failMixedResults;
        _hostEntryResolver = hostEntryResolver ?? Defaults.GetHostEntry;
        _asyncHostEntryResolver = asyncHostEntryResolver ?? Defaults.GetHostEntryAsync;

        loggerFactory ??= NullLoggerFactory.Instance;
        _logger = loggerFactory.CreateLogger<ProxiedSsrfDelegatingHandler>();

        _metrics = new SsrfMetrics(meterFactory);

        InnerHandler = SsrfSocketsHttpHandlerFactory.InternalCreate(
            connectionStrategy: connectionStrategy,
            additionalUnsafeIPNetworks: _additionalUnsafeIPNetworks,
            additionalUnsafeIPAddresses: _additionalUnsafeIPAddresses,
            allowedHostnames: _allowedHostnames,
            safeIPNetworks: _safeIPNetworks,
            safeIPAddresses: _safeIPAddresses,
            connectTimeout: connectTimeout,
            allowedSchemes: _allowedSchemes,
            allowLoopback: _allowLoopback,
            failMixedResults: _failMixedResults,
            allowAutoRedirect: allowAutoRedirect,
            automaticDecompression: automaticDecompression,
            proxy: proxy,
            sslOptions: sslOptions,
            asyncHostEntryResolver: _asyncHostEntryResolver,
            loggerFactory: loggerFactory,
            meterFactory: meterFactory); 
    }

    internal ProxiedSsrfDelegatingHandler(
        ProxiedSsrfOptions options,
        Func<string, IPHostEntry>? hostEntryResolver,
        Func<string, CancellationToken, Task<IPHostEntry>>? asyncHostEntryResolver,
        ILoggerFactory? loggerFactory,
        IMeterFactory? meterFactory)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.Proxy);
        ArgumentNullException.ThrowIfNull(options.Proxy.Address);

        ICollection<string>? snapshotAllowedSchemes = options.AllowedSchemes is null ? null : [.. options.AllowedSchemes];

        _additionalUnsafeIPNetworks = options.AdditionalUnsafeIPNetworks;
        _additionalUnsafeIPAddresses = options.AdditionalUnsafeIPAddresses;
        _safeIPNetworks = options.SafeIPNetworks;
        _safeIPAddresses = options.SafeIPAddresses;
        _allowedHostnames = options.AllowedHostnames;
        _allowedSchemes = snapshotAllowedSchemes;
        _allowLoopback = options.AllowLoopback;
        _failMixedResults = options.FailMixedResults;
        _hostEntryResolver = hostEntryResolver ?? Defaults.GetHostEntry;
        _asyncHostEntryResolver = asyncHostEntryResolver ?? Defaults.GetHostEntryAsync;

        loggerFactory ??= NullLoggerFactory.Instance;
        _logger = loggerFactory.CreateLogger<ProxiedSsrfDelegatingHandler>();

        _metrics = new SsrfMetrics(meterFactory);

        InnerHandler = SsrfSocketsHttpHandlerFactory.InternalCreate(
            connectionStrategy: options.ConnectionStrategy,
            additionalUnsafeIPNetworks: _additionalUnsafeIPNetworks,
            additionalUnsafeIPAddresses: _additionalUnsafeIPAddresses,
            allowedHostnames: _allowedHostnames,
            safeIPNetworks: _safeIPNetworks,
            safeIPAddresses: _safeIPAddresses,
            connectTimeout: options.ConnectTimeout,
            allowedSchemes: _allowedSchemes,
            allowLoopback: _allowLoopback,
            failMixedResults: _failMixedResults,
            allowAutoRedirect: options.AllowAutoRedirect,
            automaticDecompression: options.AutomaticDecompression,
            proxy: options.Proxy,
            sslOptions: options.SslOptions,
            asyncHostEntryResolver: asyncHostEntryResolver,
            loggerFactory: loggerFactory,
            meterFactory: meterFactory);
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
            uri: requestedUri,
            allowedSchemes: _allowedSchemes,
            allowLoopback: _allowLoopback,
            metrics: _metrics))
        {
            Log.UnsafeUri(_logger, requestedUri);
            _metrics.IncrementBlockedRequests();
            throw new SsrfException(requestedUri, $"Connection blocked as the uri is considered unsafe.");
        }

        try
        {
            _ = await CommonFunctions.ResolveAndReturnSafeIPAddressesAsync(
                uri: requestedUri,
                additionalUnsafeIPNetworks: _additionalUnsafeIPNetworks,
                additionalUnsafeIPAddresses: _additionalUnsafeIPAddresses,
                allowedHostnames: _allowedHostnames,
                safeIPNetworks: _safeIPNetworks,
                safeIPAddresses: _safeIPAddresses,
                allowLoopback: _allowLoopback,
                failMixedResults: _failMixedResults,
                logger: _logger,
                metrics: _metrics,
                asyncHostEntryResolver: _asyncHostEntryResolver,
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (SsrfException)
        {
            _metrics.IncrementBlockedRequests();
            throw;
        }

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
            uri: requestedUri,
            allowedSchemes: _allowedSchemes,
            allowLoopback: _allowLoopback,
            metrics: _metrics))
        {
            Log.UnsafeUri(_logger, requestedUri);
            _metrics.IncrementBlockedRequests();
            throw new SsrfException(requestedUri, $"Connection blocked as the uri is considered unsafe.");
        }

        try
        {
        _ = CommonFunctions.ResolveAndReturnSafeIPAddresses(
            uri: requestedUri,
            additionalUnsafeIPNetworks: _additionalUnsafeIPNetworks,
            additionalUnsafeIPAddresses: _additionalUnsafeIPAddresses,
            allowedHostnames: _allowedHostnames,
            safeIPNetworks: _safeIPNetworks,
            safeIPAddresses: _safeIPAddresses,
            allowLoopback: _allowLoopback,
            failMixedResults: _failMixedResults,
            logger: _logger,
            metrics: _metrics,
            hostEntryResolver: _hostEntryResolver);
        }
        catch (SsrfException)
        {
            _metrics.IncrementBlockedRequests();
            throw;
        }

        return base.Send(request, cancellationToken);
    }
}
