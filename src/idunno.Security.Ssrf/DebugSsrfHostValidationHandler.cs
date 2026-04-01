// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace idunno.Security;

/// <summary>
/// A <see cref="DelegatingHandler"/> for use with <see cref="SsrfSocketsHttpHandlerFactory"/> configurations involving a proxy.
/// The handler performs SSRF checks on the outgoing request URI, and the IP addresses it resolves to, however
/// this is vulnerable to a Time-of-Check to Time-of-Use (TOCTOU) attack as a recheck as the proxy makes its own connections to
/// the requested host, and may not perform SSRF checks.
/// </summary>
public class DebugSsrfHostValidationHandler : DelegatingHandler
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
    /// Creates a new instance of <see cref="DebugSsrfHostValidationHandler"/> with the specified configuration.
    /// </summary>
    public DebugSsrfHostValidationHandler() : this(
        additionalUnsafeNetworks: null,
        additionalUnsafeIpAddresses: null,
        allowInsecureProtocols: false,
        allowLoopback: false,
        failMixedResults: true,
        hostEntryResolver: null,
        asyncHostEntryResolver: null,
        loggerFactory: null)
    {
    }

    /// <summary>
    /// Creates a new instance of <see cref="DebugSsrfHostValidationHandler"/> with the specified configuration.
    /// </summary>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <param name="allowLoopback">Flag indicating whether loopback addresses will be allowed or rejected.</param>
    public DebugSsrfHostValidationHandler(
        bool allowInsecureProtocols,
        bool allowLoopback) : this(
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: allowLoopback,
            failMixedResults: true,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: null)
    {
    }

    /// <summary>
    /// Creates a new instance of <see cref="DebugSsrfHostValidationHandler"/> with the specified configuration.
    /// </summary>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <param name="allowLoopback">Flag indicating whether loopback addresses will be allowed or rejected.</param>
    /// <param name="failMixedResults">Flag indicating whether to fail when a mixture of safe and unsafe addresses is found. Setting this to <see langword="true"/> will reject the connection if any unsafe addresses are found.</param>
    public DebugSsrfHostValidationHandler(
        bool allowInsecureProtocols,
        bool allowLoopback,
        bool failMixedResults) : this(
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: allowLoopback,
            failMixedResults: failMixedResults,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: null)
    {
    }

    /// <summary>
    /// Creates a new instance of <see cref="DebugSsrfHostValidationHandler"/> with the specified configuration.
    /// </summary>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <param name="allowLoopback">Flag indicating whether loopback addresses will be allowed or rejected.</param>
    /// <param name="failMixedResults">Flag indicating whether to fail when a mixture of safe and unsafe addresses is found. Setting this to <see langword="true"/> will reject the connection if any unsafe addresses are found.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    public DebugSsrfHostValidationHandler(
        bool allowInsecureProtocols,
        bool allowLoopback,
        bool failMixedResults,
        ILoggerFactory loggerFactory) : this(
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: allowLoopback,
            failMixedResults: failMixedResults,
            hostEntryResolver: null,
            asyncHostEntryResolver: null,
            loggerFactory: loggerFactory)
    {
    }

    /// <summary>
    /// Creates a new instance of <see cref="DebugSsrfHostValidationHandler"/> with the specified configuration.
    /// </summary>
    /// <param name="additionalUnsafeNetworks">An optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe. This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.</param>
    /// <param name="additionalUnsafeIpAddresses">An optional collection of additional <see cref="IPAddress"/> addresses to consider unsafe. This can be used to block additional IP addresses beyond the built-in defaults, such as internal application IP addresses or other known unsafe addresses.</param>
    /// <param name="allowInsecureProtocols">Flag indicating whether http:// and ws:// URIs will be allowed or rejected.</param>
    /// <param name="allowLoopback">Flag indicating whether loopback addresses will be allowed or rejected.</param>
    /// <param name="failMixedResults">Flag indicating whether to fail when a mixture of safe and unsafe addresses is found. Setting this to <see langword="true"/> will reject the connection if any unsafe addresses are found.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    public DebugSsrfHostValidationHandler(
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        bool allowInsecureProtocols,
        bool allowLoopback,
        bool failMixedResults,
        ILoggerFactory? loggerFactory) : this(
            additionalUnsafeNetworks: additionalUnsafeNetworks,
            additionalUnsafeIpAddresses: additionalUnsafeIpAddresses,
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: allowLoopback,
            failMixedResults: failMixedResults,
            hostEntryResolver : null,
            asyncHostEntryResolver : null,
            loggerFactory: loggerFactory)
    {
    }

    /// <summary>
    /// Creates a new instance of <see cref="DebugSsrfHostValidationHandler"/> with the specified configuration.
    /// </summary>
    /// <param name="options">An <see cref="SsrfOptions"/> instance containing the configuration for the handler.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="options"/> is <see langword="null"/>.</exception>
    public DebugSsrfHostValidationHandler(SsrfOptions options) : this (
        options: options,
        hostEntryResolver: null,
        asyncHostEntryResolver: null,
        loggerFactory: null)
    {
        ArgumentNullException.ThrowIfNull(options);
    }

    /// <summary>
    /// Creates a new instance of <see cref="DebugSsrfHostValidationHandler"/> with the specified configuration.
    /// </summary>
    /// <param name="options">An <see cref="SsrfOptions"/> instance containing the configuration for the handler.</param>
    /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> to use for logging. If not provided, a <see cref="NullLoggerFactory"/> will be used and no logs will be emitted.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="options"/> is <see langword="null"/>.</exception>
    public DebugSsrfHostValidationHandler(SsrfOptions options, ILoggerFactory? loggerFactory) : this (
        options: options,
        hostEntryResolver: null,
        asyncHostEntryResolver: null,
        loggerFactory: loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(options);
    }

    internal DebugSsrfHostValidationHandler(
        ICollection<IPNetwork>? additionalUnsafeNetworks,
        ICollection<IPAddress>? additionalUnsafeIpAddresses,
        bool allowInsecureProtocols,
        bool allowLoopback,
        bool failMixedResults,
        Func<string, IPHostEntry>? hostEntryResolver,
        Func<string, CancellationToken, Task<IPHostEntry>>? asyncHostEntryResolver,
        ILoggerFactory? loggerFactory)
    {
        _additionalUnsafeNetworks = additionalUnsafeNetworks;
        _additionalUnsafeIpAddresses = additionalUnsafeIpAddresses;
        _allowInsecureProtocols = allowInsecureProtocols;
        _allowLoopback = allowLoopback;
        _failMixedResults = failMixedResults;
        _hostEntryResolver = hostEntryResolver ?? s_defaultHostEntryResolver;
        _asyncHostEntryResolver = asyncHostEntryResolver ?? s_defaultAsyncHostEntryResolver;

        loggerFactory ??= NullLoggerFactory.Instance;
        _logger = loggerFactory.CreateLogger<DebugSsrfHostValidationHandler>();
    }

    internal DebugSsrfHostValidationHandler(
        SsrfOptions options,
        Func<string, IPHostEntry>? hostEntryResolver,
        Func<string, CancellationToken, Task<IPHostEntry>>? asyncHostEntryResolver,
        ILoggerFactory? loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(options);
        _additionalUnsafeNetworks = options.AdditionalUnsafeNetworks;
        _additionalUnsafeIpAddresses = options.AdditionalUnsafeIpAddresses;
        _allowInsecureProtocols = options.AllowInsecureProtocols;
        _allowLoopback = options.AllowLoopback;
        _failMixedResults = options.FailMixedResults;
        _hostEntryResolver = hostEntryResolver ?? s_defaultHostEntryResolver;
        _asyncHostEntryResolver = asyncHostEntryResolver ?? s_defaultAsyncHostEntryResolver;

        loggerFactory ??= NullLoggerFactory.Instance;
        _logger = loggerFactory.CreateLogger<DebugSsrfHostValidationHandler>();
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
