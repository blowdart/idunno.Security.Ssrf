// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;
using System.Net.Security;

namespace idunno.Security;

/// <summary>
/// Encapsulates options for the <see cref="SsrfSocketsHttpHandlerFactory"/>.
/// </summary>
public record SsrfOptions
{
    /// <summary>
    /// Gets or sets the strategy used to establish connections to resolved IP addresses for a given host.
    /// </summary>
    public ConnectionStrategy ConnectionStrategy { get; set; } = ConnectionStrategy.None;

    /// <summary>
    /// Gets an optional collection of additional <see cref="IPNetwork"/> ranges to consider unsafe.
    /// This can be used to block additional IP ranges beyond the built-in defaults, such as internal application IP ranges or other known unsafe addresses.
    /// </summary>
    public ICollection<IPNetwork> AdditionalUnsafeIPNetworks { get; init; } = [];

    /// <summary>
    /// Gets an optional collection of additional <see cref="IPAddress"/> addresses to consider unsafe.
    /// This can be used to block additional IP addresses beyond the built-in defaults, such as internal application IP addresses or other known unsafe addresses.
    /// </summary>
    public ICollection<IPAddress> AdditionalUnsafeIPAddresses { get; init; } = [];

    /// <summary>
    /// Gets or sets the timespan to wait before the connection establishing times out. The default value is <see cref="System.Threading.Timeout.InfiniteTimeSpan"/>.
    /// </summary>
    public TimeSpan? ConnectTimeout { get; set; }

    /// <summary>
    /// Gets or sets an optional collection of URI schemes that are allowed. This can be used to restrict or allow specific protocols such as "http" or "ws".
    /// </summary>
    public ICollection<string>? AllowedSchemes { get; init; }

    /// <summary>
    /// Gets or sets a flag indicating whether to fail when a mixture of safe and unsafe addresses is found.
    /// Setting this to <see langword="false"/> will allow connections to proceed to any safe IP address discovered during
    /// resolution, even if the full range of IP addresses resolved includes unsafe addresses.
    /// </summary>
    public bool FailMixedResults { get; set; } = true;

    /// <summary>
    /// Gets or sets a value that indicates whether the handler should follow redirection responses. Defaults to <see langword="false"/>.
    /// </summary>
    public bool AllowAutoRedirect { get; set; }

    /// <summary>
    /// Gets or sets the type of decompression method used by the handler for automatic decompression of the HTTP content response.
    /// </summary>
    public DecompressionMethods? AutomaticDecompression { get; set; }

    /// <summary>
    /// Gets or sets the custom proxy to use.
    /// </summary>
    public IWebProxy? Proxy { get; set; }

    /// <summary>
    /// Gets or sets the set of options used for client TLS authentication.
    /// </summary>
    public SslClientAuthenticationOptions? SslOptions { get; set; }

    /// <summary>
    /// Gets or sets a flag indicating whether to allow loopback addresses (e.g. localhost, 127.0.0.1, ::1). Defaults to <see langword="false"/>.
    /// </summary>
    public bool AllowLoopback { get; set; }

    /// <summary>
    /// Gets or a collection of hostnames that are allowed to bypass SSRF IP address protections.
    /// This can be used to allow specific trusted hosts names.
    /// Wild cards are supported only at the start of the hostname, and must be followed by a dot
    /// (e.g. "*.example.com" would allow "api.example.com", "test.api.example.com", but not "example.com").
    /// </summary>
    /// <remarks>
    /// <para>This list does not affect the evaluation of the URI scheme, loopback status, or other built-in SSRF protections.</para>
    /// <para>The list is considered trusted data. No validation is performed on it. Do not use user-controlled input to build the list.</para>
    /// </remarks>
    public ICollection<string>? AllowedHostnames { get; init; } = [];

    /// <summary>
    /// Gets a collection of IP networks to consider safe, which can be used to allow specific safe ranges that would otherwise be blocked by the unsafe checks.
    /// </summary>
    /// <remarks>
    /// <para>
    ///   Careless use of this option can lead to security vulnerabilities by allowing potentially unsafe IP addresses or networks
    ///   to be considered safe. Use with caution and constrain the values specified to the smallest networks needed.
    ///   Safe entries take precedence over both built-in and additional unsafe entries, so if an IP address is contained in a safe network, it will be considered safe
    ///   even if it would otherwise be blocked by the unsafe checks.
    /// </para>
    /// </remarks>
    public ICollection<IPNetwork>? SafeIPNetworks { get; init; } = [];

    /// <summary>
    /// Gets a collection of IP addresses to consider safe, which can be used to allow specific safe addresses that would otherwise be blocked by the unsafe checks.
    /// </summary>
    /// <remarks>
    /// <para>
    ///   Careless use of this option can lead to security vulnerabilities by allowing potentially unsafe IP addresses or networks
    ///   to be considered safe. Use with caution and constrain the values specified to the smallest amount of IP addresses needed.
    ///   Safe entries take precedence over both built-in and additional unsafe entries, so if an IP address is contained in a safe network, it will be considered safe
    ///   even if it would otherwise be blocked by the unsafe checks.
    ///</para>
    /// </remarks>
    public ICollection<IPAddress>? SafeIPAddresses { get; init; } = [];
}
