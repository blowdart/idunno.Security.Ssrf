// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;

namespace idunno.Security;

/// <summary>
/// Encapsulates options for the <see cref="ProxiedSsrfDelegatingHandler"/>.
/// </summary>
public record ProxiedSsrfOptions : SsrfOptions
{
    /// <summary>
    /// Gets or sets the custom proxy to use.
    /// </summary>
    public WebProxy? Proxy { get; set; }

    /// <summary>
    /// Converts this instance of <see cref="ProxiedSsrfOptions"/> to an instance of <see cref="SsrfOptions"/> for use with the underlying <see cref="SsrfSocketsHttpHandlerFactory"/>.
    /// </summary>
    /// <returns>An instance of <see cref="SsrfOptions"/> with the same settings as this instance, excluding the <see cref="Proxy"/> property.</returns>
    internal SsrfOptions ToSsrfOptions()
    {
        return new SsrfOptions
        {
            ConnectionStrategy = ConnectionStrategy,
            AdditionalUnsafeIPNetworks = AdditionalUnsafeIPNetworks,
            AdditionalUnsafeIPAddresses = AdditionalUnsafeIPAddresses,
            ConnectTimeout = ConnectTimeout,
            AllowedSchemes = AllowedSchemes,
            FailMixedResults = FailMixedResults,
            AllowAutoRedirect = AllowAutoRedirect,
            AutomaticDecompression = AutomaticDecompression,
            SslOptions = SslOptions,
            AllowLoopback = AllowLoopback,
            AllowedHostnames = AllowedHostnames,
            SafeIPNetworks = SafeIPNetworks,
            SafeIPAddresses = SafeIPAddresses
        };
    }

}
