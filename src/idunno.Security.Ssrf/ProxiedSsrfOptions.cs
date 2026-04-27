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
}
