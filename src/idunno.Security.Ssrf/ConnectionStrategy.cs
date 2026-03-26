// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

namespace idunno.Security;

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
