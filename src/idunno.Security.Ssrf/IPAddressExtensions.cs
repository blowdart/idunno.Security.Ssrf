// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;

namespace idunno.Security;

/// <summary>
/// Provides extension methods for checking IPv6 addresses to see if they map to IPv4 address including IPv4 Compatible IPv6 addresses,
/// 6to4 mapping, ISATAP, and NAT64 addressing.
/// </summary>
/// <remarks><para>These methods assist in identifying and converting IPv4 compatible IPv6 addresses as defined by
/// relevant RFCs. Use these extensions to simplify interoperability between IPv4 and IPv6 address
/// representations.</para></remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Nested type is an extension property.")]
public static class IPAddressExtensions
{
    private static readonly IPAddress s_ipV6ZeroHost = IPAddress.Parse("::");
    private static readonly IPAddress s_ipV6LocalHost = IPAddress.Parse("::1");
    private static readonly IPNetwork s_6to4Network = IPNetwork.Parse("2002::/16");
    private static readonly IPNetwork s_nat64Network = IPNetwork.Parse("64:ff9b::/96");
    private static readonly IPNetwork s_nat64LocalUseNetwork = IPNetwork.Parse("64:ff9b:1::/48");

    /// <summary>
    /// Extension properties for <see cref="IPAddress"/>.
    /// </summary>
    /// <param name="ipAddress">The <see cref="IPAddress"/> to act on.</param>
    extension(IPAddress ipAddress)
    {
        /// <summary>
        /// Gets whether the IP address is an IPv4 compatible IPv6 address.
        /// </summary>
        /// <value><see langword="true"/> if the IP address is an IPv4 compatible IPv6 address; otherwise, <see langword="false"/>.</value>
        /// <remarks>
        /// <para>An IPv4 compatible IPv6 address is an IPv6 address that has the first 96 bits set to zero and the last 32 bits set to the IPv4 address,
        /// defined in RFC 1884 and updated by RFC 2373.</para>
        /// </remarks>
        public bool IsIPv4CompatibleIPv6
        {
            get
            {
                if (ipAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    return false;
                }

                // ::1 % scope / ::% scope with a non‑default scope ID won't hit the early exit fast‑path but they fall through to the byte loop and
                // end up classified as IPv4‑compatible mapping to 0.0.0.1 / 0.0.0.0. Both map to unsafe IPv4 (RFC 1122), so the SSRF outcome is fail‑closed anyway.
                if (ipAddress.Equals(s_ipV6LocalHost) || ipAddress.Equals(s_ipV6ZeroHost))
                {
                    return false;
                }

                Span<byte> bytes = stackalloc byte[16];
                if (!ipAddress.TryWriteBytes(bytes, out _))
                {
                    bytes = ipAddress.GetAddressBytes();
                }

                for (int i = 0; i < 12; i++)
                {
                    if (bytes[i] != 0)
                    {
                        return false;
                    }
                }

                return true;
            }
        }

        /// <summary>
        /// Gets whether the IP address is an 6to4-mapped IPv6 address.
        /// </summary>
        /// <value><see langword="true"/> if the IP address is an 6to4-mapped IPv6 address; otherwise, <see langword="false"/>.</value>
        /// <remarks>
        ///<para>An 6to4-mapped IPv6 address is an IPv6 address that has the first 16 bits = 0x2002, and the next 32 bits set to the IPv4 address,
        ///defined in RFC 3056.</para>
        /// </remarks>
        public bool Is6to4 =>
            ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                && s_6to4Network.Contains(ipAddress);

        /// <summary>
        /// Gets whether the IP address is an ISATAP tunnel address.
        /// </summary>
        /// <value><see langword="true"/> if the IP address is an ISATAP tunnel address; otherwise, <see langword="false"/>.</value>
        /// <remarks>
        /// <para>An ISATAP (Intra-Site Automatic Tunnel Addressing Protocol) tunnel address is an IPv6 address where the first 64 bits are any unicast prefix,
        /// the next 32 bits are set to the ISATAP identifier (<c>00-00-5E-FE</c> for a non-globally-unique IPv4, or <c>02-00-5E-FE</c> with the u-bit set for a globally-unique IPv4),
        /// and the last 32 bits are set to the IPv4 address, defined in RFC 5214.</para>
        /// <para>ISATAP has no reserved IPv6 prefix, so detection is based solely on the interface-identifier byte pattern. A legitimate non-ISATAP address
        /// matching this pattern is cryptographically improbable: the OUI <c>00-00-5E</c> is IANA-reserved and is not used for host interface identifiers;
        /// EUI-64 identifiers derived from a MAC address always place <c>FF-FE</c> at bytes 11-12 and so cannot produce <c>5E-FE</c> at bytes 10-11; and
        /// RFC 4941 privacy-extension identifiers would collide with the full pattern with probability on the order of 2^-30. If you encounter
        /// a legitimate public address that matches, it can be allow-listed via the <c>safeIPNetworks</c> or <c>safeIPAddresses</c> parameters on
        /// <see cref="Ssrf.IsUnsafeIpAddress"/> / <see cref="Ssrf.IsUnsafe(Uri, ICollection{string}, bool, ICollection{IPNetwork}, ICollection{IPAddress}, ICollection{string}, ICollection{IPNetwork}, ICollection{IPAddress}, SsrfMetrics, CancellationToken)"/>.
        /// The detection is deliberately broader than the strict RFC 5214 semantics so that an RFC-inconsistent but attacker-crafted identifier
        /// (such as the u-bit form wrapping an RFC1918 address) still fails closed.</para>
        /// </remarks>
        public bool IsISATAP
        {
            get
            {
                if (ipAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    return false;
                }

                Span<byte> bytes = stackalloc byte[16];
                if (!ipAddress.TryWriteBytes(bytes, out _))
                {
                    bytes = ipAddress.GetAddressBytes();
                }

                return (bytes[8] == 0x00 || bytes[8] == 0x02)
                    && bytes[9] == 0x00
                    && bytes[10] == 0x5E
                    && bytes[11] == 0xFE;
            }
        }

        /// <summary>
        /// Gets whether the IP address is a NAT64 well-known prefix address.
        /// </summary>
        /// <value><see langword="true"/> if the IP address is a NAT64 well-known prefix address; otherwise, <see langword="false"/>.</value>
        /// <remarks>
        ///<para>A NAT64 address is an IPv6 address that has the first 96 bits set to the NAT64 well-known prefix
        /// (64:ff9b::/96), defined in RFC 6052. For the RFC 8215 local-use /48 prefix use <see cref="get_IsNAT64LocalUse(IPAddress)"/>.</para>
        ///</remarks>
        public bool IsNAT64 =>
            ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                && s_nat64Network.Contains(ipAddress);

        /// <summary>
        /// Gets whether the IP address is within the NAT64 local-use prefix.
        /// </summary>
        /// <value><see langword="true"/> if the IP address is within the NAT64 local-use prefix (64:ff9b:1::/48); otherwise, <see langword="false"/>.</value>
        /// <remarks>
        ///<para>Defined in RFC 8215. Addresses in this range reach IPv4 destinations via an operator's local NAT64 gateway and are
        /// treated as unsafe regardless of the embedded IPv4 address, because the gateway itself is internal infrastructure.
        /// Accordingly this prefix is not normalized to IPv4 by <see cref="NormalizeToIPv4(IPAddress)"/>; it is blocked at the range level by <see cref="Ssrf.IsUnsafeIpAddress"/>.</para>
        ///</remarks>
        public bool IsNAT64LocalUse =>
            ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                && s_nat64LocalUseNetwork.Contains(ipAddress);

        /// <summary>
        /// Maps the an IPv4 compatible IPv6 <see cref="IPAddress"/> object to an IPv4 address.
        /// </summary>
        /// <returns>The mapped IPv4 address if the IP address is an IPv4 compatible IPv6 address; otherwise, the original IP address.</returns>
        /// <remarks>
        /// <para>If you want to use <see cref="MapIPv6CompatibleToIPv4(IPAddress)"/>to convert an IPv4 address from IPv6 format to IPv4 format, you must first ensure that you've got a
        /// compatible IPv6 address. Call <see cref="get_IsIPv4CompatibleIPv6(IPAddress)"/>, which will return <see langword="true"/> if the IP address is an IPv4 compatible IPv6 address,
        /// or <see langword="false"/> otherwise. If <see cref="get_IsIPv4CompatibleIPv6(IPAddress)"/> returns <see langword="true"/>, use <see cref="MapIPv6CompatibleToIPv4(IPAddress)"/>
        /// to make the conversion.</para>
        /// </remarks>
        public IPAddress MapIPv6CompatibleToIPv4()
        {
            if (ipAddress.IsIPv4CompatibleIPv6)
            {
                Span<byte> bytes = stackalloc byte[16];
                if (!ipAddress.TryWriteBytes(bytes, out _))
                {
                    bytes = ipAddress.GetAddressBytes();
                }

                return new IPAddress(bytes[12..]);
            }
            return ipAddress;
        }

        /// <summary>
        /// Maps a 6:4 -mapped IPv6 <see cref="IPAddress"/> object to an IPv4 address.
        /// </summary>
        /// <returns>The mapped IPv4 address if the IP address is a 6:4 tunnel; otherwise, the original IP address.</returns>
        /// <remarks>
        /// <para>If you want to use <see cref="Map6to4ToIPv4(IPAddress)"/>to convert an IPv4 address from IPv6 format to IPv4 format, you must first ensure that you've got a
        /// compatible IPv6 address. Call <see cref="get_Is6to4(IPAddress)"/>, which will return <see langword="true"/> if the IP address is a 6:4 tunnel,
        /// or <see langword="false"/> otherwise. If <see cref="get_Is6to4(IPAddress)"/> returns <see langword="true"/>, use <see cref="Map6to4ToIPv4(IPAddress)"/>
        /// to make the conversion.</para>
        /// </remarks>
        public IPAddress Map6to4ToIPv4()
        {
            if (ipAddress.Is6to4)
            {
                Span<byte> bytes = stackalloc byte[16];
                if (!ipAddress.TryWriteBytes(bytes, out _))
                {
                    bytes = ipAddress.GetAddressBytes();
                }

                return new IPAddress(bytes[2..6]);
            }
            return ipAddress;
        }

        /// <summary>
        /// Maps an ISATAP IPv6 <see cref="IPAddress"/> object to an IPv4 address.
        /// </summary>
        /// <returns>The mapped IPv4 address if the IP address is a ISATAP address; otherwise, the original IP address.</returns>
        /// <remarks>
        /// <para>If you want to use <see cref="MapISATAPToIPv4(IPAddress)"/>to convert an IPv4 address from IPv6 format to IPv4 format, you must first ensure that you've got a
        /// compatible IPv6 address. Call <see cref="get_IsISATAP(IPAddress)"/>, which will return <see langword="true"/> if the IP address is an ISATAP tunnel,
        /// or <see langword="false"/> otherwise. If <see cref="get_IsISATAP(IPAddress)"/> returns <see langword="true"/>, use <see cref="MapISATAPToIPv4(IPAddress)"/>
        /// to make the conversion.</para>
        /// </remarks>
        public IPAddress MapISATAPToIPv4()
        {
            if (ipAddress.IsISATAP)
            {
                Span<byte> bytes = stackalloc byte[16];
                if (!ipAddress.TryWriteBytes(bytes, out _))
                {
                    bytes = ipAddress.GetAddressBytes();
                }

                return new IPAddress(bytes[12..]);
            }
            return ipAddress;
        }

        /// <summary>
        /// Maps a NAT64 IPv6 <see cref="IPAddress"/> object to an IPv4 address.
        /// </summary>
        /// <returns>The mapped IPv4 address if the IP address is a NAT64 address; otherwise, the original IP address.</returns>
        /// <remarks>
        /// <para>If you want to use <see cref="MapNAT64ToIPv4(IPAddress)"/>to convert an IPv4 address from IPv6 format to IPv4 format, you must first ensure that you've got a
        /// compatible IPv6 address. Call <see cref="get_IsNAT64(IPAddress)"/>, which will return <see langword="true"/> if the IP address is a NAT64 address,
        /// or <see langword="false"/> otherwise. If <see cref="get_IsNAT64(IPAddress)"/> returns <see langword="true"/>, use <see cref="MapNAT64ToIPv4(IPAddress)"/>
        /// to make the conversion.</para>
        /// <para>Note that NAT64 local use IPv4 destinations are not mapped to IPv4 by this method, even though they are technically NAT64 addresses.</para>
        /// </remarks>
        public IPAddress MapNAT64ToIPv4()
        {
            if (ipAddress.IsNAT64)
            {
                byte[] bytes = ipAddress.GetAddressBytes();
                return new IPAddress(bytes[12..]);
            }
            return ipAddress;
        }

        /// <summary>
        /// Maps a Teredo IPv6 <see cref="IPAddress"/> object to an IPv4 address.
        /// </summary>
        /// <returns>The mapped IPv4 address if the IP address is a Teredo address; otherwise, the original IP address.</returns>
        /// <remarks>
        /// <para>If you want to use <see cref="MapTeredoToIPv4(IPAddress)"/>to convert an IPv4 address from IPv6 format to IPv4 format, you must first ensure that you've got a
        /// compatible IPv6 address. Call <see cref="IPAddress.IsIPv6Teredo"/>, which will return <see langword="true"/> if the IP address is a Teredo address,
        /// or <see langword="false"/> otherwise. If <see cref="IPAddress.IsIPv6Teredo"/> returns <see langword="true"/>, use <see cref="MapTeredoToIPv4(IPAddress)"/>
        /// to make the conversion.</para>
        /// </remarks>
        public IPAddress MapTeredoToIPv4()
        {
            if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                && ipAddress.IsIPv6Teredo)
            {
                Span<byte> bytes = stackalloc byte[16];
                if (!ipAddress.TryWriteBytes(bytes, out _))
                {
                    bytes = ipAddress.GetAddressBytes();
                }

                ReadOnlySpan<byte> ipV4Bytes =
                [
                    (byte)~bytes[12],
                    (byte)~bytes[13],
                    (byte)~bytes[14],
                    (byte)~bytes[15],
                ];

                return new IPAddress(ipV4Bytes);
            }
            return ipAddress;
        }

        /// <summary>
        /// Normalizes an IPv6 address to an IPv4 address if it is an IPv4 compatible IPv6 address, an 6:4-mapped IPv6 address, a NAT64 address, or a Teredo address;
        /// otherwise, returns the original IP address.
        /// </summary>
        /// <returns>A normalized IPv4 address if the IP address is an IPv4 compatible IPv6 address, an 6:4-mapped IPv6 address, a NAT64 address, or a Teredo address; otherwise, the original IP address.</returns>
        /// <remarks>
        /// <para>NAT64 local use IPv4 destinations are not mapped to IPv4 by this method, even though they are technically NAT64 addresses, because the gateway itself is internal infrastructure
        /// and will be treated as unsafe by the default IPv6 checks.</para>
        /// </remarks>
        public IPAddress NormalizeToIPv4()
        {
            if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                // Normalize IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
                if (ipAddress.IsIPv4MappedToIPv6)
                {
                    return ipAddress.MapToIPv4();
                }

                // Normalize IPv4-compatible IPv6 addresses (e.g. ::192.0.2.1)
                if (ipAddress.IsIPv4CompatibleIPv6)
                {
                    return ipAddress.MapIPv6CompatibleToIPv4();
                }

                // Normalize 6:4 addresses (e.g. 2002:c000:0201::1)
                // This may also catch an overlapping ISATAP address (e.g. 2002:c000:022a::5efe:0a00:0001), but that's not a problem since it will normalize to an unsafe IPv4 address anyway.
                if (ipAddress.Is6to4)
                {
                    return ipAddress.Map6to4ToIPv4();
                }

                // Normalize Teredo addresses (e.g. 2001::) before ISATAP, because an attacker-crafted Teredo address
                // (2001:0000::/32) can coincidentally match the ISATAP byte pattern (bytes 8-11 == 00-00-5E-FE
                // or 02-00-5E-FE). Checking Teredo first ensures the Teredo-embedded client IPv4 is evaluated
                // rather than an attacker-controlled ISATAP interpretation of the same bytes.
                if (ipAddress.IsIPv6Teredo)
                {
                    return ipAddress.MapTeredoToIPv4();
                }

                // Normalize ISATAP addresses (e.g. 2001:db8::5efe:)
                if (ipAddress.IsISATAP)
                {
                    return ipAddress.MapISATAPToIPv4();
                }

                // Normalize NAT64 addresses (e.g. 64:ff9b::)
                if (ipAddress.IsNAT64)
                {
                    return ipAddress.MapNAT64ToIPv4();
                }
            }

            return ipAddress;
        }
    }
}
