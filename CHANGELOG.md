## 5.0.0 - Unreleased

### Added

* Add property and method extensions to `IPAddress` to check for various special types of IPv6 addresses that may be relevant for SSRF protection, including:
  * Add check and normalization for IPv4-compatible IPv6 addresses, `IsIPv4CompatibleIPv6` and `MapIPv6CompatibleToIPv4()`.
  * Add check and normalization for 6:4 IPv6 addresses, `Is6to4` and `Map6to4ToIPv4()`.
  * Add check and normalization for ISATAP IPv6 addresses, `IsISATAP` and `MapISATAPToIPv4()`.
  * Add check and normalization for NAT64 IPv6 addresses, `IsNAT64` and map `MapNAT64ToIPv4()`.
  * Add normalization for Teredo IPv6 addresses, `MapTeredoToIPv4()`.

### Changed

* **Breaking** Replace `allowInsecureProtocols` parameter with `allowedSchemes` in `SsrfSocketsHttpHandlerFactory.Create()`, `ProxiedSsrfDelegatingHandler` constructor and as a property in `SsrfOptions` to allow for more flexible protocol allow listing.

  To use the new collection replace `allowInsecureProtocols : true` with `allowedSchemes : ["https", "http", "wss", "ws"]`.
  You can remove `wss` and `ws` if you have no WebSocket use.

 * **Breaking** `ProxiedSsrfDelegatingHandler` now takes a new options class, `ProxiedSsrfOptions`, instead of `SsrfOptions` to allow for proxy specific configuration. The new options class inherits from `SsrfOptions`
   so all existing configuration options are still available, and the `Proxy` property has been added
   * `Proxy` - an instance of `WebProxy` that will be used for the handler.

* **Breaking** `ProxiedSsrfDelegatingHandler` constructor now takes a `WebProxy` instance rather than an `IWebProxy`
instance to allow the automatic safe listing of the proxy address.

* Update OTEL dependencies to address [CVE-2026-40894 - OpenTelemetry dotnet: Excessive memory allocation when parsing OpenTelemetry propagation headers](https://github.com/advisories/GHSA-g94r-2vxg-569j)

## 4.0.0 - 2026-04-14

### Added

* Add `allowedHostnames` parameter to `SsrfSocketsHttpHandlerFactory.Create()`, `ProxiedSsrfDelegatingHandler`
  constructor and as a property in `SsrfOptions` to enable safe listing of host names,
  including support for wildcard patterns
  ([#6](https://github.com/blowdart/idunno.Security.Ssrf/issues/6)) ([blowdart](https://github.com/blowdart))
  ([#7](https://github.com/blowdart/idunno.Security.Ssrf/issues/7)) ([blowdart](https://github.com/blowdart))
  ([#9](https://github.com/blowdart/idunno.Security.Ssrf/issues/9)) ([blowdart](https://github.com/blowdart))
  ([#10](https://github.com/blowdart/idunno.Security.Ssrf/issues/10)) ([blowdart](https://github.com/blowdart))
* Add `safeIPNetworks` and `safeIPAddresses` parameters to `SsrfSocketsHttpHandlerFactory.Create()`,
  `ProxiedSsrfDelegatingHandler` constructor and as properties in `SsrfOptions` to enable safe listing of IP addresses and networks.
  ([#6](https://github.com/blowdart/idunno.Security.Ssrf/issues/6)) ([blowdart](https://github.com/blowdart))
  ([#8](https://github.com/blowdart/idunno.Security.Ssrf/issues/8)) ([blowdart](https://github.com/blowdart))
  ([#9](https://github.com/blowdart/idunno.Security.Ssrf/issues/9)) ([blowdart](https://github.com/blowdart))
  ([#10](https://github.com/blowdart/idunno.Security.Ssrf/issues/10)) ([blowdart](https://github.com/blowdart))
* Add metrics for tracking SSRF attempts, including counts of blocked requests and counts for blocked hosts and IP addresses.

### Changed

* Disable Nagle on new Sockets to match SocketsHttpHandler ([#11](https://github.com/blowdart/idunno.Security.Ssrf/pull/11)) ([MihaZupan](https://github.com/MihaZupan))
* **Breaking** Remove multiple overloads in favor of two `Create` methods, with defaults, on `SsrfSocketsHttpHandlerFactory`.
* **Breaking** Remove multiple constructors in favor of two constructors, with defaults, on `ProxiedSsrfDelegatingHandler`.
* **Breaking** Change casing of `AdditionalUnsafeIpAddresses` property to `AdditionalUnsafeIPAddresses` in options to match .NET's casing.
* **Breaking** Change casing of `additionalUnsafeIpAddresses` property to `additionalUnsafeIPAddresses` parameters to match .NET's casing.
* **Breaking** Change `additionalUnsafeNetworks` parameter name to `additionalUnsafeIPNetworks` to match .NET's naming.

## 3.0.0 - 2026-04-04

### Added

* Add `allowLoopback` parameter to `Ssrf.IsUnsafe`, `Ssrf.IsUnsafeHost`, `Ssrf.IsUnsafeIPAddress` and
  `SsrfSocketsHttpHandlerFactory.Create` methods to allow localhost addresses to be considered valid
  if explicitly specified. ([#4](https://github.com/blowdart/idunno.Security.Ssrf/issues/4)) ([blowdart](https://github.com/blowdart))
* Add `ProxiedSsrfDelegatingHandler` to support the use of proxies.

### Changed

* **Breaking** Remove `Proxy` parameter from `SsrfSocketsHttpHandlerFactory.Create` method.
  To create a handler with a proxy use `ProxiedSsrfDelegatingHandler`.

## 2.0.0 - 2026-31-03

### Changed

* **Breaking:** Correct spelling of `SsrfSocketsHttpHandlerFactory` ([#3](https://github.com/blowdart/idunno.Security.Ssrf/issues/3)) ([josephdecock](https://github.com/josephdecock))

## 1.1.0 - 2026-29-03

### Changed

* Expand IPV6 range per [RFC 9637 "Expanding the IPv6 Documentation Space"](https://datatracker.ietf.org/doc/rfc9637/) ([#3](https://github.com/blowdart/idunno.Security.Ssrf/issues/2)) ([vcsjones](https://github.com/vcsjones))

## 1.0.0 - 2026-29-03

### Added

* Initial release of the project with core features and functionalities.
