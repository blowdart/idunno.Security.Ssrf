## 4.0.0 - In Development

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
