## 4.0.0 - In Development

### Added

* Add `allowedHostnames` parameter to constructions and property in `SsrfOptions` to enable safe listing of host names,
  including support for wildcard patterns ([#7](https://github.com/blowdart/idunno.Security.Ssrf/issues/7)) ([blowdart](https://github.com/blowdart))

### Changed

* **Breaking** Removed multiple overloads in favour of two `Create` methods, with defaults, on `SsrfSocketsHttpHandlerFactory`.
* **Breaking** Removed multiple constructors in favour of two constructors, with defaults, on `ProxiedSsrfDelegatingHandler`.

## 3.0.0 - 2026-04-04

### Added

* Add `allowLoopback` parameter to `Ssrf.IsUnsafe`, `Ssrf.IsUnsafeHost`, `Ssrf.IsUnsafeIPAddress` and
  `SsrfSocketsHttpHandlerFactory.Create` methods to allow localhost addresses to be considered valid
  if explicitly specified. Fixes [#4](https://github.com/blowdart/idunno.Security.Ssrf/issues/4)
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
