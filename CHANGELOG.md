## 2.1.0 - 2026-31-03

### Added

* Add `allowLoopback` parameter to `Ssrf.IsUnsafe`, `Ssrf.IsUnsafeHost`, `Ssrf.IsUnsafeIPAddress` and
  `SsrfSocketsHttpHandlerFactory.Create` methods to allow localhost addresses to be considered valid
  if explicitly specified. Fixes [#4](https://github.com/blowdart/idunno.Security.Ssrf/issues/4)
* Add `DebugSsrfHostValidationHandler` to support the use of debugging proxies like Fiddler or Burp.

## 2.0.0 - 2026-31-03

### Changed

* **Breaking:** Correct spelling of `SsrfSocketsHttpHandlerFactory` ([#3](https://github.com/blowdart/idunno.Security.Ssrf/issues/3)) ([josephdecock](https://github.com/josephdecock))

## 1.1.0 - 2026-29-03

### Changed

* Expand IPV6 range per [RFC 9637 "Expanding the IPv6 Documentation Space"](https://datatracker.ietf.org/doc/rfc9637/) ([#3](https://github.com/blowdart/idunno.Security.Ssrf/issues/2)) ([vcsjones](https://github.com/vcsjones))

## 1.0.0 - 2026-29-03

### Added

* Initial release of the project with core features and functionalities.
