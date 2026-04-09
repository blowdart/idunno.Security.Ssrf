# How the SSRF handler works

The obvious mitigation is to validate the URI by resolving it to IP addresses and checking those addresses
against known unsafe ranges. Normally, security guidance prefers an allow list over a block list - 
but with 4,294,967,296 IPv4 addresses and 340,282,366,920,938,000,000,000,000,000,000,000,000 IPv6 addresses,
an allow list isn’t practical here. A list of unsafe ranges is much more manageable,
and many of those ranges are defined in RFCs such as
[RFC 1918](https://datatracker.ietf.org/doc/html/rfc1918),
[RFC 3927](https://datatracker.ietf.org/doc/html/rfc3927),
[RFC 4291](https://datatracker.ietf.org/doc/html/rfc4291),
[RFC 6052](https://datatracker.ietf.org/doc/html/rfc6052), and others.

You also need to decide which URI schemes are acceptable. In many cases you’ll want to allow only HTTPS (and possibly WSS).
There are plenty of other schemes FTP, telnet, gopher, ms-teams, and more, so checking the scheme can shortcut the need to do
IP address checks.

This is where [idunno.Security.Ssrf](https://github.com/blowdart/idunno.Security.Ssrf) comes in, a
[NuGet package](https://www.nuget.org/packages/idunno.Security.Ssrf/?ref=idunno.org) that performs both checks.


## Checking a URI

You should start by checking whether the URI itself is acceptable (before you even resolve DNS).
`IsUnsafeUri` validates that the URI is absolute, not a UNC path, not localhost, and that it represents either a DNS name or an IPv4/IPv6 address. It also verifies that the scheme is HTTPS or WSS.

```c#
if (idunno.Security.Ssrf.IsUnsafeUri(new Uri("http://example.com")))
{
    // Disallow entry of this URI into the system,
    // or log an alert, or whatever you want to do with it.
}
```

The check above will fail as, by default, only `https://` and `wss://` URIs are allowed.

## Checking an IP address

Next, check whether the IP addresses the URI resolves to are safe. You can resolve the host and
run each resulting address through `IsUnsafeIpAddress`, which checks whether it falls into any known unsafe network,
or matches an explicitly blocked IP.

```c#
if (Ssrf.IsUnsafeIpAddress(IPAddress.Parse("127.0.0.1")))
{
    // Disallow this IP address from being used in the system,
    // or log an alert, or whatever you want to do with it.
}
```

If you don’t want to write the “resolve + loop + check” logic yourself, you can use `IsUnsafe`.
It validates the URI, resolves the host, checks every resolved IP address, and returns `true`
if a host name, or the IP addresses it resolves to is dangerous, or `false` is not.

At this point it’s tempting to think: “Great! Validate the URI when it comes in, and we’re done.”

But there’s still a catch: DNS can change.

If you only validate at the point of entry, you can still end up with a time-of-check, time-of-use (TOCTOU) issue:
the hostname can resolve to safe IPs today and unsafe IPs later. An attacker could register a DNS name that looks
harmless during submission, then change it days later to point at `127.0.0.1`, `169.254.169.254`, or
something else internal or dangerous. You also need to perform the same checks when making a request to a URI, and you
can only do this within the `HttpClient` or `ClientWebSocket`.

## Protecting an HttpClient

To be fully protected, you need to validate the destination IP address right before the connection is made.
The `SsrfSocketsHttpHandlerFactory` class creates a handler that does all this:

```c#
using HttpClient httpClient = new(SsrfSocketsHttpHandlerFactory.Create());

HttpResponseMessage response = await httpClient.GetAsync(
    new Uri("https://example.com"));
```

The `Create()` method can has some optional parameters, including

* `connectionStrategy` : prefer IPv4, IPv6 or randomise which order the connections are attempted.
* `additionalUnsafeNetworks` : add your own IP Networks to the unsafe list.
* `additionalUnsafeIPAddresses` : treat additional individual IP addresses as unsafe
* `connectTimeout` : how long to wait during connection establishment before giving up.
* `allowInsecureProtocols` : allow http:// and ws:// schemes in URIs.
* `failMixedResults` : if DNS resolves to both safe and unsafe IPs, either fail immediately (true, the default) or drop unsafe IPs and try only the safe ones (false).
* `allowAutoRedirect`, `automaticDecompression`, `proxy` and `sslOptions` : these mirror the options of the same names on
  [`HttpClientHandler`](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclienthandler)

As this returns a `SocketsHttpHandler`, it must be the final handler in the chain if you’re using delegating handlers.

It uses a [`SocketsHttpHandler`](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.socketshttphandler). `SocketsHttpHandler` (instead of the more typical `HttpClientHandler`) lets you intercept connection establishment
via [`ConnectCallback`](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.socketshttphandler.connectcallback).

Inside `ConnectCallback` it validates the outbound destination, first checking whether the host name and protocol are considered
unsafe and, if those checks pass, resolving the name to its IP addresses, checking each resulting IP,
and building a list of safe IP addresses. If none are safe, the request fails with an `SsrfException`.
Depending on where the exception is thrown, and the type of client it will end up as the `InnerException` on the
`HttpRequestException`, `SocketException` or `WebSocketException` thrown by the `HttpClient` or `ClientWebSocket`.

## Protecting an ClientWebSocket

To use it with `ClientWebSocket`, create an `HttpClient` that uses a handler returned from `SsrfSocketsHttpHandlerFactory`,
then pass that `HttpClient` into
[`ClientWebSocket.ConnectAsync()`](https://learn.microsoft.com/en-us/dotnet/api/system.net.websockets.clientwebsocket.connectasync)
via the `invoker` parameter.

{
    await webSocket.ConnectAsync(
        uri: "wss://echo.websocket.org",
        invoker: invoker);
}
```
