# Configuring the handler

## Adding extra unsafe IP Networks and addresses

You may have some extra unsafe endpoints within your infrastructure which, for whatever reason are not within the
[default unsafe IP ranges](https://github.com/blowdart/idunno.Security.Ssrf/blob/main/src/idunno.Security.Ssrf/Ssrf.cs#L16).

When building the handler you can use the optional `additionalUnsafeIPNetworks` and `additionalUnsafeIPAddresses` to
add to the built-in unsafe lists. For example

```c#
using (var httpClient = new HttpClient(
    SsrfSocketsHttpHandlerFactory.Create(
        additionalUnsafeIPNetworks:
        [
            IPNetwork.Parse("104.16.0.0/12"),
            IPNetwork.Parse("2620:1ec::/36")
        ],
        additionalUnsafeIPAddresses:
        [
            IPAddress.Parse("2606:4700::6812:1b78"),
            IPAddress.Parse("104.18.26.120")
        ])))
{
    HttpResponseMessage response = await httpClient.GetAsync(
        new Uri("https://example.com"));
}
```

## Safe listing host names

The `allowedHostnames` parameter allows you to specify host names that are safe to connect to, even if they resolve to unsafe IP addresses.
This is useful for cases where you have a known safe host that may resolve to an IP address within an unsafe range, such as a local development environment
or a trusted internal service.

`allowedHostnames` supports wildcard patterns, so you can specify a pattern like `*.example.localhost`
to allow all subdomains of `example.localhost`.This can be particularly useful for allowing access to
a range of services within a trusted domain without having to list each one individually. Wildcard patterns only
apply to the leftmost part of the hostname, so `*.example.localhost` would match `service1.example.localhost`
and `live.database.example.localhost`, but not `example.localhost` itself.

## Safe listing IP addresses and networks

The `safeIPAddresses` and `safeIPNetworks` parameters allow you to specify individual IP addresses and networks
that are safe to connect to, even if they would normally be considered unsafe.
This is useful for cases where you have a known safe IP address or network that may fall within an unsafe range,
such as a local development environment or a trusted internal service.

> [!Warning]
> Careless use of `safeIPNetworks` and `safeIPAddresses` can lead to security vulnerabilities by allowing
> genuinely unsafe IP addresses or networks to be considered safe.
> Use with caution and constrain the values specified to the smallest network range or individual IP addresses needed.
> Safe entries take precedence over both built-in and additional unsafe entries, so if an IP address matches
> both a safe and unsafe address, or is within a safe network, it will be considered safe.

## Setting allowed schemes

You may have some `http` or `ws` URIs you need to access. You can add to the default allowed schemes of `https` and `wss` using the `allowedSchemes` parameter.
For example, to allow `http` and `ws` schemes you would set `allowedSchemes` to `[ "https", "wss", "http", "ws" ]`.

If you are not going to use WebSockets you can remove `wss` from the allowed schemes, by passing `[ "https" ]` to `allowedSchemes`.

## Allowing loopback connections

You may have a need for your application to talk to itself, or another application on a different port on the loopback
addresses. You can allow this using the `allowLoopback` parameter.

## Connection strategies

If a host resolves to multiple IP addresses you can choose the strategy used to pick one from the list of
safe IP addresses using the `connectionStrategy` parameter. There are four flags to choose from,

* `None` - the default connection strategy that tries each IP in the order the resolution presented them,
* `Ipv4Preferred` - try IPv4 addresses first, before IPv6 addresses, this is mutually exclusive from `Ipv6Preferred`
* `Ipv6Preferred` - try IPv6 addresses first, before IPv4 addresses, this is mutually exclusive from `Ipv4Preferred`
* `Random` - shuffle the returned IP addresses randomly, before connecting. This can be combined with `Ipv4Preferred` and `Ipv6Preferred`.

## Allowing mixed results

If you have a truly weird setup you may wish to allow a connection to continue if the IP address list returned
during name resolution returns a mixture of safe and unsafe IP addresses. If you set the `failMixedResults`
parameter to `false` all unsafe addresses will be removed from the potential connection list, and, if any safe IP addresses
remain, a connection will be attempted to each.

> [!Warning]
> DNS resolution that returns a mix of safe and unsafe IP addresses is likely to be an indicator of attack.
> Do not set `failMixedResults` to `false` unless you have a specific need to allow this, and you understand the risks of doing so.

## Other configuration parameters

The typical configuration parameters you would use in a handler, `automaticDecompression`, `allowAutoRedirect`, and
`sslOptions` are present. Both `allowAutoRedirect`, and `sslOptions` can introduce vulnerabilities if used, do
not use them unless you must. For instructions on using a proxy see [Using Proxies](usingProxies.md).

> [!Tip]
> Each of the configuration parameters has an equivalent property on the `SsrfOptions` class,
> so you can also configure the handler by creating an instance of `SsrfOptions` and passing it to
> `SsrfSocketsHttpHandlerFactory.Create` method or the constructor on `ProxiedSsrfDelegatingHandler`.
> 
> This can be useful if you want to reuse the same configuration across multiple handlers or
> if you prefer to configure the options separately from the handler creation.
