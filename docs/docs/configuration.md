# Configurating the handler

## Adding extra unsafe IP Networks and addresses

You may have some extra unsafe endpoints within your infrastructure which, for whatever reason are not within the
[default unsafe IP ranges](https://github.com/blowdart/idunno.Security.Ssrf/blob/main/src/idunno.Security.Ssrf/Ssrf.cs#L16).

When building the handler you can use the optional `additionalUnsafeNetworks` and `additionalUnsafeIpAddresses` to
add to the built-in unsafe lists. For example

```c#
using (var httpClient = new HttpClient(
    SsrfSocketsHttpHanderFactory.Create(
        additionalUnsafeNetworks: :
        [
            IPNetwork.Parse("104.16.0.0/12"),
            IPNetwork.Parse("2620:1ec::/36")
        ],
        additionalUnsafeIpAddresses:
        [
            IPAddress.Parse("2606:4700::6812:1b78"),
            IPAddress.Parse("104.18.26.120)
        ])))
{
    HttpResponseMessage response = await httpClient.GetAsync(
        new Uri("https://example.com"));
}
```

## Allowing HTTP and WS URIs

You may have some `http` or `ws` URIs you need to access. You can mark those protocols as safe using the
`allowInsecureProtocols` parameter.

## Allowing loopback connections

You have have a need for your application to talk to itself, or another application on a different port on the loopback
addresses. You can allow this using the `allowLoopback` parameter.

## Connection strategies

If a host resolves to multiple IP addresses you can choose the strategy used to pick one from the list of
safe IP addresses using the `connectionStrategy` parameter. There are four flags to choose from,

* `None` - the default connection strategy that tries each IP in the order the resolution presented them,
* `Ipv4Preferred` - try IPv4 addresses first, before IPv6 addresses, this is mutually exclusive from `Ipv6Preferred`
* `Ipv6Preferred` - try IPv6 addresses first, before IPv4 addresses, this is mutually exclusive from `Ipv4Preferred`
* `Random` - shuffle the returned IP addresses randomly, before connecting. This can be combined with Ipv4Preferred` and `Ipv6Preferred`.

## Allowing mixed results

If you have a truly weird setup you may wish to allow a connection to continue if the IP address list returned
during name resolution returns a mixture of safe and unsafe IP addresses. If you set the `allowInsecureProtocols`
parameter to `true` all unsafe addresses will be removed form the potential connection list, and, if any safe IP addresses
remain a connection will be attempted to each. Such a strange DNS setup could be an indicator of attack, so use
this option with care, as it may introduce an SSRF vulnerability.

## Other configuration parameters

The typical configuration parameters you would use in a handler, `automaticDecompression`, `allowAutoRedirect`, and
`sslOptions` are present. Both `allowAutoRedirect`, and `sslOptions` can introduce vulnerabilities if used, do
not use them unless you must. For instructions on using a proxy see [Using Proxies](usingProxies.md).
