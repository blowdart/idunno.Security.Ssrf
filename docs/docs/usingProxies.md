# Using Proxy Servers

> [!WARNING]
> Using proxy servers introduces a potential Time of Check Time Of Use (TOCTOU) vulnerability to the SSRF checks.
> Using a proxy hands requests to the proxy which then performs its own name resolution to turn a host name into
> one or more IP addresses. The proxy server may get entirely different resolution results to your application.
>
> It is suggested you do not use a proxy server in production environments, and limit the use of proxy support
> to debugging scenarios with proxies like Fiddler or Burp.

It is not possible to use the `SsrfSocketsHttpHandlerFactory` to produce a handler that uses a proxy server, as
proxy servers may be on a loopback address. A specialist handler, `ProxiedSsrfDelegatingHandler` can be used
to produce a handler which validates outgoing requests, whilst still allowing access to a proxy on a loopback address
and an unsafe `http` protocol automatically.

For example,

```c#
var proxyUri = new Uri("http://127.0.0.1:8866");

var proxiedSsrfDelegatingHandler = new ProxiedSsrfDelegatingHandler(
    proxy: new WebProxy(proxyUri));
using (var httpClient = new HttpClient(proxiedSsrfDelegatingHandler))
{
    var response = await httpClient.GetAsync("https://example.com");
}
```

While `ProxiedSsrfDelegatingHandler`is a delegating handler it sets an `InnerHandler`.
While you can use it in a message handler pipeline, it must be the last handler in
the pipeline.
