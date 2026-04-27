# Using Proxy Servers

> [!WARNING]
> Using proxy servers introduces a potential Time of Check Time Of Use (TOCTOU) vulnerability to the SSRF checks.
> Using a proxy hands requests to the proxy which then performs its own name resolution to turn a host name into
> one or more IP addresses. The proxy server may get entirely different resolution results to your application.
>
> It is strongly suggested you do not use a proxy server in production environments, and limit the use of proxy support
> to debugging scenarios with proxies like Fiddler or Burp.

When using a web proxy a specialist handler, `ProxiedSsrfDelegatingHandler`, and, optionally its
`ProxiedSsrfOptions` options class must be used
to produce a handler which validates outgoing requests, whilst still allowing access to a proxy on, potentially
a loopback address and, or with an unsafe `http` protocol. The `ProxiedSsrfDelegatingHandler` safelists calls
to the configured proxy.

To use `ProxiedSsrfDelegatingHandler` create an instance of the handler,
passing in a `WebProxy` instance configured with the proxy you want to use. For example,

```c#
var proxyUri = new Uri("http://127.0.0.1:8866");

var proxiedSsrfDelegatingHandler = new ProxiedSsrfDelegatingHandler(
    proxy: new WebProxy(proxyUri));
using (var httpClient = new HttpClient(proxiedSsrfDelegatingHandler))
{
    var response = await httpClient.GetAsync("https://example.com");
}
```

While `ProxiedSsrfDelegatingHandler` is a delegating handler it sets an `InnerHandler`.
You can use it in a message handler pipeline, however it must be the last handler in
the pipeline.
