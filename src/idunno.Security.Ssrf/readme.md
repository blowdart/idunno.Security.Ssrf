# idunno.Security.Ssrf

A .NET library to help mitigate Server Side Request Forgery (SSRF) vulnerabilities in .NET applications that use `HttpClient` or `ClientWebSocket`.

Key Features

* Mitigates common SSRF vulnerabilities in .NET applications that use `HttpClient` or `ClientWebSocket`.
* Supports both IPv4 and IPv6 addresses, including loopback, link-local, and private address ranges.
* Allows for extra IP ranges to be added to the default block list.

## Getting Started

Add the `idunno.Security.Ssrf` package to your project, and then when you create an `HttpClient` and add an instance of the handler
to the message handler pipeline.

```c#
using (var httpClient = new HttpClient(idunno.Security.SsrfSocketsHttpHanderFactory.Create()))   
{
    _ = await httpClient.GetAsync(new Uri("bad.ssl.fail")).ConfigureAwait(false);
}
```

If you want to protect a `ClientWebSocket` you can pass a an instance of the handler in as the invoker parameter of
`ConnectAsync(Uri uri, System.Net.Http.HttpMessageInvoker? invoker, System.Threading.CancellationToken cancellationToken);`.

```c#

using (var webSocket = new ClientWebSock())
using (var httpClient = new HttpClient(idunno.Security.SsrfSocketsHttpHanderFactory.Create()))
{
    await _client.ConnectAsync(
        uri: "wss://echo.websocket.org",
        invoker: httpClient);
}
```

If the SSRF check finds an unsafe host, or a host that resolves to an unsafe address it will throw an `SsrfException`.
Depending on where the exception it thrown, and the type of client it will end up as the `InnerException` on the
`HttpRequestException`, `SocketException` or `WebSocketException` thrown by the client.

Please see the full [README](https://github.com/blowdart/idunno.Security.Ssrf/blob/main/readme.md) for more details on how to use
this nupkg.

The [CHANGELOG](https://github.com/blowdart/idunno.Security.Ssrf/blob/main/CHANGELOG.md) has a full a list of changes in each version.
