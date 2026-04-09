# idunno.Security.Ssrf

A .NET library to help mitigate Server Side Request Forgery (SSRF) vulnerabilities in .NET applications that use `HttpClient` or `ClientWebSocket`.

Key Features

* Mitigates common SSRF vulnerabilities in .NET applications that use `HttpClient` or `ClientWebSocket`.
* Supports both IPv4 and IPv6 addresses.
* Allows for extra IP ranges and addresses to be added to the default block list.

## Getting Started

Add the `idunno.Security.Ssrf` package to your project, and then when you create an `HttpClient` and add an instance of the handler
to the message handler pipeline.

```c#
using (var httpClient = new HttpClient(SsrfSocketsHttpHandlerFactory.Create()))
{
    _ = await httpClient.GetAsync(new Uri("bad.ssl.fail")).ConfigureAwait(false);
}
```

If you want to protect a `ClientWebSocket` you can pass a an instance of the handler in as the invoker parameter of
`ConnectAsync();`.

```c#

using (var clientWebSocket = new ClientWebSocket())
using (var httpClient = new HttpClient(SsrfSocketsHttpHandlerFactory.Create()))
{
    await clientWebSocket.ConnectAsync(
        uri: new Uri("wss://echo.websocket.org"),
        invoker: httpClient);
}
```

If the SSRF handler encounters anything unsafe it will throw an `SsrfException`.

Please see the full [README](https://github.com/blowdart/idunno.Security.Ssrf/blob/main/readme.md) and the
[documentation](https://ssrf.idunno.dev/) for more details

The [CHANGELOG](https://github.com/blowdart/idunno.Security.Ssrf/blob/main/CHANGELOG.md) has a full a list of changes in each version.
