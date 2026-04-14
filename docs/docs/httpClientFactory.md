# Using with HttpClientFactory

To add SSRF protection to an `HttpClient` created with `HttpClientFactory` set the primary `HttpMessageHandler`. For example,

```csharp
var builder = WebApplication.CreateBuilder(args);

// ...

builder.Services.AddHttpClient();
builder.Services.ConfigureHttpClientDefaults(configure =>
    configure.ConfigurePrimaryHttpMessageHandler(() => SsrfSocketsHttpHandlerFactory.Create())
);
```

This configures all `HttpClient` instances created by the factory to use a `SocketsHttpHandler` with SSRF protection.
You can also configure individual named or typed clients to use the SSRF-protected handler as needed.
