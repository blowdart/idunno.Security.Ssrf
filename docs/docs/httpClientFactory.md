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

For example, if you want to special case loopback connections as you are using an MCP server you might to the following

```csharp
builder.Services.AddHttpClient("mcpClient")
  .ConfigurePrimaryHttpMessageHandler(() =>
    SsrfSocketsHttpHandlerFactory.Create(
      allowedSchemes: ["https", "http"],
      allowLoopback: true)
);
```

Then to use the named client, you can inject an `IHttpClientFactory` and call `CreateClient` with the name of the client you want to use.
```csharp
var client = httpClientFactory.CreateClient("mcpClient");
```

This client will use the settings specific set during its addition, allowing http connections and loopback connections in this example.

The ASP.NET documentation has more details on [HTTP Client Factory](https://learn.microsoft.com/en-us/dotnet/core/extensions/httpclient-factory).
