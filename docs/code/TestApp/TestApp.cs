#!/usr/bin/env dotnet

#:sdk Microsoft.NET.Sdk.Web
#:package idunno.Security.Ssrf@*
#:property PublishAot=false
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using idunno.Security;

Console.OutputEncoding = Encoding.UTF8;

string hostUrl = "http://localhost:3000";

var builder = WebApplication.CreateSlimBuilder(args);
builder.Logging.ClearProviders();
var app = builder.Build();
app.Urls.Add(hostUrl);
app.MapGet("/", async context =>
{
    await context.Response.WriteAsync("Hello World!");
});
await app.StartAsync().ConfigureAwait(false);

Console.Write($"Kestrel listening on ");
foreach (var url in app.Urls)
{
    Console.Write($"{url} ");
}
Console.WriteLine();
Console.WriteLine();

try
{
    using (var client = new HttpClient())
    {
        Console.WriteLine($"Making request to {hostUrl} without the SSRF handler");
        var getResult = await client.GetAsync(hostUrl);
        Console.WriteLine($"Status Code: {getResult.StatusCode}");
    }
}
catch (Exception ex)
{
    var indent = 0;

    Console.WriteLine($"{ex.GetType().Name}: {ex.Message}");

    while (ex.InnerException is not null)
    {
        indent += 2;
        ex = ex.InnerException;

        Console.Write(new string(' ', indent));
        Console.Write($"↳ { ex.GetType().Name} => {ex.Message}");
    }
}

Console.WriteLine();

try
{
    using (var client = new HttpClient(SsrfSocketsHttpHandlerFactory.Create()))
    {
        Console.WriteLine($"Making request to {hostUrl} with the SSRF handler");
        var getResult = await client.GetAsync(hostUrl);
        Console.WriteLine($"Status Code: {getResult.StatusCode}");
    }
}
catch (Exception ex)
{
    var indent = 0;

    Console.WriteLine($"{ex.GetType().Name}: {ex.Message}");

    while (ex.InnerException is not null)
    {
        indent += 2;
        ex = ex.InnerException;

        Console.Write(new string(' ', indent));
        Console.WriteLine($"↳ {ex.GetType().Name} => {ex.Message}");
    }
}

Console.WriteLine();

try
{
    using (var client = new HttpClient(SsrfSocketsHttpHandlerFactory.Create(allowInsecureProtocols: true)))
    {
        Console.WriteLine($"Making request to {hostUrl} with the SSRF handler, allowing insecure protocols");
        var getResult = await client.GetAsync(hostUrl);
        Console.WriteLine($"Status Code: {getResult.StatusCode}");
    }
}
catch (Exception ex)
{
    var indent = 0;

    Console.WriteLine($"{ex.GetType().Name}: {ex.Message}");

    while (ex.InnerException is not null)
    {
        indent += 2;
        ex = ex.InnerException;

        Console.Write(new string(' ', indent));
        Console.WriteLine($"↳ {ex.GetType().Name} => {ex.Message}");
    }
}

Console.WriteLine();

hostUrl = "http://loopback.ssrf.fail:3000";
try
{
    using (var client = new HttpClient(SsrfSocketsHttpHandlerFactory.Create(allowInsecureProtocols: true)))
    {
        Console.WriteLine($"Making request to {hostUrl} with the SSRF handler, allowing insecure protocols");
        var getResult = await client.GetAsync(hostUrl);
        Console.WriteLine($"Status Code: {getResult.StatusCode}");
    }
}
catch (Exception ex)
{
    var indent = 0;

    Console.WriteLine($"{ex.GetType().Name}: {ex.Message}");

    while (ex.InnerException is not null)
    {
        indent += 2;
        ex = ex.InnerException;

        Console.Write(new string(' ', indent));
        Console.WriteLine($"↳ {ex.GetType().Name} => {ex.Message}");
    }
}

await app.StopAsync().ConfigureAwait(false);
