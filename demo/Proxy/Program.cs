// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;
using System.Net.WebSockets;
using System.Text;

using idunno.Security;
using Microsoft.Extensions.Logging;

Console.OutputEncoding = Encoding.UTF8;
ILoggerFactory? loggerFactory = null;

// Uncomment the following lines to enable logging to the console.
//loggerFactory = LoggerFactory.Create(configure =>
//{
//    configure.AddSimpleConsole(options =>
//    {
//        options.IncludeScopes = true;
//        options.TimestampFormat = "G";
//        options.UseUtcTimestamp = false;
//    });
//    configure.SetMinimumLevel(LogLevel.Debug);
//});

var proxyUri = new Uri("http://127.0.0.1:8866");

var proxiedSsrfDelegatingHandler = new ProxiedSsrfDelegatingHandler(
    proxy: new WebProxy(proxyUri),
    connectionStrategy: ConnectionStrategy.None,
    additionalUnsafeIPNetworks: null,
    additionalUnsafeIPAddresses: null,
    allowedHostnames: null,
    connectTimeout: TimeSpan.FromSeconds(1),
    allowInsecureProtocols: false,
    allowLoopback: false,
    failMixedResults: true,
    allowAutoRedirect: false,
    automaticDecompression: DecompressionMethods.All,
    sslOptions: null,
    loggerFactory: loggerFactory);

Console.WriteLine($"Start proxy running on {proxyUri} and press Enter to continue");
Console.ReadLine();
Console.Clear();

#pragma warning disable CA1303 // Do not pass literals as localized parameters
using (var httpClient = new HttpClient(proxiedSsrfDelegatingHandler, disposeHandler: false))
{
    Console.WriteLine($"Making requests through the {proxyUri}...");
    Console.WriteLine();


    Uri destinationUri = new("https://www.example.com/");
    Console.WriteLine($"Request to {destinationUri} will succeed as it is an allowed protocol and safe destination.");
    HttpResponseMessage response = await httpClient.GetAsync(destinationUri);
    Console.WriteLine($"Response status code: {response.StatusCode}");

    Console.WriteLine();

    // This request will be blocked by the SSRF protection as it is not an allowed protocol.
    try
    {
        destinationUri = new("http://localhost:9999");
        Console.WriteLine($"Request to {destinationUri} will fail as it is an unsafe protocol.");
        response = await httpClient.GetAsync(destinationUri);
        Console.WriteLine($"Response status code: {response.StatusCode}");
    }
    catch (SsrfException ex)
    {
        Console.WriteLine($"{ex.GetType().Name}: {ex.Message}");
    }

    Console.WriteLine();

    // This request will be blocked by the SSRF protection as it a default dangerous destination.
    try
    {
        destinationUri = new("https://localhost:9999");
        Console.WriteLine($"Request to {destinationUri} will fail as it is a default dangerous destination.");
        response = await httpClient.GetAsync(destinationUri);
        Console.WriteLine($"Response status code: {response.StatusCode}");
    }
    catch (SsrfException ex)
    {
        Console.WriteLine($"{ex.GetType().Name}: {ex.Message}");
    }

    Console.WriteLine();

    // This request will be blocked by the SSRF protection as it a default dangerous destination.
    try
    {
        destinationUri = new("https://10.0.0.1");
        Console.WriteLine($"Request to {destinationUri} will fail as it is a default dangerous destination.");
        response = await httpClient.GetAsync(destinationUri);
        Console.WriteLine($"Response status code: {response.StatusCode}");
    }
    catch (SsrfException ex)
    {
        Console.WriteLine($"{ex.GetType().Name}: {ex.Message}");
    }

    Console.WriteLine();

    // This request will be blocked by the SSRF protection as the URI resolves to dangerous IP addresses.
    try
    {
        destinationUri = new("https://bad.ssrf.fail");
        Console.WriteLine($"Request to {destinationUri} will fail as it resolves to dangerous IP addresses.");
        response = await httpClient.GetAsync(destinationUri);
        Console.WriteLine($"Response status code: {response.StatusCode}");
    }
    catch (SsrfException ex)
    {
        Console.WriteLine($"{ex.GetType().Name}: {ex.Message}");
    }

    Console.WriteLine();
}

using (var clientWebSocket = new ClientWebSocket())
using (var invoker = new HttpClient(proxiedSsrfDelegatingHandler, disposeHandler: false))
{
    Uri destinationUri = new("wss://echo.websocket.org");
    Console.WriteLine($"WebSocket request to {destinationUri} will succeed as it is an allowed protocol and safe destination.");
    try
    {
        await clientWebSocket.ConnectAsync(
            uri: destinationUri,
            invoker: invoker,
            cancellationToken: CancellationToken.None);

        byte[] connectionMessage = new byte[1024];
        // Disregard the Request Served Bye response upon connection.
        await clientWebSocket.ReceiveAsync(new ArraySegment<byte>(connectionMessage), CancellationToken.None).ConfigureAwait(false);

        byte[] outgoingMessage = Encoding.ASCII.GetBytes("hello");
        await clientWebSocket.SendAsync(new ArraySegment<byte>(outgoingMessage), WebSocketMessageType.Text, true, CancellationToken.None).ConfigureAwait(false);

        byte[] incomingMessage = new byte[1024];
        await clientWebSocket.ReceiveAsync(new ArraySegment<byte>(incomingMessage), CancellationToken.None).ConfigureAwait(false);

        await clientWebSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
        Console.WriteLine($"Received: {Encoding.ASCII.GetString(incomingMessage)}");
    }
    catch (SsrfException ex)
    {
        Console.WriteLine($"{ex.GetType().Name}: {ex.Message}");
    }
}

Console.WriteLine();

using (var clientWebSocket = new ClientWebSocket())
using (var invoker = new HttpClient(proxiedSsrfDelegatingHandler))
{
    Uri destinationUri = new("ws://localhost:9999");
    Console.WriteLine($"WebSocket request to {destinationUri} will fail as it is an unsafe protocol.");
    try
    {
        await clientWebSocket.ConnectAsync(
            uri: destinationUri,
            invoker: invoker,
            cancellationToken: CancellationToken.None);

        Console.WriteLine("WebSocket connection established.");
    }
    catch (WebSocketException ex)
    {
        Console.WriteLine($"{ex.GetType().Name}: {ex.Message}");

        int indent = 0;

        Exception? exception = ex;
        while (exception?.InnerException is not null)
        {
            Console.Write(new string(' ', indent));
            Console.WriteLine($"↳ {exception.InnerException.GetType().Name}: {exception.InnerException.Message}");
            exception = exception.InnerException;
            indent += 2;
        }
    }
    catch (SsrfException ex)
    {
        Console.WriteLine($"{ex.GetType().Name}: {ex.Message}");
    }
}

Console.WriteLine();

var allowMixedSsrfHostValidationHandler = new ProxiedSsrfDelegatingHandler(
    connectionStrategy: ConnectionStrategy.None,
    additionalUnsafeIPNetworks: null,
    additionalUnsafeIPAddresses: null,
    allowedHostnames: null,
    connectTimeout: TimeSpan.FromSeconds(1),
    allowInsecureProtocols: true, // Must allow insecure protocols for the proxy itself to work.
    allowLoopback: true, // Must allow loopback for the proxy itself to work.
    failMixedResults: false,
    allowAutoRedirect: false,
    automaticDecompression: DecompressionMethods.All,
    proxy: new WebProxy(proxyUri),
    sslOptions: null,
    loggerFactory: loggerFactory);
using (var httpClient = new HttpClient(allowMixedSsrfHostValidationHandler))
{
    Uri destinationUri = new("http://mixed.ssrf.fail");
    Console.WriteLine($"Request to {destinationUri} will fail, but not with an SSRF error, as it is an allowed protocol and has at least one safe IP address.");
    try
    {
        HttpResponseMessage response = await httpClient.GetAsync(destinationUri);
        Console.WriteLine($"Response status code: {response.StatusCode}");
    }
    catch (HttpRequestException ex)
    {
        Console.WriteLine($"{ex.GetType().Name}: {ex.Message}");
    }
}

#pragma warning restore CA1303 // Do not pass literals as localized parameters
