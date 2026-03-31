// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;
using System.Net.Security;
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

#pragma warning disable S1075 // URIs should not be hardcoded
#pragma warning disable CA1303 // Do not pass literals as localized parameters

Console.WriteLine();
Console.WriteLine("HttpClient Tests (allowInsecureProtocols = true)");
Console.WriteLine("------------------------------------------------");
await TestWithHttpClient("http://private10_8.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("http://private172_16_12.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("http://private192_168_16.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("http://localhost.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("http://loopback.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("http://linklocal.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("http://cgnat.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("http://thisnetwork.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("http://benchmark.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("http://testnet192_0_2_24.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("http://testnet198_51_100_24.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("http://testnet203_0_113_24.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("http://ietfprotocolassignments.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("http://multicast.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("http://reserved.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("http://broadcast.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);

await TestWithHttpClient("http://cloudmetadata.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);

await TestWithHttpClient("http://private.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("http://testnet.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);

await TestWithHttpClient("http://linklocal.ipv6.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("http://documentation.ipv6.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("http://ietfprotocolassignments.ipv6.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
Console.WriteLine();
Console.WriteLine("IPv4");
Console.WriteLine("----");

await TestWithHttpClient("https://good.ipv4.ssrf.fail", loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("https://mixed.ipv4.ssrf.fail", loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("https://bad.ipv4.ssrf.fail", loggerFactory: loggerFactory).ConfigureAwait(false);

Console.WriteLine();
Console.WriteLine("failMixedResults = false");
Console.WriteLine("------------------------");

await TestWithHttpClient("https://good.ipv4.ssrf.fail", failMixedResults: false, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("https://mixed.ipv4.ssrf.fail", failMixedResults: false, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("https://bad.ipv4.ssrf.fail", failMixedResults: false, loggerFactory: loggerFactory).ConfigureAwait(false);

Console.WriteLine();
Console.WriteLine("allowInsecureProtocols = true");
Console.WriteLine("-----------------------------");

await TestWithHttpClient("http://good.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("http://mixed.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("http://bad.ipv4.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);

Console.WriteLine();
Console.WriteLine("IPv6");
Console.WriteLine("----");

await TestWithHttpClient("https://good.ipv6.ssrf.fail", loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("https://mixed.ipv6.ssrf.fail", loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("https://bad.ipv6.ssrf.fail", loggerFactory: loggerFactory).ConfigureAwait(false);

Console.WriteLine();
Console.WriteLine("allowInsecureProtocols = true");
Console.WriteLine("-----------------------------");

await TestWithHttpClient("https://good.ipv6.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("https://mixed.ipv6.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("https://bad.ipv6.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);

Console.WriteLine();
Console.WriteLine("Mixed");
Console.WriteLine("-----");

await TestWithHttpClient("https://good.ssrf.fail", loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("https://mixed.ssrf.fail", loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("https://bad.ssrf.fail", loggerFactory: loggerFactory).ConfigureAwait(false);

Console.WriteLine();
Console.WriteLine("failMixedResults = false");
Console.WriteLine("------------------------");

await TestWithHttpClient("https://good.ssrf.fail", failMixedResults: false, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("https://mixed.ssrf.fail", failMixedResults: false, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithHttpClient("https://bad.ssrf.fail", failMixedResults: false, loggerFactory: loggerFactory).ConfigureAwait(false);

Console.WriteLine();
Console.WriteLine("ClientWebSocket Tests");
await TestWithClientWebSocket("wss://echo.websocket.org", loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithClientWebSocket("ws://echo.websocket.org", loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithClientWebSocket("wss://good.ssrf.fail", loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithClientWebSocket("wss://mixed.ssrf.fail", loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithClientWebSocket("wss://bad.ssrf.fail", loggerFactory: loggerFactory).ConfigureAwait(false);

Console.WriteLine();
Console.WriteLine("AllowInsecureProtocols=true");
Console.WriteLine("---------------------------");
await TestWithClientWebSocket("ws://echo.websocket.org", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithClientWebSocket("ws://good.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithClientWebSocket("ws://mixed.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);
await TestWithClientWebSocket("ws://bad.ssrf.fail", allowInsecureProtocols: true, loggerFactory: loggerFactory).ConfigureAwait(false);


#pragma warning restore CA1303 // Do not pass literals as localized parameters
#pragma warning restore S1075 // URIs should not be hardcoded

static async Task TestWithHttpClient(string uri, bool allowInsecureProtocols = false, bool failMixedResults = true, ILoggerFactory? loggerFactory = null)
{
    bool exceptionThrown = false;
    string errorMessage = string.Empty;

    using (var httpClient = new HttpClient(
        SsrfSocketsHttpHandlerFactory.Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: TimeSpan.FromSeconds(1),
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: false,
            failMixedResults: failMixedResults,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: null,
            sslOptions: new SslClientAuthenticationOptions()
            {
                // Ignore SSL errors since some of the test URLs have invalid certificates. Do not do this in production code.
                RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true
            },
            loggerFactory: loggerFactory)))
    {
        try
        {
            _ = await httpClient.GetAsync(new Uri(uri)).ConfigureAwait(false);
        }
        catch (SsrfException ex)
        {
            if (ex.InnerException is null)
            {
                errorMessage = $"{ex.GetType().Name}: {ex.Uri} {ex.Message}";
            }
            else
            {
                errorMessage = $"{ex.GetType().Name} => {ex.InnerException.GetType().Name}: {ex.InnerException.Message}";
            }
            exceptionThrown = true;
        }
        catch (HttpRequestException ex)
        {
            if (ex.InnerException is null)
            {
                errorMessage = $"{ex.GetType().Name}: {ex.Message}";
            }
            else
            {
                if (ex.InnerException is SsrfException ssrfException)
                {
                    errorMessage = $"{ssrfException.GetType().Name}: {ssrfException.Message} ({ssrfException.Uri})";
                }
                else
                {
                    errorMessage = $"{ex.GetType().Name} => {ex.InnerException.GetType().Name}: {ex.InnerException.Message}";
                }
            }
            exceptionThrown = true;
        }
        catch (TaskCanceledException ex)
        {
            if (ex.InnerException is TimeoutException)
            {
            }
            else if (ex.InnerException is null)
            {
                errorMessage = $"{ex.GetType().Name}: {ex.Message}";
                exceptionThrown = true;
            }
            else
            {
                errorMessage = $"{ex.GetType().Name} => {ex.InnerException.GetType().Name}: {ex.InnerException.Message}";
                exceptionThrown = true;
            }
        }
    }

    if (!exceptionThrown)
    {
        Console.WriteLine($" ✅ {uri}");
    }
    else
    {
        Console.WriteLine($" ❌ {uri} - {errorMessage}");
    }
}

static async Task TestWithClientWebSocket(string uri, bool allowInsecureProtocols = false, bool failMixedResults = true, ILoggerFactory? loggerFactory = null)
{
    bool exceptionThrown = false;
    string errorMessage = string.Empty;

    using (var clientWebSocket = new ClientWebSocket())
    using (var invoker = new HttpClient(SsrfSocketsHttpHandlerFactory.Create(
            connectionStrategy: ConnectionStrategy.None,
            additionalUnsafeNetworks: null,
            additionalUnsafeIpAddresses: null,
            connectTimeout: TimeSpan.FromSeconds(3),
            allowInsecureProtocols: allowInsecureProtocols,
            allowLoopback: false,
            failMixedResults: failMixedResults,
            allowAutoRedirect: false,
            automaticDecompression: DecompressionMethods.All,
            proxy: null,
            sslOptions: new SslClientAuthenticationOptions()
            {
                // Ignore SSL errors since some of the test URLs have invalid certificates. Do not do this in production code.
                RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true
            },
            loggerFactory: loggerFactory)))
    {
        try
        {
            await clientWebSocket.ConnectAsync(new Uri(uri), invoker, CancellationToken.None);

            byte[] outgoingMessage = Encoding.ASCII.GetBytes("hello");
            await clientWebSocket.SendAsync(new ArraySegment<byte>(outgoingMessage), WebSocketMessageType.Text, true, CancellationToken.None).ConfigureAwait(false);

            byte[] incomingMessage = new byte[1024];
            await clientWebSocket.ReceiveAsync(new ArraySegment<byte>(incomingMessage), CancellationToken.None).ConfigureAwait(false);

            await clientWebSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
        }
        catch (SsrfException ex)
        {
            if (ex.InnerException is null)
            {
                errorMessage = $"{ex.GetType().Name}: {ex.Uri} {ex.Message}";
            }
            else
            {
                errorMessage = $"{ex.InnerException.GetType().Name}: {ex.InnerException.Message}";
            }
            exceptionThrown = true;
        }
        catch (HttpRequestException ex)
        {
            if (ex.InnerException is null)
            {
                errorMessage = $"{ex.GetType().Name}: {ex.Message}";
            }
            else
            {
                errorMessage = $"{ex.GetType().Name} => {ex.InnerException.GetType().Name}: {ex.InnerException.Message}";
            }
            exceptionThrown = true;
        }
        catch (WebSocketException ex)
        {
            if (ex.InnerException is null)
            {
                errorMessage = $"{ex.GetType().Name}: {ex.Message}";
                exceptionThrown = true;
            }
            else
            {
                Exception innerException = ex.InnerException;

                while (innerException.InnerException is not null && innerException.InnerException is not SsrfException)
                {
                    innerException = innerException.InnerException;
                }

                errorMessage = $"{ex.GetType().Name} => {innerException.GetType().Name}: {innerException.Message}";

                if (innerException is not SsrfException)
                {
                    exceptionThrown = true;
                    errorMessage = $"{ex.GetType().Name} => {innerException.GetType().Name}: {innerException.Message}";
                }
            }

        }
        catch (TaskCanceledException ex)
        {
            if (ex.InnerException is TimeoutException)
            {
            }
            else if (ex.InnerException is null)
            {
                errorMessage = $"{ex.GetType().Name}: {ex.Message}";
                exceptionThrown = true;
            }
            else
            {
                errorMessage = $"{ex.GetType().Name} => {ex.InnerException.GetType().Name}: {ex.InnerException.Message}";
                exceptionThrown = true;
            }
        }
    }

    if (!exceptionThrown)
    {
        Console.WriteLine($" ✅ {uri}");
    }
    else
    {
        Console.WriteLine($" ❌ {uri} - {errorMessage}");
    }
}

