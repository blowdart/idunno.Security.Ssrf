// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;

using idunno.Security;

var proxyUri = new Uri("http://127.0.0.1:8866");

var ssrfHostValidationHandler = new DebugSsrfHostValidationHandler(
    allowInsecureProtocols: false,
    allowLoopback: false,
    failMixedResults: true)
{
    InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
         connectionStrategy: ConnectionStrategy.None,
         additionalUnsafeNetworks: null,
         additionalUnsafeIpAddresses: null,
         connectTimeout: TimeSpan.FromSeconds(1),
         allowInsecureProtocols: true, // Must allow insecure protocols for the proxy itself to work.
         allowLoopback: true, // Must allow loopback for the proxy itself to work.
         failMixedResults: true,
         allowAutoRedirect: false,
         automaticDecompression: DecompressionMethods.All,
         proxy: new WebProxy(proxyUri),
         sslOptions: null,
         loggerFactory: null)
};

Console.WriteLine($"Start proxy running on {proxyUri} and press Enter to continue");
Console.ReadLine();

using (var httpClient = new HttpClient(ssrfHostValidationHandler))
{
#pragma warning disable CA1303 // Do not pass literals as localized parameters
    Console.WriteLine("Making requests through the proxy...");

    Uri destinationUri = new ("https://www.example.com/");
    Console.WriteLine($"Request to {destinationUri} will succeed as it is an allowed protocol and safe destination.");
    HttpResponseMessage response = await httpClient.GetAsync(destinationUri);
    Console.WriteLine($"Response status code: {response.StatusCode}");

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
        Console.WriteLine(ex.Message );
    }

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
        Console.WriteLine(ex.Message);
    }

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
        Console.WriteLine(ex.Message);
    }

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
        Console.WriteLine(ex.Message);
    }
#pragma warning restore CA1303 // Do not pass literals as localized parameters
}

