// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;

using idunno.Security;

using DelegatingHttpHandler;

var timingHandler = new TimingHandler()
{
    InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
         connectionStrategy: ConnectionStrategy.None,
         additionalUnsafeNetworks: null,
         additionalUnsafeIpAddresses: null,
         connectTimeout: TimeSpan.FromSeconds(1),
         allowInsecureProtocols: false,
         failMixedResults: true,
         allowAutoRedirect: false,
         automaticDecompression: DecompressionMethods.All,
         proxy: null,
         sslOptions: null,
         loggerFactory: null)
};

using (var httpClient = new HttpClient(timingHandler))
{
    HttpResponseMessage response = await httpClient.GetAsync("https://www.example.com/");
    Console.WriteLine($"Response status code: {response.StatusCode}");
}

timingHandler = new TimingHandler()
{
    InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
         connectionStrategy: ConnectionStrategy.None,
         additionalUnsafeNetworks: null,
         additionalUnsafeIpAddresses: [
             IPAddress.Parse("2606:4700::6812:1b78"),
             IPAddress.Parse("2606:4700::6812:1a78"),
             IPAddress.Parse("104.18.27.120"),
             IPAddress.Parse("104.18.26.120")
         ],
         connectTimeout: TimeSpan.FromSeconds(1),
         allowInsecureProtocols: false,
         failMixedResults: true,
         allowAutoRedirect: false,
         automaticDecompression: DecompressionMethods.All,
         proxy: null,
         sslOptions: null,
         loggerFactory: null)
};

using (var httpClient = new HttpClient(timingHandler))
{
    HttpResponseMessage response = await httpClient.GetAsync("https://www.example.com/");
    Console.WriteLine($"Response status code: {response.StatusCode}");
}
