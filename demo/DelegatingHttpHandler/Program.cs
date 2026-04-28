// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;

using idunno.Security;

using DelegatingHttpHandler;

var timingHandler = new TimingHandler()
{
    InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
         connectTimeout: TimeSpan.FromSeconds(1))
};

using (var httpClient = new HttpClient(timingHandler))
{
    HttpResponseMessage response = await httpClient.GetAsync("https://www.example.com/");
    Console.WriteLine($"Response status code: {response.StatusCode}");
}

Console.WriteLine();

IPAddress[] exampleComIPs = await Dns.GetHostAddressesAsync("www.example.com");

timingHandler = new TimingHandler()
{
    InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
         additionalUnsafeIPAddresses: exampleComIPs,
         connectTimeout: TimeSpan.FromSeconds(1))
};

using (var httpClient = new HttpClient(timingHandler))
{
    HttpResponseMessage response = await httpClient.GetAsync("https://www.example.com/");
    Console.WriteLine($"Response status code: {response.StatusCode}");
}
