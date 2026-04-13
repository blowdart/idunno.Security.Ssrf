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

timingHandler = new TimingHandler()
{
    InnerHandler = SsrfSocketsHttpHandlerFactory.Create(
         additionalUnsafeIPAddresses: [
             IPAddress.Parse("2606:4700::6812:1b78"),
             IPAddress.Parse("2606:4700::6812:1a78"),
             IPAddress.Parse("104.18.27.120"),
             IPAddress.Parse("104.18.26.120")
         ],
         connectTimeout: TimeSpan.FromSeconds(1))
};

using (var httpClient = new HttpClient(timingHandler))
{
    HttpResponseMessage response = await httpClient.GetAsync("https://www.example.com/");
    Console.WriteLine($"Response status code: {response.StatusCode}");
}
