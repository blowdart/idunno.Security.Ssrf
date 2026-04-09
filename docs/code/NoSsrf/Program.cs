// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using idunno.Security;

using (var httpClient = new HttpClient())
{
    var response = await httpClient.GetAsync("https://example.com");
    Console.WriteLine(response.StatusCode);
}

var ssrfHandler = SsrfSocketsHttpHandlerFactory.Create();
using (var httpClient = new HttpClient(ssrfHandler))
{
    var response = await httpClient.GetAsync("https://example.com");
    Console.WriteLine(response.StatusCode);
}

