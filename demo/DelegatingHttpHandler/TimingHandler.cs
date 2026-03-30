// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

namespace DelegatingHttpHandler;

internal class TimingHandler : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        DateTime start = DateTime.UtcNow;
        HttpResponseMessage response = await base.SendAsync(request, cancellationToken);
        TimeSpan elapsed = DateTime.UtcNow - start;
        Console.WriteLine($"Elapsed time: {elapsed}");
        return response;
    }
}
