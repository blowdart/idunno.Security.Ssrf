using idunno.Security.Ssrf;

using (SocketsHttpHandler ssrfHandler = SecurityHelpers.BuildSSRFHttpHandler())
using (var httpClient = new HttpClient(ssrfHandler))
{
    Console.OutputEncoding = System.Text.Encoding.UTF8;

#pragma warning disable S1075 // URIs should not be hardcoded
    await Test("http://private10_8.ipv4.ssrf.fail").ConfigureAwait(false);
    await Test("http://private172_16_12.ipv4.ssrf.fail").ConfigureAwait(false);
    await Test("http://private192_168_16.ipv4.ssrf.fail").ConfigureAwait(false);
    await Test("http://localhost.ipv4.ssrf.fail").ConfigureAwait(false);
    await Test("http://loopback.ipv4.ssrf.fail").ConfigureAwait(false);
    await Test("http://linklocal.ipv4.ssrf.fail").ConfigureAwait(false);
    await Test("http://cgnat.ipv4.ssrf.fail").ConfigureAwait(false);
    await Test("http://thisnetwork.ipv4.ssrf.fail").ConfigureAwait(false);
    await Test("http://benchmark.ipv4.ssrf.fail").ConfigureAwait(false);
    await Test("http://testnet192_0_2_24.ipv4.ssrf.fail").ConfigureAwait(false);
    await Test("http://testnet198_51_100_24.ipv4.ssrf.fail").ConfigureAwait(false);
    await Test("http://testnet203_0_113_24.ipv4.ssrf.fail").ConfigureAwait(false);
    await Test("http://ietfprotocolassignments.ipv4.ssrf.fail").ConfigureAwait(false);
    await Test("http://multicast.ipv4.ssrf.fail").ConfigureAwait(false);
    await Test("http://reserved.ipv4.ssrf.fail").ConfigureAwait(false);
    await Test("http://broadcast.ipv4.ssrf.fail").ConfigureAwait(false);

    await Test("http://cloudmetadata.ipv4.ssrf.fail").ConfigureAwait(false);

    await Test("http://private.ipv4.ssrf.fail").ConfigureAwait(false);
    await Test("http://testnet.ipv4.ssrf.fail").ConfigureAwait(false);

    await Test("http://good.ipv4.ssrf.fail").ConfigureAwait(false);
    await Test("http://mixed.ipv4.ssrf.fail").ConfigureAwait(false);
    await Test("http://bad.ipv4.ssrf.fail").ConfigureAwait(false);
    await Test("http://linklocal.ipv6.ssrf.fail").ConfigureAwait(false);
    await Test("http://documentation.ipv6.ssrf.fail").ConfigureAwait(false);
    await Test("http://ietfprotocolassignments.ipv6.ssrf.fail").ConfigureAwait(false);

    await Test("http://good.ipv6.ssrf.fail").ConfigureAwait(false);
    await Test("http://mixed.ipv6.ssrf.fail").ConfigureAwait(false);
    await Test("http://bad.ipv6.ssrf.fail").ConfigureAwait(false);

    await Test("http://good.ssrf.fail").ConfigureAwait(false);
    await Test("http://mixed.ssrf.fail").ConfigureAwait(false);
    await Test("http://bad.ssrf.fail").ConfigureAwait(false);
#pragma warning restore S1075 // URIs should not be hardcoded
}

static async Task Test(string uri)
{
    bool exceptionThrown = false;
    string errorMessage = string.Empty;

    using (var httpClient = new HttpClient(SecurityHelpers.BuildSSRFHttpHandler()))
    {
#pragma warning disable CA1031 // Do not catch general exception types
        try
        {
            _ = await httpClient.GetAsync(new Uri(uri)).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            if (ex.InnerException is null)
            {
                errorMessage = ex.Message;
            }
            else
            {
                errorMessage = ex.InnerException.Message;
            }
            exceptionThrown = true;
        }
#pragma warning restore CA1031 // Do not catch general exception types
    }

    if (!exceptionThrown)
    {
        Console.WriteLine($" ✅ {uri}");
    }
    else
    {
        Console.WriteLine($" ❌ {uri} - Error: {errorMessage}");
    }
}
