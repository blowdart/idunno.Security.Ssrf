// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;

namespace idunno.Security;

internal static class Defaults
{
    public static readonly string[] AllowedSchemes = ["https", "wss"];

    public static Func<string, CancellationToken, Task<IPHostEntry>> GetHostEntryAsync { get; } = Dns.GetHostEntryAsync;

    public static Func<string, IPHostEntry> GetHostEntry { get; } = Dns.GetHostEntry;
}
