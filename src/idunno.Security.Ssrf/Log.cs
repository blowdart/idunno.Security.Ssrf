// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;
using Microsoft.Extensions.Logging;

namespace idunno.Security;

internal static partial class Log
{
    [LoggerMessage(EventId = 1, Level = LogLevel.Warning, Message = "Connection to {uri} blocked as it evaluated as unsafe.")]
    public static partial void UnsafeUri(ILogger logger, Uri uri);

    [LoggerMessage(EventId = 2, Level = LogLevel.Error, Message = "DNS resolution for {uri} threw an exception")]
    public static partial void DnsResolutionException(ILogger logger, Uri uri, Exception ex);

    [LoggerMessage(EventId = 3, Level = LogLevel.Error, Message = "{uri} could not be resolved to an IP address.")]
    public static partial void DnsResolutionFailed(ILogger logger, Uri uri);

    [LoggerMessage(EventId = 4, Level = LogLevel.Error, Message = "{uri} is unreachable")]
    public static partial void HostUnreachable(ILogger logger, Uri uri);

    [LoggerMessage(EventId = 5, Level = LogLevel.Warning, Message = "All resolved IP addresses for {uri} are unsafe.")]
    public static partial void AllResolvedIpAddressesUnsafe(ILogger logger, Uri uri);

    [LoggerMessage(EventId = 6, Level = LogLevel.Warning, Message = "Some resolved IP addresses for {uri} are unsafe and failMixedResults is enabled.")]
    public static partial void SomeResolvedIpAddressesUnsafe(ILogger logger, Uri uri);

    [LoggerMessage(EventId = 7, Level = LogLevel.Error, Message = "Connection failed on {ipAddress} for {uri}.")]
    public static partial void ConnectionFailed(ILogger logger, IPAddress ipAddress, Uri uri);
}
