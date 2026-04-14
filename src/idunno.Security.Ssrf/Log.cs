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

    [LoggerMessage(EventId = 7, Level = LogLevel.Debug, Message = "IP address checks for {uri} bypassed as it matches an entry in the allowed hostnames list.")]
    public static partial void ChecksBypassedForAllowedHostnames(ILogger logger, Uri uri);

    [LoggerMessage(EventId = 8, Level = LogLevel.Debug, Message = "{ipAddress} allowed for {uri} bypassed as it is within a network in the safe network collection.")]
    public static partial void CheckBypassedForIPAddressAsItIsInSafeNetwork(ILogger logger, Uri uri, IPAddress ipAddress);

    [LoggerMessage(EventId = 9, Level = LogLevel.Debug, Message = "{ipAddress} allowed for {uri} bypassed as it is included in the safe IP address collection.")]
    public static partial void CheckBypassedForIPAddressAsItIsInSafeIpAddresses(ILogger logger, Uri uri, IPAddress ipAddress);
}
