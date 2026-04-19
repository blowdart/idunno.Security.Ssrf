// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;

#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace OpenTelemetry.Metrics;
#pragma warning restore IDE0130 // Namespace does not match folder structure

/// <summary>
/// Extension methods to simplify registering of the instrumentation meters.
/// </summary>
[ExcludeFromCodeCoverage]
public static class SsrfMetricsExtensions
{
    /// <summary>
    ///  Enables the instrumentation data collection for idunno.Security.Ssrf handlers.
    /// </summary>
    /// <param name="builder">The <see cref="MeterProviderBuilder"/> being configured.</param>
    /// <returns>The instance of <see cref="MeterProviderBuilder"/> to chain the calls.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> is <see langword="null"/>.</exception>
    public static MeterProviderBuilder AddSsrfHandlerMetrics(this MeterProviderBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddMeter(idunno.Security.SsrfMetrics.MeterName);
    }
}
