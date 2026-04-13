# Metrics Reference

This is a reference for metrics produced by `idunno.Security.Ssrf`, using the [System.Diagnostics.Metrics](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.metric) API.

> [!TIP]
> For more information about how to collect and report these metrics, see the .NET documentation
> [Collecting metrics](https://learn.microsoft.com/en-us/dotnet/core/diagnostics/metrics-collection).
>
> During development you can use the [dotnet-counters](https://learn.microsoft.com/en-us/dotnet/core/diagnostics/dotnet-counters) tool to
> observe these metrics in real time. e.g.
>
> ```c#
> dotnet-counters monitor --process-id <pid> --counters idunno.Security.Ssrf
> ```
>
> For production environments, you can use a variety of exporters to send these metrics to monitoring systems
> like Aspire, Prometheus, Grafana, or Azure Monitor.

## idunno.Security.Ssrf

The `idunno.Security.Ssrf` Meter reports measures from the `idunno.Security.Ssrf` library.

### Metric : blocked.requests.total

| Name | Instrument Type | Unit | Description |
| --- | --- | --- | --- |
| `blocked.requests.total` | Counter&lt;long&gt; | Requests | Total number of outgoing requests blocked. |

### Metric : unsafe.uri.total

| Name | Instrument Type | Unit | Description |
| --- | --- | --- | --- |
| `unsafe.uri.total` | Counter&lt;long&gt; | URIs | Total number of unsafe URIs detected. |

### Metric : unsafe.ip_address.total

| Name | Instrument Type | Unit | Description |
| --- | --- | --- | --- |
| `unsafe.ip_address.total` | Counter&lt;long&gt; | IP Addresses | Total number of unsafe IP addresses detected. |
