# idunno.Security.Ssrf

A .NET 8, 9 and 10 library to help mitigate Server Side Request Forgery (SSRF) vulnerabilities in .NET applications that use `HttpClient` or `ClientWebSocket`.

[if you want me to wear 37 pieces of flair, like your pretty boy over there, Brian, why don't you just make the minimum 37 pieces of flair?]: #

[![GitHub License](https://img.shields.io/github/license/blowdart/idunno.Security.Ssrf)](https://github.com/blowdart/idunno.Security.Ssrf/blob/main/LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/blowdart/idunno.Security.Ssrf)](https://github.com/blowdart/idunno.Security.Ssrf/commits/main/)
[![GitHub Tag](https://img.shields.io/github/v/tag/blowdart/idunno.Security.Ssrf)](https://github.com/blowdart/idunno.Security.Ssrf/tags)
[![NuGet Version](https://img.shields.io/nuget/vpre/idunno.Security.Ssrf)](https://www.nuget.org/packages/idunno.Security.Ssrf/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/idunno.Security.Ssrf)](https://www.nuget.org/packages/idunno.Security.Ssrf/)
[![Documentation deployment](https://img.shields.io/github/deployments/blowdart/idunno.Security.Ssrf/github-pages?label=documentation)](https://ssrf.idunno.dev)


## Getting Started

Add the `idunno.Security.Ssrf` package to your project, then, when you create an `HttpClient`
pass an create a handler with `SsrfSocketsHttpHandlerFactory.Create()` and pass it in as
the handler parameter of the `HttpClient` constructor.

```c#
using (var httpClient = new HttpClient(
    SsrfSocketsHttpHandlerFactory.Create(connectTimeout: new TimeSpan(0, 0, 5))))
{
    _ = await httpClient.GetAsync(new Uri("bad.ssl.fail")).ConfigureAwait(false);
}
```

If you want to protect a `ClientWebSocket` create an `HttpClient` with a handler created by `SsrfSocketsHttpHandlerFactory.Create()`,
and pass it in as the `invoker` parameter of the
`ConnectAsync();`.

```c#
using (var clientWebSocket = new ClientWebSocket())
using (var invoker = new HttpClient(
    SsrfSocketsHttpHandlerFactory.Create()))
{
    await clientWebSocket.ConnectAsync(
        uri: new Uri("wss://echo.websocket.org"),
        invoker: invoker);
}
```

If the SSRF handler encounters anything unsafe it will throw an `SsrfException`.

You can read the full documentation at https://ssrf.idunno.dev/

## Key Features

* Mitigates Common SSRF vulnerabilities in .NET applications that use `HttpClient` or `ClientWebSocket`.
* Supports both IPv4 and IPv6 addresses.
* Allows for extra IP ranges and individual addresses to be added to the default block list.

If you want to perform both checks you can use the `IsUnsafe` method, which will check both the URI and the resolved IP addresses.

## What is SSRF / Do I need this?

When an application and an attacker love each other very much ...

A ServerSide Request Forgery (SSRF) vulnerability occurs when an application takes a user-supplied URL and makes a request to that URL without
properly, and continuously validating it.

Imagine an application that takes a user-supplied URL as input and fetches data from it. Everything works fine when the user supplies a URL like `https://example.com/data`,
but what if the user supplies a URL like `http://localhost/admin`? If the application is running on a server that has an admin interface accessible at `http://localhost/admin`,
then the application could potentially access sensitive information and share it with an attacker or allow them
to perform actions on the server that they shouldn't be able to.

It gets worse. If the user supplies a URL like `https://notanattacksite.com` and the URL is validated during
data entry by resolving the IP addresses for the domain and checking against a block list, and marked as safe.
Then later on the DNS entry for `notanattacksite.com` is changed to point to `127.0.0.1` and your application
starts making internal requests. This is called a Time of Check / Time of Use (TOCTOU) vulnerability,
and is a common pitfall when trying to mitigate SSRF vulnerabilities.

In addition the default lists of [known bad IP networks and IP addresses](https://github.com/blowdart/idunnoSecuritySsrf/blob/main/src/idunno.Security.Ssrf/Ssrf.cs#L14) are probably longer than you think.

If you are accepting user input that is used to make outgoing HTTP requests, or WebSocket connections, then you should be
mitigating SSRF vulnerabilities in your application, and this library can help you do that.

## Manual URI and IP checking Helper Methods

If you want to manually check URIs supplied by untrusted you can use the `idunno.Security.Ssrf` class.

```c#
if (Ssrf.IsUnsafeUri(new Uri("https://bad.ssl.fail")))
{
    // Disallow entry of this URI into the system,
    // or log an alert, or whatever you want to do with it.
}
```

If you want to manually check an IP address you can use the `idunno.Security.Ssrf` class.

```c#
if (Ssrf.IsUnsafeIpAddress(IPAddress.Parse("127.0.0.1")))
{
    // Disallow this IP address from being used in the system,
    // or log an alert, or whatever you want to do with it.
}
```



## Current Build Status

[![Build Status](https://github.com/blowdart/idunnoSecuritySsrf/actions/workflows/ci-build.yml/badge.svg?branch=main)](https://github.com/blowdart/idunnoSecuritySsrf/actions/workflows/ci-build.yml)
[![CodeQL Scan](https://github.com/blowdart/idunnoSecuritySsrf/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/blowdart/idunnoSecuritySsrf/actions/workflows/codeql-analysis.yml)

## License

`idunno.Security.Ssrf` is available under the MIT license, see the [LICENSE](LICENSE) file for more information.

## Tipping / Sponsoring

If you find this library useful please consider donating to
* a local food bank,
* a local animal rescue or shelter, or
* a national Multiple Sclerosis charity in your country
  * US: [National Multiple Sclerosis Society](https://www.nationalmssociety.org/)
  * UK: [MS Society UK](https://www.mssociety.org.uk/)
  * Canada: [MS Canada](https://mscanada.ca/)

If you want to give me the warm fuzzies, you can tag me on Bluesky at [@blowdart.me](https://bsky.app/profile/blowdart.me) to let me know.

## Release History

The [releases page](https://github.com/blowdart/idunno.Security.Ssrf/releases) provides details of each release and what was added, changed or removed.
The [changelog](CHANGELOG.md) also contains this information, as well as information on upcoming releases.

## Release Verification

The project uses an Authenticode certificate to sign assemblies and to author sign the nupkg packages.
nuget validates the signatures during its publication process.

To validate these signatures use

```
dotnet nuget verify [<package-path(s)>]
```

The subject name of the signing certificate should be

```
Subject Name: CN=Barry Dorrans, O=Barry Dorrans, L=Bothell, S=Washington, C=US
```

In addition, GitHub artifacts are attested during build,
and are also signed with [minisign](https://github.com/jedisct1/minisign) with the following public key.

```
RWTsT4BHHChe/Rj/GBAuZHg3RaZFnfBDqaZ7KzLvr44a7mO6fLCxSAFc
```

To validate a file using an artifact signature from a [release](https://github.com/blowdart/idunno.Security.Ssrf/releases)
download the `.nupkg` from nuget and the appropriate the `.minisig` from the release page, then use the following command,
replacing `<package-path>` with the file name you wish to verify.

```
minisign -Vm <package-path> -P RWTsT4BHHChe/Rj/GBAuZHg3RaZFnfBDqaZ7KzLvr44a7mO6fLCxSAFc
```

## Pre-releases

[![Prerelease Version](https://img.shields.io/myget/blowdart/vpre/idunno.Security.Ssrf?label=idunno.Security.Ssrf)](https://www.myget.org/gallery/blowdart)

If you want to test pre-releases you can find them in the [myget feed](https://www.myget.org/gallery/blowdart).

You can add this as a Package Source in [Visual Studio](https://learn.microsoft.com/en-us/nuget/consume-packages/install-use-packages-visual-studio#package-sources)
or through the [command line](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-nuget-add-source), or by using the sample `nuget.config` file shown below:

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
    <add key="blowdart.myget.org" value="https://www.myget.org/F/blowdart/api/v3/index.json" />
  </packageSources>

  <packageSourceMapping>
    <packageSource key="blowdart.myget.org">
      <package pattern="idunno.Security.Ssrf" />
    </packageSource>
    <packageSource key="nuget.org">
      <package pattern="*" />
    </packageSource>
  </packageSourceMapping>
</configuration>
```

The package source URI is https://www.myget.org/F/blowdart/api/v3/index.json

Please note that nightly builds are signed with Azure [Artifact Signing](https://azure.microsoft.com/en-us/products/artifact-signing/),
the signing certificate chain will not match the signing chain of a release build. The subject name remains the same.

### External analyzers used during builds
* [DotNetAnalyzers.DocumentationAnalyzers](https://github.com/DotNetAnalyzers/DocumentationAnalyzers) - used to validate XML docs on public types.
* [CommentSense](https://www.nuget.org/packages/CommentSense) - used to validate XML docs on public types.
* [Microsoft.CodeAnalysis.PublicApiAnalyzers](https://github.com/dotnet/roslyn/blob/main/src/RoslynAnalyzers/PublicApiAnalyzers/PublicApiAnalyzers.Help.md) - used to track public API changes.
* [SonarAnalyzer.CSharp](https://www.sonarsource.com/products/sonarlint/features/visual-studio/) - used for common code smell detection.

### External build &amp; testing tools

* [DotNet.ReproducibleBuilds](https://github.com/dotnet/reproducible-builds) - used to easily set .NET reproducible build settings.
* [Coverlet.Collector](https://github.com/coverlet-coverage/coverlet) - used to produce code coverage files
* [JunitXml.TestLogger](https://github.com/spekt/junit.testlogger) - used in CI builds to produce test results in a format understood by the [test-summary](https://github.com/test-summary/action) GitHub action.
* [NerdBank.GitVersioning](https://github.com/dotnet/Nerdbank.GitVersioning) - used for version stamping assemblies and packages.
* [ReportGenerator](https://github.com/danielpalme/ReportGenerator) - used to produce code coverage reports.
* [sign](https://github.com/dotnet/sign) - used to code sign assemblies and nuget packages.
* [xunit](https://github.com/xunit/xunit) - used for unit tests.
