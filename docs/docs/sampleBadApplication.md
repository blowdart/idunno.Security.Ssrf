# Testing the SSRF handler works as expected

What follows is a sample console application using .NET 10's [file based applications](https://learn.microsoft.com/en-us/dotnet/core/sdk/file-based-apps)
which opens an http listener on localhost, and attempts to connect to it, with and without the SSRF handler so you can see what happens.

## Create a .NET .cs File

# [Linux and Mac](#tab/linux)

1. At the command line change to the directory you want your app to run from run the following commands
   ```bash
   touch TestApp.cs
   chmod +x TestApp.cs
   ```

# [Windows](#tab/windows)

1. Open a PowerShell console, change to the directory you want your app to run from and enter the following command
   ```PowerShell
   New-Item .\TestApp.cs -type file
   ```

---

## Paste the application code in TestApp.cs

# [Linux and Mac](#tab/code/linux)

1. Open the TestApp.cs in your favourite editor and paste the following code
   [!code-csharp[](../code/TestApp/TestApp.cs)]
1. Save the file

# [Windows](#tab/code/windows)

1. Open the TestApp.cs in your favourite editor and paste the following code
   [!code-csharp[](../code/TestApp/TestApp.cs)]
1. Save the file


The application creates a Kestrel web host running on port 3000 which responses with "Hello World". It then sends
test requests with and without SSRF protection.

---

## Run the application

# [Linux and Mac](#tab/run/linux)

1. At the command line change to the directory you want your app to run from run the following commands
   ```bash
   dotnet run TestApp.cs
   ```

# [Windows](#tab/run/windows)

1. Open a PowerShell console, change to the directory you want your app to run from and enter the following command
   ```PowerShell
   dotnet run .\TestApp.cs
   ```

---

What you will see is a request with a plain `HttpClient` being made to http://localhost:3000 with no SSRF protection,
which works, and gets an HTTP 200 response.

Next the same request is made, but with an `HttpClient` with has the SSRF handler. An exception
is thrown because the uri is considered unsafe, as it is http and not https.

Next the same request is made, but with an `HttpClient `with has the SSRF handler and configured to allow insecure
protocols and attempts to send the same request, at which point an exception is thrown because the uri is considered unsafe,
as it is a loopback address.

Finally it creates an `HttpClient` with SSRF protection, allowing insecure protocols, but this time sends the request
to http://loopback.ssrf.fail:3000. loopback.ssrf.fail is a test DNS entry that resolves to both the ipv4 and ipv6
loopback addresses. This time an SsrfException is thrown but the message is different,
"Connection blocked as all resolved addresses are unsafe", showing that the URI passed inspection, but the IP addresses
it resolved to did not.
