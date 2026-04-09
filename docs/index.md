# Get started

Let's get your .NET application protected against [Server Side Request Forgery](docs/ssrf.md) attacks.

## Create a .NET project with the idunno.Security.Ssrf nuget package

# [Command Line](#tab/commandLine)

1. At the command line run the following commands
   ```PowerShell
   dotnet new console -n NoSsrf
   cd NoSsrf
   dotnet add package idunno.Security.Ssrf
   ```

# [Visual Studio](#tab/visualStudio)

1. Create a new .NET Command Line project by opening the File menu, and choosing **New ▶ Project**.
1. In the "**Create a new project**" dialog select C# as the language, choose **Console App** as the project type then click Next.
1. In the "**Configure your new project**" dialog name the project `NoSsrf` and click Next.
1. In the "**Additional information**" dialog choose a Framework as .NET 10.0, uncheck the "Do not use top level statements" check box then click **Create**.
1. Under the **Project** menu Select **Manage nuget packages**, select the *Browse* tab. Search for `idunno.Security.Ssrf`, and click **Install**.
1. Close the **Manage nuget packages** dialog.

# [Visual Studio Code](#tab/vsCode)

1. Create a new .NET Command Line project by opening the Command Palette (**Ctrl + Shift + P**) and search for **.NET New Project**
1. In the Create a new .NET Project template search for and select **Console App**
1. Select the folder you want to save your project in
1. Name your project `NoSsrf`
1. Choose the solution format you prefer.
1. Press **Enter** to create the solution.
1. Select the `NoSsrf.csproj` file in Explorer window.
1. Opening the Command Palette (Ctrl + Shift + P) and search for **Nuget: Add**
1. Enter `idunno.Security.Ssrf` in the package search dialog and choose the latest version.

---

## Create an HttpClient

# [Command Line](#tab/httpClient/commandLine)

1. Open the `Program.cs` file in your editor of choice and add the following lines.
   [!code-csharp[](code/NoSsrf/Program.cs#L6-L10)]
1. Save the changed file.
1. Compile and run your project with the following command
   ```PowerShell
   dotnet run
   ```

# [Visual Studio](#tab/httpClient/visualStudio)

1. Open the `Program.cs` file from the Solution Explorer window and and add the following lines.
   [!code-csharp[](code/NoSsrf/Program.cs#L6-L10)]
1. Save the changed file.
1. Run the project by pressing **F5** or choosing **Start Debugging** under the Debug menu.

# [Visual Studio Code](#tab/httpClient/vsCode)

1. Open the `Program.cs` file from the Explorer window and cand add the following lines.
   [!code-csharp[](code/NoSsrf/Program.cs#L6-10)]
1. Save the changed file.
1. Run the project by pressing **F5** or choosing **Start Debugging** under the Run menu.

---

The program should run without any errors, and should output `200`, the HTTP status code for a successful request.

## Create an HttpClient with SSRF protection

# [Command Line](#tab/ssrfHttpClient/commandLine)

1. Open the `Program.cs` file in your editor of choice and add the following lines.
   [!code-csharp[](code/NoSsrf/Program.cs#L12-L17)]
1. Save the changed file.
1. Compile and run your project with the following command
   ```PowerShell
   dotnet run
   ```

# [Visual Studio](#tab/ssrfHttpClient/visualStudio)

1. Open the `Program.cs` file from the Solution Explorer window and and add the following lines.
   [!code-csharp[](code/NoSsrf/Program.cs#L12-L17)]
1. Save the changed file.
1. Run the project by pressing **F5** or choosing **Start Debugging** under the Debug menu.

# [Visual Studio Code](#tab/ssrfHttpClient/vsCode)

1. Open the `Program.cs` file from the Explorer window and cand add the following lines.
   [!code-csharp[](code/NoSsrf/Program.cs#L12-L17)]
1. Save the changed file.
1. Run the project by pressing **F5** or choosing **Start Debugging** under the Run menu.

---

The program should run without any errors, and should output two lines that say `200`, the HTTP status code for a successful request.

Congratulations, you have an `HttpClient` with protection from SSRF!

### Explainers

* [What is SSRF?](docs/ssrf.md)
* [How does the SSRF handler work?](docs/ssrf.md)

### Advanced Topics

* [Configuration](docs/configuration.md)
* [Using Proxy Servers](docs/usingProxies.md)
* [Testing the SSRF handler works as expected](docs/sampleBadApplication.md)
