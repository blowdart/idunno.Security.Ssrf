// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using idunno.Security;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

builder.Services.AddHttpClient();
builder.Services.ConfigureHttpClientDefaults(configure =>
    configure.ConfigurePrimaryHttpMessageHandler(() => SsrfSocketsHttpHandlerFactory.Create(allowInsecureProtocols: true))
);

var app = builder.Build();

app.UseRouting();

app.MapStaticAssets();
app.MapRazorPages()
   .WithStaticAssets();

app.Run();
