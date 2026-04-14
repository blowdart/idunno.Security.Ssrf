// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.ComponentModel.DataAnnotations;
using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AspNetHttpClientFactory.Pages;

public class IndexModel(HttpClient httpClient) : PageModel
{
    [BindProperty]
    [Required]
    public string? TestUri { get; set; }

    [BindProperty]
    public HttpStatusCode? ResultStatusCode { get; set; }

    public void OnGet()
    {
    }

    public PageResult OnPost(string testUri)
    {
        if (!Uri.TryCreate(testUri, UriKind.Absolute, out var uri))
        {
            ModelState.AddModelError(nameof(TestUri), "The URI is not valid.");
        }

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var result = httpClient.GetAsync(uri).Result;
        ResultStatusCode = result.StatusCode;

        return Page();
    }
}
