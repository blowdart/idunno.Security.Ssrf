// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

namespace idunno.Security;

/// <summary>
/// The exception thrown when the SsrfChecks encounter an unsafe uri or host.
/// </summary>
public class SsrfException : Exception
{
    /// <summary>
    /// Initializes a new instance of <see cref="SsrfException"/>.
    /// </summary>
    public SsrfException() : base()
    {
    }

    /// <summary>
    /// Initializes a new instance of <see cref="SsrfException"/>
    /// </summary>
    /// <param name="message">The error message string.</param>
    public SsrfException(string? message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of <see cref="SsrfException"/>
    /// </summary>
    /// <param name="message">The error message string.</param>
    /// <param name="inner">The exception that is the cause of the current exception, or a <see langword="null" /> reference if no inner exception is specified.</param>
    public SsrfException(string? message, Exception? inner) : base(message, inner)
    {
    }

    /// <summary>
    /// Initializes a new instance of <see cref="SsrfException"/> with the <see cref="Uri" /> that causes the exception.
    /// </summary>
    /// <param name="uri">The <see cref="Uri" /> that causes the exception.</param>
    public SsrfException(Uri? uri) : base()
    {
        Uri = uri;
    }

    /// <summary>
    /// Initializes a new instance of <see cref="SsrfException"/>
    /// </summary>
    /// <param name="uri">The <see cref="Uri" /> that causes the exception.</param>
    /// <param name="message">The error message string.</param>
    public SsrfException(Uri? uri, string? message) : base(message)
    {
        Uri = uri;
    }

    /// <summary>
    /// Initializes a new instance of <see cref="SsrfException"/>
    /// </summary>
    /// <param name="uri">The <see cref="Uri" /> that causes the exception.</param>
    /// <param name="message">The error message string.</param>
    /// <param name="inner">The exception that is the cause of the current exception, or a <see langword="null" /> reference if no inner exception is specified.</param>
    public SsrfException(Uri? uri, string? message, Exception? inner) : base(message, inner)
    {
        Uri = uri;
    }

    /// <summary>
    /// Gets or sets the URI that causes this exception.
    /// </summary>
    /// <remarks>
    /// <para>The Uri, if present, may contain sensitive information such as query parameters. Do not include this information in messages to end users, and
    ///secure any logs that may contain this information.</para>
    /// </remarks>
    public Uri? Uri { get; set; }
}
