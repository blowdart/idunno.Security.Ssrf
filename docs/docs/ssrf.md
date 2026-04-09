# What is Server Side Request Forgery (SSRF)?

In short: SSRF is what happens when an application makes server-side requests to a user-controlled URL,
and an attacker abuses that to reach internal services the attacker can’t access directly.

Many applications can import data from a user-specified URI or send data to one. An attacker can provide a URI
that causes the application to send requests somewhere unexpected inside your network — like `localhost` or an
internal host such as `10.0.0.1`. As applications often have a trust relationship with the networks they run in,
SSRF lets an attacker “borrow” that trust.

For a real-world example, [Capital One’s largest breach](https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af)
was driven by SSRF. It affected around 100 million cardholders in the US and another 6 million in Canada, and exposed data including Social Security numbers,
Social Insurance Numbers, and bank account details. The SSRF weakness was used to access AWS S3 bucket listings and related credentials.

Cloud environments can make SSRF more damaging because most providers expose an instance metadata service on a well-known link-local address
(for example http://169.254.169.254/). If an attacker can trigger SSRF, they may be able to query that metadata endpoint
from the application server and read the responses—sometimes including credentials, role information, or storage configuration
(as in Capital One’s case).

Checking the IP addresses a host resolves to on ingestion is not enough. The IP addresses that a host name resolves
to can change with time, an attacker can input, for example, https://badsite.example which, at the time of input resolves
to 1.2.3.4, then waits for a day and changes the DNS record so now it resolves to 169.254.169.254 and now you have a Time of Check, Time of Use vulnerability (TOCTOU).

If you want examples of [SSRF payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
(and many other attacks), [swissky’s GitHub repository](https://github.com/swisskyrepo/PayloadsAllTheThings) is a great starting point.

If your application accepts a URI as input directly or indirectly from a user, from a request parameter,
or from any other untrusted source, like an OAuth metadata endpoint, you need to think about protecting against SSRF.


