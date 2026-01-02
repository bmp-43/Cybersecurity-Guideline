## **HTTP Security headers Introduction**

Here we will focus on basic theory on what HTTP headers are exactly.

#### **Step 1: Introduction**

In web application penetration testing , understanding HTTP security headers is crucial for identifying vulnerabilities that can be exploited by attackers. This document provides an in-depth overview of the most relevant headers, explaining:

*   **What** each header is
*   **Why** it is important for security
*   **How** it is configured, tested, and used in Testing

Content is divided between **Request Headers** (sent by the client) and **Response Headers** (sent by the server), followed by **Real-World Exploits** and **Recommendations**.

#### **Step 2: Request Headers**

These headers originate from the browser or client application and carry important context or credentials.

##### **2.1 Origin**

*   **What:** Indicates the origin of the request, comprising protocol, host, and port.
*   **Why:** Used by servers to enforce Cross-Origin Resource Sharing (CORS) policies. CORS determines what domains are allowed to talk to the server, it is enforced by browser. By checking `Origin`, a server can allow or block cross-origin requests.
*   **How:** Browsers automatically include this header on cross-origin AJAX (Asynchronous JavaScript and XML) or fetch requests. Right now JavaScript often uses JSON instead of XML but name stuck. In VAPT (Vulnerability Assessment and Penetration Testing), testers manipulate `Origin` values to test CORS misconfigurations.
*   **Example** **Configuration on Server** **(Nginx):**

add\_header 'Access-Control-Allow-Origin' 'https://URL';  
add\_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS';

*   **Example** **Configuration on Server** **(Caddy):**

```
https://example.com {
    header Access-Control-Allow-Origin "https://URL"
    header Access-Control-Allow-Methods "GET, POST, OPTIONS"
    
    route /api/* {
        respond "ok"
    }
}
```

**Testing with curl:**

```
curl -H "Origin: https://abc.com" -I https://URL/api/resource
```

> [!TIP]
> Look for `Access-Control-Allow-Origin: *` or matching the malicious origin.
> 
> Simply put, if the Origin in our request doesn’t match what the server allows, the browser blocks access to the response. However **the server may still respond**, but the **browser won’t let JS read it**. That’s the key CORS point most people miss.

##### **2.2 Referer**

> [!IMPORTANT]
> IMPORTANT: In browsers and this domain overall the name is misspelled so we use Referer not the correct English word “referrer”

*   **What:** Indicates the URL of the page making the request (not always included if privacy settings or HTTPS→HTTP transition). For example clicking a URL from ChatGPT will make it your referrer.
*   **Why:** Helps the server understand navigation flow. This is for the website owners to know where they receive their mainly traffic. However, it can unintentionally leak sensitive paths or query parameters (e.g., session tokens in URL).
*   **How:** Browsers send `Referer` automatically. VAPT testers inspect it to see if sensitive information is leaked.
*   **Example Leak:** We're logged in into a site and the URL shows like this:
    
    [`https://bank.com/account?session=ABC123`](https://bank.com/account?session=ABC123)

That ‘session=ABC123’ is sensitive and should never leave the site! Now let's say the site has a image or something else from another site like this.

```
<img src="https://ads.evil.com/banner.png">
```

Now if we click on that URL the other site will receive this kind of request.

`Referer:` [`https://bank.com/account?session=ABC123`](https://bank.com/account?session=ABC123)

Now if site is malicious and it receives our session token and can exploit it, OR if evil.com is not actually evil but has poor security another attacker can hijack our session token.

**Mitigation (Server/HTML):**

```
<meta name="referrer" content="no-referrer-when-downgrade">
```

or serve header (modern practice):

```
Referrer-Policy: strict-origin-when-cross-origin
```

## **2.3 Authorization**

Authorization is needed to prove to the server that you are **allowed** to enter and do x, its not the same as **Authentication** which is for proving who **you**  are.

*   **What:** Carries authorization credentials, its point is to prove the server that you are already logged in and that you're allowed to do whatever you want to do.

**Credentials example** **Basic vs Bearer:**

**Basic authorization** credential will be something like:

`Authorization: Basic dXNlcjpwYXNz`  
Its encoded in Base64 and simply means  
`username:password`

So with Basic:

*   Your **real password** is sent **on every request**
*   Server decodes it every time
*   If someone sees it once, they have your password forever

Over HTTP → instant compromise  
Over HTTPS → still bad practice, but survivable

**Basic is always username + password**

**Bearer authorization** credential will be something like:

`Authorization: Bearer eyJhbGciOi...`

Now this is not our password or something else, it is our Token. It basically means that we were logged in, and it is our proof that we are allowed to access the service.

The token usually contains or points to:

*   Your user ID
*   Your permissions
*   Expiration time

The server checks:

*   Is this token real?
*   Did I issue it?
*   Is it still valid?

This is safer than Basic credentials because stealing this we steal **session** not the **password.** Session will expire sooner or later unless the service was made by an idiot, and when it does attacker will lose access if we didn't know that we are compromised.

> [!WARNING]
> Important to note that Base64 is NOT for security, its made for **b**inary-to-text encoding and easier data transfer.

*   **Why:** Necessary for API endpoints that require user authentication since API's don't have login pages, they trust **Tokens**. can be stolen if transmitted insecurely, for example: **If token** - Is sent through HTTP, visible through logs, via referrer headers, through XSS, then anyone who sees it can reuse it. The server can’t tell legit from stolen. Same token, same trust.
*   **How:** Sent automatically by browser or API client, once client got the token the app or browser will auto-attach it, user doesn't see it. In VAPT, testers observe if endpoints enforce HTTPS and inspect token format to verify if they are predictable or vulnerable.

> [!TIP]
> *   **Testing Steps:**
> 
> 1.  Use HTTP rather than HTTPS to see if token is transmitted in plaintext.
> 2.  Use Burp Suite to intercept and modify the header to test for token reuse or impersonation.
> 3.  Check if tokens expire properly by replaying old tokens.

#### **2.4 User-Agent**

*   **What:** Identifies the client application and version, telling the server ‘characteristics’ of the requester, e.g., `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/... Chrome/... Safari/...`.
*   **Why:** Servers can use **User-Agent** for content negotiation or device-specific functionality, like desktop vs mobile layout etc. In security, determining if server discloses platform-specific info or behaves differently for certain agents can reveal vulnerabilities. From attacker's perspective if server changes its behavior because of different user agent that's - ‘**Interesting’****.** If the server:  
    1\. Trusts it too much.
    
    2\. Reveals extra info.
    
    3\. Disables or downgrades security for “older browsers” or devices.
    
    That is a vulnerability, not a feature.
*   **How:** Automatically sent by browsers. VAPT testers often spoof **User-Agent** to test server responses to outdated or vulnerable clients.

**Example Spoof:**

curl -A "BadBot/1.0" https://abc.com

Here we are checking:

*   Does the server block unknown agents?
*   Does it return different headers?
*   Does it expose debug info?
*   Does it serve weaker code paths?

> [!CAUTION]
> If “Chrome” gets one response and “BadBot” gets another, your ears should perk up.  
> User‑Agent is **advisory**, not identity.  
> If a server _trusts_ it for security decisions, it’s being naive.  
> Basically User‑Agent tells the server what you _claim_ to be, not what you _are_.  
> Any security based on it, is cosmetic at best, exploitable at worst.

#### **2.5 Cookie**

*   **What:** Cookies are tiny pieces of data the server gives your browser to remember you. They are sent automatically as name=value pairs of stored cookies, like:
    
    `Cookie: sessionId=abc123; pref=darkmode;`.
    
    sessionId=abc123 → identifies your session (who you are logged in as)
    
    pref=darkmode → personalization
*   **Why:** Cookies do 3 main things.
    
    **1\.  Session management** – keeps you logged in.
    
    **2\. Personalization** – stores preferences.
    
    **3\. Tracking** – analytics or advertising.
    
    **Security angle:**
    
    Cookies are like **keys to your account**. If they leak, the attacker doesn’t need your password—they can impersonate you instantly.
    
    **HttpOnly:**
    
    Stops JavaScript from reading the cookie.
    
    Without it, an XSS payload anywhere on the page can grab `document.cookie` and steal your session.
    
    Think: XSS + no HttpOnly = instant account takeover.
    
    **Secure:**
    
    Cookie only travels over **HTTPS**.
    
    Without it, the cookie can be intercepted over HTTP.
    
    Example: public WiFi, sniffing traffic → attacker sees sessionId in plain text → can replay it.
    
    **SameSite:**
    
    Prevents cookie from being sent in cross-site requests.
    
    Without it, CSRF attacks are easy:
    
    Victim logged into bank.com → Visits evil.com → Evil.com triggers a request to bank.com → Cookie automatically sent → Transaction happens under victim’s session

> [!NOTE]
> `SameSite=None` **must** be paired with `Secure`. That’s a modern browser rule.

**Combined danger:**

XSS + missing HttpOnly → attacker steals session

Missing Secure + HTTP → network sniffers grab session

Missing SameSite → attacker can trick browser into sending cookie cross-site

Any of these combined → attacker fully owns your session, sometimes without you noticing

> [!IMPORTANT]
> Session cookies should expire quickly. Persistent cookies without expiration or rotation make compromise long-lasting. Weak session IDs (predictable or short) → brute-force attacks possible.

*   **Testing Example:**

1.  Open DevTools → Application → Cookies.
2.  Check if the session cookie has `HttpOnly` and `Secure` attributes. If missing, attempt XSS or, drop to HTTP to intercept cookie (if it lacks `Secure`).

> [!WARNING]
> **Session Fixation Is important to pay attention to:** Attacker sets or predicts a session ID before login; if the server doesn’t rotate it after authentication, the attacker can use the same ID to access the victim’s account.  
> **Example:** `https://site.com/login?sessionId=ATTACKER123` → victim logs in → server keeps `sessionId=ATTACKER123` → attacker reuses it to access the account.  
> **Mitigation:** always regenerate session ID on login and ignore externally supplied IDs.

#### **2.6 Content-Type / Accept**

*   **What:** `Content-Type` indicates the media type of the request body 
    
    Example (JavaScript):
    
    ```
    fetch("https://api.example.com/data", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({foo: "bar"})
    });
    ```
    
    The server reads this header to know it should parse the body as JSON.
    
    Sometimes developers also enforce or check this server-side in code (e.g., `if request.content_type != 'application/json' → reject`).
    
    **Accept:**
    
    This is the client telling the server that it can handle X response type.
    
    Usually set in the **HTTP request headers**. Developers set it in:
    
    *   JavaScript fetch/XHR
    *   API clients
    *   Sometimes server frameworks auto-set it depending on route.
    
    Example in fetch():
    
    ```
    fetch("https://api.example.com/data", {
      headers: {
        "Accept": "application/json"
      }
    });
    ```
    
    **To see this process as a user:**
    
    1\.  Open **DevTools → Network tab** in your browser.
    
    2\. Make the request (click a link, submit a form, call an API).
    
    3\. Click the request → **Headers** tab.
    
    4\. Under **Request Headers**, you’ll see both:
    
    *   `Content-Type` (if it has a body, like POST/PUT)
    *   `Accept` (always sent by browser for GETs too)

**Basically:**

*   Content-Type = _“How I’m sending you data”_
*   Accept = _“How I want you to respond”_
*   **Why:** Servers rely on `Content-Type` to parse input correctly, `Content-Type` tells the server how to interpret the request body.

> [!WARNING]
> If server expects `application/json` but receives `application/xml`, it may:
> 
> *   Throw errors → information leak
> *   Misparse the body → injection opportunity (e.g., XML injection, SQL injection, deserialization)
> *   Accept it anyway → trust the wrong data type

**Accept** tells the server which response formats the client can handle, aka helps server pick JSON, HTML, XML, or others.

> [!WARNING]
> In security testing, different Accept headers may cause the server to:
> 
> *   Return debug info
> *   Change response structure
> *   Reveal alternate endpoints or error messages

**Security angle:**

**Blind trust in Content-Type = parsing vulnerabilities**

**Accept header behavior** = information disclosure risk.

Attackers can send “weird” headers or mismatched types to test how robust server parsing and content negotiation are.

*   **How (VAPT Perspective)**: Tester can do These:

**Send unexpected Content-Type** (Using Burp Suite, Curl, Or a custom Script)**:**

`POST /api/data HTTP/1.1 Content-Type: text/plain`

Check if server rejects it, crashes, or misinterprets data.

If server accepts it anyway → parsing logic may be unsafe.

**Send mismatched payload:**

Example:

`Content-Type: application/json` 

`Body: foo=bar&baz=1` 

Tests how server parses different formats. A weak parser may:

*   Ignore type checks
*   Merge inputs incorrectly
*   Execute unsafe code

**Test Accept behavior:**

Example: `Accept: application/xml` or `Accept: text/html`

Observe:

*   Different error messages
*   Extra headers or debug info
*   Alternate content rendering paths

> [!NOTE]
> Mismatched Content-Type can also bypass certain input filters or WAF rules if the server only checks headers superficially.

## **Step 3: Response Headers (Sent by the Server)**

These are the primary security headers to instruct browsers on handling content and interactions.

#### **3.1 Content-Security-Policy (CSP)**

*   **What:** A powerful security layer that defines where browsers can load resources (scripts, styles, images, frames) from, which prevents execution of injected malicious scripts since CSP will not tolerate their execution. It can also mitigate inline script/style risks and prevent eval().
*   **Why:** Prevents Cross-Site Scripting (XSS), data injection, and mixed-content issues. By limiting resource origins, CSP reduces the risk of malicious third-party scripts executing.
*   **How:** Configured by adding a `Content-Security-Policy` header. CSP has many directives:
    *   `default-src`: Fallback for any resource type.
    *   `script-src`: Defines allowed script sources.
    *   `style-src`: Defines allowed styles.
    *   `img-src`: Defines allowed image sources.
    *   `frame-src` or `child-src` (child-src is deprecated in modern browsers):  Defines allowed iframe sources.
    *   `object-src`: Defines allowed plugins/Flash sources.
    *   `report-uri` or `report-to`: Endpoint where violations are reported.

**Example of a Strict CSP:**

```
Content-Security-Policy:
    default-src 'self';
    script-src 'self' https://trus.cdn.com;
    style-src 'self';
    img-src 'self';
    object-src 'none';
    frame-ancestors 'self';
```

*   `'self'` = only your own site.
*   `object-src 'none'` = block plugins.
*   `frame-ancestors 'self'` = only let your pages be framed by your own domain.

**Implementation Tips:**

*   Start with a report-only policy to monitor violations. This will not block anything yet BUT it will log what it would have blocked. It helps to see if your rules are too strict or too loose, without breaking the site.
*   Use nonce-based or hash-based scripts if inline scripts are needed.
    *   If you really need inline scripts (the `<script>` tags right in your HTML), don’t just allow all of them.
    *   **Nonce**: a random ID you add to each allowed script. Browser only runs scripts with that exact nonce.
    *   **Hash**: you compute a hash of the script content; only scripts that match that hash run.
    *   Both methods prevent random injected scripts from running.
*   Avoid `'unsafe-inline'` and `'unsafe-eval'` when possible.
    *   `unsafe-inline` = let's any inline script run → basically handing hackers a key.
    *   `unsafe-eval` = let's scripts execute code via `eval()` → another hacker door.
    *   Only use these if there’s literally no other option.

**Testing :**

1.  Check response headers for missing or overly permissive policies.
    1.  Open DevTools → Network → pick a request → check the headers.
    2.  Make sure your CSP is there and not too permissive (like `*` or allowing sketchy domains).
2.  Attempt injecting a `<script>` tag from a non-whitelisted domain.
    1.  If your CSP works, the browser blocks it and logs a violation.
3.  Use browser DevTools to view CSP violations in the Console.
    1.  DevTools Console will show messages like `Blocked script from xyz.com`.
    2.  Helps you spot gaps in your policy.

> [!IMPORTANT]
> CSP is a mitigation layer, not a replacement for input validation.

#### **3.2 Strict-Transport-Security (HSTS)**

*   **What:** Tells browsers to only connect via HTTPS for a specified time period (`max-age`), optionally including subdomains and enabling site on HSTS preload lists. Site will NOT connect over HTTP. HSTS only works **after the first HTTPS visit, unless preloaded.**
*   **Why:** Prevents downgrade attacks (forcing HTTP) and SSL-stripping. Ensures all future requests use encrypted channels, protecting cookies and sensitive data in transit.
*   **How:** Configured by adding a `Strict-Transport-Security` header. Common directives:
*   `max-age=[seconds]`: How long the policy is enforced.
*   `includeSubDomains`: Apply policy to all subdomains.
*   `preload`: Indicate the domain should be included in browser preload lists.

**Example:**

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

This means “For one year, force HTTPS everywhere, including subdomains, even before the first visit.”

**Implementation Tips:**

*   Only enable `preload` after verifying HTTPS works correctly on all subdomains.
*   Use a long `max-age` (e.g., one year = 31536000 seconds).

**Testing :**

*   Use `curl -I URL`to verify header presence.
*   Connect to `http:URL` to ensure it redirects to HTTPS.
*   Attempt MITM downgrade attacks (e.g., use tools like Mallory) to see if traffic is forced to HTTPS.

> [!NOTE]
> Once a domain is preloaded, removing HSTS requires browser list updates and can take months.

#### 3.3 X-Frame-Options

*   **What:** Controls whether a browser can display the page in an `<iframe>`. An `<iframe>` (inline frame) is an HTML element that embeds another HTML document within the current page. It allows separate content to be loaded independently while keeping it part of the parent document’s layout. Three directives exist:
*   `DENY`: Prevents any framing.
*   `SAMEORIGIN`: Allows framing only from the same origin (same domain).
*   `ALLOW-FROM uri`: Allows framing from a specified origin (deprecated in some browsers).
*   **Why:** Protects against Clickjacking, where an attacker embeds a site inside a transparent frame and tricks users into clicking hidden buttons.
*   **How:** Add `X-Frame-Options` header.

```
X-Frame-Options: SAMEORIGIN
```

**Implementation Tips:**

*   Use `DENY` if the application should never be framed.
*   Use `SAMEORIGIN` if internal dashboards or subdomains need framing.

**Testing :**

*   Create a simple HTML page with an `<iframe src="https://t.com">`. If the browser blocks the framing, `X-Frame-Options` is effective.
*   In Burp Suite, observe the header in server responses.

> [!IMPORTANT]
> X-Frame-Options is deprecated in favor of CSP `frame-ancestors`, which provides finer control.

#### 3.4 X-Content-Type-Options

Sometimes browsers try to be smart and _guess_ what a file ‘really’ is. This header prevents that.

*   **What:** Instructs browsers not to perform MIME-type sniffing and to trust the declared `Content-Type` only. This matters because browsers may override incorrect MIME types.
*   **Why:** Prevents attacks where browsers interpret a file as a different type (e.g., treating a `.txt` file as JavaScript), which can lead to XSS or content spoofing. It basically mitigates XSS vectors caused by browsers executing content in a more dangerous context than intended.
*   **How:** Include `X-Content-Type-Options: nosniff` in responses.

```
X-Content-Type-Options: nosniff
```

**Implementation Tips:**

Always set on responses that serve user-uploaded content or files with a defined `Content-Type` for:

*   User-uploaded files
*   Static assets
*   API responses returning JSON
*   Especially critical when serving files from public or shared directories

**Testing :**

*   Serve a file with misleading content (e.g., `.txt` containing `<script>`). Without `nosniff`, some browsers might execute it as JavaScript.
*   Check response headers in DevTools or via `curl -I`.

> [!NOTE]
> This header has no performance or compatibility downsides and should be enabled by default, for security reasons. This header is particularly important for legacy browsers and edge cases where MIME sniffing is still applied.

#### 3.5 Referrer-Policy

*   **What:** Controls the amount of referrer information (website URL) sent with requests when navigating from one page to another or when fetching resources. Basically when we click a link in site A and get redirected to site B, the referrer-policy determines how much should site B know about site A.
*   **Why:** Prevents leaking sensitive URLs or query parameters to third-party sites. URLs are not harmless they can easily contain crucial data. For example:
    
    *   Tokens
    *   Session identifiers
    *   Internal paths
    *   User IDs
    
    If your page links to a third-party site and sends the full URL as referrer, you just leaked that data.
*   **How:** Set `Referrer-Policy` header or use HTML `<meta>` tag.

```
Referrer-Policy: strict-origin-when-cross-origin
```

Common values:

*   `no-referrer`: No referrer information sent.
*   `no-referrer-when-downgrade`: Default in older browsers; no referrer sent on HTTPS→HTTP.
*   `strict-origin`: Only send origin (scheme + host + port) over HTTPS to HTTPS.
*   `strict-origin-when-cross-origin`: Send full URL as referrer for same-origin, only origin for cross-origin requests.
*   `same-origin`: Send referrer only to same-origin requests.
*   `unsafe-url`: Always send full URL (least safe).

**Testing:**

*   Visit a page with query parameters (e.g. `?token=123`).
*   Click a third-party link.
*   Inspect the outbound request in DevTools → Network → `Referer` header.
*   Confirm only the allowed portion is sent.

> [!NOTE]
> Referrer-Policy reduces passive data leakage without impacting application logic.

#### 3.6 Permissions-Policy (Feature-Policy)

*   **What:** Browsers have powerful features. Camera, mic, GPS, sensors. Permissions-Policy is telling the browser **which features this site and embedded content are even allowed to ask for**. For example if camera permission is blocked in API, even if user clicks “allow” the site will not let camera to activate.
*   **Why:** Some attacks don’t always exploit bugs. They exploit **permissions**.
    
    Examples:
    
    *   Third-party iframe abusing camera or mic
    *   Embedded ad trying to read clipboard
    *   Compromised script accessing sensors
        
        Permissions-Policy limits the blast radius.

> [!IMPORTANT]
> This is a _defense-in-depth_ control. It assumes JavaScript might be compromised.

*   **How:** Even if JavaScript asks for X feature browser will check whether that feature is even allowed by the server, if not - It wont turn on no matter what.

```
Permissions-Policy: geolocation=("self"), camera=(), microphone=()
```

*   `("self")` → only your own origin can use it
*   `()` → completely disabled
*   You can also allow specific trusted origins

This applies to **iframes** too.

**Common features:**

*   **geolocation** → user tracking and location leakage
*   **camera** → visual surveillance and privacy invasion
*   **microphone** → audio surveillance and eavesdropping
*   **gyroscope** → motion-based tracking and device fingerprinting
*   **accelerometer** → behavioral tracking and movement inference
*   **fullscreen** → UI deception and phishing attacks
*   **payment** → fraud and unauthorized payment requests
*   **clipboard-read** → leakage of sensitive copied data (passwords, tokens)
*   **clipboard-write** → clipboard manipulation and data replacement attacks

**Testing :**

*   Block a certain browser feature then try to allow it in JavaScript
    
    ```
     navigator.geolocation.getCurrentPosition()
    ```
    
    If blocked:
    
    *   Browser throws a permission error
    *   No prompt shown
    *   Console logs policy violation
    
    That proves enforcement is server-side, not UI-based.
*   Check response headers via DevTools or `curl -I`.

#### 3.7 Access-Control-Allow-Origin (CORS)

*   **What:** Browsers block cross-site requests by default. CORS (Cross-Origin Resource Sharing) Specifies which origins can access the server resource in a cross-origin context. Can be a single domain or wildcard (`*`).
*   **Why:** Controls and restricts cross-origin access to APIs and resources. Misconfigured CORS is a goldmine for attackers. For example:
    *   If `*` is used with credentials → attacker gets full access
    *   Echoing back untrusted origins → SOP (Same-Origin Policy) bypass
    *   Could allow stolen API responses or session hijacking
*   **How:** Be surgical with what you allow, only necessary origins must be able to access the server.
    
    *   Allow only specific, trusted origins (`https://yourdomain.com`)
    *   Avoid `*` with credentials
    *   Explicitly allow only required methods and headers
    *   Never blindly echo the `Origin` header
    
    Example:
    
    ```
    Access-Control-Allow-Origin: https://t.com
    Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
    Access-Control-Allow-Headers: Content-Type, Authorization
    Access-Control-Allow-Credentials: true
    ```

**Testing :**

*   Use curl or Postman with a fake origin (`Origin: https://evil.com`)
    
    like `curl -H "Origin: https://evil.com" -I https://target.com/api`
*   Check if the server incorrectly allows it:
    *   `Access-Control-Allow-Origin: *` → risky if credentials allowed
    *   Echoed `evil.com` → SOP bypass

> [!NOTE]
> Proper CORS configuration prevents unauthorized cross-origin access and enforces SOP, protecting sensitive APIs and user data.

#### 3.8 Cross-Origin-Resource-Policy (CORP)

*   **What:** This is a resource-side header that says **who is allowed to load this resource in a cross-origin context**. 
    
    Values:
    
    *   `same-origin`: Only same-origin documents can embed.
    *   `same-site`: Only same-site documents.
    *   `cross-origin`: Resource can be shared with any origin.
*   **Why:** Works hand-in-hand with **COEP** **(featured later)** on the page side. Prevents sensitive resources from being loaded by untrusted pages, which is crucial for mitigating side-channel attacks (Spectre, Meltdown) and safely using features like **SharedArrayBuffer**.
*   **How:** Add:

```
Cross-Origin-Resource-Policy: same-origin
```

**Testing:**

*   Try embedding the resource from a different origin (image, script, iframe).
*   If `same-origin` is set, it should be blocked.
*   Check DevTools Console for CORP-related errors.

> [!TIP]
> COEP + CORP together = page enforces “I only want CORP-compliant resources” and resource enforces “only trusted pages can use me.” Both must line up, otherwise the browser blocks it. COEP will be explained in no time later on!

#### 3.9 Access-Control-Allow-Credentials

*   **What:** Indicates whether the response to a request can be exposed when credentials (cookies, authorization headers) are included, by default they're not. 
    
    It allows:
    
    *   let's cross-origin requests include credentials (cookies, auth headers)
    *   Must be used **with specific origin**, not `*`
    *   Enforces server-side control over which trusted origins can receive authenticated responses
    
    **Intent:** Safely allow authenticated cross-origin requests without opening a door to attackers.
*   **Why:** Necessary when the server wants to accept cookies/credentials in cross-origin requests. However, combining `Allow-Credentials: true` with a wildcard origin is a security risk.

> [!CAUTION]
> Must be paired with strict origin checks to prevent session hijacking.

*   **How:** Add header:
    
    ```
    Access-Control-Allow-Credentials: true
    Access-Control-Allow-Origin: https://trusted.com
    ```
    
    *   **Do not** use `*` with credentials
    *   Always whitelist trusted origins

**Testing :**

*   Confirm that `Access-Control-Allow-Origin` is not `*` if `Allow-Credentials` is `true`.
*   Attempt a fetch in browser console:

```
fetch('https://t.com/api', { credentials: 'include' })
  .then(res => console.log(res));
```

If data is returned when origin is not trusted, CORS is misconfigured.

> [!NOTE]
> Enables cross-origin requests with credentials while enforcing origin restrictions to prevent session hijacking.

#### 3.10 Set-Cookie with Flags

We already covered cookies in section 2.5, here we will focus on the implementation.

*   Header Syntax:
    
    ```
    Set-Cookie: sessionId=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600
    ```
    
    *   **Secure** → only sent over HTTPS
    *   **HttpOnly** → not accessible via JavaScript
    *   **SameSite** → controls cross-site sending: Strict / Lax / None
    *   **Path / Max-Age** → scope and lifetime
*   **Implementation tips:**
    *   Always set **Secure** in production
    *   Default to **HttpOnly** for session cookies
    *   Use **Strict or Lax** for SameSite unless cross-site access is needed
*   **Testing:**
    *   DevTools → Application → Cookies → verify flags
    *   `document.cookie` → HttpOnly cookies **should not appear**
    *   Cross-site requests → check if cookie is sent only if SameSite allows
    *   Inspect network → confirm Secure cookies travel over HTTPS only

#### 3.11 Cache-Control / Pragma / Expires

*   **What:** These headers control how browsers and intermediate proxies store copies of responses. They determine **if, how long, and under what conditions content can be cached**.
    *   **Cache-Control** → modern, flexible caching rules (`no-store`, `no-cache`, `must-revalidate`)
    *   **Pragma** → `no-cache` for HTTP/1.0 backward compatibility
    *   **Expires** → forces content to expire immediately or at a specific date
*   **Why:** Prevents sensitive data (like PII, tokens, personal info) from being stored in browser or intermediate caches. For example data can leak through:
    
    *   Browser back/forward buttons
    *   Shared computers
    *   Proxy caches (corporate networks, ISPs)
    
    Examples:
    
    *   Session tokens in a cached page → attacker can grab them
    *   Personal info displayed on logout → stays in history
*   **How:** Add:
    
    ```
    Cache-Control: no-store, no-cache, must-revalidate
    Pragma: no-cache
    Expires: 0
    ```
    
    **Flags explained:**
    
    *   `no-store` → **never store content**, even temporarily
    *   `no-cache` → **must validate with server** before using cached content
    *   `must-revalidate` → enforce validation on every request
    *   `Pragma: no-cache` → backward support for old clients
    *   `Expires: 0` → content is immediately stale
    
    Combination ensures **modern and legacy browsers** respect your caching rules.
    
    **Implementation Tips:**
    
    *   Always use `no-store` for **sensitive pages** (tokens, PII, banking info)
    *   Combine with `no-cache` + `must-revalidate` for stricter control
    *   Include **Pragma** and **Expires** for compatibility with older HTTP clients
    *   Avoid caching sensitive API responses
*   **Testing :**
    *   Log in to a sensitive page → log out → hit “back” in browser → content should **not appear**
    *   DevTools → Network tab → verify headers are present and respected
    *   Test across browsers to ensure caching is actually blocked

> [!NOTE]
> Proper caching headers prevent sensitive data from being stored in browser or proxy caches, reducing exposure of tokens, PII, or session info.

#### 3.12 Cross-Origin-Embedder-Policy (COEP)

*   **What:** Governs whether a document can load cross-origin resources that do not grant permission via CORP/CORS. A resource might allow its usage by other servers but unless your COEP explicitly allows to accept data from that specific resource, it'll be blocked. 
    
    It has Two values:
    
    *   `unsafe-none`: Default, no restrictions.
    *   `require-corp`: Only loads cross-origin resources with `Cross-Origin-Resource-Policy` allowing inclusion.
    
    Essentially, it **forces a page to only embed “safe” external resources**, blocking any uncooperative cross-origin content.
*   **Why:** Ensures that a document can be safely used in cross-origin isolation contexts (important for SharedArrayBuffer, advanced features).
    *   Prevents attacks where a malicious cross-origin resource could interfere with sensitive data or browser memory.
    *   Adds another layer of defense in depth for sensitive applications.
*   **How:** Add:
    
    ```
    Cross-Origin-Embedder-Policy: require-corp
    ```
    
    *   Use `require-corp` to enforce strict embedding rules
    *   Only include resources that send proper CORP/CORS headers
*   **Testing :**
    *   Try loading a cross-origin script/resource **without a proper** **CORP/CORS** **header**. It should be blocked.
    *   Open DevTools → Console → check for **COEP-related errors**
    *   Verify that trusted resources with CORP/CORS headers still load

#### 3.13 Cross-Origin-Opener-Policy (COOP)

*   **What:** Tells the browser how your page interacts with other pages opened via `window.open()` in cross-origin scenarios. 
    
    Values:
    
    *   `unsafe-none`: Default, no restrictions.
    *   `same-origin`: Only allows pages from the same origin to access `window.opener`. Other origins get `null`.
    *   `same-origin-allow-popups`: Allows popups to open, but ensures `window.opener` is safe (other origins can’t mess with your page).
*   **Why:** Prevents cross-origin attacks that exploit `window.opener` . These attacks potentially can:
    *   Navigate your page to phishing URLs
    *   Access sensitive data in your page’s JS context
    *   Leak information between tabs
*   **How:** Add:

```
Cross-Origin-Opener-Policy: same-origin
```

**Testing :**

*   Open your page from a popup (`window.open()`) from a different origin.
*   If `same-origin` is set, `window.opener` should be `null`.
*   Check DevTools Console for COOP enforcement messages.

> [!TIP]
> Combine **COOP + COEP** to fully isolate your page, which is required for advanced features like **SharedArrayBuffer** and other cross-origin isolated APIs.

## **4\. SOP (Same-Origin Policy) and Header Role**

*   **What:** SOP is a fundamental security mechanism in browsers that restricts interactions between resources of different origins. Origin is the scheme + host + port, aka `https://a.com:443` ≠ `http://a.com` ≠ `https://api.a.com`
*   **Why:** Prevents malicious scripts from one origin reading or interacting with resources from another origin. Without it other sites would have ability to:
    *   Read your bank data
    *   Steal API responses
    *   Hijack sessions

> [!NOTE]
> Every modern web security model is built on SOP.

*   **How Headers Affect SOP/CORS: SOP** is enforced by the browser and will always DENY interactions from resources of different origins. However, Security headers _**can**_ allow some exceptions.
    
    Example:
    
    We're in [`https://evil.com`](https://evil.com) and we try to run this script:
    
    ```
    fetch("https://bank.com/api/balance")
    ```
    
    **Without headers:**
    
    *   Request may be sent
    *   Response arrives
    *   Browser blocks JS from reading it thanks to SOP
    
    But we can poke a hole in this system using headers. If `bank.com` responds with:
    
    ```
    Access-Control-Allow-Origin: https://evil.com
    ```
    
    Browser will think that the server explicitly allows that origin, and JS can read the response.

> [!IMPORTANT]
> **Important detail to not miss**
> 
> *   SOP is enforced by the **browser**
> *   CORS headers are **permissions**, not bypasses
> *   The server cannot force SOP off
> *   The browser decides if the hole is allowed
> 
> So:
> 
> *   No header → no hole
> *   Wrong header → no hole
> *   Overly broad header → huge hole
> 
> **CORS doesn't and cant disable SOP,it selectively relaxes SOP under explicit server-defined conditions.**

*   `Origin`: Provides the requesting origin for cross-origin requests.
*   `Access-Control-Allow-Origin`: Server’s response indicating which origins are permitted.
*   `Access-Control-Allow-Credentials`: Whether credentials can be included in cross-origin requests.
*   `Referrer-Policy`: Controls referrer information that could reveal origin data.
*   `Cross-Origin-*` headers (COOP, COEP, CORP): Hardens cross-origin interactions to prevent data leakage and side-channel attacks.

> [!TIP]
> **The tools for testing such as curl, Burp Suite, OWASP ZAP etc. will be discussed in next chapters!**
