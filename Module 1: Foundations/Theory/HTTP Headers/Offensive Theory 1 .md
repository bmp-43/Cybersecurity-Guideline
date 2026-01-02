# HTTP Security Headers - Offensive Theory Part 1
## Custom and Standardized HTTP headers - Vary HTTP header

HTTP headers control how browsers and servers interact with data so vulnerabilities in them may affect the whole application. Headers can reveal running services, software versions, and programming languages employed by the application. Such details help in tailoring payloads and selecting appropriate attack methods for further testing or direct HTTP header exploitation.

Real-world examples are used to illustrate how header analysis contributes to vulnerability discovery.

Custom headers are the headers made exclusively for that specific application by their developer team. Usually their names start with `X-` But now it is more common to see regular names, BUT we can still verify if header is custom or standard.

##### Why Pay Attention?

There are multiple reasons on why custom made headers can be an interesting finding for VAPT. They are not standardized headers defined by RFC, so they lack strict specifications which VAPT team should be paying attention to.

*   **Tech stack fingerprinting**: frameworks, proxies, auth layers. Faster attack planning.
*   **Auth logic insight**: headers tied to roles, tokens, internal trust paths.
*   **Session handling clues**: custom session IDs, user mapping, tracking logic.
*   **Environment leaks**: staging, dev, internal hostnames. Those are softer targets.
*   **Attack chaining fuel**: combine header behavior with IDOR, CORS, cache poisoning, auth bypass.
*   **OSINT wins**: find backend code, configs, or comments explaining exactly how the app thinks.

> [!IMPORTANT]
> A header becomes security-relevant only when backend logic changes behavior based on its presence or value. It is crucial to note that custom headers spotting is not for finding the vulnerability itself, its a blood-trail that will potentially lead us to the security hole.

##### How to spot them?

While headers with X- at the beginning are obvious, others might be much harder, however, there are still tricks to do it, when we check headers of the site we must pay attention to these potential clues.

*   **Baseline first**: know common headers. Anything outside that set demands attention.
*   **Diff responses**: normal 200 vs 400/403/500. New headers popping up = custom.
*   **Trigger parser errors**: malformed paths, bad encoding, weird methods. Sloppy responses talk more.
*   **Proxy tools**: Burp, ZAP. Sort headers alphabetically. The odd names jump out.
*   **Repetition test**: hit another site. If the header only exists here, it’s custom.
*   **Name smell test**: words like `internal`, `debug`, `env`, `user`, `role`, `session` almost certainly are app specific headers.

After we identified a somewhat suspicious header name we must do a quick search to find information about that header, easiest way to do so is to use **Google Dorking**. Let's look at the example bellow.

```
HTTP/2 400 Bad Request
Server: Apache
X-Content-Type-Options: nosniff
Accept-Ranges: bytes
Vary: Accept-Encoding
X-REDACTED_Session: <redacted-value>
```

For instance, source code in Github repos sometimes includes elements that interact with custom headers. So if you identified the header ‘X-Internal-Token: secret-value’, you could use Google to search **(dork)** "X-Internal-Token" site:github.com”, which might then reveal hardcoded references in backend code, sample configs or .env files, or middleware or route handlers checking for the header.

Now we will get more technical.

1.  First let's curl to get the response from the server
    
    ```
    curl -v https://ipapi.co/json
    ```
    
    We are receiving a response from this request, we are interested in headers and they will be starting with `<` (this is exclusive for -v, aka verbose mode). In this case our headers are these
    
    ```
    < HTTP/2 200  
    < date: Sun, 28 Dec 2025 12:26:01 GMT 
    < content-type: application/json 
    < content-length: 724 
    < nel: {"report_to":"cf-nel","success_fraction":0.0,"max_age":604800} 
    < server: cloudflare 
    < allow: POST, OPTIONS, GET, OPTIONS, HEAD 
    < x-frame-options: DENY 
    < vary: Host, origin 
    < x-content-type-options: nosniff 
    < referrer-policy: same-origin 
    < cross-origin-opener-policy: same-origin 
    < content-security-policy-report-only: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://*.stripe.com https:/
    /*.paddle.com https://www.google.com https://www.gstatic.com https://maps.gstatic.com https://maps.googleapis.com https://www.google.co
    m/recaptcha/ https://www.gstatic.com/recaptcha/; style-src 'self' 'unsafe-inline' https://*.paddle.com https://fonts.gstatic.com https:
    //fonts.googleapis.com; img-src 'self' data: https://ipapi.co https://maps.gstatic.com https://maps.googleapis.com https://*.stripe.com
    ; font-src 'self' data: https://fonts.gstatic.com https://fonts.googleapis.com; frame-src 'self' https://www.google.com https://*.strip
    e.com https://*.paddle.com https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/; connect-src 'self' https://ipapi.
    co/ https://*.paddle.com https://*.stripe.com https://maps.googleapis.com https://www.google.com/recaptcha/; object-src 'none'; frame-a
    ncestors 'none'; base-uri 'self'; form-action 'self'; 
    < cf-cache-status: DYNAMIC 
    < report-to: {"group":"cf-nel","max_age":604800,"endpoints":[{"url":"https://a.nel.cloudflare.com/report/v4?s=sQ4siVO1FBc%2BTiiiF0Pbdpm
    CfyGC9qZysZyNKy3Nybcu2b5X8q9RqDleMmDLVEu2WK5lMVEgAGgekWTbBll5LCUu7cgo"}]} 
    < cf-ray: 9b510b2e3fc2dfb0-EVN
    ```
    
    As we can see here besides `X-` starting headers we also have `cf-ray` which is technically a custom header since its not standardized by RFC however in VAPT its still not application-defined because its used in a lot of infrastructures that rely on Cloudflare.
    
    In case we don't want to see other data and see headers only we should use `-I` instead of `-v` (verbose)
    
    ```
    curl -I https://ipapi.co/json
    ```
2.  Now let's see what we can find about this header using Google Dorking.
    
    If we try searching **“cf-ray”** we will find out that this is a Cloudflare HTTP header, otherwise knows as Ray ID, it's a hashed value that encodes information about the data center and the visitor's request.

Being standardized by RFC doesn't mean its pointless for VAPT, even if the header is technically _harmless._

1.  Run
    
    ```
    curl -I https://pokeapi.co/api/v2/pokemon/pikachu    
    ```
    
    We will see our headers
    
    ```
    HTTP/2 200 
    date: Sun, 28 Dec 2025 12:55:10 GMT
    content-type: application/json; charset=utf-8
    access-control-allow-origin: *
    cache-control: public, max-age=86400, s-maxage=86400
    nel: {"report_to":"cf-nel","success_fraction":0.0,"max_age":604800}
    etag: W/"3fa24-wbt3/8cXlN2gHJ6CC6+3DtEKJMc"
    server: cloudflare
    strict-transport-security: max-age=31556926
    traceparent: 00-56faeedd9ecb60dfdb9e51b1388e11f1-e62c36a9e5de6889-00
    x-cloud-trace-context: 56faeedd9ecb60dfdb9e51b1388e11f1/16585691631032625289
    x-country-code: DK
    x-orig-accept-language: fr-CH,fr-FR;q=0.9,fr;q=0.8,en-US;q=0.7,en;q=0.6
    x-powered-by: Express
    x-served-by: cache-bma-essb1270021-BMA
    x-cache: HIT
    x-cache-hits: 0
    x-timer: S1765974536.323588,VS0,VE1
    vary: Accept-Encoding,cookie,need-authorization, x-fh-requested-host, accept-encoding
    alt-svc: h3=":443"; ma=86400
    report-to: {"group":"cf-nel","max_age":604800,"endpoints":[{"url":"https://a.nel.cloudflare.com/report/v4?s=molvjxUnL%2FCIqKdhT9VYD5TeJlSmNtTBH2qW64VNUAijalKvMXuIrG7oIbq1faT%2BZEDgpTcmriHgsbsc460F8YmdmScyBaZd"}]}
    age: 1420
    cf-cache-status: HIT
    cf-ray: 9b5135e07e62e540-EVN
    ```
    
    Here let's focus on `traceparent` header.
2.  `traceparent` is a distributed tracing header. Harmless by itself but if dev was sloppy it can leak:
    
    1.  internal service structure
    2.  correlation IDs tied to logs
    3.  sometimes other trace headers get echoed back or logged publicly
    
    Its not a vulnerability, more like a **fingerprint / recon helper**. Depending on a specific case this can be a serious flag.

Now we will try a harder example:  
 

1.  First let's curl our target to check its response.
    
    ```
    curl -I -H "Authorization: Bearer fk-fakekey123" https://api.openai.com/v1/models
    ```
    
    Here we can find our headers.
    
    ```
    HTTP/2 401 
    date: Sun, 28 Dec 2025 13:14:16 GMT
    content-type: application/json
    content-length: 242
    www-authenticate: Bearer realm="OpenAI API"
    openai-version: 2020-10-01
    x-request-id: req_5a0f57ef8f4b4d9aa9c14502d0624925
    openai-processing-ms: 4
    x-envoy-upstream-service-time: 6
    x-openai-proxy-wasm: v0.1
    cf-cache-status: DYNAMIC
    set-cookie: __cf_bm=p4ywGRx4xaMlaxuz4UXqaKnbm8ZY8yCmW0OqqjgvuhU-1766927656-1.0.1.1-wAy4aXPRqSQltBMGwu2W4V0sASGrOCJq84YhCvjYpMFj93RTOamHjCpveseEt06O0BuzSaN4E5U5bLpq8vhKGCiDoZBVBBw7ld0U1pyy_j4; path=/; expires=Sun, 28-Dec-25 13:44:16 GMT; domain=.api.openai.com; HttpOnly; Secure; SameSite=None
    strict-transport-security: max-age=31536000; includeSubDomains; preload
    x-content-type-options: nosniff
    set-cookie: _cfuvid=xes5NHC5Vd__5iekCtUB9jbdZE0ElhGSdrfIJ9arLOg-1766927656089-0.0.1.1-604800000; path=/; domain=.api.openai.com; HttpOnly; Secure; SameSite=None
    server: cloudflare
    cf-ray: 9b5151ce5905dfb0-EVN
    alt-svc: h3=":443"; ma=86400
    ```
2.  We need to identify custom headers. Some of them have app specific names for OpenAI, Some outright start with `X-`. Our custom headers are:
    
    1.  openai-version: 2020-10-01
    2.  x-request-id: 56f45b37ee1ad46329aa8715b44a48e4
    3.  openai-processing-ms: 1
    4.  x-envoy-upstream-service-time: 4
    5.  x-openai-proxy-wasm: v0.1
3.  Finally we will perform a search to find data on these headers.
    
    Using google dorking we search our newly found headers. 
    
    1.  **openai-version: 2020-10-01**
        
        By searching: `"openai-version: 2020-10-01" site:github.com -inurl:issues`
        
        We identify that this is the version of the API we were sending request to. So now we know for what version try to find vulnerabilities.
    2.  **x-request-id: 56f45b37ee1ad46329aa8715b44a48e4**
        
        By searching: `"x-request-id" site:github.com "openai"` 
        
        We can find how is that header used and how is it interacting with our application of interest. Here we managed to find the 
        
        "openai-python" repository where we can find how is the header implemented: 
        
        "All object responses in the SDK provide a `_request_id` property which is added from the `x-request-id` response header so that you can quickly log failing requests and report them back to OpenAI."
        
        This is a snippet from the README if the repository.
        
        We can even find a code snippet where this header is used by searching:  
        
        `"x-request-id" site:github.com inurl:openai-python filetype:py`
        
        ```
        log.debug("request_id: %s", response.headers.get("x-request-id"))
        ```
    3.  openai-processing-ms: 1  
        By searching: `site:github.com “openai-processing-ms”`
        
        This is representing the server-side processing time in milliseconds (ms). In our case, it's a measly 1ms because it was a quick auth rejection—real AI queries spike higher.
        
        If we search: `site:github.com “openai-processing-ms” inurl:issues “2025” “dec”`   
        
        we can potentially have a chance to find recent bugs that may be exploitable.
    
    And so on. Here specifically no vulnerabilities are claimed, but they can be, in different cases that are close to this example.

Now we see repos where that header is used and can read its code, comments, questions, issues around them etc. This will help us understand what they do, and get us into the blood-trail. 

> [!TIP]
> Put a great attention to non 200 responses, especially 400 Bad Request. Custom headers usually appear when we make the server _**uncomfortable**_.

Now using the knowledge we have about HTTP headers we will cover other topics related to this subject. This Section covers techniques for exploiting weaknesses in HTTP headers, ranging from custom header abuse to cache poisoning and proxy misconfigurations.

### **Vary HTTP header**

The Vary HTTP response header tells caches which request headers must be considered when deciding whether a cached response can be reused. Without Vary cache will assume `Same URL = same response` That assumption is often wrong. Vary corrects it by saying: `Same URL + same listed header values = same response`. 

How does it do that? Well, Caches normally key on: `[HTTP method] + [URL]`, But when Vary exists, the cache key becomes: 

`[HTTP method] + [URL] + [values of headers listed in Vary]`. For example

```
Vary: X-Forwarded-Host, Origin
```

This means that the cache will be reused if `Cache key = / + value of X-Forwarded-Host + value of Origin`

> [!IMPORTANT]
> **It's Important to note what Vary doesn't do.**
> 
> *   It **does not validate** headers
> *   It **does not block** headers
> *   It **does not make things safe by itself**
> *   It **does not prevent the server from trusting bad input**
> 
> It only talks to caches.

##### **Red Team Perspective**

If a header appears in the Vary response header, it means the application uses that header when generating the response and that directly implies that server (backend) is looking for that header and it is part of the application logic, which is signal for the Red Team to keep an eye on that header.

We will focus on Examples now:

Example:

1.  First we will look at the server's response:
    
    ```
    HTTP/1.1 200 OK
    Server: Apache/2.4.37
    Vary: X-Forwarded-Host,Origin
    Content-type: text/html; charset=utf-8
    Connection: close
    Content-Length: 11512
    ```
    
    As we can see above, the response contains the `Vary` header, which comprises header values `X-Forwarded-Host` and `Origin`. Now we will leverage this information to test if the web application trusts user input
2.  We will send:
    
    ```
    curl -i https://example.com/ -H "X-Forwarded-Host: testing.com" 
    ```
    
    We receive this response from the server:
    
    ```
    HTTP/1.1 200 OK
    
    Server: Apache/2.4.37
    Vary: X-Forwarded-Host,Origin
    Content-type: text/html; charset=utf-8
    Connection: close
    Content-Length: 11509
    
    <!DOCTYPE html>
    <html>
    ...
    <script src="https://testing/assets/js/vendor/jquery-ui.custom.min.js"></script>
    ...
    </html>
    ```
    
    Sure enough, the response confirmed that the X-Forwarded-Host header is being reflected in the HTML and is likely being trusted by the application.
    
    This discovery paves the way to using the X-Forwarded-Host header to check for unexpected behaviors. Techniques such as spoofing, server-side request forgery (SSRF) and browser-powered desync attacks can potentially lead to **cache poisoning**. It might be possible to poison the cache if some responses use X-Forwarded-Host without including it in Vary.