# Burp Suite Methodology PART 1
## **Getting started with Burp Suite**

Burp Suite is a core offensive security platform used for manual web application testing. Here I will document Burp from a red team perspective, focusing on request analysis, attack surface discovery, and exploit development rather than automated scanning. For our target we will use DVWA (Damn Vulnerable Web Application). Check official repository if you're interested - [https://github.com/digininja/DVWA](https://github.com/digininja/DVWA)

> [!IMPORTANT]
> This write up is NOT a documentation and is not supposed to teach you every function of the tool, it is supposed to be showing actual Red Team methodology using Burp Suite, if your aim is to learn the tool specifically, it's recommended to use the actual documentation of the tool [Portswigger guide](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls).

## Intercepting a request

We will use Burp Proxy to intercept requests. Burp Proxy allows interception and modification of HTTP requests in transit, enabling visibility into parameters, headers, cookies, and server trust assumptions.

<figure class="image image-style-block-align-left"><img style="aspect-ratio:1915/1080;" src="img/Burp Suite Methodology PAR.png" width="1915" height="1080"></figure>

Click the Proxy tab then turn on the intercept. You will see the image in the middle say “Intercept is on”. Now every request performed by Burps browser will be shown here. Click “Open Browser” to open Chromium - Burp Suits built-in browser, it is preconfigured to work with with Burp Suite.

When we send a HTTP request Burp Suite will intercept it so the page wont load, and we can study the request. 

<figure class="image"><img style="aspect-ratio:1915/1080;" src="img/6_Burp Suite Methodology PAR.png" width="1915" height="1080"></figure>

Now we can study the request, and even **modify** it. We can see that currently its in **pretty** mode, but there are also Raw and Hex versions. So the request gets to the server we have to click forward. Logically you wont need to intercept every request so turn it off when you don't need it. Next to Intercept tab there's also **HTTP history tab** that we can use to check requests and responses that we already did.

> [!NOTE]
> At this stage, no exploitation is performed. The goal is to understand request structure, flow, and server responses before attempting manipulation.

**What browsers hide:**

When you click "login" in a browser, this happens invisibly:

1.  JavaScript may modify your input
2.  Hidden fields are added
3.  Headers are automatically set
4.  Request is sent

**You never see:**

*   What data is actually being sent
*   Which fields are validated client-side only
*   What the server actually receives

**Burp reveals this:**

```
POST /login.php HTTP/1.1
Host: localhost:8081
Content-Type: application/x-www-form-urlencoded

username=admin&password=password&user_token=abc123&Login=Login
```

**Security implications:**

*   `user_token` is a CSRF token - can we bypass it?
*   `Login=Login` is a hidden field - is it validated?
*   Client-side JavaScript might reject input - does the server also check?

**Attack surface questions:**

*   What happens if I remove `user_token`?
*   What if I change `Login` to something else?
*   What if I add extra parameters?

## **Modifying HTTP requests with Burp Proxy**

Now we will manipulate these requests in ways that the website isn't expecting, in order to see how it responds. 

In this technical write up we will focus on understanding the topic and develop a mindset of a Red Team. 

**Login:**

Go back to http://localhost:8081/login.php and turn **intercept** on. Now click login again.

<figure class="image"><img style="aspect-ratio:1920/1080;" src="img/1_Burp Suite Methodology PAR.png" width="1920" height="1080"></figure>

Using the previously identified login request, we now manipulate parameters to observe backend validation behavior. After doing so go to **HTTP history** and pick your request to see information about it and the response. _Don't forget to switch the “Original request” to "Edited request" to look at right thing._

<figure class="image"><img style="aspect-ratio:1920/1080;" src="img/5_Burp Suite Methodology PAR.png" width="1920" height="1080"></figure>

When we change the username or the password to wrong one we receive code 302 which redirects us back to login page. In addition if we change the **user\_token** we will also see that original body of the login page has changed, it now has following lines.

```
<div class="message">CSRF token is incorrect</div>
```

This confirms that DVWA enforces CSRF protection on the login endpoint and validates the token before credential processing. Authentication failure and CSRF failure are handled as separate conditions, each producing distinct server responses. Now you know how to modify requests in Burp Suite.

> [!TIP]
> HTTP History tab will be saving all the requests that happened in the browser including third party requests like Google Analytics and etc. They add noise and make our job harder, To prevent that add the Hosts of interest to **scope**.
> 
> To make this easier to read, keep clicking the header of the leftmost column (#) until the requests are sorted in descending order (to see the latest requests) then right click on the request and click **“Add to scope”**. You can manage the scope by going to **Target > Site map**.

### **Reissue requests with Burp Repeater**

In this section we will be using we will be using **Burp Repeater**  to send an _interesting request_ over and over again. This will allow us to study server response to different input without having to constantly use intercept every single request. We will dissect DVWA login page to determine how does CSRF token work in that application _exactly_.

#### **Step 1: Identify an interesting request**

An interesting request can be anything depending on the application, sometimes it's about a certain product like `GET /product` request with a `productId` query parameter or it can be related to the login, etc.

For us the interesting request is the  POST request that's being sent by the client to the server to login to the application

<figure class="image"><img style="aspect-ratio:1920/1080;" src="img/3_Burp Suite Methodology PAR.png" width="1920" height="1080"></figure>

Right click on it and click “Send to Repeater” The repeater tab will start blooming you can see your request there.

#### **Step 2: Understand how Repeater works**

<figure class="image"><img style="aspect-ratio:1920/1080;" src="img/4_Burp Suite Methodology PAR.png" width="1920" height="1080"></figure>

Here we see our request lets first send the original version, it will give us status 302 which means we're being redirected, next to send button “Follow redirection” button will appear, click it. after that we see the response confirming we are in index.php (this is the Home of the DVWA)

```
HTTP/1.1 200 OK
Date: Thu, 08 Jan 2026 11:02:52 GMT
Server: Apache/2.4.25 (Debian)
Expires: Tue, 23 Jun 2009 12:00:00 GMT
Cache-Control: no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 6864
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html;charset=utf-8


<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">

<html xmlns="http://www.w3.org/1999/xhtml">

	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />

		<title>Welcome :: Damn Vulnerable Web Application (DVWA) v1.10 *Development*</title>

		<link rel="stylesheet" type="text/css" href="dvwa/css/main.css" />

		<link rel="icon" type="\image/ico" href="favicon.ico" />

		<script type="text/javascript" src="dvwa/js/dvwaPage.js"></script>

	</head>

	<body class="home">
	...
```

Now we can resend this request as many times as we like and response will be new every time. Next to the same “Send” button click “<” to go back to our original request since it changed because of the redirection and session/cookie assignment. 

#### **Step 3: Modify the request in Repeater**

Finally we will edit the request to try different case scenarios to understand how the server works with CSRF tokens.

1.  **Case 1 - Missing token:**
    
    Edit the request like you did before and hit send → follow redirect like i showed earlier. We still receive status code 302 BUT this time were send back to /login.php with the response body containing `<div class="message">CSRF token is incorrect</div>`.
2.  **Case 2 - Wrong Token (Discussed previously):**
    
    After we send wrong token we receive the exact same response. Also interesting to point out that in the response body we can see a different CSRF token from the original one (happens every time), if we try that one we will still receive incorrect token message. _Interesting._
3.  **Case 3 - Malformed Token:**
    1.  How about we don't send just wrong token but a malformed one? I will use Chinese, Arabic Cyrillic letters and non ASCII symbols. In Burp those symbols will be rectangles or “?” that is not an error on your side Burp simply can't show it to you because it lacks fonts. The server response remains unchanged, indicating that CSRF validation is not influenced by character encoding or token format.
    2.  Browsers default to UTF-8 and server **expects it** but its not enforced. What if we change the encoding? To do so lets lie to the header and resend our malformed request.
        
        `Content-Type: application/x-www-form-urlencoded; charset=ISO-8859-1`. The key parts of the response are:
        
        ```
        HTTP/1.1 200 OK
        Date: Thu, 08 Jan 2026 11:28:37 GMT
        Server: Apache/2.4.25 (Debian)
        Expires: Tue, 23 Jun 2009 12:00:00 GMT
        Cache-Control: no-cache, must-revalidate
        Pragma: no-cache
        Vary: Accept-Encoding
        Content-Length: 1735
        Keep-Alive: timeout=5, max=100
        Connection: Keep-Alive
        Content-Type: text/html;charset=utf-8 <!--Server enforces UTF 8-->
        
        
        <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
        
        <html xmlns="http://www.w3.org/1999/xhtml">
        
        ...
        
        
        	<div class="message">You have logged in as 'admin'</div>
        	<div class="message">You have logged in as 'admin'</div>
        	<div class="message">CSRF token is incorrect</div>
        	<div class="message">CSRF token is incorrect</div>
        
        ...
        </html>
        ```
        
        Although the application does not redirect to the authenticated area, the presence of the ‘You have logged in as admin’ message confirms that authentication logic executed successfully and a session was established. Which means: **Authentication happens before CSRF token validation**. But why do we receive each message twice? This is the result of sloppiness of the “low” difficulty. The application processes authentication and CSRF validation without enforcing a strict execution order or terminating request processing on failure. As a result, both success and failure messages are generated and rendered multiple times within a single response.
    3.  Now lets check whether the  server has proper input-handling, aka we will poke the server's decoding to see if it has holes of its own. To do this we will try **Raw Binary Abuse**. To do so in the Repeater, when editing the request change the ‘Pretty’ presentation to ‘Raw’. Important to note that this technique will work best if the backend has C, C++  extensions, Legacy libraries or Mixed language stacks. Its not DVWA's case the technique remains valid for other applications.
        1.  **Null Byte injection:**
            
            This will tell us whether the backend treat's %00 as string terminator.
            
            For example lets use: `user_token=abc%00def`. Now the response body contains 2 “CSRF token is incorrect” messages again, which we already discussed. Note no auth this time.
        2.  **Invalid UTF‑8 sequences:**
            
            Sometimes this can cause a crash if parser is _really bad_. We will use `user_token=%C0%AF`. This time no interesting response was received.
        3.  **Control Characters:**
            
            ASCII control characters are **still** ASCII but _different_. `user_token=abc%0D%0Adef`. This is CRLF (The term CRLF refers to **Carriage Return (ASCII 13, \\r ) Line Feed (ASCII 10, \\n )**. They're used to note the termination of a line, however, dealt with differently in today's popular Operating Systems.) Response is the same.
        4.  **Size mismatch:**
            
            Here we will try to **lie** about the size of our content. Set `Content-Length` header to 1. Note that this is more effective in raw sockets, Burp Suite wont allow us to fully desync HTTP easily. Response is **double** message about CSRF token being incorrect.

**Observations Summary**

*   CSRF token presence and value are validated, but validation does not block authentication logic.
*   Character encoding manipulation does not influence CSRF validation.
*   Malformed, binary, and control-character input is normalized before validation.
*   No decoding or parsing vulnerabilities were identified.
*   Authentication executes prior to CSRF enforcement on low security configuration.

### **Conclusion and Tips**

These were specific examples, but there are **unwritten rules** when we analyse server behavior through HTTP Requests:

1.  **HTTP status code:**
    
    These are crucial for understanding backend logic.
    
    *   **200** → action likely succeeded or app failed open
    *   **302 / 301** → redirect, often auth or validation failure
    *   **401 / 403** → access control triggered
    *   **400** → input rejected early
    *   **500** → you broke backend logic (valuable)
2.  **Response body differences:**
    
    You don't need to check the whole response. 
    
    *   New error message?
    *   Different HTML block?
    *   Debug output?
    *   Same page but different content?
    
    Example we already saw:
    
    *   Invalid CSRF → explicit CSRF error
    *   Invalid credentials → generic login failure
3.  **Authentication state changes:**
    
    After forwarding a modified request, ask:
    
    1.  Am I still logged in?
    2.  Was I logged out?
    3.  Did my role change?
    4.  Did access persist?
4.  **Headers:**
    
    For example `Set-Cookie` can appear in **failed auth responses** too. Pay attention to
    
    *   **Is it a NEW session token?** (auth succeeded)
    *   **Is it the SAME token?** (auth failed, session persisted)
    *   **Is the token DELETED?** (session terminated)
    
    Other headers can give interesting information too.
5.  **What the server ignores:**
    
    Sometimes _nothing_ can be more useful than _something_
    
    *   Duplicate parameters (which one wins?)
    *   Case sensitivity in parameter names
    *   Content-Type manipulation (JSON → form-data → XML)
    *   HTTP verb changes (POST → PUT → PATCH)

Thanks to these you will be able to build a **mental security map.** Use this structure mentally or make your own:

1.  **Entry points:** **Login, Settings, Forms, API endpoints** - anything that changes state
2.  **For each entry point answer 4 questions:**
    1.  What controls access? **Session cookie, Token, Role, Nothing**?
    2.  What validation exists? **CSRF, Input length, Method check, Client-side only**?
    3.  What happens if input lies? **Silent fail, Explicit error, Partial Success**?
    4.  What does the server trust by default? This is a crucial one.

In next Burp-Suite Methodology tradecrafts we will focus on more offensive techniques.
