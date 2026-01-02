# Module 1: Foundations

This module builds the technical foundation required for web application security testing.  
Focus is placed on how HTTP works internally, how browsers enforce security, and where real-world attack surfaces emerge.


> [!CAUTION]
> The following material is intended for **educational and defensive security research purposes only**.  
> It describes techniques observed in real-world attacks to help developers, defenders, and security practitioners understand and mitigate **cache poisoning vulnerabilities**.  
> **No authorization or encouragement for illegal activity is implied.**

## Theory
Covers the core mechanics of web communication and security boundaries:
- HTTP request lifecycle
- Request and response structure and flow
- Headers, cookies, sessions, and tokens
- Security-relevant headers and information leakage
- CORS vs Same-Origin Policy
- Browser-enforced security boundaries
- Core web attack surfaces

## Practice
Hands-on interaction with live traffic and protocols:
- HTTP request replay and mutation using Burp Suite
- Header, cookie, and HTTP method tampering
- Session reuse and fixation testing
- TCP stream reconstruction with Tshark
- DNS traffic analysis
- Nmap service and version detection with NSE scripting

## Lab
Applied experimentation and failure-driven learning:
- Build a minimal web service with custom logging
- Send malformed and edge-case requests
- Observe failures, fix issues, and re-test iteratively

---

By the end of this module, the student should understand **how web traffic actually behaves**, **where security assumptions fail**, and **how attackers interact with applications at the protocol level**.
