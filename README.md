# Cybersecurity Guideline

> **Offensive security training for intermediate practitioners.**  
> Red team techniques, exploitation methodologies, and hands-on vulnerable labs—documented in public.

---


> [!CAUTION]
> The content in this repository is provided **strictly for educational, training, and defensive security research purposes**.  
> It describes techniques and concepts observed in real-world attacks to help developers, defenders, and security practitioners **understand and mitigate vulnerabilities**.  
>
> **You must NOT use any of the information, tools, techniques, or examples contained herein for illegal activity, unauthorized access, exploitation of systems you do not own, or any purpose outside of a controlled lab or authorized engagement.**  
>
> Unauthorized use of offensive security techniques can cause serious harm, violate laws in most jurisdictions, and may result in civil or criminal penalties.  
>
> By accessing or using this repository you acknowledge that:
>
> * All activities must be conducted in a **personal isolated lab, within a bug bounty scope with permission, or under written authorization**.  
> * The authors **assume no liability** for misuse, damages, or any legal consequences arising from actions taken based on these materials.  
> * You are **solely responsible** for ensuring compliance with applicable laws and approvals before testing.


## ⚠️ Who This Is For

This is **NOT** a beginner's guide.

**Prerequisites:**
- Comfortable with Linux command line and filesystem
- Basic programming knowledge (Python/Bash)
- Understanding of networking fundamentals (TCP/IP, DNS, ports)
- Knowledge of how web applications work (requests, responses, sessions)
- Familiarity with HTTP methods and status codes

If you're starting from zero, build foundations elsewhere first. This curriculum assumes technical literacy.

---

## 🎯 What This Is

A **red team focused** learning path covering offensive security from intermediate to advanced exploitation.

**Methodology:** Theory → Practice → Own Lab

Each module includes:
- **Phase 1:** Deep technical theory
- **Phase 2:** Hands-on exploitation practice
- **Phase 3:** Build and break your own vulnerable systems

**Perspective:** Attacker mindset. Understanding exploitation to build better defenses.

---

## 📚 Full Curriculum (In progress and changing)

---

## 🛠️ Tool Methodology

Progressive documentation of offensive security tooling and tradecraft.

**Coverage:**
- Burp Suite: Request interception, parameter manipulation, session analysis
- cURL: Protocol testing, header injection, authentication bypass
- Nmap: Service enumeration, version detection, NSE exploitation
- Metasploit: Exploit delivery, payload generation, post-exploitation
- SQLMap: Injection testing, database enumeration, blind exploitation
- Custom scripting: Automation patterns, API interaction, data parsing

Each methodology document includes:
- **Technical foundation**: What the tool does and why it matters
- **Security testing workflows**: How to use it for vulnerability discovery
- **Real exploitation examples**: Practical application against vulnerable targets
- **Common pitfalls**: What breaks, what fails, and how to troubleshoot

*Methodology docs are added as tools are mastered during module progression.*

---

## 🔬 Labs 

Custom Labs will be created progressively.

### **Module 1: Foundations**
**Theory:**
- HTTP request lifecycle
- HTTP request/response structure and flow
- Headers, cookies, sessions, tokens
- Security‑relevant headers and leakage
- CORS vs Same‑Origin Policy
- Browser‑enforced security boundaries
- Core web attack surfaces

**Practice:**
- HTTP request replay and mutation in Burp Suite
- Header, cookie, and method tampering
- Session reuse and fixation testing
- TCP stream reconstruction with Tshark
- DNS traffic analysis
- Nmap service/version detection + NSE scripting

---

### **Module 2: OWASP Top 10**
**Theory:**
- OWASP methodology and purpose
- Risk calculation (impact × likelihood)
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable and Outdated Components
- A07: Identification and Authentication Failures
- A08: Software and Data Integrity Failures
- A09: Security Logging and Monitoring Failures
- A10: Server-Side Request Forgery (SSRF)
- Mapping real-world vulnerabilities to categories

**Practice:**
- Identify OWASP category before exploitation
- Exploit and justify classification
- Propose and implement mitigations
- Re-test after fixes

---

### **Module 3: Injection Attacks**
**Theory:**
- SQL query construction and contexts
- String vs numeric injection
- Error-based SQL injection
- UNION-based SQL injection
- Boolean blind SQL injection
- Time-based blind SQL injection
- Prepared statements and parameterization
- Command injection mechanics
- Command chaining techniques
- NoSQL query logic and abuse vectors

**Practice:**
- Manual authentication bypass
- Database enumeration (columns, tables)
- Blind data extraction techniques
- Timing inference attacks
- Filter and WAF bypass
- Remote command execution

---

### **Module 4: Client-Side Attacks**
**Theory:**
- Browser parsing and execution rules
- JavaScript execution contexts
- Reflected XSS
- Stored XSS
- DOM-based XSS (sinks and sources)
- Encoding vs escaping
- Content Security Policy (CSP) logic and bypass
- CSRF attack flow and token mechanics
- SameSite cookie behavior
- Clickjacking techniques

**Practice:**
- Custom XSS payload development
- Filter and WAF bypass
- Cookie exfiltration
- CSP breaking attempts
- Manual CSRF payload construction
- Token bypass testing

---

### **Module 5: Authentication & Access Control**
**Theory:**
- Authentication vs authorization
- Password hashing vs encryption
- Salt implementation
- Rate limiting mechanisms
- Session identifier security
- Session fixation attacks
- JWT structure and claims
- IDOR (Insecure Direct Object Reference) patterns
- Horizontal vs vertical privilege escalation

**Practice:**
- IDOR enumeration and exploitation
- Session hijacking and reuse
- JWT claim manipulation
- Role-based access control abuse
- Brute force and credential stuffing

---

### **Module 6: Server-Side Attacks (SSRF & Advanced)**
**Theory:**
- SSRF routing and exploitation
- Internal service enumeration
- Cloud metadata endpoint attacks (AWS, GCP, Azure)
- SSRF filter bypass techniques
- XML External Entity (XXE) injection
- Server-Side Template Injection (SSTI)

**Practice:**
- SSRF to localhost exploitation
- Internal service probing
- Cloud metadata extraction
- XXE data exfiltration
- SSTI to RCE

---

### **Module 7: File Vulnerabilities**
**Theory:**
- Path traversal mechanics and encoding tricks
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)
- File upload validation failures
- MIME type vs file extension
- Web server execution rules
- Magic bytes and file signatures

**Practice:**
- Path traversal exploitation
- Sensitive file reads (/etc/passwd, config files)
- Upload filter bypass (MIME, extension, content)
- Webshell upload and execution
- LFI to RCE exploitation chains

---

### **Module 8: Network Security**
**Theory:**
- OSI model vs TCP/IP stack
- Man-in-the-Middle (MITM) attack flow
- ARP spoofing mechanics
- DNS poisoning techniques
- Firewalls (stateful vs stateless)
- IDS vs IPS (detection vs prevention)
- VPN basics and tunneling

**Practice:**
- ARP poisoning execution
- Credential interception (HTTP, FTP)
- Traffic manipulation and injection
- Detection evasion techniques
- Firewall rule analysis

---

### **Module 9: Cryptography**
**Theory:**
- Cryptographic hash functions
- Collision resistance importance
- Password storage best practices (bcrypt, Argon2)
- Symmetric encryption concepts
- Asymmetric encryption and key exchange
- TLS handshake process
- Certificate chains and validation
- Common cryptographic failures (weak algorithms, ECB mode, padding oracles)

**Practice:**
- Hash cracking (rainbow tables, dictionary attacks)
- Weak cryptography identification
- TLS connection inspection
- Downgrade attack analysis
- Padding oracle exploitation

---

### **Module 10: Integration & Kill Chain**
**Theory:**
- Penetration testing methodology
- Reconnaissance techniques
- Attack surface mapping
- Kill chain framework
- Threat modeling approaches
- Professional reporting standards

**Practice:**
- Timed full-scope CTF challenges
- Multi-stage exploitation chains
- Lateral movement techniques
- Privilege escalation paths
- Evidence collection and documentation

---

# 📂 Repository Structure
```
cybersecurity-guideline/
│
├── README.md
├── LICENSE
├── .gitignore
│
├── Module - X/
│   ├── README.md
│   ├── theory/
│   └── practice/
│   
├── Tool Methodology/
│   └── [Write up and tradecrafts of Security tools]
│
├── Labs/
│   └── [CTF, Labs and their solutions]
│
└── resources/
    └── [cheatsheets, references, wordlists, Lab Setups]
```

---

## ✍️ Articles

Simplified breakdowns and attack explanations published on Medium.

**Topics covered:**
- HTTP security deep dives
- Exploitation technique walkthroughs
- Real-world vulnerability analysis
- Defense and mitigation strategies

*Article links will be added as content is published.*

---

## 📊 Current Progress

- 🔄 **Module 1:** Foundations (In Progress)
- ⬜ **Module 2:** OWASP Top 10
- ⬜ **Module 3:** Injection Attacks
- ⬜ **Module 4:** Client-Side Attacks
- ⬜ **Module 5:** Authentication & Access Control
- ⬜ **Module 6:** Server-Side Attacks
- ⬜ **Module 7:** File Vulnerabilities
- ⬜ **Module 8:** Network Security
- ⬜ **Module 9:** Cryptography
- ⬜ **Module 10:** Integration & Kill Chain

**Last Updated:** December 31, 2024

---

## ⚖️ Legal Disclaimer

**All content is for educational and authorized testing purposes only.**

### Acceptable Use:
- Personal isolated lab environments
- Bug bounty programs (within defined scope)
- Authorized penetration testing engagements with written permission
- Academic and security research

### Prohibited Use:
- Unauthorized access to systems you do not own
- Testing without explicit written permission
- Any illegal activity

**Unauthorized computer access is a crime in virtually all jurisdictions.**

The techniques documented here are powerful and can cause significant damage if misused. The author assumes **no liability** for misuse, illegal activity, or damage caused by applying these techniques.

**You are solely responsible for ensuring your testing is legal and authorized.**

---

## 🤝 Contributing

This is primarily a personal learning journey, but community input is valued.

- **Found an error?** Open an issue with details
- **Have a better technique?** Start a discussion
- **Want to add resources?** Pull requests welcome
- **Security concern?** Contact privately

---

## 📬 Contact & Availability

**Freelance Services:**
- Technical cybersecurity content writing
- Penetration testing documentation
- Red team engagement reports
- Security tool development
- Vulnerability research write-ups

📧 email: martinsimonyan2563@gmail.com
📝 medium: https://medium.com/@aegis-martin
🐦 twitter: not here yet :)

---

## 📜 License

Licensed under the Apache License 2.0 - see [LICENSE](LICENSE) for full details.

**Summary:**
- ✅ Use freely for any purpose
- ✅ Modify and distribute
- ✅ Use commercially
- ⚠️ Must provide attribution
- ⚠️ Must state significant changes
- ⚠️ Includes patent grant protection

---

**Built with determination. Documented with transparency. Shared for education.**
