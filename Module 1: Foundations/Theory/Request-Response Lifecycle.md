# Request-Response Lifecycle

When we send a HTTP request we receive our response almost immediately, but is that process actually that easy? What's happening behind the scenes? In this Article I will explain the full life-cycle of HTTP.

> [!IMPORTANT]
> This is not a complete beginner friendly material its recommended to have prior minimal web/security experience.

#### **Step 1 - Client Prepares HTTP/HTTPS Request**

The client (browser or application) prepares an HTTP or HTTPS request for the required resource (HTML, image, file, or API endpoint). The request includes:

*   **URL** – the resource location
*   **Method** – GET, POST, or other HTTP methods
*   **Headers** – Host, User-Agent, Accept, Cookie, and others
*   **Body** – present for POST requests or when sending data

For HTTPS, encryption setup begins here, preparing the request for a secure transmission. This step initiates the lifecycle of the HTTP request.

#### **Step 2 - Local DNS Resolver \[Request\]**

The client relies on the local DNS resolver to convert the requested domain into an IP address. The resolver first checks the local cache. If the IP is not cached, the query is forwarded to recursive DNS servers.

Key points:

*   The local resolver abstracts the DNS process for applications.
*   Caching improves performance and reduces unnecessary external queries.
*   Understanding this step helps troubleshoot network issues and ensures the client can locate the server efficiently.

#### **Step 3: Recursive DNS Servers \[Request\]**

  
If the local DNS doesn't have the IP address you're looking for, the query is sent to a series of DNS servers. These are usually managed by your ISP (Internet Service Provider) or another third-party provider. The recursive DNS servers have their own caches, and if they can't satisfy the request, they'll talk to root DNS servers, followed by TLD (Top-Level Domain) servers and finally the authoritative DNS servers for the domain. This is a hierarchical structure and often takes several steps.  
**DNS Resolution Hierarchy & Steps:**

1.  **Local DNS Resolver (your computer)**
    *   Checks local cache for the domain-IP mapping.
    *   If found → return IP. If not → forward query.
2.  **Recursive DNS Server (ISP or third-party)**
    *   Has its own cache; checks if it knows the IP.
    *   If found → return IP. If not → continue up the hierarchy.
3.  **Root DNS Servers**
    *   The “top of the Internet” directory.
    *   Don’t know IPs themselves, but direct the query to the correct **TLD servers**.
4.  **TLD (Top-Level Domain) DNS Servers**
    *   Example: `.com`, `.org`, `.net`.
    *   Provide the authoritative DNS server for the requested domain.
5.  **Authoritative DNS Servers**
    *   Hold the final IP address for the domain.
    *   Return the IP back down the chain.
6.  **Response Back to Client**
    *   Recursive DNS → local resolver → your computer → browser uses IP to connect.
    *   Along the way, caches store the IP for faster future requests.

Each query might also involve multiple DNS servers before finally getting the correct IP address. Once the IP address is found, it's returned to the client and stored in the local cache for future use. Recursive DNS servers are vital cogs in the DNS architecture, connecting local queries to the global DNS infrastructure.

#### **Step 4: ARP Basics (Local Network Only) \[Request\]**

After DNS gives the target IP (or gateway IP), if the next hop is on the local network, the client needs the MAC address for layer 2 delivery. It uses ARP (Address Resolution Protocol):

*   **ARP Request:** Broadcast "Who has this IP? Tell my MAC address."
*   **ARP Reply:** The device with that IP responds with its MAC address.
*   **Cache:** The MAC-IP mapping is stored in the ARP table for quick reuse.

**Key points:**

*   ARP only happens on local LAN segments (not across internet routers).
*   Essential for Ethernet/Wi-Fi framing—packets need destination MAC.
*   Attacks like ARP spoofing poison this cache for MITM.

Summary: ARP bridges layer 3 (IP) to layer 2 (MAC), letting packets leave your machine properly on local networks.

#### **Step 5: TCP & SSL/TLS Handshake (if HTTPS) \[Request\]**

Before any data is securely transmitted, the client must first establish a reliable connection with the server using the **TCP three-way handshake**:

*   **SYN** – client sends a connection request to the server.
*   **SYN-ACK** – server acknowledges the request and agrees to connect.
*   **ACK** – client confirms, completing the TCP connection.

Once the TCP connection is established, the **TLS handshake** begins to secure the session. This sets up encryption so all subsequent HTTP data is protected:

**TLS 1.3 Handshake Steps:**

*   **ClientHello** – client proposes protocol version, cipher suites, and key share.
*   **ServerHello** – server selects protocol and cipher, returns its key share.
*   **EncryptedExtensions** – server sends additional negotiated parameters (encrypted).
*   **Certificate** – server (and optionally client) sends X.509 certificate chain.
*   **CertificateVerify** – proves possession of the private key for the certificate.
*   **Finished** – final handshake integrity check (both sides).
*   **NewSessionTicket** – optional post-handshake ticket for session resumption.

**Phases of TLS Handshake:**

*   **Hello phase → ClientHello + ServerHello**: agree on protocol version, cipher suites, and random values.
*   **Key exchange / authentication phase → EncryptedExtensions + Certificate + CertificateVerify**: server proves identity, keys are exchanged, client may authenticate.
*   **Finished phase → Finished (+ optional NewSessionTicket)**: handshake verified, encrypted session starts.

**Key point:** After this step, **all HTTP/HTTPS data sent over this connection is encrypted**, protecting sensitive information like passwords, payment info, and personal details.

Now the connection is secure and ready.

#### **Step 6: ISP Kickoff & Initial Transit \[Request\]**

  
After the connection is established, packets containing the HTTP request begin their journey across the internet, starting with the **Internet Service Provider (ISP)**. The ISP serves as the primary gateway, routing data through its high-speed backbone networks and peering points.

This phase marks the transition from local network to global internet routing, where **latency**, **bandwidth** limitations, and **routing policies** often become noticeable.

**Key ISP Functions:**

*   Utilizes **Border Gateway Protocol (BGP)** for inter-domain routing decisions, peering agreements, and prefix announcements.
*   Dynamically selects paths based on congestion, outages, cost optimization, or geopolitical factors.
*   May apply **traffic shaping**, QoS prioritization, or throttling (common on consumer plans for P2P or video streaming).
*   Early **deep packet inspection (DPI)** or **carrier-grade NAT (CGNAT)** possible for security, monitoring, or IPv4 conservation.
*   Potential injection of headers (e.g., X-Forwarded-For in some transparent proxies).

#### **Step 7: Deep Routing Through Routers & Nodes \[Request\]**

Packets proceed through the core internet infrastructure, traversing multiple **autonomous systems (AS)** and network hops across global backbones.

**Key Routing Actions:**

*   Core **routers** analyze the **destination IP address** against massive routing tables (hundreds of thousands of prefixes).
*   Forward packets along optimal paths using **IGP** protocols like **OSPF/IS-IS** (interior) and **BGP** (exterior).
*   Paths adapt in real-time via route reflection, confederations, or anomaly detection (e.g., RPKI validation against hijacks).
*   Typical requests involve **15–30 hops**; high-latency paths (e.g., transoceanic) can exceed 100ms round-trip.
*   Common issues: packet loss from congested peering points or asymmetric routing.

Tools like **traceroute** or **mtr** reveal this multi-hop process, highlighting potential points of delay or failure.

#### **Step 8: Firewalls En Route \[Request\]**

Packets encounter multiple **firewall** and security appliance instances throughout the transit path, providing defense-in-depth screening.

**Key Firewall Operations:**

*   **Stateful packet inspection (SPI)** tracks connection states (NEW, ESTABLISHED, RELATED) and allows only valid TCP flows.
*   **Rule-based filtering** on source/destination IP, ports, protocols, payload signatures, or geolocation.
*   Detection and blocking of common threats (e.g., SYN floods, port scans, malformed packets, known exploit signatures).
*   Distributed deployment: client-side (host firewall), ISP-level, cloud provider (e.g., AWS Security Groups), and server-side WAF.
*   Advanced features: application-layer inspection (Layer 7), rate limiting, or bot mitigation.

Effective firewall chaining significantly reduces the **attack surface** and blocks reconnaissance before requests reach the application.

#### **Step 9: Cache Servers & CDN Check \[Request\]**

**Distributed caching** layers intercept requests to potentially serve content without reaching the **origin server**, dramatically improving performance.

**Key Caching Mechanisms:**

*   **Content Delivery Networks (CDNs)** (Cloudflare, Akamai, Fastly) store static assets at thousands of edge **Points of Presence (PoPs)** worldwide.
*   **Cache hit**: Immediate delivery of immutable content (images, CSS, JavaScript, videos) from geographically closest node.
*   **Cache miss**: Forward to origin; response headers (**Cache-Control**, **Expires**, **ETag**, **Last-Modified**) dictate storability and TTL.
*   Validation techniques (**If-None-Match**, **If-Modified-Since**) prevent stale delivery while minimizing origin hits.
*   Security benefits: DDoS mitigation, TLS edge termination, WAF integration.

CDNs are critical for reducing **latency** on high-traffic sites, cutting origin load by 70–90% for static assets.

#### **Step 10: Server-Side Load Balancer \[Request\]**

Upon reaching the destination network, a **load balancer** (hardware or software) distributes incoming traffic across backend servers for scalability and resilience.

**Key Distribution Features:**

*   Algorithms: **round-robin**, **least connections**, **weighted**, or **IP hashing/content-based** for session persistence.
*   Continuous **health monitoring** via HTTP probes, TCP checks, or custom scripts to exclude unhealthy instances gracefully.
*   **Layer 7** capabilities enable deep HTTP inspection for routing based on path, headers, or cookies.
*   Common **TLS termination** or passthrough; offloads CPU-intensive cryptography from backends.
*   Advanced: global server load balancing (GSLB) across data centers using DNS.

Load balancers enable **horizontal scaling**, **high availability**, and zero-downtime deployments in modern web architectures.

#### **Step 11: OS Network Stack on Server \[Request\]**

The selected backend server receives packets, where the **operating system kernel** processes them before delivery to the application process.

**Key Kernel Responsibilities:**

*   **Reassembly** of fragmented (IP fragmentation) or out-of-order packets into coherent TCP streams.
*   **Checksum verification** (IP header, TCP segment) and error detection to discard corrupted data silently.
*   Application of final local firewall rules (e.g., **iptables/nftables**, **ebtables** on Linux; pf on BSD).
*   Efficient handoff to the correct user-space process via **socket queues** and epoll/kqueue mechanisms.
*   Congestion control via TCP algorithms (Cubic, BBR) and buffer management.

Modern kernels optimize this with **zero-copy**, GRO/GSO offloading, and interrupt coalescing for minimal overhead under high load.

#### **Step 12: Application Processing, Logic & Response Build \[Response\]**

The web application (or reverse proxy like Nginx) receives the parsed HTTP request and executes all required processing before constructing the response.

**Parsing and Middleware Stages:**

*   Extraction of **method** (GET/POST/etc.), **path**, **query parameters**, headers (**User-Agent**, **Cookie**, **Authorization**, **Host**), and **body** content (multipart, JSON).
*   Middleware execution for **logging** (access/error logs), **authentication/authorization** (sessions, JWT, OAuth), **rate limiting**, **input validation/sanitization**, and **CSRF protection**.

**Core Logic and Data Retrieval:**

*   Routing to appropriate handler based on URL pattern (e.g., MVC frameworks, API gateways).
*   Business logic execution, including external API calls, computations, or third-party integrations.
*   Data access from **databases** (SQL/NoSQL with prepared statements to prevent injection), **caches** (Redis/Memcached for hot data), file systems, or cloud storage (S3/GCS with signed URLs).

**Response Construction:**

*   Determination of **status code** (e.g., 200 OK, 301 Redirect, 404 Not Found, 429 Too Many Requests, 500 Internal Server Error).
*   Assembly of headers (**Content-Type**, **Content-Length**, **Set-Cookie**, **Cache-Control**, **Location**, **X-RateLimit**).
*   Body generation (templated HTML via engines like Jinja, JSON serialization, binary streams).

The response then travels back through the OS stack, load balancer, caching layers (potentially stored with fresh headers), reverse routing/firewalls, and ISP to the client, where the browser decrypts (if HTTPS), processes headers, and renders content—completing the cycle while triggering additional requests for sub-resources (images, scripts, etc.).
