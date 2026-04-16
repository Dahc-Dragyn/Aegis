Report Generated: 2026-04-13 22:22:37 UTC

**BLUF:**

We are experiencing two high-severity incidents: Active Directory enumeration potentially indicating reconnaissance activity and suspicious network traffic involving a Microsoft CryptoAPI client reaching out to an external OCSP server. Immediate investigation and containment actions are required.

**Active Threats:**

1.  **Active Directory Enumeration:** A security-enabled local group membership was enumerated from `we6922srv.waynecorpinc.local` by the SYSTEM account. This behavior is characteristic of reconnaissance activity, where an attacker is mapping the network to identify potential targets and vulnerabilities.

2.  **Suspicious Network Traffic:** Network traffic originating from `192.168.224.45` to `ocsp.msocsp.com`, with user agent `Microsoft-CryptoAPI/10.0`. The connection is using HTTP and receiving OCSP responses. Requires analysis to determine if the traffic is legitimate or indicative of compromised certificates or other malicious activity, despite the HTTP 200 OK status.

**Tactical Remediation:**

1.  **Active Directory Enumeration:**
    *   Initiate incident response procedures.
    *   Isolate `we6922srv.waynecorpinc.local` to prevent further potential data compromise.
    *   Investigate the svchost.exe process and any other processes spawned by it around the time of the event.
    *   Review system logs and network traffic for lateral movement or other indicators of compromise.
    *   Implement stricter access controls and monitoring for Active Directory objects.
    *   Consider deploying deception technology (honey accounts) to identify similar enumeration attempts.

2.  **Suspicious Network Traffic:**
    *   Investigate endpoint `192.168.224.45` for malware or other signs of compromise.
    *   Determine if the Microsoft-CryptoAPI client is behaving as expected and contacting legitimate OCSP servers.
    *   Analyze the OCSP responses received to check for revoked certificates or anomalies.
    *   If suspicious, block traffic to `ocsp.msocsp.com` and consider deploying a local OCSP responder for managed certificate validation.
    *   Inspect the certificate chain being validated by the client.
