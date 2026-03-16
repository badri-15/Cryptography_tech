# Cryptographic Techniques

A collection of cryptographic technique implementations as part of a Cryptography and Network Security lab. Each implementation demonstrates a core concept in modern cryptography using different programming languages.

---

## Diffie-Hellman Key Exchange
**Language:** HTML + JavaScript

### Definition
Diffie-Hellman is a cryptographic key exchange protocol invented by Whitfield Diffie and Martin Hellman in 1976. It allows two parties (commonly referred to as Alice and Bob) to independently compute a shared secret key over a public and insecure channel, without ever transmitting the secret itself. The security of this protocol is based on the mathematical hardness of the **Discrete Logarithm Problem** — given g, p, and g^a mod p, it is computationally infeasible to determine a for large values.

### How It Works
Both parties agree on two public parameters — a large prime number (p) and a generator (g). Each party then chooses a private secret, computes their public key using modular exponentiation, and exchanges it. Using each other's public key and their own private key, both parties independently arrive at the same shared secret.

```
Alice's Public Key     →  A = g^a mod p
Bob's   Public Key     →  B = g^b mod p
Alice's Shared Secret  =  B^a mod p
Bob's   Shared Secret  =  A^b mod p
Both values are equal  →  Shared Secret established!
```

### Significance
- First publicly known key exchange protocol — a landmark in cryptography history
- Enables secure communication over completely insecure networks
- No need to physically meet or pre-share keys between parties
- Forms the backbone of HTTPS, SSH, TLS, IPSec, and VPN protocols
- Evolved into ECDH (Elliptic Curve Diffie-Hellman) used in modern TLS 1.3

---

## VirusTotal Security API
**Language:** Python

### Definition
VirusTotal is a free online threat intelligence platform owned by Google that aggregates over 70 antivirus engines and URL/domain scanners to analyze suspicious files, URLs, IP addresses, and domains for malware and malicious content. The VirusTotal API v3 allows developers to programmatically submit and retrieve security analysis results, enabling automated threat detection within applications and security pipelines.

### Features Implemented
| Feature | Description |
|---|---|
| URL Scanning | Submits a URL and retrieves analysis from 70+ engines |
| File Scanning | Uploads a local file and checks it for malware |
| Hash Lookup | Identifies a file by its MD5 or SHA256 hash fingerprint |
| IP Reputation | Checks if an IP address is flagged as malicious |
| Domain Reputation | Checks if a domain is known for malicious activity |

### Techniques Used Internally by VirusTotal
- **Signature-based Detection** — Matches files against a database of known malware patterns
- **Heuristic Analysis** — Detects unknown threats by identifying suspicious behavior
- **Hash Fingerprinting** — Uses MD5/SHA256 to uniquely identify files without re-uploading
- **Reputation Scoring** — Rates URLs and IPs based on historical threat intelligence data

### Significance
- Provides access to 70+ security engines through a single API call
- Enables automated security scanning in CI/CD pipelines and applications
- Widely used in Security Operations Centers (SOC) and incident response workflows
- Hash lookup allows instant identification of known malware without uploading the file
- Free API tier makes it accessible for learning, research, and small-scale deployments

---

## Elliptic Curve Cryptography (ECC)
**Language:** Java

### Definition
Elliptic Curve Cryptography is a public-key cryptography approach based on the algebraic structure of elliptic curves over finite fields. An elliptic curve satisfies the equation **y² = x³ + ax + b**. Security is grounded in the **Elliptic Curve Discrete Logarithm Problem (ECDLP)** — given two points P and Q on the curve where Q = kP, it is computationally infeasible to find the scalar k. ECC achieves equivalent security to RSA but with significantly smaller key sizes, making it faster and more resource-efficient.

**Curve Used:** `secp256r1` (NIST P-256) — the industry standard curve used in HTTPS, TLS 1.3, Bitcoin, and SSL certificates.

### Three Operations Implemented

#### ECDH — Elliptic Curve Diffie-Hellman
A key agreement protocol that uses elliptic curve mathematics to allow two parties to derive an identical shared secret independently. Alice uses her private key with Bob's public key, and Bob uses his private key with Alice's public key — both arrive at the same secret without transmitting it.

#### AES-128 — Advanced Encryption Standard
A symmetric block cipher that encrypts data in 128-bit blocks using a shared key. The shared secret derived from ECDH is used as the AES key to encrypt and decrypt messages between the two parties. AES is the global standard encryption algorithm adopted by NIST and used in Wi-Fi security, banking, and file encryption.

#### ECDSA — Elliptic Curve Digital Signature Algorithm
A digital signature scheme that uses ECC to sign messages with a private key and verify them with the corresponding public key. It ensures authenticity (the message came from Alice), integrity (the message was not altered), and non-repudiation (Alice cannot deny sending it). Any tampering with the message causes verification to fail.

### ECC vs RSA — Key Size Comparison
| Security Level | RSA Key Size | ECC Key Size |
|---|---|---|
| 80-bit | 1024 bits | 160 bits |
| 112-bit | 2048 bits | 224 bits |
| 128-bit | 3072 bits | 256 bits |
| 256-bit | 15360 bits | 512 bits |

### Significance
- Provides the same level of security as RSA with far smaller key sizes
- Faster key generation, signing, and verification compared to RSA
- Ideal for resource-constrained environments — mobile devices, IoT, and smart cards
- Used in TLS 1.3, Bitcoin, Ethereum, Apple Pay, and modern Passkeys
- ECDSA is the standard for code signing, SSL certificates, and blockchain technology
- No external libraries needed in Java — fully supported by the built-in `java.security` package

---

## Summary

| Technique | Language | Core Algorithm | Real-World Usage |
|---|---|---|---|
| Diffie-Hellman Key Exchange | HTML + JavaScript | Discrete Logarithm | HTTPS, SSH, VPN, TLS |
| VirusTotal API | Python | Hash Analysis + Signature Detection | Antivirus, SOC, Threat Intel |
| ECC (ECDH + AES + ECDSA) | Java | Elliptic Curve Discrete Logarithm | TLS 1.3, Bitcoin, SSL, IoT |

---

## References
- Diffie-Hellman: https://en.wikipedia.org/wiki/Diffie-Hellman_key_exchange
- VirusTotal API Docs: https://developers.virustotal.com/reference
- ECC Overview: https://en.wikipedia.org/wiki/Elliptic-curve_cryptography
- Java Security Docs: https://docs.oracle.com/javase/8/docs/technotes/guides/security/
