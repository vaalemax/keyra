# 🛡️ VaultShield — Secure Password Manager

A full-stack password manager built from the ground up to explore how production-grade
Java applications are actually structured — clean layering, defensive security design,
and the kind of decisions that matter once real users (and real attackers) are involved.

This is a personal portfolio project, not a toy CRUD app: every credential is encrypted
client-independent with AES-256, every login is protected against brute force, and every
sensitive action is recorded in a tamper-evident audit trail.

---

## 🎯 Why this project exists

Most portfolio projects demonstrate that you can build a working app. This one was built
to demonstrate something more specific: an understanding of **how security-critical
software is engineered** — encryption that can't be reversed by an admin with database
access, authentication that survives credential stuffing attempts, and a codebase
structured so that a new developer could safely extend it without breaking something they
didn't know was there.

It's also a practical study of clean architecture: keeping HTTP concerns in controllers,
business rules in services, and making sure logs, audit trails, and error handling follow
the same discipline throughout the codebase.

---

## ✨ Key Features

- 🔐 **Encrypted vault** — every stored password is encrypted with AES-256-GCM using a key
  derived from the user's own master password. The server never stores that key; it's
  re-derived at login and kept only for the session.
- 🔑 **Master password, never stored in reversible form** — hashed with BCrypt, exactly
  like any credential should be.
- 📱 **Two-factor authentication (TOTP)** — Google Authenticator–compatible, with QR code
  setup and one-time backup codes for account recovery.
- 🚦 **Brute-force protection** — IP-based rate limiting on login, registration, and
  sensitive endpoints, with stricter limits on high-risk actions.
- 📜 **Full audit trail** — every login, credential change, export, and security event is
  logged with timestamp, IP address, and outcome — visible to the user in a readable
  activity log.
- 🎲 **Password generator** — configurable length and character sets, built to encourage
  strong, unique passwords instead of reused ones.
- 📦 **Vault export/import** — portable backup of your credentials in a structured format.
- 🗂️ **Categorized credentials** — organize entries by category with at-a-glance
  statistics (total, secure, weak).
- 🔄 **Safe master password rotation** — changing your master password automatically
  re-encrypts every stored credential with the new key, atomically.

---

## 🏗️ Architecture & Design Principles

The application follows a **layered architecture** with a clear separation of concerns:

```
Controller  →  handles HTTP only (requests, redirects, form binding)
Service     →  owns business logic, validation, and orchestration
Repository  →  data access (Spring Data JPA)
```

Some of the deliberate engineering decisions behind this project:

- **Defense in depth** — validation happens at multiple layers (form binding, service-level
  checks) so the system stays safe even if called from somewhere other than the web UI.
- **No secrets in logs** — encryption keys, session tokens, and passwords are never written
  to application logs, even at debug level.
- **Fail securely** — cryptographic verification (AES-GCM authentication tags) rejects
  tampered or mismatched data outright, rather than silently returning corrupted results.
- **Database schema as code** — all schema changes are version-controlled and reproducible
  via Liquibase migrations, not manual SQL or "it worked on my machine" state.
- **Audit trail survives account changes** — security events remain traceable even after
  the account that generated them is modified or removed.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Language | Java 21 |
| Framework | Spring Boot 3 |
| Security | Spring Security 6, BCrypt, AES-256-GCM, TOTP (Google Authenticator) |
| Persistence | Spring Data JPA (Hibernate), PostgreSQL |
| Schema migrations | Liquibase |
| Web layer | Spring MVC, Thymeleaf |
| Build | Maven |
| Other libraries | Lombok, Jackson, ZXing (QR code generation), Google Authenticator library |

---

## 🔒 Security Highlights

This project treats security as a design constraint, not an afterthought:

- **Zero-knowledge-style encryption** — the master password is never stored; it's the only
  key that can unlock a user's vault, so even direct database access reveals nothing
  readable.
- **Two-factor authentication** with TOTP and single-use backup codes.
- **Rate limiting** to slow down brute-force and credential-stuffing attempts.
- **CSRF protection** enabled on all state-changing requests.
- **Content Security Policy, X-Frame-Options, and secure cookie flags** configured at the
  HTTP layer.
- **Full audit logging** of authentication events, credential changes, and security-sensitive
  actions.

> ⚠️ This is a portfolio/learning project, not an audited production system. See
> [Known Limitations](#known-limitations) below for an honest breakdown of what would need
> to change before real-world deployment at scale.

---

## 📸 Screenshots

*(add a few screenshots here — vault view, 2FA setup, audit log — this section sells the
project instantly to a non-technical reviewer)*

---

## 🚀 Running Locally

```bash
git clone https://github.com/<your-username>/vaultshield.git
cd vaultshield

cp .env.example .env
# edit .env with your local database credentials

mvn spring-boot:run
```

The app will be available at `http://localhost:8080`.

**Requirements:** Java 21, Maven, PostgreSQL.

---

## Known Limitations

Documented honestly, because knowing the limits of your own design is part of engineering
maturity:

- **Rate limiting is in-memory and per-instance.** Works correctly for a single-instance
  deployment; a horizontally scaled setup would need a shared store (e.g. Redis) for
  consistent limits across nodes.
- **CSP allows `'unsafe-inline'`** for a small number of server-rendered inline scripts
  (e.g. the countdown timer on the rate-limit page). A stricter, nonce-based CSP is a
  planned improvement.
- **Session-based key material.** The AES key used to decrypt the vault is derived at
  login and held in the HTTP session for the session's duration — standard for this
  architecture, but its lifetime is tied to session expiry rather than an independent
  policy.
- **IP detection trusts proxy headers**, which assumes a properly configured reverse proxy
  in front of the app in any real deployment.

---

## 📄 License

This project is available for portfolio/demonstration purposes.

---

Built by **Valerio Massimo Moretti** — [vm.moretti](#) · Software Engineer

## Setup
   Copy `.env.example` to `.env` (or export the variables directly) before running the app.

## Known Limitations

- **Rate limit cache cleanup is a full flush, not a per-key expiry.** `ScheduledTasks` 
  clears the entire in-memory rate-limit map every hour, rather than expiring individual 
  stale entries. This is simple and effective, but for a brief moment after each cleanup 
  all clients start with a fresh limit window, which is a minor fairness trade-off rather 
  than a security issue.

- **Content Security Policy allows `'unsafe-inline'` for scripts and styles.** A few 
  server-rendered pages use inline `<script>`/`<style>` blocks (e.g. the countdown timer 
  on the rate-limit page), which currently requires `'unsafe-inline'` in the CSP. This 
  weakens CSP's protection against injected inline scripts. A stricter CSP with 
  nonce-based script allowlisting is a planned improvement.

- **Session-based AES key storage.** The AES key used to decrypt vault entries is derived 
  at login and kept in the HTTP session for the duration of the authenticated session. 
  This is standard for this architecture, but means the key's lifetime is tied to session 
  timeout/invalidation rather than an independent expiry policy.

- **Single-server IP detection.** Client IP resolution trusts `X-Forwarded-For`/`X-Real-IP` 
  headers, which assumes a properly configured reverse proxy in front of the app. Running 
  this directly exposed to the internet without a trusted proxy in front would make IP-based 
  rate limiting spoofable.
