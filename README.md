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
