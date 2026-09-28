# ADR-008: Opaque server-side sessions

- Status: Accepted (session lifecycle and CSRF design completed in Phase 0.5)
- Date: 2026-09-28
- Related: [session-and-csrf.md](../../security/session-and-csrf.md), [crypto-decisions.md](../../crypto/crypto-decisions.md) CP-08, [data-flow.md](../data-flow.md) DF-01, T-08, T-12, T-13

## Context

The browser client needs authenticated API access. Revocation must take effect immediately (logout, a disabled account, suspected theft). Session age must be checkable for policy (PC-02, PC-03). Tokens must be out of reach of JavaScript, because an XSS is especially damaging in a client-side encryption application. Cookies are sent automatically, so the design must also defend against CSRF without relying on SameSite alone.

## Decision

- A session is a **256-bit random opaque token** in the cookie `__Host-cm_session`, with `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/` and no `Domain` attribute. The same settings apply in every environment. Development uses HTTPS through the local Nginx.
- The server stores only the **SHA-256 digest** of the token. With it, it stores the user, creation time, last activity, idle and absolute expiry, last password authentication, MFA verification time, step-up time, rotation time, IP address and user agent.
- **Lifetimes:** idle timeout 30 minutes, absolute lifetime 12 hours (CP-08). A separate 5-minute pre-authentication state covers only the MFA step of login.
- **Rotation:** a new token at login, after MFA verification, after step-up and after password or MFA changes. The server never accepts a token it did not issue.
- **Invalidation:** logout revokes the session on the server and clears the cookie. A password change, MFA change, vault reset or recovery-code login revokes the user's other sessions. Disabling the account, an administrator-assisted reset and a PLATFORM_ADMIN role change revoke all of them.
- **Concurrency:** at most 10 active sessions per user. The least recently used session is evicted, and every session can be listed and revoked.
- **CSRF:** SameSite=Strict is one layer. Every state-changing request, including login and registration, must also pass same-origin verification (`Sec-Fetch-Site`, otherwise an exact `Origin` match). It must use a JSON body and carry the `X-CipherMesh-Request` header. The API never grants CORS access with credentials (INV-19).

The full rules, tables and tests are in [session-and-csrf.md](../../security/session-and-csrf.md).

## Alternatives Considered

- **JWT access and refresh tokens in browser storage:** stateless verification, but readable by any XSS, hard to revoke before expiry, and exposed to algorithm-confusion mistakes.
- **JWT inside an HttpOnly cookie:** removes XSS theft of the token, but revocation still needs server state, so statelessness gives no benefit.
- **External identity provider with OpenID Connect:** a strong option for federation, but adds infrastructure or another runtime SaaS. Out of scope.
- **Synchronizer CSRF tokens:** not needed while the web client and API share one origin. They become mandatory if the client moves to another origin (see [session-and-csrf.md](../../security/session-and-csrf.md) section 8.2).
- **Passkeys (WebAuthn) as a factor:** stronger phishing resistance than TOTP. Tracked as OCD-11.

## Consequences

- One indexed database lookup per request, which is acceptable at this scale.
- The worker deletes expired sessions.
- CSRF and session behaviour need dedicated test suites.

## Security Implications

- Mitigates token theft through XSS (the token is unreadable), session fixation (rotation, and no unissued tokens accepted) and replay after logout (server-side revocation) (T-08).
- Mitigates CSRF and login CSRF independently of SameSite (T-13). It does not help against XSS, which runs same-origin (T-12).
- A stolen session still cannot decrypt content, because unlocking the vault needs the Vault Passphrase.

## Status

Accepted.
