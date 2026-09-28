# Session and CSRF Security

Status: Phase 0.5 design. Normative. Implementation: Phase 3 (CM-T016, CM-T017, CM-T020, CM-T021). Related: [ADR-008](../architecture/adr/ADR-008-server-side-sessions.md), [trust-boundaries.md](../architecture/trust-boundaries.md) TB-02, [threat-model.md](../threat-model/threat-model.md) T-08 and T-13, parameter register CP-08.

## 1. Summary

- Sessions are opaque 256-bit random tokens. The server stores only their SHA-256 digest.
- The cookie `__Host-cm_session` is HttpOnly, Secure, SameSite=Strict and scoped to the whole origin.
- Tokens rotate after authentication and security-sensitive events. Idle expiry, absolute expiry, logout and password changes invalidate sessions on the server.
- **SameSite does not solve CSRF on its own.** It is one layer. The API also verifies that every state-changing request comes from the CipherMesh origin, requires a JSON body and a custom request header, and never grants CORS access with credentials. Login and registration get the same checks.

## 2. Token and cookie

| Property | Value | Reason |
|---|---|---|
| Token | 32 bytes from the server CSPRNG, base64url encoded | Unguessable, carries no data |
| Server storage | SHA-256 of the token | A database copy yields no usable tokens. A fast hash is enough because the token has 256 bits of entropy |
| Cookie name | `__Host-cm_session` | The prefix forces `Secure`, `Path=/` and no `Domain`, which blocks cookie injection from other subdomains |
| `HttpOnly` | Set | Scripts cannot read the token. An XSS can still act inside the page (T-12) |
| `Secure` | Set in every environment | HTTPS only |
| `SameSite` | `Strict` | Not sent on any cross-site request, including top-level navigations |
| `Max-Age` | Remaining absolute lifetime | The browser discards the cookie when the server-side session ends anyway |

**Why SameSite=Strict fits this application.** The web client is a static export (ADR-011). Its HTML and scripts need no cookie. Every authenticated call is a same-origin `fetch()` made by the loaded page, which is a same-site request, so the cookie is sent. A link from email or chat into CipherMesh loads the static page, and the page's own requests then carry the cookie. Strict therefore costs no usability. This depends on never serving authenticated server-rendered pages.

**Same settings in every environment.** Local development and E2E tests run behind the local Nginx over HTTPS with a locally trusted development certificate. The `__Host-` prefix requires `Secure`, and browsers differ in how they treat `Secure` cookies on plain `http://localhost`. The API refuses to start with any other cookie configuration. There is no "insecure cookie" switch.

## 3. Lifetimes

| Timer | Value | Rule |
|---|---|---|
| Idle timeout | 30 minutes (CP-08) | `lastSeenAt` is updated on authenticated requests, at most once per minute. A request after idle expiry revokes the session and returns 401 |
| Absolute lifetime | 12 hours (CP-08) | Counted from password authentication. Activity never extends it |
| Pre-authentication state (MFA pending) | 5 minutes | Separate cookie `__Host-cm_preauth` with the same attributes. Valid only for the MFA endpoints, single use, at most 5 code attempts |
| Step-up validity | 15 minutes, 5 minutes for profile downgrades | See [security-policy-profiles.md](security-policy-profiles.md) |
| Profile freshness | 12 hours, 4 hours or 1 hour | PC-02, per room profile |

## 4. Rotation and invalidation

Rotation means the server issues a new random token, replaces the stored digest and records `rotatedAt`. The old token stops working immediately. The server never accepts a session identifier it did not issue, so a token planted before login is never promoted (session fixation, T-08).

| Event | Current session | Other sessions of the user | Audit event |
|---|---|---|---|
| Login without MFA | New token; any cookie sent with the request is ignored and replaced | Unchanged | `LOGIN_SUCCEEDED` |
| Login with MFA | Pre-authentication state consumed; new session token after the code is verified | Unchanged | `LOGIN_SUCCEEDED` |
| Step-up | Rotated | Unchanged | `STEP_UP_COMPLETED` |
| Password change | Rotated | Revoked | `PASSWORD_CHANGED` |
| MFA enabled or disabled | Rotated | Revoked | `MFA_ENABLED`, `MFA_DISABLED` |
| Login with a recovery code | New session | Revoked | `RECOVERY_CODE_USED` |
| Vault reset (new identity key) | Rotated | Revoked, because they may hold the old private key in memory | `VAULT_RESET` |
| PLATFORM_ADMIN granted or removed | Not applicable (server-side CLI) | All revoked | `PLATFORM_ROLE_CHANGED` |
| Account disabled or administrator-assisted reset | Not applicable | All revoked | `ACCOUNT_DISABLED`, `ADMIN_RESET` |
| Logout | Revoked | Unchanged | `LOGOUT` |
| "Sign out other sessions" | Unchanged | Revoked | `SESSIONS_REVOKED` |
| Session limit exceeded at login | New session created | Least recently used session revoked | `SESSION_EVICTED` |

Changes of room membership or role do not touch sessions. Authorization reads membership from the database on every request.

## 5. Logout

1. The client calls `POST /api/auth/logout`, which passes the CSRF checks like any other state change.
2. The server revokes the session row and answers with a cookie deletion (`Max-Age=0`, same attributes).
3. The client locks the vault, drops decrypted content and clears in-memory caches.
4. If the server is unreachable, the client still locks locally. The server session then ends through its timers.

## 6. Concurrent sessions

- Several devices may be signed in at once. At most 10 sessions per user are active (CP-08). A login beyond the limit revokes the least recently used session and records an audit event.
- The session list shows each session's browser and operating system (from the user agent), creation and last activity time, and an IP address subject to retention limits. Each session can be revoked individually, and "sign out other sessions" revokes all but the current one.
- A single-session mode per room profile was considered and rejected. It adds friction without protecting content, because decryption needs the Vault Passphrase anyway.

## 7. Password change policy

Changing the password requires the current password, plus a current TOTP code when MFA is enabled. The new password must meet CP-06. The server stores a fresh Argon2id hash, rotates the current session and revokes all others. The vault is unaffected, because the Vault Passphrase is a separate secret (CD-01).

## 8. CSRF design

### 8.1 Why SameSite is not enough on its own

- SameSite is based on the site (the registrable domain), not the origin. Any other host under the same site counts as same-site.
- Behaviour differs across browsers and versions, and older browsers ignore the attribute.
- There is no session cookie yet during login, so SameSite cannot prevent login CSRF.
- A later change, such as a subdomain or a separate frontend origin, could silently remove the protection.

### 8.2 Layers

1. **SameSite=Strict** on the session cookie.
2. **Same-origin verification** on every state-changing request (POST, PUT, PATCH, DELETE), including registration, login, MFA verification and logout:
   1. If `Sec-Fetch-Site` is present, only `same-origin` is accepted.
   2. Otherwise, if `Origin` is present, it must equal the configured application origin exactly (scheme, host and port). `Origin: null` is rejected.
   3. If neither header is present, the request is rejected. Every browser on the supported list (fixed in Phase 1) sends at least one of them for such requests. Non-browser clients are not supported for state-changing endpoints.
3. **Request shape.** The body must be `application/json` (anything else returns 415), and the request must carry the header `X-CipherMesh-Request: 1`. A browser cannot add a custom header to a cross-origin request without a CORS preflight, and the API never approves one.
4. **No state changes on GET or HEAD.** State-changing routes reject those methods, and a route test checks that GET handlers have no side effects.
5. **No CORS.** The API sends no `Access-Control-Allow-Origin` header and never allows credentials cross-origin.

**Referer is not used.** The application sends `Referrer-Policy: no-referrer`, so browsers omit the `Referer` header. Under the Fetch standard, the same policy makes browsers send `Origin: null` for HTML form submissions but the real origin for `fetch()` requests in their default mode. The client therefore never submits forms and uses `fetch()` for every state change. Phase 3 tests confirm this behaviour in Chromium, Firefox and WebKit.

**Synchronizer tokens.** A per-session CSRF token is not required in this same-origin design, because layers 2 and 3 are strong and independent of SameSite. It becomes mandatory if the web client ever moves to a different origin, because CORS with credentials would then be enabled. That change would need an ADR that adds a session-bound token and an exact CORS allowlist.

### 8.3 Login CSRF

Registration, login and MFA verification go through the same checks. Another site therefore cannot sign a victim into an attacker-controlled account and trick them into uploading content there.

### 8.4 Limits

A script running in the CipherMesh origin passes every CSRF check, because its requests really are same-origin. XSS is handled by CSP, text-only rendering and the other controls in T-12.

### 8.5 Failure handling

Failed checks return 403 `ORIGIN_REJECTED` (or 415 for the content type) before any handler runs, so there are no side effects. The log records the reason code, route and received `Origin` value. It never records cookies or bodies.

## 9. Related protections

- **Clickjacking:** `frame-ancestors 'none'` in the CSP, plus `X-Frame-Options: DENY` for older browsers.
- **Caching:** API responses carry `Cache-Control: no-store`.
- **Transport:** HSTS and TLS settings from [../cloud/deployment-architecture.md](../cloud/deployment-architecture.md).

## 10. Tests

| Suite | Cases |
|---|---|
| `session` | Cookie attributes and prefix; token length; only the digest is stored; each rotation and invalidation event in section 4; idle and absolute expiry; logout clears the cookie and revokes the row; a planted cookie is not promoted at login; the 11th session evicts the least recently used; pre-authentication cookie scope, expiry and attempt limit |
| `csrf` | Cross-site form posts (url-encoded, multipart, `text/plain`) rejected; foreign-origin `fetch()` rejected; missing custom header rejected; `Sec-Fetch-Site: cross-site` and `same-site` rejected; `Origin: null` rejected; neither header present rejected; registration, login, MFA and logout covered; GET handlers have no side effects; `fetch()` sends the real `Origin` under `no-referrer` in all three engines |
