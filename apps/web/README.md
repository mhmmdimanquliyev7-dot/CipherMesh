# apps/web

Next.js + TypeScript + Tailwind CSS client (planned: static export served by Nginx, see ADR-011).

Status: foundation shell (Phase 1). `pnpm build` writes the export to `out/` and the security headers, including the CSP with inline-script hashes, to `out-meta/security-headers.json`.

Rules:
- All client-side cryptography runs in the browser through `packages/crypto`. Never re-implement crypto here.
- Decrypted content and unlocked keys live in memory only. Never write them to localStorage, sessionStorage, IndexedDB, cookies, logs or analytics.
- Hiding a control in the UI is not authorization. The API enforces every rule.
- See CLAUDE.md and docs/architecture/system-overview.md.
