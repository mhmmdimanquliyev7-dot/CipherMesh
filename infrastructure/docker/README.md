# infrastructure/docker

- `compose.dev.yml`: development-only PostgreSQL and S3 emulator (SeaweedFS), bound to 127.0.0.1, credentials from the git-ignored `.env`, images pinned by digest. Start with `pnpm services:up`. See docs/architecture/engineering-baseline.md section 5.

Production Dockerfiles and the production Compose stack arrive in Phase 17 (CM-T065). Production images run as non-root with read-only root filesystems where possible. Secrets are mounted as files, never baked into images.
