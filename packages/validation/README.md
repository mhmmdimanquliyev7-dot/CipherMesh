# packages/validation

zod schemas for API requests and responses, used at trust boundaries on both sides: the API validates input and projects responses through them, and the client validates responses before use. Every object schema is strict. `parseWith` reports paths and issue codes only, never the rejected values (INV-10).

Status: foundation (Phase 1): boundary schemas for health, readiness, the error body and UUIDs. Business schemas arrive with their phases.
