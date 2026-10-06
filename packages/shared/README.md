# packages/shared

Non-sensitive primitives shared by the client and server: API error codes and the error body type, HTTP constants (API prefix, request-ID and CipherMesh request headers), UUIDv4 checks, product constants and the room authorization matrix with its decision function. No dependencies, nothing server-only, nothing secret.

Status: foundation (Phase 1); the room authorization matrix and `decideRoomAction` (`src/authorization.ts`, CM-T029) and the room constants (`src/rooms.ts`: profiles, the PC-01 and PC-02 values room creation applies, page sizes; CM-T030) since Phase 5. The policy catalogue (CM-T046) is added in Phase 10. The web client may read the matrix to hide controls; only the API enforces it (INV-05).
