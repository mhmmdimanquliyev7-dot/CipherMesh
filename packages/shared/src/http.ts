/** All API routes live under this prefix; Nginx proxies it to the API (deployment architecture). */
export const API_PREFIX = '/api';

/** Response header carrying the server-generated request identifier. */
export const REQUEST_ID_HEADER = 'x-request-id';

/** Header every state-changing request must carry (INV-19, docs/security/session-and-csrf.md). */
export const CIPHERMESH_REQUEST_HEADER = 'x-ciphermesh-request';
export const CIPHERMESH_REQUEST_HEADER_VALUE = '1';
