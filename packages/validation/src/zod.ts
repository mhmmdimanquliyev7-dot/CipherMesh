import { z } from 'zod';

// zod 4 compiles object parsers with `new Function` unless `jitless` is set, and it probes for
// that ability when the first object schema is constructed. Under the web client's strict CSP
// (no 'unsafe-eval', ADR-011) the browser reports the probe as a 'script-src eval' violation even
// though zod catches the error. Every shared schema takes `z` from this module, so the setting
// is in place before any schema exists. It also keeps runtime code generation out of the API
// for these schemas.
z.config({ jitless: true });

export { z };
