// Pacing for the deployment tests (ADR-014). Nginx limits authentication requests to 10 per
// minute per client address (cm_auth zone), and every test browser on one machine shares one
// address. Instead of raising the production limit for tests, the tests wait for room: at most 9
// authentication requests in any 61-second window. The state lives in the worker process
// (playwright.deployment.config.ts runs one worker), so it spans the spec files of a run.

const WINDOW_MS = 61_000;
const MAX_IN_WINDOW = 9;
const sent: number[] = [];

/** Waits until `count` more authentication requests fit under the per-address limit. */
export async function authSlots(count = 1): Promise<void> {
  for (;;) {
    const now = Date.now();
    while (sent.length > 0 && now - (sent[0] ?? now) > WINDOW_MS) sent.shift();
    if (sent.length + count <= MAX_IN_WINDOW) {
      for (let i = 0; i < count; i += 1) sent.push(now);
      return;
    }
    const wait = (sent[0] ?? now) + WINDOW_MS - now + 250;
    await new Promise((resolve) => setTimeout(resolve, Math.max(wait, 250)));
  }
}
