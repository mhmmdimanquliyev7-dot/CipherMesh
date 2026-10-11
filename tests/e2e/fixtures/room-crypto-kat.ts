import { contextBytes } from '../../../packages/crypto/src/contexts';
import { toHex } from '../../../packages/crypto/src/encoding';
import { deriveBits, importKeyMaterial } from '../../../packages/crypto/src/hkdf';
import { computeSafetyCode, safetyCodeFromBits, type OpenedRoomKey } from '../../../packages/crypto/src/room-keys';

// Known-answer harness for the browser engines (CM-T085 acceptance: the derivation and the word
// mapping give the same answers in Chromium, Firefox and WebKit). Bundled by tests/e2e/room-keys.spec.ts
// with esbuild from the real package source and evaluated in a page of the CipherMesh origin. The
// key material is a fixed public test vector (00 01 .. 1f), never a real key.
async function run() {
  const roomId = '0f3e2d1c-4b5a-4968-8776-a5b4c3d2e1f0';
  const rkm = () => Uint8Array.from({ length: 32 }, (_, i) => i);
  const material = await importKeyMaterial(rkm());
  const commitment = await deriveBits(material, contextBytes('cm.room.commitment', { roomId, keyVersion: 1 }));
  const code = await computeSafetyCode({ roomId, keyVersion: 1, material } as OpenedRoomKey);
  const ones = safetyCodeFromBits(3, new Uint8Array(32).fill(0xff));
  return { commitment: toHex(commitment), code, ones };
}

(globalThis as unknown as { __cmRoomKat: () => Promise<unknown> }).__cmRoomKat = run;
