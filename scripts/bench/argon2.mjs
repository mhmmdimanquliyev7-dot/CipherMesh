// `pnpm bench:argon2`: server Argon2id benchmark for CP-05 (OCD-03, CM-T015, EV-03-02).
// Uses Node's built-in crypto.argon2 (OpenSSL), the implementation selected as LIB-04.
// Prints a Markdown table. Run it on the target hardware before changing CP-05.
import { argon2, argon2Sync, randomBytes } from 'node:crypto';
import { availableParallelism, cpus, totalmem } from 'node:os';

// RFC 9106 section 5.3 Argon2id test vector: the implementation must reproduce it exactly.
const kat = argon2Sync('argon2id', {
  message: Buffer.alloc(32, 0x01),
  nonce: Buffer.alloc(16, 0x02),
  secret: Buffer.alloc(8, 0x03),
  associatedData: Buffer.alloc(12, 0x04),
  parallelism: 4,
  tagLength: 32,
  memory: 32,
  passes: 3,
}).toString('hex');
const expected = '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659';
if (kat !== expected) {
  console.error('FAIL RFC 9106 Argon2id test vector');
  process.exit(1);
}

const CANDIDATES = [
  { label: 'CP-05 floor', memory: 19456, passes: 2, parallelism: 1 },
  { label: 'OWASP alternative', memory: 47104, passes: 1, parallelism: 1 },
  { label: 'm=64 MiB, t=3, p=1', memory: 65536, passes: 3, parallelism: 1 },
  { label: 'CP-05 target (RFC 9106 second option)', memory: 65536, passes: 3, parallelism: 4 },
];
const CONCURRENCY = [1, 2, 4, 8];
const ROUNDS = 8;

/** @param {{ memory: number, passes: number, parallelism: number }} p @returns {Promise<number>} */
const hashOnce = (p) =>
  new Promise((resolve, reject) => {
    const start = process.hrtime.bigint();
    argon2(
      'argon2id',
      {
        message: randomBytes(16),
        nonce: randomBytes(16),
        parallelism: p.parallelism,
        tagLength: 32,
        memory: p.memory,
        passes: p.passes,
      },
      (error) => (error ? reject(error) : resolve(Number(process.hrtime.bigint() - start) / 1e6)),
    );
  });

/** @param {number[]} values @param {number} q @returns {number} */
const percentile = (values, q) => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))] ?? 0;
};

console.log('PASS RFC 9106 Argon2id test vector (section 5.3)');
console.log(
  `Hardware: ${cpus()[0]?.model ?? 'unknown CPU'}, ${availableParallelism()} logical CPUs, ${(totalmem() / 2 ** 30).toFixed(1)} GiB RAM`,
);
console.log(
  `Runtime: Node.js ${process.versions.node}, OpenSSL ${process.versions.openssl}, UV_THREADPOOL_SIZE=${process.env.UV_THREADPOOL_SIZE ?? '4 (default)'}`,
);
console.log('');
console.log(
  '| Parameters | Concurrency | Median latency (ms) | p95 latency (ms) | Hashes per second | Memory in use (MiB) |',
);
console.log('|---|---|---|---|---|---|');
for (const p of CANDIDATES) {
  await hashOnce(p); // warm-up
  for (const c of CONCURRENCY) {
    const latencies = [];
    const start = process.hrtime.bigint();
    for (let r = 0; r < ROUNDS; r += 1) {
      latencies.push(...(await Promise.all(Array.from({ length: c }, () => hashOnce(p)))));
    }
    const seconds = Number(process.hrtime.bigint() - start) / 1e9;
    console.log(
      `| ${p.label}: m=${p.memory} KiB, t=${p.passes}, p=${p.parallelism} | ${c} | ${percentile(latencies, 0.5).toFixed(0)} | ${percentile(latencies, 0.95).toFixed(0)} | ${(latencies.length / seconds).toFixed(1)} | ${((Math.min(c, 4) * p.memory) / 1024).toFixed(0)} |`,
    );
  }
}
