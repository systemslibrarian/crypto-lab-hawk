/**
 * Phase 4 verification: the comprehensive gold-standard suite.
 *
 * This is the machine-checked backing for the page's "honesty panel" claims.
 * It covers, for both parameter sets:
 *   - full keygen -> sign -> verify round-trips
 *   - the detailed verification identity (recovered f - g === q01)
 *   - tamper rejection across many coefficients
 *   - signature/public-key serialization (determinism + sizes)
 *   - the CDT sampler's distribution via a chi-square goodness-of-fit test
 *   - CDT trace self-consistency (the step-through matches the magnitude)
 */
import {
  hawkKeygen,
  hawkSign,
  hawkVerify,
  hawkVerifyDetailed,
  serializePublicKey,
  serializeSignature,
  type HAWKSignature,
} from '../src/hawk.ts';
import {
  DISCRETE_GAUSSIAN_TABLE_T1,
  EXPECTED_SIGMA,
  sampleDiscreteGaussian,
  traceDiscreteGaussian,
} from '../src/gaussian.ts';
import { HAWK_512_PARAMS, HAWK_1024_PARAMS } from '../src/polynomial.ts';

let checks = 0;

function assert(condition: boolean, message: string): void {
  checks += 1;
  if (!condition) {
    throw new Error(`assertion failed: ${message}`);
  }
}

const encoder = new TextEncoder();

async function roundTrip(params: typeof HAWK_512_PARAMS | typeof HAWK_1024_PARAMS): Promise<void> {
  const message = encoder.encode(`gold-standard round trip for n=${params.n}`);
  const { privateKey, publicKey, generationAttempts } = await hawkKeygen(params);

  assert(generationAttempts >= 1, `keygen reports at least one attempt (n=${params.n})`);
  assert(publicKey.n === params.n, `public key keeps n=${params.n}`);

  const { signature, restartCount } = await hawkSign(message, privateKey);
  assert(signature.n === params.n, `signature keeps n=${params.n}`);
  assert(signature.s1.length === params.n, `s1 has n coefficients (n=${params.n})`);
  assert(restartCount >= 0, `restart count is non-negative (n=${params.n})`);

  const detail = await hawkVerifyDetailed(message, signature, publicKey);
  assert(detail.ok, `genuine signature verifies (n=${params.n})`);
  assert(detail.identityHolds, `recovered basis satisfies the identity (n=${params.n})`);
  assert(detail.normWithinBound, `recovered basis is within the norm bound (n=${params.n})`);
  assert(detail.totalNorm <= detail.bound, `total norm <= bound (n=${params.n})`);

  // The recovered consistency polynomial must equal the published q01 exactly.
  assert(detail.consistency.length === detail.q01.length, `consistency length matches q01 (n=${params.n})`);
  for (let i = 0; i < detail.q01.length; i += 1) {
    assert(detail.consistency[i] === detail.q01[i], `consistency[${i}] === q01[${i}] (n=${params.n})`);
  }

  // Tamper rejection: flipping any one of several coefficients must break it.
  const probes = [0, 1, Math.floor(params.n / 2), params.n - 1];
  for (const index of probes) {
    const tampered: HAWKSignature = {
      salt: signature.salt,
      s1: Int32Array.from(signature.s1),
      n: signature.n,
    };
    tampered.s1[index] += index % 2 === 0 ? 1 : -1;
    const stillValid = await hawkVerify(message, tampered, publicKey);
    assert(!stillValid, `tampering s1[${index}] is rejected (n=${params.n})`);
  }

  // A signature from a different message must not verify against this one.
  const otherMessage = encoder.encode(`different message for n=${params.n}`);
  const otherValid = await hawkVerify(otherMessage, signature, publicKey);
  assert(!otherValid, `signature does not verify a different message (n=${params.n})`);

  // Serialization: deterministic and correctly sized.
  const sigBytesA = serializeSignature(signature);
  const sigBytesB = serializeSignature(signature);
  assert(sigBytesA.length === sigBytesB.length, `signature serialization is length-stable (n=${params.n})`);
  for (let i = 0; i < sigBytesA.length; i += 1) {
    assert(sigBytesA[i] === sigBytesB[i], `signature serialization is byte-stable (n=${params.n})`);
  }
  assert(sigBytesA.length > params.saltBits / 8, `serialized signature carries data beyond the salt (n=${params.n})`);

  const pkBytes = serializePublicKey(publicKey);
  assert(pkBytes.length === params.n * 4 * 2, `public key serializes to 2*n int32 (n=${params.n})`);
}

function distributionTest(): void {
  // Expected magnitude probabilities implied directly by the CDT table.
  // magnitude = #{i : word < T[i]} with T descending, word uniform in [0, 2^64).
  const table = DISCRETE_GAUSSIAN_TABLE_T1;
  const TWO_64 = 1n << 64n;
  const buckets = table.length + 1; // magnitudes 0..table.length
  const expectedProb = new Array<number>(buckets).fill(0);
  expectedProb[0] = Number(TWO_64 - table[0]) / Number(TWO_64);
  for (let k = 1; k < table.length; k += 1) {
    expectedProb[k] = Number(table[k - 1] - table[k]) / Number(TWO_64);
  }
  expectedProb[table.length] = Number(table[table.length - 1]) / Number(TWO_64);

  const probSum = expectedProb.reduce((a, b) => a + b, 0);
  assert(Math.abs(probSum - 1) < 1e-9, 'table-implied magnitude probabilities sum to 1');

  const N = 60000;
  const observed = new Array<number>(buckets).fill(0);
  let sum = 0;
  let sumSq = 0;
  for (let i = 0; i < N; i += 1) {
    const value = sampleDiscreteGaussian(table);
    const magnitude = Math.abs(value);
    observed[Math.min(magnitude, buckets - 1)] += 1;
    sum += value;
    sumSq += value * value;
  }

  // Chi-square goodness-of-fit against the table-implied magnitude distribution.
  let chiSq = 0;
  for (let k = 0; k < buckets; k += 1) {
    const expectedCount = expectedProb[k] * N;
    if (expectedCount < 1) {
      continue; // skip vanishingly rare tail buckets to keep the statistic stable
    }
    const diff = observed[k] - expectedCount;
    chiSq += (diff * diff) / expectedCount;
  }
  // df ~= buckets - 1 = 7; critical value at p=0.001 is ~24. Use a generous
  // ceiling so the test is meaningful but not flaky.
  assert(chiSq < 30, `CDT magnitude distribution matches the table (chi-square=${chiSq.toFixed(2)})`);

  const mean = sum / N;
  const variance = sumSq / N - mean * mean;
  const sigma = Math.sqrt(variance);
  assert(Math.abs(mean) < 0.1, `CDT sampler is centered at zero (mean=${mean.toFixed(4)})`);
  assert(
    Math.abs(sigma - EXPECTED_SIGMA) < 0.2,
    `CDT sampler sigma is near the advertised ${EXPECTED_SIGMA} (observed=${sigma.toFixed(3)})`,
  );
}

function traceConsistencyTest(): void {
  for (let i = 0; i < 200; i += 1) {
    const trace = traceDiscreteGaussian(DISCRETE_GAUSSIAN_TABLE_T1);
    // Every draw must run all thresholds — no early exit.
    assert(
      trace.steps.length === DISCRETE_GAUSSIAN_TABLE_T1.length,
      'CDT trace walks the entire table every time',
    );
    // The recorded magnitude must equal an independent recount.
    const recount = trace.steps.filter((step) => step.isLess).length;
    assert(recount === trace.magnitude, 'CDT trace magnitude matches a recount of the steps');
    // The final sample must be a sign-applied magnitude.
    const expected = trace.magnitude === 0 ? 0 : trace.signBit === 0 ? trace.magnitude : -trace.magnitude;
    assert(trace.sample === expected, 'CDT trace sample is the signed magnitude');
  }
}

await roundTrip(HAWK_512_PARAMS);
await roundTrip(HAWK_1024_PARAMS);
distributionTest();
traceConsistencyTest();

console.log(JSON.stringify({ checks }));
console.log('phase-4 verification passed');
