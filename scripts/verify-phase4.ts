/**
 * Phase 4 verification: the comprehensive gold-standard suite.
 *
 * This is the machine-checked backing for the page's "honesty panel" claims.
 * It covers, for both parameter sets:
 *   - full keygen -> sign -> verify round-trips
 *   - the verification identity: the signature's coset image under the public
 *     parity basis (B mod 2)·c must equal the message's hashed parity target
 *   - the Gram-matrix norm: ||B c||^2 recomputed as c* Q c from the PUBLIC key
 *   - tamper rejection across many coefficients (breaks the coset identity)
 *   - WRONG-KEY rejection: a valid signature must fail against a different
 *     public key, because verification depends on that key's Gram matrix and
 *     parity basis, not just on a hash match
 *   - a norm-only forgery (parity kept, lattice vector inflated) is rejected
 *     by the Gram-matrix bound
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
  assert(signature.c0.length === params.n, `c0 has n coefficients (n=${params.n})`);
  assert(restartCount >= 0, `restart count is non-negative (n=${params.n})`);

  const detail = await hawkVerifyDetailed(message, signature, publicKey);
  assert(detail.ok, `genuine signature verifies (n=${params.n})`);
  assert(detail.identityHolds, `signature coset matches the message target (n=${params.n})`);
  assert(detail.normWithinBound, `lattice point is within the Gram-matrix bound (n=${params.n})`);
  assert(detail.totalNorm <= detail.bound, `total norm <= bound (n=${params.n})`);
  assert(detail.totalNorm > 0, `Gram-matrix norm is a genuine positive length (n=${params.n})`);

  // The coset image (h0||h1) must be a real parity vector, not trivially zero:
  // if it were all-zero, the identity check would be vacuous.
  let targetOnes = 0;
  for (let i = 0; i < detail.q01.length; i += 1) {
    if (detail.q01[i] !== 0) {
      targetOnes += 1;
    }
  }
  assert(targetOnes > 0, `hashed parity target is non-trivial (n=${params.n})`);

  // Identity: the recomputed coset image must equal the target coset exactly.
  assert(detail.consistency.length === detail.q01.length, `coset image length matches target (n=${params.n})`);
  for (let i = 0; i < detail.q01.length; i += 1) {
    assert(detail.consistency[i] === detail.q01[i], `coset image[${i}] === target[${i}] (n=${params.n})`);
  }

  // Tamper rejection: flipping any one of several coefficients must break it.
  const probes = [0, 1, Math.floor(params.n / 2), params.n - 1];
  for (const index of probes) {
    const tampered: HAWKSignature = {
      salt: signature.salt,
      c0: Int32Array.from(signature.c0),
      s1: Int32Array.from(signature.s1),
      n: signature.n,
    };
    tampered.s1[index] ^= 1;
    const stillValid = await hawkVerify(message, tampered, publicKey);
    assert(!stillValid, `tampering s1[${index}] is rejected (n=${params.n})`);
  }

  // A signature from a different message must not verify against this one.
  const otherMessage = encoder.encode(`different message for n=${params.n}`);
  const otherValid = await hawkVerify(otherMessage, signature, publicKey);
  assert(!otherValid, `signature does not verify a different message (n=${params.n})`);

  // WRONG-KEY REJECTION. This is the test that would fail if signing were not
  // bound to the lattice: verification must depend on THIS key's Gram matrix
  // and parity basis. An independently generated keypair signs the same
  // message; each signature must be rejected against the other public key.
  const other = await hawkKeygen(params);
  const otherSig = await hawkSign(message, other.privateKey);
  assert(
    !(await hawkVerify(message, signature, other.publicKey)),
    `signature is rejected against a different public key (n=${params.n})`,
  );
  assert(
    !(await hawkVerify(message, otherSig.signature, publicKey)),
    `foreign signature is rejected against this public key (n=${params.n})`,
  );
  // Sanity: each genuine signature still verifies against its own key.
  assert(await hawkVerify(message, otherSig.signature, other.publicKey), `foreign signature verifies against its own key (n=${params.n})`);

  // NORM-ONLY FORGERY. Keep the parity coset intact (add an even offset 2e to
  // both coordinates so B·c stays in the same coset mod 2) but inflate the
  // lattice vector's length. The coset identity still holds, so ONLY the
  // Gram-matrix norm bound can catch it — proving that check is non-vacuous.
  const inflated: HAWKSignature = {
    salt: signature.salt,
    c0: Int32Array.from(signature.c0),
    s1: Int32Array.from(signature.s1),
    n: signature.n,
  };
  for (let i = 0; i < params.n; i += 1) {
    inflated.c0[i] += 2 * 40;
    inflated.s1[i] += 2 * 40;
  }
  const inflatedDetail = await hawkVerifyDetailed(message, inflated, publicKey);
  assert(inflatedDetail.identityHolds, `inflated forgery keeps the parity coset (n=${params.n})`);
  assert(!inflatedDetail.normWithinBound, `inflated forgery overshoots the Gram-matrix bound (n=${params.n})`);
  assert(!inflatedDetail.ok, `inflated forgery is rejected by the norm bound (n=${params.n})`);

  // Serialization: deterministic and correctly sized.
  const sigBytesA = serializeSignature(signature);
  const sigBytesB = serializeSignature(signature);
  assert(sigBytesA.length === sigBytesB.length, `signature serialization is length-stable (n=${params.n})`);
  for (let i = 0; i < sigBytesA.length; i += 1) {
    assert(sigBytesA[i] === sigBytesB[i], `signature serialization is byte-stable (n=${params.n})`);
  }
  assert(sigBytesA.length > params.saltBits / 8, `serialized signature carries data beyond the salt (n=${params.n})`);

  const pkBytes = serializePublicKey(publicKey);
  // q00, q01, q11 plus the four parity-basis polynomials = 7 int32 vectors.
  assert(pkBytes.length === params.n * 4 * 7, `public key serializes to 7*n int32 (n=${params.n})`);
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
