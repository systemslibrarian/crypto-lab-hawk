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
 *   - a PUBLIC-KEY-ONLY forgery is ACCEPTED. That is asserted on purpose: this
 *     build's signing path has no trapdoor, the page says so and demonstrates
 *     it with a button, and a claim that visible deserves a test pinning it.
 *   - the acceptance bound is a live parameter: tightening it below the
 *     observed norm makes the same verifier reject the same signature
 *   - signature/public-key serialization (determinism + sizes)
 *   - the CDT sampler's distribution via a chi-square goodness-of-fit test
 *   - CDT trace self-consistency (the step-through matches the magnitude)
 */
import {
  hawkForgeFromPublicKey,
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

  // NORM-ONLY FORGERY. Keep the parity coset intact (add an EVEN offset to a
  // coordinate, so c mod 2 — and therefore B·c mod 2 — is untouched) but
  // inflate the lattice vector's length. The coset identity still holds, so
  // ONLY the Gram-matrix norm bound can catch it — proving that check is
  // non-vacuous.
  //
  // The inflation is DERIVED, not guessed. An earlier version of this test
  // added a hardcoded +2*40 to every coordinate, which was flaky twice over:
  // the key and the signature are freshly random every run, and the acceptance
  // bound is a live parameter, so nothing tied the offset to either. Worse, an
  // n-wide offset of that size drove the true norm to ~5e9-6e10 while
  // `quadraticFormNorm` accumulates in Int32Array — the reported norm was a
  // silently wrapped value, uniform over the int32 range, and this assertion
  // failed whenever it happened to wrap into [0, bound]: ~0.3% of runs at
  // n=512 and ~0.9% at n=1024 (measured; = bound / 2^32).
  //
  // Derivation. Write ‖v‖ for the Gram-matrix length ‖B·v‖. Put the whole
  // offset on coordinate 0 of c0: δ = 2e·X^0 in the first component, zero in
  // the second. Then B·δ = (f·2e, g·2e) and its squared length is exactly
  //   ‖δ‖² = 4e²·(Σf_i² + Σg_i²) = 4e²·q00[0],
  // because q00 = f*f + g*g and the constant term of p*p is Σp_i². q00[0] is
  // published in the PUBLIC key, so the test never touches a secret. By the
  // reverse triangle inequality ‖c + δ‖ ≥ ‖δ‖ − ‖c‖, so choosing e with
  //   2e·√q00[0] ≥ ‖c‖ + 1.05·√bound
  // guarantees ‖c + δ‖² ≥ 1.1025·bound > bound for ANY key, ANY signature and
  // ANY live bound. The 1.05 is headroom against floating-point rounding in
  // the square roots, not a fudge factor for randomness.
  const gramUnit = publicKey.q00[0]; // = Σf_i² + Σg_i² > 0 for any usable key
  assert(gramUnit > 0, `public Gram matrix has a positive unit length q00[0] (n=${params.n})`);
  const genuineLength = Math.sqrt(detail.totalNorm);
  const halfOffset = Math.ceil((genuineLength + 1.05 * Math.sqrt(detail.bound)) / (2 * Math.sqrt(gramUnit)));
  const inflationLength = 2 * halfOffset * Math.sqrt(gramUnit);
  // Both bounds hold by the triangle inequality, in both directions.
  const normFloor = (inflationLength - genuineLength) ** 2;
  const normCeiling = (inflationLength + genuineLength) ** 2;
  assert(normFloor > detail.bound, `derived inflation provably clears the live bound (n=${params.n})`);
  // The Gram form is accumulated in Int32Array. If the inflated norm could not
  // be represented there the verifier would report a wrapped value and this
  // whole block would be meaningless — which is exactly the bug above. Pin it.
  assert(normCeiling < 2 ** 31 - 1, `inflated norm stays inside the int32 Gram accumulator (n=${params.n})`);

  const inflated: HAWKSignature = {
    salt: signature.salt,
    c0: Int32Array.from(signature.c0),
    s1: Int32Array.from(signature.s1),
    n: signature.n,
  };
  inflated.c0[0] += 2 * halfOffset;
  const inflatedDetail = await hawkVerifyDetailed(message, inflated, publicKey);
  assert(inflatedDetail.identityHolds, `inflated forgery keeps the parity coset (n=${params.n})`);
  // Guard against silent int32 wraparound: a wrapped value would almost surely
  // land outside the interval the triangle inequality allows.
  assert(
    inflatedDetail.totalNorm >= Math.floor(normFloor) && inflatedDetail.totalNorm <= Math.ceil(normCeiling),
    `inflated norm lands in the analytically predicted interval, so it did not wrap (n=${params.n})`,
  );
  assert(!inflatedDetail.normWithinBound, `inflated forgery overshoots the Gram-matrix bound (n=${params.n})`);
  assert(!inflatedDetail.ok, `inflated forgery is rejected by the norm bound (n=${params.n})`);

  // PUBLIC-KEY-ONLY FORGERY — asserted to SUCCEED, deliberately.
  //
  // This build has no signing trapdoor: hawkSign uses nothing from the private
  // key that the public key does not already publish (B mod 2, shipped verbatim
  // as publicKey.basisMod2, plus the Gram matrix). The page says so out loud and
  // hands the visitor a button to prove it, so the claim has to be pinned by a
  // test in the same way the positive claims are. If a future change ever gives
  // this build a real trapdoor, this assertion is where it will surface — and
  // the page copy, the honesty panel, and the README must change with it.
  const forged = await hawkForgeFromPublicKey(message, publicKey);
  const forgedDetail = await hawkVerifyDetailed(message, forged.signature, publicKey);
  assert(forgedDetail.identityHolds, `public-key-only forgery lands in the message coset (n=${params.n})`);
  assert(forgedDetail.normWithinBound, `public-key-only forgery is short enough (n=${params.n})`);
  assert(forgedDetail.ok, `public-key-only forgery is ACCEPTED — this build has no trapdoor (n=${params.n})`);

  // The acceptance bound is a live parameter, not a baked-in constant: drive it
  // below the observed norm and the same verifier rejects the same signature.
  // This is what makes the bound slider in Exhibit 3 a real control rather than
  // a decoration, and what makes the restart counter reachable.
  const tightDetail = await hawkVerifyDetailed(
    message,
    signature,
    publicKey,
    Math.max(1, Math.floor(detail.totalNorm / 2)),
  );
  assert(tightDetail.identityHolds, `a tightened bound leaves the coset check untouched (n=${params.n})`);
  assert(!tightDetail.normWithinBound, `a tightened bound rejects on length (n=${params.n})`);
  assert(!tightDetail.ok, `a tightened bound rejects an otherwise-valid signature (n=${params.n})`);

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

  function drawSample(): { chiSq: number; mean: number; sigma: number } {
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

    const mean = sum / N;
    const variance = sumSq / N - mean * mean;
    return { chiSq, mean, sigma: Math.sqrt(variance) };
  }

  // CHI-SQUARE THRESHOLD, AND WHY IT IS CONFIRMED RATHER THAN LOOSENED.
  //
  // At N=60000 the expected bucket counts are 16824, 26298, 12492, 3656, 658,
  // 67.2, 4.62, 0.18; the last is dropped by the expectedCount < 1 guard, so 7
  // buckets are scored and df ≈ 6. A strict threshold on random data fails at
  // exactly its false-positive rate, so that rate was measured rather than
  // assumed: over 40,000 simulated null samples, P(chiSq ≥ 30) = 1.0e-4 and the
  // largest value seen was 33.2. One in ten thousand runs is rare, but this
  // suite gates a deploy on every push, so it is not rare enough to leave
  // undocumented.
  //
  // Raising the ceiling would trade away the power that makes the test worth
  // running. Instead the threshold stays at 30 and a flagged sample is
  // CONFIRMED on a second, independent draw: a genuinely wrong table reproduces
  // (its chi-square grows linearly in N and lands in the hundreds), a
  // 1-in-10,000 fluctuation does not. That puts the false-positive rate at
  // ~1e-8 per run while leaving the detection threshold exactly where it was.
  let { chiSq, mean, sigma } = drawSample();
  if (chiSq >= 30) {
    const confirmation = drawSample();
    assert(
      confirmation.chiSq < 30,
      `CDT magnitude distribution matches the table (chi-square=${chiSq.toFixed(2)} then ` +
        `${confirmation.chiSq.toFixed(2)} on an independent resample — two flags in a row is a real ` +
        'distribution error, not a fluctuation)',
    );
    ({ chiSq, mean, sigma } = confirmation);
  }
  assert(chiSq < 30, `CDT magnitude distribution matches the table (chi-square=${chiSq.toFixed(2)})`);

  // These two are safe by a wide margin and are recorded here so the margin is
  // not re-litigated: the table's true sigma is 1.42331, so the mean is 0 and
  // the sigma error is 0.0017. At N=60000 the standard error of the mean is
  // 0.0058 and of sigma is 0.0041, putting the 0.1 and 0.2 tolerances at 17 and
  // 48 standard errors respectively.
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
