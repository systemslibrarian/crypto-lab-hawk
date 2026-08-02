/**
 * Phase 5 verification: the sampler gap.
 *
 * Exhibit 3 gained a bench that answers the obvious follow-up to the forgery
 * demo — "so if you used a real Gaussian sampler instead of a mod-2 linear
 * solve, it would be fine, right?" — by running both samplers against the same
 * key and measuring. The answer it prints is a negative result, and negative
 * results are exactly the kind that rot silently, so every number the bench can
 * show is pinned here.
 *
 * Covered:
 *   - the Gaussian coset sampler preserves the parity coset (c' ≡ c mod 2),
 *     which is why its signatures still verify
 *   - a genuine Gaussian-coset signature verifies, and the SAME signature with
 *     one coefficient shifted by 1 is rejected (the failure path is reachable)
 *   - a Gaussian-coset signature is rejected against a different public key,
 *     and rejected when the bound is tightened below its norm
 *   - ||B·c||² from the PUBLIC Gram matrix equals ||B·c||² recomputed from the
 *     SECRET basis, at Gaussian coordinate magnitudes. The Gram-matrix path is
 *     what the verifier uses and it never sees the basis, so this is the only
 *     place the two can be compared — and it is what would catch an accumulator
 *     wrap in the quadratic form, which would otherwise be silent.
 *   - the bench's five structural measurements, including the one that does
 *     NOT change (additivity mod 2) and the forgery that survives both samplers
 */
import {
  hawkCosetNorm,
  hawkKeygen,
  hawkParityTarget,
  hawkPublicKeyHash,
  hawkSaltBytes,
  hawkSignGaussianCoset,
  hawkVerify,
  hawkVerifyDetailed,
  solveCosetGaussian,
  solveCosetLinear,
  type HAWKPublicKey,
} from '../src/hawk.ts';
import { HAWK_512_PARAMS, polyMulExact, type Polynomial } from '../src/polynomial.ts';
import { runSamplerGap } from '../src/sampler-gap.ts';

let checks = 0;

function assert(condition: boolean, message: string): void {
  checks += 1;
  if (!condition) {
    throw new Error(`assertion failed: ${message}`);
  }
}

const encoder = new TextEncoder();

function parityOf(value: number): number {
  return ((value % 2) + 2) % 2;
}

/**
 * ||B·c||² computed the long way: build the lattice point B·c from the SECRET
 * basis and sum its squared coefficients. The public verifier never gets to do
 * this, which is the point of the Gram matrix — but it gives us ground truth to
 * check the Gram-matrix path against.
 */
function latticePointNorm(
  f: Polynomial,
  g: Polynomial,
  F: Polynomial,
  G: Polynomial,
  c0: Polynomial,
  c1: Polynomial,
): number {
  const v0 = polyMulExact(f, c0);
  const v1 = polyMulExact(g, c0);
  const w0 = polyMulExact(F, c1);
  const w1 = polyMulExact(G, c1);

  let total = 0;
  for (let index = 0; index < v0.length; index += 1) {
    const a = v0[index] + w0[index];
    const b = v1[index] + w1[index];
    total += a * a + b * b;
  }
  return total;
}

async function gaussianCosetSampler(): Promise<void> {
  const params = HAWK_512_PARAMS;
  const message = encoder.encode('phase-5 gaussian coset sampler');
  const { privateKey, publicKey } = await hawkKeygen(params);
  const pubKeyHash = await hawkPublicKeyHash(publicKey);

  const salt = new Uint8Array(hawkSaltBytes(params.n));
  globalThis.crypto.getRandomValues(salt);
  const { h0, h1 } = await hawkParityTarget(message, salt, pubKeyHash, params.n);

  const linear = solveCosetLinear(publicKey, h0, h1);
  const gaussian = solveCosetGaussian(publicKey, h0, h1);

  // 1. The offset is a multiple of 2, so the parity coset is untouched. This
  //    is both why the Gaussian signatures verify and why forging still works.
  let parityMatches = 0;
  let differsOverZ = 0;
  for (let index = 0; index < params.n; index += 1) {
    if (parityOf(gaussian.c0[index]) === linear.c0[index]) parityMatches += 1;
    if (parityOf(gaussian.c1[index]) === linear.c1[index]) parityMatches += 1;
    if (gaussian.c0[index] !== linear.c0[index]) differsOverZ += 1;
    if (gaussian.c1[index] !== linear.c1[index]) differsOverZ += 1;
  }
  assert(parityMatches === 2 * params.n, 'Gaussian coset offset preserves every coefficient parity');
  assert(differsOverZ > 0, 'Gaussian coset offset actually moves coordinates over Z');
  assert(gaussian.gaussianDraws === 2 * params.n, 'one Gaussian draw per coordinate coefficient');

  // 2. The Gram-matrix norm must equal the true lattice-point norm even at
  //    Gaussian coordinate magnitudes. This fails under Int32 accumulation.
  const publicNorm = hawkCosetNorm(publicKey, gaussian);
  const secretNorm = latticePointNorm(
    privateKey.f,
    privateKey.g,
    privateKey.F,
    privateKey.G,
    gaussian.c0,
    gaussian.c1,
  );
  assert(publicNorm > 0, `Gaussian-coset norm is positive (got ${publicNorm})`);
  assert(
    publicNorm === secretNorm,
    `public Gram-matrix norm equals the secret-basis norm (${publicNorm} vs ${secretNorm})`,
  );
  assert(
    publicNorm > 1_000_000,
    `Gaussian-coset norm is at the magnitude the accumulator has to carry (${publicNorm})`,
  );

  // 3. A genuine Gaussian-coset signature verifies under a bound that clears it.
  const bound = Math.ceil(publicNorm * 3);
  const signed = await hawkSignGaussianCoset(message, privateKey, publicKey, bound);
  assert(
    await hawkVerify(message, signed.signature, publicKey, bound),
    'a Gaussian-coset signature verifies against the unmodified verifier',
  );

  // 4. FAILURE PATH: shift one coefficient by 1 and the coset check must fail.
  for (const coefficient of [0, 7, 128, 511]) {
    const tampered = {
      ...signed.signature,
      s1: Int32Array.from(signed.signature.s1),
    };
    tampered.s1[coefficient] += 1;
    const detail = await hawkVerifyDetailed(message, tampered, publicKey, bound);
    assert(!detail.identityHolds, `shifting s1[${coefficient}] breaks the parity coset`);
    assert(!detail.ok, `a shifted Gaussian-coset signature is rejected (s1[${coefficient}])`);
  }

  // 5. FAILURE PATH: a bound below the measured norm rejects it on length.
  const tight = await hawkVerifyDetailed(message, signed.signature, publicKey, Math.floor(publicNorm / 2));
  assert(tight.identityHolds, 'tightening the bound leaves the coset check passing');
  assert(!tight.normWithinBound, 'a bound below the norm rejects on length');
  assert(!tight.ok, 'a Gaussian-coset signature is rejected under a tight bound');

  // 6. FAILURE PATH: a different key must reject it.
  const other = await hawkKeygen(params);
  const foreign: HAWKPublicKey = other.publicKey;
  assert(
    !(await hawkVerify(message, signed.signature, foreign, bound)),
    'a Gaussian-coset signature is rejected against a different public key',
  );
}

async function samplerGapReport(): Promise<void> {
  const params = HAWK_512_PARAMS;
  const { privateKey, publicKey } = await hawkKeygen(params);
  const report = await runSamplerGap(privateKey, publicKey, 'phase-5 sampler gap');

  const [linear, gaussian] = report.columns;
  const total = linear.coefficientCount;
  assert(total === 2 * params.n, `bench examines all 2n = ${2 * params.n} coordinate coefficients`);

  // The linear solve is a function of (message, salt) and is GF(2)-linear.
  assert(linear.reproducibilityDiff === 0, 'the linear solve reproduces itself exactly');
  assert(linear.linearOverZMatches === total, 'the linear solve is additive over Z');
  assert(linear.linearMod2Matches === total, 'the linear solve is additive mod 2');
  assert(linear.distinctValues === 2, 'the linear solve emits coordinates in {0, 1}');
  assert(
    linear.entropyBitsPerCoefficient > 0.9 && linear.entropyBitsPerCoefficient <= 1,
    `the linear solve carries about one bit per coefficient (${linear.entropyBitsPerCoefficient.toFixed(3)})`,
  );

  // The Gaussian sampler is neither reproducible nor additive over Z.
  assert(gaussian.reproducibilityDiff > total / 4, `the Gaussian sampler is not reproducible (${gaussian.reproducibilityDiff}/${total} coefficients differ)`);
  assert(gaussian.linearOverZMatches < total, 'the Gaussian sampler is not additive over Z');
  assert(gaussian.distinctValues > 2, `the Gaussian sampler spreads over more than two values (${gaussian.distinctValues})`);
  assert(
    gaussian.entropyBitsPerCoefficient > linear.entropyBitsPerCoefficient,
    'the Gaussian sampler carries more entropy per coefficient',
  );
  assert(gaussian.meanNorm > linear.meanNorm, 'Gaussian coset representatives are longer');
  assert(report.normInflation > 2, `the norm inflation is substantial (${report.normInflation.toFixed(1)}x)`);

  // THE RESULT THE EXHIBIT EXISTS FOR: additivity mod 2 survives the Gaussian,
  // and so does the forgery. If either of these ever flips, the page's verdict
  // is wrong and this build's story about *why* it is forgeable has changed.
  assert(gaussian.linearMod2Matches === total, 'the Gaussian sampler is STILL additive mod 2');
  assert(linear.forgeryAccepted, 'the public-key-only forgery is accepted under the linear solve');
  assert(gaussian.forgeryAccepted, 'the public-key-only forgery is accepted under the Gaussian sampler too');
  assert(linear.forgeryCosetHolds && gaussian.forgeryCosetHolds, 'both forgeries land in the message coset');
  assert(report.bothForgeable, 'the bench reports both samplers as forgeable');
  assert(
    report.changedProperties === report.comparedProperties - 1,
    `exactly one measured property is unchanged by the Gaussian (changed ${report.changedProperties} of ${report.comparedProperties})`,
  );

  console.log(
    JSON.stringify({
      normInflation: Number(report.normInflation.toFixed(2)),
      changedProperties: report.changedProperties,
      comparedProperties: report.comparedProperties,
      gaussianReproducibilityDiff: gaussian.reproducibilityDiff,
      gaussianLinearOverZMatches: gaussian.linearOverZMatches,
      gaussianLinearMod2Matches: gaussian.linearMod2Matches,
      bothForgeable: report.bothForgeable,
    }),
  );
}

await gaussianCosetSampler();
await samplerGapReport();

console.log(JSON.stringify({ checks }));
console.log('phase-5 verification passed');
