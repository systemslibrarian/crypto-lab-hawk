import {
  DISCRETE_GAUSSIAN_TABLE_T0,
  simulateFalconFastFourierSamplingPass,
} from './gaussian';
import {
  HAWK_512_PARAMS,
  HAWK_1024_PARAMS,
  polyAdd,
  polyAddMod2,
  polyAdjoint,
  polyInvMod2,
  polyMod2,
  polyMul,
  polyMulMod2,
  type Polynomial,
} from './polynomial';

/**
 * HAWK secret key: the short lattice basis B = [[f, F], [g, G]] over
 * R = Z[X]/(X^n + 1). In production HAWK, signing needs the actual short
 * integers and the public key exposes only their Gram matrix.
 *
 * In THIS build that is not true: `hawkSign` reads nothing from these
 * polynomials except their mod-2 image and their Gram matrix, and both of
 * those are published in `HAWKPublicKey`. See the notes on `HAWKPublicKey`
 * and `hawkSign`.
 */
export interface HAWKPrivateKey {
  f: Polynomial;
  g: Polynomial;
  F: Polynomial;
  G: Polynomial;
  pubKeyHash: Uint8Array;
  n: number;
}

/**
 * HAWK public key. The Gram matrix Q = B* B (q00, q01, q11) is what
 * verification uses to measure a signature's length without ever seeing the
 * short basis; basisMod2 is the parity image [[f,F],[g,G]] mod 2, which this
 * build publishes so the verifier can bind a signature's coset to the message.
 *
 * HONESTY NOTE: publishing basisMod2 is a simplification, and it is a fatal
 * one for unforgeability. Production HAWK's public key is (q00, q01) only; the
 * verifier recovers the coset by a rational rounding step against q00/q01
 * rather than by applying a published parity basis. Because this build hands
 * out B mod 2, and because this build's signing path uses nothing about the
 * secret basis beyond B mod 2 (see `hawkSign`), anyone holding only the public
 * key can recompute a signature that the real verifier accepts. That is
 * demonstrated on the page by `hawkForgeFromPublicKey` below, which is wired to
 * the "Forge with only the public key" control. Treat this build as a working
 * model of HAWK's *verification identity*, not of its unforgeability.
 */
export interface HAWKPublicKey {
  q00: Polynomial;
  q01: Polynomial;
  q11: Polynomial;
  basisMod2: { f: Polynomial; g: Polynomial; F: Polynomial; G: Polynomial };
  n: number;
}

/**
 * HAWK signature: a short integer coordinate vector c = (c0, c1) such that
 * the lattice point B·c lands in the message's parity coset. c0 is the ring
 * element the UI historically called s1's companion; both are published so
 * the verifier can recompute the quadratic form under the public Gram matrix.
 */
export interface HAWKSignature {
  salt: Uint8Array;
  c0: Polynomial;
  s1: Polynomial;
  n: number;
}

type HawkParams = typeof HAWK_512_PARAMS | typeof HAWK_1024_PARAMS;

const encoder = new TextEncoder();

function getCrypto(): Crypto {
  if (!globalThis.crypto) {
    throw new Error('Web Crypto API is not available in this environment.');
  }

  return globalThis.crypto;
}

function nowMs(): number {
  return globalThis.performance?.now() ?? Date.now();
}

function getParamsForN(n: number): HawkParams {
  if (n === HAWK_512_PARAMS.n) {
    return HAWK_512_PARAMS;
  }

  if (n === HAWK_1024_PARAMS.n) {
    return HAWK_1024_PARAMS;
  }

  throw new Error(`Unsupported HAWK parameter n=${n}.`);
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const length = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const merged = new Uint8Array(length);
  let offset = 0;

  for (let index = 0; index < chunks.length; index += 1) {
    merged.set(chunks[index], offset);
    offset += chunks[index].length;
  }

  return merged;
}

function encodeUint32(value: number): Uint8Array {
  const out = new Uint8Array(4);
  const view = new DataView(out.buffer);
  view.setUint32(0, value, false);
  return out;
}

function bytesToUint64(bytes: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let index = 0; index < 8; index += 1) {
    value = (value << 8n) | BigInt(bytes[offset + index]);
  }

  return value;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await getCrypto().subtle.digest('SHA-256', data as BufferSource);
  return new Uint8Array(digest);
}

async function expandDeterministic(seed: Uint8Array, label: string, length: number): Promise<Uint8Array> {
  const labelBytes = encoder.encode(label);
  const chunks: Uint8Array[] = [];
  let generated = 0;
  let counter = 0;

  while (generated < length) {
    const block = await sha256(concatBytes(labelBytes, encodeUint32(counter), seed));
    chunks.push(block);
    generated += block.length;
    counter += 1;
  }

  return concatBytes(...chunks).slice(0, length);
}

function sampleMagnitudeFromWord(word: bigint, table: readonly bigint[]): number {
  let magnitude = 0;

  for (let index = 0; index < table.length; index += 1) {
    if (word < table[index]) {
      magnitude += 1;
    }
  }

  return magnitude;
}

async function sampleDeterministicGaussianPolynomial(
  n: number,
  table: readonly bigint[],
  seed: Uint8Array,
  label: string,
): Promise<Polynomial> {
  const stream = await expandDeterministic(seed, label, n * 8);
  const coefficients = new Int32Array(n);

  for (let index = 0; index < n; index += 1) {
    const word = bytesToUint64(stream, index * 8);
    const magnitude = sampleMagnitudeFromWord(word, table);

    if (magnitude === 0) {
      coefficients[index] = 0;
      continue;
    }

    coefficients[index] = (word & 1n) === 0n ? magnitude : -magnitude;
  }

  return coefficients;
}

/**
 * Hash the message (bound to salt and public key) to a parity target
 * h = (h0, h1) in {0,1}^{2n}. This is the coset a valid signature's lattice
 * point B·c must land in; it is what ties a signature to a specific message.
 */
async function hashToParityTarget(
  message: Uint8Array,
  salt: Uint8Array,
  pubKeyHash: Uint8Array,
  n: number,
): Promise<{ h0: Polynomial; h1: Polynomial }> {
  const h0 = new Int32Array(n);
  const h1 = new Int32Array(n);
  let filled = 0;
  let counter = 0;

  // Two coset polynomials of n bits each = 2n bits total.
  while (filled < 2 * n) {
    const block = await sha256(
      concatBytes(pubKeyHash, salt, encodeUint32(counter), message),
    );

    for (let byteIndex = 0; byteIndex < block.length && filled < 2 * n; byteIndex += 1) {
      const byte = block[byteIndex];
      for (let bit = 0; bit < 8 && filled < 2 * n; bit += 1) {
        const value = (byte >> bit) & 1;
        if (filled < n) {
          h0[filled] = value;
        } else {
          h1[filled - n] = value;
        }
        filled += 1;
      }
    }

    counter += 1;
  }

  return { h0, h1 };
}

function serializePolynomial(poly: Polynomial): Uint8Array {
  const out = new Uint8Array(poly.length * 4);
  const view = new DataView(out.buffer);

  for (let index = 0; index < poly.length; index += 1) {
    view.setInt32(index * 4, poly[index], true);
  }

  return out;
}

async function hashPublicKey(publicKey: HAWKPublicKey): Promise<Uint8Array> {
  return sha256(
    concatBytes(
      serializePolynomial(publicKey.q00),
      serializePolynomial(publicKey.q01),
      serializePolynomial(publicKey.q11),
      serializePolynomial(publicKey.basisMod2.f),
      serializePolynomial(publicKey.basisMod2.g),
      serializePolynomial(publicKey.basisMod2.F),
      serializePolynomial(publicKey.basisMod2.G),
    ),
  );
}

/**
 * Build the public Gram matrix Q = B* B from the secret basis, entirely via
 * ring multiplication and adjoints:
 *   q00 = f* f + g* g,   q01 = f* F + g* G,   q11 = F* F + G* G.
 * These are the only inner products a verifier ever learns about the basis.
 */
function gramMatrix(
  f: Polynomial,
  g: Polynomial,
  F: Polynomial,
  G: Polynomial,
): { q00: Polynomial; q01: Polynomial; q11: Polynomial } {
  const q00 = polyAdd(polyMul(polyAdjoint(f), f), polyMul(polyAdjoint(g), g));
  const q01 = polyAdd(polyMul(polyAdjoint(f), F), polyMul(polyAdjoint(g), G));
  const q11 = polyAdd(polyMul(polyAdjoint(F), F), polyMul(polyAdjoint(G), G));
  return { q00, q01, q11 };
}

/**
 * The squared Euclidean length of the lattice point B·c, computed from the
 * PUBLIC Gram matrix alone as the constant term of c* Q c. Because Q = B* B,
 * this equals ||B c||^2 exactly, so verification measures a signature's
 * length using only the public key — the heart of HAWK's verify identity.
 */
function quadraticFormNorm(
  c0: Polynomial,
  c1: Polynomial,
  q00: Polynomial,
  q01: Polynomial,
  q11: Polynomial,
): number {
  const t00 = polyMul(polyMul(polyAdjoint(c0), q00), c0);
  const t01 = polyMul(polyMul(polyAdjoint(c0), q01), c1);
  const t10 = polyMul(polyMul(polyAdjoint(c1), polyAdjoint(q01)), c0);
  const t11 = polyMul(polyMul(polyAdjoint(c1), q11), c1);
  const sum = polyAdd(polyAdd(t00, t01), polyAdd(t10, t11));
  return sum[0];
}

/**
 * Sample a fresh short basis B = [[f,F],[g,G]] from the discrete Gaussian
 * over Z. This is where HAWK's integer-only sampler feeds real key material.
 */
async function sampleBasis(
  seed: Uint8Array,
  n: number,
): Promise<{ f: Polynomial; g: Polynomial; F: Polynomial; G: Polynomial }> {
  const basisSeed = concatBytes(seed, encodeUint32(n));
  const f = await sampleDeterministicGaussianPolynomial(n, DISCRETE_GAUSSIAN_TABLE_T0, basisSeed, 'hawk-f');
  const g = await sampleDeterministicGaussianPolynomial(n, DISCRETE_GAUSSIAN_TABLE_T0, basisSeed, 'hawk-g');
  const F = await sampleDeterministicGaussianPolynomial(n, DISCRETE_GAUSSIAN_TABLE_T0, basisSeed, 'hawk-F');
  const G = await sampleDeterministicGaussianPolynomial(n, DISCRETE_GAUSSIAN_TABLE_T0, basisSeed, 'hawk-G');
  return { f, g, F, G };
}

/**
 * Invert the 2x2 parity basis (B mod 2) over (Z/2)[X]/(X^n+1). Returns null
 * when det B is not a unit mod 2 — the honest analogue of HAWK's NTRU solve
 * failing for a sampled basis, which forces a keygen retry.
 */
function invertParityBasis(
  fB: Polynomial,
  gB: Polynomial,
  FB: Polynomial,
  GB: Polynomial,
): { a: Polynomial; b: Polynomial; c: Polynomial; d: Polynomial } | null {
  // det = fG - gF; mod 2, subtraction is addition.
  const det = polyAddMod2(polyMulMod2(fB, GB), polyMulMod2(gB, FB));
  const detInv = polyInvMod2(det);
  if (!detInv) {
    return null;
  }

  // inverse = det^{-1} * [[G, F],[g, f]] (mod 2, since -1 = 1).
  return {
    a: polyMulMod2(detInv, GB),
    b: polyMulMod2(detInv, FB),
    c: polyMulMod2(detInv, gB),
    d: polyMulMod2(detInv, fB),
  };
}

function keygenFailureReason(
  parityInverse: ReturnType<typeof invertParityBasis>,
): string | null {
  if (!parityInverse) {
    return 'NTRU solve failed: the sampled basis is singular mod 2 (det not a unit)';
  }
  return null;
}

function getSaltBytes(params: HawkParams): number {
  return (params.saltBits + 7) >> 3;
}

/**
 * The default signature-length acceptance bound.
 *
 * HONESTY NOTE: this is a demo-calibrated constant, not a derived HAWK
 * parameter. A coset representative B·c with c a {0,1} coordinate vector has
 * ||B c||^2 concentrated around 9e5 at n=512, so the 1.2e7 ceiling below sits
 * roughly 12x above where genuine signatures actually land. Two consequences
 * worth seeing rather than hiding: the norm check is slack enough that it never
 * rejects anything the signer produces (so `restartCount` is always 0 at the
 * default), and a *tampered* coordinate vector is caught by the coset check,
 * not by this bound. The page exposes this number as a slider precisely so a
 * learner can drag it down through the genuine-norm band and watch restarts
 * appear and acceptance flip. Production HAWK derives its bound from the
 * signing sigma and the parameter set; nothing here does.
 */
export function defaultVerificationBound(n: number): number {
  return n === HAWK_512_PARAMS.n ? 12_000_000 : 40_000_000;
}

function verificationBound(n: number, override?: number): number {
  if (typeof override === 'number' && Number.isFinite(override) && override > 0) {
    return override;
  }

  return defaultVerificationBound(n);
}

export async function hawkKeygen(
  params: typeof HAWK_512_PARAMS | typeof HAWK_1024_PARAMS,
  onAttempt?: (attempt: number, reason: string) => void,
): Promise<{
  privateKey: HAWKPrivateKey;
  publicKey: HAWKPublicKey;
  generationAttempts: number;
}> {
  let attempt = 0;

  while (attempt < 32) {
    attempt += 1;
    const kgseed = new Uint8Array(32);
    getCrypto().getRandomValues(kgseed);

    const { f, g, F, G } = await sampleBasis(kgseed, params.n);

    const fB = polyMod2(f);
    const gB = polyMod2(g);
    const FB = polyMod2(F);
    const GB = polyMod2(G);

    // The signer must be able to hit any parity coset, which requires the
    // parity basis to be invertible mod 2. This is the honest analogue of
    // HAWK's NTRU solve succeeding for the sampled basis.
    const parityInverse = invertParityBasis(fB, gB, FB, GB);
    const failure = keygenFailureReason(parityInverse);
    if (failure || !parityInverse) {
      onAttempt?.(attempt, failure ?? 'NTRU solve failed');
      continue;
    }

    const { q00, q01, q11 } = gramMatrix(f, g, F, G);

    const publicKey: HAWKPublicKey = {
      q00,
      q01,
      q11,
      basisMod2: { f: fB, g: gB, F: FB, G: GB },
      n: params.n,
    };

    const pubKeyHash = await hashPublicKey(publicKey);
    const privateKey: HAWKPrivateKey = {
      f,
      g,
      F,
      G,
      pubKeyHash,
      n: params.n,
    };

    return {
      privateKey,
      publicKey,
      generationAttempts: attempt,
    };
  }

  throw new Error('HAWK key generation exceeded the retry budget.');
}

/**
 * Sign a message under the secret basis.
 *
 * HONESTY NOTE — READ THIS BEFORE BELIEVING THE PAGE COPY. Despite taking the
 * private key as an argument, the *only* thing this function uses from it is
 * the basis reduced mod 2 (plus the Gram matrix, which is also public). Both
 * are published in `HAWKPublicKey`, so this signing path has no trapdoor: see
 * `hawkForgeFromPublicKey`, which reproduces identical coordinates from the
 * public key alone and is accepted by the real verifier.
 *
 * Why the shortcut is here rather than fixed: a genuine HAWK trapdoor needs
 * (a) keygen to solve the NTRU equation f·G − g·F = 1 so that B is unimodular
 * and B^-1 is an integer matrix, and (b) signing to draw x from a discrete
 * Gaussian over the coset 2Z^{2n} + (B·h mod 2) and publish w = B^-1·x. This
 * build samples f, g, F, G independently — no NTRU solve — so B^-1 is not
 * integral and step (b) has nothing to invert. Layering a Gaussian offset on
 * top of the mod-2 solve would *not* fix this: the forgeability comes from
 * publishing B mod 2 and from a verifier that accepts anything in the coset
 * under a slack bound, not from the sampler. So the flaw is surfaced as an
 * exhibit instead of being papered over.
 *
 * `boundOverride` lets the page drive the acceptance bound from a slider; the
 * norm rejection below is a real loop, it is simply unreachable at the default.
 */
export async function hawkSign(
  message: Uint8Array,
  privateKey: HAWKPrivateKey,
  boundOverride?: number,
): Promise<{
  signature: HAWKSignature;
  signingTimeMs: number;
  restartCount: number;
}> {
  const params = getParamsForN(privateKey.n);
  const startedAt = nowMs();
  const { f, g, F, G } = privateKey;

  // NOTE: fB..GB below are exactly `publicKey.basisMod2`. Nothing secret
  // survives this reduction.
  const fB = polyMod2(f);
  const gB = polyMod2(g);
  const FB = polyMod2(F);
  const GB = polyMod2(G);
  const parityInverse = invertParityBasis(fB, gB, FB, GB);
  if (!parityInverse) {
    throw new Error('HAWK signing failed: parity basis is not invertible.');
  }

  const bound = verificationBound(privateKey.n, boundOverride);
  const { q00, q01, q11 } = gramMatrix(f, g, F, G);
  let restartCount = 0;

  // Each pass draws a fresh salt, solves the parity coset once (a single
  // linear solve mod 2, no retry inside), and restarts only when the resulting
  // coset vector exceeds the length bound. At the default bound that never
  // happens; lower the bound and this becomes a live rejection loop.
  while (restartCount < 8) {
    const salt = new Uint8Array(getSaltBytes(params));
    getCrypto().getRandomValues(salt);

    const { h0, h1 } = await hashToParityTarget(message, salt, privateKey.pubKeyHash, privateKey.n);

    // Solve (B mod 2) c = h  =>  c = (B mod 2)^{-1} h, giving coordinates in
    // {0,1}. B·c is then a lattice point in the message's parity coset.
    const c0 = polyAddMod2(polyMulMod2(parityInverse.a, h0), polyMulMod2(parityInverse.b, h1));
    const c1 = polyAddMod2(polyMulMod2(parityInverse.c, h0), polyMulMod2(parityInverse.d, h1));

    // Length of the lattice point B·c, measured via the public Gram matrix.
    const norm = quadraticFormNorm(c0, c1, q00, q01, q11);

    if (norm > bound) {
      restartCount += 1;
      continue;
    }

    return {
      signature: {
        salt,
        c0,
        s1: c1,
        n: privateKey.n,
      },
      signingTimeMs: nowMs() - startedAt,
      restartCount,
    };
  }

  throw new Error(
    `HAWK signing restarted 8 times without landing under the acceptance bound (${bound.toLocaleString()}). ` +
      'That is the norm-rejection loop doing its job: every fresh salt produced a coset vector longer than the bound you set. ' +
      'Raise the bound to sign again.',
  );
}

/**
 * Produce a signature for an arbitrary message using ONLY the public key.
 *
 * This is the same computation `hawkSign` performs, with `publicKey.basisMod2`
 * substituted for `polyMod2(f), polyMod2(g), polyMod2(F), polyMod2(G)` — which
 * is not a substitution at all, because keygen defines basisMod2 as exactly
 * those four polynomials. The public key also pins down the message target,
 * since `pubKeyHash` is a hash of the public key. Nothing secret is consulted:
 * there is no `HAWKPrivateKey` in scope anywhere in this function.
 *
 * The output is fed to the unmodified `hawkVerifyDetailed`, which accepts it.
 * That is the lesson: a signature scheme is only as strong as the gap between
 * what the signer knows and what the verifier publishes, and this build has no
 * gap. Real HAWK keeps one by never publishing B mod 2.
 */
export async function hawkForgeFromPublicKey(
  message: Uint8Array,
  publicKey: HAWKPublicKey,
  boundOverride?: number,
): Promise<{
  signature: HAWKSignature;
  forgeTimeMs: number;
  restartCount: number;
}> {
  const params = getParamsForN(publicKey.n);
  const startedAt = nowMs();

  const { f: fB, g: gB, F: FB, G: GB } = publicKey.basisMod2;
  const parityInverse = invertParityBasis(fB, gB, FB, GB);
  if (!parityInverse) {
    throw new Error('Forgery failed: the published parity basis is not invertible.');
  }

  // Derived from the public key alone, exactly as the verifier derives it.
  const pubKeyHash = await hashPublicKey(publicKey);
  const bound = verificationBound(publicKey.n, boundOverride);
  let restartCount = 0;

  while (restartCount < 8) {
    const salt = new Uint8Array(getSaltBytes(params));
    getCrypto().getRandomValues(salt);

    const { h0, h1 } = await hashToParityTarget(message, salt, pubKeyHash, publicKey.n);

    const c0 = polyAddMod2(polyMulMod2(parityInverse.a, h0), polyMulMod2(parityInverse.b, h1));
    const c1 = polyAddMod2(polyMulMod2(parityInverse.c, h0), polyMulMod2(parityInverse.d, h1));

    const norm = quadraticFormNorm(c0, c1, publicKey.q00, publicKey.q01, publicKey.q11);
    if (norm > bound) {
      restartCount += 1;
      continue;
    }

    return {
      signature: { salt, c0, s1: c1, n: publicKey.n },
      forgeTimeMs: nowMs() - startedAt,
      restartCount,
    };
  }

  throw new Error('Forgery restarted too many times: the acceptance bound is below the coset norm.');
}

export interface HAWKVerifyDetail {
  /** Final verdict: parity binding holds and the length bound holds. */
  ok: boolean;
  /** Does the signature's coset match the message's parity target under B mod 2? */
  identityHolds: boolean;
  /** Is the lattice point B·c within the Euclidean length bound (via public Q)? */
  normWithinBound: boolean;
  /** Sizes mismatched, so the rest of the check was skipped. */
  parameterMismatch: boolean;
  /** ||B c||^2 computed as the constant term of c* Q c from the public key. */
  totalNorm: number;
  /** The acceptance bound the total norm is compared against. */
  bound: number;
  /** The recovered coset image (B mod 2)·c, first coordinate. */
  recoveredF: Polynomial;
  /** The recovered coset image (B mod 2)·c, second coordinate. */
  recoveredG: Polynomial;
  /** The recomputed parity target h0 || h1 the coset image must equal. */
  consistency: Polynomial;
  /** The coset image the target is compared against (h0 || h1 side by side). */
  q01: Polynomial;
}

/**
 * Run verification and return every intermediate quantity, not just the
 * boolean. Verification uses only the PUBLIC key: it reconstructs the coset
 * image of the signature under the parity basis (message binding, via
 * polyMul mod 2) and measures the lattice point's length under the Gram
 * matrix c* Q c (via polyMul). A single flipped coefficient breaks the coset
 * match or overshoots the bound, so neither check is tautological.
 */
export async function hawkVerifyDetailed(
  message: Uint8Array,
  signature: HAWKSignature,
  publicKey: HAWKPublicKey,
  boundOverride?: number,
): Promise<HAWKVerifyDetail> {
  const bound = verificationBound(publicKey.n, boundOverride);
  const n = publicKey.n;

  if (signature.n !== publicKey.n) {
    const empty = new Int32Array(0);
    return {
      ok: false,
      identityHolds: false,
      normWithinBound: false,
      parameterMismatch: true,
      totalNorm: Number.NaN,
      bound,
      recoveredF: empty,
      recoveredG: empty,
      consistency: empty,
      q01: empty,
    };
  }

  const pubKeyHash = await hashPublicKey(publicKey);
  const { h0, h1 } = await hashToParityTarget(message, signature.salt, pubKeyHash, n);

  const c0 = polyMod2(signature.c0);
  const c1 = polyMod2(signature.s1);
  const { f: fB, g: gB, F: FB, G: GB } = publicKey.basisMod2;

  // Recompute the coset image (B mod 2)·c from the PUBLIC parity basis.
  const image0 = polyAddMod2(polyMulMod2(fB, c0), polyMulMod2(FB, c1));
  const image1 = polyAddMod2(polyMulMod2(gB, c0), polyMulMod2(GB, c1));

  let identityHolds = true;
  for (let index = 0; index < n; index += 1) {
    if (image0[index] !== h0[index] || image1[index] !== h1[index]) {
      identityHolds = false;
      break;
    }
  }

  // Length of the lattice point via the public Gram matrix.
  const totalNorm = quadraticFormNorm(
    signature.c0,
    signature.s1,
    publicKey.q00,
    publicKey.q01,
    publicKey.q11,
  );
  const normWithinBound = totalNorm >= 0 && totalNorm <= bound;

  // Side-by-side polynomials for the UI: recovered coset image vs. target.
  const recoveredF = image0;
  const recoveredG = image1;
  const consistency = concatPolynomials(image0, image1);
  const targetSideBySide = concatPolynomials(h0, h1);

  return {
    ok: identityHolds && normWithinBound,
    identityHolds,
    normWithinBound,
    parameterMismatch: false,
    totalNorm,
    bound,
    recoveredF,
    recoveredG,
    consistency,
    q01: targetSideBySide,
  };
}

function concatPolynomials(a: Polynomial, b: Polynomial): Polynomial {
  const out = new Int32Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export async function hawkVerify(
  message: Uint8Array,
  signature: HAWKSignature,
  publicKey: HAWKPublicKey,
  boundOverride?: number,
): Promise<boolean> {
  const detail = await hawkVerifyDetailed(message, signature, publicKey, boundOverride);
  return detail.ok;
}

function simulateFalconSignWork(n: number): number {
  let accumulator = 0;
  for (let pass = 0; pass < 3; pass += 1) {
    accumulator += simulateFalconFastFourierSamplingPass(n).accumulator;
  }
  return accumulator;
}

/**
 * Illustrative model of ML-DSA's signing loop shape (NOT production ML-DSA).
 * ML-DSA's signing critical path is dominated by a rejection loop: each
 * iteration samples y, computes the high bits of A*y, hashes to a challenge,
 * and either accepts or restarts. Production implementations average roughly
 * four iterations per signature with a wide distribution.
 *
 * We reproduce that *shape* with a per-iteration integer workload (so the
 * timing reflects real work, not a hand-tuned constant) and an acceptance
 * probability of ~0.235 per pass, which yields a mean near four iterations.
 * The point is the iteration-count distribution, not a wall-clock claim.
 */
const MLDSA_ACCEPT_PROBABILITY = 0.235;

function simulateMldsaSignWork(n: number): { iterations: number; work: number } {
  let iterations = 0;
  let accepted = false;
  let work = 0;

  while (!accepted && iterations < 16) {
    iterations += 1;
    const passes = Math.ceil(Math.log2(n));

    for (let pass = 0; pass < passes; pass += 1) {
      for (let index = 0; index < n; index += 1) {
        const sample = ((index * 1103515245 + pass * 12345) % 8380417) | 0;
        work = (work + sample * (pass + 1)) | 0;
      }
    }

    if (Math.random() < MLDSA_ACCEPT_PROBABILITY) {
      accepted = true;
    }
  }

  return { iterations, work };
}

function stdev(values: number[]): number {
  if (values.length === 0) {
    return 0;
  }

  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  const variance = values.reduce((sum, value) => sum + (value - mean) * (value - mean), 0) / values.length;
  return Math.sqrt(variance);
}

export async function benchmarkHAWK(
  iterations: number = 100,
  paramSet: HawkParams = HAWK_512_PARAMS,
): Promise<{
  hawkKeygenMs: number;
  hawkSignMs: number;
  hawkSignStdev: number;
  hawkVerifyMs: number;
  falconSimulationMs: number;
  falconSimulationStdev: number;
  mldsaSimulationMs: number;
  mldsaSimulationStdev: number;
  mldsaAvgIterations: number;
  /**
   * Ratio of the simulated Falcon-style pass time to this build's HAWK sign
   * time. This is a within-this-JS-build artifact, NOT a HAWK-vs-Falcon
   * speedup: this HAWK uses O(n^2) schoolbook multiplication with no NTT,
   * so it is much slower here than a production HAWK would be, and the
   * Falcon path is a rough float-cost illustration. The value is exposed for
   * transparency, not as a performance claim.
   */
  illustrativeFalconToHawkTimeRatio: number;
}> {
  const message = encoder.encode('hawk benchmark message');

  const hawkSignSamples: number[] = [];
  const falconSamples: number[] = [];
  const mldsaSamples: number[] = [];
  const mldsaIterations: number[] = [];

  let keygenTotal = 0;
  let verifyTotal = 0;

  for (let index = 0; index < iterations; index += 1) {
    let startedAt = nowMs();
    const { privateKey, publicKey } = await hawkKeygen(paramSet);
    keygenTotal += nowMs() - startedAt;

    startedAt = nowMs();
    const { signature } = await hawkSign(message, privateKey);
    hawkSignSamples.push(nowMs() - startedAt);

    startedAt = nowMs();
    const verified = await hawkVerify(message, signature, publicKey);
    verifyTotal += nowMs() - startedAt;

    if (!verified) {
      throw new Error('Benchmark verification failed for a generated signature.');
    }

    startedAt = nowMs();
    simulateFalconSignWork(paramSet.n);
    falconSamples.push(nowMs() - startedAt);

    startedAt = nowMs();
    const { iterations: loops } = simulateMldsaSignWork(paramSet.n);
    mldsaSamples.push(nowMs() - startedAt);
    mldsaIterations.push(loops);
  }

  const mean = (values: number[]) => values.reduce((sum, value) => sum + value, 0) / values.length;
  const hawkSignMs = mean(hawkSignSamples);
  const falconSimulationMs = mean(falconSamples);
  const mldsaSimulationMs = mean(mldsaSamples);

  return {
    hawkKeygenMs: keygenTotal / iterations,
    hawkSignMs,
    hawkSignStdev: stdev(hawkSignSamples),
    hawkVerifyMs: verifyTotal / iterations,
    falconSimulationMs,
    falconSimulationStdev: stdev(falconSamples),
    mldsaSimulationMs,
    mldsaSimulationStdev: stdev(mldsaSamples),
    mldsaAvgIterations: mean(mldsaIterations),
    illustrativeFalconToHawkTimeRatio: falconSimulationMs / hawkSignMs,
  };
}

/**
 * Serialize a HAWK signature using a Golomb-Rice-style encoding for the
 * coordinate vector c = (c0, c1). Each coefficient is encoded as a sign bit +
 * unary high bits + a low-bits payload. The result is salt-prefixed and the
 * bit stream is packed into whole bytes. This is the same shape the HAWK v1.1
 * spec uses for its compact signature format, just with simplified parameters.
 */
export function serializeSignature(signature: HAWKSignature): Uint8Array {
  const params = getParamsForN(signature.n);
  const saltBytes = getSaltBytes(params);
  const lowBits = 5;
  const bits: number[] = [];

  const encodeCoefficient = (value: number): void => {
    const sign = value < 0 ? 1 : 0;
    const magnitude = Math.abs(value);
    const low = magnitude & ((1 << lowBits) - 1);
    const high = magnitude >> lowBits;

    bits.push(sign);
    for (let bit = lowBits - 1; bit >= 0; bit -= 1) {
      bits.push((low >> bit) & 1);
    }
    for (let count = 0; count < high; count += 1) {
      bits.push(1);
    }
    bits.push(0);
  };

  for (let index = 0; index < signature.c0.length; index += 1) {
    encodeCoefficient(signature.c0[index]);
  }
  for (let index = 0; index < signature.s1.length; index += 1) {
    encodeCoefficient(signature.s1[index]);
  }

  const byteLength = saltBytes + Math.ceil(bits.length / 8);
  const out = new Uint8Array(byteLength);
  out.set(signature.salt, 0);

  for (let index = 0; index < bits.length; index += 1) {
    if (bits[index]) {
      const target = saltBytes + (index >> 3);
      out[target] |= 1 << (7 - (index & 7));
    }
  }

  return out;
}

export function serializePublicKey(publicKey: HAWKPublicKey): Uint8Array {
  return concatBytes(
    serializePolynomial(publicKey.q00),
    serializePolynomial(publicKey.q01),
    serializePolynomial(publicKey.q11),
    serializePolynomial(publicKey.basisMod2.f),
    serializePolynomial(publicKey.basisMod2.g),
    serializePolynomial(publicKey.basisMod2.F),
    serializePolynomial(publicKey.basisMod2.G),
  );
}