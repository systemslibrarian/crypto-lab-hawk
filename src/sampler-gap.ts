/**
 * Sampler-gap bench.
 *
 * This build signs by solving c = (B mod 2)^{-1} h — a public linear map.
 * Production HAWK signs by drawing the coset representative from a discrete
 * Gaussian over the secret basis. The README and the honesty panel have always
 * *stated* what that difference costs. This module measures it.
 *
 * It runs both samplers against the same key and the same message and reports
 * five properties, each computed from the run rather than asserted:
 *
 *   1. Reproducibility   — sign twice under a pinned salt, count differing
 *                          coefficients. The linear solve is a function of
 *                          (message, salt); a sampler is not.
 *   2. Linearity over Z  — is c(h_a ⊕ h_b) exactly c(h_a) ⊕ c(h_b) as integers?
 *   3. Linearity mod 2   — is it still true after reduction mod 2?
 *   4. Coefficient shape — distinct values and Shannon entropy per coefficient.
 *   5. Forgeability      — run each sampler's public-key-only forger and hand
 *                          the result to the unmodified verifier.
 *
 * Rows 2, 3 and 5 are the ones that matter, and they land in an order that is
 * easy to get wrong by intuition: the Gaussian offset destroys reproducibility
 * and integer linearity, and changes nothing at all about forgeability, because
 * 2z ≡ 0 (mod 2) leaves the parity coset untouched and the parity coset is the
 * only thing the forger needs. The gap production HAWK keeps is not the
 * Gaussian; it is that a public key of (q00, q01) alone never reveals B mod 2.
 */

import {
  hawkCosetNorm,
  hawkForgeFromPublicKey,
  hawkForgeGaussianCoset,
  hawkParityTarget,
  hawkPublicKeyHash,
  hawkSaltBytes,
  hawkSign,
  hawkSignGaussianCoset,
  hawkVerifyDetailed,
  solveCosetGaussian,
  solveCosetLinear,
  type CosetCoordinates,
  type HAWKPrivateKey,
  type HAWKPublicKey,
} from './hawk';
import { type Polynomial } from './polynomial';

export type SamplerId = 'linear' | 'gaussian';

export interface SamplerColumn {
  id: SamplerId;
  label: string;
  /** Total coordinate coefficients examined (2n). */
  coefficientCount: number;
  /** Coefficients that differ between two signings of the same (message, salt). */
  reproducibilityDiff: number;
  /** Coefficients where c(h_a ⊕ h_b) equals c(h_a) ⊕ c(h_b) exactly, as integers. */
  linearOverZMatches: number;
  /** The same comparison taken mod 2. */
  linearMod2Matches: number;
  /** Distinct integer values appearing in one signature's coordinates. */
  distinctValues: number;
  /** Shannon entropy of the coefficient distribution, in bits per coefficient. */
  entropyBitsPerCoefficient: number;
  /** Mean ||B·c||² over the sampled signatures, from the public Gram matrix. */
  meanNorm: number;
  /** Largest ||B·c||² observed, which is what the bound has to clear. */
  maxNorm: number;
  /** The acceptance bound this column was run under. */
  boundUsed: number;
  /** Did the public-key-only forger produce something the verifier accepted? */
  forgeryAccepted: boolean;
  /** The forged signature's ||B·c||². */
  forgeryNorm: number;
  /** Did the forged signature land in the message's parity coset? */
  forgeryCosetHolds: boolean;
}

export interface SamplerGapReport {
  n: number;
  samples: number;
  columns: SamplerColumn[];
  /** Ratio of the two mean norms — how much longer a Gaussian signature is. */
  normInflation: number;
  /** Structural properties whose measured value differs between the columns. */
  changedProperties: number;
  /** Structural properties compared. */
  comparedProperties: number;
  /** True when both samplers were forged successfully by the same verifier. */
  bothForgeable: boolean;
  elapsedMs: number;
}

const encoder = new TextEncoder();

function nowMs(): number {
  return globalThis.performance?.now() ?? Date.now();
}

function parityOf(value: number): number {
  return ((value % 2) + 2) % 2;
}

/** Count coefficients on which two coordinate vectors disagree. */
function coordinateDifference(a: CosetCoordinates, b: CosetCoordinates): number {
  let differing = 0;
  for (let index = 0; index < a.c0.length; index += 1) {
    if (a.c0[index] !== b.c0[index]) {
      differing += 1;
    }
    if (a.c1[index] !== b.c1[index]) {
      differing += 1;
    }
  }
  return differing;
}

/** Distinct values and Shannon entropy of one signature's coefficients. */
function coefficientShape(coordinates: CosetCoordinates): {
  distinctValues: number;
  entropyBitsPerCoefficient: number;
} {
  const counts = new Map<number, number>();
  const total = coordinates.c0.length + coordinates.c1.length;

  for (const source of [coordinates.c0, coordinates.c1]) {
    for (let index = 0; index < source.length; index += 1) {
      const value = source[index];
      counts.set(value, (counts.get(value) ?? 0) + 1);
    }
  }

  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / total;
    entropy -= probability * Math.log2(probability);
  }

  return { distinctValues: counts.size, entropyBitsPerCoefficient: entropy };
}

/** A uniformly random parity target, standing in for a hashed message. */
function randomTarget(n: number): { h0: Polynomial; h1: Polynomial } {
  const bytes = new Uint8Array(2 * n);
  globalThis.crypto.getRandomValues(bytes);
  const h0 = new Int32Array(n);
  const h1 = new Int32Array(n);
  for (let index = 0; index < n; index += 1) {
    h0[index] = bytes[index] & 1;
    h1[index] = bytes[n + index] & 1;
  }
  return { h0, h1 };
}

function xorTargets(
  a: { h0: Polynomial; h1: Polynomial },
  b: { h0: Polynomial; h1: Polynomial },
): { h0: Polynomial; h1: Polynomial } {
  const n = a.h0.length;
  const h0 = new Int32Array(n);
  const h1 = new Int32Array(n);
  for (let index = 0; index < n; index += 1) {
    h0[index] = a.h0[index] ^ b.h0[index];
    h1[index] = a.h1[index] ^ b.h1[index];
  }
  return { h0, h1 };
}

/**
 * Is the solver additive? Solve two random targets and their XOR, then compare
 * the third answer against the XOR of the first two — once as integers and once
 * mod 2. A solver that is a GF(2)-linear map matches on both counts; a sampler
 * matches only on the second, and only because its offset is even.
 */
function measureLinearity(
  publicKey: HAWKPublicKey,
  solve: (h0: Polynomial, h1: Polynomial) => CosetCoordinates,
): { overZ: number; mod2: number; total: number } {
  const targetA = randomTarget(publicKey.n);
  const targetB = randomTarget(publicKey.n);
  const targetAB = xorTargets(targetA, targetB);

  const a = solve(targetA.h0, targetA.h1);
  const b = solve(targetB.h0, targetB.h1);
  const ab = solve(targetAB.h0, targetAB.h1);

  let overZ = 0;
  let mod2 = 0;
  let total = 0;

  for (const [left, right, combined] of [
    [a.c0, b.c0, ab.c0],
    [a.c1, b.c1, ab.c1],
  ] as const) {
    for (let index = 0; index < left.length; index += 1) {
      const expected = parityOf(left[index]) ^ parityOf(right[index]);
      if (combined[index] === expected) {
        overZ += 1;
      }
      if (parityOf(combined[index]) === expected) {
        mod2 += 1;
      }
      total += 1;
    }
  }

  return { overZ, mod2, total };
}

async function measureColumn(
  id: SamplerId,
  label: string,
  message: Uint8Array,
  privateKey: HAWKPrivateKey,
  publicKey: HAWKPublicKey,
  samples: number,
): Promise<SamplerColumn> {
  const pinnedSalt = new Uint8Array(hawkSaltBytes(publicKey.n));
  globalThis.crypto.getRandomValues(pinnedSalt);
  const pubKeyHash = await hawkPublicKeyHash(publicKey);
  const { h0, h1 } = await hawkParityTarget(message, pinnedSalt, pubKeyHash, publicKey.n);

  const solve = id === 'linear'
    ? (a: Polynomial, b: Polynomial) => solveCosetLinear(publicKey, a, b)
    : (a: Polynomial, b: Polynomial) => solveCosetGaussian(publicKey, a, b);

  // 1. Reproducibility: two solves of the identical target.
  const first = solve(h0, h1);
  const second = solve(h0, h1);
  const reproducibilityDiff = coordinateDifference(first, second);

  // 2 & 3. Additivity over Z and mod 2.
  const linearity = measureLinearity(publicKey, solve);

  // 4. Coefficient shape of a real signature's coordinates.
  const shape = coefficientShape(first);

  // 5. Norms across independent salts, which set the bound this column needs.
  let normTotal = 0;
  let maxNorm = 0;
  for (let sample = 0; sample < samples; sample += 1) {
    const salt = new Uint8Array(hawkSaltBytes(publicKey.n));
    globalThis.crypto.getRandomValues(salt);
    const target = await hawkParityTarget(message, salt, pubKeyHash, publicKey.n);
    const norm = hawkCosetNorm(publicKey, solve(target.h0, target.h1));
    normTotal += norm;
    maxNorm = Math.max(maxNorm, norm);
  }
  const meanNorm = normTotal / samples;

  // The bound each column is judged under is derived from that column's own
  // measured norms, so the forgery test is not decided by a constant that
  // happens to suit one sampler.
  const boundUsed = Math.ceil(maxNorm * 1.25);

  // A genuine signature under this sampler must verify at that bound, or the
  // forgery comparison below would be meaningless.
  if (id === 'linear') {
    await hawkSign(message, privateKey, boundUsed);
  } else {
    await hawkSignGaussianCoset(message, privateKey, publicKey, boundUsed);
  }

  // 6. The forgery, from the public key alone, through the unmodified verifier.
  const forged = id === 'linear'
    ? await hawkForgeFromPublicKey(message, publicKey, boundUsed)
    : await hawkForgeGaussianCoset(message, publicKey, boundUsed);
  const detail = await hawkVerifyDetailed(message, forged.signature, publicKey, boundUsed);

  return {
    id,
    label,
    coefficientCount: linearity.total,
    reproducibilityDiff,
    linearOverZMatches: linearity.overZ,
    linearMod2Matches: linearity.mod2,
    distinctValues: shape.distinctValues,
    entropyBitsPerCoefficient: shape.entropyBitsPerCoefficient,
    meanNorm,
    maxNorm,
    boundUsed,
    forgeryAccepted: detail.ok,
    forgeryNorm: detail.totalNorm,
    forgeryCosetHolds: detail.identityHolds,
  };
}

/**
 * Run the bench. Every number in the returned report is computed here; nothing
 * is filled in from a constant.
 */
export async function runSamplerGap(
  privateKey: HAWKPrivateKey,
  publicKey: HAWKPublicKey,
  messageText: string,
  samples = 3,
): Promise<SamplerGapReport> {
  const startedAt = nowMs();
  const message = encoder.encode(messageText);

  const linear = await measureColumn(
    'linear',
    'This build: mod-2 linear solve',
    message,
    privateKey,
    publicKey,
    samples,
  );
  const gaussian = await measureColumn(
    'gaussian',
    'Discrete-Gaussian coset sampler (T₁)',
    message,
    privateKey,
    publicKey,
    samples,
  );

  // Which structural properties the Gaussian offset actually moved. Counted
  // rather than claimed, because the interesting part is which one it misses.
  const comparisons: Array<[number, number]> = [
    [linear.reproducibilityDiff, gaussian.reproducibilityDiff],
    [linear.linearOverZMatches, gaussian.linearOverZMatches],
    [linear.linearMod2Matches, gaussian.linearMod2Matches],
    [linear.distinctValues, gaussian.distinctValues],
    [Math.round(linear.meanNorm), Math.round(gaussian.meanNorm)],
  ];
  const changedProperties = comparisons.filter(([a, b]) => a !== b).length;

  return {
    n: publicKey.n,
    samples,
    columns: [linear, gaussian],
    normInflation: gaussian.meanNorm / linear.meanNorm,
    changedProperties,
    comparedProperties: comparisons.length,
    bothForgeable: linear.forgeryAccepted && gaussian.forgeryAccepted,
    elapsedMs: nowMs() - startedAt,
  };
}
