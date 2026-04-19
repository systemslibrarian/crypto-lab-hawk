import { type Polynomial } from './polynomial';

/**
 * Discrete Gaussian sampler over the integer lattice Z.
 * THIS IS THE KEY DIFFERENCE FROM FALCON.
 *
 * HAWK uses two fixed precomputed lookup tables:
 *   - T_0: for sampling during key generation
 *   - T_1: for sampling during signing
 */

const EXPECTED_SIGMA = 1.425;

function getCrypto(): Crypto {
  if (!globalThis.crypto) {
    throw new Error('Web Crypto API is not available in this environment.');
  }

  return globalThis.crypto;
}

function randomUint64(): bigint {
  const words = new Uint32Array(2);
  getCrypto().getRandomValues(words);
  return (BigInt(words[0]) << 32n) | BigInt(words[1]);
}

function randomSignBit(): number {
  const byte = new Uint8Array(1);
  getCrypto().getRandomValues(byte);
  return byte[0] & 1;
}

/**
 * Tail thresholds scaled to 2^64 for an educational sigma ~= 1.425.
 * A sampled magnitude is the number of thresholds exceeded.
 */
export const DISCRETE_GAUSSIAN_TABLE_T0 = [
  13276121709848764416n,
  5196447805563980800n,
  1350301666195539200n,
  225050277699256544n,
  22873962651399844n,
  1475739525896764n,
  55340232221128n,
] as const satisfies readonly bigint[];

export const DISCRETE_GAUSSIAN_TABLE_T1 = [
  13274277035441303552n,
  5189079107934490624n,
  1348456991788168192n,
  224313407936307232n,
  22136086062411464n,
  1475739525896764n,
  55340232221128n,
] as const satisfies readonly bigint[];

/**
 * Sample a single integer from the discrete Gaussian over Z
 * using the provided CDT.
 *
 * Constant-time at the algorithm level: always walks the full table.
 */
export function sampleDiscreteGaussian(table: readonly bigint[]): number {
  const random = randomUint64();
  let magnitude = 0;

  for (let index = 0; index < table.length; index += 1) {
    if (random < table[index]) {
      magnitude += 1;
    }
  }

  if (magnitude === 0) {
    return 0;
  }

  return randomSignBit() === 0 ? magnitude : -magnitude;
}

/**
 * Sample a polynomial with coefficients from the discrete Gaussian.
 */
export function sampleGaussianPolynomial(
  n: number,
  table: readonly bigint[],
): Polynomial {
  const coefficients = new Int32Array(n);

  for (let index = 0; index < n; index += 1) {
    coefficients[index] = sampleDiscreteGaussian(table);
  }

  return coefficients;
}

/**
 * Analyze samples: compute mean, variance, and compare to expected
 * Gaussian parameters. Used in UI to show the sampler is working.
 */
export function analyzeSampleDistribution(samples: number[]): {
  mean: number;
  variance: number;
  expectedSigma: number;
  minObserved: number;
  maxObserved: number;
  histogram: Map<number, number>;
} {
  if (samples.length === 0) {
    throw new Error('Cannot analyze an empty sample set.');
  }

  let total = 0;
  let totalSquares = 0;
  let minObserved = samples[0];
  let maxObserved = samples[0];
  const histogram = new Map<number, number>();

  for (let index = 0; index < samples.length; index += 1) {
    const sample = samples[index];
    total += sample;
    totalSquares += sample * sample;
    minObserved = Math.min(minObserved, sample);
    maxObserved = Math.max(maxObserved, sample);
    histogram.set(sample, (histogram.get(sample) ?? 0) + 1);
  }

  const mean = total / samples.length;
  const variance = totalSquares / samples.length - mean * mean;

  return {
    mean,
    variance,
    expectedSigma: EXPECTED_SIGMA,
    minObserved,
    maxObserved,
    histogram,
  };
}