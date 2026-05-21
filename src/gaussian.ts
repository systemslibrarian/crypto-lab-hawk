import { type Polynomial } from './polynomial';

/**
 * Discrete Gaussian sampler over the integer lattice Z.
 * THIS IS THE KEY DIFFERENCE FROM FALCON.
 *
 * HAWK uses two fixed precomputed lookup tables:
 *   - T_0: for sampling during key generation
 *   - T_1: for sampling during signing
 */

export const EXPECTED_SIGMA = 1.425;

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

export interface CdtWalkStep {
  thresholdIndex: number;
  threshold: bigint;
  randomWord: bigint;
  isLess: boolean;
  magnitudeAfter: number;
}

export interface CdtWalkTrace {
  randomWord: bigint;
  table: readonly bigint[];
  steps: CdtWalkStep[];
  magnitude: number;
  signBit: number;
  sample: number;
}

/**
 * Trace one CDT walk for pedagogical display. Same control flow as
 * sampleDiscreteGaussian, but records each threshold comparison so the UI
 * can step through it.
 */
export function traceDiscreteGaussian(table: readonly bigint[]): CdtWalkTrace {
  const randomWord = randomUint64();
  const steps: CdtWalkStep[] = [];
  let magnitude = 0;

  for (let index = 0; index < table.length; index += 1) {
    const threshold = table[index];
    const isLess = randomWord < threshold;
    if (isLess) {
      magnitude += 1;
    }
    steps.push({
      thresholdIndex: index,
      threshold,
      randomWord,
      isLess,
      magnitudeAfter: magnitude,
    });
  }

  const signBit = magnitude === 0 ? 0 : randomSignBit();
  const sample = magnitude === 0 ? 0 : signBit === 0 ? magnitude : -magnitude;

  return { randomWord, table, steps, magnitude, signBit, sample };
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
 * Closed-form theoretical PMF of the centered discrete Gaussian over Z at sigma.
 * Useful for overlaying the expected curve on the observed histogram.
 */
export function discreteGaussianPmf(sigma: number, span: number): Array<[number, number]> {
  const denomTwoSigmaSq = 2 * sigma * sigma;
  const unnormalised: Array<[number, number]> = [];
  let total = 0;

  for (let k = -span; k <= span; k += 1) {
    const weight = Math.exp(-(k * k) / denomTwoSigmaSq);
    unnormalised.push([k, weight]);
    total += weight;
  }

  return unnormalised.map(([k, weight]) => [k, weight / total]);
}

/**
 * Reference Falcon-style discrete Gaussian over Z, built on a Box-Muller core.
 * This is intentionally float-heavy: it walks through a continuous Gaussian
 * draw, a Karney-style integer rounding, and a rejection check against the
 * exact ratio of the discrete to the continuous density. It is NOT the
 * production Falcon sampler, but it captures the real engineering cost that
 * Falcon pays: transcendentals (Math.log, Math.cos, Math.exp), float
 * arithmetic on the critical path, and a rejection loop.
 *
 * The point of having this in the lab is to compare its wall-clock cost
 * against HAWK's pure-integer CDT walk honestly, without a hand-tuned
 * multiplier.
 */
const FALCON_REF_SIGMA = 1.55;

function boxMullerPair(): [number, number] {
  let u1 = 0;
  let u2 = 0;
  while (u1 === 0) {
    u1 = Math.random();
  }
  u2 = Math.random();
  const radius = Math.sqrt(-2 * Math.log(u1));
  const angle = 2 * Math.PI * u2;
  return [radius * Math.cos(angle), radius * Math.sin(angle)];
}

let pendingBoxMuller: number | null = null;

function nextStandardNormal(): number {
  if (pendingBoxMuller !== null) {
    const cached = pendingBoxMuller;
    pendingBoxMuller = null;
    return cached;
  }

  const [first, second] = boxMullerPair();
  pendingBoxMuller = second;
  return first;
}

export function sampleFalconStyleDiscreteGaussian(sigma: number = FALCON_REF_SIGMA): number {
  while (true) {
    const continuous = nextStandardNormal() * sigma;
    const rounded = Math.round(continuous);
    const deltaSq = (continuous - rounded) * (continuous - rounded);
    const acceptanceProbability = Math.exp(-deltaSq / (2 * sigma * sigma));
    if (Math.random() < acceptanceProbability) {
      return rounded;
    }
  }
}

function floatFftPass(real: Float64Array, imag: Float64Array): void {
  const n = real.length;
  for (let stride = 1; stride < n; stride *= 2) {
    const step = 2 * stride;
    for (let block = 0; block < n; block += step) {
      for (let offset = 0; offset < stride; offset += 1) {
        const angle = (-Math.PI * offset) / stride;
        const twiddleReal = Math.cos(angle);
        const twiddleImag = Math.sin(angle);
        const i = block + offset;
        const j = i + stride;
        const tr = twiddleReal * real[j] - twiddleImag * imag[j];
        const ti = twiddleReal * imag[j] + twiddleImag * real[j];
        real[j] = real[i] - tr;
        imag[j] = imag[i] - ti;
        real[i] += tr;
        imag[i] += ti;
      }
    }
  }
}

/**
 * Falcon-style polynomial sampling: a Box-Muller leaf draw at every
 * coefficient. Used for cheaper exhibits where we only need leaf-level cost.
 */
export function sampleFalconStylePolynomial(n: number, sigma: number = FALCON_REF_SIGMA): Float64Array {
  const real = new Float64Array(n);
  const imag = new Float64Array(n);

  for (let index = 0; index < n; index += 1) {
    real[index] = sampleFalconStyleDiscreteGaussian(sigma);
  }

  floatFftPass(real, imag);
  return real;
}

/**
 * Honest model of one Falcon signing pass. Falcon's signing critical path
 * is fast Fourier sampling: a recursive tree traversal over R[X]/(X^n+1)
 * where every node samples a discrete Gaussian and recombines via an FFT.
 * The total work is roughly O(n log n) Gaussian draws plus O(log n) FFT
 * passes plus a Babai-style rounding pass. That is what we cost here.
 *
 * This is intentionally not the production Falcon sampler. The point is
 * that the FALCON_REF_SIGMA leaf draw, the float FFT, and the rounding all
 * use real transcendentals and float arithmetic, so the wall-clock cost
 * scales the way the production code does.
 */
export function simulateFalconFastFourierSamplingPass(
  n: number,
  sigma: number = FALCON_REF_SIGMA,
): { leafSamples: number; accumulator: number } {
  const real = new Float64Array(n);
  const imag = new Float64Array(n);
  let leafSamples = 0;
  let accumulator = 0;

  const depth = Math.log2(n);
  for (let level = 0; level < depth; level += 1) {
    const nodes = 1 << level;
    const nodeSize = n / nodes;
    const levelSigma = sigma * Math.sqrt(1 + level / depth);

    for (let node = 0; node < nodes; node += 1) {
      for (let offset = 0; offset < nodeSize; offset += 1) {
        const draw = sampleFalconStyleDiscreteGaussian(levelSigma);
        const index = node * nodeSize + offset;
        real[index] += draw;
        leafSamples += 1;
      }
    }

    floatFftPass(real, imag);
  }

  for (let index = 0; index < n; index += 1) {
    const target = real[index];
    const rounded = Math.round(target);
    accumulator += Math.exp(-(target - rounded) * (target - rounded));
  }

  return { leafSamples, accumulator };
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