import {
  DISCRETE_GAUSSIAN_TABLE_T0,
  DISCRETE_GAUSSIAN_TABLE_T1,
  analyzeSampleDistribution,
  sampleDiscreteGaussian,
  sampleGaussianPolynomial,
} from '../src/gaussian.ts';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const sampleCount = 100000;
const samples: number[] = [];

for (let index = 0; index < sampleCount; index += 1) {
  samples.push(sampleDiscreteGaussian(DISCRETE_GAUSSIAN_TABLE_T1));
}

const stats = analyzeSampleDistribution(samples);
const poly = sampleGaussianPolynomial(64, DISCRETE_GAUSSIAN_TABLE_T0);

assert(poly.length === 64, 'sampleGaussianPolynomial should honor the requested degree.');
assert(stats.minObserved >= -10, 'Gaussian samples should stay within the expected lower range.');
assert(stats.maxObserved <= 10, 'Gaussian samples should stay within the expected upper range.');
assert(Math.abs(stats.mean) < 0.05, 'Gaussian mean should stay close to zero.');
assert(stats.variance > 1.5 && stats.variance < 2.4, 'Gaussian variance should stay near sigma^2.');
assert((stats.histogram.get(0) ?? 0) > (stats.histogram.get(4) ?? 0), 'Histogram should peak near zero.');
assert((stats.histogram.get(1) ?? 0) > (stats.histogram.get(5) ?? 0), 'Histogram should decay in the tails.');

console.log(
  JSON.stringify({
    mean: Number(stats.mean.toFixed(4)),
    variance: Number(stats.variance.toFixed(4)),
    minObserved: stats.minObserved,
    maxObserved: stats.maxObserved,
  }),
);
console.log('phase-2 verification passed');