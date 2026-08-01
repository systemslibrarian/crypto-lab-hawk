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

// These thresholds are checked against freshly drawn random data on every run,
// so their false-positive rates were computed rather than eyeballed. T_1's
// exact moments are variance 2.02584 and sigma 1.42332; at N = 100000 the
// standard error of the mean is 0.00450 and of the variance is 0.00906.
//   * the +/-10 range checks are structural, not statistical: T_1 has 7
//     thresholds, so a magnitude cannot exceed 7 and the bound cannot be
//     crossed at all;
//   * |mean| < 0.05 sits 11.1 standard errors out;
//   * variance in (1.5, 2.4) sits 58 standard errors below and 41 above;
//   * the two histogram comparisons are 28040 vs 1096 and 43830 vs 112 in
//     expectation.
// None of these can realistically fire on a correct sampler. Contrast the
// chi-square check in verify-phase4.ts, whose tail is genuinely reachable and
// is handled there.
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