import {
  DISCRETE_GAUSSIAN_TABLE_T0,
  DISCRETE_GAUSSIAN_TABLE_T1,
  EXPECTED_SIGMA,
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

// ── These two tables are this lab's own, not the specification's pair ───────
//
// The page copy, the honesty panel, the README and the gaussian.ts header all
// say so now, so the property is pinned here rather than asserted in prose.
//
// In HAWK v1.1, section 3.5.1, equations (36) and (37), T_0 and T_1 are the
// tails of the two PARITY COSETS of the signing Gaussian — T_0[k] = floor(2^78
// * P_0(2 + 2k)) over 2Z and T_1[k] = floor(2^78 * P_1(3 + 2k)) over 2Z + 1 —
// and Algorithm 14 (SamplerSign) walks both on every draw. Two cosets means two
// genuinely different tables: in the specification's own Table 5 the leading
// entries are 0.605 and 0.301 (HAWK-256), 0.688 and 0.422 (HAWK-512) and 0.693
// and 0.430 (HAWK-1024) once divided by 2^78, so T_1[0]/T_0[0] runs from 0.50
// to 0.62.
//
// This lab's two tables are tails of ONE centred Gaussian over all of Z at
// EXPECTED_SIGMA, scaled to 2^64, so they are near-identical instead. Both
// halves of the claim are checked: that the tables agree with each other, and
// that each agrees with the single-over-Z tail it is claimed to be. The
// reference tail is computed here, not copied from the tables.
const TWO_64 = 2 ** 64;

const weight = (k: number) => Math.exp(-(k * k) / (2 * EXPECTED_SIGMA * EXPECTED_SIGMA));
let partition = 0;
for (let k = -60; k <= 60; k += 1) partition += weight(k);
const tailOverZ = (threshold: number): number => {
  let mass = 0;
  for (let k = -60; k <= 60; k += 1) if (Math.abs(k) >= threshold) mass += weight(k);
  return mass / partition;
};

assert(
  DISCRETE_GAUSSIAN_TABLE_T0.length === DISCRETE_GAUSSIAN_TABLE_T1.length,
  "this lab's two tables are the same shape.",
);

const leadingRatio = Number(DISCRETE_GAUSSIAN_TABLE_T1[0]) / Number(DISCRETE_GAUSSIAN_TABLE_T0[0]);
assert(
  leadingRatio > 0.999,
  `this lab's T_0 and T_1 must be near-identical, not a coset pair: leading ratio is ` +
    `${leadingRatio.toFixed(6)} (the specification's coset pair sits between 0.50 and 0.62).`,
);

const labTables: Array<{ name: string; table: readonly bigint[] }> = [
  { name: 'T_0', table: DISCRETE_GAUSSIAN_TABLE_T0 },
  { name: 'T_1', table: DISCRETE_GAUSSIAN_TABLE_T1 },
];
let maxTailError = 0;
for (const { name, table } of labTables) {
  for (let k = 0; k < table.length; k += 1) {
    const stored = Number(table[k]) / TWO_64;
    const overZ = tailOverZ(k + 1);
    maxTailError = Math.max(maxTailError, Math.abs(stored - overZ));
    assert(
      Math.abs(stored - overZ) < 2e-3,
      `${name}[${k}] = ${stored.toFixed(6)} should be the single-Gaussian-over-Z tail ` +
        `P(|X| >= ${k + 1}) = ${overZ.toFixed(6)}, not a coset tail.`,
    );
  }
}

console.log(
  JSON.stringify({
    leadingRatio: Number(leadingRatio.toFixed(6)),
    maxTailError: Number(maxTailError.toExponential(2)),
    mean: Number(stats.mean.toFixed(4)),
    variance: Number(stats.variance.toFixed(4)),
    minObserved: stats.minObserved,
    maxObserved: stats.maxObserved,
  }),
);
console.log('phase-2 verification passed');