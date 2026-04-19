import {
  polyAdd,
  polyInfNorm,
  polyMul,
  polyNormSquared,
  polySub,
  randomSmallPolynomial,
  zeroPoly,
  type Polynomial,
} from '../src/polynomial.ts';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function poly(values: number[]): Polynomial {
  return Int32Array.from(values);
}

const zeros = zeroPoly(8);
assert(zeros.length === 8, 'zeroPoly should return requested length.');
assert(zeros.every((value) => value === 0), 'zeroPoly should initialize all coefficients to 0.');

const left = poly([1, 2, -1, 0]);
const right = poly([3, -1, 2, 1]);

assert(
  JSON.stringify(Array.from(polyAdd(left, right))) === JSON.stringify([4, 1, 1, 1]),
  'polyAdd should add coefficient-wise.',
);
assert(
  JSON.stringify(Array.from(polySub(left, right))) === JSON.stringify([-2, 3, -3, -1]),
  'polySub should subtract coefficient-wise.',
);

const product = Array.from(polyMul(poly([0, 0, 0, 1]), poly([0, 1, 0, 0])));
assert(
  JSON.stringify(product) === JSON.stringify([-1, 0, 0, 0]),
  'polyMul should satisfy X^n = -1 in the negacyclic ring.',
);

const schoolbook = Array.from(polyMul(poly([1, 2, 3, 0]), poly([4, -1, 2, 0])));
assert(
  JSON.stringify(schoolbook) === JSON.stringify([-2, 7, 12, 1]),
  'polyMul should match expected negacyclic schoolbook multiplication.',
);

const norms = poly([-3, 4, 0, 2]);
assert(polyInfNorm(norms) === 4, 'polyInfNorm should report the largest absolute coefficient.');
assert(polyNormSquared(norms) === 29, 'polyNormSquared should sum integer coefficient squares.');

const sampled = randomSmallPolynomial(32);
assert(sampled.length === 32, 'randomSmallPolynomial should return requested length.');
assert(
  sampled.every((value) => Number.isInteger(value) && value >= -1 && value <= 1),
  'randomSmallPolynomial should only emit coefficients in {-1, 0, 1}.',
);

console.log('phase-1 verification passed');