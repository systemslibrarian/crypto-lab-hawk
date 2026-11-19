/**
 * Phase 8: the aligned-basis model behind the Polar-KEM "Related" note.
 *
 * The note in Exhibit 1.5 says two things about a 2 x 2 model, and this file
 * pins both, in both directions:
 *
 *   aligned   B_pk = O * B_red        ->  B_pk * B_red^-1 IS O
 *   general   B_2  = O * B_red * U    ->  B_2  * B_red^-1 is NOT O, and is not
 *                                         even orthogonal, unless U = I
 *
 * These are the statements of Proposition 2.1, Theorem 5.1 and Section 5.6 of
 * Xiao, Chen and Zhang, "Structural Cryptanalysis of Polar-KEM: Direct Recovery
 * of the Secret Isometry", at dimension 2. Nothing here runs Polar-KEM, and no
 * figure about Polar-KEM is derived here: the note quotes those from the paper.
 */

import {
  ROTATION_3_4_5,
  alignedBasisModel,
  basisFromVectors,
  determinant,
  formatMatrix,
  frac,
  fracEquals,
  inverse,
  isOrthogonal,
  isUnimodular,
  matrix,
  matrixEquals,
  multiply,
  transpose,
  type Matrix2,
} from '../src/aligned-basis.js';

let checks = 0;

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`phase-8 assertion failed: ${message}`);
  }
  checks += 1;
}

const IDENTITY = matrix([
  [1, 0],
  [0, 1],
]);

// The two bases Exhibit 1.5 draws, as the exhibit stores them (basis vectors).
const SHORT = basisFromVectors([
  [2, 0],
  [0, 2],
]);
const BAD = basisFromVectors([
  [2, 0],
  [6, 2],
]);

// 1. The rotation is what the note calls it.
assert(isOrthogonal(ROTATION_3_4_5), 'the 3-4-5 rotation must satisfy O^T O = I');
assert(fracEquals(determinant(ROTATION_3_4_5), frac(1)), 'the 3-4-5 rotation must have determinant 1');
assert(formatMatrix(ROTATION_3_4_5) === '[[3/5, −4/5], [4/5, 3/5]]', 'the rotation must format as printed');
assert(matrixEquals(inverse(ROTATION_3_4_5), transpose(ROTATION_3_4_5)), 'O^-1 must equal O^T');
console.log('PASS  the 3-4-5 rotation is orthogonal with determinant 1');

// 2. The exhibit's bad basis is the short basis times a unimodular U, so the two
//    really are bases of one lattice and U really is a legal LIP change of basis.
const change = multiply(inverse(SHORT), BAD);
assert(isUnimodular(change), 'short^-1 * bad must be unimodular');
assert(matrixEquals(multiply(SHORT, change), BAD), 'short * U must reproduce the bad basis');
assert(!matrixEquals(change, IDENTITY), 'U must not be the identity, or the contrast shows nothing');
console.log(`PASS  the exhibit's bad basis is its short basis times unimodular U = ${formatMatrix(change)}`);

// 3. Aligned case: one linear solve returns the secret exactly.
const model = alignedBasisModel(SHORT, ROTATION_3_4_5, change);
assert(model.alignedRecoversSecret, 'B_pk * B_red^-1 must equal O in the aligned case');
assert(matrixEquals(model.alignedRecovered, ROTATION_3_4_5), 'the recovered matrix must be O entry for entry');
assert(isOrthogonal(model.alignedRecovered), 'the recovered matrix must be orthogonal');
assert(matrixEquals(multiply(model.alignedRecovered, SHORT), model.alignedPublic), 'recovered * B_red must equal B_pk');
assert(!matrixEquals(model.alignedPublic, SHORT), 'the published basis must differ from the reference basis');
console.log(`PASS  aligned: B_pk = ${formatMatrix(model.alignedPublic)} gives back O = ${formatMatrix(model.alignedRecovered)}`);

// 4. General case: the same formula does not return O, and its output is not
//    orthogonal, so an attacker can tell it failed.
assert(!model.generalNaiveRecoversSecret, 'with U != I the one-step formula must NOT return O');
assert(!model.generalNaiveIsOrthogonal, 'with U != I the one-step output must not be orthogonal');
assert(matrixEquals(model.generalNaive, multiply(ROTATION_3_4_5, multiply(multiply(SHORT, change), inverse(SHORT)))),
  'the naive output must equal O * (B U B^-1)');
console.log(`PASS  general: the same formula returns ${formatMatrix(model.generalNaive)}, not orthogonal`);

// 5. The contrast is about U and nothing else: with U = I the general case IS
//    the aligned case. Without this control a model that always failed the
//    general branch would pass check 4.
const trivial = alignedBasisModel(SHORT, ROTATION_3_4_5, IDENTITY);
assert(trivial.generalNaiveRecoversSecret && trivial.generalNaiveIsOrthogonal, 'with U = I the general case must reduce to the aligned one');
console.log('PASS  control: with U = I the general instance is the aligned instance');

// 6. It is not an artefact of the short basis being a multiple of the identity.
//    Take the skewed bad basis as the reference, and three other unimodular U.
const others: Matrix2[] = [
  matrix([[1, 1], [0, 1]]),
  matrix([[0, 1], [-1, 0]]),
  matrix([[2, 1], [1, 1]]),
];
const skewed = alignedBasisModel(BAD, ROTATION_3_4_5, others[0]);
assert(skewed.alignedRecoversSecret, 'the aligned identity must hold for a skewed reference basis too');
for (const u of others) {
  const run = alignedBasisModel(BAD, ROTATION_3_4_5, u);
  assert(isUnimodular(u), `${formatMatrix(u)} must be unimodular`);
  assert(run.alignedRecoversSecret, `aligned recovery must hold beside U = ${formatMatrix(u)}`);
  assert(!run.generalNaiveRecoversSecret, `the formula must not return O for U = ${formatMatrix(u)}`);
}
console.log('PASS  the identity and the contrast hold for a skewed reference basis and three other U');

// 7. Guards: a non-orthogonal "secret" and a non-unimodular "U" are refused
//    rather than modelled, so the note can never describe something else.
let refused = 0;
for (const attempt of [
  () => alignedBasisModel(SHORT, matrix([[1, 1], [0, 1]]), IDENTITY),
  () => alignedBasisModel(SHORT, ROTATION_3_4_5, matrix([[2, 0], [0, 1]])),
]) {
  try {
    attempt();
  } catch {
    refused += 1;
  }
}
assert(refused === 2, 'a non-orthogonal secret and a non-unimodular U must both be refused');
console.log('PASS  non-orthogonal secrets and non-unimodular changes of basis are refused');

console.log(`\nPhase 8: ${checks} checks passed.`);
