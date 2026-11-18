/**
 * A 2 x 2 model of the aligned-basis special case of the lattice isomorphism
 * problem, in exact rational arithmetic.
 *
 * It backs the "Related" note in Exhibit 1.5 about Polar-KEM, a first-round
 * NGCC candidate whose specified key generation publishes B_pk = O * B_red
 * with B_red publicly recomputable. The real result is Xiao, Chen and Zhang,
 * "Structural Cryptanalysis of Polar-KEM: Direct Recovery of the Secret
 * Isometry" (Proposition 2.1, Theorem 5.1, Section 5.6). This file is a toy
 * re-creation at dimension 2 and is labelled as modelled wherever it is shown.
 * It implements nothing of Polar-KEM itself: no polar codes, no Construction D,
 * no LLL.
 *
 * Convention: matrices are written as rows, and a basis matrix holds its basis
 * vectors as COLUMNS, as in the paper (Section 2.1).
 */

export interface Frac {
  readonly n: bigint;
  readonly d: bigint;
}

export type Matrix2 = readonly [readonly [Frac, Frac], readonly [Frac, Frac]];

function gcd(a: bigint, b: bigint): bigint {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;
  while (y !== 0n) [x, y] = [y, x % y];
  return x;
}

export function frac(n: bigint | number, d: bigint | number = 1): Frac {
  const num = BigInt(n);
  const den = BigInt(d);
  if (den === 0n) throw new Error('zero denominator');
  const g = gcd(num, den) || 1n;
  const sign = den < 0n ? -1n : 1n;
  return { n: (sign * num) / g, d: (sign * den) / g };
}

const add = (a: Frac, b: Frac): Frac => frac(a.n * b.d + b.n * a.d, a.d * b.d);
const sub = (a: Frac, b: Frac): Frac => frac(a.n * b.d - b.n * a.d, a.d * b.d);
const mul = (a: Frac, b: Frac): Frac => frac(a.n * b.n, a.d * b.d);
const div = (a: Frac, b: Frac): Frac => frac(a.n * b.d, a.d * b.n);
export const fracEquals = (a: Frac, b: Frac): boolean => a.n === b.n && a.d === b.d;

export function matrix(rows: readonly [readonly [bigint | number, bigint | number], readonly [bigint | number, bigint | number]]): Matrix2 {
  return [
    [frac(rows[0][0]), frac(rows[0][1])],
    [frac(rows[1][0]), frac(rows[1][1])],
  ];
}

/** Basis vectors (as the LIP exhibit stores them) to a column-basis matrix. */
export function basisFromVectors(vectors: readonly [readonly [number, number], readonly [number, number]]): Matrix2 {
  return matrix([
    [vectors[0][0], vectors[1][0]],
    [vectors[0][1], vectors[1][1]],
  ]);
}

export function multiply(a: Matrix2, b: Matrix2): Matrix2 {
  const cell = (i: 0 | 1, j: 0 | 1): Frac => add(mul(a[i][0], b[0][j]), mul(a[i][1], b[1][j]));
  return [
    [cell(0, 0), cell(0, 1)],
    [cell(1, 0), cell(1, 1)],
  ];
}

export function transpose(a: Matrix2): Matrix2 {
  return [
    [a[0][0], a[1][0]],
    [a[0][1], a[1][1]],
  ];
}

export function determinant(a: Matrix2): Frac {
  return sub(mul(a[0][0], a[1][1]), mul(a[0][1], a[1][0]));
}

export function inverse(a: Matrix2): Matrix2 {
  const det = determinant(a);
  if (det.n === 0n) throw new Error('matrix is singular');
  const neg = (x: Frac): Frac => frac(-x.n, x.d);
  return [
    [div(a[1][1], det), div(neg(a[0][1]), det)],
    [div(neg(a[1][0]), det), div(a[0][0], det)],
  ];
}

export function matrixEquals(a: Matrix2, b: Matrix2): boolean {
  return [0, 1].every((i) => [0, 1].every((j) => fracEquals(a[i][j], b[i][j])));
}

const IDENTITY: Matrix2 = matrix([
  [1, 0],
  [0, 1],
]);

/** O is orthogonal exactly when O^T O = I. */
export function isOrthogonal(a: Matrix2): boolean {
  return matrixEquals(multiply(transpose(a), a), IDENTITY);
}

/** An integer matrix with determinant +1 or -1. */
export function isUnimodular(a: Matrix2): boolean {
  const integral = a.every((row) => row.every((x) => x.d === 1n));
  const det = determinant(a);
  return integral && det.d === 1n && (det.n === 1n || det.n === -1n);
}

export function formatFrac(x: Frac): string {
  const sign = x.n < 0n ? '−' : '';
  const n = x.n < 0n ? -x.n : x.n;
  return x.d === 1n ? `${sign}${n}` : `${sign}${n}/${x.d}`;
}

export function formatMatrix(a: Matrix2): string {
  return `[[${formatFrac(a[0][0])}, ${formatFrac(a[0][1])}], [${formatFrac(a[1][0])}, ${formatFrac(a[1][1])}]]`;
}

export interface AlignedBasisModel {
  /** The publicly recomputable reference basis (B_red in the paper). */
  readonly reference: Matrix2;
  /** The secret orthogonal matrix O. */
  readonly secret: Matrix2;
  /** Aligned case: the published matrix O * B_red. */
  readonly alignedPublic: Matrix2;
  /** B_pk * B_red^-1. */
  readonly alignedRecovered: Matrix2;
  readonly alignedRecoversSecret: boolean;
  /** The unknown unimodular change of basis U of a general LIP instance. */
  readonly change: Matrix2;
  /** General case: the published matrix O * B_red * U. */
  readonly generalPublic: Matrix2;
  /** The same formula applied to the general case: B_2 * B_red^-1. */
  readonly generalNaive: Matrix2;
  readonly generalNaiveIsOrthogonal: boolean;
  readonly generalNaiveRecoversSecret: boolean;
}

/**
 * Publish an orthogonal image of a known basis two ways and try the one-step
 * formula on each: aligned (O * B), and with a unimodular change of basis
 * hidden on the right (O * B * U).
 */
export function alignedBasisModel(reference: Matrix2, secret: Matrix2, change: Matrix2): AlignedBasisModel {
  if (!isOrthogonal(secret)) throw new Error('the secret matrix must be orthogonal');
  if (!isUnimodular(change)) throw new Error('the change of basis must be unimodular');
  const referenceInverse = inverse(reference);
  const alignedPublic = multiply(secret, reference);
  const alignedRecovered = multiply(alignedPublic, referenceInverse);
  const generalPublic = multiply(multiply(secret, reference), change);
  const generalNaive = multiply(generalPublic, referenceInverse);
  return {
    reference,
    secret,
    alignedPublic,
    alignedRecovered,
    alignedRecoversSecret: matrixEquals(alignedRecovered, secret),
    change,
    generalPublic,
    generalNaive,
    generalNaiveIsOrthogonal: isOrthogonal(generalNaive),
    generalNaiveRecoversSecret: matrixEquals(generalNaive, secret),
  };
}

/**
 * The rational rotation with cosine 3/5 and sine 4/5. The paper builds its
 * exact-arithmetic test matrices from this 3-4-5 block (Section 5.5).
 */
export const ROTATION_3_4_5: Matrix2 = [
  [frac(3, 5), frac(-4, 5)],
  [frac(4, 5), frac(3, 5)],
];
