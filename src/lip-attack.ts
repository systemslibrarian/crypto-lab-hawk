/**
 * The 2026 module-LIP key-recovery attack, at toy parameters.
 *
 * Straznickas and Weis, "HAWK-n Key Recovery Reduces to SVP in Dimension
 * n/2 + 1" (Anthropic, July 2026), reduce HAWK key recovery to shortest-vector
 * calls in half the dimension the scheme's parameters were sized against. This
 * module runs that reduction end to end, from the public key alone, at n = 4
 * and n = 8 — small enough that plain LLL stands in for the sieve and the whole
 * thing finishes in a browser tick.
 *
 * The three steps are the paper's own:
 *
 *   1. From Q alone, build the tau-cocycle lattice: the integer solutions of
 *      two Z-linear constraints whose coefficients come from Q and tau(Q).
 *      It has rank n and contains V = B^-1 tau(B) as a shortest vector.
 *   2. Reduce and enumerate. There are exactly 2(n/2 + 1) shortest vectors.
 *   3. Parity-test Y = I (mod 2) to single out the two real cocycles, then
 *      descend to a basis B' with B'* B' = Q.
 *
 * Deliberately separate from src/hawk.ts. That module is the HAWK-512/1024
 * teaching build and its keys are NOT unimodular, so it has no cocycle to
 * recover; this one builds genuine det = 1 keys at toy size. Nothing here
 * touches the demo's signing path, and nothing here threatens real HAWK: the
 * attack's cost is SVP in dimension n/2 + 1, which is 257 at HAWK-512.
 *
 * Arbitrary-precision throughout. The raw kernel basis has entries hundreds of
 * digits long before reduction, which is exactly what LLL is for.
 */

// ---------------------------------------------------------------------------
// R = Z[x]/(x^n + 1), coefficients as bigint
// ---------------------------------------------------------------------------

export type ToyPoly = bigint[];
export type ToyMatrix = [[ToyPoly, ToyPoly], [ToyPoly, ToyPoly]];

export const TOY_DEGREES = [4, 8] as const;
export type ToyDegree = (typeof TOY_DEGREES)[number];

function rzero(n: number): ToyPoly {
  return new Array<bigint>(n).fill(0n);
}

function rone(n: number): ToyPoly {
  const r = rzero(n);
  r[0] = 1n;
  return r;
}

function radd(a: ToyPoly, b: ToyPoly): ToyPoly {
  return a.map((x, i) => x + b[i]);
}

function rsub(a: ToyPoly, b: ToyPoly): ToyPoly {
  return a.map((x, i) => x - b[i]);
}

function rneg(a: ToyPoly): ToyPoly {
  return a.map((x) => -x);
}

/** Negacyclic convolution: x^n = -1. */
function rmul(a: ToyPoly, b: ToyPoly, n: number): ToyPoly {
  const r = rzero(n);
  for (let i = 0; i < n; i += 1) {
    if (a[i] === 0n) continue;
    for (let j = 0; j < n; j += 1) {
      if (b[j] === 0n) continue;
      const k = i + j;
      if (k < n) r[k] += a[i] * b[j];
      else r[k - n] -= a[i] * b[j];
    }
  }
  return r;
}

/** The Galois involution tau: zeta -> -zeta. Flips the odd coefficients. */
function rtau(a: ToyPoly): ToyPoly {
  return a.map((c, i) => (i % 2 === 0 ? c : -c));
}

/** Complex conjugation c: zeta -> zeta^-1 = -zeta^(n-1). */
function rconj(a: ToyPoly, n: number): ToyPoly {
  const r = rzero(n);
  r[0] = a[0];
  for (let i = 1; i < n; i += 1) r[n - i] = -a[i];
  return r;
}

function req(a: ToyPoly, b: ToyPoly): boolean {
  return a.every((x, i) => x === b[i]);
}

// ---------------------------------------------------------------------------
// 2x2 matrices over R
// ---------------------------------------------------------------------------

function mmul(A: ToyMatrix, B: ToyMatrix, n: number): ToyMatrix {
  const out = [
    [rzero(n), rzero(n)],
    [rzero(n), rzero(n)],
  ] as ToyMatrix;
  for (let i = 0; i < 2; i += 1) {
    for (let j = 0; j < 2; j += 1) {
      out[i][j] = radd(rmul(A[i][0], B[0][j], n), rmul(A[i][1], B[1][j], n));
    }
  }
  return out;
}

function msub(A: ToyMatrix, B: ToyMatrix): ToyMatrix {
  return [
    [rsub(A[0][0], B[0][0]), rsub(A[0][1], B[0][1])],
    [rsub(A[1][0], B[1][0]), rsub(A[1][1], B[1][1])],
  ];
}

function mdet(A: ToyMatrix, n: number): ToyPoly {
  return rsub(rmul(A[0][0], A[1][1], n), rmul(A[0][1], A[1][0], n));
}

/** adj is LINEAR in the entries — the reason constraint (C1) is a lattice condition. */
function madj(A: ToyMatrix): ToyMatrix {
  return [
    [A[1][1], rneg(A[0][1])],
    [rneg(A[1][0]), A[0][0]],
  ];
}

function mstar(A: ToyMatrix, n: number): ToyMatrix {
  return [
    [rconj(A[0][0], n), rconj(A[1][0], n)],
    [rconj(A[0][1], n), rconj(A[1][1], n)],
  ];
}

function mtau(A: ToyMatrix): ToyMatrix {
  return [
    [rtau(A[0][0]), rtau(A[0][1])],
    [rtau(A[1][0]), rtau(A[1][1])],
  ];
}

function mid(n: number): ToyMatrix {
  return [
    [rone(n), rzero(n)],
    [rzero(n), rone(n)],
  ];
}

function meq(A: ToyMatrix, B: ToyMatrix): boolean {
  for (let i = 0; i < 2; i += 1) {
    for (let j = 0; j < 2; j += 1) if (!req(A[i][j], B[i][j])) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Toy keygen
// ---------------------------------------------------------------------------

export type Rng = () => number;

/**
 * A unimodular basis B = [[f,F],[g,G]] with det B = fG - gF = 1, built as a
 * product of elementary matrices with short entries.
 *
 * det B = 1 is the only key property the attack needs. Lemma 4.4 of the paper
 * fixes the cocycle's length at n/4 "regardless of the key-generation
 * distribution", so a constructed unimodular basis exercises the attack exactly
 * as a sampled one would. Real HAWK reaches det B = 1 by solving the NTRU
 * equation f*G - g*F = 1, which is only brute-forceable at n = 4.
 */
export function toyKeygen(n: number, rng: Rng, steps = 6): ToyMatrix {
  let B = mid(n);
  for (let k = 0; k < steps; k += 1) {
    const a: ToyPoly = Array.from({ length: n }, () => {
      const r = Math.floor(rng() * 4);
      return r === 0 ? -1n : r === 3 ? 1n : 0n;
    });
    const E: ToyMatrix =
      k % 2 === 0
        ? [
            [rone(n), a],
            [rzero(n), rone(n)],
          ]
        : [
            [rone(n), rzero(n)],
            [a, rone(n)],
          ];
    B = mmul(B, E, n);
  }
  return B;
}

/** Q = B* B. The public key, and the only input the attack gets. */
export function publicGram(B: ToyMatrix, n: number): ToyMatrix {
  return mmul(mstar(B, n), B, n);
}

// ---------------------------------------------------------------------------
// Step 1: the tau-cocycle lattice, from Q alone
// ---------------------------------------------------------------------------

function vec(Y: ToyMatrix): bigint[] {
  return [...Y[0][0], ...Y[0][1], ...Y[1][0], ...Y[1][1]];
}

function unvec(v: bigint[], n: number): ToyMatrix {
  return [
    [v.slice(0, n), v.slice(n, 2 * n)],
    [v.slice(2 * n, 3 * n), v.slice(3 * n, 4 * n)],
  ];
}

/**
 * Rows of an integer matrix M with M.vec(Y) = 0 exactly when Y satisfies
 *
 *   (C1)  tau(Y) = adj(Y)            the cocycle relation, linearized by det = 1
 *   (C2)  Q Y    = adj(Y)* tau(Q)    the intertwining relation between Q and tau(Q)
 *
 * Every coefficient is computed from Q and tau(Q). Nothing secret enters.
 */
function constraintMatrix(Q: ToyMatrix, n: number): bigint[][] {
  const tQ = mtau(Q);
  const cols: bigint[][] = [];
  for (let k = 0; k < 4 * n; k += 1) {
    const e = new Array<bigint>(4 * n).fill(0n);
    e[k] = 1n;
    const Y = unvec(e, n);
    const c1 = msub(mtau(Y), madj(Y));
    const c2 = msub(mmul(Q, Y, n), mmul(mstar(madj(Y), n), tQ, n));
    cols.push([...vec(c1), ...vec(c2)]);
  }
  const rows: bigint[][] = [];
  for (let r = 0; r < 8 * n; r += 1) {
    rows.push(cols.map((col) => col[r]));
  }
  return rows;
}

/** Integer kernel by column-style Hermite reduction. */
function integerKernel(M: bigint[][]): bigint[][] {
  if (M.length === 0) return [];
  const rows = M.length;
  const N = M[0].length;
  const A = M.map((row) => row.slice());
  const U: bigint[][] = Array.from({ length: N }, (_, i) =>
    Array.from({ length: N }, (_, j) => (i === j ? 1n : 0n)),
  );

  const swap = (c1: number, c2: number): void => {
    for (let r = 0; r < rows; r += 1) {
      const t = A[r][c1];
      A[r][c1] = A[r][c2];
      A[r][c2] = t;
    }
    for (let r = 0; r < N; r += 1) {
      const t = U[r][c1];
      U[r][c1] = U[r][c2];
      U[r][c2] = t;
    }
  };

  const addmul = (dst: number, src: number, q: bigint): void => {
    if (q === 0n) return;
    for (let r = 0; r < rows; r += 1) A[r][dst] -= q * A[r][src];
    for (let r = 0; r < N; r += 1) U[r][dst] -= q * U[r][src];
  };

  let pivot = 0;
  for (let r = 0; r < rows && pivot < N; r += 1) {
    for (let c = pivot + 1; c < N; c += 1) {
      // Euclidean algorithm run on columns.
      while (A[r][c] !== 0n) {
        if (A[r][pivot] === 0n) {
          swap(pivot, c);
        } else {
          addmul(c, pivot, A[r][c] / A[r][pivot]);
          if (A[r][c] !== 0n) swap(pivot, c);
        }
      }
    }
    if (A[r][pivot] !== 0n) pivot += 1;
  }

  const basis: bigint[][] = [];
  for (let c = pivot; c < N; c += 1) {
    basis.push(U.map((row) => row[c]));
  }
  return basis;
}

/** Q^(tau)(Y) = Tr_F(det Y) = n * (det Y)_0 / 4. */
function qform(Y: ToyMatrix, n: number): bigint {
  const num = BigInt(n) * mdet(Y, n)[0];
  return num / 4n;
}

/** Twice the polarization of qform — kept doubled so it stays integral. */
function cocycleInner(n: number): (x: bigint[], y: bigint[]) => bigint {
  return (x, y) => {
    const X = unvec(x, n);
    const Y = unvec(y, n);
    const sum: ToyMatrix = [
      [radd(X[0][0], Y[0][0]), radd(X[0][1], Y[0][1])],
      [radd(X[1][0], Y[1][0]), radd(X[1][1], Y[1][1])],
    ];
    return qform(sum, n) - qform(X, n) - qform(Y, n);
  };
}

// ---------------------------------------------------------------------------
// Rational arithmetic for LLL / enumeration
// ---------------------------------------------------------------------------

type Frac = { num: bigint; den: bigint };

function babs(x: bigint): bigint {
  return x < 0n ? -x : x;
}

function bgcd(a: bigint, b: bigint): bigint {
  let x = babs(a);
  let y = babs(b);
  while (y) {
    const t = x % y;
    x = y;
    y = t;
  }
  return x;
}

function fr(num: bigint, den = 1n): Frac {
  if (den === 0n) throw new Error('zero denominator');
  if (den < 0n) {
    num = -num;
    den = -den;
  }
  const g = bgcd(num, den) || 1n;
  return { num: num / g, den: den / g };
}

const FZERO = fr(0n);
const fadd = (a: Frac, b: Frac): Frac => fr(a.num * b.den + b.num * a.den, a.den * b.den);
const fsub = (a: Frac, b: Frac): Frac => fr(a.num * b.den - b.num * a.den, a.den * b.den);
const fmul = (a: Frac, b: Frac): Frac => fr(a.num * b.num, a.den * b.den);
const fdiv = (a: Frac, b: Frac): Frac => fr(a.num * b.den, a.den * b.num);
const fcmp = (a: Frac, b: Frac): number => {
  const l = a.num * b.den;
  const r = b.num * a.den;
  return l < r ? -1 : l > r ? 1 : 0;
};

/** Nearest integer, ties away from zero. */
function fround(a: Frac): bigint {
  const twice = 2n * a.num;
  const q = a.num / a.den;
  const rem = fsub(a, fr(q, 1n));
  const half = fr(1n, 2n);
  void twice;
  if (fcmp(rem, half) >= 0) return q + 1n;
  if (fcmp(rem, fr(-1n, 2n)) <= 0) return q - 1n;
  return q;
}

/** Integer square root of a non-negative bigint. */
function bisqrt(v: bigint): bigint {
  if (v < 2n) return v;
  let x = v;
  let y = (x + 1n) / 2n;
  while (y < x) {
    x = y;
    y = (x + v / x) / 2n;
  }
  return x;
}

// ---------------------------------------------------------------------------
// LLL and enumeration under an arbitrary positive-definite form
// ---------------------------------------------------------------------------

type Inner = (x: bigint[], y: bigint[]) => bigint;

function gramSchmidt(b: bigint[][], ip: Inner): { mu: Frac[][]; norm: Frac[] } {
  const m = b.length;
  const mu: Frac[][] = Array.from({ length: m }, () => Array.from({ length: m }, () => FZERO));
  const norm: Frac[] = Array.from({ length: m }, () => FZERO);
  for (let i = 0; i < m; i += 1) {
    for (let j = 0; j < i; j += 1) {
      if (norm[j].num === 0n) {
        mu[i][j] = FZERO;
        continue;
      }
      let acc = fr(ip(b[i], b[j]));
      for (let t = 0; t < j; t += 1) acc = fsub(acc, fmul(fmul(mu[i][t], mu[j][t]), norm[t]));
      mu[i][j] = fdiv(acc, norm[j]);
    }
    let nn = fr(ip(b[i], b[i]));
    for (let t = 0; t < i; t += 1) nn = fsub(nn, fmul(fmul(mu[i][t], mu[i][t]), norm[t]));
    norm[i] = nn;
  }
  return { mu, norm };
}

function lll(basis: bigint[][], ip: Inner): bigint[][] {
  const b = basis.map((v) => v.slice());
  if (b.length < 2) return b;
  const delta = fr(99n, 100n);
  let { mu, norm } = gramSchmidt(b, ip);
  let k = 1;
  let guard = 0;
  while (k < b.length) {
    if (guard > 200000) break;
    guard += 1;
    for (let j = k - 1; j >= 0; j -= 1) {
      const q = fround(mu[k][j]);
      if (q !== 0n) {
        b[k] = b[k].map((x, t) => x - q * b[j][t]);
        ({ mu, norm } = gramSchmidt(b, ip));
      }
    }
    const bound = fmul(fsub(delta, fmul(mu[k][k - 1], mu[k][k - 1])), norm[k - 1]);
    if (fcmp(norm[k], bound) >= 0) {
      k += 1;
    } else {
      const t = b[k];
      b[k] = b[k - 1];
      b[k - 1] = t;
      ({ mu, norm } = gramSchmidt(b, ip));
      k = Math.max(k - 1, 1);
    }
  }
  return b;
}

/** Every lattice vector of exactly the given norm (Fincke-Pohst). */
function enumerateNorm(basis: bigint[][], ip: Inner, target: bigint): bigint[][] {
  const m = basis.length;
  const { mu, norm } = gramSchmidt(basis, ip);
  const dim = basis[0].length;
  const x = new Array<bigint>(m).fill(0n);
  const found: bigint[][] = [];
  const tgt = fr(target);

  const rec = (i: number, partial: Frac): void => {
    if (i < 0) {
      if (x.some((c) => c !== 0n)) {
        const v = new Array<bigint>(dim).fill(0n);
        for (let j = 0; j < m; j += 1) {
          if (x[j] === 0n) continue;
          for (let t = 0; t < dim; t += 1) v[t] += x[j] * basis[j][t];
        }
        if (ip(v, v) === target) found.push(v);
      }
      return;
    }
    if (norm[i].num === 0n) return;
    let c = FZERO;
    for (let j = i + 1; j < m; j += 1) c = fadd(c, fmul(fr(x[j]), mu[j][i]));
    const room = fsub(tgt, partial);
    if (fcmp(room, FZERO) < 0) return;
    const span = fdiv(room, norm[i]);
    // ceil(sqrt(span)) + 1, generously rounded outward
    const sq = bisqrt(babs(span.num) * babs(span.den)) / (span.den || 1n);
    const lim = sq + 2n;
    const centre = fround(c);
    for (let d = -lim; d <= lim; d += 1n) {
      const xi = -centre + d;
      x[i] = xi;
      const off = fadd(fr(xi), c);
      const add = fmul(fmul(off, off), norm[i]);
      if (fcmp(fadd(partial, add), tgt) <= 0) rec(i - 1, fadd(partial, add));
    }
    x[i] = 0n;
  };

  rec(m - 1, FZERO);
  return found;
}

// ---------------------------------------------------------------------------
// Step 3: van Gent-Pulles descent
// ---------------------------------------------------------------------------

type ToyVec = [ToyPoly, ToyPoly];

function vvec(x: ToyVec): bigint[] {
  return [...x[0], ...x[1]];
}

function vunvec(v: bigint[], n: number): ToyVec {
  return [v.slice(0, n), v.slice(n, 2 * n)];
}

/** M_Y = { x in R^2 : tau(x) = adj(Y) x }, a rank-n sublattice. */
function kernelSublattice(Y: ToyMatrix, n: number): bigint[][] {
  const A = madj(Y);
  const cols: bigint[][] = [];
  for (let k = 0; k < 2 * n; k += 1) {
    const e = new Array<bigint>(2 * n).fill(0n);
    e[k] = 1n;
    const x = vunvec(e, n);
    const lhs: ToyVec = [rtau(x[0]), rtau(x[1])];
    const rhs: ToyVec = [
      radd(rmul(A[0][0], x[0], n), rmul(A[0][1], x[1], n)),
      radd(rmul(A[1][0], x[0], n), rmul(A[1][1], x[1], n)),
    ];
    cols.push(vvec([rsub(lhs[0], rhs[0]), rsub(lhs[1], rhs[1])]));
  }
  const rows: bigint[][] = [];
  for (let r = 0; r < 2 * n; r += 1) rows.push(cols.map((col) => col[r]));
  return integerKernel(rows);
}

/** x* Q y, as a ring element. */
function qInner(x: ToyVec, y: ToyVec, Q: ToyMatrix, n: number): ToyPoly {
  let out = rzero(n);
  for (let i = 0; i < 2; i += 1) {
    for (let j = 0; j < 2; j += 1) {
      out = radd(out, rmul(rmul(rconj(x[i], n), Q[i][j], n), y[j], n));
    }
  }
  return out;
}

/**
 * From the cocycle Y = +/-V_tau and the public key Q, recover a basis B' with
 * B'* B' = Q. Note B' need not equal the original secret basis: key recovery
 * asks for ANY B' reproducing Q, and such a B' signs in place of the real key.
 */
function recoverBasis(Y: ToyMatrix, Q: ToyMatrix, n: number): ToyMatrix | null {
  const K = kernelSublattice(Y, n);
  if (K.length === 0) return null;
  const ip: Inner = (a, b) => {
    const xa = vunvec(a, n);
    const xb = vunvec(b, n);
    return 2n * BigInt(n) * qInner(xa, xb, Q, n)[0];
  };
  const reduced = lll(K, ip);
  const shorts = enumerateNorm(reduced, ip, 2n * BigInt(n));
  const zero = rzero(n);
  for (let i = 0; i < shorts.length; i += 1) {
    for (let j = 0; j < shorts.length; j += 1) {
      if (i === j) continue;
      const u1 = vunvec(shorts[i], n);
      const u2 = vunvec(shorts[j], n);
      if (!req(qInner(u1, u2, Q, n), zero)) continue;
      const U: ToyMatrix = [
        [u1[0], u2[0]],
        [u1[1], u2[1]],
      ];
      // U* Q U = I is exactly the statement that B' = U^-1 satisfies B'* B' = Q.
      if (meq(mmul(mstar(U, n), mmul(Q, U, n), n), mid(n))) {
        return mmul(mstar(U, n), Q, n); // B' = U^-1 = U* Q
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// The attack, as a reportable run
// ---------------------------------------------------------------------------

export type AttackStage = {
  id: string;
  title: string;
  detail: string;
  result: string;
  ok: boolean;
};

export type AttackRun = {
  n: number;
  svpDimension: number;
  secretBasis: string;
  publicKey: string;
  cocycle: string | null;
  recoveredBasis: string | null;
  latticeRank: number;
  shortestFound: number;
  shortestExpected: number;
  paritySurvivors: number;
  cocycleMatchesSecret: boolean;
  gramMatches: boolean;
  identicalToSecret: boolean;
  elapsedMs: number;
  stages: AttackStage[];
};

export function formatPoly(p: ToyPoly): string {
  return `[${p.map((c) => c.toString()).join(', ')}]`;
}

export function formatMatrix(M: ToyMatrix): string {
  return `[[${formatPoly(M[0][0])}, ${formatPoly(M[0][1])}], [${formatPoly(M[1][0])}, ${formatPoly(M[1][1])}]]`;
}

/**
 * Run the full reduction against a freshly generated toy key. The secret basis
 * is generated here so the run can be checked afterwards, but nothing past
 * step 0 reads it — every later stage takes Q and its own prior output.
 */
export function runLipAttack(n: ToyDegree, rng: Rng): AttackRun {
  const started = performance.now();
  const stages: AttackStage[] = [];

  const B = toyKeygen(n, rng);
  const Q = publicGram(B, n);
  const trueCocycle = mmul(madj(B), mtau(B), n);
  const detIsOne = req(mdet(B, n), rone(n));

  stages.push({
    id: 'keygen',
    title: 'Generate a toy HAWK key',
    detail: `Unimodular basis B over Z[x]/(x^${n}+1), then publish only Q = B*B.`,
    result: detIsOne ? 'det B = 1 — B is a genuine HAWK-shaped basis' : 'det B ≠ 1',
    ok: detIsOne,
  });

  // Step 1 — the cocycle lattice, from Q alone.
  const kernel = integerKernel(constraintMatrix(Q, n));
  const ip = cocycleInner(n);
  const rankOk = kernel.length === n;
  stages.push({
    id: 'lattice',
    title: 'Build the τ-cocycle lattice from Q',
    detail: 'Integer solutions of τ(Y) = adj(Y) and QY = adj(Y)*τ(Q). Coefficients come from Q and τ(Q) only.',
    result: `rank ${kernel.length}${rankOk ? ` = n` : ` (expected ${n})`}`,
    ok: rankOk,
  });

  // Step 2 — reduce and enumerate.
  const reduced = lll(kernel, ip);
  const minNorm = 2n * (BigInt(n) / 4n);
  const shortest = enumerateNorm(reduced, ip, minNorm);
  const expected = 2 * (n / 2 + 1);
  const countOk = shortest.length === expected;
  stages.push({
    id: 'reduce',
    title: `Reduce, then enumerate at dimension n/2 + 1 = ${n / 2 + 1}`,
    detail: `LLL stands in for the sieve at this size. The minimum is n/4 = ${n / 4}, fixed for every key by Lemma 4.4.`,
    result: `${shortest.length} shortest vectors${countOk ? ` = 2(n/2 + 1)` : ` (expected ${expected})`}`,
    ok: countOk,
  });

  // Step 3a — the parity test picks out the two real cocycles.
  const identity = vec(mid(n));
  const survivors = shortest.filter((s) => s.every((c, i) => (c - identity[i]) % 2n === 0n));
  const trueVec = vec(trueCocycle);
  const negVec = trueVec.map((c) => -c);
  const matches = survivors.filter(
    (s) => s.every((c, i) => c === trueVec[i]) || s.every((c, i) => c === negVec[i]),
  );
  const parityOk = survivors.length === 2 && matches.length === 2;
  stages.push({
    id: 'parity',
    title: 'Parity-test Y ≡ I (mod 2)',
    detail: 'Exactly two shortest vectors survive, and they are ±V_τ = ±B⁻¹τ(B).',
    result: parityOk
      ? `2 survivors, both equal ±V_τ`
      : `${survivors.length} survivors, ${matches.length} matched`,
    ok: parityOk,
  });

  // Step 3b — descend to a working basis.
  const recovered = survivors.length > 0 ? recoverBasis(unvec(survivors[0], n), Q, n) : null;
  const gramMatches = recovered !== null && meq(mmul(mstar(recovered, n), recovered, n), Q);
  const identical = recovered !== null && meq(recovered, B);
  stages.push({
    id: 'descent',
    title: 'Descend from V_τ to a signing basis',
    detail: 'Kernel sublattice M_Y = { x : τ(x) = adj(V_τ)x }, reduced, then a T-orthogonal pair gives B′ = U⁻¹.',
    result: gramMatches ? "B′*B′ = Q — B′ signs in place of the secret key" : 'no basis recovered',
    ok: gramMatches,
  });

  return {
    n,
    svpDimension: n / 2 + 1,
    secretBasis: formatMatrix(B),
    publicKey: formatMatrix(Q),
    cocycle: survivors.length > 0 ? formatMatrix(unvec(survivors[0], n)) : null,
    recoveredBasis: recovered ? formatMatrix(recovered) : null,
    latticeRank: kernel.length,
    shortestFound: shortest.length,
    shortestExpected: expected,
    paritySurvivors: survivors.length,
    cocycleMatchesSecret: parityOk,
    gramMatches,
    identicalToSecret: identical,
    elapsedMs: performance.now() - started,
    stages,
  };
}
