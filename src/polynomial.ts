/**
 * Polynomial in R = Z[X] / (X^n + 1) where n is a power of 2.
 * All HAWK operations use integer polynomials exclusively.
 */

export type Polynomial = Int32Array;

export const HAWK_256_PARAMS = {
  n: 256,
  q: 12289,
  signatureBytes: 252,
  publicKeyBytes: 512,
  saltBits: 96,
  securityLevel: 'Challenge',
} as const;

export const HAWK_512_PARAMS = {
  n: 512,
  q: 12289,
  signatureBytes: 555,
  publicKeyBytes: 1024,
  saltBits: 112,
  securityLevel: 'NIST-I',
} as const;

export const HAWK_1024_PARAMS = {
  n: 1024,
  q: 12289,
  signatureBytes: 1221,
  publicKeyBytes: 2560,
  saltBits: 192,
  securityLevel: 'NIST-V',
} as const;

function assertCompatible(a: Polynomial, b: Polynomial): void {
  if (a.length !== b.length) {
    throw new Error(`Polynomial length mismatch: ${a.length} !== ${b.length}`);
  }
}

function assertPowerOfTwo(n: number): void {
  if (n < 1 || (n & (n - 1)) !== 0) {
    throw new Error(`Polynomial degree ${n} must be a power of 2.`);
  }
}

function getCrypto(): Crypto {
  if (!globalThis.crypto) {
    throw new Error('Web Crypto API is not available in this environment.');
  }

  return globalThis.crypto;
}

/**
 * Create zero polynomial of length n.
 */
export function zeroPoly(n: number): Polynomial {
  assertPowerOfTwo(n);
  return new Int32Array(n);
}

/**
 * Polynomial addition in R.
 */
export function polyAdd(a: Polynomial, b: Polynomial): Polynomial {
  assertCompatible(a, b);
  const out = new Int32Array(a.length);

  for (let index = 0; index < a.length; index += 1) {
    out[index] = a[index] + b[index];
  }

  return out;
}

/**
 * Polynomial subtraction in R.
 */
export function polySub(a: Polynomial, b: Polynomial): Polynomial {
  assertCompatible(a, b);
  const out = new Int32Array(a.length);

  for (let index = 0; index < a.length; index += 1) {
    out[index] = a[index] - b[index];
  }

  return out;
}

/**
 * Polynomial multiplication in R = Z[X]/(X^n + 1).
 * Uses schoolbook for educational clarity.
 * (Production HAWK uses NTT for speed.)
 */
export function polyMul(a: Polynomial, b: Polynomial): Polynomial {
  assertCompatible(a, b);
  const n = a.length;
  const out = new Int32Array(n);

  for (let left = 0; left < n; left += 1) {
    for (let right = 0; right < n; right += 1) {
      const target = left + right;
      const product = a[left] * b[right];

      if (target < n) {
        out[target] += product;
      } else {
        out[target - n] -= product;
      }
    }
  }

  return out;
}

/**
 * Hermitian adjoint (conjugation) in R = Z[X]/(X^n + 1).
 *
 * The adjoint a* satisfies <a·u, v> = <u, a*·v> for the coefficient inner
 * product. Because X^n = -1 we have X^{-1} = -X^{n-1}, so a*(X) = a(X^{-1})
 * has a*[0] = a[0] and a*[i] = -a[n-i] for i = 1..n-1. This is the ring
 * conjugation HAWK uses to build its Gram matrix Q = B* B from a basis B.
 */
export function polyAdjoint(a: Polynomial): Polynomial {
  const n = a.length;
  const out = new Int32Array(n);
  out[0] = a[0];

  for (let index = 1; index < n; index += 1) {
    out[index] = -a[n - index];
  }

  return out;
}

/**
 * Reduce every coefficient into {0, 1}. Used for the mod-2 parity basis
 * that binds a signature's coset to the hashed message target.
 */
export function polyMod2(a: Polynomial): Polynomial {
  const out = new Int32Array(a.length);

  for (let index = 0; index < a.length; index += 1) {
    out[index] = a[index] & 1;
  }

  return out;
}

/**
 * Addition in (Z/2)[X]/(X^n + 1) (coefficient-wise XOR).
 */
export function polyAddMod2(a: Polynomial, b: Polynomial): Polynomial {
  assertCompatible(a, b);
  const out = new Int32Array(a.length);

  for (let index = 0; index < a.length; index += 1) {
    out[index] = (a[index] + b[index]) & 1;
  }

  return out;
}

/**
 * Multiplication in (Z/2)[X]/(X^n + 1): a full negacyclic multiply reduced
 * mod 2. (Mod 2 the sign folds away, so this is also the cyclic product,
 * but we keep the negacyclic multiply for consistency with the ring.)
 */
export function polyMulMod2(a: Polynomial, b: Polynomial): Polynomial {
  const product = polyMul(a, b);
  return polyMod2(product);
}

/**
 * Multiplicative inverse in (Z/2)[X]/(X^n + 1), or null if `a` is not a unit.
 *
 * Mod 2, X^n + 1 = (X + 1)^n, so the ring is local with maximal ideal (X+1)
 * and every unit has the form 1 + m with m nilpotent. `a` is a unit iff
 * a(1) = 1 (odd Hamming weight); then a^{-1} = sum_k m^k with m = a + 1,
 * a finite sum because m is nilpotent.
 */
export function polyInvMod2(a: Polynomial): Polynomial | null {
  const n = a.length;

  let weight = 0;
  for (let index = 0; index < n; index += 1) {
    weight ^= a[index] & 1;
  }
  if (weight === 0) {
    return null;
  }

  const oneP = new Int32Array(n);
  oneP[0] = 1;

  // m = a + 1 (mod 2) lies in the maximal ideal and is nilpotent.
  const m = polyAddMod2(polyMod2(a), oneP);

  let inverse: Polynomial = oneP;
  let term: Polynomial = oneP;
  for (let k = 1; k <= n; k += 1) {
    term = polyMulMod2(term, m);
    let zero = true;
    for (let index = 0; index < n; index += 1) {
      if (term[index] !== 0) {
        zero = false;
        break;
      }
    }
    if (zero) {
      break;
    }
    inverse = polyAddMod2(inverse, term);
  }

  return inverse;
}

/**
 * Infinity norm of a polynomial (max |coefficient|).
 */
export function polyInfNorm(p: Polynomial): number {
  let max = 0;

  for (let index = 0; index < p.length; index += 1) {
    const coefficient = Math.abs(p[index]);
    if (coefficient > max) {
      max = coefficient;
    }
  }

  return max;
}

/**
 * Euclidean-style norm squared (sum of squares).
 * Used for HAWK's signature verification bound.
 */
export function polyNormSquared(p: Polynomial): number {
  let total = 0;

  for (let index = 0; index < p.length; index += 1) {
    const coefficient = p[index];
    total += coefficient * coefficient;
  }

  return total;
}

/**
 * Random small polynomial with coefficients in {-1, 0, 1}
 * via rejection sampling of byte values.
 * No non-cryptographic RNG is used here; randomness comes from crypto.getRandomValues.
 */
export function randomSmallPolynomial(n: number): Polynomial {
  assertPowerOfTwo(n);
  const out = new Int32Array(n);
  const buffer = new Uint8Array(Math.max(32, n * 2));
  const webCrypto = getCrypto();

  let filled = 0;
  while (filled < n) {
    webCrypto.getRandomValues(buffer);

    for (let index = 0; index < buffer.length && filled < n; index += 1) {
      const candidate = buffer[index];
      if (candidate >= 3) {
        continue;
      }

      out[filled] = candidate - 1;
      filled += 1;
    }
  }

  return out;
}