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
 * No Math.random — uses crypto.getRandomValues.
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