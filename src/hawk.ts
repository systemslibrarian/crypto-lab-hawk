import {
  DISCRETE_GAUSSIAN_TABLE_T0,
  DISCRETE_GAUSSIAN_TABLE_T1,
  sampleGaussianPolynomial,
  simulateFalconFastFourierSamplingPass,
} from './gaussian';
import {
  HAWK_512_PARAMS,
  HAWK_1024_PARAMS,
  polyAdd,
  polyInfNorm,
  polyNormSquared,
  polySub,
  type Polynomial,
} from './polynomial';

export interface HAWKPrivateKey {
  kgseed: Uint8Array;
  F_mod_2: Polynomial;
  G_mod_2: Polynomial;
  pubKeyHash: Uint8Array;
  n: number;
}

export interface HAWKPublicKey {
  q00: Polynomial;
  q01: Polynomial;
  n: number;
}

export interface HAWKSignature {
  salt: Uint8Array;
  s1: Polynomial;
  n: number;
}

type HawkParams = typeof HAWK_512_PARAMS | typeof HAWK_1024_PARAMS;
type HAWKPrivateKeyWithCache = HAWKPrivateKey & {
  _cachedF?: Polynomial;
  _cachedG?: Polynomial;
};

const encoder = new TextEncoder();

function getCrypto(): Crypto {
  if (!globalThis.crypto) {
    throw new Error('Web Crypto API is not available in this environment.');
  }

  return globalThis.crypto;
}

function nowMs(): number {
  return globalThis.performance?.now() ?? Date.now();
}

function getParamsForN(n: number): HawkParams {
  if (n === HAWK_512_PARAMS.n) {
    return HAWK_512_PARAMS;
  }

  if (n === HAWK_1024_PARAMS.n) {
    return HAWK_1024_PARAMS;
  }

  throw new Error(`Unsupported HAWK parameter n=${n}.`);
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const length = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const merged = new Uint8Array(length);
  let offset = 0;

  for (let index = 0; index < chunks.length; index += 1) {
    merged.set(chunks[index], offset);
    offset += chunks[index].length;
  }

  return merged;
}

function encodeUint32(value: number): Uint8Array {
  const out = new Uint8Array(4);
  const view = new DataView(out.buffer);
  view.setUint32(0, value, false);
  return out;
}

function bytesToUint64(bytes: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let index = 0; index < 8; index += 1) {
    value = (value << 8n) | BigInt(bytes[offset + index]);
  }

  return value;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await getCrypto().subtle.digest('SHA-256', data as BufferSource);
  return new Uint8Array(digest);
}

async function expandDeterministic(seed: Uint8Array, label: string, length: number): Promise<Uint8Array> {
  const labelBytes = encoder.encode(label);
  const chunks: Uint8Array[] = [];
  let generated = 0;
  let counter = 0;

  while (generated < length) {
    const block = await sha256(concatBytes(labelBytes, encodeUint32(counter), seed));
    chunks.push(block);
    generated += block.length;
    counter += 1;
  }

  return concatBytes(...chunks).slice(0, length);
}

function sampleMagnitudeFromWord(word: bigint, table: readonly bigint[]): number {
  let magnitude = 0;

  for (let index = 0; index < table.length; index += 1) {
    if (word < table[index]) {
      magnitude += 1;
    }
  }

  return magnitude;
}

async function sampleDeterministicGaussianPolynomial(
  n: number,
  table: readonly bigint[],
  seed: Uint8Array,
  label: string,
): Promise<Polynomial> {
  const stream = await expandDeterministic(seed, label, n * 8);
  const coefficients = new Int32Array(n);

  for (let index = 0; index < n; index += 1) {
    const word = bytesToUint64(stream, index * 8);
    const magnitude = sampleMagnitudeFromWord(word, table);

    if (magnitude === 0) {
      coefficients[index] = 0;
      continue;
    }

    coefficients[index] = (word & 1n) === 0n ? magnitude : -magnitude;
  }

  return coefficients;
}

async function hashToPolynomial(
  message: Uint8Array,
  salt: Uint8Array,
  pubKeyHash: Uint8Array,
  n: number,
): Promise<Polynomial> {
  const target = new Int32Array(n);
  let filled = 0;
  let counter = 0;

  while (filled < n) {
    const block = await sha256(
      concatBytes(pubKeyHash, salt, encodeUint32(counter), message),
    );

    for (let index = 0; index < block.length && filled < n; index += 1) {
      const candidate = block[index];
      if (candidate >= 250) {
        continue;
      }

      target[filled] = (candidate % 5) - 2;
      filled += 1;
    }

    counter += 1;
  }

  return target;
}

function normalizeMod2(poly: Polynomial): Polynomial {
  const reduced = new Int32Array(poly.length);

  for (let index = 0; index < poly.length; index += 1) {
    reduced[index] = poly[index] & 1;
  }

  return reduced;
}

function serializePolynomial(poly: Polynomial): Uint8Array {
  const out = new Uint8Array(poly.length * 4);
  const view = new DataView(out.buffer);

  for (let index = 0; index < poly.length; index += 1) {
    view.setInt32(index * 4, poly[index], true);
  }

  return out;
}

async function hashPublicKey(publicKey: HAWKPublicKey): Promise<Uint8Array> {
  return sha256(concatBytes(serializePolynomial(publicKey.q00), serializePolynomial(publicKey.q01)));
}

function toyKeygenFailureReason(f: Polynomial, g: Polynomial): string | null {
  if (f[0] === 0 && g[0] === 0) {
    return 'toy NTRU solve failed: both constant coefficients were zero';
  }

  if (polyInfNorm(f) > 6 || polyInfNorm(g) > 6) {
    return 'toy NTRU solve failed: sampled basis was too wide';
  }

  return null;
}

async function derivePrivateBasis(seed: Uint8Array, n: number): Promise<{ f: Polynomial; g: Polynomial; F: Polynomial; G: Polynomial }> {
  const basisSeed = concatBytes(seed, encodeUint32(n));
  const f = await sampleDeterministicGaussianPolynomial(n, DISCRETE_GAUSSIAN_TABLE_T0, basisSeed, 'hawk-f');
  const g = await sampleDeterministicGaussianPolynomial(n, DISCRETE_GAUSSIAN_TABLE_T0, basisSeed, 'hawk-g');
  const F = new Int32Array(n);
  const G = new Int32Array(n);

  for (let index = 0; index < n; index += 1) {
    F[index] = -g[index];
    G[index] = f[index];
  }

  return { f, g, F, G };
}

function copyBytes(input: Uint8Array): Uint8Array {
  return new Uint8Array(input);
}

function equalPolynomials(left: Polynomial, right: Polynomial): boolean {
  if (left.length !== right.length) {
    return false;
  }

  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) {
      return false;
    }
  }

  return true;
}

function getSaltBytes(params: HawkParams): number {
  return (params.saltBits + 7) >> 3;
}

function shouldRestart(salt: Uint8Array, params: HawkParams): boolean {
  const bits = params.n === HAWK_512_PARAMS.n ? 18 : 19;
  let remaining = bits;
  let index = 0;

  while (remaining > 0 && index < salt.length) {
    const current = salt[index];
    const take = Math.min(remaining, 8);
    if ((current >> (8 - take)) !== 0) {
      return false;
    }

    remaining -= take;
    index += 1;
  }

  return remaining === 0;
}

function verificationBound(n: number): number {
  return n * 18;
}

export async function hawkKeygen(
  params: typeof HAWK_512_PARAMS | typeof HAWK_1024_PARAMS,
  onAttempt?: (attempt: number, reason: string) => void,
): Promise<{
  privateKey: HAWKPrivateKey;
  publicKey: HAWKPublicKey;
  generationAttempts: number;
}> {
  let attempt = 0;

  while (attempt < 32) {
    attempt += 1;
    const kgseed = new Uint8Array(32);
    getCrypto().getRandomValues(kgseed);

    const { f, g, F, G } = await derivePrivateBasis(kgseed, params.n);
    const failure = toyKeygenFailureReason(f, g);
    if (failure) {
      onAttempt?.(attempt, failure);
      continue;
    }

    const publicKey: HAWKPublicKey = {
      q00: polyAdd(f, g),
      q01: polySub(f, g),
      n: params.n,
    };

    const pubKeyHash = await hashPublicKey(publicKey);
    const privateKey: HAWKPrivateKeyWithCache = {
      kgseed: copyBytes(kgseed),
      F_mod_2: normalizeMod2(F),
      G_mod_2: normalizeMod2(G),
      pubKeyHash,
      n: params.n,
      _cachedF: f,
      _cachedG: g,
    };

    return {
      privateKey,
      publicKey,
      generationAttempts: attempt,
    };
  }

  throw new Error('HAWK key generation exceeded the retry budget.');
}

export async function hawkSign(
  message: Uint8Array,
  privateKey: HAWKPrivateKey,
): Promise<{
  signature: HAWKSignature;
  signingTimeMs: number;
  restartCount: number;
}> {
  const params = getParamsForN(privateKey.n);
  const startedAt = nowMs();
  const cachedPrivateKey = privateKey as HAWKPrivateKeyWithCache;
  const f = cachedPrivateKey._cachedF ?? (await derivePrivateBasis(privateKey.kgseed, privateKey.n)).f;

  if (!cachedPrivateKey._cachedF) {
    cachedPrivateKey._cachedF = f;
  }

  let restartCount = 0;

  while (restartCount < 4) {
    const salt = new Uint8Array(getSaltBytes(params));
    getCrypto().getRandomValues(salt);

    const perturbation = sampleGaussianPolynomial(privateKey.n, DISCRETE_GAUSSIAN_TABLE_T1);
    const hiddenNorm = polyNormSquared(polyAdd(f, perturbation));

    if (shouldRestart(salt, params) && hiddenNorm > verificationBound(privateKey.n)) {
      restartCount += 1;
      continue;
    }

    const h = await hashToPolynomial(message, salt, privateKey.pubKeyHash, privateKey.n);
    const s1 = polyAdd(h, f);

    return {
      signature: {
        salt,
        s1,
        n: privateKey.n,
      },
      signingTimeMs: nowMs() - startedAt,
      restartCount,
    };
  }

  throw new Error('HAWK signing restarted too many times.');
}

export async function hawkVerify(
  message: Uint8Array,
  signature: HAWKSignature,
  publicKey: HAWKPublicKey,
): Promise<boolean> {
  if (signature.n !== publicKey.n) {
    return false;
  }

  const pubKeyHash = await hashPublicKey(publicKey);
  const h = await hashToPolynomial(message, signature.salt, pubKeyHash, publicKey.n);
  const recoveredF = polySub(signature.s1, h);
  const recoveredG = polySub(publicKey.q00, recoveredF);
  const consistency = polySub(recoveredF, recoveredG);

  if (!equalPolynomials(consistency, publicKey.q01)) {
    return false;
  }

  const totalNorm = polyNormSquared(recoveredF) + polyNormSquared(recoveredG);
  return totalNorm <= verificationBound(publicKey.n);
}

function simulateFalconSignWork(n: number): number {
  let accumulator = 0;
  for (let pass = 0; pass < 3; pass += 1) {
    accumulator += simulateFalconFastFourierSamplingPass(n).accumulator;
  }
  return accumulator;
}

/**
 * ML-DSA's signing critical path is dominated by a rejection loop: each
 * iteration samples y, computes the high bits of A*y, hashes to a
 * challenge, and either accepts or restarts. Production implementations
 * average roughly 4 iterations per signature with a wide distribution.
 *
 * We model that here with a geometric loop count and per-iteration work
 * proportional to n*log(n) integer multiplications, which lets us report
 * both a mean signing time and a meaningful timing variance number.
 */
function simulateMldsaSignWork(n: number): { iterations: number } {
  let iterations = 0;
  let acceptance = 0;

  while (acceptance < 1 && iterations < 16) {
    iterations += 1;
    let workSum = 0;
    const passes = Math.ceil(Math.log2(n));

    for (let pass = 0; pass < passes; pass += 1) {
      for (let index = 0; index < n; index += 1) {
        const sample = ((index * 1103515245 + pass * 12345) % 8380417) | 0;
        workSum = (workSum + sample * (pass + 1)) | 0;
      }
    }

    if (Math.random() < 0.235 + (workSum & 0)) {
      acceptance = 1;
    }
  }

  return { iterations };
}

function stdev(values: number[]): number {
  if (values.length === 0) {
    return 0;
  }

  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  const variance = values.reduce((sum, value) => sum + (value - mean) * (value - mean), 0) / values.length;
  return Math.sqrt(variance);
}

export async function benchmarkHAWK(
  iterations: number = 100,
  paramSet: HawkParams = HAWK_512_PARAMS,
): Promise<{
  hawkKeygenMs: number;
  hawkSignMs: number;
  hawkSignStdev: number;
  hawkVerifyMs: number;
  falconSimulationMs: number;
  falconSimulationStdev: number;
  mldsaSimulationMs: number;
  mldsaSimulationStdev: number;
  mldsaAvgIterations: number;
  speedupRatio: number;
}> {
  const message = encoder.encode('hawk benchmark message');

  const hawkSignSamples: number[] = [];
  const falconSamples: number[] = [];
  const mldsaSamples: number[] = [];
  const mldsaIterations: number[] = [];

  let keygenTotal = 0;
  let verifyTotal = 0;

  for (let index = 0; index < iterations; index += 1) {
    let startedAt = nowMs();
    const { privateKey, publicKey } = await hawkKeygen(paramSet);
    keygenTotal += nowMs() - startedAt;

    startedAt = nowMs();
    const { signature } = await hawkSign(message, privateKey);
    hawkSignSamples.push(nowMs() - startedAt);

    startedAt = nowMs();
    const verified = await hawkVerify(message, signature, publicKey);
    verifyTotal += nowMs() - startedAt;

    if (!verified) {
      throw new Error('Benchmark verification failed for a generated signature.');
    }

    startedAt = nowMs();
    simulateFalconSignWork(paramSet.n);
    falconSamples.push(nowMs() - startedAt);

    startedAt = nowMs();
    const { iterations: loops } = simulateMldsaSignWork(paramSet.n);
    mldsaSamples.push(nowMs() - startedAt);
    mldsaIterations.push(loops);
  }

  const mean = (values: number[]) => values.reduce((sum, value) => sum + value, 0) / values.length;
  const hawkSignMs = mean(hawkSignSamples);
  const falconSimulationMs = mean(falconSamples);
  const mldsaSimulationMs = mean(mldsaSamples);

  return {
    hawkKeygenMs: keygenTotal / iterations,
    hawkSignMs,
    hawkSignStdev: stdev(hawkSignSamples),
    hawkVerifyMs: verifyTotal / iterations,
    falconSimulationMs,
    falconSimulationStdev: stdev(falconSamples),
    mldsaSimulationMs,
    mldsaSimulationStdev: stdev(mldsaSamples),
    mldsaAvgIterations: mean(mldsaIterations),
    speedupRatio: falconSimulationMs / hawkSignMs,
  };
}

/**
 * Serialize a HAWK signature using a Golomb-Rice-style encoding for the s1
 * polynomial. Each coefficient is encoded as a sign bit + unary high bits +
 * a low-bits payload. The result is salt-prefixed and the bit stream is
 * packed into whole bytes. This is the same shape the HAWK v1.1 spec uses
 * for its compact signature format, just with simplified parameters.
 */
export function serializeSignature(signature: HAWKSignature): Uint8Array {
  const params = getParamsForN(signature.n);
  const saltBytes = getSaltBytes(params);
  const lowBits = 5;
  const bits: number[] = [];

  for (let index = 0; index < signature.s1.length; index += 1) {
    const value = signature.s1[index];
    const sign = value < 0 ? 1 : 0;
    const magnitude = Math.abs(value);
    const low = magnitude & ((1 << lowBits) - 1);
    const high = magnitude >> lowBits;

    bits.push(sign);
    for (let bit = lowBits - 1; bit >= 0; bit -= 1) {
      bits.push((low >> bit) & 1);
    }
    for (let count = 0; count < high; count += 1) {
      bits.push(1);
    }
    bits.push(0);
  }

  const byteLength = saltBytes + Math.ceil(bits.length / 8);
  const out = new Uint8Array(byteLength);
  out.set(signature.salt, 0);

  for (let index = 0; index < bits.length; index += 1) {
    if (bits[index]) {
      const target = saltBytes + (index >> 3);
      out[target] |= 1 << (7 - (index & 7));
    }
  }

  return out;
}

export function serializePublicKey(publicKey: HAWKPublicKey): Uint8Array {
  return concatBytes(serializePolynomial(publicKey.q00), serializePolynomial(publicKey.q01));
}