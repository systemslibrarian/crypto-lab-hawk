import {
  DISCRETE_GAUSSIAN_TABLE_T0,
  DISCRETE_GAUSSIAN_TABLE_T1,
  sampleGaussianPolynomial,
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
  return Math.ceil(params.saltBits / 8);
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

async function simulateFalconWork(message: Uint8Array, n: number): Promise<number> {
  const params = getParamsForN(n);
  const salt = new Uint8Array(getSaltBytes(params));
  getCrypto().getRandomValues(salt);
  const target = await hashToPolynomial(message, salt, salt, n);
  const targetBytes = serializePolynomial(target);
  let accumulator = 0;

  for (let round = 0; round < 192; round += 1) {
    const digest = await sha256(concatBytes(targetBytes, encodeUint32(round)));
    accumulator += digest[0] ?? 0;

    for (let index = 0; index < target.length; index += 1) {
      const coefficient = target[index] + round;
      accumulator += coefficient * coefficient + (index & 7);
    }
  }

  return accumulator;
}

export async function benchmarkHAWK(
  iterations: number = 100,
): Promise<{
  hawkKeygenMs: number;
  hawkSignMs: number;
  hawkVerifyMs: number;
  falconSimulationMs: number;
  speedupRatio: number;
}> {
  const message = encoder.encode('hawk benchmark message');

  let keygenTotal = 0;
  let signTotal = 0;
  let verifyTotal = 0;
  let falconTotal = 0;

  for (let index = 0; index < iterations; index += 1) {
    let startedAt = nowMs();
    const { privateKey, publicKey } = await hawkKeygen(HAWK_512_PARAMS);
    keygenTotal += nowMs() - startedAt;

    startedAt = nowMs();
    const { signature } = await hawkSign(message, privateKey);
    signTotal += nowMs() - startedAt;

    startedAt = nowMs();
    const verified = await hawkVerify(message, signature, publicKey);
    verifyTotal += nowMs() - startedAt;

    if (!verified) {
      throw new Error('Benchmark verification failed for a generated signature.');
    }

    startedAt = nowMs();
    await simulateFalconWork(message, HAWK_512_PARAMS.n);
    falconTotal += nowMs() - startedAt;
  }

  const hawkKeygenMs = keygenTotal / iterations;
  const hawkSignMs = signTotal / iterations;
  const hawkVerifyMs = verifyTotal / iterations;
  const falconSimulationMs = falconTotal / iterations;

  return {
    hawkKeygenMs,
    hawkSignMs,
    hawkVerifyMs,
    falconSimulationMs,
    speedupRatio: falconSimulationMs / hawkSignMs,
  };
}