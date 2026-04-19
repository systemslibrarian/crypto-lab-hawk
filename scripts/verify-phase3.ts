import { benchmarkHAWK, hawkKeygen, hawkSign, hawkVerify } from '../src/hawk.ts';
import { HAWK_512_PARAMS } from '../src/polynomial.ts';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const attempts: string[] = [];
const message = new TextEncoder().encode('Release firmware v2.3.1 on 2026-04-19');

const { privateKey, publicKey, generationAttempts } = await hawkKeygen(HAWK_512_PARAMS, (attempt, reason) => {
  attempts.push(`${attempt}:${reason}`);
});

assert(generationAttempts <= 10, 'Key generation should usually finish within 10 attempts.');

const { signature, restartCount } = await hawkSign(message, privateKey);
assert(signature.n === HAWK_512_PARAMS.n, 'Signature should retain the HAWK parameter set.');
assert(restartCount >= 0, 'Signing restart count should be non-negative.');

const verified = await hawkVerify(message, signature, publicKey);
assert(verified, 'Freshly signed messages should verify.');

const tampered = {
  ...signature,
  s1: Int32Array.from(signature.s1),
};
tampered.s1[0] += 1;

const tamperedVerified = await hawkVerify(message, tampered, publicKey);
assert(!tamperedVerified, 'Tampered signatures must fail verification.');

const benchmark = await benchmarkHAWK(8);
assert(benchmark.hawkSignMs > 0, 'Signing benchmark should produce a positive timing.');
assert(benchmark.speedupRatio > 3, 'Educational Falcon simulation should remain materially slower than HAWK signing.');

console.log(
  JSON.stringify({
    generationAttempts,
    failedAttempts: attempts.length,
    restartCount,
    hawkSignMs: Number(benchmark.hawkSignMs.toFixed(3)),
    falconSimulationMs: Number(benchmark.falconSimulationMs.toFixed(3)),
    speedupRatio: Number(benchmark.speedupRatio.toFixed(2)),
  }),
);
console.log('phase-3 verification passed');