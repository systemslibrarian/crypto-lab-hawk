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

// KEYGEN ATTEMPTS. An attempt succeeds only when the sampled basis is
// invertible mod 2. Over GF(2), X^n + 1 = (X + 1)^n for n a power of two, so
// the ring is local and an element is a unit iff its coefficient sum is odd.
// det(B mod 2) = fG + gF is odd for 6 of the 16 equally likely settings of the
// four parity bits, so an attempt succeeds with probability 3/8 and
// `generationAttempts` is geometric: mean 8/3 ≈ 2.67, and
// P(attempts > 10) = (5/8)^10 ≈ 0.9%.
//
// This used to assert `<= 10`, so it failed roughly one run in a hundred —
// measured at 6 of 300 keygens, with a per-attempt failure rate of 0.640
// against the predicted 0.625. Ten is not a ceiling on anything real. The only
// real ceiling is hawkKeygen's own retry budget of 32, which throws when
// exhausted, with probability (5/8)^32 ≈ 6e-7. Pin the budget rather than a
// lucky quantile of a geometric tail.
assert(generationAttempts >= 1, 'Key generation should report at least one attempt.');
assert(generationAttempts <= 32, "Key generation should stay inside hawkKeygen's 32-attempt retry budget.");
assert(
  attempts.length === generationAttempts - 1,
  'Every failed keygen attempt should be reported through the onAttempt callback.',
);

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
assert(benchmark.falconSimulationMs > 0, 'Falcon-style reference work should produce a positive timing.');
assert(benchmark.mldsaSimulationMs > 0, 'ML-DSA-style reference work should produce a positive timing.');
assert(benchmark.mldsaAvgIterations >= 1, 'ML-DSA simulation should report at least one rejection-loop iteration.');
assert(benchmark.hawkSignStdev >= 0, 'HAWK signing stdev must be non-negative.');
assert(benchmark.mldsaSimulationStdev >= 0, 'ML-DSA simulation stdev must be non-negative.');
// The structural difference between the schemes is what matters pedagogically:
// ML-DSA's rejection loop restarts, while HAWK has no accept/reject step inside
// its sampler and restarts only when the coset vector overshoots the length
// bound. Asserting on iteration structure rather than wall-clock keeps this
// check meaningful without being flaky on fast or noisy CI runners.
//
// The threshold is 1, not 1.5. Each simulated ML-DSA signature accepts with
// probability 0.235, so the per-signature iteration count is geometric with
// mean 4.20 and standard deviation 3.72 — a heavy right tail averaged over only
// the 8 benchmark loops. `> 1.5` therefore failed 1 run in 540
// (P = 1.85e-3 over 2,000,000 simulated benchmarks). `> 1` is the claim the
// comment above actually makes — that the rejection loop restarts at all — and
// it is equivalent to "at least one of the 8 loops took more than one
// iteration", which fails only when all 8 accept first try: 0.235^8 = 9.0e-6,
// confirmed by the same simulation. Raising the loop count instead was measured
// and rejected: 16 loops would still leave `> 1.5` at 4.7e-6 while doubling the
// slowest step in this suite.
assert(
  benchmark.mldsaAvgIterations > 1,
  'ML-DSA rejection loop should average more than one iteration, unlike HAWK.',
);

console.log(
  JSON.stringify({
    generationAttempts,
    failedAttempts: attempts.length,
    restartCount,
    hawkSignMs: Number(benchmark.hawkSignMs.toFixed(3)),
    hawkSignStdev: Number(benchmark.hawkSignStdev.toFixed(3)),
    falconSimulationMs: Number(benchmark.falconSimulationMs.toFixed(3)),
    mldsaSimulationMs: Number(benchmark.mldsaSimulationMs.toFixed(3)),
    mldsaAvgIterations: Number(benchmark.mldsaAvgIterations.toFixed(2)),
    illustrativeFalconToHawkTimeRatio: Number(benchmark.illustrativeFalconToHawkTimeRatio.toFixed(2)),
  }),
);
console.log('phase-3 verification passed');