import './styles.css';

import {
  DISCRETE_GAUSSIAN_TABLE_T1,
  EXPECTED_SIGMA,
  analyzeSampleDistribution,
  discreteGaussianPmf,
  sampleDiscreteGaussian,
  sampleFalconStyleDiscreteGaussian,
  traceDiscreteGaussian,
  type CdtWalkTrace,
} from './gaussian';
import {
  benchmarkHAWK,
  hawkKeygen,
  hawkSign,
  hawkVerify,
  hawkVerifyDetailed,
  serializePublicKey,
  serializeSignature,
  type HAWKPrivateKey,
  type HAWKPublicKey,
  type HAWKSignature,
  type HAWKVerifyDetail,
} from './hawk';
import { HAWK_512_PARAMS, HAWK_1024_PARAMS } from './polynomial';

type SchemeKey = 'falcon' | 'mldsa' | 'hawk';
type ParamKey = '512' | '1024';

type GaussianState = {
  mean: number;
  variance: number;
  minObserved: number;
  maxObserved: number;
  hawkSampleMs: number;
  falconSampleMs: number;
  sampleCount: number;
  histogram: Array<[number, number]>;
  pmf: Array<[number, number]>;
} | null;

type SigningState = {
  generationAttempts: number;
  restartCount: number;
  signingTimeMs: number;
  verified: boolean;
  saltHex: string;
  s1Preview: string;
  benchmark: Awaited<ReturnType<typeof benchmarkHAWK>>;
  signatureBytes: number;
  publicKeyBytes: number;
  attempts: Array<{ attempt: number; reason: string }>;
  paramSet: ParamKey;
  tampered: { verified: boolean; coefficient: number; delta: number } | null;
  verifyDetail: HAWKVerifyDetail;
  signature: HAWKSignature;
  publicKey: HAWKPublicKey;
  privateKey: HAWKPrivateKey;
} | null;

type SelfTestState = 'idle' | 'running' | 'pass' | 'fail';

type QuizState = {
  answers: Record<string, number>;
  score: number | null;
};

type GlossaryTerm = {
  slug: string;
  term: string;
  short: string;
  full: string;
};

const app = document.querySelector<HTMLDivElement>('#app');

if (!app) {
  throw new Error('App root not found.');
}

const appRoot = app;

const schemeCopy: Record<SchemeKey, { title: string; accent: string; summary: string; bullets: string[] }> = {
  falcon: {
    title: 'Falcon / FN-DSA',
    accent: 'amber',
    summary: 'Compact and fast, but its floating-point Gaussian sampler is the long-term implementation liability.',
    bullets: [
      'Hard problem: NTRU-SIS',
      'Requires floating-point Gaussian sampling over a lattice',
      'No rejection loop, but constant-time hardening is difficult',
      'Currently progressing toward FIPS 206',
    ],
  },
  mldsa: {
    title: 'ML-DSA / Dilithium',
    accent: 'magenta',
    summary: 'Integer-only and standardized, but signing uses rejection loops with visible timing variance.',
    bullets: [
      'Hard problem: Module-LWE + SIS',
      'Fiat-Shamir style lattice signatures',
      'Rejection loops typically cost 3-5 iterations',
      'FIPS 204 standardized and production-ready today',
    ],
  },
  hawk: {
    title: 'HAWK',
    accent: 'cyan',
    summary: 'The research frontier: integer-only Gaussian sampling over Z, no rejection sampling, and simpler constant-time structure.',
    bullets: [
      'Hard problem: smLIP + omSVP',
      'No floating point anywhere in the core path',
      'No rejection loop in signing',
      'NIST On-Ramp Round 2, still not standardized',
    ],
  },
};

const paramOptions: Record<ParamKey, typeof HAWK_512_PARAMS | typeof HAWK_1024_PARAMS> = {
  '512': HAWK_512_PARAMS,
  '1024': HAWK_1024_PARAMS,
};

type CrossLink = { name: string; href: string; blurb: string };

const crossLinks: CrossLink[] = [
  { name: 'crypto-lab-falcon-seal', href: 'https://github.com/systemslibrarian/crypto-lab-falcon-seal', blurb: 'Falcon float sampler walkthrough' },
  { name: 'crypto-lab-dilithium-seal', href: 'https://github.com/systemslibrarian/crypto-lab-dilithium-seal', blurb: 'ML-DSA signing internals' },
  { name: 'crypto-lab-dilithium-reject', href: 'https://github.com/systemslibrarian/crypto-lab-dilithium-reject', blurb: 'Rejection-loop variance lab' },
  { name: 'crypto-lab-sphincs-ledger', href: 'https://github.com/systemslibrarian/crypto-lab-sphincs-ledger', blurb: 'SLH-DSA stateless hash signatures' },
  { name: 'crypto-lab-lms-xmss', href: 'https://github.com/systemslibrarian/crypto-lab-lms-xmss', blurb: 'Stateful hash signatures' },
  { name: 'crypto-lab-hybrid-sign', href: 'https://github.com/systemslibrarian/crypto-lab-hybrid-sign', blurb: 'Hybrid classical + PQ signatures' },
  { name: 'crypto-lab-lattice-fault', href: 'https://github.com/systemslibrarian/crypto-lab-lattice-fault', blurb: 'Fault attacks on lattice schemes' },
  { name: 'crypto-lab-kyberslash', href: 'https://github.com/systemslibrarian/crypto-lab-kyberslash', blurb: 'Side-channel timing case study' },
];

type LearningStep = { href: string; index: string; title: string; blurb: string };

const learningPath: LearningStep[] = [
  { href: '#exhibit-schemes', index: '01', title: 'Meet the three schemes', blurb: 'Where Falcon, ML-DSA, and HAWK each pay their cost.' },
  { href: '#exhibit-lip', index: '02', title: 'See the hard problem', blurb: 'Why a short basis is secret and a long one is public.' },
  { href: '#exhibit-gaussian', index: '03', title: 'Watch the sampler', blurb: 'Integer table walk versus floating-point rejection.' },
  { href: '#exhibit-signing', index: '04', title: 'Sign and verify', blurb: 'A full round-trip with the identity shown in the open.' },
  { href: '#glossary', index: '05', title: 'Check your understanding', blurb: 'Glossary of terms, then a four-question self-check.' },
];

type CompareRow = { dimension: string; falcon: string; mldsa: string; hawk: string };

const compareRows: CompareRow[] = [
  { dimension: 'Hard problem', falcon: 'NTRU-SIS', mldsa: 'Module-LWE + SIS', hawk: 'module-LIP + omSVP' },
  { dimension: 'Signature size (NIST-I)', falcon: '666 B', mldsa: '2,420 B', hawk: '555 B' },
  { dimension: 'Public key (NIST-I)', falcon: '897 B', mldsa: '1,312 B', hawk: '1,024 B' },
  { dimension: 'Core arithmetic', falcon: 'Floating-point', mldsa: 'Integer', hawk: 'Integer only' },
  { dimension: 'Signing sampler', falcon: 'Float Gaussian over a lattice', mldsa: 'Uniform + rejection', hawk: 'Integer Gaussian over Z (CDT)' },
  { dimension: 'Rejection loop?', falcon: 'No', mldsa: 'Yes (≈3–5 iterations)', hawk: 'No' },
  { dimension: 'Constant-time posture', falcon: 'Hard to achieve', mldsa: 'Mixed', hawk: 'Designed in' },
  { dimension: 'Standardization', falcon: 'FIPS 206 (in progress)', mldsa: 'FIPS 204 (standard)', hawk: 'Round 2 on-ramp' },
];

const glossary: GlossaryTerm[] = [
  { slug: 'lattice', term: 'Lattice', short: 'A regular grid of points spanned by integer combinations of basis vectors.', full: 'A lattice is the set of all integer combinations of a set of basis vectors. The same lattice can be described by many different bases — some short and almost-orthogonal, some long and skewed. Lattice cryptography hides secrets in the gap between an easy (short) basis and a hard (long) one.' },
  { slug: 'module-lip', term: 'module-LIP', short: 'Lattice Isomorphism Problem over a module: recover a short basis from a long one.', full: 'The Lattice Isomorphism Problem asks: given two bases of the same lattice, find the transformation between them — in practice, recover a short basis from a long one. HAWK works over a module (a structured, ring-based lattice), so its assumption is "module-LIP." This is what makes HAWK signatures unforgeable without the secret short basis.' },
  { slug: 'omsvp', term: 'omSVP', short: 'One-more Short Vector Problem — HAWK’s second supporting assumption.', full: 'The one-more Short Vector Problem (omSVP) is the assumption that, even after seeing many HAWK signatures, an attacker cannot produce one more short lattice vector of the kind a valid signature reveals. It backs HAWK’s unforgeability alongside module-LIP.' },
  { slug: 'ntru', term: 'NTRU', short: 'A ring-based lattice family; Falcon’s keys solve an NTRU equation.', full: 'NTRU is a family of lattice problems built over polynomial rings. Falcon’s key generation must solve the NTRU equation f·G − g·F = q, which can fail for a sampled basis and force a retry. HAWK reuses NTRU-style structure but leans on the Lattice Isomorphism Problem for its security.' },
  { slug: 'discrete-gaussian', term: 'Discrete Gaussian', short: 'A bell-curve distribution sampled over the integers instead of the reals.', full: 'A discrete Gaussian assigns each integer k a probability proportional to exp(−k² / 2σ²). Lattice signatures need samples from this distribution so the signature leaks nothing about the secret basis. HAWK samples it over Z with fixed integer tables; Falcon samples a Gaussian over a lattice using floating-point math.' },
  { slug: 'cdt', term: 'CDT', short: 'Cumulative Distribution Table — sample by comparing one random word to fixed thresholds.', full: 'A Cumulative Distribution Table stores the running probability thresholds of a distribution. To sample, you draw one uniform random word and count how many thresholds it falls under — that count is the magnitude. Because every draw runs the same fixed comparisons with no early exit, the operation is naturally constant-time.' },
  { slug: 'rejection-sampling', term: 'Rejection sampling', short: 'Draw a candidate, accept or retry — so the loop count (and timing) varies.', full: 'Rejection sampling proposes a candidate and accepts it with some probability, retrying otherwise. ML-DSA’s signing uses it and averages a few iterations, which makes signing time data-dependent. HAWK avoids a rejection loop on its signing critical path entirely.' },
  { slug: 'constant-time', term: 'Constant-time', short: 'Runs in the same time regardless of secret data, defeating timing attacks.', full: 'Constant-time code takes the same amount of time and the same memory-access pattern no matter what the secret inputs are, so an attacker measuring timing learns nothing. Floating-point math and data-dependent loops make this hard, which is why HAWK’s integer-only, loop-free signing path is attractive.' },
  { slug: 'golomb-rice', term: 'Golomb-Rice', short: 'A compact code for small integers: a few low bits plus a unary tail.', full: 'Golomb-Rice coding splits each integer into low bits stored directly and high bits stored in unary. It is efficient when values are usually small, which is exactly the case for HAWK’s signature coefficients. This demo uses a real Golomb-Rice encoder to measure signature byte sizes.' },
  { slug: 'ntt', term: 'NTT', short: 'Number Theoretic Transform: a fast integer convolution, the integer cousin of the FFT.', full: 'The Number Theoretic Transform multiplies polynomials quickly using modular arithmetic instead of floating-point roots of unity. Production HAWK uses it to make signing fast; this educational build uses slower schoolbook multiplication for clarity, which is why production HAWK is much faster than the JS here.' },
  { slug: 'fips', term: 'FIPS 204 / 206', short: 'NIST standards: 204 is ML-DSA (final); 206 will be Falcon (FN-DSA, in progress).', full: 'FIPS 204 standardized ML-DSA in 2024 and is production-ready today. FIPS 206 will standardize Falcon as FN-DSA and is still being finalized. HAWK is not in any FIPS draft — it is a Round 2 candidate in NIST’s additional-signatures on-ramp.' },
];

const glossaryBySlug = new Map(glossary.map((entry) => [entry.slug, entry]));

type QuizQuestion = { id: string; prompt: string; options: string[]; correct: number; explain: string };

const quizQuestions: QuizQuestion[] = [
  {
    id: 'q-constant-time',
    prompt: 'What is the main reason HAWK’s signing path is easier to make constant-time than Falcon’s?',
    options: [
      'It uses no floating-point arithmetic and no data-dependent rejection loop.',
      'It uses a faster hash function.',
      'It produces larger signatures, which are harder to attack.',
      'It runs entirely on the GPU.',
    ],
    correct: 0,
    explain: 'HAWK samples integers from fixed tables and never branches on secret data, so there is no float rounding or variable loop count for a timing attacker to measure.',
  },
  {
    id: 'q-mldsa-variance',
    prompt: 'Why does ML-DSA signing show measurable timing variance?',
    options: [
      'Its signatures vary in length.',
      'Its signing uses a rejection loop that takes a variable number of iterations.',
      'It re-generates the keypair on every signature.',
      'It waits for network entropy.',
    ],
    correct: 1,
    explain: 'ML-DSA accepts or rejects each candidate signature, averaging roughly 3–5 iterations. The loop count depends on the data, so signing time varies.',
  },
  {
    id: 'q-hardness',
    prompt: 'HAWK’s security rests primarily on which assumption?',
    options: [
      'Factoring large integers.',
      'The discrete logarithm problem.',
      'The Lattice Isomorphism Problem (module-LIP).',
      'The hardness of inverting SHA-256.',
    ],
    correct: 2,
    explain: 'HAWK is built on module-LIP: recovering a short lattice basis from a long one. The same lattice is described by both bases; only the short one lets you sign.',
  },
  {
    id: 'q-standard',
    prompt: 'Which of these post-quantum signature schemes is standardized and production-ready today?',
    options: [
      'HAWK, under FIPS 205.',
      'Falcon, under FIPS 204.',
      'ML-DSA, under FIPS 204.',
      'None of them are standardized yet.',
    ],
    correct: 2,
    explain: 'ML-DSA was standardized as FIPS 204 in 2024. Falcon (FIPS 206) is still in progress, and HAWK is only a Round 2 candidate.',
  },
];

type CdtWalkState = {
  trace: CdtWalkTrace;
  visibleSteps: number;
  revealedSign: boolean;
  counted: boolean;
};

type LipState = {
  view: 'short' | 'bad';
};

const state: {
  selectedScheme: SchemeKey;
  paramSet: ParamKey;
  gaussian: GaussianState;
  signing: SigningState;
  busyGaussian: boolean;
  busySigning: boolean;
  busyTamper: boolean;
  message: string;
  theme: 'dark' | 'light';
  statusMessage: string | null;
  liveMessage: string;
  pendingFocusSelector: string | null;
  cdt: CdtWalkState | null;
  cdtSamples: number[];
  lip: LipState;
  activeGlossary: string | null;
  quiz: QuizState;
  selfTest: SelfTestState;
  copied: string | null;
} = {
  selectedScheme: 'hawk',
  paramSet: (localStorage.getItem('hawk-param') as ParamKey | null) === '1024' ? '1024' : '512',
  gaussian: null,
  signing: null,
  busyGaussian: false,
  busySigning: false,
  busyTamper: false,
  message: localStorage.getItem('hawk-message') ?? 'Release firmware v2.3.1 on 2026-04-19',
  theme: (document.documentElement.getAttribute('data-theme') as 'dark' | 'light' | null) ?? 'dark',
  statusMessage: null,
  liveMessage: 'HAWK demo loaded. Round 2 status notice: educational build only.',
  pendingFocusSelector: null,
  cdt: null,
  cdtSamples: [],
  lip: { view: 'short' },
  activeGlossary: null,
  quiz: { answers: {}, score: null },
  selfTest: 'idle',
  copied: null,
};

const schemeOrder: SchemeKey[] = ['falcon', 'mldsa', 'hawk'];

function setTheme(theme: 'dark' | 'light'): void {
  state.theme = theme;
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);
}

function setLiveMessage(message: string): void {
  state.liveMessage = message;
}

function setStatusMessage(message: string | null): void {
  state.statusMessage = message;
  if (message) {
    setLiveMessage(message);
  }
}

function setPendingFocus(selector: string | null): void {
  state.pendingFocusSelector = selector;
}

function selectScheme(scheme: SchemeKey, focusSelector: string | null = null): void {
  state.selectedScheme = scheme;
  setLiveMessage(`${schemeCopy[scheme].title} details selected.`);
  setPendingFocus(focusSelector);
  render();
}

function setParamSet(param: ParamKey): void {
  if (state.paramSet === param) {
    return;
  }
  state.paramSet = param;
  state.signing = null;
  localStorage.setItem('hawk-param', param);
  setLiveMessage(`HAWK parameter set switched to n=${param}.`);
  render();
}

function formatMs(value: number): string {
  return `${value.toFixed(value >= 10 ? 1 : 3)} ms`;
}

function formatRatio(value: number): string {
  return `${value.toFixed(2)}x`;
}

function formatBytes(value: number): string {
  if (value < 1024) {
    return `${value} B`;
  }
  return `${(value / 1024).toFixed(2)} KB`;
}

function formatHex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function previewPolynomial(values: Int32Array, width: number = 12): string {
  return Array.from(values.slice(0, width)).join(', ');
}

function svgHistogram(
  histogram: Array<[number, number]>,
  pmf: Array<[number, number]>,
  totalSamples: number,
): string {
  if (histogram.length === 0) {
    return '<p class="mini-note">No samples yet.</p>';
  }

  const width = 720;
  const height = 220;
  const padding = { top: 24, right: 24, bottom: 36, left: 44 };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;

  const allKeys = new Set<number>();
  histogram.forEach(([k]) => allKeys.add(k));
  pmf.forEach(([k]) => allKeys.add(k));
  const xs = Array.from(allKeys).sort((a, b) => a - b);
  const xMin = xs[0];
  const xMax = xs[xs.length - 1];
  const span = Math.max(1, xMax - xMin);

  const observedMax = histogram.reduce((acc, [, count]) => Math.max(acc, count / totalSamples), 0);
  const pmfMax = pmf.reduce((acc, [, prob]) => Math.max(acc, prob), 0);
  const yMax = Math.max(observedMax, pmfMax) * 1.1 || 1;

  const xScale = (value: number) => padding.left + ((value - xMin) / span) * plotWidth;
  const yScale = (value: number) => padding.top + plotHeight - (value / yMax) * plotHeight;
  const barWidth = Math.max(8, plotWidth / xs.length - 6);

  const bars = histogram
    .map(([k, count]) => {
      const probability = count / totalSamples;
      const x = xScale(k) - barWidth / 2;
      const y = yScale(probability);
      const h = padding.top + plotHeight - y;
      return `<rect x="${x.toFixed(2)}" y="${y.toFixed(2)}" width="${barWidth.toFixed(2)}" height="${Math.max(0, h).toFixed(2)}" rx="3" class="hist-rect"><title>k=${k}, observed=${(probability * 100).toFixed(2)}%</title></rect>`;
    })
    .join('');

  const pmfPoints = pmf
    .map(([k, prob]) => `${xScale(k).toFixed(2)},${yScale(prob).toFixed(2)}`)
    .join(' ');
  const pmfDots = pmf
    .map(([k, prob]) => `<circle cx="${xScale(k).toFixed(2)}" cy="${yScale(prob).toFixed(2)}" r="3" class="hist-pmf-dot"><title>k=${k}, expected=${(prob * 100).toFixed(2)}%</title></circle>`)
    .join('');

  const xTicks = xs
    .map((k) => `<text x="${xScale(k).toFixed(2)}" y="${(height - padding.bottom + 18).toFixed(2)}" text-anchor="middle" class="hist-axis-label">${k}</text>`)
    .join('');

  const yTickCount = 4;
  const yTicks = Array.from({ length: yTickCount + 1 }, (_, index) => {
    const ratio = index / yTickCount;
    const value = ratio * yMax;
    const y = yScale(value);
    return `
      <line x1="${padding.left}" y1="${y.toFixed(2)}" x2="${(width - padding.right).toFixed(2)}" y2="${y.toFixed(2)}" class="hist-grid"/>
      <text x="${(padding.left - 8).toFixed(2)}" y="${(y + 4).toFixed(2)}" text-anchor="end" class="hist-axis-label">${(value * 100).toFixed(1)}%</text>
    `;
  }).join('');

  return `
    <figure class="histogram-figure" aria-label="Observed discrete Gaussian samples versus the theoretical PMF at sigma ${EXPECTED_SIGMA}">
      <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMid meet" role="img">
        <title>Observed sample distribution and theoretical PMF</title>
        <g class="hist-grid-group">${yTicks}</g>
        <g class="hist-bars">${bars}</g>
        <polyline points="${pmfPoints}" class="hist-pmf-line" fill="none"/>
        <g class="hist-pmf-dots">${pmfDots}</g>
        <g class="hist-axis-ticks">${xTicks}</g>
      </svg>
      <figcaption class="histogram-caption">
        <span class="legend-chip"><span class="swatch swatch-observed" aria-hidden="true"></span>Observed (${totalSamples.toLocaleString()} samples)</span>
        <span class="legend-chip"><span class="swatch swatch-theory" aria-hidden="true"></span>Theoretical PMF at sigma=${EXPECTED_SIGMA}</span>
      </figcaption>
    </figure>
  `;
}

function schemeDetailMarkup(): string {
  const detail = schemeCopy[state.selectedScheme];

  return `
    <article class="detail-panel accent-${detail.accent}" id="scheme-detail-panel" tabindex="-1">
      <div class="detail-header">
        <span class="eyebrow">Deep Dive</span>
        <h3>${detail.title}</h3>
      </div>
      <p>${detail.summary}</p>
      <ul class="detail-list">
        ${detail.bullets.map((bullet) => `<li>${bullet}</li>`).join('')}
      </ul>
    </article>
  `;
}

function gaussianMarkup(): string {
  if (!state.gaussian) {
    return `
      <div class="status-card muted">
        <p>Run the sampler to compare HAWK's integer-table lookup against a real Box-Muller plus rejection float sampler of the kind Falcon's signing path is built on.</p>
      </div>
    `;
  }

  const ratio = state.gaussian.falconSampleMs / Math.max(state.gaussian.hawkSampleMs, 0.0001);

  return `
    <div class="stats-grid compact" aria-label="Gaussian sampler statistics">
      <article class="metric-card accent-cyan">
        <span>HAWK integer sampler</span>
        <strong>${formatMs(state.gaussian.hawkSampleMs)}</strong>
      </article>
      <article class="metric-card accent-amber">
        <span>Falcon float sampler</span>
        <strong>${formatMs(state.gaussian.falconSampleMs)}</strong>
      </article>
      <article class="metric-card accent-gold">
        <span>Float-to-integer ratio</span>
        <strong>${formatRatio(ratio)}</strong>
      </article>
      <article class="metric-card accent-green">
        <span>Observed variance</span>
        <strong>${state.gaussian.variance.toFixed(4)}</strong>
      </article>
    </div>
    ${svgHistogram(state.gaussian.histogram, state.gaussian.pmf, state.gaussian.sampleCount)}
    <p class="mini-note">Observed mean: ${state.gaussian.mean.toFixed(4)} (target 0). Observed support: ${state.gaussian.minObserved} to ${state.gaussian.maxObserved}. Both samplers ran ${state.gaussian.sampleCount.toLocaleString()} times. The Falcon path costs more because of Math.log, Math.cos, Math.exp and the rejection loop; HAWK's integer table walk is a single linear scan.</p>
  `;
}

function attemptsMarkup(attempts: SigningState extends infer T ? T extends { attempts: infer A } ? A : never : never): string {
  if (!attempts || (attempts as Array<unknown>).length === 0) {
    return '<p class="mini-note">No rejected NTRU bases. The first sampled basis solved the toy NTRU equation cleanly.</p>';
  }

  const rows = (attempts as Array<{ attempt: number; reason: string }>)
    .map((entry) => `<li><span class="attempt-index">#${entry.attempt}</span><span class="attempt-reason">${escapeHtml(entry.reason)}</span></li>`)
    .join('');

  return `
    <ol class="attempts-list" aria-label="Rejected key generation attempts">${rows}</ol>
    <p class="mini-note">Real HAWK keygen retries until the NTRU equation is solvable. Production code rejects many more bases for a wider set of reasons than this educational toy.</p>
  `;
}

function tamperMarkup(): string {
  if (!state.signing) {
    return '';
  }

  if (!state.signing.tampered) {
    return `
      <div class="tamper-row">
        <button class="ghost-button" type="button" data-action="tamper-signature" ${state.busyTamper ? 'disabled' : ''} aria-busy="${state.busyTamper}">${state.busyTamper ? 'Tampering...' : 'Flip one coefficient and re-verify'}</button>
        <span class="mini-note">Verify recovers (f, g) from the signature and checks both an exact polynomial identity and a Euclidean norm bound. Any single-bit edit breaks the identity.</span>
      </div>
    `;
  }

  const { coefficient, delta, verified } = state.signing.tampered;
  const detail = verified
    ? 'Verification still passes for this perturbation, which is unexpected: please reload and try again.'
    : `Verification correctly rejects: s1[${coefficient}] shifted by ${delta} fails the basis identity recovery.`;

  return `
    <div class="tamper-result ${verified ? 'tamper-soft' : 'tamper-hard'}" role="status">
      <strong>${verified ? 'PASS (unexpected)' : 'FAIL (expected)'}</strong>
      <p>${escapeHtml(detail)}</p>
      <button class="ghost-button" type="button" data-action="tamper-reset">Clear tamper result</button>
    </div>
  `;
}

function signingMarkup(): string {
  if (!state.signing) {
    return `
      <div class="status-card muted">
        <p>Generate a HAWK keypair, sign the current message, and watch the round-trip complete with a verification check. The signature, byte sizes, and rejected NTRU bases all surface below.</p>
      </div>
    `;
  }

  const params = paramOptions[state.signing.paramSet];
  const benchmark = state.signing.benchmark;

  return `
    <div class="stats-grid" aria-label="Signing statistics">
      <article class="metric-card accent-green">
        <span>Verification</span>
        <strong>${state.signing.verified ? 'PASS' : 'FAIL'}</strong>
      </article>
      <article class="metric-card accent-cyan">
        <span>Signing time</span>
        <strong>${formatMs(state.signing.signingTimeMs)}</strong>
      </article>
      <article class="metric-card accent-gold">
        <span>Keygen attempts</span>
        <strong>${state.signing.generationAttempts}</strong>
      </article>
      <article class="metric-card accent-purple">
        <span>Restart count</span>
        <strong>${state.signing.restartCount}</strong>
      </article>
      <article class="metric-card accent-cyan">
        <span>Signature bytes (measured)</span>
        <strong>${formatBytes(state.signing.signatureBytes)}</strong>
      </article>
      <article class="metric-card accent-amber">
        <span>Public key bytes (measured)</span>
        <strong>${formatBytes(state.signing.publicKeyBytes)}</strong>
      </article>
      <article class="metric-card accent-magenta">
        <span>HAWK-${params.n} target sig size</span>
        <strong>${formatBytes(params.signatureBytes)}</strong>
      </article>
      <article class="metric-card accent-green">
        <span>Security level</span>
        <strong>${params.securityLevel}</strong>
      </article>
    </div>

    <section class="bench-strip" aria-label="Side-by-side benchmark across the three schemes">
      <article class="bench-card accent-cyan">
        <h4>HAWK</h4>
        <p class="bench-row">Sign mean <strong>${formatMs(benchmark.hawkSignMs)}</strong></p>
        <p class="bench-row">Stdev <strong>${formatMs(benchmark.hawkSignStdev)}</strong></p>
        <p class="bench-row">Verify mean <strong>${formatMs(benchmark.hawkVerifyMs)}</strong></p>
      </article>
      <article class="bench-card accent-amber">
        <h4>Falcon-style (simulated)</h4>
        <p class="bench-row">FFS pass <strong>${formatMs(benchmark.falconSimulationMs)}</strong></p>
        <p class="bench-row">Stdev <strong>${formatMs(benchmark.falconSimulationStdev)}</strong></p>
        <p class="bench-row">Critical-path floats <strong>yes</strong></p>
      </article>
      <article class="bench-card accent-magenta">
        <h4>ML-DSA-style (simulated)</h4>
        <p class="bench-row">Loop mean <strong>${formatMs(benchmark.mldsaSimulationMs)}</strong></p>
        <p class="bench-row">Stdev <strong>${formatMs(benchmark.mldsaSimulationStdev)}</strong></p>
        <p class="bench-row">Avg iterations <strong>${benchmark.mldsaAvgIterations.toFixed(2)}</strong></p>
      </article>
    </section>

    <p class="mini-note">The benchmark numbers above are honest wall-clock measurements in this browser. They are not production HAWK / Falcon / ML-DSA timings. The point is the <em>shape</em>: HAWK has no rejection loop so its stdev is dominated by JS jitter, ML-DSA's stdev is dominated by its accept/reject distribution, and Falcon's cost is dominated by transcendentals on the critical path.</p>

    <div class="signing-log" tabindex="-1">
      <div>
        <span class="eyebrow">Verification, in the open</span>
        ${verifyMathMarkup()}
      </div>
      <div>
        <div class="log-head">
          <span class="eyebrow">Salt</span>
          ${copyButton('salt', state.signing.saltHex, 'salt')}
        </div>
        <p class="mono-block">${escapeHtml(state.signing.saltHex)}</p>
      </div>
      <div>
        <div class="log-head">
          <span class="eyebrow">s1 preview (first 12 coefficients)</span>
          ${copyButton('s1 preview', state.signing.s1Preview, 's1')}
        </div>
        <p class="mono-block">${escapeHtml(state.signing.s1Preview)}</p>
      </div>
      <div>
        <span class="eyebrow">Rejected NTRU bases</span>
        ${attemptsMarkup(state.signing.attempts)}
      </div>
      <div>
        <span class="eyebrow">Tamper test</span>
        ${tamperMarkup()}
      </div>
      <div>
        <span class="eyebrow">Export</span>
        ${downloadMarkup()}
        <p class="mini-note">Signature is the ${termChip('golomb-rice', 'Golomb-Rice')}-encoded s1 prefixed by the salt. Public key is q00 || q01 as little-endian Int32.</p>
      </div>
    </div>
  `;
}

function statusMarkup(): string {
  if (!state.statusMessage) {
    return '';
  }

  return `
    <div class="status-banner" role="status" aria-live="polite" tabindex="-1">
      <strong>Notice:</strong> ${escapeHtml(state.statusMessage)}
    </div>
  `;
}

function cdtWalkMarkup(): string {
  const cdt = state.cdt;
  if (!cdt) {
    return `
      <div class="status-card muted">
        <p>Click "New random draw" to walk through a single CDT sample step by step: one 64-bit random word, seven threshold comparisons, an integer magnitude, and a sign bit.</p>
        <button class="primary-button" type="button" data-action="cdt-new">New random draw</button>
      </div>
    `;
  }

  const wordHex = cdt.trace.randomWord.toString(16).padStart(16, '0').toUpperCase();
  const compareValue = cdt.trace.randomWord;
  const visibleSteps = cdt.visibleSteps;
  const totalSteps = cdt.trace.steps.length;
  const complete = visibleSteps >= totalSteps && cdt.revealedSign;

  const stepCards = cdt.trace.steps
    .map((step, index) => {
      const shown = index < visibleSteps;
      if (!shown) {
        return `
          <li class="cdt-step pending" aria-hidden="true">
            <span class="cdt-step-index">${index}</span>
            <span class="cdt-step-threshold">T[${index}]</span>
            <span class="cdt-step-outcome">— pending —</span>
          </li>
        `;
      }
      const decision = step.isLess
        ? `<span class="cdt-step-outcome accepted">word &lt; T[${index}] → magnitude += 1 (now ${step.magnitudeAfter})</span>`
        : `<span class="cdt-step-outcome rejected">word ≥ T[${index}] → magnitude stays (${step.magnitudeAfter})</span>`;
      return `
        <li class="cdt-step ${step.isLess ? 'cdt-accept' : 'cdt-reject'}">
          <span class="cdt-step-index">${index}</span>
          <span class="cdt-step-threshold mono-block">T[${index}] = ${step.threshold.toString(16).toUpperCase().padStart(16, '0')}</span>
          ${decision}
        </li>
      `;
    })
    .join('');

  const finalLine = complete
    ? `<p class="cdt-final ${cdt.trace.sample === 0 ? '' : cdt.trace.signBit === 0 ? 'positive' : 'negative'}">Magnitude ${cdt.trace.magnitude} ${cdt.trace.magnitude === 0 ? '(zero needs no sign bit)' : cdt.trace.signBit === 0 ? '× +1' : '× -1'} = <strong>${cdt.trace.sample}</strong></p>`
    : visibleSteps >= totalSteps
    ? `<p class="cdt-final pending">Magnitude ${cdt.trace.magnitude}. Reveal the sign bit to get the final sample.</p>`
    : `<p class="cdt-final pending">Magnitude so far: ${cdt.trace.steps[visibleSteps - 1]?.magnitudeAfter ?? 0}</p>`;

  return `
    <div class="cdt-shell">
      <div class="cdt-header">
        <div class="cdt-word">
          <span class="eyebrow">Random 64-bit word</span>
          <p class="mono-block">0x${wordHex}</p>
          <p class="mini-note">As a decimal: ${compareValue.toString()}. Every comparison in this walk uses this same word against a different threshold.</p>
        </div>
        <div class="cdt-controls">
          <button class="ghost-button" type="button" data-action="cdt-step" ${visibleSteps >= totalSteps ? 'disabled' : ''}>Step</button>
          <button class="ghost-button" type="button" data-action="cdt-reveal-sign" ${visibleSteps < totalSteps || cdt.revealedSign ? 'disabled' : ''}>Reveal sign bit</button>
          <button class="ghost-button" type="button" data-action="cdt-fast">Run to end</button>
          <button class="primary-button" type="button" data-action="cdt-new">New random draw</button>
        </div>
      </div>
      <ol class="cdt-steps">${stepCards}</ol>
      ${finalLine}
      <p class="mini-note">Notice: every draw runs all seven comparisons. There is no early exit. That's why the algorithm has no data-dependent branch on its critical path.</p>
    </div>
  `;
}

function lipMarkup(): string {
  const view = state.lip.view;
  const width = 520;
  const height = 320;
  const cx = width / 2;
  const cy = height / 2;
  const scale = 30;

  const shortBasis: [number, number][] = [[2, 0], [0, 2]];
  const badBasis: [number, number][] = [[6, 1], [5, 2]];
  const basis = view === 'short' ? shortBasis : badBasis;

  const lattice: Array<{ x: number; y: number }> = [];
  for (let a = -8; a <= 8; a += 1) {
    for (let b = -8; b <= 8; b += 1) {
      const lx = a * 2 + b * 0;
      const ly = a * 0 + b * 2;
      if (Math.abs(lx) <= 8 && Math.abs(ly) <= 6) {
        lattice.push({ x: cx + lx * scale, y: cy - ly * scale });
      }
    }
  }

  const target = { x: cx + 1.3 * scale, y: cy - 1.7 * scale };
  const nearestLattice = { x: cx + 2 * scale, y: cy - 2 * scale };

  const basisVectors = basis
    .map(([vx, vy], index) => {
      const endX = cx + vx * scale;
      const endY = cy - vy * scale;
      const color = index === 0 ? 'var(--cyan)' : 'var(--gold)';
      return `<line x1="${cx}" y1="${cy}" x2="${endX}" y2="${endY}" stroke="${color}" stroke-width="3" marker-end="url(#lipArrow)"/>`;
    })
    .join('');

  const dots = lattice
    .map(({ x, y }) => `<circle cx="${x}" cy="${y}" r="3" class="lip-lattice-dot"/>`)
    .join('');

  return `
    <div class="lip-shell">
      <div class="lip-controls" role="radiogroup" aria-label="LIP basis view">
        <button type="button" role="radio" aria-checked="${view === 'short'}" data-lip="short" class="${view === 'short' ? 'active' : ''}">Short basis (secret)</button>
        <button type="button" role="radio" aria-checked="${view === 'bad'}" data-lip="bad" class="${view === 'bad' ? 'active' : ''}">Bad basis (public)</button>
      </div>
      <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMid meet" class="lip-svg" role="img" aria-label="Two-dimensional lattice with ${view === 'short' ? 'short' : 'long'} basis vectors">
        <defs>
          <marker id="lipArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M0,0 L10,5 L0,10 z" fill="currentColor"/>
          </marker>
        </defs>
        <g class="lip-grid">${dots}</g>
        <g class="lip-basis">${basisVectors}</g>
        <line x1="${cx}" y1="${cy}" x2="${target.x}" y2="${target.y}" stroke="var(--magenta)" stroke-width="2" stroke-dasharray="4 3"/>
        <circle cx="${target.x}" cy="${target.y}" r="6" class="lip-target"/>
        <circle cx="${nearestLattice.x}" cy="${nearestLattice.y}" r="6" class="lip-nearest"/>
      </svg>
      <div class="lip-legend">
        <span><span class="swatch swatch-short" aria-hidden="true"></span>Basis vector 1</span>
        <span><span class="swatch swatch-long" aria-hidden="true"></span>Basis vector 2</span>
        <span><span class="swatch swatch-target" aria-hidden="true"></span>Hash target</span>
        <span><span class="swatch swatch-nearest" aria-hidden="true"></span>Nearest lattice point</span>
      </div>
      <p class="mini-note">${view === 'short' ? 'The short basis spans the same lattice but with almost-orthogonal vectors. Rounding the hash target to the nearest lattice point is easy: walk a few small basis steps. This is what HAWK signs with.' : 'The bad basis spans the same lattice with long skewed vectors. The lattice points are identical, but finding the nearest one from the same target now requires much longer combinations. This is the public basis. Recovering the short basis from the bad one is the LIP assumption.'}</p>
    </div>
  `;
}

function downloadMarkup(): string {
  if (!state.signing) {
    return '';
  }
  return `
    <div class="download-row">
      <button class="ghost-button" type="button" data-action="download-sig">Download signature (.bin)</button>
      <button class="ghost-button" type="button" data-action="download-pk">Download public key (.bin)</button>
    </div>
  `;
}

function heroLiveStatsMarkup(): string {
  const items: Array<{ label: string; value: string }> = [];

  if (state.signing) {
    items.push({ label: 'Last sign', value: formatMs(state.signing.signingTimeMs) });
    items.push({ label: 'Signature bytes', value: formatBytes(state.signing.signatureBytes) });
    items.push({ label: 'Keygen attempts', value: String(state.signing.generationAttempts) });
    items.push({ label: 'Verification', value: state.signing.verified ? 'PASS' : 'FAIL' });
  }

  if (state.gaussian) {
    const ratio = state.gaussian.falconSampleMs / Math.max(state.gaussian.hawkSampleMs, 0.0001);
    items.push({ label: 'Float vs integer Gaussian', value: formatRatio(ratio) });
  }

  if (items.length === 0) {
    return `<p class="mini-note">Run the samplers and the signing demo to populate live numbers here.</p>`;
  }

  const rows = items
    .map((item) => `<dt>${item.label}</dt><dd>${escapeHtml(item.value)}</dd>`)
    .join('');

  return `<dl class="hero-stats">${rows}</dl>`;
}

function transparencyMarkup(): string {
  return `
    <section class="exhibit transparency" aria-labelledby="transparency-title">
      <div class="section-heading">
        <span class="eyebrow">Honesty Panel</span>
        <h2 id="transparency-title">What's exact, what's simulated, what's simplified</h2>
        <p>This page is an educational demo. Different parts of it have different fidelity to the spec, and we'd rather you know.</p>
      </div>
      <div class="transparency-grid">
        <article class="advice-card accent-green">
          <h3>Exact</h3>
          <ul>
            <li>HAWK signing returns a salt and an s1 polynomial that pass the public-key consistency check and the norm bound.</li>
            <li>Verification recovers (f, g), checks the polynomial identity exactly, and applies a real norm bound.</li>
            <li>The discrete Gaussian CDT walk is constant-shape: same comparisons every call, no early exit.</li>
            <li>Signature byte counts come from a real Golomb-Rice encoder applied to the generated s1.</li>
          </ul>
        </article>
        <article class="advice-card accent-amber">
          <h3>Simulated</h3>
          <ul>
            <li>The Falcon path is a real Box-Muller plus rejection sampler plus a float FFT tree pass. It is NOT the production Falcon sampler, but its critical path is genuinely float-heavy.</li>
            <li>The ML-DSA path is a stand-in that models the rejection-loop iteration count distribution and reports real timing variance.</li>
            <li>The keygen failure reasons here are toy NTRU heuristics, not the real f*G - g*F = q solve.</li>
          </ul>
        </article>
        <article class="advice-card accent-purple">
          <h3>Simplified</h3>
          <ul>
            <li>HAWK signing uses SHA-256-based deterministic expansion of f from the kgseed. Production uses fast PRGs and NTT, which makes production HAWK materially faster than what this JS shows.</li>
            <li>The hidden Gaussian perturbation in signing is modeled, not the full fast-Fourier sampling tree.</li>
            <li>Restart probabilities in the UI are illustrative; the real bound depends on the salt distribution and the lattice norm.</li>
          </ul>
        </article>
      </div>
    </section>
  `;
}

function copyButton(label: string, payload: string, key: string): string {
  const copied = state.copied === key;
  return `<button class="copy-button${copied ? ' copied' : ''}" type="button" data-copy-text="${escapeHtml(payload)}" data-copy-key="${escapeHtml(key)}" aria-label="Copy ${escapeHtml(label)}">${copied ? '✓ Copied' : 'Copy'}</button>`;
}

function termChip(slug: string, label?: string): string {
  const entry = glossaryBySlug.get(slug);
  if (!entry) {
    return escapeHtml(label ?? slug);
  }
  return `<button class="term-chip" type="button" data-term="${escapeHtml(slug)}" aria-describedby="glossary-${escapeHtml(slug)}" title="${escapeHtml(entry.short)}">${escapeHtml(label ?? entry.term)}</button>`;
}

function learningPathMarkup(): string {
  const steps = learningPath
    .map(
      (step) => `
        <li>
          <a class="path-step" href="${step.href}" data-path-step>
            <span class="path-index" aria-hidden="true">${step.index}</span>
            <span class="path-body">
              <span class="path-title">${escapeHtml(step.title)}</span>
              <span class="path-blurb">${escapeHtml(step.blurb)}</span>
            </span>
          </a>
        </li>`,
    )
    .join('');

  return `
    <nav class="learning-path" aria-label="Suggested learning path">
      <p class="eyebrow">Start here · a five-step tour</p>
      <ol class="path-list">${steps}</ol>
    </nav>
  `;
}

function comparisonTableMarkup(): string {
  const rows = compareRows
    .map(
      (row) => `
        <tr>
          <th scope="row">${escapeHtml(row.dimension)}</th>
          <td>${escapeHtml(row.falcon)}</td>
          <td>${escapeHtml(row.mldsa)}</td>
          <td class="compare-hawk">${escapeHtml(row.hawk)}</td>
        </tr>`,
    )
    .join('');

  return `
    <div class="table-scroll" tabindex="0" role="region" aria-label="Scheme comparison table (scroll horizontally to see all columns)">
      <table class="compare-table">
        <caption class="sr-only">Side-by-side comparison of Falcon, ML-DSA, and HAWK across eight dimensions. The HAWK column is highlighted.</caption>
        <thead>
          <tr>
            <th scope="col">Dimension</th>
            <th scope="col">Falcon</th>
            <th scope="col">ML-DSA</th>
            <th scope="col" class="compare-hawk">HAWK</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <p class="mini-note">Sizes are the commonly cited NIST-I figures for each scheme. ML-DSA is the only row that is standardized and deployable today; the HAWK column is the design this lab explores.</p>
  `;
}

function verifyMathMarkup(): string {
  if (!state.signing) {
    return '';
  }
  const detail = state.signing.verifyDetail;
  if (detail.parameterMismatch) {
    return '<p class="mini-note">Parameter sets did not match, so the basis identity was not checked.</p>';
  }

  const fPreview = previewPolynomial(detail.recoveredF, 8);
  const gPreview = previewPolynomial(detail.recoveredG, 8);
  const lhsPreview = previewPolynomial(detail.consistency, 8);
  const rhsPreview = previewPolynomial(detail.q01, 8);

  return `
    <div class="verify-math" aria-label="Verification math">
      <ol class="verify-steps">
        <li>
          <span class="verify-label">Recover f = s1 − h</span>
          <p class="mono-block">[ ${escapeHtml(fPreview)} … ]</p>
        </li>
        <li>
          <span class="verify-label">Recover g = q00 − f</span>
          <p class="mono-block">[ ${escapeHtml(gPreview)} … ]</p>
        </li>
        <li class="${detail.identityHolds ? 'verify-pass' : 'verify-fail'}">
          <span class="verify-label">Identity check: does f − g equal the public q01?</span>
          <p class="mono-block">f − g = [ ${escapeHtml(lhsPreview)} … ]</p>
          <p class="mono-block">q01  = [ ${escapeHtml(rhsPreview)} … ]</p>
          <p class="verify-verdict">${detail.identityHolds ? '✓ identical — the recovered basis is consistent with the public key' : '✗ mismatch — this is not a valid signature for this key'}</p>
        </li>
        <li class="${detail.normWithinBound ? 'verify-pass' : 'verify-fail'}">
          <span class="verify-label">Norm bound: is ‖f‖² + ‖g‖² within the acceptance bound?</span>
          <p class="mono-block">${Number.isNaN(detail.totalNorm) ? '—' : detail.totalNorm.toLocaleString()} ${detail.normWithinBound ? '≤' : '>'} ${detail.bound.toLocaleString()}</p>
          <p class="verify-verdict">${detail.normWithinBound ? '✓ short enough — the signer knew the secret short basis' : '✗ too long — rejected'}</p>
        </li>
      </ol>
      <p class="mini-note">Verification never sees f or g directly. It reconstructs them from the public key plus the signature, then checks an exact polynomial identity and a length bound. A single flipped coefficient breaks the first check — try the tamper test below.</p>
    </div>
  `;
}

function cdtAggregateMarkup(): string {
  const samples = state.cdtSamples;
  if (samples.length === 0) {
    return '';
  }

  const counts = new Map<number, number>();
  for (const value of samples) {
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  const keys = Array.from(counts.keys()).sort((a, b) => a - b);
  const maxCount = Math.max(...counts.values());

  const bars = keys
    .map((k) => {
      const count = counts.get(k) ?? 0;
      const pct = (count / maxCount) * 100;
      return `
        <div class="cdt-tally-row">
          <span class="cdt-tally-key">${k > 0 ? `+${k}` : k}</span>
          <span class="cdt-tally-bar"><span style="width:${pct.toFixed(1)}%"></span></span>
          <span class="cdt-tally-count">${count}</span>
        </div>`;
    })
    .join('');

  const last = samples[samples.length - 1];
  return `
    <div class="cdt-aggregate" aria-live="polite">
      <p class="mini-note">Your hand-drawn samples so far: <strong>${samples.length}</strong>. Latest landed at k = ${last > 0 ? `+${last}` : last}. Each draw above is one bar here — run a few thousand and this shape converges to the smooth theoretical curve plotted in the histogram.</p>
      <div class="cdt-tally" role="img" aria-label="Tally of ${samples.length} hand-drawn CDT samples by value">${bars}</div>
    </div>
  `;
}

function glossaryMarkup(): string {
  const items = glossary
    .map((entry) => {
      const open = state.activeGlossary === entry.slug;
      return `
        <div class="glossary-entry${open ? ' open' : ''}" id="glossary-${entry.slug}">
          <button class="glossary-term" type="button" data-glossary="${entry.slug}" aria-expanded="${open}" aria-controls="glossary-body-${entry.slug}">
            <span>${escapeHtml(entry.term)}</span>
            <span class="glossary-toggle" aria-hidden="true">${open ? '−' : '+'}</span>
          </button>
          <div class="glossary-body" id="glossary-body-${entry.slug}" ${open ? '' : 'hidden'}>
            <p class="glossary-short">${escapeHtml(entry.short)}</p>
            <p class="glossary-full">${escapeHtml(entry.full)}</p>
          </div>
        </div>`;
    })
    .join('');

  return `<div class="glossary-grid">${items}</div>`;
}

function quizMarkup(): string {
  const answered = Object.keys(state.quiz.answers).length;
  const total = quizQuestions.length;

  const questions = quizQuestions
    .map((question, qIndex) => {
      const chosen = state.quiz.answers[question.id];
      const hasAnswer = chosen !== undefined;
      const options = question.options
        .map((option, oIndex) => {
          const selected = chosen === oIndex;
          const isCorrect = oIndex === question.correct;
          let cls = 'quiz-option';
          if (hasAnswer && selected) {
            cls += isCorrect ? ' quiz-correct' : ' quiz-wrong';
          }
          if (hasAnswer && isCorrect) {
            cls += ' quiz-answer';
          }
          return `
            <button class="${cls}" type="button" role="radio" aria-checked="${selected}" data-quiz="${question.id}" data-quiz-option="${oIndex}" ${hasAnswer ? 'disabled' : ''}>
              <span class="quiz-marker" aria-hidden="true"></span>
              <span>${escapeHtml(option)}</span>
            </button>`;
        })
        .join('');

      const feedback = hasAnswer
        ? `<p class="quiz-feedback ${chosen === question.correct ? 'good' : 'bad'}">${chosen === question.correct ? 'Correct. ' : 'Not quite. '}${escapeHtml(question.explain)}</p>`
        : '';

      return `
        <fieldset class="quiz-question">
          <legend><span class="quiz-q-index">Q${qIndex + 1}.</span> ${escapeHtml(question.prompt)}</legend>
          <div class="quiz-options" role="radiogroup" aria-label="Answer choices for question ${qIndex + 1}">${options}</div>
          ${feedback}
        </fieldset>`;
    })
    .join('');

  const scoreLine =
    answered === total
      ? `<p class="quiz-score" role="status">You answered all ${total} — score ${state.quiz.score}/${total}. <button class="ghost-button" type="button" data-action="quiz-reset">Reset quiz</button></p>`
      : `<p class="mini-note">${answered} of ${total} answered. Pick an option to lock in each answer and see why.</p>`;

  return `
    <div class="quiz">
      ${questions}
      ${scoreLine}
    </div>
  `;
}

const selfTestBadgeCopy: Record<SelfTestState, { cls: string; text: string }> = {
  idle: { cls: 'pending', text: 'Self-test queued' },
  running: { cls: 'pending', text: 'Self-test running…' },
  pass: { cls: 'pass', text: '✓ Self-test passed in your browser' },
  fail: { cls: 'fail', text: '✗ Self-test failed — see console' },
};

function selfTestBadgeMarkup(): string {
  const badge = selfTestBadgeCopy[state.selfTest];
  return `<span class="self-test-badge ${badge.cls}" id="self-test-badge" role="status" title="Live keygen → sign → verify → tamper-reject round-trip run on page load">${badge.text}</span>`;
}

/**
 * Update only the badge element in place. The self-test runs on load and must
 * not rebuild the whole view, or it could steal focus from a visitor who
 * started interacting in the first moments after load.
 */
function paintSelfTestBadge(): void {
  const el = document.getElementById('self-test-badge');
  if (!el) {
    return;
  }
  const badge = selfTestBadgeCopy[state.selfTest];
  el.className = `self-test-badge ${badge.cls}`;
  el.textContent = badge.text;
}

function render(): void {
  appRoot.innerHTML = `
    <a class="skip-link" href="#main-content">Skip to main content</a>
    <div class="sr-only" aria-live="polite" aria-atomic="true">${escapeHtml(state.liveMessage)}</div>
    <main class="shell" id="main-content">
      ${statusMarkup()}
      <section class="hero" aria-labelledby="hero-title">
        <div class="hero-copy">
          <span class="hero-tag">HAWK signature laboratory</span>
          <h1 id="hero-title">Integer-only lattice signatures, built for the post-Falcon era.</h1>
          <p class="lede">Browser-based educational demo of HAWK, the only lattice-based scheme still standing in Round 2 of NIST's additional PQ signature process as of April 2026.</p>
          <div class="hero-actions">
            <button class="pill-button" type="button" data-action="theme-toggle" aria-pressed="${state.theme === 'light'}" aria-label="Switch to ${state.theme === 'dark' ? 'light' : 'dark'} mode">Switch to ${state.theme === 'dark' ? 'light' : 'dark'} mode</button>
            <span class="status-badge round-2">Round 2, not standardized</span>
            <span class="status-badge caution">Educational build only</span>
            ${selfTestBadgeMarkup()}
          </div>
        </div>
        <aside class="hero-aside">
          <p class="eyebrow">Why HAWK matters</p>
          <ul class="hero-list">
            <li>No floating-point arithmetic</li>
            <li>No rejection loop in signing</li>
            <li>Discrete Gaussian sampling over Z via fixed tables</li>
            <li>Smaller signatures than Falcon at level I</li>
            <li>Potentially friendlier to FHE and MPC circuits</li>
          </ul>
          <div class="hero-live" aria-live="polite" aria-label="Live stats from this session">
            <p class="eyebrow">Live from this session</p>
            ${heroLiveStatsMarkup()}
          </div>
        </aside>
      </section>

      ${learningPathMarkup()}

      <section class="exhibit" id="exhibit-schemes" aria-labelledby="exhibit-one-title">
        <div class="section-heading">
          <span class="eyebrow">Exhibit 1</span>
          <h2 id="exhibit-one-title">The Three Lattice Signatures</h2>
          <p>Click a scheme to inspect the engineering tradeoff that dominates its deployment story.</p>
        </div>
        <div class="scheme-grid" role="radiogroup" aria-label="Signature scheme comparison cards">
          <button class="scheme-card accent-amber ${state.selectedScheme === 'falcon' ? 'active' : ''}" type="button" role="radio" tabindex="${state.selectedScheme === 'falcon' ? '0' : '-1'}" data-scheme="falcon" aria-checked="${state.selectedScheme === 'falcon'}" aria-describedby="scheme-detail-panel">
            <h3>Falcon</h3>
            <p>Small signatures, difficult floating-point hardening.</p>
            <ul>
              <li>NTRU-SIS</li>
              <li>Float Gaussian over a lattice</li>
              <li>FIPS 206 in progress</li>
            </ul>
          </button>
          <button class="scheme-card accent-magenta ${state.selectedScheme === 'mldsa' ? 'active' : ''}" type="button" role="radio" tabindex="${state.selectedScheme === 'mldsa' ? '0' : '-1'}" data-scheme="mldsa" aria-checked="${state.selectedScheme === 'mldsa'}" aria-describedby="scheme-detail-panel">
            <h3>ML-DSA</h3>
            <p>Standardized and integer-only, but rejection loops complicate timing.</p>
            <ul>
              <li>Module-LWE + SIS</li>
              <li>3-5 signing loops</li>
              <li>FIPS 204 today</li>
            </ul>
          </button>
          <button class="scheme-card accent-cyan ${state.selectedScheme === 'hawk' ? 'active' : ''}" type="button" role="radio" tabindex="${state.selectedScheme === 'hawk' ? '0' : '-1'}" data-scheme="hawk" aria-checked="${state.selectedScheme === 'hawk'}" aria-describedby="scheme-detail-panel">
            <h3>HAWK</h3>
            <p>Integer-only Gaussian sampling over Z with no rejection loop.</p>
            <ul>
              <li>smLIP + omSVP</li>
              <li>Round 2 On-Ramp</li>
              <li>Potential Falcon successor</li>
            </ul>
          </button>
        </div>
        <div class="comparison-strip">
          <article>
            <span>NIST-I signatures</span>
            <strong>Falcon 666 B | ML-DSA 2,420 B | HAWK 555 B</strong>
          </article>
          <article>
            <span>Signing posture</span>
            <strong>Falcon: float lattice work | ML-DSA: rejection loop | HAWK: single integer pass</strong>
          </article>
          <article>
            <span>Constant-time posture</span>
            <strong>Falcon hard | ML-DSA mixed | HAWK designed for it</strong>
          </article>
        </div>
        ${schemeDetailMarkup()}
        <h3 class="compare-heading">Full comparison, at a glance</h3>
        ${comparisonTableMarkup()}
      </section>

      <section class="exhibit" id="exhibit-lip" aria-labelledby="exhibit-lip-title">
        <div class="section-heading">
          <span class="eyebrow">Exhibit 1.5</span>
          <h2 id="exhibit-lip-title">What module-LIP actually means</h2>
          <p>HAWK's hardness assumption is the ${termChip('module-lip', 'Lattice Isomorphism Problem')}: given two bases of the same ${termChip('lattice')}, find a short one from a long one. The two views below span <em>the same lattice</em>; only the basis differs.</p>
        </div>
        ${lipMarkup()}
      </section>

      <section class="exhibit" id="exhibit-gaussian" aria-labelledby="exhibit-two-title" aria-busy="${state.busyGaussian}">
        <div class="section-heading">
          <span class="eyebrow">Exhibit 2</span>
          <h2 id="exhibit-two-title">The Gaussian Sampling Difference</h2>
          <p>HAWK samples a ${termChip('discrete-gaussian')} over Z with fixed integer tables (a ${termChip('cdt')}). Falcon samples over a lattice with floating-point machinery and ${termChip('rejection-sampling', 'rejection sampling')}. The histogram below overlays observed counts on the closed-form theoretical PMF.</p>
        </div>
        <div class="two-column">
          <article class="flow-card accent-amber">
            <h3>Falcon path</h3>
            <pre>hash message -> target c
Babai rounding over lattice basis
floating-point FFT and Gaussian steps
constant-time audit burden stays high</pre>
          </article>
          <article class="flow-card accent-gold">
            <h3>HAWK path</h3>
            <pre>hash salt || message -> h in Z^(2n)
table lookup in two fixed CDTs
integer polynomial arithmetic only
no transcendental functions anywhere</pre>
          </article>
        </div>
        <div class="panel-actions">
          <button class="primary-button" type="button" data-action="sample-gaussian" ${state.busyGaussian ? 'disabled' : ''} aria-busy="${state.busyGaussian}">${state.busyGaussian ? 'Sampling...' : 'Sample both distributions (4,096 draws each)'}</button>
          <p class="mini-note">Target sigma in this educational build: ${EXPECTED_SIGMA}, matching the fixed-table story in HAWK v1.1.</p>
        </div>
        ${gaussianMarkup()}

        <div class="cdt-section">
          <h3>Inside one CDT sample</h3>
          <p class="mini-note">Aggregate stats are useful but the algorithm is best understood at the level of one draw. Walk through it.</p>
          ${cdtWalkMarkup()}
          ${cdtAggregateMarkup()}
        </div>
      </section>

      <section class="exhibit" id="exhibit-signing" aria-labelledby="exhibit-three-title" aria-busy="${state.busySigning}">
        <div class="section-heading">
          <span class="eyebrow">Exhibit 3</span>
          <h2 id="exhibit-three-title">HAWK Signing In Action</h2>
          <p>This educational implementation keeps the public-key consistency check exact while modeling the hidden Gaussian perturbation internally.</p>
        </div>

        <div class="param-toggle" role="radiogroup" aria-label="HAWK parameter set">
          <button type="button" role="radio" aria-checked="${state.paramSet === '512'}" data-param="512" class="${state.paramSet === '512' ? 'active' : ''}">HAWK-512 (NIST-I)</button>
          <button type="button" role="radio" aria-checked="${state.paramSet === '1024'}" data-param="1024" class="${state.paramSet === '1024' ? 'active' : ''}">HAWK-1024 (NIST-V)</button>
        </div>

        <div class="sign-form">
          <label for="message-input">Message</label>
          <textarea id="message-input" data-role="message-input" rows="3" aria-describedby="message-help">${escapeHtml(state.message)}</textarea>
          <div class="panel-actions">
            <button class="primary-button" type="button" data-action="run-signing" ${state.busySigning ? 'disabled' : ''} aria-busy="${state.busySigning}">${state.busySigning ? 'Signing...' : `Generate HAWK-${state.paramSet} keypair and sign`}</button>
            <span class="mini-note" id="message-help">Restart odds: about 1 in 200,000 for HAWK-512 and 1 in 400,000 for HAWK-1024. Real keygen retries until the NTRU solve succeeds.</span>
          </div>
        </div>
        ${signingMarkup()}
      </section>

      ${transparencyMarkup()}

      <section class="exhibit roadmap" id="exhibit-roadmap" aria-labelledby="exhibit-four-title">
        <div class="section-heading">
          <span class="eyebrow">Exhibit 4</span>
          <h2 id="exhibit-four-title">Standardization Roadmap</h2>
          <p>HAWK is still speculative. The point of this lab is to understand the design frontier, not to imply deployment approval.</p>
        </div>
        <div class="timeline">
          <article>
            <span>2022</span>
            <p>NIST selects ML-DSA, Falcon, ML-KEM, and SLH-DSA, then opens the additional-signatures on-ramp.</p>
          </article>
          <article>
            <span>October 2024</span>
            <p>NIST IR 8528 advances 14 schemes to Round 2. HAWK is the only lattice survivor.</p>
          </article>
          <article>
            <span>February 2025</span>
            <p>HAWK v1.1 lands with the current public specification used by this demo.</p>
          </article>
          <article>
            <span>April 2026</span>
            <p>Round 2 evaluation is still underway. Down-select and final standardization remain uncertain.</p>
          </article>
        </div>
      </section>

      <section class="exhibit deployment" id="exhibit-deploy" aria-labelledby="exhibit-five-title">
        <div class="section-heading">
          <span class="eyebrow">Exhibit 5</span>
          <h2 id="exhibit-five-title">Why This Matters For Deployment</h2>
          <p>HAWK is a roadmap item, not a production recommendation. Design for crypto agility now so you can adopt new signatures later.</p>
        </div>
        <div class="deployment-grid">
          <article class="advice-card accent-green">
            <h3>If you need PQ signatures now</h3>
            <p>Use ML-DSA-65 in hybrid mode with a classical signature for current production work.</p>
          </article>
          <article class="advice-card accent-cyan">
            <h3>If you care about constrained devices</h3>
            <p>Track HAWK closely, but do not deploy it until standardization settles and implementations mature.</p>
          </article>
          <article class="advice-card accent-purple">
            <h3>If you care about FHE or MPC</h3>
            <p>HAWK's integer-only structure is a serious research advantage, even if NIST ultimately picks something else.</p>
          </article>
        </div>
        <h3 class="cross-links-heading">Related crypto-lab notebooks</h3>
        <ul class="cross-links">
          ${crossLinks.map((link) => `<li><a href="${link.href}" rel="noopener" target="_blank"><span class="cross-name">${link.name}</span><span class="cross-blurb">${link.blurb}</span></a></li>`).join('')}
        </ul>
      </section>

      <section class="exhibit" id="glossary" aria-labelledby="exhibit-glossary-title">
        <div class="section-heading">
          <span class="eyebrow">Exhibit 6</span>
          <h2 id="exhibit-glossary-title">Glossary &amp; self-check</h2>
          <p>Every underlined term elsewhere on this page jumps here. Expand a card for the full explanation, then test yourself below.</p>
        </div>
        ${glossaryMarkup()}

        <div class="quiz-section" id="quiz">
          <h3>Four-question self-check</h3>
          <p class="mini-note">No grading server, no tracking — this runs entirely in your browser. Pick an answer to see why it is right or wrong.</p>
          ${quizMarkup()}
        </div>
      </section>
    </main>

    <footer class="site-footer" aria-label="Site footer">
      <blockquote>
        Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God.
        <footer>1 Corinthians 10:31</footer>
      </blockquote>
      <p class="footer-meta">Related demos: <a href="https://systemslibrarian.github.io/crypto-lab-falcon-seal/" rel="noopener" target="_blank">crypto-lab-falcon-seal</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-dilithium-seal/" rel="noopener" target="_blank">crypto-lab-dilithium-seal</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/" rel="noopener" target="_blank">crypto-lab-sphincs-ledger</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-multivariate/" rel="noopener" target="_blank">crypto-lab-multivariate</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-hybrid-sign/" rel="noopener" target="_blank">crypto-lab-hybrid-sign</a></p>
      <p class="footer-meta">crypto-lab-hawk &middot; Educational build &middot; HAWK v1.1 framing &middot; <a href="https://github.com/systemslibrarian/crypto-lab-hawk" rel="noopener" target="_blank">Source on GitHub</a></p>
    </footer>
  `;

  bindEvents();
  restorePendingFocus();
}

function restorePendingFocus(): void {
  if (!state.pendingFocusSelector) {
    return;
  }

  const selector = state.pendingFocusSelector;
  state.pendingFocusSelector = null;

  requestAnimationFrame(() => {
    const target = document.querySelector<HTMLElement>(selector);
    target?.focus();
  });
}

async function runGaussianDemo(): Promise<void> {
  state.busyGaussian = true;
  setStatusMessage(null);
  setLiveMessage('Sampling both the discrete and continuous Gaussian distributions.');
  setPendingFocus('[data-action="sample-gaussian"]');
  render();

  try {
    const sampleCount = 4096;
    const samples: number[] = [];
    const hawkStart = performance.now();
    for (let index = 0; index < sampleCount; index += 1) {
      samples.push(sampleDiscreteGaussian(DISCRETE_GAUSSIAN_TABLE_T1));
    }
    const hawkSampleMs = performance.now() - hawkStart;

    const falconStart = performance.now();
    for (let index = 0; index < sampleCount; index += 1) {
      sampleFalconStyleDiscreteGaussian();
    }
    const falconSampleMs = performance.now() - falconStart;

    const stats = analyzeSampleDistribution(samples);
    const histogram = Array.from(stats.histogram.entries())
      .filter(([value]) => value >= -6 && value <= 6)
      .sort((left, right) => left[0] - right[0]);
    const pmf = discreteGaussianPmf(EXPECTED_SIGMA, 6);

    state.gaussian = {
      mean: stats.mean,
      variance: stats.variance,
      minObserved: stats.minObserved,
      maxObserved: stats.maxObserved,
      hawkSampleMs,
      falconSampleMs,
      sampleCount,
      histogram,
      pmf,
    };
    setLiveMessage(`Gaussian sampling complete. HAWK took ${hawkSampleMs.toFixed(2)} ms. Falcon-style took ${falconSampleMs.toFixed(2)} ms.`);
    setPendingFocus('.histogram-figure');
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Gaussian sampling failed.';
    setStatusMessage(message);
    setPendingFocus('.status-banner');
  } finally {
    state.busyGaussian = false;
    render();
  }
}

async function runSigningDemo(): Promise<void> {
  state.busySigning = true;
  setStatusMessage(null);
  setLiveMessage(`Generating a HAWK-${state.paramSet} keypair and signing the current message.`);
  setPendingFocus('[data-action="run-signing"]');
  render();

  const attempts: Array<{ attempt: number; reason: string }> = [];

  try {
    const params = paramOptions[state.paramSet];
    const message = new TextEncoder().encode(state.message);
    const { privateKey, publicKey, generationAttempts } = await hawkKeygen(params, (attempt, reason) => {
      attempts.push({ attempt, reason });
    });
    const { signature, signingTimeMs, restartCount } = await hawkSign(message, privateKey);
    const verifyDetail = await hawkVerifyDetailed(message, signature, publicKey);
    const verified = verifyDetail.ok;
    const serializedSig = serializeSignature(signature);
    const serializedPk = serializePublicKey(publicKey);
    const benchmark = await benchmarkHAWK(state.paramSet === '1024' ? 4 : 8, params);

    state.signing = {
      generationAttempts,
      restartCount,
      signingTimeMs,
      verified,
      saltHex: formatHex(signature.salt),
      s1Preview: previewPolynomial(signature.s1),
      benchmark,
      signatureBytes: serializedSig.length,
      publicKeyBytes: serializedPk.length,
      attempts,
      paramSet: state.paramSet,
      tampered: null,
      verifyDetail,
      signature,
      publicKey,
      privateKey,
    };
    setLiveMessage(`Signing complete. Verification ${verified ? 'passed' : 'failed'}. Signature is ${serializedSig.length} bytes.`);
    setPendingFocus('.signing-log');
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Signing failed.';
    setStatusMessage(message);
    setPendingFocus('.status-banner');
  } finally {
    state.busySigning = false;
    render();
  }
}

async function runTamperDemo(): Promise<void> {
  if (!state.signing) {
    return;
  }

  state.busyTamper = true;
  setStatusMessage(null);
  setLiveMessage('Tampering with the signature and re-running verification.');
  render();

  try {
    const original = state.signing.signature;
    const coefficient = Math.floor(Math.random() * original.s1.length);
    const delta = Math.random() < 0.5 ? 1 : -1;
    const s1Copy = Int32Array.from(original.s1);
    s1Copy[coefficient] += delta;
    const tampered: HAWKSignature = {
      salt: original.salt,
      s1: s1Copy,
      n: original.n,
    };

    const message = new TextEncoder().encode(state.message);
    const verified = await hawkVerify(message, tampered, state.signing.publicKey);

    state.signing.tampered = { verified, coefficient, delta };
    setLiveMessage(`Tampered verification ${verified ? 'unexpectedly passed' : 'correctly failed'}.`);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Tamper test failed.';
    setStatusMessage(message);
  } finally {
    state.busyTamper = false;
    render();
  }
}

function bindEvents(): void {
  document.querySelectorAll<HTMLButtonElement>('[data-scheme]').forEach((button) => {
    button.addEventListener('click', () => {
      selectScheme(button.dataset.scheme as SchemeKey, '[data-scheme][aria-checked="true"]');
    });

    button.addEventListener('keydown', (event) => {
      const currentScheme = button.dataset.scheme as SchemeKey;
      const currentIndex = schemeOrder.indexOf(currentScheme);

      if (currentIndex === -1) {
        return;
      }

      let nextIndex: number | null = null;

      switch (event.key) {
        case 'ArrowRight':
        case 'ArrowDown':
          nextIndex = (currentIndex + 1) % schemeOrder.length;
          break;
        case 'ArrowLeft':
        case 'ArrowUp':
          nextIndex = (currentIndex - 1 + schemeOrder.length) % schemeOrder.length;
          break;
        case 'Home':
          nextIndex = 0;
          break;
        case 'End':
          nextIndex = schemeOrder.length - 1;
          break;
        default:
          return;
      }

      event.preventDefault();
      selectScheme(schemeOrder[nextIndex], '[data-scheme][aria-checked="true"]');
    });
  });

  document.querySelectorAll<HTMLButtonElement>('[data-param]').forEach((button) => {
    button.addEventListener('click', () => {
      setParamSet(button.dataset.param as ParamKey);
    });
  });

  const themeToggle = document.querySelector<HTMLButtonElement>('[data-action="theme-toggle"]');
  themeToggle?.addEventListener('click', () => {
    setTheme(state.theme === 'dark' ? 'light' : 'dark');
    setLiveMessage(`Theme switched to ${state.theme} mode.`);
    setPendingFocus('[data-action="theme-toggle"]');
    render();
  });

  const messageInput = document.querySelector<HTMLTextAreaElement>('[data-role="message-input"]');
  messageInput?.addEventListener('input', () => {
    state.message = messageInput.value;
    localStorage.setItem('hawk-message', messageInput.value);
  });

  const gaussianButton = document.querySelector<HTMLButtonElement>('[data-action="sample-gaussian"]');
  gaussianButton?.addEventListener('click', () => {
    void runGaussianDemo();
  });

  const signingButton = document.querySelector<HTMLButtonElement>('[data-action="run-signing"]');
  signingButton?.addEventListener('click', () => {
    void runSigningDemo();
  });

  const tamperButton = document.querySelector<HTMLButtonElement>('[data-action="tamper-signature"]');
  tamperButton?.addEventListener('click', () => {
    void runTamperDemo();
  });

  const tamperReset = document.querySelector<HTMLButtonElement>('[data-action="tamper-reset"]');
  tamperReset?.addEventListener('click', () => {
    if (state.signing) {
      state.signing.tampered = null;
      render();
    }
  });

  document.querySelector<HTMLButtonElement>('[data-action="cdt-new"]')?.addEventListener('click', () => {
    state.cdt = { trace: traceDiscreteGaussian(DISCRETE_GAUSSIAN_TABLE_T1), visibleSteps: 0, revealedSign: false, counted: false };
    setLiveMessage('New CDT draw ready. Step through the seven threshold comparisons.');
    render();
  });

  document.querySelector<HTMLButtonElement>('[data-action="cdt-step"]')?.addEventListener('click', () => {
    if (!state.cdt) {
      return;
    }
    if (state.cdt.visibleSteps < state.cdt.trace.steps.length) {
      state.cdt.visibleSteps += 1;
      const step = state.cdt.trace.steps[state.cdt.visibleSteps - 1];
      setLiveMessage(`Threshold ${step.thresholdIndex}: word ${step.isLess ? 'is less than' : 'is at least'} T[${step.thresholdIndex}], magnitude ${step.magnitudeAfter}.`);
      render();
    }
  });

  document.querySelector<HTMLButtonElement>('[data-action="cdt-fast"]')?.addEventListener('click', () => {
    if (!state.cdt) {
      state.cdt = { trace: traceDiscreteGaussian(DISCRETE_GAUSSIAN_TABLE_T1), visibleSteps: 0, revealedSign: false, counted: false };
    }
    state.cdt.visibleSteps = state.cdt.trace.steps.length;
    state.cdt.revealedSign = true;
    recordCdtSample();
    setLiveMessage(`Walk complete. Sample value ${state.cdt.trace.sample}.`);
    render();
  });

  document.querySelector<HTMLButtonElement>('[data-action="cdt-reveal-sign"]')?.addEventListener('click', () => {
    if (!state.cdt) {
      return;
    }
    state.cdt.revealedSign = true;
    recordCdtSample();
    setLiveMessage(`Sign bit revealed. Sample value ${state.cdt.trace.sample}.`);
    render();
  });

  document.querySelectorAll<HTMLButtonElement>('[data-lip]').forEach((button) => {
    button.addEventListener('click', () => {
      const view = button.dataset.lip as 'short' | 'bad';
      state.lip.view = view;
      setLiveMessage(view === 'short' ? 'Short basis view: HAWK signs with this.' : 'Bad basis view: this is the public information.');
      render();
    });
  });

  document.querySelector<HTMLButtonElement>('[data-action="download-sig"]')?.addEventListener('click', () => {
    if (!state.signing) {
      return;
    }
    const data = serializeSignature(state.signing.signature);
    downloadBlob(`hawk-${state.signing.paramSet}-signature.bin`, data);
  });

  document.querySelector<HTMLButtonElement>('[data-action="download-pk"]')?.addEventListener('click', () => {
    if (!state.signing) {
      return;
    }
    const data = serializePublicKey(state.signing.publicKey);
    downloadBlob(`hawk-${state.signing.paramSet}-publickey.bin`, data);
  });

  document.querySelectorAll<HTMLButtonElement>('[data-glossary]').forEach((button) => {
    button.addEventListener('click', () => {
      const slug = button.dataset.glossary ?? null;
      state.activeGlossary = state.activeGlossary === slug ? null : slug;
      const entry = slug ? glossaryBySlug.get(slug) : undefined;
      if (entry && state.activeGlossary === slug) {
        setLiveMessage(`${entry.term}: ${entry.short}`);
      }
      setPendingFocus(`[data-glossary="${slug}"]`);
      render();
    });
  });

  document.querySelectorAll<HTMLButtonElement>('[data-term]').forEach((button) => {
    button.addEventListener('click', () => {
      const slug = button.dataset.term ?? null;
      if (!slug) {
        return;
      }
      state.activeGlossary = slug;
      const entry = glossaryBySlug.get(slug);
      setLiveMessage(entry ? `Jumped to glossary: ${entry.term}.` : 'Jumped to glossary.');
      render();
      requestAnimationFrame(() => {
        const target = document.querySelector<HTMLElement>(`#glossary-${slug}`);
        target?.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'center' });
        document.querySelector<HTMLButtonElement>(`[data-glossary="${slug}"]`)?.focus();
      });
    });
  });

  document.querySelectorAll<HTMLButtonElement>('[data-quiz]').forEach((button) => {
    button.addEventListener('click', () => {
      const id = button.dataset.quiz;
      const option = Number(button.dataset.quizOption);
      if (!id || Number.isNaN(option) || state.quiz.answers[id] !== undefined) {
        return;
      }
      state.quiz.answers[id] = option;
      const question = quizQuestions.find((entry) => entry.id === id);
      const correct = question?.correct === option;
      if (Object.keys(state.quiz.answers).length === quizQuestions.length) {
        state.quiz.score = quizQuestions.reduce(
          (sum, entry) => sum + (state.quiz.answers[entry.id] === entry.correct ? 1 : 0),
          0,
        );
      }
      setLiveMessage(`${correct ? 'Correct.' : 'Not quite.'} ${question?.explain ?? ''}`);
      setPendingFocus(`[data-quiz="${id}"][data-quiz-option="${option}"]`);
      render();
    });
  });

  document.querySelector<HTMLButtonElement>('[data-action="quiz-reset"]')?.addEventListener('click', () => {
    state.quiz = { answers: {}, score: null };
    setLiveMessage('Quiz reset.');
    render();
  });

  document.querySelectorAll<HTMLButtonElement>('[data-copy-text]').forEach((button) => {
    button.addEventListener('click', () => {
      const text = button.dataset.copyText ?? '';
      const key = button.dataset.copyKey ?? null;
      void copyToClipboard(text, key);
    });
  });
}

function recordCdtSample(): void {
  if (!state.cdt || state.cdt.counted) {
    return;
  }
  state.cdt.counted = true;
  state.cdtSamples.push(state.cdt.trace.sample);
}

function prefersReducedMotion(): boolean {
  return globalThis.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
}

async function copyToClipboard(text: string, key: string | null): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    state.copied = key;
    setLiveMessage('Copied to clipboard.');
    render();
    if (key) {
      globalThis.setTimeout(() => {
        if (state.copied === key) {
          state.copied = null;
          render();
        }
      }, 1600);
    }
  } catch {
    setLiveMessage('Clipboard copy was blocked by the browser.');
  }
}

/**
 * Run the core HAWK round-trip live in the visitor's browser so the honesty
 * claims on this page are machine-checked, not just asserted: generate a
 * keypair, sign, verify (must pass), then flip one coefficient and verify
 * again (must fail). The badge in the hero reflects the outcome.
 */
async function runSelfTest(): Promise<void> {
  state.selfTest = 'running';
  paintSelfTestBadge();

  try {
    const message = new TextEncoder().encode('crypto-lab-hawk self-test');
    const { privateKey, publicKey } = await hawkKeygen(HAWK_512_PARAMS);
    const { signature } = await hawkSign(message, privateKey);

    const genuine = await hawkVerify(message, signature, publicKey);

    const tampered: HAWKSignature = {
      salt: signature.salt,
      s1: Int32Array.from(signature.s1),
      n: signature.n,
    };
    tampered.s1[0] += 1;
    const tamperRejected = !(await hawkVerify(message, tampered, publicKey));

    const passed = genuine && tamperRejected;
    state.selfTest = passed ? 'pass' : 'fail';
    if (!passed) {
      console.error('HAWK self-test failed', { genuine, tamperRejected });
    }
  } catch (error) {
    state.selfTest = 'fail';
    console.error('HAWK self-test threw', error);
  } finally {
    paintSelfTestBadge();
  }
}

function downloadBlob(filename: string, data: Uint8Array): void {
  const blob = new Blob([data as BlobPart], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

render();
void runSelfTest();
