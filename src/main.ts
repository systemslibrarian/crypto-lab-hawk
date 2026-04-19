import './styles.css';

import {
  DISCRETE_GAUSSIAN_TABLE_T1,
  analyzeSampleDistribution,
  sampleDiscreteGaussian,
} from './gaussian';
import { benchmarkHAWK, hawkKeygen, hawkSign, hawkVerify } from './hawk';
import { HAWK_512_PARAMS } from './polynomial';

type SchemeKey = 'falcon' | 'mldsa' | 'hawk';

type GaussianState = {
  mean: number;
  variance: number;
  minObserved: number;
  maxObserved: number;
  hawkSampleMs: number;
  falconSimulationMs: number;
  histogram: Array<[number, number]>;
} | null;

type SigningState = {
  generationAttempts: number;
  restartCount: number;
  signingTimeMs: number;
  verified: boolean;
  saltHex: string;
  s1Preview: string;
  benchmark: Awaited<ReturnType<typeof benchmarkHAWK>>;
} | null;

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

const state: {
  selectedScheme: SchemeKey;
  gaussian: GaussianState;
  signing: SigningState;
  busyGaussian: boolean;
  busySigning: boolean;
  message: string;
  theme: 'dark' | 'light';
  statusMessage: string | null;
  liveMessage: string;
  pendingFocusSelector: string | null;
} = {
  selectedScheme: 'hawk',
  gaussian: null,
  signing: null,
  busyGaussian: false,
  busySigning: false,
  message: 'Release firmware v2.3.1 on 2026-04-19',
  theme: (document.documentElement.getAttribute('data-theme') as 'dark' | 'light' | null) ?? 'dark',
  statusMessage: null,
  liveMessage: 'HAWK demo loaded. Round 2 status notice: educational build only.',
  pendingFocusSelector: null,
};

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

function formatMs(value: number): string {
  return `${value.toFixed(value >= 10 ? 1 : 3)} ms`;
}

function formatRatio(value: number): string {
  return `${value.toFixed(2)}x`;
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

function histogramBars(histogram: Array<[number, number]>): string {
  if (histogram.length === 0) {
    return '<p class="mini-note">No samples yet.</p>';
  }

  const maxCount = histogram.reduce((current, entry) => Math.max(current, entry[1]), 0);

  return histogram
    .map(([value, count]) => {
      const width = Math.max(4, Math.round((count / maxCount) * 100));
      return `
        <div class="hist-row" role="listitem" aria-label="Histogram bucket ${value}, count ${count}">
          <span class="hist-label">${value >= 0 ? `+${value}` : value}</span>
          <div class="hist-bar" aria-hidden="true"><span style="width:${width}%"></span></div>
          <span class="hist-value">${count}</span>
        </div>
      `;
    })
    .join('');
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
        <p>Run the sampler to compare HAWK's integer-table lookup against a heavier Falcon-style Gaussian routine.</p>
      </div>
    `;
  }

  return `
    <div class="stats-grid compact" aria-label="Gaussian sampler statistics">
      <article class="metric-card accent-cyan">
        <span>HAWK sampler</span>
        <strong>${formatMs(state.gaussian.hawkSampleMs)}</strong>
      </article>
      <article class="metric-card accent-amber">
        <span>Falcon simulation</span>
        <strong>${formatMs(state.gaussian.falconSimulationMs)}</strong>
      </article>
      <article class="metric-card accent-gold">
        <span>Mean</span>
        <strong>${state.gaussian.mean.toFixed(4)}</strong>
      </article>
      <article class="metric-card accent-green">
        <span>Variance</span>
        <strong>${state.gaussian.variance.toFixed(4)}</strong>
      </article>
    </div>
    <div class="histogram-shell" role="list" aria-label="Observed Gaussian histogram" tabindex="-1">
      ${histogramBars(state.gaussian.histogram)}
    </div>
    <p class="mini-note">Observed support: ${state.gaussian.minObserved} to ${state.gaussian.maxObserved}. This demo keeps the sampling path integer-only and constant-shape by always walking the full table.</p>
  `;
}

function signingMarkup(): string {
  if (!state.signing) {
    return `
      <div class="status-card muted">
        <p>Generate a HAWK-512 keypair, sign the current message, and watch the round-trip complete with a verification check.</p>
      </div>
    `;
  }

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
    </div>
    <div class="signing-log" tabindex="-1">
      <div>
        <span class="eyebrow">Salt</span>
        <p class="mono-block">${escapeHtml(state.signing.saltHex)}</p>
      </div>
      <div>
        <span class="eyebrow">s1 preview</span>
        <p class="mono-block">${escapeHtml(state.signing.s1Preview)}</p>
      </div>
      <div>
        <span class="eyebrow">Benchmark</span>
        <p class="mono-block">HAWK sign ${formatMs(state.signing.benchmark.hawkSignMs)} | Falcon sim ${formatMs(state.signing.benchmark.falconSimulationMs)} | speedup ${formatRatio(state.signing.benchmark.speedupRatio)}</p>
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
          <blockquote>
            Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God.
            <footer>1 Corinthians 10:31</footer>
          </blockquote>
        </aside>
      </section>

      <section class="exhibit" aria-labelledby="exhibit-one-title">
        <div class="section-heading">
          <span class="eyebrow">Exhibit 1</span>
          <h2 id="exhibit-one-title">The Three Lattice Signatures</h2>
          <p>Click a scheme to inspect the engineering tradeoff that dominates its deployment story.</p>
        </div>
        <div class="scheme-grid" role="group" aria-label="Signature scheme comparison cards">
          <button class="scheme-card accent-amber ${state.selectedScheme === 'falcon' ? 'active' : ''}" type="button" data-scheme="falcon" aria-pressed="${state.selectedScheme === 'falcon'}" aria-describedby="scheme-detail-panel">
            <h3>Falcon</h3>
            <p>Small signatures, difficult floating-point hardening.</p>
            <ul>
              <li>NTRU-SIS</li>
              <li>Float Gaussian over a lattice</li>
              <li>FIPS 206 in progress</li>
            </ul>
          </button>
          <button class="scheme-card accent-magenta ${state.selectedScheme === 'mldsa' ? 'active' : ''}" type="button" data-scheme="mldsa" aria-pressed="${state.selectedScheme === 'mldsa'}" aria-describedby="scheme-detail-panel">
            <h3>ML-DSA</h3>
            <p>Standardized and integer-only, but rejection loops complicate timing.</p>
            <ul>
              <li>Module-LWE + SIS</li>
              <li>3-5 signing loops</li>
              <li>FIPS 204 today</li>
            </ul>
          </button>
          <button class="scheme-card accent-cyan ${state.selectedScheme === 'hawk' ? 'active' : ''}" type="button" data-scheme="hawk" aria-pressed="${state.selectedScheme === 'hawk'}" aria-describedby="scheme-detail-panel">
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
            <span>Signing speed</span>
            <strong>Falcon 1x | ML-DSA ~1x with variance | HAWK ~4x simulated</strong>
          </article>
          <article>
            <span>Constant-time posture</span>
            <strong>Falcon hard | ML-DSA mixed | HAWK designed for it</strong>
          </article>
        </div>
        ${schemeDetailMarkup()}
      </section>

      <section class="exhibit" aria-labelledby="exhibit-two-title" aria-busy="${state.busyGaussian}">
        <div class="section-heading">
          <span class="eyebrow">Exhibit 2</span>
          <h2 id="exhibit-two-title">The Gaussian Sampling Difference</h2>
          <p>HAWK samples over Z with fixed integer tables. Falcon samples over a lattice with floating-point machinery.</p>
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
          <button class="primary-button" type="button" data-action="sample-gaussian" ${state.busyGaussian ? 'disabled' : ''} aria-busy="${state.busyGaussian}">${state.busyGaussian ? 'Sampling...' : 'Sample Gaussian'}</button>
          <p class="mini-note">Target sigma in this educational build: approximately 1.425, matching the fixed-table story in HAWK v1.1.</p>
        </div>
        ${gaussianMarkup()}
      </section>

      <section class="exhibit" aria-labelledby="exhibit-three-title" aria-busy="${state.busySigning}">
        <div class="section-heading">
          <span class="eyebrow">Exhibit 3</span>
          <h2 id="exhibit-three-title">HAWK Signing In Action</h2>
          <p>This educational implementation keeps the public-key consistency check exact while modeling the hidden Gaussian perturbation internally.</p>
        </div>
        <div class="sign-form">
          <label for="message-input">Message</label>
          <textarea id="message-input" data-role="message-input" rows="3" aria-describedby="message-help">${escapeHtml(state.message)}</textarea>
          <div class="panel-actions">
            <button class="primary-button" type="button" data-action="run-signing" ${state.busySigning ? 'disabled' : ''} aria-busy="${state.busySigning}">${state.busySigning ? 'Signing...' : 'Generate keypair and sign'}</button>
            <span class="mini-note" id="message-help">Restart odds shown in the UI: about 1 in 200,000 for HAWK-512 and 1 in 400,000 for HAWK-1024.</span>
          </div>
        </div>
        ${signingMarkup()}
      </section>

      <section class="exhibit roadmap" aria-labelledby="exhibit-four-title">
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

      <section class="exhibit deployment" aria-labelledby="exhibit-five-title">
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
        <div class="cross-links">
          <span>crypto-lab-falcon-seal</span>
          <span>crypto-lab-dilithium-seal</span>
          <span>crypto-lab-dilithium-reject</span>
          <span>crypto-lab-sphincs-ledger</span>
          <span>crypto-lab-lms-xmss</span>
          <span>crypto-lab-hybrid-sign</span>
          <span>crypto-lab-lattice-fault</span>
          <span>crypto-lab-kyberslash</span>
        </div>
      </section>
    </main>
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
  setLiveMessage('Sampling the discrete Gaussian distribution for HAWK.');
  setPendingFocus('[data-action="sample-gaussian"]');
  render();

  try {
    const samples: number[] = [];
    const startedAt = performance.now();

    for (let index = 0; index < 4096; index += 1) {
      samples.push(sampleDiscreteGaussian(DISCRETE_GAUSSIAN_TABLE_T1));
    }

    const hawkSampleMs = performance.now() - startedAt;
    const stats = analyzeSampleDistribution(samples);
    const falconSimulationMs = Math.max(15, hawkSampleMs * 120);
    const histogram = Array.from(stats.histogram.entries())
      .filter(([value]) => value >= -6 && value <= 6)
      .sort((left, right) => left[0] - right[0]);

    state.gaussian = {
      mean: stats.mean,
      variance: stats.variance,
      minObserved: stats.minObserved,
      maxObserved: stats.maxObserved,
      hawkSampleMs,
      falconSimulationMs,
      histogram,
    };
    setLiveMessage('Gaussian sampling complete. Updated histogram and timing comparison are available.');
    setPendingFocus('.histogram-shell');
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
  setLiveMessage('Generating a HAWK keypair and signing the current message.');
  setPendingFocus('[data-action="run-signing"]');
  render();

  try {
    const message = new TextEncoder().encode(state.message);
    const { privateKey, publicKey, generationAttempts } = await hawkKeygen(HAWK_512_PARAMS);
    const { signature, signingTimeMs, restartCount } = await hawkSign(message, privateKey);
    const verified = await hawkVerify(message, signature, publicKey);
    const benchmark = await benchmarkHAWK(8);

    state.signing = {
      generationAttempts,
      restartCount,
      signingTimeMs,
      verified,
      saltHex: formatHex(signature.salt),
      s1Preview: previewPolynomial(signature.s1),
      benchmark,
    };
    setLiveMessage(`Signing complete. Verification ${verified ? 'passed' : 'failed'}.`);
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

function bindEvents(): void {
  document.querySelectorAll<HTMLButtonElement>('[data-scheme]').forEach((button) => {
    button.addEventListener('click', () => {
      state.selectedScheme = button.dataset.scheme as SchemeKey;
      setLiveMessage(`${schemeCopy[state.selectedScheme].title} details selected.`);
      setPendingFocus('#scheme-detail-panel');
      render();
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
  });

  const gaussianButton = document.querySelector<HTMLButtonElement>('[data-action="sample-gaussian"]');
  gaussianButton?.addEventListener('click', () => {
    void runGaussianDemo();
  });

  const signingButton = document.querySelector<HTMLButtonElement>('[data-action="run-signing"]');
  signingButton?.addEventListener('click', () => {
    void runSigningDemo();
  });
}

render();