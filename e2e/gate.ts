import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The version of this gate
 *     this file replaces did drive the two expensive exhibits — which was more
 *     than most gates in this fleet did — but then called a `revealEverything`
 *     helper that force-opened every glossary accordion at once, wrote
 *     `aria-expanded="true"` onto their buttons, set `display: block` on their
 *     bodies, and stripped `[hidden]` off every element on the page. Forcing the
 *     accessibility tree to agree with the fabricated visual state is the part
 *     that hurts: axe was handed a consistent-looking page that no visitor can
 *     produce, so any mismatch between the accordion's real markup and its real
 *     visible state was papered over exactly where the gate was looking for it.
 *     Every accordion here opens on a click, and this gate clicks them.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. axe over an empty container passes having checked
 *     nothing. This lab's result surfaces — the signing log, the tamper and
 *     forgery verdicts, the sampler-gap table, the LIP attack stages, the CDT
 *     walkthrough, the quiz feedback — are all downstream of a click.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 *
 * The previous gate also scanned exactly one accumulated state per theme: it
 * ran every exhibit and then scanned once at the end. Intermediate states, and
 * every `*-reset` state, were never looked at.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 *
 * The 20s ceiling is deliberately generous rather than tight: on a loaded
 * machine the raf cadence stretches, and the correct response to that is a
 * longer wait, never a narrower scan.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This page
 * fades in several result blocks, which is exactly the shape of thing that can
 * strand at zero.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. Applying it after `goto` is too late — the
 * page reads the media query at module-evaluation time — and without the
 * assertion a gate can believe it is testing a reduced-motion rendering while
 * the page happily animates.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // The lab is injected by JS. Assert the structure every scan relies on is
  // really there, so no scan can pass over a shell.
  await expect(page.locator('#app section.exhibit')).toHaveCount(8);
  await expect(page.locator('[data-action="run-signing"]')).toBeVisible();
  await expect(page.locator('.glossary-entry')).not.toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it prints polynomial coefficient rows, hex key blocks,
 * signature blobs and the sampler-gap table, all monospace and all wide.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;
    const widest = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right)[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * axe's own `scrollable-region-focusable` covers this, but only where the
 * content actually overflows — several regions here only overflow at phone
 * width, so a desktop-only gate never saw them.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less div hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node,
 *    measured against the surface the text is genuinely painted on.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  expect(violations, `axe violations in state: ${label}`).toEqual([]);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  expect(unexplainedIncomplete, `axe incomplete results in state: ${label}`).toEqual([]);

  // Deduplicated: a single stylesheet mistake can repeat across many identical
  // cells, and an assertion diff that long is unreadable.
  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  expect(contrast, `measured contrast failures in state: ${label}`).toEqual([]);

  await expectScrollersReachable(page, label);
  await expectNoHorizontalOverflow(page, label);
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Ordered so the expensive real cryptography runs once: signing produces the
 * key material the tamper and forgery paths then operate on.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  await scan(page, `${theme} / first paint`);

  // Exhibit 2 — the discrete-Gaussian sampler and the CDT walkthrough.
  await page.click('[data-action="sample-gaussian"]');
  await settle(page);
  await scan(page, `${theme} / gaussian samples`);

  await page.click('[data-action="cdt-new"]');
  await page.click('[data-action="cdt-step"]');
  await expect(page.locator('.cdt-step').first()).toBeVisible();
  await scan(page, `${theme} / CDT one step`);

  // Step to the end rather than using "Run to end": `cdt-fast` sets
  // `revealedSign` itself, so it skips the reveal-sign button entirely. Walking
  // the thresholds one at a time is both the taught path and the only way the
  // per-step accept/reject rows and the enabled reveal button ever render.
  const step = page.locator('[data-action="cdt-step"]');
  while (await step.isEnabled()) {
    await step.click();
  }
  await expect(page.locator('[data-action="cdt-reveal-sign"]')).toBeEnabled();
  await page.click('[data-action="cdt-reveal-sign"]');
  await expect(page.locator('.cdt-final')).toBeVisible();
  await scan(page, `${theme} / CDT complete`);

  // Exhibit 1.5 — the lattice-isomorphism attack runner.
  await page.click('[data-action="run-lip-attack"]');
  await expect(page.locator('#cryptanalysis-2026 .attack-verdict')).toBeVisible({
    timeout: 120_000,
  });
  await scan(page, `${theme} / LIP attack verdict`);

  // Exhibit 3 — real signing, then the two failure paths off it.
  await page.click('[data-action="run-signing"]');
  await expect(page.locator('[data-action="sampler-gap"]')).toBeVisible({ timeout: 120_000 });
  await scan(page, `${theme} / signing log`);

  await page.click('[data-action="tamper-signature"]');
  await expect(page.locator('[data-action="tamper-reset"]')).toBeVisible({ timeout: 120_000 });
  await scan(page, `${theme} / tampered signature rejected`);
  await page.click('[data-action="tamper-reset"]');
  await scan(page, `${theme} / tamper reset`);

  await page.click('[data-action="forge-signature"]');
  await expect(page.locator('[data-action="forge-reset"]')).toBeVisible({ timeout: 120_000 });
  await scan(page, `${theme} / forgery attempt`);
  await page.click('[data-action="forge-reset"]');

  await page.click('[data-action="sampler-gap"]');
  await expect(page.locator('[data-action="sampler-gap-reset"]')).toBeVisible({
    timeout: 180_000,
  });
  await scan(page, `${theme} / sampler gap table`);

  // The glossary accordions, opened the way a visitor opens them. Opening all
  // of them at once is the state the replaced gate fabricated; opening one is
  // the state that exists.
  const firstTerm = page.locator('.glossary-term').first();
  await firstTerm.click();
  await expect(firstTerm).toHaveAttribute('aria-expanded', 'true');
  await scan(page, `${theme} / glossary entry open`);

  // The quiz, both verdicts: a wrong answer and a right one are separately
  // styled, and only one of them is on screen at a time.
  const q1 = page.locator('[data-quiz]').first();
  const qid = await q1.getAttribute('data-quiz');
  await q1.click();
  await expect(page.locator(`[data-quiz="${qid}"]`).first()).toBeDisabled();
  await expect(page.locator('.quiz-feedback')).toHaveCount(1);
  await scan(page, `${theme} / quiz answered`);
}
