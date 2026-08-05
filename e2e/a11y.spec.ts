import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the phase-verify checks;
 * this gates them on accessibility the same way. Scans the full page in both
 * themes, with every collapsible / class-toggled panel forced open first so
 * axe sees content that is normally revealed on interaction.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function revealEverything(page: Page): Promise<void> {
  await page.evaluate(() => {
    // Neutralize animations / transitions / opacity so nothing is mid-fade
    // or transparent when axe measures contrast.
    const style = document.createElement('style');
    style.textContent = `*,*::before,*::after{
      animation-duration:0s !important;
      animation-delay:0s !important;
      transition-duration:0s !important;
      transition-delay:0s !important;
    }
    .cdt-step.pending{opacity:1 !important;}`;
    document.head.appendChild(style);

    // Native <details> (none expected here, but harmless if added later).
    for (const details of Array.from(document.querySelectorAll('details'))) {
      (details as HTMLDetailsElement).open = true;
    }

    // Class-toggled glossary accordions: mark every entry open, reveal bodies,
    // and set aria-expanded so structure matches the visible state.
    for (const entry of Array.from(document.querySelectorAll('.glossary-entry'))) {
      entry.classList.add('open');
    }
    for (const term of Array.from(document.querySelectorAll('.glossary-term'))) {
      term.setAttribute('aria-expanded', 'true');
    }
    for (const body of Array.from(document.querySelectorAll('.glossary-body'))) {
      body.removeAttribute('hidden');
      (body as HTMLElement).style.display = 'block';
    }

    // Reveal anything still hidden via [hidden] or inline display:none.
    for (const el of Array.from(document.querySelectorAll<HTMLElement>('[hidden]'))) {
      el.removeAttribute('hidden');
    }
  });
}

/**
 * Exhibit 3's signing log, tamper result, forgery result and sampler-gap table
 * only exist after their buttons are pressed. Without driving them, the largest
 * block of injected markup on the page is never seen by axe at all.
 */
async function driveExhibitThree(page: Page): Promise<void> {
  await page.click('[data-action="run-signing"]');
  await page.waitForSelector('[data-action="sampler-gap"]', { timeout: 120_000 });
  await page.click('[data-action="tamper-signature"]');
  await page.waitForSelector('[data-action="tamper-reset"]', { timeout: 120_000 });
  await page.click('[data-action="forge-signature"]');
  await page.waitForSelector('[data-action="forge-reset"]', { timeout: 120_000 });
  await page.click('[data-action="sampler-gap"]');
  await page.waitForSelector('[data-action="sampler-gap-reset"]', { timeout: 180_000 });
}

/**
 * Exhibit 1.5's attack runner injects its stage list, verdict and key blocks
 * only after it has run. Same reasoning as driveExhibitThree.
 */
async function driveAttackRunner(page: Page): Promise<void> {
  await page.click('[data-action="run-lip-attack"]');
  await page.waitForSelector('#cryptanalysis-2026 .attack-verdict', { timeout: 120_000 });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  test.slow();
  await page.goto('.');
  await driveExhibitThree(page);
  await driveAttackRunner(page);
  await revealEverything(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  test.slow();
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await driveExhibitThree(page);
  await driveAttackRunner(page);
  await revealEverything(page);
  await scan(page);
});
