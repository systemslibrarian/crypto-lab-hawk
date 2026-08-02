import { expect, test, type Page } from '@playwright/test';

/**
 * Blocking browser gate for the Exhibit 3 sampler-gap bench.
 *
 * The bench exists to turn one of the page's honesty claims — that swapping in
 * a real Gaussian coset sampler would not restore unforgeability — from an
 * assertion into a measurement. Its headline is a *negative* result, which is
 * the kind that decays quietly into a hard-coded string, so this test reads the
 * rendered table and checks that the two columns really do carry different
 * measured data and that the specific row that must NOT change did not.
 *
 * `scripts/verify-phase5.ts` pins the same properties headlessly; this pins
 * that the browser actually computes and renders them.
 */

const BENCH_TIMEOUT = 180_000;

async function runBench(page: Page): Promise<void> {
  await page.goto('.');
  await page.click('[data-action="run-signing"]');
  await page.waitForSelector('[data-action="sampler-gap"]', { timeout: 120_000 });
  await page.click('[data-action="sampler-gap"]');
  await page.waitForSelector('[data-action="sampler-gap-reset"]', { timeout: BENCH_TIMEOUT });
}

/** The (linear, gaussian) cells of the bench row whose label contains `label`. */
async function readRow(page: Page, label: string): Promise<[string, string]> {
  const row = page.locator('table.compare-table tbody tr').filter({ has: page.locator('th', { hasText: label }) });
  await expect(row).toHaveCount(1);
  const cells = row.locator('td');
  return [(await cells.nth(0).innerText()).trim(), (await cells.nth(1).innerText()).trim()];
}

function leadingNumber(text: string): number {
  const match = text.replace(/,/g, '').match(/-?\d+(\.\d+)?/);
  expect(match, `expected a number in ${JSON.stringify(text)}`).not.toBeNull();
  return Number(match?.[0]);
}

test.describe('Exhibit 3 sampler-gap bench', () => {
  test.slow();

  test('measures a real difference between the two samplers', async ({ page }) => {
    await runBench(page);

    const [linearRepro, gaussianRepro] = await readRow(page, 'Two signings');
    expect(leadingNumber(linearRepro)).toBe(0);
    // Failure path for the linear column's determinism claim: a real sampler
    // must move a substantial fraction of the coefficients.
    expect(leadingNumber(gaussianRepro)).toBeGreaterThan(256);

    const [linearZ, gaussianZ] = await readRow(page, 'over Z');
    expect(leadingNumber(linearZ)).toBe(1024);
    expect(leadingNumber(gaussianZ)).toBeLessThan(1024);
    expect(leadingNumber(gaussianZ)).toBeGreaterThan(0);

    const [linearShape, gaussianShape] = await readRow(page, 'Distinct coefficient');
    expect(leadingNumber(linearShape)).toBe(2);
    expect(leadingNumber(gaussianShape)).toBeGreaterThan(2);

    const [linearNorm, gaussianNorm] = await readRow(page, 'Mean ');
    expect(leadingNumber(gaussianNorm)).toBeGreaterThan(leadingNumber(linearNorm));

    // The two columns must not be the same numbers rendered twice.
    expect(gaussianRepro).not.toBe(linearRepro);
    expect(gaussianZ).not.toBe(linearZ);
  });

  test('the property the Gaussian does not change is the one that keeps it forgeable', async ({ page }) => {
    await runBench(page);

    // The row that must stay identical: additivity mod 2 survives the offset,
    // because 2z leaves the parity coset alone.
    const [linearMod2, gaussianMod2] = await readRow(page, '…the same comparison mod 2');
    expect(leadingNumber(linearMod2)).toBe(1024);
    expect(leadingNumber(gaussianMod2)).toBe(1024);

    // And therefore both samplers are still forged from the public key alone,
    // by the unmodified verifier.
    const [linearForgery, gaussianForgery] = await readRow(page, 'Public-key-only forgery');
    expect(linearForgery).toBe('ACCEPTED');
    expect(gaussianForgery).toBe('ACCEPTED');

    const verdict = page.locator('.forge-result:has([data-action="sampler-gap-reset"]) p').first();
    await expect(verdict).toContainText(/moved \d of the \d structural properties/);
    await expect(verdict).toContainText('left forgeability exactly where it was');

    // The forged norms are printed, not implied.
    const forgedLine = page.locator('.forge-result:has([data-action="sampler-gap-reset"]) .mono-block');
    await expect(forgedLine).toContainText('coset match yes / yes');
  });

  test('the bench result can be cleared and re-run', async ({ page }) => {
    await runBench(page);
    await page.click('[data-action="sampler-gap-reset"]');
    await expect(page.locator('[data-action="sampler-gap-reset"]')).toHaveCount(0);
    await expect(page.locator('[data-action="sampler-gap"]')).toBeVisible();
    await expect(page.locator('table.compare-table tbody tr:has-text("Two signings")')).toHaveCount(0);
  });
});
