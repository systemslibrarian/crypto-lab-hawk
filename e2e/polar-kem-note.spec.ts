import { expect, test } from '@playwright/test';

/**
 * Exhibit 1.5's "Related" note on Polar-KEM. verify-phase8 pins the 2 x 2
 * model; this pins that the browser really computes and renders it, and that
 * the note sits inside the LIP exhibit at desktop and phone width.
 *
 * The matrices are compared with each other on the page, not with strings typed
 * here: the recovered matrix must be the secret one, and the general-case
 * output must be neither.
 */

for (const width of [1280, 380]) {
  test(`Polar-KEM related note renders its computed model at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto('.');

    const note = page.locator('#exhibit-lip #related-polar-kem');
    await expect(note).toBeVisible();
    await expect(note.getByRole('heading', { level: 3 })).toContainText('Polar-KEM');

    const cell = (hook: string) => note.locator(`[data-related="${hook}"]`);
    const secret = (await cell('secret').innerText()).trim();
    const recovered = (await cell('aligned-recovered').innerText()).trim();
    const naive = (await cell('general-naive').innerText()).trim();
    const published = (await cell('aligned-public').innerText()).trim();

    // Aligned case: the one-step formula gives back the secret.
    expect(secret).toMatch(/^\[\[.+\], \[.+\]\]$/);
    expect(recovered).toBe(secret);
    await expect(cell('aligned-verdict')).toHaveText('which is O exactly');
    // What is published is not the secret itself.
    expect(published).not.toBe(secret);
    // General case: the same formula gives something else.
    expect(naive).not.toBe(secret);
    await expect(cell('general-verdict')).toHaveText('which is not orthogonal, so it is not O');

    // The note points at its sources and carries a dated status line.
    await expect(note.locator('a[href="https://ngcc.dev/reports/kem-29.html"]')).toHaveCount(1);
    await expect(note).toContainText('As of November 2026, NGCC is in its first round');
    await expect(note).toContainText('The LIP assumption was not broken');

    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(1);
  });
}
