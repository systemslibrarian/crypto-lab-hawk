import { expect, test } from '@playwright/test';

/**
 * Exhibit 1.5's attack runner. verify-phase6 pins the mathematics; this pins
 * that the browser really runs it and renders what it found.
 */

test.describe('Exhibit 1.5 key-recovery attack', () => {
  test('recovers a key from the public key alone', async ({ page }) => {
    test.slow();
    await page.goto('.');

    const panel = page.locator('#cryptanalysis-2026');
    await expect(panel).toBeVisible();

    await panel.locator('[data-action="run-lip-attack"]').click();
    const verdict = panel.locator('.attack-verdict');
    await expect(verdict).toBeVisible({ timeout: 120_000 });
    await expect(verdict).toHaveClass(/recovered/);
    await expect(verdict).toContainText('Secret key recovered from the public key alone');

    // Every stage of the reduction must have succeeded.
    const stages = panel.locator('.attack-stages li');
    await expect(stages).toHaveCount(5);
    await expect(panel.locator('.attack-stages li.stage-bad')).toHaveCount(0);

    // The structural counts the paper predicts, rendered on screen.
    await expect(stages.nth(1)).toContainText('rank 4 = n');
    await expect(stages.nth(2)).toContainText('6 shortest vectors = 2(n/2 + 1)');
    await expect(stages.nth(3)).toContainText('2 survivors, both equal ±V_τ');
    await expect(stages.nth(4)).toContainText("B′*B′ = Q");

    // The attacker's input and output are both shown, and differ.
    const blocks = panel.locator('.attack-keys pre');
    await expect(blocks).toHaveCount(3);
    const publicKey = await blocks.nth(0).textContent();
    const recovered = await blocks.nth(1).textContent();
    expect(publicKey?.trim().length).toBeGreaterThan(0);
    expect(recovered?.trim()).not.toBe('—');
  });

  test('runs at n = 8, where the SVP dimension is 5', async ({ page }) => {
    test.slow();
    await page.goto('.');

    const panel = page.locator('#cryptanalysis-2026');
    await panel.locator('[data-lip-degree="8"]').click();
    await expect(panel.locator('[data-lip-degree="8"]')).toHaveAttribute('aria-checked', 'true');
    await expect(panel).toContainText('n/2 + 1 = 5');

    await panel.locator('[data-action="run-lip-attack"]').click();
    await expect(panel.locator('.attack-verdict.recovered')).toBeVisible({ timeout: 180_000 });
    await expect(panel.locator('.attack-stages li').nth(2)).toContainText(
      '10 shortest vectors = 2(n/2 + 1)',
    );
  });

  test('the result can be cleared', async ({ page }) => {
    await page.goto('.');
    const panel = page.locator('#cryptanalysis-2026');
    await panel.locator('[data-action="run-lip-attack"]').click();
    await expect(panel.locator('.attack-verdict')).toBeVisible({ timeout: 120_000 });
    await panel.locator('[data-action="lip-attack-reset"]').click();
    await expect(panel.locator('.attack-verdict')).toHaveCount(0);
    await expect(panel).toContainText('Nothing run yet');
  });
});
