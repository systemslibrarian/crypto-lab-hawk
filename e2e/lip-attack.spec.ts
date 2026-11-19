import { readFileSync } from 'node:fs';
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

test.describe('what the page says module-LIP is', () => {
  /* The glossary entry was corrected to the real definition, but two shorter
   * strings beside it kept the old one and ended up contradicting it: the
   * term-chip tooltip read "recover a short basis from a long one", and the
   * caption under the bad-basis view said "Recovering the short basis from this
   * bad one is the module-LIP assumption HAWK rests on."
   *
   * HAWK v1.1 §6.6, Definition 7 (Worst case smLIP): "Given a CM-field K, its
   * ring of integers R and Q ∈ H_r^{>0}(K), an instance of the worst case
   * search module lattice isomorphism problem wc−smLIP^Q_{K,r} is given by any
   * Q′ ∈ [Q]. A solution is U ∈ GL_r(R) such that Q′ = U⋆QU." HAWK's class is
   * [I₂(K)], and its public key is the Gram matrix Q = B⋆B of the secret basis.
   * Changing between two bases of ONE lattice is a linear-algebra calculation
   * and is not the assumption, which is what the glossary already says. */

  test('the term-chip tooltip gives the definition, not a change of basis', async ({ page }) => {
    await page.goto('.');
    const chip = page.locator('[data-term="module-lip"]').first();
    await expect(chip).toHaveCount(1);
    const tip = (await chip.getAttribute('title')) ?? '';
    expect(tip).toContain('find the unimodular matrix that relates them');
    expect(tip).not.toContain('recover a short basis from a long one');
  });

  test('the bad-basis caption separates the picture from the assumption', async ({ page }) => {
    await page.goto('.');
    await page.locator('[data-lip="bad"]').click();
    await expect(page.locator('[data-lip="bad"]')).toHaveAttribute('aria-checked', 'true');

    const caption = (await page.locator('.lip-shell .mini-note').first().innerText()).replace(
      /\s+/g,
      ' ',
    );
    expect(caption).not.toContain('Recovering the short basis from this bad one is the module-LIP');
    expect(caption).toContain('Going between two bases of one lattice is only linear algebra');
    expect(caption).toContain('module-LIP asks for the unimodular U with Q = U*U');
    expect(caption).toContain('HAWK v1.1 §6.6, Definition 7');

    // The short-basis view keeps its own caption, which was never wrong.
    await page.locator('[data-lip="short"]').click();
    await expect(page.locator('.lip-shell .mini-note').first()).toContainText(
      'This is what HAWK signs with',
    );
  });

  /* The README's exhibit list kept the sentence the page dropped: "What
   * module-LIP means, shown as a short basis versus a bad basis over the same
   * lattice". The same-lattice picture is basis reduction, not module-LIP, and
   * the README has to draw the line where the page's caption draws it. */
  test('the README draws the same line as the caption it describes', async ({ page }) => {
    const readme = readFileSync('README.md', 'utf8').replace(/\\\*/g, '*').replace(/\s+/g, ' ');
    expect(readme).not.toMatch(/What module-LIP means, shown as a short basis versus a bad basis/);
    expect(readme).not.toMatch(/module-LIP[^.—]{0,40}over the \*same\* lattice/);
    expect(readme).toContain('why module-LIP is a different problem: an isometry between two forms');
    expect(readme).toContain('not a change of basis within one lattice, which is only linear algebra');

    // The definition the README quotes is the one the page's caption prints.
    await page.goto('.');
    await page.locator('[data-lip="bad"]').click();
    const caption = (await page.locator('.lip-shell .mini-note').first().innerText()).replace(/\s+/g, ' ');
    for (const phrase of ['unimodular U with Q = U*U', 'HAWK v1.1 §6.6, Definition 7']) {
      expect(caption).toContain(phrase);
      expect(readme).toContain(phrase);
    }
  });
});
