import { test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW } from './gate';

/**
 * WCAG A/AA regression gate. Deploys are already gated on the phase-verify
 * checks; this gates them on accessibility the same way.
 *
 * Every state this lab can render is scanned in both themes at desktop and
 * phone width. See `gate.ts` for why nothing is injected into the page, why
 * each scan asserts its content first, and why `violations` is not the whole
 * oracle.
 *
 * These are slow by construction: the signing exhibit runs real HAWK key
 * generation and signing, the sampler-gap table runs a large sample, and every
 * one of the thirteen states gets a full axe pass — which at 380px has far more
 * to walk, since narrow width reflows the wide monospace blocks into scrolling
 * boxes.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);

    // The third ratchet rule — a baselined finding that no longer appears must
    // be deleted, so the list can only shrink. `expectBaselineNotStale` was
    // exported from `gate.ts` and imported by nothing, so it had never run.
    //
    // Called in all four configurations, which this lab's baseline permits:
    // every one of the ten entries is produced by every configuration, checked
    // through the gate's own capture path rather than assumed. (Sibling labs do
    // not have that luxury — where a control is accent-bordered it fails in one
    // theme only, and the check has to be scoped to the drive that sees it.)
    expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expectBaselineNotStale();
  });
}
