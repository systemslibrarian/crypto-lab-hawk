/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {
  "control-boundary|a.cl-btn": { ratio: 2.45, required: 3.0, unverified: false },
  "control-boundary|button#cl-theme-toggle.cl-btn.cl-icon": { ratio: 2.45, required: 3.0, unverified: false },
  "control-boundary|button.active": { ratio: 1.37, required: 3.0, unverified: false },
  "control-boundary|button.copy-button": { ratio: 1.25, required: 3.0, unverified: false },
  "control-boundary|button.ghost-button": { ratio: 1.26, required: 3.0, unverified: false },
  "control-boundary|button.primary-button": { ratio: 1.26, required: 3.0, unverified: false },
  "control-boundary|button.quiz-option": { ratio: 1.27, required: 3.0, unverified: false },
  "control-boundary|button.scheme-card.accent-amber": { ratio: 1.0, required: 3.0, unverified: false },
  "control-boundary|button.scheme-card.accent-magenta": { ratio: 1.0, required: 3.0, unverified: false }
};
