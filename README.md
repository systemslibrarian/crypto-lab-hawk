# crypto-lab-hawk

## What It Is

Browser-based educational demo of HAWK, the post-quantum signature scheme by Léo Ducas, Eamonn W. Postlethwaite, Ludo N. Pulles, and Wessel van Woerden. HAWK is the only lattice-based scheme in Round 2 of NIST's Additional Digital Signatures process after NIST IR 8528 (October 2024). This repo focuses on the structural reasons HAWK is interesting in 2026: integer-only arithmetic, discrete Gaussian sampling over Z through fixed lookup tables, no accept/reject loop inside the sampler, and a cleaner constant-time story than Falcon.

This is a Vite + TypeScript + vanilla CSS educational lab that compares Falcon, ML-DSA, and HAWK side by side. The demo implements HAWK-512 and HAWK-1024 at educational fidelity around the HAWK v1.1 specification dated February 5, 2025. It is intentionally not a production implementation and does not claim byte-exact compatibility with the official reference code.

The emphasis is on HAWK's architectural differences from Falcon:

- No floating-point arithmetic in the core signing path
- No accept/reject loop inside the sampler, unlike ML-DSA's outer rejection loop and Falcon's internal SamplerZ rejection
- Integer-only discrete Gaussian sampling over Z with fixed tables
- A simplified public/private basis story tied to the Lattice Isomorphism Problem
- A browser-native exhibit showing why HAWK may become Falcon's conceptual successor if standardization continues successfully

The UI opens with a five-step guided learning path and then walks through six exhibits:

- The three lattice signatures at a glance, including a full side-by-side comparison matrix
- What module-LIP means, shown as a short basis versus a bad basis over the *same* lattice: both bases are unimodular recombinations (determinant 4) that render the identical dot grid, and a draggable hash target animates greedy Babai rounding as basis-step arrows from the origin, counting the steps on screen so the short-basis-is-easy / bad-basis-is-hard claim is something you discover by dragging rather than read
- The Gaussian sampling difference between Falcon and HAWK, with a step-through of a single CDT draw (pre-seeded with a worked example on load) that accumulates into a live tally, plus a synchronized bell-curve panel that marks where the random word lands on the discrete Gaussian and shades the tail regions the crossed thresholds correspond to, making "how many thresholds it falls under = magnitude" visually obvious
- A live HAWK signing walkthrough that shows the verification identity in the open: recompute the message's parity target, check the signature's lattice coset against it with the public parity basis, and check the lattice point's Euclidean length via the public Gram matrix Q = B*B, with the actual numbers
- A Round 2 standardization roadmap and deployment guidance for real 2026 systems
- A glossary of every key term plus a five-question self-check that grades entirely in the browser

A self-test runs on page load — a real keygen → sign → verify → tamper-reject round-trip, plus a public-key-only forgery that this build is expected to accept — so the honesty claims are machine-checked in both directions, not just asserted. The result shows as a badge in the header.

The verification path is a genuine, integer-only lattice round-trip, not a forced arithmetic identity. Keys are a real short basis B = [[f,F],[g,G]] sampled from the discrete Gaussian; the public key is its Gram matrix Q = B*B computed with actual polynomial multiplication and ring adjoints. A signature is a short lattice vector B·c whose coset is bound to the message, and verification uses only the public key: it checks the coset with the public parity basis (via polynomial multiplication mod 2) and measures the vector's length as c*·Q·c. Because verification depends on Q and the parity basis, a signature made with a different key is rejected and a single flipped coefficient is rejected — both are covered by the test suite (see `verify:phase4`), which also confirms a norm-only forgery that keeps the coset intact is caught by the Gram-matrix bound.

### The signing path has no trapdoor, and the demo says so

This is the one thing to know before using this repo to teach unforgeability: **it cannot.** `hawkSign` takes the private key as an argument but reads nothing from it that the public key does not already publish — the parity basis B mod 2, which keygen ships verbatim as `publicKey.basisMod2`, and the Gram matrix Q. So anyone holding only the public key can recompute identical signature coordinates and the unmodified verifier accepts them. Exhibit 3 has a **Forge with only the public key** button that does exactly this, live, and the on-load self-test asserts the forgery succeeds.

Fixing it properly is not a small edit. It would need keygen to solve the NTRU equation f·G − g·F = 1 so that B is unimodular and B⁻¹ is an integer matrix, and it would need the public key to drop the parity basis, with the verifier instead recovering the signature's coset by a rational rounding step against q00/q01 — floating-point ring arithmetic that this integer-only build deliberately avoids. This build samples f, g, F, G independently, so it does neither. Layering a Gaussian coset offset on top of the mod-2 solve would not have helped: the forgeability comes from publishing B mod 2 and from an acceptance bound slack enough to admit anything in the coset, not from the sampler.

What stays simplified elsewhere: a mod-2 coset solve instead of the full discrete-Gaussian lattice sampler (so table T1, the signing-time table, is exhibited standalone in Exhibit 2 and is never reached by signing — T0 does run for real during keygen); schoolbook multiplication instead of the NTT; uncompressed serializers, so measured bytes (920 B signature, 14,336 B public key at n=512) run far above the HAWK v1.1 spec figures (555 B and 1,024 B), which Exhibit 3 now shows side by side; and a demo-calibrated acceptance bound roughly 12x above where genuine signatures land, which Exhibit 3 exposes as a slider so the norm-rejection loop and the restart counter become reachable instead of permanently reading 0. All of it is disclosed in the in-app honesty panel.

## When to Use It

Use this repo when you want to:

- Understand the research frontier of lattice signatures as of 2026
- Explain why Falcon's floating-point Gaussian sampler remains a deployment liability
- Compare HAWK's smLIP-based design against ML-DSA and Falcon
- Show students how discrete Gaussian sampling over Z differs from Falcon's lattice-centered sampling
- Illustrate why HAWK is attractive for constrained devices, FHE, and MPC-oriented discussions
- Keep an eye on possible 2027+ post-standardization adoption paths
- Do NOT use this repo for production signatures — if you need production-ready PQ signatures now, use ML-DSA per FIPS 204 and deploy with crypto agility.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-hawk](https://systemslibrarian.github.io/crypto-lab-hawk/)**

The lab opens with a five-step guided path, then six exhibits: the three lattice signatures at a glance, a module-LIP short-basis vs bad-basis view, a step-through of HAWK's integer-only discrete Gaussian sampling against Falcon's, a live HAWK-512/1024 signing walkthrough that exposes the verification identity and norm bound with real numbers, a Round 2 standardization roadmap, and a glossary plus self-check. A keygen → sign → verify → tamper-reject self-test runs on page load and reports as a header badge.

## What Can Go Wrong

- HAWK is still a Round 2 candidate, not a standard. NIST may not select it.
- This code is educational, not byte-exact reference code. The parameter handling and verification structure are simplified to make the design legible in a browser demo.
- Round 2 cryptanalysis is ongoing. Security estimates, implementation guidance, and even parameter choices may still change.
- HAWK's masking story is still an active research topic even though its constant-time shape is cleaner than Falcon's.
- Key generation can fail in real HAWK because the NTRU equation may not solve for a sampled basis. This demo preserves that retry story in educational form.
- Signature restart is rare in HAWK and modeled here as a rare event, but the full reference implementation details are more nuanced than this browser version.

## Real-World Usage

HAWK was introduced in Ducas, Postlethwaite, Pulles, and van Woerden, "Hawk: Module LIP makes Lattice Signatures Fast, Compact and Simple" at ASIACRYPT 2022. The current public specification for this repo's framing is HAWK v1.1 dated February 5, 2025. NIST IR 8528 documented the first-round additional-signatures report in October 2024 and advanced HAWK to Round 2, where it remains notable as the only lattice-based candidate still in the field.

As of April 2026, the most practical deployment guidance is still:

- Production PQ signatures now: ML-DSA in hybrid deployments
- Research and future lattice-signature tracking: HAWK
- Small-signature deployments today: Falcon only with serious implementation caution
- FHE or MPC oriented signature research: HAWK is one of the most interesting designs to watch

If HAWK is eventually standardized, it could materially change how teams think about compact lattice signatures on constrained or side-channel-sensitive platforms. If it is not selected, it will still have influenced the direction of future post-Falcon designs.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-hawk
cd crypto-lab-hawk
npm install
npm run dev
```

## Related Demos

- [crypto-lab-falcon-seal](https://systemslibrarian.github.io/crypto-lab-falcon-seal/) — Falcon, the compact lattice signature HAWK is positioned to succeed.
- [crypto-lab-dilithium-seal](https://systemslibrarian.github.io/crypto-lab-dilithium-seal/) — ML-DSA (FIPS 204), the production PQ signature standard.
- [crypto-lab-sphincs-ledger](https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/) — SLH-DSA, the hash-based PQ signature alternative.
- [crypto-lab-multivariate](https://systemslibrarian.github.io/crypto-lab-multivariate/) — UOV, a non-lattice PQ signature family for contrast.
- [crypto-lab-hybrid-sign](https://systemslibrarian.github.io/crypto-lab-hybrid-sign/) — composite Ed25519 + ML-DSA-65 signatures for transitional deployment.

## References

- Ducas, Postlethwaite, Pulles, van Woerden, Hawk: Module LIP makes Lattice Signatures Fast, Compact and Simple, ASIACRYPT 2022
- HAWK v1.1 specification, February 5, 2025
- NIST IR 8528, First Round Report, October 2024

## Development

```bash
npm install
npm run build
npm test
```

`npm test` runs the four-phase verification suite (`scripts/verify-phase*.ts`). Phase 4 is the comprehensive gold-standard check: full keygen → sign → verify round-trips for HAWK-512 and HAWK-1024, the coset verification identity, tamper rejection, wrong-key rejection (a valid signature must fail against a different public key, since verification depends on that key's Gram matrix and parity basis), a norm-only forgery that keeps the coset but inflates the lattice vector (caught by the Gram-matrix bound), a public-key-only forgery that is asserted to be **accepted** (this build has no signing trapdoor, and the negative claim is pinned by a test just like the positive ones), a tightened acceptance bound flipping an otherwise-valid signature to rejected, serialization determinism and sizes, and a chi-square goodness-of-fit test on the discrete Gaussian sampler. CI runs the build and the suite on every push and pull request, and the GitHub Pages deploy is gated on `npm test` so a broken crypto path can never ship.

The app is static and deploys to GitHub Pages with base path `/crypto-lab-hawk/`.

---

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
