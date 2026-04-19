# crypto-lab-hawk

Browser-based educational demo of HAWK, the post-quantum signature scheme by Léo Ducas, Eamonn W. Postlethwaite, Ludo N. Pulles, and Wessel van Woerden. HAWK is the only lattice-based scheme in Round 2 of NIST's Additional Digital Signatures process after NIST IR 8528 (October 2024). This repo focuses on the structural reasons HAWK is interesting in 2026: integer-only arithmetic, discrete Gaussian sampling over Z through fixed lookup tables, no rejection loop in signing, and a cleaner constant-time story than Falcon.

> "Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God."
> 1 Corinthians 10:31

## What It Is

This is a Vite + TypeScript + vanilla CSS educational lab that compares Falcon, ML-DSA, and HAWK side by side. The demo implements HAWK-512 and HAWK-1024 at educational fidelity around the HAWK v1.1 specification dated February 5, 2025. It is intentionally not a production implementation and does not claim byte-exact compatibility with the official reference code.

The emphasis is on HAWK's architectural differences from Falcon:

- No floating-point arithmetic in the core signing path
- No rejection sampling loop like ML-DSA
- Integer-only discrete Gaussian sampling over Z with fixed tables
- A simplified public/private basis story tied to the Lattice Isomorphism Problem
- A browser-native exhibit showing why HAWK may become Falcon's conceptual successor if standardization continues successfully

The UI includes five exhibits:

- The three lattice signatures at a glance
- The Gaussian sampling difference between Falcon and HAWK
- A live HAWK signing walkthrough
- A Round 2 standardization roadmap
- Deployment guidance for real 2026 systems

## When to Use It

Use this repo when you want to:

- Understand the research frontier of lattice signatures as of 2026
- Explain why Falcon's floating-point Gaussian sampler remains a deployment liability
- Compare HAWK's smLIP-based design against ML-DSA and Falcon
- Show students how discrete Gaussian sampling over Z differs from Falcon's lattice-centered sampling
- Illustrate why HAWK is attractive for constrained devices, FHE, and MPC-oriented discussions
- Keep an eye on possible 2027+ post-standardization adoption paths

Do not use this repo for production signatures. If you need production-ready PQ signatures now, use ML-DSA per FIPS 204 and deploy with crypto agility.

## Live Demo

https://systemslibrarian.github.io/crypto-lab-hawk/

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

## References

- Ducas, Postlethwaite, Pulles, van Woerden, Hawk: Module LIP makes Lattice Signatures Fast, Compact and Simple, ASIACRYPT 2022
- HAWK v1.1 specification, February 5, 2025
- NIST IR 8528, First Round Report, October 2024

## Development

```bash
npm install
npm run build
```

The app is static and deploys to GitHub Pages with base path `/crypto-lab-hawk/`.