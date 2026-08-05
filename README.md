# crypto-lab-hawk

## What It Is

Browser-based educational demo of HAWK, the post-quantum signature scheme by Léo Ducas, Eamonn W. Postlethwaite, Ludo N. Pulles, and Wessel van Woerden. HAWK was the last lattice-based scheme standing in NIST's Additional Digital Signatures process — advanced to Round 2 by NIST IR 8528 (October 2024) and to Round 3 by NIST IR 8610 (2026) — until its designers **withdrew it on 29 July 2026**, one day after a key-recovery attack halved its security margin. This repo covers the structural reasons HAWK was interesting: integer-only arithmetic, discrete Gaussian sampling over Z through fixed lookup tables, no accept/reject loop inside the sampler, and a cleaner constant-time story than Falcon — and then why none of that saved it.

> **HAWK is withdrawn.** On 28 July 2026 Straznickas and Weis published an unconditional reduction from HAWK-*n* key recovery to SVP in dimension *n*/2 + 1, dropping HAWK-512 from 2¹⁵⁰ to ≤2¹⁰⁸ gates and recovering real HAWK-256 keys end to end. On 29 July the HAWK team withdrew the scheme on the NIST pqc-forum, judging that doubling parameters or moving to higher-rank modules would leave it uncompetitive. NIST lists it as withdrawn. See [Security status](#security-status-the-july-2026-key-recovery-attack) below — and note the lab now *runs* that attack. Nothing deployed is affected; Falcon and ML-DSA are untouched.

This is a Vite + TypeScript + vanilla CSS educational lab that compares Falcon, ML-DSA, and HAWK side by side. The demo implements HAWK-512 and HAWK-1024 at educational fidelity around the HAWK v1.1 specification dated February 5, 2025. It is intentionally not a production implementation and does not claim byte-exact compatibility with the official reference code.

The emphasis is on HAWK's architectural differences from Falcon:

- No floating-point arithmetic in the core signing path
- No accept/reject loop inside the sampler, unlike ML-DSA's outer rejection loop and Falcon's internal SamplerZ rejection
- Integer-only discrete Gaussian sampling over Z with fixed tables
- A simplified public/private basis story tied to the Lattice Isomorphism Problem
- A browser-native exhibit showing why HAWK was positioned as Falcon's conceptual successor, and what the July 2026 key-recovery attack did to that story

The UI opens with a five-step guided learning path and then walks through six exhibits:

- The three lattice signatures at a glance, including a full side-by-side comparison matrix
- What module-LIP means, shown as a short basis versus a bad basis over the *same* lattice: both bases are unimodular recombinations (determinant 4) that render the identical dot grid, and a draggable hash target animates greedy Babai rounding as basis-step arrows from the origin, counting the steps on screen so the short-basis-is-easy / bad-basis-is-hard claim is something you discover by dragging rather than read — followed by a cryptanalysis panel carrying the July 2026 result, because that exhibit is exactly where the assumption moved — including a live runner that executes the key-recovery reduction at toy parameters and recovers a working basis from the public key alone
- The Gaussian sampling difference between Falcon and HAWK, with a step-through of a single CDT draw (pre-seeded with a worked example on load) that accumulates into a live tally, plus a synchronized bell-curve panel that marks where the random word lands on the discrete Gaussian and shades the tail regions the crossed thresholds correspond to, making "how many thresholds it falls under = magnitude" visually obvious
- A live HAWK signing walkthrough that shows the verification identity in the open: recompute the message's parity target, check the signature's lattice coset against it with the public parity basis, and check the lattice point's Euclidean length via the public Gram matrix Q = B*B, with the actual numbers — plus a public-key-only forgery you can run, and a sampler-gap bench that measures whether swapping in a real discrete-Gaussian coset sampler would have stopped it (it does not, and the bench shows exactly which property is the reason)
- A standardization roadmap from the 2022 on-ramp through the July 2026 attack and withdrawal, plus deployment guidance for real 2026 systems
- A glossary of every key term plus a six-question self-check that grades entirely in the browser

A self-test runs on page load — a real keygen → sign → verify → tamper-reject round-trip, plus a public-key-only forgery that this build is expected to accept — so the honesty claims are machine-checked in both directions, not just asserted. The result shows as a badge in the header.

The verification path is a genuine, integer-only lattice round-trip, not a forced arithmetic identity. Keys are a real short basis B = [[f,F],[g,G]] sampled from the discrete Gaussian; the public key is its Gram matrix Q = B*B computed with actual polynomial multiplication and ring adjoints. A signature is a short lattice vector B·c whose coset is bound to the message, and verification uses only the public key: it checks the coset with the public parity basis (via polynomial multiplication mod 2) and measures the vector's length as c*·Q·c. Because verification depends on Q and the parity basis, a signature made with a different key is rejected and a single flipped coefficient is rejected — both are covered by the test suite (see `verify:phase4`), which also confirms a norm-only forgery that keeps the coset intact is caught by the Gram-matrix bound.

### The signing path has no trapdoor, and the demo says so

This is the one thing to know before using this repo to teach unforgeability: **it cannot.** `hawkSign` takes the private key as an argument but reads nothing from it that the public key does not already publish — the parity basis B mod 2, which keygen ships verbatim as `publicKey.basisMod2`, and the Gram matrix Q. So anyone holding only the public key can recompute identical signature coordinates and the unmodified verifier accepts them. Exhibit 3 has a **Forge with only the public key** button that does exactly this, live, and the on-load self-test asserts the forgery succeeds.

Fixing it properly is not a small edit. It would need keygen to solve the NTRU equation f·G − g·F = 1 so that B is unimodular and B⁻¹ is an integer matrix, and it would need the public key to drop the parity basis, with the verifier instead recovering the signature's coset by a rational rounding step against q00/q01 — floating-point ring arithmetic that this integer-only build deliberately avoids. This build samples f, g, F, G independently, so it does neither.

### The sampler gap is measured, not asserted

The natural next question is whether the *sampler* is the problem: if this build drew its coset representative from a real discrete Gaussian instead of solving a linear system mod 2, would the forgery stop? Exhibit 3 answers that with a bench rather than a paragraph. **Measure the sampler gap** builds a genuine discrete-Gaussian coset sampler — `solveCosetGaussian` draws one integer per coordinate coefficient from HAWK's signing table T₁ through the same constant-time CDT walk Exhibit 2 steps through, and adds 2z to the mod-2 solution — then runs both samplers against the same live key and message, measuring five structural properties plus the forgery outcome for each.

What comes out (measured on every run; typical figures at n = 512):

| Measured property | mod-2 linear solve | + discrete-Gaussian coset offset |
|---|---|---|
| Two signings of one (message, salt) differ in | 0 of 1024 coefficients | ~800–830 of 1024 |
| c(hₐ ⊕ h_b) = c(hₐ) ⊕ c(h_b) over Z | 1024 of 1024 | ~260–300 of 1024 |
| …the same comparison mod 2 | 1024 of 1024 | **1024 of 1024** |
| Distinct coefficient values · entropy | 2 · 1.00 bits | ~18 · ~3.5 bits |
| Mean ‖B·c‖² | ~1.1e6–1.5e6 | ~1.5e7–2.5e7 (13–25× — it varies with the sampled basis, and the bench prints the ratio it measured) |
| Public-key-only forgery, judged by the unmodified verifier | **ACCEPTED** | **ACCEPTED** |

The Gaussian moves four of the five structural properties and leaves forgeability exactly where it was, because the one row it does not move is additivity mod 2: the offset is a multiple of 2, so the representative stays in the same parity coset, and the parity coset is the only thing a forger holding `publicKey.basisMod2` needs. That is the honest shape of this build's gap — the missing piece is a smaller public key, not a better sampler. Each column is judged under a bound derived from its own measured norms, because a Gaussian coset representative is genuinely longer than the bare {0,1} one; sampler width and acceptance bound are coupled, and the bench shows by how much.

`scripts/verify-phase5.ts` pins every one of those properties, including the negative results and the failure paths — a shifted coefficient, a bound tightened below the norm, and a foreign public key each reject a Gaussian-coset signature — plus a check that the public Gram-matrix norm equals ‖B·c‖² recomputed from the secret basis at Gaussian coordinate magnitudes. `e2e/sampler-gap.spec.ts` pins that the browser really computes and renders them.

What stays simplified elsewhere: a mod-2 coset solve instead of the full discrete-Gaussian lattice sampler (so table T1, the signing-time table, is not reached by the default signing path — it runs for real in Exhibit 2 and in the Gaussian column of the sampler-gap bench above, while T0 runs for real during keygen); schoolbook multiplication instead of the NTT; uncompressed serializers, so measured bytes (920 B signature, 14,336 B public key at n=512) run far above the HAWK v1.1 spec figures (555 B and 1,024 B), which Exhibit 3 now shows side by side; and a demo-calibrated acceptance bound roughly 12x above where genuine signatures land, which Exhibit 3 exposes as a slider so the norm-rejection loop and the restart counter become reachable instead of permanently reading 0. All of it is disclosed in the in-app honesty panel.

## Security status: the July 2026 key-recovery attack

HAWK is withdrawn as of 29 July 2026. Here is what ended it.

On 28 July 2026, Zygimantas Straznickas and Stephen A. Weis (Anthropic) published *HAWK-n Key Recovery Reduces to SVP in Dimension n/2 + 1*: an unconditional, deterministic polynomial-time reduction from HAWK key recovery to polynomially many exact-SVP calls in **half** the dimension HAWK's parameters were sized against.

**What the attack uses.** HAWK's public key is the Gram matrix Q = B\*B of a secret short basis B over the power-of-two cyclotomic field Q(ζ). That field has three order-2 Galois involutions; every prior module-LIP attack worked only with complex conjugation. The new attack uses a second one, τ: ζ ↦ −ζ, and shows that Q *by itself* cuts out a publicly computable lattice of rank n whose shortest vector is the τ-cocycle V = B⁻¹τ(B). That lattice is near-hypercubic — isometric up to scale to Z^(n/2+1) ⊕ √2·Z^(n/2−1) — so Ducas's block reduction returns V with SVP-oracle calls in dimension n/2 + 1, and the van Gent–Pulles descent turns V back into a basis that signs.

The theoretical possibility was already known: prior work proved that an efficiently findable nontrivial automorphism of the key lattice would break the scheme. What was missing, and what this paper supplies, is that HAWK's own lattice contains one.

**What it costs.** In the AGPS20 gate model the specification itself uses:

| Parameter set | HAWK v1.1 claim | After the reduction | Heuristic, spec's own methodology |
|---|---|---|---|
| HAWK-256 (challenge) | 2⁷⁴ | 2⁵² | recovered end-to-end in practice |
| HAWK-512 | 2¹⁵⁰ | ≤2¹⁰⁸ | ~2⁸⁰·⁸ |
| HAWK-1024 | 2²⁸⁸ | ≤2¹⁸² | ~2¹⁴⁶·⁵ |

The authors implemented the attack and recovered the secret keys of two HAWK-256 public keys generated by the reference key generator, end to end, in a few hours on a single 96-core server — verified against the HAWK reference implementation. HAWK-512 has not been attempted.

**What happened next.** On 29 July 2026, one day after publication, the HAWK team withdrew the scheme from the NIST process on the pqc-forum. They confirmed the attack "approximately halves the block size required in lattice reduction to recover an equivalent secret key," and concluded that the straightforward mitigations — doubling the parameters or moving to higher-rank modules — "make HAWK uncompetitive." NIST updated its third-round candidate page to mark HAWK withdrawn. Four years of expert review, and the scheme was retired a day after the attack landed.

**What it does not touch.** Falcon is unaffected; the construction does not transfer. Nothing in production was ever at risk, because HAWK shipped in no standard and no product. The attack needs a Galois involution other than complex conjugation, which exists exactly when (Z/m)× is non-cyclic — so conductors m ∈ {p^k, 2p^k} for an odd prime p evade it. That makes this a result about HAWK's choice of ring, not about lattice signatures or module-LIP in general.

**Provenance.** The mathematics was found by Claude Mythos Preview working semi-autonomously inside a multi-agent scaffold built on Claude Code, with access to Python, Sage, and a library of published cryptography — roughly 60 hours of model work and about $100,000 in API cost, directed by one non-specialist researcher. Anthropic disclosed to the HAWK designers in June 2026 and published in coordination with the NIST PQC forum in July; Thomas Pornin and the HAWK team reviewed the work. The paper's own acknowledgements state that the majority of its mathematical discoveries were AI-assisted, with the human authors directing, organizing, and verifying.

**A companion result, same program.** The same effort produced *Cryptanalysis of 7-Round AES via the Algebraic Structure of its S-box* (Milad Nasr and Nicholas Carlini), which introduces an algebraic **Möbius bridge** exploiting the invert-then-affine structure of the AES S-box to eliminate one of the nine key bytes guessed by Derbez–Fouque–Jean, cutting the attack on 7-round AES from 2⁹⁹ to between 2⁸⁹·³ and 2⁹¹·⁴ time at the same 2¹⁰⁵ chosen-plaintext data complexity. Full 10-round AES as deployed is untouched and the attack is completely impractical. It is unrelated to HAWK and is noted here only because it is the other half of the same disclosure.

**What this repo did about it.** Every status claim in the app and this README now reads *withdrawn* rather than Round 2 or Round 3, Exhibit 1.5 gained a cryptanalysis panel carrying the result and the numbers above, the roadmap ends at the withdrawal, the glossary gained a Galois-automorphism entry, and the self-check gained a question on the attack.

### The attack runs live, at toy parameters

Exhibit 1.5 does not just describe the reduction — it runs it. **Recover the key from the public key** generates a genuine unimodular toy basis B over Z[x]/(xⁿ+1), publishes only Q = B\*B, and then executes the paper's three steps against Q alone:

1. Build the τ-cocycle lattice from Q: the integer solutions of τ(Y) = adj(Y) and QY = adj(Y)\*τ(Q), whose coefficients come only from Q and τ(Q). Rank comes out exactly n.
2. LLL-reduce and enumerate. There are exactly 2(n/2 + 1) shortest vectors, at the key-independent minimum n/4 that Lemma 4.4 predicts.
3. Parity-test Y ≡ I (mod 2). Exactly two survive, and they are ±V_τ. Descend through the kernel sublattice M_Y = {x : τ(x) = adj(V_τ)x} to a basis B′, and check B′\*B′ = Q.

It runs at n = 4 (SVP dimension 3, a few milliseconds) and n = 8 (dimension 5, about a second). Plain LLL stands in for the sieve a real attack needs; at HAWK-512 the proven oracle dimension is 257, which is why this demonstrates the mechanism rather than breaking anything.

The detail worth pausing on: **the recovered basis is usually not the original one.** It is a different basis with the same Gram matrix, and it signs just as well — because key recovery asks for any B′ with B′\*B′ = Q. The paper reports exactly this from its HAWK-256 runs ("distinct but unitarily-equivalent secret keys"). The exhibit prints Q, B′ and B side by side so you can see it.

This is a separate module (`src/lip-attack.ts`) from the HAWK-512/1024 teaching build, and it has to be: this demo's own keys are sampled independently rather than by solving the NTRU equation, so they are not unimodular and have no cocycle to recover. That is a pre-existing, thoroughly documented limitation (see below), not something the attack introduced. Arbitrary-precision arithmetic throughout — the raw kernel basis carries entries hundreds of digits long before reduction.

`scripts/verify-phase6.ts` pins all of it: the rank, the 2(n/2 + 1) count, the two parity survivors matching ±V_τ, the final B′\*B′ = Q, that at least one run recovers a *distinct* but equivalent basis, and a negative control that two different public keys do not yield the same recovered basis. `e2e/lip-attack.spec.ts` pins that the browser really runs it. The authors' own implementation, which reaches HAWK-256 for real, is at [anthropics/cryptography-research-demo](https://github.com/anthropics/cryptography-research-demo).

## When to Use It

Use this repo when you want to:

- Understand how the lattice-signature frontier looked in 2026, and how fast it moved
- Explain why Falcon's floating-point Gaussian sampler remains a deployment liability
- Compare HAWK's smLIP-based design against ML-DSA and Falcon
- Show students how discrete Gaussian sampling over Z differs from Falcon's lattice-centered sampling
- Illustrate why HAWK was attractive for constrained devices, FHE, and MPC-oriented discussions — and why that was not enough
- Teach how a scheme's security assumption can move underneath a well-engineered implementation, using the July 2026 automorphism attack as the worked example — and let students run that attack themselves at a size that finishes instantly
- Study a complete arc: proposal, four years of expert review, an AI-found structural attack, and withdrawal in a day
- Do NOT use this repo for production signatures — if you need production-ready PQ signatures now, use ML-DSA per FIPS 204 and deploy with crypto agility.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-hawk](https://systemslibrarian.github.io/crypto-lab-hawk/)**

The lab opens with a five-step guided path, then six exhibits: the three lattice signatures at a glance, a module-LIP short-basis vs bad-basis view, a step-through of HAWK's integer-only discrete Gaussian sampling against Falcon's, a live HAWK-512/1024 signing walkthrough that exposes the verification identity and norm bound with real numbers, a standardization roadmap ending in the July 2026 withdrawal, and a glossary plus self-check. A keygen → sign → verify → tamper-reject self-test runs on page load and reports as a header badge.

## What Can Go Wrong

- HAWK is withdrawn. It is not a standard and will not become one on its current design. Nothing here is a deployment path; it is a case study.
- HAWK's published parameter sets no longer deliver the security they claim. HAWK-512 drops from 2¹⁵⁰ to ≤2¹⁰⁸ gates. Treat every parameter and size figure in this lab as describing HAWK v1.1 as specified, not as a current security estimate.
- This code is educational, not byte-exact reference code. The parameter handling and verification structure are simplified to make the design legible in a browser demo.
- Cryptanalysis is ongoing and just proved the point. Security estimates, implementation guidance, and even parameter choices may still change again — the open question the attack's authors leave is whether the same rank-4 module structure admits a solver below dimension n/2.
- HAWK's masking story is still an active research topic even though its constant-time shape is cleaner than Falcon's.
- Key generation can fail in real HAWK because the NTRU equation may not solve for a sampled basis. This demo preserves that retry story in educational form.
- Signature restart is rare in HAWK and modeled here as a rare event, but the full reference implementation details are more nuanced than this browser version.

## Real-World Usage

HAWK was introduced in Ducas, Postlethwaite, Pulles, and van Woerden, "Hawk: Module LIP makes Lattice Signatures Fast, Compact and Simple" at ASIACRYPT 2022. The current public specification for this repo's framing is HAWK v1.1 dated February 5, 2025. NIST IR 8528 documented the first-round additional-signatures report in October 2024 and advanced HAWK to Round 2; NIST IR 8610 reported on Round 2 in 2026 and advanced HAWK to Round 3, again as the only lattice-based candidate in the field — while specifically asking for further analysis of smLIP within the structure of cyclotomic number fields. That is precisely where the July 2026 attack landed, and on 29 July 2026 the HAWK team withdrew the scheme on the NIST pqc-forum.

As of August 2026, the most practical deployment guidance is:

- Production PQ signatures now: ML-DSA in hybrid deployments
- Research and future lattice-signature tracking: HAWK, now with the caveat that its published parameters are under-strength
- Small-signature deployments today: Falcon only with serious implementation caution — and note that the HAWK attack does not transfer to it
- FHE or MPC oriented signature research: HAWK's integer-only structure is still one of the most interesting designs to watch, since the attack targets its ring rather than its arithmetic

If HAWK is eventually standardized — with larger parameters, a different conductor, or both — it could still change how teams think about compact lattice signatures on constrained or side-channel-sensitive platforms. If it is not selected, it will have influenced the direction of future post-Falcon designs anyway, and it will stand as a well-documented case of an assumption weakening years after the design looked settled.

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
- NIST IR 8610, Status Report on the Second Round of the Additional Digital Signature Schemes, 2026 — [doi:10.6028/NIST.IR.8610](https://doi.org/10.6028/NIST.IR.8610)

### The July 2026 cryptanalysis

- Straznickas and Weis, *HAWK-n Key Recovery Reduces to SVP in Dimension n/2 + 1*, Anthropic, July 2026 — [paper](https://www.anthropic.com/document/hawk_key_recovery.pdf)
- Nasr and Carlini, *Cryptanalysis of 7-Round AES via the Algebraic Structure of its S-box*, Anthropic, July 2026 — [paper](https://www.anthropic.com/document/aes_mobius_bridge.pdf) · [chain of thought](https://www.anthropic.com/document/aes_mobius_bridge_cot.pdf)
- Anthropic, [Discovering cryptographic weaknesses with Claude](https://www.anthropic.com/research/discovering-cryptographic-weaknesses)
- The disclosure and the HAWK team's withdrawal, NIST pqc-forum, 28–29 July 2026 — [thread](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/2r2u6SbHun4)
- Attack implementation and lemma-verification scripts: [anthropics/cryptography-research-demo](https://github.com/anthropics/cryptography-research-demo)
- Ducas, *Provable lattice reduction of Zⁿ with blocksize n/2*, Des. Codes Cryptogr. 92(4), 2024 — the block reduction the attack runs
- van Gent and Pulles, 2025 — the automorphism descent that recovers the key from the cocycle
- Press coverage: [Ars Technica](https://arstechnica.com/security/2026/07/mythos-uncovers-crypto-weaknesses-that-went-unknown-for-years/) · [CyberScoop](https://cyberscoop.com/anthropic-claude-mythos-encryption-flaws-hawk-aes-pqc/)

## Development

```bash
npm install
npm run build
npm test
```

`npm test` runs the six-phase verification suite (`scripts/verify-phase*.ts`). Phase 4 is the comprehensive gold-standard check: full keygen → sign → verify round-trips for HAWK-512 and HAWK-1024, the coset verification identity, tamper rejection, wrong-key rejection (a valid signature must fail against a different public key, since verification depends on that key's Gram matrix and parity basis), a norm-only forgery that keeps the coset but inflates the lattice vector (caught by the Gram-matrix bound), a public-key-only forgery that is asserted to be **accepted** (this build has no signing trapdoor, and the negative claim is pinned by a test just like the positive ones), a tightened acceptance bound flipping an otherwise-valid signature to rejected, serialization determinism and sizes, and a chi-square goodness-of-fit test on the discrete Gaussian sampler. Phase 5 covers the sampler gap: that the Gaussian coset offset preserves the parity coset, that a Gaussian-coset signature verifies and that a shifted coefficient, a tightened bound and a foreign key each reject it, that the public Gram-matrix norm agrees with a secret-basis recomputation at Gaussian coordinate magnitudes, and every measurement the Exhibit 3 bench prints — including the two that must NOT change, additivity mod 2 and the forgery being accepted. Phase 6 covers the 2026 key-recovery attack at toy parameters: the cocycle lattice's rank, the exact 2(n/2 + 1) shortest-vector count, the two parity survivors being ±V_τ, the recovered basis satisfying B′\*B′ = Q at n = 4 and n = 8 across five seeds each, that at least one run recovers a distinct-but-equivalent basis, and a negative control that two different public keys never yield the same recovered basis. CI runs the build and the suite on every push and pull request, and the GitHub Pages deploy is gated on `npm test` so a broken crypto path can never ship.

The app is static and deploys to GitHub Pages with base path `/crypto-lab-hawk/`.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
