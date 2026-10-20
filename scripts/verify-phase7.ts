/* Phase 7 — published ground truth for the digest, and the properties of the
 * lab's own expander.
 *
 * src/hawk.ts builds every deterministic value from SHA-256: expandDeterministic
 * runs it in counter mode with a label prefix. Nothing pinned the digest, so a
 * wrong hash would have produced self-consistent nonsense that every other phase
 * would have accepted.
 *
 * THE DIGEST VECTOR IS COPIED FROM THE PUBLICATION, not reproduced from
 * WebCrypto: the Len = 24 case of SHA256ShortMsg.rsp, from NIST's Cryptographic
 * Algorithm Validation Program (shabytetestvectors.zip, csrc.nist.gov). It is
 * asserted THROUGH this lab's sha256() rather than against crypto.subtle, because
 * an assertion on subtle tests the runtime and not the lab.
 *
 * NO VECTOR IS CLAIMED FOR THE EXPANDER, and that is deliberate.
 * expandDeterministic is this lab's own construction -- SHA-256 in counter mode,
 * where real Hawk uses SHAKE256 -- so no published answer exists for it. What
 * can be checked are the properties the key generation relies on: determinism,
 * exact length, label separation, and a counter that actually advances so the
 * second block differs from the first.
 */
import { sha256, expandDeterministic } from '../src/hawk.ts';

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

const hex = (h: string) => Uint8Array.from((h.match(/../g) ?? []).map((b) => parseInt(b, 16)));
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

async function main(): Promise<void> {
  // 1. The published digest, through the lab's own function.
  const got = await sha256(hex('b4190e'));
  assert(
    toHex(got) === 'dff2e73091f6c05e528896c4c831b9448653dc2ff043528f6769437bc7b975c2',
    `sha256 does not match NIST CAVP SHA256ShortMsg Len=24: got ${toHex(got)}`,
  );
  assert(got.length === 32, `sha256 must return 32 bytes, got ${got.length}`);
  console.log('PASS  sha256 matches NIST CAVP SHA256ShortMsg.rsp, Len = 24');

  // 2. The expander's properties. No published vector; these are the claims
  //    key generation actually rests on.
  const seed = hex('00112233445566778899aabbccddeeff');

  const a = await expandDeterministic(seed, 'f', 64);
  const b = await expandDeterministic(seed, 'f', 64);
  assert(eq(a, b), 'expandDeterministic must be deterministic for one seed and label');
  console.log('PASS  the expander is deterministic');

  for (const len of [1, 31, 32, 33, 64, 100]) {
    const out = await expandDeterministic(seed, 'f', len);
    assert(out.length === len, `expandDeterministic(${len}) returned ${out.length} bytes`);
  }
  console.log('PASS  it returns exactly the requested length, across block boundaries');

  const other = await expandDeterministic(seed, 'g', 64);
  assert(!eq(a, other), 'a different label must give a different stream');
  console.log('PASS  labels separate the streams');

  /* The counter must advance, or every 32-byte block would be identical and the
     stream would repeat -- which a length-only test would never notice. */
  const twoBlocks = await expandDeterministic(seed, 'f', 64);
  const first = twoBlocks.slice(0, 32);
  const second = twoBlocks.slice(32, 64);
  assert(!eq(first, second), 'the counter does not advance: block 2 repeats block 1');
  /* And block 1 must be exactly the digest of label || counter 0 || seed, which
     is what makes the construction inspectable rather than magic. */
  const counterZero = new Uint8Array([0, 0, 0, 0]);
  const expectedFirst = await sha256(
    Uint8Array.from([...new TextEncoder().encode('f'), ...counterZero, ...seed]),
  );
  assert(eq(first, expectedFirst), 'block 1 is not sha256(label || uint32(0) || seed)');
  console.log('PASS  the counter advances, and block 1 is the documented preimage');

  const changed = Uint8Array.from(seed); changed[0] ^= 1;
  assert(!eq(a, await expandDeterministic(changed, 'f', 64)), 'a changed seed must change the stream');
  console.log('PASS  a one-bit seed change changes the stream');

  console.log('\nphase 7: 6 checks passed.');
}

main().catch((err) => { console.error(err); process.exit(1); });
