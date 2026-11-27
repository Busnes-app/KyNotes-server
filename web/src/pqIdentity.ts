import { x25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { loadPQ, result, pqReady, PQ_PRIVATE_BYTES, PQ_PUBLIC_BYTES, XWING_PUBLIC_BYTES } from "./pq";
// No imports from teamKeys: it imports this module for the identity boundary.
const join = (...parts: Uint8Array[]) => { const out = new Uint8Array(parts.reduce((n,p) => n+p.length,0)); let i=0; for(const p of parts){out.set(p,i);i+=p.length;} return out; };
const equal = (a: Uint8Array,b: Uint8Array) => a.length===b.length && a.every((v,i)=>v===b[i]);
export const isPQPublic = (key: Uint8Array): boolean => key.length === PQ_PUBLIC_BYTES && key[0] === 4;

export async function generatePQIdentity(legacy: Uint8Array = randomBytes(32)): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
  if (legacy.length !== 32) throw new Error("invalid legacy identity key");
  await loadPQ();
  return generatePQIdentityReady(legacy);
}
export function generatePQIdentityReady(legacy: Uint8Array = randomBytes(32)): { privateKey: Uint8Array; publicKey: Uint8Array } {
  const pq = pqReady();
  const x = result(pq.xwingGenerate()), s = result(pq.hybridsigGenerate());
  const publicKey = join(Uint8Array.of(4), x25519.getPublicKey(legacy), x.publicKey, s.publicKey);
  return { publicKey, privateKey: join(Uint8Array.of(4), legacy, x.seed, s.mldsaSeed, s.ed25519Seed, publicKey) };
}

/** Validate a private encoding against its embedded public keys, using the shared library. */
export function identityPublic(privateKey: Uint8Array): Uint8Array {
  if (privateKey.length === 32) return x25519.getPublicKey(privateKey);
  if (privateKey.length !== PQ_PRIVATE_BYTES || privateKey[0] !== 4) throw new Error("invalid identity private key");
  const pub = privateKey.subarray(129);
  if (!isPQPublic(pub) || !equal(x25519.getPublicKey(privateKey.subarray(1,33)),pub.subarray(1,33))) throw new Error("identity key mismatch");
  const pq = pqReady();
  const label = "kynotes/identity/v4/key-check", ctx = new TextEncoder().encode(label), msg = new Uint8Array(32);
  const sealed = result(pq.xwingSeal(pub.subarray(33,33+XWING_PUBLIC_BYTES),ctx,ctx,msg));
  if (!equal(result(pq.xwingOpen(privateKey.subarray(33,65),ctx,ctx,sealed)),msg)) throw new Error("identity key mismatch");
  const sig = result(pq.hybridsigSign(privateKey.subarray(65,97),privateKey.subarray(97,129),label,pub));
  result(pq.hybridsigVerify(pub.subarray(33+XWING_PUBLIC_BYTES),label,pub,sig));
  return pub.slice();
}
