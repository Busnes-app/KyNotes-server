/** One implementation of PQ crypto: the pinned ky-primitives command, built locally/CI. */
type Result<T> = T | { error: string };
type PQ = {
  xwingGenerate(): Result<{ seed: Uint8Array; publicKey: Uint8Array }>;
  xwingSeal(pub: Uint8Array, info: Uint8Array, aad: Uint8Array, msg: Uint8Array): Result<Uint8Array>;
  xwingOpen(seed: Uint8Array, info: Uint8Array, aad: Uint8Array, msg: Uint8Array): Result<Uint8Array>;
  hybridsigGenerate(): Result<{ mldsaSeed: Uint8Array; ed25519Seed: Uint8Array; publicKey: Uint8Array }>;
  hybridsigSign(m: Uint8Array, e: Uint8Array, label: string, msg: Uint8Array): Result<Uint8Array>;
  hybridsigVerify(pub: Uint8Array, label: string, msg: Uint8Array, sig: Uint8Array): Result<boolean>;
};
declare global {
  var pqwasm: PQ | undefined;
  var Go: { new(): { importObject: WebAssembly.Imports; run(instance: WebAssembly.Instance): Promise<void> } };
}
let loading: Promise<PQ> | undefined;
export function loadPQ(): Promise<PQ> {
  return loading ??= (async () => {
    if (globalThis.pqwasm) return globalThis.pqwasm;
    await new Promise<void>((resolve, reject) => {
      const script = document.createElement("script");
      script.src = "/assets/pq/wasm_exec.js";
      script.onload = () => resolve(); script.onerror = () => reject(new Error("Could not load encryption runtime"));
      document.head.append(script);
    });
    const go = new globalThis.Go();
    const response = await fetch("/assets/pq/pq.wasm");
    if (!response.ok) throw new Error("Could not load encryption module");
    const { instance } = await WebAssembly.instantiate(await response.arrayBuffer(), go.importObject);
    void go.run(instance);
    if (!globalThis.pqwasm) throw new Error("Encryption module did not initialize");
    return globalThis.pqwasm;
  })();
}
export function result<T>(value: Result<T>): T {
  if (typeof value === "object" && value !== null && "error" in value) throw new Error(value.error);
  return value;
}
export const XWING_PUBLIC_BYTES = 1216;
export const HYBRID_PUBLIC_BYTES = 2000;
export const HYBRID_SIGNATURE_BYTES = 3389;
export const PQ_PUBLIC_BYTES = 1 + 32 + XWING_PUBLIC_BYTES + HYBRID_PUBLIC_BYTES;
export const PQ_PRIVATE_BYTES = 129 + PQ_PUBLIC_BYTES;

export function pqReady(): PQ { if (!globalThis.pqwasm) throw new Error("Encryption module is not loaded"); return globalThis.pqwasm; }
