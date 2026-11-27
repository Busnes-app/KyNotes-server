// Vitest's Node environment runs the same WASM binary served to the browser.
import { readFile } from "node:fs/promises";
import "./public/assets/pq/wasm_exec.js";
const go = new globalThis.Go();
const { instance } = await WebAssembly.instantiate(await readFile(new URL("./public/assets/pq/pq.wasm",import.meta.url)),go.importObject);
void go.run(instance);
