import { initWasm, isWasmBackend } from "../src/crypto/backend";

// Detection modules (jailbreak, output sanitizer, canonical JSON, etc.) work
// best with the WASM backend.  Try to initialize it, but fall back to the
// noble (pure-JS) backend when @clawdstrike/wasm is not installed (e.g. in CI
// where the WASM package has not been built/linked).
const ok = await initWasm();
if (!ok || !isWasmBackend()) {
  // biome-ignore lint/suspicious/noConsole: setup diagnostics
  console.warn(
    "[test setup] WASM crypto backend unavailable — falling back to noble (pure-JS). " +
      "Install @clawdstrike/wasm for full coverage.",
  );
}
