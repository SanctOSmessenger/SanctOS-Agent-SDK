/* ============================================================
 * 🌐 SanctOS Standalone Public SDK — v0.3.0 (Standalone V3)
 * - Preserves your existing on-chain formats:
 *   - Message memo:  SANCTOS_MSG:<owner58>:<b64url(nonce24||cipher)>
 *   - Pointer32:     sha256(packed)[0..32]
 *   - Identity memo: SANCTOS_PUBKEY:<owner58>:<devicePubB64url>:<ts>
 * - Deterministic routing:
 *   - route:"wallet"   -> uses runtime postMessage/postSanctosMsg (atomic memo+fee+pointer)
 *   - route:"delegate" -> uses runtime postMessageDelegated (fee+memo) THEN postSanctosMsgDelegated(pointer32)
 * - Adds packed helpers + memo parsing + pointer derivation from *sent tx*
 * - Standalone: adapts to whatever your runtime exposes on window.sanctos / globalThis.sanctos
 * ============================================================ */

(() => {
  const g = typeof window !== "undefined" ? window : globalThis;
  g.sanctos = g.sanctos || {};

  // ------------------------------------------------------------
  // One-time install guard
  // ------------------------------------------------------------
  if (g.__SANCTOS_SDK_V3_INSTALLED) return;
  g.__SANCTOS_SDK_V3_INSTALLED = true;

  // ------------------------------------------------------------
  // Small event emitter (no deps)
  // ------------------------------------------------------------
  function createEmitter() {
    const map = new Map();
    return {
      on(evt, fn) {
        if (!map.has(evt)) map.set(evt, new Set());
        map.get(evt).add(fn);
        return () => map.get(evt)?.delete(fn);
      },
      emit(evt, payload) {
        const set = map.get(evt);
        if (!set || !set.size) return;
        for (const fn of set) {
          try {
            fn(payload);
          } catch (e) {
            console.warn("[SanctOS SDK v3] listener error:", e);
          }
        }
      },
    };
  }

  const emitter = (g.__sanctosApiEmitter ||= createEmitter());

  // ------------------------------------------------------------
  // Error helper (typed)
  // ------------------------------------------------------------
  function err(code, message, extra) {
    const e = new Error(message);
    e.code = code;
    if (extra && typeof extra === "object") e.extra = extra;
    return e;
  }

  // ------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------
  function pickFn(...candidates) {
    for (const fn of candidates) if (typeof fn === "function") return fn;
    return null;
  }

  function sleep(ms) {
    return new Promise((r) => setTimeout(r, ms));
  }

  function norm58(x) {
    return String(x || "").trim();
  }

  // ------------------------------------------------------------
  // Base58 (small, standalone) — decode only (for getTransaction ix.data)
  // ------------------------------------------------------------
  // Adapted from common minimal implementations (no external deps).
  const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const B58_MAP = (() => {
    const m = new Map();
    for (let i = 0; i < B58_ALPHABET.length; i++) m.set(B58_ALPHABET[i], i);
    return m;
  })();

  function b58decode(str) {
    str = String(str || "");
    if (!str) return new Uint8Array(0);

    let zeros = 0;
    while (zeros < str.length && str[zeros] === "1") zeros++;

    const bytes = [];
    for (let i = zeros; i < str.length; i++) {
      const c = str[i];
      const val = B58_MAP.get(c);
      if (val == null) throw err("B58_INVALID", "Invalid base58 character", { c });

      let carry = val;
      for (let j = 0; j < bytes.length; j++) {
        carry += bytes[j] * 58;
        bytes[j] = carry & 0xff;
        carry >>= 8;
      }
      while (carry > 0) {
        bytes.push(carry & 0xff);
        carry >>= 8;
      }
    }

    // reverse
    const out = new Uint8Array(zeros + bytes.length);
    for (let i = 0; i < zeros; i++) out[i] = 0;
    for (let i = 0; i < bytes.length; i++) out[out.length - 1 - i] = bytes[i];
    return out;
  }

  // ------------------------------------------------------------
  // b64url helpers (packed bytes)
  // ------------------------------------------------------------
  function u8ToB64url(u8) {
    u8 = u8 instanceof Uint8Array ? u8 : new Uint8Array(u8 || []);
    // Browser
    if (typeof btoa === "function") {
      let s = "";
      for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
      const b64 = btoa(s);
      return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
    // Node fallback
    if (typeof Buffer !== "undefined") {
      return Buffer.from(u8)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
    }
    throw err("NO_B64", "No base64 encoder available");
  }

  function b64urlToU8(b64url) {
    b64url = String(b64url || "");
    const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64url.length + 3) % 4);

    if (typeof atob === "function") {
      const bin = atob(b64);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    if (typeof Buffer !== "undefined") {
      return new Uint8Array(Buffer.from(b64, "base64"));
    }
    throw err("NO_B64", "No base64 decoder available");
  }

  // ------------------------------------------------------------
  // sha256 (WebCrypto preferred)
  // ------------------------------------------------------------
  async function sha256(u8) {
    u8 = u8 instanceof Uint8Array ? u8 : new Uint8Array(u8 || []);
    // If runtime exposes sha256, use it (keeps consistency across builds)
    const rt = getRuntime();
    const fn = pickFn(rt?.sha256, g.sha256);
    if (fn) {
      const out = await fn(u8);
      return out instanceof Uint8Array ? out : new Uint8Array(out);
    }
    // WebCrypto
    const subtle = g.crypto?.subtle;
    if (!subtle?.digest) throw err("NO_SHA256", "No sha256 helper available (need runtime sha256 or crypto.subtle)");
    const buf = await subtle.digest("SHA-256", u8);
    return new Uint8Array(buf);
  }

  // ------------------------------------------------------------
  // Runtime adapter
  // ------------------------------------------------------------
  function getRuntime() {
    // Your runtime is usually g.sanctos already.
    return g.sanctos || null;
  }

  // ------------------------------------------------------------
  // Ready gate (minimal)
  // ------------------------------------------------------------
  async function ready(timeoutMs = 12000) {
    const t0 = Date.now();
    while (Date.now() - t0 < timeoutMs) {
      const rt = getRuntime();
      if (rt && typeof rt.getAnchorProvider === "function") return true;
      await sleep(50);
    }
    throw err("SANCTOS_NOT_READY", "ready() timeout: need sanctos.getAnchorProvider() on this page/build");
  }

  async function getProvider() {
    await ready();
    const rt = getRuntime();
    const fn = pickFn(rt.getAnchorProvider, g.getAnchorProvider);
    if (!fn) throw err("NO_PROVIDER", "getAnchorProvider missing");
    const provider = await fn();
    if (!provider?.connection) throw err("NO_CONNECTION", "Provider has no connection");
    return provider;
  }

  function tryGetWallet58(provider) {
    try {
      const pk = provider?.wallet?.publicKey;
      return pk?.toBase58?.() || "";
    } catch {
      return "";
    }
  }

  function getDelegatePubkey58() {
    try {
      const kp = g.__sanctosDelegateKeypair;
      return kp?.publicKey?.toBase58?.() || "";
    } catch {
      return "";
    }
  }

  function hasLocalDeviceKey(me58) {
    me58 = String(me58 || "");
    // Your runtime often uses a cluster-aware key, keep best-effort checks:
    try {
      const cluster = String(g.SANCTOS_CLUSTER_STORAGE || g.SANCTOS_CLUSTER || "mainnet").trim();
      const k = `sanctos:x25519:${cluster}:${me58}`;
      if (localStorage.getItem(k)) return true;
    } catch {}

    try {
      const f = g.deviceStoreKey;
      if (typeof f === "function") {
        const k2 = f(me58);
        if (k2 && localStorage.getItem(k2)) return true;
      }
    } catch {}

    // heuristic fallback
    try {
      for (const k of Object.keys(localStorage)) {
        if (k.includes(me58) && k.toLowerCase().includes("device")) return true;
      }
    } catch {}

    return false;
  }

  // ------------------------------------------------------------
  // Capabilities (feature detect)
  // ------------------------------------------------------------
  function capabilities() {
    const rt = getRuntime() || {};
    return {
      walletSend: !!pickFn(rt.postMessage, rt.postSanctosMsg, rt.postMessageWallet),
      delegateMemoSend: !!pickFn(rt.postMessageDelegated),
      delegatePointer: !!pickFn(rt.postSanctosMsgDelegated),
      publishIdentity: !!pickFn(rt.publishIdentityWithDelegateInit),
      packedHelpers: true,
      fetch: typeof rt.fetchMessages === "function",
      sync: typeof rt.syncPair === "function" || typeof rt.fetchMessages === "function",
    };
  }

  // ------------------------------------------------------------
  // Memo parsing helpers (SANCTOS_MSG / SANCTOS_PUBKEY)
  // ------------------------------------------------------------
  function isSanctosMsgMemo(s) {
    return typeof s === "string" && s.startsWith("SANCTOS_MSG:");
  }

  function toMsgMemo(owner58, packedU8) {
    const b64url = u8ToB64url(packedU8);
    return `SANCTOS_MSG:${String(owner58 || "").trim()}:${b64url}`;
  }

  function fromMsgMemo(memoStr) {
    try {
      const s = String(memoStr || "");
      if (!isSanctosMsgMemo(s)) return null;
      const parts = s.split(":");
      if (parts.length < 3) return null;
      const owner58 = parts[1];
      const b64url = parts.slice(2).join(":"); // tolerate extra ":" just in case
      const packed = b64urlToU8(b64url);
      return { owner58, packed };
    } catch {
      return null;
    }
  }

  function toPubkeyMemo(owner58, devicePubB64url, atMs) {
    const ts = Number.isFinite(atMs) ? Math.floor(atMs) : Date.now();
    return `SANCTOS_PUBKEY:${String(owner58 || "").trim()}:${String(devicePubB64url || "").trim()}:${ts}`;
  }

  function fromPubkeyMemo(memoStr) {
    try {
      const s = String(memoStr || "");
      if (!s.startsWith("SANCTOS_PUBKEY:")) return null;
      const parts = s.split(":");
      if (parts.length < 4) return null;
      const owner58 = parts[1];
      const devicePubB64url = parts[2];
      const atMs = Number(parts[3]);
      return { owner58, devicePubB64url, atMs: Number.isFinite(atMs) ? atMs : undefined };
    } catch {
      return null;
    }
  }

  // ------------------------------------------------------------
  // Extract memo string from an on-chain transaction (RPC getTransaction)
  // and derive packed + pointer32.
  // ------------------------------------------------------------
  const MEMO_PID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

  function getMessageAccountKeys(msg) {
    // getTransaction formats differ (jsonParsed, legacy, versioned)
    // Aim to return an array of pubkey base58 strings.
    const keys = msg?.accountKeys;
    if (!keys) return [];
    // Sometimes it's array of strings
    if (Array.isArray(keys) && typeof keys[0] === "string") return keys;
    // Sometimes it's array of objects like { pubkey, signer, writable }
    if (Array.isArray(keys) && keys[0] && typeof keys[0] === "object") {
      return keys.map((k) => (k?.pubkey?.toBase58?.() ? k.pubkey.toBase58() : String(k?.pubkey || k)));
    }
    return [];
  }

  function ixProgramId58(ix, accountKeys58) {
    try {
      // compiled ix: { programIdIndex, accounts, data }
      const idx = ix?.programIdIndex;
      if (typeof idx === "number" && accountKeys58?.[idx]) return accountKeys58[idx];
      // already expanded ix might have programId
      const pid = ix?.programId?.toBase58?.() || ix?.programId;
      if (pid) return String(pid);
      return "";
    } catch {
      return "";
    }
  }

  function ixDataU8(ix) {
    // compiled ix data is base58 string; expanded may be Uint8Array/Buffer
    const d = ix?.data;
    if (!d) return new Uint8Array(0);
    if (d instanceof Uint8Array) return d;
    // Buffer
    if (typeof Buffer !== "undefined" && Buffer.isBuffer(d)) return new Uint8Array(d);
    // string -> base58 decode
    if (typeof d === "string") return b58decode(d);
    // array-like
    try {
      return new Uint8Array(d);
    } catch {
      return new Uint8Array(0);
    }
  }

  function u8ToUtf8(u8) {
    u8 = u8 instanceof Uint8Array ? u8 : new Uint8Array(u8 || []);
    try {
      return new TextDecoder().decode(u8);
    } catch {
      // Node fallback
      if (typeof Buffer !== "undefined") return Buffer.from(u8).toString("utf8");
      let s = "";
      for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
      return s;
    }
  }

  async function fetchPackedFromTxSig(sig, commitment = "confirmed") {
    const provider = await getProvider();
    const conn = provider.connection;

    // getTransaction options differ across web3 versions
    let tx;
    try {
      tx = await conn.getTransaction(sig, {
        commitment,
        maxSupportedTransactionVersion: 0,
      });
    } catch {
      tx = await conn.getTransaction(sig, commitment);
    }

    if (!tx?.transaction?.message) throw err("TX_NOT_FOUND", "Transaction not available via getTransaction yet", { sig });

    const msg = tx.transaction.message;
    const accountKeys58 = getMessageAccountKeys(msg);

    const ixs = msg.instructions || [];
    for (const ix of ixs) {
      const pid58 = ixProgramId58(ix, accountKeys58);
      if (pid58 !== MEMO_PID) continue;

      const memoBytes = ixDataU8(ix);
      const memoStr = u8ToUtf8(memoBytes);

      const parsed = fromMsgMemo(memoStr);
      if (parsed?.packed) return parsed;
    }

    throw err("NO_MEMO", "Could not find SANCTOS_MSG memo in transaction", { sig });
  }

  async function pointer32FromPacked(packed) {
    const digest = await sha256(packed);
    return digest.slice(0, 32);
  }

  // ------------------------------------------------------------
  // Key resolution (uses your handshake + caches if present)
  // ------------------------------------------------------------
  async function resolvePeerDeviceKey(peer58, opts = {}) {
    peer58 = norm58(peer58);
    if (!peer58) throw err("PEER_MISSING", "resolvePeerDeviceKey: peer58 missing");

    const rt = getRuntime();
    const provider = await getProvider();
    const mePk = provider.wallet.publicKey;

    // Ensure bs58 global if your runtime expects it (keep your convention)
    try {
      if (!g.bs58 && typeof g.bs58mod !== "undefined") g.bs58 = g.bs58mod;
    } catch {}

    const sol = (g.solanaWeb3 || g.web3 || (g.anchor && g.anchor.web3));
    const PublicKey = sol?.PublicKey || provider.wallet.publicKey?.constructor;
    if (!PublicKey) throw err("NO_PUBLICKEY", "No web3 PublicKey available");

    const peerPk = new PublicKey(peer58);

    // Optional: ensureHandshake
    if (opts.handshake !== false) {
      const fnHandshake = pickFn(rt.ensureHandshake, g.ensureHandshake);
      if (fnHandshake) {
        await fnHandshake(provider, mePk, peerPk);
      }
    }

    const fnGetCached = pickFn(rt.getCachedPeerDevKey);
    const fnCache = pickFn(rt.cachePeerDevKey);
    const fnFind = pickFn(rt.findPeerDevicePubkey);

    let peerDev = null;
    if (fnGetCached) {
      try { peerDev = fnGetCached(mePk, peerPk); } catch {}
    }
    if (!peerDev && fnFind) {
      peerDev =
        (await fnFind(provider, mePk, peerPk)) ||
        (await fnFind(provider, peerPk, mePk)) ||
        null;
    }
    if (peerDev && fnCache) {
      try { fnCache(mePk, peerPk, peerDev); } catch {}
    }

    if (!peerDev) throw err("PEER_DEVICE_KEY_NOT_FOUND", "Peer device pubkey not found (peer must publish once)");
    return peerDev instanceof Uint8Array ? peerDev : new Uint8Array(peerDev);
  }

  function getCachedPeerDeviceKey(peer58) {
    try {
      const rt = getRuntime();
      const fnGetCached = pickFn(rt.getCachedPeerDevKey);
      if (!fnGetCached) return null;
      // best effort requires provider/mePk; we can only do this if provider already exists
      // so return null if we can't.
      // (Advanced callers should call resolvePeerDeviceKey() instead.)
      return null;
    } catch {
      return null;
    }
  }

  // ------------------------------------------------------------
  // Packed crypto (preserves your deriveSharedKey + secretbox)
  // ------------------------------------------------------------
  async function encryptPacked(peer58, plaintext, opts = {}) {
    peer58 = norm58(peer58);
    plaintext = typeof plaintext === "string" ? plaintext : String(plaintext ?? "");

    const rt = getRuntime();
    const provider = await getProvider();
    const mePk = provider.wallet.publicKey;

    const sol = (g.solanaWeb3 || g.web3 || (g.anchor && g.anchor.web3));
    const PublicKey = sol?.PublicKey || provider.wallet.publicKey?.constructor;
    if (!PublicKey) throw err("NO_PUBLICKEY", "No web3 PublicKey available");
    const peerPk = new PublicKey(peer58);

    // Ensure local + peer keys available
    const fnGetDev = pickFn(rt.getDeviceKeypair, g.getDeviceKeypair);
    if (!fnGetDev) throw err("NO_DEVICE_KEYPAIR", "Runtime missing getDeviceKeypair() needed for encryption");
    const myDev = fnGetDev(mePk);

    let peerDevPub = opts.peerDevPubOverride || null;
    if (!peerDevPub) peerDevPub = await resolvePeerDeviceKey(peer58, { handshake: true });

    // shared key
    let sharedKey = null;
    const fnDerive = pickFn(rt.deriveSharedKey, g.deriveSharedKey);
    if (fnDerive) {
      sharedKey = fnDerive(myDev.secretKey, peerDevPub);
    } else {
      // fallback: nacl.box.before if available and keys are compatible
      const nacl = g.nacl || g.tweetnacl || (globalThis || {}).nacl;
      if (!nacl?.box?.before) throw err("NO_SHAREDKEY", "No deriveSharedKey() and no nacl.box.before fallback available");
      sharedKey = nacl.box.before(peerDevPub, myDev.secretKey);
    }

    // encrypt: prefer runtime encryptMessage for exact behavior; fallback to nacl.secretbox
    const fnEncrypt = pickFn(rt.encryptMessage, g.encryptMessage);
    if (fnEncrypt) {
      const out = fnEncrypt(sharedKey, plaintext);
      const nonce = out?.nonce instanceof Uint8Array ? out.nonce : new Uint8Array(out?.nonce || []);
      const cipher = out?.cipher instanceof Uint8Array ? out.cipher : new Uint8Array(out?.cipher || []);
      const packed = new Uint8Array(nonce.length + cipher.length);
      packed.set(nonce, 0);
      packed.set(cipher, nonce.length);
      return packed;
    }

    const nacl = g.nacl || g.tweetnacl || (globalThis || {}).nacl;
    if (!nacl?.secretbox) throw err("NO_ENCRYPT", "No encryptMessage() and no nacl.secretbox available");
    const nonce = nacl.randomBytes(24);
    const msgBytes = new TextEncoder().encode(plaintext);
    const cipher = nacl.secretbox(msgBytes, nonce, sharedKey);
    const packed = new Uint8Array(nonce.length + cipher.length);
    packed.set(nonce, 0);
    packed.set(cipher, nonce.length);
    return packed;
  }

  async function decryptPacked(peer58, packedU8, opts = {}) {
    peer58 = norm58(peer58);
    packedU8 = packedU8 instanceof Uint8Array ? packedU8 : new Uint8Array(packedU8 || []);

    const rt = getRuntime();
    const provider = await getProvider();
    const mePk = provider.wallet.publicKey;

    const sol = (g.solanaWeb3 || g.web3 || (g.anchor && g.anchor.web3));
    const PublicKey = sol?.PublicKey || provider.wallet.publicKey?.constructor;
    if (!PublicKey) throw err("NO_PUBLICKEY", "No web3 PublicKey available");
    const peerPk = new PublicKey(peer58);

    const fnGetDev = pickFn(rt.getDeviceKeypair, g.getDeviceKeypair);
    if (!fnGetDev) throw err("NO_DEVICE_KEYPAIR", "Runtime missing getDeviceKeypair() needed for decryption");
    const myDev = fnGetDev(mePk);

    let peerDevPub = opts.peerDevPubOverride || null;
    if (!peerDevPub) peerDevPub = await resolvePeerDeviceKey(peer58, { handshake: false });

    let sharedKey = null;
    const fnDerive = pickFn(rt.deriveSharedKey, g.deriveSharedKey);
    if (fnDerive) {
      sharedKey = fnDerive(myDev.secretKey, peerDevPub);
    } else {
      const nacl = g.nacl || g.tweetnacl || (globalThis || {}).nacl;
      if (!nacl?.box?.before) throw err("NO_SHAREDKEY", "No deriveSharedKey() and no nacl.box.before fallback available");
      sharedKey = nacl.box.before(peerDevPub, myDev.secretKey);
    }

    // decrypt: prefer runtime decryptMessage; fallback to nacl.secretbox.open
    const fnDecrypt = pickFn(rt.decryptMessage, g.decryptMessage);
    if (fnDecrypt) return String(fnDecrypt(sharedKey, packedU8) ?? "");

    const nacl = g.nacl || g.tweetnacl || (globalThis || {}).nacl;
    if (!nacl?.secretbox?.open) throw err("NO_DECRYPT", "No decryptMessage() and no nacl.secretbox.open available");

    const nonce = packedU8.slice(0, 24);
    const cipher = packedU8.slice(24);
    const msg = nacl.secretbox.open(cipher, nonce, sharedKey);
    if (!msg) throw err("DECRYPT_FAIL", "secretbox.open failed");
    return new TextDecoder().decode(msg);
  }

  // ------------------------------------------------------------
  // Identity API (publish uses your idempotent atomic tx if present)
  // ------------------------------------------------------------
  async function getMe() {
    const provider = await getProvider();
    const wallet58 = tryGetWallet58(provider);
    const delegate58 = getDelegatePubkey58();
    return {
      wallet58,
      delegate58: delegate58 || "",
      hasLocalDeviceKey: wallet58 ? hasLocalDeviceKey(wallet58) : false,
      delegateEnabled: !!(delegate58 && g.__sanctosDelegateEnabled !== false),
    };
  }

  async function ensureLocalIdentity(opts = {}) {
    const rt = getRuntime();
    const provider = await getProvider();
    const me58 = tryGetWallet58(provider);
    if (!me58) throw err("WALLET_NOT_READY", "Wallet not connected");

    // Non-invasive best-effort: call a runtime helper if you have it
    const fn = pickFn(rt.ensureLocalDeviceIdentity, rt.ensureDeviceIdentityOnConnect, g.ensureLocalDeviceIdentity, g.ensureDeviceIdentityOnConnect);
    if (fn) {
      try {
        await fn(me58, provider);
      } catch (e) {
        emitter.emit("error", { kind: "ensureLocalIdentity", error: e });
        // do not hard fail; caller can still proceed
      }
    }

    // Optional interactive gate if present
    if (opts?.interactive) {
      const gate = pickFn(rt.openIdentityGate, rt.showIdentityGate, g.openIdentityGate, g.showIdentityGate);
      if (gate) {
        try { await gate(); }
        catch (e) { emitter.emit("error", { kind: "identityGate", error: e }); }
      }
    }
  }

  async function publishIdentity(opts = {}) {
    const rt = getRuntime();
    const fn = pickFn(rt.publishIdentityWithDelegateInit, g.publishIdentityWithDelegateInit);
    if (!fn) throw err("NO_PUBLISH", "publishIdentityWithDelegateInit() not available in this build/runtime");

    if (opts?.interactive) {
      await ensureLocalIdentity({ interactive: true });
    } else {
      await ensureLocalIdentity({ interactive: false });
    }

    const res = await fn(await getProvider());
    try {
      emitter.emit("identity", await getMe());
    } catch {}
    return res;
  }

  // ------------------------------------------------------------
  // Messaging send (pointers REQUIRED)
  // ------------------------------------------------------------
  async function send(peer58, plaintext, opts = {}) {
    peer58 = norm58(peer58);
    if (!peer58) throw err("PEER_MISSING", "send: peer58 missing");

    plaintext = typeof plaintext === "string" ? plaintext : String(plaintext ?? "");
    const route = String(opts.route || "wallet");

    const rt = getRuntime();
    const provider = await getProvider();
    const conn = provider.connection;

    // Ensure identity is published if needed (best-effort, do not auto-tx unless developer calls publish())
    // We do NOT auto-call publishIdentity() here to avoid unexpected tx prompts.

    // -------------------------
    // WALLET route (atomic)
    // -------------------------
    if (route === "wallet") {
      const fnWalletSend = pickFn(
        rt.postMessage,
        rt.postSanctosMsg,
        rt.postMessageWallet,
        g.postMessage,
        g.postSanctosMsg
      );
      if (!fnWalletSend) throw err("NO_WALLET_SEND", "No wallet send function found (need sanctos.postMessage or sanctos.postSanctosMsg)");

      const sig = await fnWalletSend(peer58, plaintext, opts);

      // Derive pointer32 by reading the tx memo (best-effort, but normally works)
      let pointer32 = null;
      try {
        const parsed = await fetchPackedFromTxSig(sig, "confirmed");
        pointer32 = await pointer32FromPacked(parsed.packed);
      } catch (e) {
        // Keep send working even if RPC doesn't return tx yet
        emitter.emit("error", { kind: "pointerDerive", route, sig, error: e });
      }

      return { memoSig: sig, pointerSig: sig, pointer32 };
    }

    // -------------------------
    // DELEGATE route (2-step)
    // -------------------------
    if (route === "delegate") {
      const fnDelMemo = pickFn(rt.postMessageDelegated, g.postMessageDelegated);
      if (!fnDelMemo) throw err("NO_DELEGATE_MEMO", "Delegate memo send missing (need sanctos.postMessageDelegated)");

      const memoSig = await fnDelMemo(peer58, plaintext, opts);

      // Extract packed from the delegated memo TX (NO re-encrypt)
      const parsed = await fetchPackedFromTxSig(memoSig, "confirmed");
      const pointer32 = await pointer32FromPacked(parsed.packed);

      const fnPtr = pickFn(rt.postSanctosMsgDelegated, g.postSanctosMsgDelegated);
      if (!fnPtr) throw err("NO_DELEGATE_POINTER", "Delegate pointer update missing (need sanctos.postSanctosMsgDelegated)");

      const pointerSig = await fnPtr(peer58, pointer32);

      return { memoSig, pointerSig, pointer32 };
    }

    // -------------------------
    // AGENT route (placeholder)
    // - This standalone file can support agent mode later via injected keyring + transport,
    //   but your requirement here is "pointers necessary" => agent must be able to sign and send Solana txs.
    // - For now we expose packed helpers for "privacy layer only" use-cases.
    // -------------------------
    if (route === "agent") {
      throw err(
        "AGENT_NOT_IMPLEMENTED",
        "route:'agent' not implemented in this standalone v3 yet. Use packed.encrypt()/toMsgMemo() for off-chain privacy layer, or provide a headless Solana signer transport in a future v3.x.",
        { hint: "Implement agent transport: build memo+pointer tx, sign, send." }
      );
    }

    throw err("BAD_ROUTE", "Unknown route. Expected 'wallet' | 'delegate' | 'agent'.", { route });
  }

  // ------------------------------------------------------------
  // Receive/fetch/sync/getMessages — adapt to runtime, keep SDK store optional
  // ------------------------------------------------------------
  const __msgStore = (g.__sanctosApiMsgStore ||= new Map()); // peer58 -> msgs[]
  const __seenByPeer = (g.__sanctosApiMsgSeen ||= new Map()); // peer58 -> Set(sig)

  function msgSig(m) {
    return String(m?.sig || m?.signature || m?.txid || m?.id || "") || "";
  }

  function storeUpsert(peer58, msgs) {
    peer58 = norm58(peer58);
    if (!peer58) return;
    const arr = __msgStore.get(peer58) || [];
    const seen = __seenByPeer.get(peer58) || new Set();
    if (!__seenByPeer.has(peer58)) __seenByPeer.set(peer58, seen);
    for (const m of msgs || []) {
      if (!m) continue;
      const s = msgSig(m);
      if (s && seen.has(s)) continue;
      if (s) seen.add(s);
      arr.push(m);
    }
    __msgStore.set(peer58, arr);
  }

  async function fetch(peer58, opts = {}) {
    peer58 = norm58(peer58);
    if (!peer58) throw err("PEER_MISSING", "fetch: peer58 missing");
    await ready();

    const rt = getRuntime();
    if (typeof rt.fetchMessages !== "function") throw err("NO_FETCH", "Runtime missing fetchMessages()");

    const out = await rt.fetchMessages(peer58, {
      ...opts,
      onMessage: (m) => {
        try { storeUpsert(peer58, [m]); } catch {}
        try { if (typeof opts.onMessage === "function") opts.onMessage(m); } catch {}
        emitter.emit("message", { peer: peer58, msg: m });
      },
    });

    return out;
  }

  async function sync(peer58, opts = {}) {
    peer58 = norm58(peer58);
    if (!peer58) throw err("PEER_MISSING", "sync: peer58 missing");
    await ready();

    const rt = getRuntime();

    if (typeof rt.syncPair === "function") {
      const res = await rt.syncPair(peer58, opts);
      try {
        if (Array.isArray(res?.messages) && res.messages.length) storeUpsert(peer58, res.messages);
      } catch {}
      emitter.emit("messages", { peer: peer58, ...res });
      return res;
    }

    // fallback: fetch then snapshot
    await fetch(peer58, { limit: opts.limit });
    const messages = getMessages(peer58);
    const payload = { peer: peer58, messages, lastAt: messages?.at?.(-1)?.at || 0 };
    emitter.emit("messages", payload);
    return payload;
  }

  function getMessages(peer58) {
    peer58 = norm58(peer58);
    if (!peer58) return [];

    // Prefer runtime cached store if available (optional)
    const rt = getRuntime();
    const fn = pickFn(rt.getCachedMessages);
    if (fn) {
      try {
        const one = fn(peer58);
        if (Array.isArray(one) && one.length) return one;
      } catch {}
    }

    // SDK store
    try {
      const arr = __msgStore.get(peer58);
      if (Array.isArray(arr)) return arr;
    } catch {}
    return [];
  }

  // ------------------------------------------------------------
  // Attach API v3
  // ------------------------------------------------------------
  g.sanctos.api = g.sanctos.api || {};
  Object.assign(g.sanctos.api, {
    version: "0.3.0",

    // lifecycle
    init: async function init(_opts = {}) {
      // For now, standalone v3 is adapter-first.
      // Future: accept keyring/transport here for agent mode.
      await ready();
      emitter.emit("identity", await getMe());
    },
    ready,
    capabilities,

    // identity
    identity: {
      getMe,
      ensureLocal: ensureLocalIdentity,
      publish: publishIdentity,
    },

    // keys + packed
    keys: {
      resolvePeerDeviceKey,
      getCachedPeerDeviceKey,
    },

    packed: {
      encrypt: encryptPacked,
      decrypt: decryptPacked,
      pointer32: pointer32FromPacked,
      toMsgMemo,
      fromMsgMemo,
      toPubkeyMemo,
      fromPubkeyMemo,
      isSanctosMsgMemo,
      b64urlToU8,
      u8ToB64url,
    },

    // messaging
    send,
    fetch,
    sync,
    getMessages,

    // events
    on: emitter.on,

    // raw escape hatch
    raw: g.sanctos,
  });

  console.log("[SanctOS SDK v3] ✅ attached:", g.sanctos.api.version);
// ============================================================
  // 🤖 sanctos.api.agent — Headless agent identity + messaging
  // Works outside the browser: Node.js, Cloudflare Workers, etc.
  // Usage:
  //   const agent = await sanctos.api.agent.init(keypair, { rpcUrl, nacl });
  //   await agent.publish();
  //   await agent.send("RecipientPubkey58", "hello");
  //   const msgs = await agent.inbox();
  // ============================================================
  function createAgentInstance(keypair, opts = {}) {
    const { Connection, PublicKey, Transaction, TransactionInstruction } =
      opts.web3 || g.solanaWeb3 || g.web3 || {};

    if (!Connection || !PublicKey)
      throw err("AGENT_NO_WEB3", "agent.init: pass opts.web3 = require('@solana/web3.js') or load solanaWeb3 globally");

    const nacl = opts.nacl || g.nacl || g.tweetnacl;
    if (!nacl?.box)
      throw err("AGENT_NO_NACL", "agent.init: pass opts.nacl = require('tweetnacl') or load nacl globally");

    const rpcUrl  = opts.rpcUrl  || g.__SANCTOS_RPC_URL || "https://sanctos-rpc-node.sanctos.workers.dev";
    const cluster = opts.cluster || "mainnet";
    const conn    = opts.connection || new Connection(rpcUrl, "confirmed");

    const ownerKp = keypair;
    const ownerPk = ownerKp.publicKey;
    const owner58 = ownerPk.toBase58();

    // ── Device (x25519) key — derived deterministically from owner signing key ──
    const _deviceKp = (() => {
      const seedMsg = new TextEncoder().encode(`sanctos:device:${owner58}`);
      const signed  = nacl.sign(seedMsg, ownerKp.secretKey);
      const seed    = signed.slice(0, 32);
      return nacl.box.keyPair.fromSecretKey(seed);
    })();

    const devicePub58 = u8ToB64url(_deviceKp.publicKey);

    // ── Peer device key cache ──
    const _peerDevCache = new Map();

    async function resolveAgentPeerDevKey(peer58) {
      if (_peerDevCache.has(peer58)) return _peerDevCache.get(peer58);

      const peerPk = new PublicKey(peer58);
      const sigs   = await conn.getSignaturesForAddress(peerPk, { limit: 50 });

      for (const { signature } of sigs) {
        const tx = await conn.getTransaction(signature, { maxSupportedTransactionVersion: 0 });
        if (!tx) continue;

        const msg  = tx.transaction?.message;
        const ixs  = msg?.instructions || [];
        const keys = msg?.staticAccountKeys || msg?.accountKeys || [];

        for (const ix of ixs) {
          try {
            const pid = keys[ix.programIdIndex]?.toBase58?.() || "";
            if (pid !== "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr") continue;

            let memo = "";
            try { memo = new TextDecoder().decode(b58decode(ix.data)); } catch {}
            if (!memo) try { memo = String(ix.data || ""); } catch {}

            if (!memo.startsWith("SANCTOS_PUBKEY:")) continue;
            const parts = memo.split(":");
            if (parts.length < 3) continue;
            if (parts[1] !== peer58) continue;

            const devPubU8 = b64urlToU8(parts[2]);
            _peerDevCache.set(peer58, devPubU8);
            return devPubU8;
          } catch {}
        }
      }
      throw err("PEER_DEVICE_NOT_FOUND", `No SANCTOS_PUBKEY memo found for ${peer58}`);
    }

    // ── Encryption / decryption ──
    function agentEncrypt(peerDevPubU8, plaintext) {
      const sharedKey = nacl.box.before(peerDevPubU8, _deviceKp.secretKey);
      const nonce     = nacl.randomBytes(24);
      const msgBytes  = new TextEncoder().encode(plaintext);
      const cipher    = nacl.secretbox(msgBytes, nonce, sharedKey);
      const packed    = new Uint8Array(nonce.length + cipher.length);
      packed.set(nonce, 0);
      packed.set(cipher, nonce.length);
      return packed;
    }

    function agentDecrypt(peerDevPubU8, packedU8) {
      const sharedKey = nacl.box.before(peerDevPubU8, _deviceKp.secretKey);
      const nonce     = packedU8.slice(0, 24);
      const cipher    = packedU8.slice(24);
      const plain     = nacl.secretbox.open(cipher, nonce, sharedKey);
      if (!plain) throw err("DECRYPT_FAIL", "Agent decrypt failed — wrong key or corrupted message");
      return new TextDecoder().decode(plain);
    }

    // ── Memo instruction builder ──
    function memoIx(text, signerPk) {
      const MEMO_PROGRAM = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
      return new TransactionInstruction({
        keys: [{ pubkey: signerPk, isSigner: true, isWritable: false }],
        programId: MEMO_PROGRAM,
        data: Buffer.from(text, "utf8"),
      });
    }

    // ── Hand-encoded SystemProgram transfer ix (avoids BigInt encoding issues) ──
    function transferIx(fromPk, toPk, lamports) {
      const SYSTEM_PROGRAM = new PublicKey("11111111111111111111111111111111");
      const buf = new Uint8Array(12);
      new DataView(buf.buffer).setUint32(0, 2, true);
      new DataView(buf.buffer).setBigUint64(4, BigInt(lamports), true);
      return new TransactionInstruction({
        keys: [
          { pubkey: fromPk, isSigner: true,  isWritable: true },
          { pubkey: toPk,   isSigner: false, isWritable: true },
        ],
        programId: SYSTEM_PROGRAM,
        data: buf,
      });
    }

    // ── Treasury fee helpers ──
    function _feePaidKey() { return `sanctos:acctfee:paid:${cluster}:${owner58}`; }
    function _markFeePaid() { try { g.localStorage?.setItem(_feePaidKey(), "1"); } catch {} }
    function _isFeePaid()   { try { return !!g.localStorage?.getItem(_feePaidKey()); } catch { return false; } }

    // ── Send a tx ──
    async function _sendTx(instructions) {
      const { blockhash } = await conn.getLatestBlockhash();
      const tx = new Transaction();
      tx.recentBlockhash = blockhash;
      tx.feePayer = ownerPk;
      for (const ix of instructions) tx.add(ix);
      tx.sign(ownerKp);
      const raw = tx.serialize();
      const sig = await conn.sendRawTransaction(raw, { skipPreflight: false });
      await conn.confirmTransaction(sig, "confirmed");
      return sig;
    }

    // ── Public API ──
    return {
      pubkey:       owner58,
      devicePubkey: devicePub58,

      // Publish SANCTOS_PUBKEY on-chain (one-time, idempotent)
      async publish() {
        const TREASURY     = opts.treasury || "FhUFtN9MngoRj7YW1eYw57TxsYsTJ5xyMwMmdifxmwBi";
        const FEE_LAMPORTS = typeof opts.feeLamports !== "undefined"
          ? BigInt(opts.feeLamports)
          : 10_000_000n; // 0.01 SOL

        const treasuryPk = new PublicKey(TREASURY);
        const memo = `SANCTOS_PUBKEY:${owner58}:${devicePub58}:${Date.now()}`;

        const sig = await _sendTx([
          transferIx(ownerPk, treasuryPk, FEE_LAMPORTS),
          memoIx(memo, ownerPk),
        ]);
        _markFeePaid();
        console.log(`[SanctOS Agent] ✅ Identity published + ${Number(FEE_LAMPORTS) / 1e9} SOL fee paid: ${sig}`);
        return sig;
      },

      // Check if identity is already published
      async isPublished() {
        // ✅ Check local cache first — avoids RPC call on every run
        if (_isFeePaid()) return true;
        try {
          await resolveAgentPeerDevKey(owner58);
          _markFeePaid(); // cache for next time
          return true;
        } catch {
          return false;
        }
      },

      // Send an encrypted message to a peer
      async send(peer58, plaintext) {
        peer58 = norm58(peer58);
        if (!peer58) throw err("PEER_MISSING", "agent.send: peer58 required");

        const peerDevPub = await resolveAgentPeerDevKey(peer58);
        const packed     = agentEncrypt(peerDevPub, plaintext);
        const packedB64  = u8ToB64url(packed);
        const memo       = `SANCTOS_MSG:${owner58}:${packedB64}`;
        const peerPk     = new PublicKey(peer58);

        // ✅ 0-lamport transfer to recipient — makes tx appear in their
        //    getSignaturesForAddress history without requiring their signature
        const sig = await _sendTx([
          transferIx(ownerPk, peerPk, 0n),
          memoIx(memo, ownerPk),
        ]);
        console.log(`[SanctOS Agent] ✅ Message sent to ${peer58.slice(0, 8)}…: ${sig}`);
        return { sig, peer58, plaintext };
      },

      // Fetch and decrypt messages from a specific peer
      async fetchFrom(peer58, fetchOpts = {}) {
        peer58 = norm58(peer58);
        const limit      = fetchOpts.limit || 50;
        const peerPk     = new PublicKey(peer58);
        const peerDevPub = await resolveAgentPeerDevKey(peer58);
        const sigs       = await conn.getSignaturesForAddress(peerPk, { limit });
        const messages   = [];

        for (const { signature } of sigs) {
          try {
            const tx   = await conn.getTransaction(signature, { maxSupportedTransactionVersion: 0 });
            if (!tx) continue;
            const msg  = tx.transaction?.message;
            const ixs  = msg?.instructions || [];
            const keys = msg?.staticAccountKeys || msg?.accountKeys || [];

            for (const ix of ixs) {
              const pid = keys[ix.programIdIndex]?.toBase58?.() || "";
              if (pid !== "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr") continue;

              let memo = "";
              try { memo = new TextDecoder().decode(b58decode(ix.data)); } catch {}
              if (!memo.startsWith("SANCTOS_MSG:")) continue;

              const parts = memo.split(":");
              if (parts.length < 3) continue;
              if (parts[1] !== peer58) continue;

              const text = agentDecrypt(peerDevPub, b64urlToU8(parts[2]));
              messages.push({ sig: signature, from: peer58, text, at: (tx.blockTime || 0) * 1000 });
            }
          } catch {}
        }

        return messages.sort((a, b) => a.at - b.at);
      },

      // Fetch and decrypt the agent's own inbox
      async inbox(inboxOpts = {}) {
        const limit    = inboxOpts.limit || 100;
        const sigs     = await conn.getSignaturesForAddress(ownerPk, { limit });
        const messages = [];

        for (const { signature } of sigs) {
          try {
            const tx   = await conn.getTransaction(signature, { maxSupportedTransactionVersion: 0 });
            if (!tx) continue;
            const msg  = tx.transaction?.message;
            const ixs  = msg?.instructions || [];
            const keys = msg?.staticAccountKeys || msg?.accountKeys || [];

            for (const ix of ixs) {
              const pid = keys[ix.programIdIndex]?.toBase58?.() || "";
              if (pid !== "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr") continue;

              let memo = "";
              try { memo = new TextDecoder().decode(b58decode(ix.data)); } catch {}
              if (!memo.startsWith("SANCTOS_MSG:")) continue;

              const parts  = memo.split(":");
              if (parts.length < 3) continue;
              const from58 = parts[1];
              if (from58 === owner58) continue; // skip own outgoing msgs

              try {
                const peerDevPub = await resolveAgentPeerDevKey(from58);
                const text       = agentDecrypt(peerDevPub, b64urlToU8(parts[2]));
                messages.push({ sig: signature, from: from58, text, at: (tx.blockTime || 0) * 1000 });
              } catch {}
            }
          } catch {}
        }

        return messages.sort((a, b) => a.at - b.at);
      },
    };
  }

  // ── Add to public API ──
  g.sanctos.api.agent = {
    /**
     * Initialize a headless SanctOS agent.
     *
     * @param {Keypair} keypair — @solana/web3.js Keypair (the agent's identity)
     * @param {object}  opts   — options:
     *   rpcUrl?       {string}       — custom RPC endpoint (default: SanctOS node)
     *   cluster?      {string}       — "mainnet" | "devnet" (default: "mainnet")
     *   connection?   {Connection}   — pre-built Connection (overrides rpcUrl)
     *   web3?         {object}       — require("@solana/web3.js") for Node.js
     *   nacl?         {object}       — require("tweetnacl") for Node.js
     *   treasury?     {string}       — override treasury wallet address
     *   feeLamports?  {number|bigint}— override fee (default: 10_000_000 = 0.01 SOL)
     *
     * @returns agent instance:
     *   agent.pubkey          — agent's Solana address (string)
     *   agent.devicePubkey    — agent's x25519 device key (b64url)
     *   agent.publish()       — publish SANCTOS_PUBKEY + pay treasury fee
     *   agent.isPublished()   — check identity on-chain (cached locally)
     *   agent.send(peer, txt) — encrypt + send to any SanctOS address
     *   agent.fetchFrom(peer) — decrypt messages from a specific peer
     *   agent.inbox()         — decrypt full incoming message history
     *
     * Example (Node.js):
     *   const web3  = require("@solana/web3.js");
     *   const nacl  = require("tweetnacl");
     *   const kp    = web3.Keypair.fromSecretKey(mySecretKeyBytes);
     *   const agent = sanctos.api.agent.init(kp, { web3, nacl });
     *   if (!(await agent.isPublished())) await agent.publish();
     *   await agent.send("RecipientPubkey58", "gm from agent");
     *   const msgs = await agent.inbox();
     */
    init(keypair, opts = {}) {
      return createAgentInstance(keypair, opts);
    },
  };

})();