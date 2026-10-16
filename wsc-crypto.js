// Security helpers shared by the scanner (index.html) and the report page (report.html).
// ECDSA P-256 signatures and PBKDF2/AES-GCM come from the browser (WebCrypto); SHA-256 for the record chain
// is computed here synchronously so a scan is saved at once. Nothing here sends data anywhere.
const WSC = (() => {
  "use strict";
  const enc = new TextEncoder();

  // ---------- SHA-256 (sync) ----------
  const K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  function sha256Bytes(msg){
    const bytes = typeof msg === "string" ? enc.encode(msg) : msg;
    const n = bytes.length, total = ((n + 9 + 63) >> 6) << 6;
    const buf = new Uint8Array(total); buf.set(bytes); buf[n] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(total - 4, (n * 8) >>> 0); dv.setUint32(total - 8, Math.floor(n / 0x20000000));
    const H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
    const W = new Uint32Array(64);
    for (let o = 0; o < total; o += 64) {
      for (let i = 0; i < 16; i++) W[i] = dv.getUint32(o + i * 4);
      for (let i = 16; i < 64; i++) {
        const a = W[i - 15], b = W[i - 2];
        const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
        const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
        W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
      }
      let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (let i = 0; i < 64; i++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const t1 = (h + S1 + ((e & f) ^ (~e & g)) + K[i] + W[i]) >>> 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }
    const out = new Uint8Array(32), ov = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) ov.setUint32(i * 4, H[i]);
    return out;
  }
  const hex = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
  const unhex = s => new Uint8Array((s.match(/../g) || []).map(x => parseInt(x, 16)));
  const sha256 = msg => hex(sha256Bytes(msg));

  // ---------- encodings ----------
  function b64u(bytes){
    bytes = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes;
    let s = ""; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function unb64u(s){
    s = String(s || "").replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "=";
    const bin = atob(s), out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  // canonical JSON: sorted keys, no spaces; the exact text that is hashed and signed
  function canon(v){
    if (v === null || typeof v !== "object") return JSON.stringify(v === undefined ? null : v);
    if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
    return "{" + Object.keys(v).filter(k => v[k] !== undefined).sort().map(k => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
  }
  const randHex = n => hex(crypto.getRandomValues(new Uint8Array(n)));

  // ---------- ECDSA P-256 ----------
  const EC = {name: "ECDSA", namedCurve: "P-256"}, SIG = {name: "ECDSA", hash: "SHA-256"};
  async function genKey(extractable){ return crypto.subtle.generateKey(EC, !!extractable, ["sign", "verify"]); }
  async function exportPub(pair){ return b64u(await crypto.subtle.exportKey("raw", pair.publicKey)); }
  const pubCache = new Map();
  async function importPub(pubB64u){
    if (!pubCache.has(pubB64u)) pubCache.set(pubB64u, crypto.subtle.importKey("raw", unb64u(pubB64u), EC, true, ["verify"]));
    return pubCache.get(pubB64u);
  }
  async function sign(privKey, text){ return b64u(await crypto.subtle.sign(SIG, privKey, enc.encode(text))); }
  async function verify(pubB64u, sig, text){
    try { return await crypto.subtle.verify(SIG, await importPub(pubB64u), unb64u(sig), enc.encode(text)); }
    catch(e) { return false; }
  }
  // short fingerprint of a public key, for reading out loud or comparing on screen
  function fp(pubB64u){ const h = sha256(unb64u(pubB64u)).toUpperCase(); return h.slice(0, 4) + "-" + h.slice(4, 8) + "-" + h.slice(8, 12); }
  // signed object: {body, sig}; the signature covers canon(body)
  async function signObj(privKey, body){ return {body, sig: await sign(privKey, canon(body))}; }
  async function verifyObj(pubB64u, o){ return !!(o && o.body && o.sig) && verify(pubB64u, o.sig, canon(o.body)); }

  // ---------- PBKDF2 (PINs, passphrase) and AES-GCM (manager key backup) ----------
  async function pbkdf2(secret, saltHex, iter, bytes){
    const base = await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveBits"]);
    return new Uint8Array(await crypto.subtle.deriveBits({name: "PBKDF2", hash: "SHA-256", salt: unhex(saltHex), iterations: iter}, base, (bytes || 32) * 8));
  }
  async function pinHash(pin, salt, iter){
    salt = salt || randHex(16); iter = iter || 150000;
    return {salt, iter, hash: hex(await pbkdf2(String(pin), salt, iter, 32))};
  }
  async function pinCheck(pin, rec){ return !!rec && (await pinHash(pin, rec.salt, rec.iter)).hash === rec.hash; }
  async function aesKey(pass, saltHex, iter){
    return crypto.subtle.importKey("raw", await pbkdf2(pass, saltHex, iter, 32), "AES-GCM", false, ["encrypt", "decrypt"]);
  }
  // the private key leaves the browser only as this encrypted package
  async function sealPriv(privKey, pass){
    const salt = randHex(16), iv = randHex(12), iter = 600000;
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", privKey);
    const ct = await crypto.subtle.encrypt({name: "AES-GCM", iv: unhex(iv)}, await aesKey(pass, salt, iter), pkcs8);
    return {alg: "PBKDF2-SHA256/AES-GCM", salt, iv, iter, ct: b64u(ct)};
  }
  async function openPriv(sealed, pass){
    const pkcs8 = await crypto.subtle.decrypt({name: "AES-GCM", iv: unhex(sealed.iv)}, await aesKey(pass, sealed.salt, sealed.iter), unb64u(sealed.ct));
    return crypto.subtle.importKey("pkcs8", pkcs8, EC, false, ["sign"]);
  }

  // ---------- IndexedDB: the phone's own key pair, kept non-extractable ----------
  function idb(){
    return new Promise((res, rej) => {
      const r = indexedDB.open("wsc-keys", 1);
      r.onupgradeneeded = () => r.result.createObjectStore("kv");
      r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
    });
  }
  async function kvGet(k){ const db = await idb(); return new Promise((res, rej) => { const q = db.transaction("kv").objectStore("kv").get(k); q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error); }); }
  async function kvSet(k, v){ const db = await idb(); return new Promise((res, rej) => { const t = db.transaction("kv", "readwrite"); t.objectStore("kv").put(v, k); t.oncomplete = () => res(true); t.onerror = () => rej(t.error); }); }

  return {sha256, sha256Bytes, hex, unhex, b64u, unb64u, canon, randHex, genKey, exportPub, importPub, sign, verify, fp, signObj, verifyObj,
    pinHash, pinCheck, sealPriv, openPriv, kvGet, kvSet};
})();
