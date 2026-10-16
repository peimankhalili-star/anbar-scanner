// Offline cache for the warehouse scanner. Bump CACHE when any file changes.
// Pages and small scripts: network first (a new version shows on the next open when there is internet),
// cache when offline or slow. Large files that never change (barcode reader, fonts, icons): cache first.
const CACHE = "wsc-v7";
const FILES = ["./", "index.html", "locations.js", "zxing-reader.js", "zxing_reader.wasm", "manifest.webmanifest",
  "icon-192.png", "icon-512.png", "Vazirmatn-Regular.woff2", "Vazirmatn-Bold.woff2", "report.html", "parts.js", "wsc-crypto.js"];
const STATIC = /(\.wasm|\.woff2|\.png|zxing-reader\.js)$/;

self.addEventListener("install", e => {
  // "reload": never fill a new cache from the browser's own HTTP cache, which may still hold the old version
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(FILES.map(f => new Request(f, {cache: "reload"})))).then(() => self.skipWaiting()));
});
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", e => {
  if (e.request.method !== "GET") return;
  const url = new URL(e.request.url);
  if (url.origin !== location.origin) return;
  const key = url.origin + url.pathname;
  if (STATIC.test(url.pathname)) {
    e.respondWith(caches.open(CACHE).then(async c => (await c.match(key)) ||
      fetch(e.request).then(r => { if (r.ok) c.put(key, r.clone()); return r; })));
    return;
  }
  e.respondWith(caches.open(CACHE).then(async c => {
    const net = fetch(new Request(url.href, {cache: "no-cache", credentials: "same-origin"}))
      .then(r => { if (r.ok) c.put(key, r.clone()); return r; }).catch(() => null);
    const slow = new Promise(res => setTimeout(() => res(null), 4000));
    const r = await Promise.race([net, slow]);
    if (r && r.ok) return r;
    // only a page falls back to index.html; a missing script (manager.js before it exists) just fails to load
    return (await c.match(key)) || (await net) || (e.request.mode === "navigate" && await c.match(url.origin + url.pathname.replace(/[^/]*$/, "") + "index.html")) || Response.error();
  }));
});
