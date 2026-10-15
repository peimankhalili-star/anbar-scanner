// Offline cache for the warehouse scanner. Bump CACHE when any file changes.
const CACHE = "wsc-v3";
const FILES = ["./", "index.html", "locations.js", "zxing-reader.js", "zxing_reader.wasm", "manifest.webmanifest",
  "icon-192.png", "icon-512.png", "Vazirmatn-Regular.woff2", "Vazirmatn-Bold.woff2", "report.html"];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(FILES)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
// cache first, refresh in the background, so the app opens without a network
self.addEventListener("fetch", e => {
  if (e.request.method !== "GET" || new URL(e.request.url).origin !== location.origin) return;
  e.respondWith(caches.open(CACHE).then(async c => {
    const hit = await c.match(e.request, {ignoreSearch: true});
    const net = fetch(e.request).then(r => { if (r.ok) c.put(e.request, r.clone()); return r; }).catch(() => null);
    return hit || (await net) || c.match("index.html");
  }));
});
