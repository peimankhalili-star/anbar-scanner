// Barcode decoding off the page's main thread, so the screen and the camera preview never wait for it.
// The page sends an RGBA frame (its buffer is transferred, not copied) and gets the texts back.
importScripts("zxing-reader.js");
const ready = ZXingWASM.prepareZXingModule({
  overrides: { locateFile: (path, prefix) => path.endsWith(".wasm") ? new URL("zxing_reader.wasm", self.location.href).href : prefix + path },
  fireImmediately: true
});
let oc = null, og = null;
self.onmessage = async e => {
  const { id, w, h, buf, bmp, opts, ping } = e.data;
  try {
    await ready;
    if (ping) { self.postMessage({ id, ok: true, texts: [], offscreen: typeof OffscreenCanvas !== "undefined" }); return; }
    let img;
    if (bmp) {
      // a camera frame handed over as a bitmap: its pixels are read here, not on the page
      if (!oc || oc.width !== bmp.width || oc.height !== bmp.height) { oc = new OffscreenCanvas(bmp.width, bmp.height); og = oc.getContext("2d", { willReadFrequently: true }); }
      og.drawImage(bmp, 0, 0); bmp.close();
      img = og.getImageData(0, 0, oc.width, oc.height);
      // some phones hand out empty (all one colour) bitmaps from video; a real camera picture never is
      const d = img.data, n = d.length >> 2, v0 = d[0] + d[1] * 256 + d[2] * 65536;
      let same = true;
      for (let i = 1; i < 64 && same; i++) { const j = ((i * 7919) % n) << 2; same = d[j] + d[j + 1] * 256 + d[j + 2] * 65536 === v0; }
      if (same) { self.postMessage({ id, ok: true, texts: [], blank: true }); return; }
    } else img = new ImageData(new Uint8ClampedArray(buf), w, h);
    const res = await ZXingWASM.readBarcodes(img, opts);
    self.postMessage({ id, ok: true, texts: res.filter(r => r.isValid && r.text).map(r => r.text) });
  } catch (err) {
    self.postMessage({ id, ok: false, err: String((err && err.message) || err) });
  }
};
