// Renders installer/art: node render.mjs [outdir] [look.json overrides]
// Needs: npm ci here (three, playwright), Google Chrome, ImageMagick (magick)
// and pngquant. Each picture is rendered at twice its size, shrunk with
// Lanczos, then stored as a palette PNG (a third of the size, no visible
// difference at 1:1).
import { chromium } from 'playwright';
import http from 'node:http'; import fs from 'node:fs'; import path from 'node:path'; import { execFileSync } from 'node:child_process';
const ROOT = path.dirname(new URL(import.meta.url).pathname);
const OUT = path.resolve(process.argv[2] || path.join(ROOT, '..')); fs.mkdirSync(OUT, { recursive: true });
const opts = JSON.parse(process.argv[3] || fs.readFileSync(path.join(ROOT, 'look.json'), 'utf8'));
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.woff2': 'font/woff2' };
const server = http.createServer((q, r) => { const p = path.join(ROOT, decodeURIComponent(q.url.split('?')[0])); let real; try { real = fs.realpathSync(p); } catch { r.writeHead(404); return r.end(); } r.writeHead(200, { 'content-type': MIME[path.extname(p)] || 'application/octet-stream' }); fs.createReadStream(real).pipe(r); });
await new Promise(r => server.listen(0, '127.0.0.1', r));
const browser = await chromium.launch({ channel: 'chrome', headless: true, args: ['--use-angle=metal', '--enable-gpu', '--ignore-gpu-blocklist'] });
const page = await browser.newPage(); page.on('console', m => console.log('[page]', m.text())); page.on('pageerror', e => console.log('[pageerror]', e.message));
await page.goto(`http://127.0.0.1:${server.address().port}/scene.html`); await page.waitForFunction('window.__ready');
const save = (url, f) => fs.writeFileSync(f, Buffer.from(url.split(',')[1], 'base64'));
const big = [[202, 386], [269, 515], [336, 643], [403, 772], [430, 824], [498, 953], [534, 1022]];
const small = [58, 77, 97, 116, 124, 143, 159];
const SS = 2;
// palette PNG: a third of the size, no visible difference at 1:1
const quant = f => execFileSync('pngquant', ['--quality', '85-100', '--speed', '1', '--strip', '--force', '--output', f, f]);
for (const [w, h] of (opts.only === 'icon' ? [] : big.filter(b => !opts.w || opts.w.includes(b[0])))) {
  const tmp = path.join(OUT, `_w${w}.png`);
  save(await page.evaluate(([w, h, o]) => window.renderWelcome(w, h, o), [w * SS, h * SS, opts.welcome || {}]), tmp);
  execFileSync('magick', [tmp, '-filter', 'Lanczos', '-resize', `${w}x${h}!`, '-strip', `PNG24:${path.join(OUT, `welcome-${w}.png`)}`]); fs.rmSync(tmp); quant(path.join(OUT, `welcome-${w}.png`));
  console.log('welcome', w, h);
}
for (const s of (opts.only === 'welcome' ? [] : small.filter(b => !opts.s || opts.s.includes(b)))) {
  const tmp = path.join(OUT, `_i${s}.png`);
  save(await page.evaluate(([s, o]) => window.renderIcon(s, o), [s * 4, opts.icon || {}]), tmp);
  execFileSync('magick', [tmp, '-filter', 'Lanczos', '-resize', `${s}x${s}!`, '-strip', `PNG32:${path.join(OUT, `header-${s}.png`)}`]); fs.rmSync(tmp); quant(path.join(OUT, `header-${s}.png`));
  console.log('icon', s);
}
await browser.close(); server.close();
