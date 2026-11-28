// Screenshots and videos of the real page on the mock bridge.
//   node capture.mjs shots [name…]     -> out/<name>.png (1440x900 @2x)
//   node capture.mjs videos [name…]    -> out/<name>.mp4 (H.264, 30 fps)
//   OUT=<dir> to write somewhere else; CHANNEL=chromium for Playwright's own browser.
import { chromium } from 'playwright';
import fs from 'node:fs'; import path from 'node:path'; import { execFileSync } from 'node:child_process'; import { fileURLToPath } from 'node:url';
import { start } from './server.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = process.env.OUT || path.join(HERE, 'out'); fs.mkdirSync(OUT, { recursive: true });
const TMP = path.join(HERE, '.frames');
const FFMPEG = process.env.FFMPEG || (fs.existsSync('/opt/homebrew/bin/ffmpeg') ? '/opt/homebrew/bin/ffmpeg' : 'ffmpeg');
const srv = await start(0);
const channel = process.env.CHANNEL || 'chrome';
const browser = await chromium.launch({ channel: channel === 'chromium' ? undefined : channel, headless: true, args: ['--use-angle=metal', '--enable-gpu', '--ignore-gpu-blocklist', '--enable-unsafe-swiftshader', '--hide-scrollbars'] });
const [mode, ...rest] = process.argv.slice(2);

async function open(query, dpr = 2, h = 900, w = 1440) {
  const ctx = await browser.newContext({ viewport: { width: w, height: h }, deviceScaleFactor: dpr }); const page = await ctx.newPage();
  page.on('console', m => { if (m.type() === 'error' || m.type() === 'warning') console.log('[page]', m.text()); }); page.on('pageerror', e => console.log('[pageerror]', e.message));
  await page.goto(srv.url + '?manual=1&' + (/slow=1/.test(query) ? '' : 'fast=1&') + query); await page.waitForFunction(() => window.__abaReady === true, null, { timeout: 30000 });
  await page.evaluate(() => document.fonts.ready);
  return page;
}
const step = (page, from, to, dt = 1 / 10) => page.evaluate(([a, b, d]) => { for (let t = a; t <= b + 1e-6; t += d) window.__aba.frame(t); }, [from, to, dt]);
const settle = page => page.evaluate(() => new Promise(r => setTimeout(r, 120)));

// name -> [query, what to do before the picture]
const SHOTS = {
  '01-home': ['home=protected'],
  '02-home-frozen': ['home=frozen&screen=home'],
  '03-caught': ['home=frozen&screen=caught'],
  '04-report': ['home=frozen&screen=report', 'full'],
  '05-history': ['home=frozen&screen=history'],
  '06-baits': ['home=protected&screen=baits'],
  '07-settings': ['home=protected&screen=settings'],
  '08-locked': ['mode=locked'],
  '09-locked-frozen': ['mode=locked&home=frozen'],
  '10-caught-killed': ['home=frozen&screen=caught', 'kill'],
  '11-report-cannot-tell': ['home=protected&alert=cannot-tell&screen=report', 'full'],
  '12-report-nothing-sent': ['home=frozen&alert=frozen-nothing-sent&screen=report', 'full'],
  '13-caught-hostile': ['home=protected&alert=hostile&screen=caught'],
  '14-report-hostile': ['home=protected&alert=hostile&screen=report', 'full'],
  '15-report-miner': ['home=protected&alert=miner&screen=report', 'full'],
  '16-bait-contents': ['home=protected&screen=baits', 'inside'],
  '17-safe-test-running': ['home=protected&slow=1', 'test'],
  '18-settings-strict': ['home=protected&screen=settings', 'strict'],
  '19-home-alert-only': ['home=protected', 'alertonly'],
  '20-home-light': ['home=protected&tier=light'],
  '21-caught-light': ['home=frozen&screen=caught&tier=light'],
};

if (mode === 'shots') {
  for (const name of (rest.length ? rest : Object.keys(SHOTS))) {
    const [q, what] = SHOTS[name]; let page = await open(q);
    if (what === 'full') { await step(page, 0, 2); const hgt = await page.evaluate(() => { window.__aba.revealAll(); return window.__aba.reportHeight(); }); await page.context().close(); page = await open(q + '&stageh=856', 2, hgt + 44); await page.evaluate(() => window.__aba.revealAll()); }
    await step(page, 0, 9);
    if (what === 'kill') { await page.click('button[data-act=kill]'); await page.waitForSelector('.c-result[data-kind=ok]'); await settle(page); await step(page, 9, 13); }
    if (what === 'inside') { await page.evaluate(() => window.__aba.screens.baits.select('desktop-passwords')); await step(page, 9, 10); await page.click('.bd-btns button'); await page.waitForSelector('.dlg'); await step(page, 10, 12); }
    if (what === 'test') { await page.evaluate(() => { window.__aba.app.runTest(); }); await page.waitForSelector('.tc-steps li:nth-child(2)'); await step(page, 9, 11.6); }
    if (what === 'strict') { await page.click('button[data-preset=strict]'); await settle(page); await step(page, 9, 12); }
    if (what === 'alertonly') { await page.focus('.dial'); await page.keyboard.press('ArrowLeft'); await settle(page); await step(page, 9, 12); }
    await settle(page);
    await page.screenshot({ path: path.join(OUT, name + '.png') }); console.log('shot', name); await page.context().close();
  }
}

if (mode === 'videos') {
  const FPS = 30;
  const plans = {
    // Home comes up: the web draws itself, gems pop, panels slide in
    'v1-home': { q: 'home=protected', dur: 9 },
    // a catch while the app is open: the crawl, the freeze, the ice wave, the Caught screen
    'v2-freeze': { q: 'home=protected', dur: 12, pre: 12, ev: [[.8, () => { window.__abaDev.catchNow('frozen-sent'); window.__aba.present('20261127-140207-7f3a'); }]] },
    // from the catch into the full report, scrolling
    'v3-report': { q: 'home=frozen&screen=caught', dur: 14, pre: 6, ev: [[1.2, () => window.__aba.go('report')]], scroll: [3.4, 13.2] },
    // the app opening on a catch
    'v4-open-on-catch': { q: 'home=frozen&open=1', dur: 8 },
    // the knob: alert only -> balanced -> strict
    'v5-knob': { q: 'home=protected&screen=settings', dur: 8, pre: 5, ev: [[.6, () => document.querySelector('button[data-preset=alert]').click()], [2.8, () => document.querySelector('button[data-preset=balanced]').click()], [5, () => document.querySelector('button[data-preset=strict]').click()]] },
  };
  for (const name of (rest.length ? rest : Object.keys(plans))) {
    const p = plans[name]; fs.rmSync(TMP, { recursive: true, force: true }); fs.mkdirSync(TMP, { recursive: true });
    const page = await open(p.q, 1);
    let t0 = 0; if (p.pre) { await step(page, 0, p.pre); t0 = p.pre; }
    const ev = (p.ev || []).slice(); let maxScroll = 0;
    for (let f = 0; f < p.dur * FPS; f++) {
      const t = f / FPS; while (ev.length && t >= ev[0][0]) { await page.evaluate(ev.shift()[1]); await settle(page); }
      if (p.scroll && t > p.scroll[0]) { if (!maxScroll) maxScroll = await page.evaluate(() => window.__aba.reportHeight() - document.querySelector('#report').clientHeight); const k = Math.min(1, (t - p.scroll[0]) / (p.scroll[1] - p.scroll[0])); const e = k < .5 ? 2 * k * k : 1 - Math.pow(-2 * k + 2, 2) / 2; await page.evaluate(y => window.__aba.scroll(y), e * maxScroll); }
      await page.evaluate(tt => window.__aba.frame(tt), t0 + t);
      await page.screenshot({ path: path.join(TMP, `f${String(f).padStart(4, '0')}.jpg`), type: 'jpeg', quality: 92 });
      if (f % 60 === 0) console.log(name, 'frame', f);
    }
    execFileSync(FFMPEG, ['-y', '-loglevel', 'error', '-framerate', String(FPS), '-i', path.join(TMP, 'f%04d.jpg'), '-c:v', 'libx264', '-preset', 'slow', '-crf', '23', '-pix_fmt', 'yuv420p', '-movflags', '+faststart', path.join(OUT, name + '.mp4')]);
    console.log('video', name); await page.context().close();
  }
  fs.rmSync(TMP, { recursive: true, force: true });
}
await browser.close(); await srv.close();
