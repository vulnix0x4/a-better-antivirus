// --selftest: the page checks WebGL and tries what the guard must stop,
// then hands its report to Go (which decides). --probe: a button and a
// native Yes/No box, to check from a VM that lower programs can't drive the
// app. Neither is part of the app a person sees.
import { h, $, sleep } from './dom.js';
import { bridge } from './bridge.js';
import * as gfx from './gfx.js';

// Every CSP violation is recorded; the self-test fails on any it didn't cause on purpose.
export const violations = [];
document.addEventListener('securitypolicyviolation', e => violations.push({ directive: e.effectiveDirective, blocked: String(e.blockedURI).slice(0, 120) }));

async function attacks() {
  const r = {};
  // A new window (would be an administrator's browser window).
  try { r.windowOpen = window.open('https://example.com/') === null ? 'blocked' : 'opened'; } catch { r.windowOpen = 'threw'; }
  // The network (CSP connect-src 'none'): this one violation is expected.
  try { await fetch('https://example.com/'); r.fetch = 'allowed'; } catch { r.fetch = 'blocked'; }
  // A download (an administrator saving whatever a page hands it).
  try { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob(['x'])); a.download = 'x.txt'; document.body.append(a); a.click(); a.remove(); r.download = 'tried'; } catch { r.download = 'threw'; }
  // Permissions (Wails grants all of them by default).
  try { r.notifications = await Notification.requestPermission(); } catch { r.notifications = 'threw'; }
  try { await navigator.clipboard.readText(); r.clipboardRead = 'allowed'; } catch (e) { r.clipboardRead = 'blocked:' + e.name; }
  // Wails IPC the app doesn't use: open a URL in the (elevated) browser, events.
  try { window.chrome.webview.postMessage('BO:https://example.com/'); window.chrome.webview.postMessage('EE:x:[]'); r.ipc = 'sent'; } catch { r.ipc = 'threw'; }
  // Navigation away: to the disk, and to the web. If either went through,
  // this page would be gone and the test would time out.
  location.href = 'file:///C:/Windows/win.ini'; await sleep(800);
  location.href = 'https://example.com/'; await sleep(800);
  const f = document.createElement('iframe'); f.src = 'https://example.com/'; document.body.append(f); await sleep(500); f.remove();
  r.stillHere = true;
  return r;
}

// The little panel that says what the app is running on.
export function diag(info, scene) {
  const box = $('#diag'); box.hidden = false;
  const fps = h('dd', '-');
  const g = gfx.gl;
  box.append(h('h3', info.selftest ? 'Self-test' : 'Probe'), h('dl',
    h('dt', 'Mode'), h('dd', `${info.mode}${info.elevated ? ' (elevated)' : ''}`),
    h('dt', 'WebGL'), h('dd', g.ok ? `${g.renderer}${g.software ? ' (software)' : ''}` : 'no WebGL'),
    h('dt', 'Scene'), h('dd', `${gfx.tier}${gfx.reduced ? ', still' : ''}`),
    h('dt', 'Engine'), h('dd', info.runtime || '-'),
    h('dt', 'Guard'), h('dd', info.guard && info.guard.ok ? 'on' : `FAILED: ${info.guard && info.guard.error}`),
    h('dt', 'Frames'), fps));
  const t0 = performance.now();
  if (scene) setInterval(() => { const n = scene.frames(), s = (performance.now() - t0) / 1000; fps.textContent = `${n} (${(n / s).toFixed(0)} fps${scene.light ? ', light' : ''})`; }, 500);
  if (info.probe) {
    const clicks = h('b', '0'), keys = h('b', '0');
    const show = c => { clicks.textContent = c.clicks; keys.textContent = c.keys; };
    box.append(h('div.probe',
      h('button.btn.sm#probeBtn', { type: 'button', on: { click: async () => show(await bridge.probe('click')) } }, 'Probe button'),
      h('button.btn.sm#probeConfirm', { type: 'button', on: { click: async () => show(await bridge.probeConfirm()) } }, 'Native confirm'),
      h('p', 'clicks ', clicks, ' · keys ', keys)));
    addEventListener('keydown', async () => show(await bridge.probe('key')));
  }
}

export async function selftest(info, scene) {
  const report = { gl: gfx.gl, tier: gfx.tier, reducedMotion: gfx.reduced, mode: info.mode };
  const t0 = performance.now(), f0 = scene ? scene.frames() : 0;
  await sleep(3000);
  const sec = (performance.now() - t0) / 1000;
  report.frames = scene ? scene.frames() - f0 + (gfx.reduced ? Math.min(1, f0) : 0) : 0;
  report.fps = scene ? +((scene.frames() - f0) / sec).toFixed(1) : 0;
  report.light = scene ? scene.light : null;
  report.attacks = await attacks();
  report.cspViolations = violations;
  report.errors = window.__abaErrors;
  await bridge.selftestDone(JSON.stringify(report));
}
