// ABA desktop app: the page's entry. It wires the bridge (Go), the screens
// and the 3D scene together.
//
// Rules for everything here and under js/: nothing that parses markup is
// ever given data (text goes in as text nodes, elements are made one by
// one); there are no inline scripts, handlers or styles (the page's CSP
// allows scripts, styles and fonts from the app itself only); nothing is
// fetched (no network at all); links never navigate. The Go side is reached
// only through the bound API methods.
import { $, $$, h, fill, clamp, sleep, setNow } from './js/dom.js';
import { bridge, win } from './js/bridge.js';
import * as gfx from './js/gfx.js';
import { icon3, setIcon, COLORS } from './js/icons.js';
import { glyph } from './js/glyphs.js';
import { toast, spinner } from './js/ui.js';
import { violations, diag, selftest } from './js/selftest.js';
import { createLocked } from './js/screens/locked.js';

window.__abaStarted = true;
const dev = window.__abaDev || null;
const SCREENS = ['home', 'caught', 'report', 'history', 'baits', 'settings'];
const TONE = { protected: 'ok', frozen: 'ice', isolated: 'ice', attention: 'warn', stopped: 'bad' };

/* ---------------- the window: one design size, scaled to fit ---------------- */
const root = document.documentElement, frame = $('#window');
let scene = null; const frameHooks = [];
function layout() {
  const W = innerWidth, H = innerHeight; if (!W || !H) return;
  const k = clamp(Math.min(W / 1440, H / 900), .5, 1.35);
  frame.style.width = (W / k) + 'px'; frame.style.height = (H / k) + 'px'; frame.style.transform = k === 1 ? '' : `scale(${k})`;
  root.style.setProperty('--k', k);
  if (scene) scene.resize(W / k - 88, H / k - 44, k);
}
addEventListener('resize', layout); layout();
$('#wMin').addEventListener('click', () => win.minimise());
$('#wMax').addEventListener('click', () => win.toggleMax());
$('#wClose').addEventListener('click', () => win.quit());
// Nothing in the page is a link, and nothing dropped or dragged goes anywhere.
addEventListener('dragover', e => e.preventDefault()); addEventListener('drop', e => e.preventDefault());

/* ---------------- state ---------------- */
const S = { info: null, snap: null, screen: '', alert: null, alertId: '', testing: false, presented: new Set(), keepCatch: '', sceneCatch: '' };
const screens = {};
const app = {
  bridge, go, openAlert, runTest, setPreset, answer, reload, watchProgress,
  onFrame: f => { frameHooks.push(f); }, hasScene: () => !!scene, sceneTime: () => scene ? scene.time : 0,
  setScroll: y => scene && scene.setScroll(y), selectBait: id => scene && scene.select(id),
};

/* ---------------- frame: the title bar, the rail ---------------- */
const railIcons = {};
function buildRail() {
  const names = { home: 'home', history: 'history', baits: 'hook', settings: 'sliders' };
  for (const b of $$('#rail button')) {
    const n = b.dataset.nav; const ic = icon3(names[n], COLORS.dim); railIcons[n] = ic; b.querySelector('.ri').replaceWith(ic);
    b.addEventListener('click', () => go(n));
  }
}
function paintFrame() {
  const p = S.snap && S.snap.protection;
  const icy = document.body.classList.contains('icy');
  const on = S.screen === 'caught' || S.screen === 'report' ? 'home' : S.screen;
  for (const b of $$('#rail button')) {
    const is = b.dataset.nav === on; b.classList.toggle('on', is); if (is) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
    const col = is ? (icy ? COLORS.ice : COLORS.green) : COLORS.dim;
    if (railIcons[b.dataset.nav] && railIcons[b.dataset.nav].dataset.c !== col) { railIcons[b.dataset.nav].dataset.c = col; setIcon(railIcons[b.dataset.nav], { color: col }); }
  }
  if (p) { $('#tbState').textContent = p.headline; document.body.dataset.tone = TONE[p.state] || 'warn'; }
}
function notice(text) { const n = $('#notice'); n.hidden = !text; n.textContent = text || ''; }

/* ---------------- data ---------------- */
async function loadSnap() {
  try {
    const sn = await bridge.snapshot(); S.snap = sn; notice('');
    if (dev && dev.fixedNow) setNow(sn.now);
    if (scene) scene.setBaits(sn.baits.tags);
    screens.home.update(sn); paintFrame(); syncCatch();
    return sn;
  } catch (e) { notice("ABA's data can't be read right now. " + String(e && e.message || e)); return null; }
}
async function loadAlert(id) {
  try { const a = await bridge.alert(id); if (id === S.alertId) { S.alert = a; screens.caught.update(a); screens.report.update(a); } return a; }
  catch (e) { return null; }
}
const loaders = {
  history: async () => screens.history.update(await bridge.history()),
  baits: async () => screens.baits.update(await bridge.baits()),
  settings: async () => screens.settings.update(await bridge.settings()),
};
async function reload(name, quiet) {
  try { if (loaders[name]) await loaders[name](); if (!quiet) await loadSnap(); } catch (e) { if (!quiet) toast(String(e && e.message || e), 'bad'); }
}
function watchProgress(cb) {
  let n = -1, stopped = false;
  const tick = async () => { if (stopped) return; const p = await bridge.progress(); if (!stopped && p.events.length !== n) { n = p.events.length; cb(p.events); } };
  const iv = setInterval(tick, 300); tick();
  return () => { stopped = true; clearInterval(iv); };
}

/* ---------------- what's in ice on the scene ---------------- */
const catchInfo = a => ({ baitId: a.baits[0] ? a.baits[0].id : '', label: a.baits[0] ? a.baits[0].label : '', program: a.program ? a.program.name : '' });
const rowInfo = r => { const t = S.snap && S.snap.baits.tags.find(x => x.label === r.bait); return { baitId: t ? t.id : '', label: r.bait || '', program: r.program || '' }; };
// Whatever is frozen now sits in its ice cube; nothing else does.
function syncCatch() {
  const onAlert = (S.screen === 'caught' || S.screen === 'report') && S.alert;
  let want = '', info = null;
  if (onAlert) { if (S.alert.frozenNow || S.keepCatch === S.alert.id) { want = S.alert.id; info = catchInfo(S.alert); } }
  else {
    S.keepCatch = '';
    // (a catch not shown yet is left for present(), which shows it happen)
    const w = S.snap && S.snap.waiting.find(x => x.outcome === 'frozen' && S.presented.has(x.id)); if (w) { want = w.id; info = rowInfo(w); }
  }
  if (!scene) { document.body.classList.toggle('icy', !!want); return; }
  if (S.testing || scene.catching) return;
  if (want === S.sceneCatch) { if (!want && onAlert) scene.aim(catchInfo(S.alert).baitId); return; }
  if (!want) { S.sceneCatch = ''; scene.melt(); if (onAlert) scene.aim(catchInfo(S.alert).baitId); }
  else { S.sceneCatch = want; scene.showFrozen(info); }
}

/* ---------------- navigation ---------------- */
let enterTimer = 0;
async function go(name, params = {}) {
  if (!SCREENS.includes(name)) name = 'home';
  if (name === 'caught' || name === 'report') {
    const id = params.id || S.alertId; if (!id) { name = 'home'; }
    else if (id !== S.alertId || !S.alert) {
      S.alertId = id; S.alert = null; screens.caught.reset(); screens.report.reset();
      const a = await loadAlert(id);
      if (!a) { toast("That alert can't be opened.", 'bad'); S.alertId = ''; name = S.screen || 'home'; if (name === 'caught' || name === 'report') name = 'home'; }
    }
  }
  const same = S.screen === name;
  S.screen = name; document.body.dataset.screen = name;
  for (const s of $$('.screen')) {
    const on = s.id === name; s.classList.toggle('on', on); s.inert = !on;
    if (on && (!same || params.replay)) { s.classList.remove('enter'); void s.offsetWidth; s.classList.add('enter'); s.style.setProperty('--base', (params.base || 0) + 's'); }
  }
  clearTimeout(enterTimer); enterTimer = setTimeout(() => { for (const s of $$('.screen.enter')) s.classList.remove('enter'); }, 4200 + (params.base || 0) * 1000);
  if (!params.keepScene) syncCatch();
  if (scene) scene.go(name, { d: params.d });
  if (name === 'report') screens.report.enterScreen();
  if (name === 'baits' && params.bait) screens.baits.select(params.bait);
  paintFrame();
  if (loaders[name]) reload(name, true);
  if (name === 'home' || name === 'baits') loadSnap();
  const focusTo = $(`#${name} h1`); if (!same && focusTo && !params.quiet) { focusTo.tabIndex = -1; focusTo.focus({ preventScroll: true }); }
}
function openAlert(id) { return go('caught', { id }); }

/* ---------------- actions ---------------- */
async function answer(a, kind) {
  const r = await bridge.act(kind, a.id);
  if (r.ok) { S.keepCatch = ''; if (scene && S.sceneCatch === a.id) { S.sceneCatch = ''; scene.melt(); } }
  await loadAlert(a.id); await loadSnap();
  return r;
}
async function setPreset(id) {
  const r = await bridge.act('preset', '', id);
  toast(r.message || (r.ok ? 'Protection level changed.' : "Couldn't change the protection level."), r.ok ? 'ok' : 'bad');
  await loadSnap(); if (S.screen === 'settings') await reload('settings', true);
  return r.ok;
}

// A catch that happens while the app is open: show it happen, then the decision.
async function present(id) {
  if (!id || S.presented.has(id)) return; S.presented.add(id);
  if (S.testing) return; // the safe test shows its own
  const a = await bridge.alert(id).catch(() => null); if (!a) return;
  const live = a.frozenNow && scene && !gfx.reduced;
  if (live) {
    toast('ABA just caught something.', 'info');
    S.sceneCatch = id; scene.clearCatch();
    await go('home', { keepScene: true, quiet: true });
    await Promise.race([scene.playCatch(catchInfo(a)), sleep(9000)]);
  }
  await loadSnap();
  await go('caught', { id, d: 1.7 });
}

// The safe test, live: the fake stealer crawls in while ABA's steps are shown.
const testCard = $('#testCard');
async function runTest() {
  if (S.testing) return; S.testing = true;
  screens.home.setTestRunning(true); screens.settings.setTestRunning(true);
  if (S.screen !== 'home') await go('home', { quiet: true });
  const steps = h('ol.tc-steps'), msg = h('p.tc-msg');
  const close = h('button.btn.sm', { type: 'button', hidden: true, on: { click: () => { testCard.hidden = true; } } }, h('span', 'Close'));
  fill(testCard, h('div.tc-h', spinner(), h('strong', 'Running the safe test')), steps, msg, close); testCard.hidden = false; testCard.dataset.state = 'run';
  const tags = S.snap ? S.snap.baits.tags : [];
  const guess = tags.find(t => /passwords$/.test(t.id)) || tags[0];
  const info = { baitId: guess ? guess.id : '', label: guess ? guess.label : '', program: 'A harmless fake stealer' };
  if (scene) { S.sceneCatch = ''; scene.clearCatch(); scene.approach(info); }
  const stop = watchProgress(evs => fill(steps, evs.filter(e => e.event === 'step').map((e, i, all) => h('li', { class: i === all.length - 1 ? 'now' : 'done' }, glyph('check'), h('span', e.text)))));
  const r = await bridge.act('test');
  stop();
  for (const li of steps.children) li.className = 'done';
  const id = r.ok && r.details && typeof r.details.alertId === 'string' ? r.details.alertId : '';
  if (id) {
    S.presented.add(id);
    const a = await bridge.alert(id).catch(() => null);
    testCard.dataset.state = 'ok'; msg.textContent = 'Caught. ABA works.';
    if (scene && a) { S.sceneCatch = id; S.keepCatch = id; await Promise.race([scene.strike(catchInfo(a)), sleep(6000)]); }
    S.testing = false; testCard.hidden = true;
    await loadSnap(); await go('caught', { id, d: 1.7 });
  } else {
    if (scene) scene.clearCatch();
    testCard.dataset.state = 'bad'; msg.textContent = r.message || "The test didn't finish."; close.hidden = false;
    S.testing = false; await loadSnap();
  }
  screens.home.setTestRunning(false); screens.settings.setTestRunning(false);
}

/* ---------------- keeping up to date ---------------- */
let ticks = 0, polling = false;
async function poll() {
  if (document.hidden || polling) return; polling = true; ticks++;
  try {
    if (ticks % 2 === 0) { const p = await bridge.pending(); if (p) await present(p); }
    if (ticks % 5 === 0 && !S.testing) {
      const sn = await loadSnap();
      // a catch nobody told the app about (the open request got lost): still show it
      if (sn && S.started) { const w = sn.waiting.find(x => !S.presented.has(x.id) && Date.parse(x.time) > S.started); if (w) await present(w.id); }
    }
    if ((S.screen === 'caught' || S.screen === 'report') && S.alertId) {
      const a = S.alert, hot = a && (a.frozenNow || (a.report && a.report.pending));
      if (ticks % (hot ? 3 : 10) === 0) { await loadAlert(S.alertId); syncCatch(); }
    } else if (loaders[S.screen] && ticks % 12 === 0) await reload(S.screen, true);
  } finally { polling = false; }
}

/* ---------------- start ---------------- */
async function startLocked(info) {
  const lk = createLocked(app);
  const load = async () => { try { lk.update(await bridge.locked(), info.alert); $('#tbState').textContent = 'Locked'; } catch { lk.update(null, info.alert); } };
  lk.update(null, info.alert); await load();
  if (!gfx.manual) setInterval(() => { if (!document.hidden) load(); }, 5000);
}

async function startFull(info) {
  const [home, caught, report, history, baits, settings] = await Promise.all([
    import('./js/screens/home.js'), import('./js/screens/caught.js'), import('./js/screens/report.js'),
    import('./js/screens/history.js'), import('./js/screens/baits.js'), import('./js/screens/settings.js')]);
  // The scene first (the screens hook into its clock); without WebGL there is none.
  if (gfx.tier !== 'none') {
    try {
      const m = await import('./js/scene.js');
      const heldI = $('#held .held-i'); heldI.replaceWith(icon3('snow', COLORS.ice));
      $('#intruder .in-i').replaceWith(icon3('virus', COLORS.red, { live: true }));
      $('#loneTag .tile').append(icon3('hook', COLORS.ice));
      scene = m.createScene({
        canvas: $('#gl'), tier: gfx.tier, reduced: gfx.reduced, manual: gfx.manual,
        els: { tags: $('#tags'), intruder: $('#intruder'), held: $('#held'), flash: $('#flash'), lone: $('#loneTag') },
        onTag: id => { if (S.screen === 'baits') screens.baits.select(id); else go('baits', { bait: id }); },
      });
      scene.onFrame(t => { for (const f of frameHooks) f(t); });
      if (info.selftest || info.probe) scene.setKeepAwake(true);
      layout();
    } catch (e) { console.warn('No 3D scene:', e); scene = null; root.dataset.gfx = 'none'; }
  }
  if (!scene) $('#gl').hidden = true;
  buildRail();
  screens.home = home.createHome(app); screens.caught = caught.createCaught(app); screens.report = report.createReport(app);
  screens.history = history.createHistory(app); screens.baits = baits.createBaits(app); screens.settings = settings.createSettings(app);

  const sn = await loadSnap();
  S.started = Date.now() - 5000;
  const want = dev && dev.screen;
  const startId = info.alert || (sn && sn.waiting[0] ? sn.waiting[0].id : '') || (dev && dev.alert) || '';
  let a = null;
  if (startId && (!want || want === 'caught' || want === 'report')) { S.alertId = startId; a = await loadAlert(startId); }
  if (a) {
    S.presented.add(a.id); for (const w of (sn ? sn.waiting : [])) S.presented.add(w.id);
    // Opened on a catch: the last scuttle onto the bait, the ice, then the words.
    const intro = a.frozenNow && scene && !gfx.reduced && !want;
    if (intro) { await go('caught', { id: a.id, keepScene: true, base: 1.25 }); S.sceneCatch = a.id; scene.playCatch(catchInfo(a), { crawl: 1.1, from: .7 }); }
    else await go(want === 'report' ? 'report' : 'caught', { id: a.id });
  } else { S.alertId = ''; for (const w of (sn ? sn.waiting : [])) S.presented.add(w.id); await go(want && want !== 'caught' && want !== 'report' ? want : 'home'); }

  if (!gfx.manual) setInterval(poll, 1000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) { ticks = 4; poll(); } });
}

(async () => {
  const info = await bridge.info(); // waits on the Go side until the guard is in place
  S.info = info;
  document.body.dataset.mode = info.mode === 'full' ? 'full' : 'locked';
  $('#ver').textContent = info.version || '';
  if (info.mode === 'full') await startFull(info); else await startLocked(info);
  if (info.selftest || info.probe) diag(info, scene);
  // Development and tests: step the page by hand.
  if (dev) {
    const seen = new WeakMap();
    window.__aba = {
      app, S, screens, go, present, violations, gfx,
      frame(t) { for (const an of document.getAnimations()) { if (!seen.has(an)) seen.set(an, t); an.pause(); an.currentTime = Math.max(0, (t - seen.get(an)) * 1000); } if (scene) scene.frame(t); },
      revealAll: () => screens.report && screens.report.revealAll(), scroll: y => { $('#report').scrollTop = y; if (scene) scene.setScroll(y); },
      reportHeight: () => $('#report .r-wrap').scrollHeight,
      scene: () => scene,
    };
    window.__abaReady = true;
  }
  if (info.selftest) await selftest(info, scene);
})().catch(e => {
  window.__abaErrors.push('start: ' + String(e && e.stack || e));
  notice('ABA could not start this window. ' + String(e && e.message || e));
  document.body.dataset.mode = document.body.dataset.mode === 'loading' ? 'failed' : document.body.dataset.mode;
  bridge.selftestDone(JSON.stringify({ error: String(e && e.stack || e) })).catch(() => {});
});
