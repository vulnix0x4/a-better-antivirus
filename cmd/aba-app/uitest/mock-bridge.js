// The mock bridge: stands in for what Wails injects (window.go.main.API and
// window.runtime) and serves the fixtures. Development and tests only; it is
// never part of the app.
(() => {
  const F = window.__FIXTURES, Q = new URLSearchParams(location.search);
  const clone = v => JSON.parse(JSON.stringify(v));
  const wait = ms => new Promise(r => setTimeout(r, Q.has('fast') ? 0 : ms * (Q.has('slow') ? 6 : 1)));
  const mode = Q.get('mode') === 'locked' ? 'locked' : 'full';
  const calls = [];

  const alerts = {}; // by ID; ?alert=<fixture> wins for an ID two fixtures share
  for (const [name, v] of Object.entries(F)) if (name.startsWith('alert-')) alerts[v.id] = clone(v);
  const pick = Q.get('alert') && F['alert-' + Q.get('alert')] ? clone(F['alert-' + Q.get('alert')]) : null;
  if (pick) alerts[pick.id] = pick;
  let snap = clone(F['home-' + (Q.get('home') === 'frozen' ? 'frozen' : 'protected')]);
  const settings = clone(F.settings), history = clone(F.history), baits = clone(F.baits);
  if (Q.has('empty')) { snap.baits.tags = []; snap.baits.total = snap.baits.healthy = 0; snap.traps.baits = 0; snap.recentQuiet = []; history.items = []; history.counts = { total: 0, caught: 0, frozen: 0, killed: 0, trusted: 0, quiet: 0, tests: 0 }; baits.items = []; baits.total = baits.healthy = 0; }
  if (Q.has('nosupport')) { for (const o of [snap.traps, settings]) { o.clipboard.supported = false; o.miners.supported = false; } }
  if (Q.has('update')) { for (const o of [snap.update, settings.update]) { o.latest = 'v0.10.3'; o.available = true; } }
  const pending = [];
  let progress = { running: false, kind: '', events: [] };
  const step = text => progress.events.push({ event: 'step', text, time: new Date().toISOString() });

  function resolve(a, outcome, note, words) {
    a.outcome = outcome; a.status = 'resolved'; a.note = note; a.frozenNow = false; a.cutOff = false; a.buttons = [];
    if (words) a.did.push({ action: outcome, ok: true, words, time: new Date().toISOString() });
    const p = clone(F['home-protected']); p.preset = snap.preset; p.traps = snap.traps; p.quietDays = 0; snap = p;
    const row = history.items.find(i => i.id === a.id); if (row) row.outcome = outcome;
  }
  async function act(kind, id, arg) {
    calls.push(['Act', kind, id, arg]);
    if (Q.get('fail') === kind) { await wait(500); return { ok: false, message: "ABA couldn't do that: access is denied (mock)." }; }
    const a = alerts[id];
    switch (kind) {
      case 'kill': await wait(1400); if (!a) break; resolve(a, 'killed', 'killed', 'Killed it'); return { ok: true, message: `Killed ${a.program ? a.program.name : 'it'}. The evidence is saved.` };
      case 'resume': await wait(700); if (!a) break; resolve(a, 'resumed', 'let go once', 'Let it go, once'); return { ok: true, message: 'Unfrozen. It runs this once; ABA trusts nothing from it.' };
      case 'trust': await wait(700); if (!a) break; resolve(a, 'trusted', 'you trusted this program', 'Unfroze it'); return { ok: true, message: 'Trusted. ABA will leave it alone from now on.' };
      case 'release': await wait(700); if (a) resolve(a, 'resumed', 'released'); return { ok: true, message: 'Reconnected.' };
      case 'instant': case 'recorder': await wait(350); settings[kind] = arg === 'on'; snap.traps[kind] = arg === 'on'; return { ok: true, message: '' };
      case 'clipboard': case 'miners': await wait(350); settings[kind].on = arg === 'on'; snap.traps[kind].on = arg === 'on'; return { ok: true, message: '' };
      case 'auto-update': await wait(350); settings.update.auto = snap.update.auto = arg === 'on'; return { ok: true, message: `Updates ${arg === 'on' ? 'install themselves' : 'wait for you'} now.` };
      case 'preset': { await wait(450); const p = settings.presets.find(x => x.id === arg); if (!p) break; settings.preset = arg; snap.preset = { id: p.id, name: p.name, says: { alert: 'On a catch: tell you, stop nothing', balanced: 'On a catch: freeze it, cut its internet', strict: 'On a catch: freeze it, take this PC offline' }[arg] }; return { ok: true, message: `Protection level: ${p.name}.` }; }
      case 'bait-show': {
        await wait(300); const b = baits.items.find(x => x.id === id); if (!b) break;
        return { ok: true, message: '', details: { files: b.files.map((f, i) => i === 0 ? { path: f.path, size: f.size, binary: false, text: 'gmail      sam.k.wright@gmail.com      Tr0ub4dor&3-horse\nbank       sam.wright                  correct-staple-9\n<img src=x onerror=alert(9)> <script>alert(10)</script>\n' } : { path: f.path, size: f.size, binary: true, text: '' }) } };
      }
      case 'test': {
        progress = { running: true, kind, events: [] };
        step('A harmless fake stealer is about to read password list on the Desktop.'); await wait(1300);
        step('Waiting for ABA to catch it…'); await wait(1700);
        step('Caught and frozen.'); await wait(300);
        progress.running = false;
        return { ok: true, message: 'ABA caught the test.', details: { alertId: F['alert-test'].id, latencyMs: 110, instant: true } };
      }
      case 'update-check': await wait(900); return { ok: true, message: snap.update.available ? `${snap.update.latest} is available.` : 'You have the newest version.', details: { current: snap.update.version, latest: snap.update.latest, available: snap.update.available } };
      case 'update': progress = { running: true, kind, events: [] }; step('Downloading ' + snap.update.latest); await wait(1500); step('Installing and restarting the service'); await wait(1500); progress.running = false; for (const o of [snap.update, settings.update]) { o.version = o.latest; o.available = false; } return { ok: true, message: 'Updated to ' + snap.update.latest + '.' };
      case 'phone-test': await wait(800); return { ok: true, message: 'Sent. Check your phone.' };
    }
    return { ok: false, message: `no such thing: ${kind} ${id}` };
  }

  const full = fn => (...a) => mode === 'full' ? fn(...a) : Promise.reject(new Error('this needs administrator rights: use Open ABA'));
  const API = {
    Info: async () => ({ mode, elevated: mode === 'full', version: snap.version, alert: Q.has('open') ? (pick ? pick.id : snap.waiting[0] ? snap.waiting[0].id : '') : '', runtime: 'mock', guard: { ok: true }, selftest: false, probe: Q.has('probe') }),
    Snapshot: full(async () => { if (Q.has('nodata')) throw new Error('open C:\\ProgramData\\FileAccessMonitor\\config.json: Access is denied.'); return clone(snap); }),
    Alert: full(async id => { calls.push(['Alert', id]); if (!alerts[id]) throw new Error('no alert ' + id); return clone(alerts[id]); }),
    History: full(async () => clone(history)),
    Baits: full(async () => clone(baits)),
    Settings: full(async () => clone(settings)),
    Locked: async () => clone(F[Q.get('home') === 'frozen' ? 'locked-frozen' : 'locked']),
    Act: (kind, id, arg) => mode === 'full' ? act(kind, id, arg) : Promise.resolve({ ok: false, message: 'this needs administrator rights: use Open ABA' }),
    Progress: async () => clone(progress),
    OpenElevated: async () => { calls.push(['OpenElevated']); await wait(300); return Q.has('uac') ? '' : "Windows didn't start ABA as administrator (mock)."; },
    Copy: async text => { calls.push(['Copy', text]); window.__copied = text; return true; },
    Pending: async () => pending.shift() || '',
    SelftestDone: async () => {}, Probe: async () => ({ clicks: 0, keys: 0 }), ProbeConfirm: async () => ({ clicks: 0, keys: 0 }),
  };
  window.go = { main: { API } };
  window.runtime = { WindowMinimise: () => calls.push(['min']), WindowToggleMaximise: () => calls.push(['max']), Quit: () => calls.push(['quit']) };
  window.__abaDev = {
    tier: Q.get('tier') || undefined, reduced: Q.has('reduced') ? true : (Q.has('motion') ? false : undefined), manual: Q.has('manual'),
    screen: Q.get('screen') || '', stageH: Number(Q.get('stageh')) || 0, alert: pick && !Q.has('open') ? pick.id : '', fixedNow: !Q.has('realnow'), calls,
    // a catch while the app is open: the alert goes into the snapshot and the open request
    catchNow(name = 'frozen-sent') { const a = clone(F['alert-' + name]); alerts[a.id] = a; const fz = clone(F['home-frozen']); fz.preset = snap.preset; snap = fz; pending.push(a.id); },
    state: () => ({ snap, settings, alerts }),
  };
})();
