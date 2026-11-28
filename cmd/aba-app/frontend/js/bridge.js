// The bridge to Go (internal/appapi/CONTRACT.md): window.go.main.API, bound
// by Wails. Every method returns a promise. In development and tests the
// same object is provided by a mock that serves the fixtures.
const api = () => window.go && window.go.main && window.go.main.API;
const call = (name, ...args) => {
  const a = api();
  if (!a || typeof a[name] !== 'function') return Promise.reject(new Error('ABA is not connected (' + name + ')'));
  try { return Promise.resolve(a[name](...args)); } catch (e) { return Promise.reject(e); }
};

// Characters that change how text is laid out without being seen (the
// right-to-left override that turns "exe.gpj" into a picture's name,
// zero-width spaces, control codes): shown as ‹U+202E›, the way the CLI
// does, so a caught program's strings can't rearrange the words around them.
const HIDDEN = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u061C\u200B-\u200F\u2028-\u202E\u2060-\u2069\uFEFF]/g;
export const visible = t => t.replace(HIDDEN, c => '\u2039U+' + c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0') + '\u203A');
function scrub(v, depth = 0) {
  if (typeof v === 'string') return visible(v);
  if (!v || typeof v !== 'object' || depth > 40) return v;
  if (Array.isArray(v)) return v.map(x => scrub(x, depth + 1));
  const o = {}; for (const k of Object.keys(v)) o[k] = scrub(v[k], depth + 1); return o;
}
const data = (name, ...args) => call(name, ...args).then(v => scrub(v));

export const bridge = {
  info: () => call('Info'),
  snapshot: () => data('Snapshot'),
  alert: id => data('Alert', id),
  history: () => data('History'),
  baits: () => data('Baits'),
  settings: () => data('Settings'),
  locked: () => data('Locked'),
  // -> {ok, message, details}; never rejects (a failed call is a failed action).
  act: (kind, id = '', arg = '') => data('Act', kind, id, arg)
    .then(r => r && typeof r === 'object' ? { ok: !!r.ok, message: String(r.message || ''), details: r.details } : { ok: false, message: 'ABA gave no answer.' })
    .catch(e => ({ ok: false, message: String(e && e.message || e) })),
  progress: () => data('Progress').catch(() => ({ running: false, events: [] })),
  openElevated: () => data('OpenElevated').catch(e => String(e && e.message || e)),
  copy: text => call('Copy', String(text)).then(Boolean).catch(() => false),
  pending: () => call('Pending').then(v => typeof v === 'string' ? v : '').catch(() => ''),
  // self-test and probe (main_windows.go)
  selftestDone: report => call('SelftestDone', report),
  probe: kind => call('Probe', kind),
  probeConfirm: () => call('ProbeConfirm'),
};

// The window itself (Wails' runtime; the guard lets only these through).
const rt = () => window.runtime || {};
export const win = {
  minimise: () => rt().WindowMinimise && rt().WindowMinimise(),
  toggleMax: () => rt().WindowToggleMaximise && rt().WindowToggleMaximise(),
  quit: () => rt().Quit && rt().Quit(),
};
