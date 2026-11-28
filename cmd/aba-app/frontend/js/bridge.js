// The bridge to Go (internal/appapi/CONTRACT.md): window.go.main.API, bound
// by Wails. Every method returns a promise. In development and tests the
// same object is provided by a mock that serves the fixtures.
const api = () => window.go && window.go.main && window.go.main.API;
const call = (name, ...args) => {
  const a = api();
  if (!a || typeof a[name] !== 'function') return Promise.reject(new Error('ABA is not connected (' + name + ')'));
  try { return Promise.resolve(a[name](...args)); } catch (e) { return Promise.reject(e); }
};

export const bridge = {
  info: () => call('Info'),
  snapshot: () => call('Snapshot'),
  alert: id => call('Alert', id),
  history: () => call('History'),
  baits: () => call('Baits'),
  settings: () => call('Settings'),
  locked: () => call('Locked'),
  // -> {ok, message, details}; never rejects (a failed call is a failed action).
  act: (kind, id = '', arg = '') => call('Act', kind, id, arg)
    .then(r => r && typeof r === 'object' ? { ok: !!r.ok, message: String(r.message || ''), details: r.details } : { ok: false, message: 'ABA gave no answer.' })
    .catch(e => ({ ok: false, message: String(e && e.message || e) })),
  progress: () => call('Progress').catch(() => ({ running: false, events: [] })),
  openElevated: () => call('OpenElevated').catch(e => String(e && e.message || e)),
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
