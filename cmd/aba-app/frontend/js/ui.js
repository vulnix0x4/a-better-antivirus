// Shared controls: the rotary protection knob, switches, buttons that show
// they're working, toasts, a dialog.
import { h, $, clamp } from './dom.js';
import { icon3, setIcon, line, COLORS } from './icons.js';

// Entrance: el slides in `kind` (up | left | right | pop) after `delay` seconds
// when its screen is entered.
export function enter(el, kind, delay = 0) { el.dataset.a = kind; el.style.setProperty('--d', delay + 's'); return el; }

/* ---------------- toasts ---------------- */
export function toast(text, kind = 'ok') {
  const box = $('#toasts'); if (!box || !text) return;
  const t = h('div.toast', { class: kind, role: kind === 'bad' ? 'alert' : 'status' }, line(kind === 'bad' ? 'warn' : kind === 'info' ? 'snow' : 'check'), h('span', text));
  box.append(t);
  while (box.children.length > 3) box.firstChild.remove();
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 400); }, kind === 'bad' ? 9000 : 4500);
}

/* ---------------- a button that does something slow ---------------- */
// Runs fn on click; while it runs the button is disabled and shows a spinner.
export function action(btn, fn) {
  btn.addEventListener('click', async () => {
    if (btn.disabled) return;
    btn.disabled = true; btn.classList.add('busy');
    try { await fn(btn); } finally { btn.classList.remove('busy'); if (btn.isConnected) btn.disabled = false; }
  });
  return btn;
}
export const spinner = () => h('span.spin', { 'aria-hidden': 'true' });
export function button(label, { icon, cls = '', sub, onClick, title } = {}) {
  const b = h('button.btn', { type: 'button', class: cls, title }, icon ? line(icon) : null, sub ? h('span', label, h('small', sub)) : h('span', label), spinner());
  if (onClick) action(b, onClick);
  return b;
}

/* ---------------- switch ---------------- */
export function toggle(on, label, onChange) {
  const b = h('button.tog', { type: 'button', role: 'switch', 'aria-checked': on ? 'true' : 'false', 'aria-label': label, class: on ? 'on' : '' }, h('i'));
  const set = v => { b.classList.toggle('on', v); b.setAttribute('aria-checked', v ? 'true' : 'false'); };
  if (onChange) action(b, async () => {
    const want = b.getAttribute('aria-checked') !== 'true';
    set(want); // move at once, put it back if ABA says no
    if (!(await onChange(want))) set(!want);
  }); else b.disabled = true;
  b.set = set;
  return b;
}

/* ---------------- the protection knob ---------------- */
// A machined rotary control with three detents. The shield under its glass
// dome grows from a faint outline (alert only) to an armoured, bright one
// (strict), and the lit arc and ticks follow the pointer.
const DETENTS = [['alert', -120, 'Alert only'], ['balanced', 0, 'Balanced'], ['strict', 120, 'Strict']];
export function knob({ onChange, big = false, live = true } = {}) {
  const shield = icon3('shield', COLORS.green, { live, level: 1 });
  const dets = DETENTS.map(([id, a]) => h('i.d-det', { vars: { '--a': a + 'deg' }, data: { id } }));
  const dial = h('div.dial', { class: big ? 'big' : '', role: 'slider', tabindex: '0', 'aria-label': 'Protection level', 'aria-valuemin': '0', 'aria-valuemax': '2' },
    h('div.d-ticks'), h('div.d-ticks.lit'), h('div.d-chan'), h('div.d-arc'), ...dets,
    h('div.d-knob', h('div.d-knurl'), h('div.d-cap'), h('div.d-ptr', h('u')), h('div.d-dome', shield)),
    h('span.d-lab.l', 'Alert only'), h('span.d-lab.r', 'Strict'));
  let cur = -1, busy = false;
  function show(i, custom = false) {
    cur = i; const k = custom ? 1 : i;
    dial.style.setProperty('--ang', DETENTS[k][1] + 'deg');
    dial.dataset.level = custom ? 'custom' : DETENTS[i][0];
    dets.forEach((d, j) => d.classList.toggle('on', !custom && j <= i));
    dial.setAttribute('aria-valuenow', String(k)); dial.setAttribute('aria-valuetext', custom ? 'Custom' : DETENTS[i][2]);
    setIcon(shield, { level: custom ? 1 : i, color: custom ? COLORS.amber : i === 2 ? '#b9ffd6' : COLORS.green });
  }
  async function pick(i) {
    i = clamp(i, 0, 2);
    if (busy || (i === cur && dial.dataset.level !== 'custom')) { show(Math.max(0, cur), dial.dataset.level === 'custom'); return; }
    const prev = cur, wasCustom = dial.dataset.level === 'custom';
    show(i); busy = true; dial.classList.add('busy');
    let ok = true; try { ok = onChange ? await onChange(DETENTS[i][0]) : true; } catch { ok = false; }
    busy = false; dial.classList.remove('busy');
    if (!ok) show(Math.max(0, prev), wasCustom);
  }
  dial.addEventListener('keydown', e => {
    const d = { ArrowLeft: -1, ArrowDown: -1, ArrowRight: 1, ArrowUp: 1 }[e.key];
    if (d) { e.preventDefault(); pick((dial.dataset.level === 'custom' ? 1 : cur) + d); }
    else if (e.key === 'Home') { e.preventDefault(); pick(0); } else if (e.key === 'End') { e.preventDefault(); pick(2); }
  });
  // Turn it with the pointer: it follows, then settles in the nearest detent.
  const angleAt = e => { const r = dial.getBoundingClientRect(); const a = Math.atan2(e.clientX - (r.left + r.width / 2), -(e.clientY - (r.top + r.height / 2))) * 180 / Math.PI; return clamp(a, -120, 120); };
  let drag = false;
  dial.addEventListener('pointerdown', e => { if (busy || e.button) return; drag = true; dial.setPointerCapture(e.pointerId); dial.classList.add('drag'); dial.style.setProperty('--ang', angleAt(e) + 'deg'); });
  dial.addEventListener('pointermove', e => { if (drag) dial.style.setProperty('--ang', angleAt(e) + 'deg'); });
  const drop = e => { if (!drag) return; drag = false; dial.classList.remove('drag'); const a = angleAt(e); pick(a < -60 ? 0 : a > 60 ? 2 : 1); };
  dial.addEventListener('pointerup', drop); dial.addEventListener('pointercancel', () => { if (drag) { drag = false; dial.classList.remove('drag'); show(Math.max(0, cur), dial.dataset.level === 'custom'); } });
  return {
    el: dial,
    set(id) { const i = DETENTS.findIndex(d => d[0] === id); if (!busy && !drag) show(i < 0 ? 1 : i, i < 0); },
    pick: id => pick(DETENTS.findIndex(d => d[0] === id)),
  };
}

/* ---------------- dialog ---------------- */
export function dialog(title, body, { wide = false } = {}) {
  const host = $('#overlay'); const prev = document.activeElement;
  const close = () => { wrap.remove(); document.removeEventListener('keydown', onKey, true); if (prev && prev.isConnected) prev.focus(); };
  const x = h('button.dlg-x', { type: 'button', 'aria-label': 'Close this', on: { click: close } }, line('x')); // (not "Close": that's the window's)
  const box = h('div.dlg.panel', { class: wide ? 'wide' : '', role: 'dialog', 'aria-modal': 'true', 'aria-label': title }, h('div.dlg-h', h('h2', title), x), h('div.dlg-b', body));
  const wrap = h('div.dlg-wrap', { on: { mousedown: e => { if (e.target === wrap) close(); } } }, box);
  const onKey = e => {
    if (e.key === 'Escape') { e.stopPropagation(); close(); return; }
    if (e.key !== 'Tab') return; // keep the focus inside
    const f = [...box.querySelectorAll('button:not([disabled]),[tabindex="0"]')]; if (!f.length) return;
    const i = f.indexOf(document.activeElement);
    if (e.shiftKey && i <= 0) { e.preventDefault(); f[f.length - 1].focus(); } else if (!e.shiftKey && i === f.length - 1) { e.preventDefault(); f[0].focus(); }
  };
  document.addEventListener('keydown', onKey, true);
  host.append(wrap); x.focus();
  return { close, box };
}

// "Copy": the page may not touch the clipboard; Go does it.
export function copyButton(bridge, getText, label = 'Copy', cls = 'sm') {
  const b = button(label, { icon: 'copy', cls });
  action(b, async () => {
    const ok = await bridge.copy(getText());
    const s = b.querySelector('span'); const was = s.textContent;
    s.textContent = ok ? 'Copied' : "Couldn't copy"; b.classList.toggle('done', ok);
    setTimeout(() => { s.textContent = was; b.classList.remove('done'); }, 1600);
  });
  return b;
}
