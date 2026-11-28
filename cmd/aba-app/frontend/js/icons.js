// Icons for the screens: icon3() gives a rendered 3D icon (a canvas), line()
// a flat stroke glyph. Without WebGL every icon is the flat one.
import { glyph, GLYPHS } from './glyphs.js';
import { tier, reduced } from './gfx.js';

export const COLORS = { green: '#6ee7a0', ice: '#a6dbff', amber: '#ffcf66', red: '#ff5545', ink: '#eef1ec', teal: '#8fe3d2', dim: '#8d978f' };

let maker = null, failed = tier === 'none';
const live = new Set();

// The 3D renderer is loaded on first use (the locked view never needs it).
let loading = null;
const pending = [];
function ensure() {
  if (maker || failed) return;
  if (!loading) {
    loading = import('./icons3d.js').then(m => { maker = m.makeIcons(); for (const o of pending.splice(0)) paint(o); })
      .catch(e => { failed = true; console.warn('3D icons unavailable:', e); for (const o of pending.splice(0)) flatten(o); });
  }
}
function flatten(o) { o.el.classList.remove('i3'); o.el.classList.add('ic', 'i3-flat'); o.el.replaceChildren(...glyph(o.name).childNodes); live.delete(o); }
function paint(o, t = 0) {
  try { maker.draw(o.cv, o.name, o.color, { t, live: o.live && t > 0, level: o.level }); } catch (e) { failed = true; flatten(o); }
}

// icon3('discord', COLORS.ice, {live: true}) -> <i class="i3"><canvas></i>
export function icon3(name, color = COLORS.green, opts = {}) {
  if (!GLYPHS[name] && name !== 'virus') name = 'doc';
  if (name === 'virus') color = COLORS.red;
  if (failed) return glyph(name, 'i3-flat');
  const el = document.createElement('i'); el.className = 'i3'; el.setAttribute('aria-hidden', 'true');
  const cv = document.createElement('canvas'); cv.width = cv.height = 224; el.append(cv);
  const o = { el, cv, name, color, level: opts.level ?? 1, live: !!opts.live && tier === 'full' && !reduced };
  el.__icon = o;
  if (maker) paint(o); else { pending.push(o); ensure(); }
  if (o.live) live.add(o);
  return el;
}
// Change an icon in place (the rail's colour, the knob's shield).
export function setIcon(el, { name, color, level } = {}) {
  const o = el && el.__icon; if (!o) return;
  if (name) o.name = name; if (color) o.color = color; if (level != null) o.level = level;
  if (maker) paint(o);
}
// A tile: the recessed plate an icon sits in.
export function tile(name, color = COLORS.green, cls = '', opts = {}) {
  const t = document.createElement('span'); t.className = 'tile' + (cls ? ' ' + cls : ''); t.style.setProperty('--c', color);
  t.append(icon3(name, color, opts)); return t;
}
export const line = glyph;

// Called by the frame loop: the icons on screen turn slowly.
let lastT = 0;
export function tickIcons(t) {
  if (!maker || !live.size || t - lastT < 1 / 20) return; lastT = t;
  for (const o of live) {
    if (!o.el.isConnected) { if (o.gone++ > 40) live.delete(o); continue; }
    o.gone = 0;
    const scr = o.scr === undefined ? (o.scr = o.el.closest('.screen')) : o.scr;
    if (scr && !scr.classList.contains('on')) continue;
    paint(o, t);
  }
}

// What each bait icon is tinted with.
const BAIT_C = { discord: 'ice', telegram: 'ice', chrome: 'amber', firefox: 'amber', globe: 'amber', wallet: 'green', vault: 'green', key: 'ink', cloud: 'ink', server: 'ink', git: 'ink', doc: 'teal', grid: 'teal', hashi: 'teal' };
export const baitColor = icon => COLORS[BAIT_C[icon] || 'teal'];
// An alert row's icon and colour.
const ALERT_I = { stealer: ['virus', 'red'], miner: ['pick', 'amber'], clipper: ['clipboard', 'amber'], trusted: ['shield', 'green'], quiet: ['eye', 'green'], test: ['snow', 'ice'], system: ['warn', 'amber'] };
export const alertIcon = icon => { const [n, c] = ALERT_I[icon] || ALERT_I.system; return [n, COLORS[c]]; };
