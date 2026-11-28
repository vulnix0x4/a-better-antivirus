// DOM helpers. The one rule of this page: nothing that parses markup is ever
// used. Every string shown may come from a caught program (its file name,
// its command line, the address it sends to), so text goes in as text nodes
// and elements are made one by one.

export const $ = (s, r = document) => r.querySelector(s);
export const $$ = (s, r = document) => [...r.querySelectorAll(s)];
export const clamp = (x, a = 0, b = 1) => Math.min(b, Math.max(a, x));
export const lerp = (a, b, k) => a + (b - a) * k;
export const sleep = ms => new Promise(r => setTimeout(r, ms));

const SVGNS = 'http://www.w3.org/2000/svg';
// Attributes h() may set. No style strings, no handlers, nothing that takes a URL.
const ATTR = new Set(['id', 'role', 'tabindex', 'title', 'type', 'disabled', 'hidden', 'for', 'lang', 'dir']);

function append(el, kids) {
  for (const k of kids) {
    if (k == null || k === false || k === '') continue;
    if (Array.isArray(k)) append(el, k);
    else el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return el;
}

function apply(el, props) {
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class') { for (const c of String(v).split(/\s+/)) if (c) el.classList.add(c); }
    else if (k === 'text') el.textContent = String(v);
    else if (k === 'on') { for (const [e, fn] of Object.entries(v)) el.addEventListener(e, fn); }
    else if (k === 'vars' || k === 'style') { for (const [p, val] of Object.entries(v)) if (val != null) el.style.setProperty(p, String(val)); }
    else if (k === 'data') { for (const [p, val] of Object.entries(v)) if (val != null) el.dataset[p] = String(val); }
    else if (ATTR.has(k) || k.startsWith('aria-')) el.setAttribute(k, v === true ? '' : String(v));
    else throw new Error('h(): attribute not allowed: ' + k);
  }
}

// h('button.btn.sm#id', {on:{click}}, 'text', child…): tag, classes and id
// from the first word; children are nodes or plain text.
export function h(spec, props, ...kids) {
  const m = /^([a-z0-9]+)?((?:[.#][\w-]+)*)$/i.exec(spec);
  if (!m) throw new Error('h(): bad spec ' + spec);
  const el = document.createElement(m[1] || 'div');
  for (const part of m[2].match(/[.#][\w-]+/g) || []) {
    if (part[0] === '.') el.classList.add(part.slice(1)); else el.id = part.slice(1);
  }
  if (props instanceof Node || typeof props !== 'object' || props === null || Array.isArray(props)) { kids.unshift(props); props = null; }
  if (props) apply(el, props);
  return append(el, kids);
}

// s('path', {d: '…'}): an SVG element. Attributes are numbers and fixed
// strings from this code; text goes in as a child.
export function s(tag, attrs, ...kids) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null) continue;
    if (/^on|href|style/i.test(k)) throw new Error('s(): attribute not allowed: ' + k);
    if (k === 'class') el.setAttribute('class', String(v)); else el.setAttribute(k, String(v));
  }
  return append(el, kids);
}

export const clear = el => { el.replaceChildren(); return el; };
export const fill = (el, ...kids) => { el.replaceChildren(); return append(el, kids); };

/* ---------------- words for numbers and times ---------------- */
const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
export const monthName = i => MON[i];
const pad = n => String(n).padStart(2, '0');
export const date = v => { if (!v) return null; const d = new Date(v); return isNaN(d) ? null : d; };

// The app's idea of "now": the real clock, or the fixture's (development).
let nowOffset = 0;
export const setNow = v => { const d = date(v); nowOffset = d ? d.getTime() - Date.now() : 0; };
export const now = () => new Date(Date.now() + nowOffset);

export function bytes(n) {
  n = Number(n) || 0;
  if (n < 1000) return `${n} bytes`;
  const u = ['KB', 'MB', 'GB', 'TB']; let i = -1; let x = n;
  do { x /= 1024; i++; } while (x >= 999.5 && i < u.length - 1);
  return `${x >= 100 ? Math.round(x) : x >= 10 ? x.toFixed(x % 1 > .05 ? 1 : 0).replace(/\.0$/, '') : x.toFixed(1).replace(/\.0$/, '')} ${u[i]}`;
}

// "−1.8 s", "0", "+0.12 s", "+3 min": a moment relative to the bait.
export function offset(ms) {
  if (!ms) return '0';
  const a = Math.abs(ms), sign = ms < 0 ? '−' : '+';
  if (a < 995) return `${sign}${(a / 1000).toFixed(2).replace(/0$/, '')} s`;
  if (a < 60000) return `${sign}${(a / 1000).toFixed(1).replace(/\.0$/, '')} s`;
  if (a < 3600000) return `${sign}${Math.round(a / 60000)} min`;
  return `${sign}${Math.round(a / 3600000)} h`;
}

// "1.9 s", "3 minutes", "2 hours": how long something lasted.
export function span(ms, long = false) {
  const a = Math.abs(ms);
  if (a < 60000) { const v = a < 9950 ? (a / 1000).toFixed(1).replace(/\.0$/, '') : String(Math.round(a / 1000)); return long ? `${v} second${v === '1' ? '' : 's'}` : `${v} s`; }
  if (a < 3600000) { const v = Math.round(a / 60000); return long ? `${v} minute${v === 1 ? '' : 's'}` : `${v} min`; }
  const v = Math.round(a / 3600000); return long ? `${v} hour${v === 1 ? '' : 's'}` : `${v} h`;
}

export function ago(v) {
  const d = date(v); if (!d) return '';
  const sec = Math.max(0, (now() - d) / 1000);
  if (sec < 50) return 'just now';
  if (sec < 3600) return `${Math.max(1, Math.round(sec / 60))} min ago`;
  if (sec < 86400) return `${Math.round(sec / 3600)} h ago`;
  const days = Math.round(sec / 86400);
  return days === 1 ? 'yesterday' : days < 30 ? `${days} days ago` : day(v);
}

const sameDay = (a, b) => a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
// "Today", "Yesterday", "Nov 19", "Nov 19, 2025"
export function day(v) {
  const d = date(v); if (!d) return '';
  const n = now();
  if (sameDay(d, n)) return 'Today';
  const y = new Date(n); y.setDate(y.getDate() - 1);
  if (sameDay(d, y)) return 'Yesterday';
  return `${MON[d.getMonth()]} ${d.getDate()}${d.getFullYear() !== n.getFullYear() ? ', ' + d.getFullYear() : ''}`;
}
export function clock(v, tenths = false) {
  const d = date(v); if (!d) return '';
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}${tenths ? '.' + Math.floor(d.getMilliseconds() / 100) : ''}`;
}
export const dayTime = v => { const d = date(v); return d ? `${day(v)}, ${clock(v)}` : ''; };
// "0:50", "12:07", "1:02:33": a running count.
export function count(ms) {
  const t = Math.max(0, Math.floor(ms / 1000)), hh = Math.floor(t / 3600), mm = Math.floor(t % 3600 / 60), ss = t % 60;
  return hh ? `${hh}:${pad(mm)}:${pad(ss)}` : `${mm}:${pad(ss)}`;
}
export const plural = (n, one, many = one + 's') => `${n} ${n === 1 ? one : many}`;
export const cap = t => t ? t[0].toUpperCase() + t.slice(1) : t;
// The last part of a Windows or Unix path.
export const baseName = p => String(p || '').split(/[\\/]/).filter(Boolean).pop() || '';
