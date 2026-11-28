// The full report: the timeline, what to do now, where it was sending, what
// left the PC, the files it packed, the program, and the evidence. Where ABA
// doesn't know, it says so. All of it is the caught program's own strings:
// text only.
import { h, s, $, fill, bytes, offset, span, clock, dayTime, baseName, cap, clamp, plural } from '../dom.js';
import { tile, line, COLORS, alertIcon } from '../icons.js';
import { button, spinner, copyButton, toast } from '../ui.js';
import { reduced } from '../gfx.js';
import { didWhat } from './caught.js';

const NUM = ['No', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven', 'Eight', 'Nine'];
const WHERE = { memory: 'Found in its memory', file: 'Found in a file it wrote', 'memory+file': 'Found in its memory and in a file', connection: 'It connected here' };
const ADDR = {
  'discord-webhook': ['discord', 'A Discord webhook', 'The thief reads what arrives here.'],
  'telegram-bot': ['telegram', 'A Telegram bot', 'The thief reads what arrives here.'],
  url: ['globe', 'A web address', ''],
  connection: ['up', 'A connection it made', ''],
};

// "Kill X: it's still frozen." -> a title and the rest. The words stay as
// they are (only a first letter is capitalised, never an address).
const capWord = t => /^[a-z]+:\/\//.test(t) ? t : cap(t);
function splitStep(t) {
  let i = t.indexOf(': ');
  if (i > 0 && i < 64) return [t.slice(0, i), capWord(t.slice(i + 2))];
  i = t.indexOf(', then ');
  if (i > 0 && i < 64) return [t.slice(0, i), capWord(t.slice(i + 2))];
  return t.length > 64 ? ['', t] : [t, ''];
}
function stepIcon(t) {
  if (/chrome/i.test(t)) return ['chrome', COLORS.amber];
  if (/discord/i.test(t)) return ['discord', COLORS.ice];
  if (/telegram/i.test(t)) return ['telegram', COLORS.ice];
  if (/crypto|wallet|seed/i.test(t)) return ['wallet', COLORS.green];
  if (/password|sign out|log ?out|2fa/i.test(t)) return ['key', COLORS.ink];
  if (/offline|internet/i.test(t)) return ['netoff', COLORS.red];
  if (/scan|defender|reset/i.test(t)) return ['shield', COLORS.green];
  return null;
}
const panel = (cls, title, hint, ...kids) => h('div.panel', { class: cls, data: { reveal: '1' } }, h('div.ph', h('h3', title), hint ? (hint instanceof Node ? hint : h('span.hint', hint)) : null), ...kids);
const list = (items, cls = '') => h('ul.r-list', { class: cls }, items.map(t => h('li', t)));

export function createReport(app) {
  const el = $('#report'); const wrap = h('div.r-wrap'); el.append(wrap);
  el.addEventListener('scroll', () => app.setScroll(el.scrollTop), { passive: true });
  const io = new IntersectionObserver(es => { for (const e of es) if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } }, { root: el, rootMargin: '0px 0px -60px 0px' });
  let A = null, last = '', flows = [], flowBox = null, flowData = null;

  /* ---- the timeline ---- */
  function timeline(a, r) {
    const tl = r.timeline; if (!tl.length) return null;
    const fz = tl.find(e => e.kind === 'frozen'); let before = tl.filter(e => e !== fz);
    const max = fz ? 5 : 6; let dropped = 0;
    if (before.length > max) { // keep the start, the bait and what was bad; then the rest in order
      const keep = new Set(before.filter(e => e.kind === 'start' || e.kind === 'bait' || e.bad).slice(0, max));
      for (const e of before) { if (keep.size >= max) break; keep.add(e); }
      dropped = before.length - keep.size; before = before.filter(e => keep.has(e));
    }
    const dur = (fz || tl[tl.length - 1]).offsetMs - tl[0].offsetMs;
    const split = fz ? 76 : 100, step = (split - 2) / Math.max(1, before.length);
    const ico = e => e.kind === 'start' ? ['virus', COLORS.red] : e.kind === 'bait' ? ['hook', COLORS.amber] : e.kind === 'send' ? ['up', e.bad ? COLORS.red : COLORS.amber]
      : [/cookie/i.test(e.label) ? 'cookie' : /password|login|key/i.test(e.label) ? 'key' : /wallet/i.test(e.label) ? 'wallet' : 'doc', e.bad ? COLORS.red : COLORS.amber];
    const revs = before.map((e, i) => {
      const [n, c] = ico(e);
      return h('div.rev', { class: e.kind === 'start' ? '' : e.kind === 'bait' ? 'amber' : e.bad ? 'red' : 'amber', vars: { left: (2 + i * step) + '%', width: `calc(${step}% - 14px)`, '--k': i } },
        tile(n, c), h('time', e.kind === 'start' ? clock(e.at, true) : offset(e.offsetMs)), h('b', e.label), e.detail ? h('p', e.detail) : null);
    });
    if (fz) revs.push(h('div.rev.ice', { vars: { left: (split + 2) + '%', width: `calc(${100 - split - 4}%)`, '--k': before.length } }, tile('snow', COLORS.ice), h('time', offset(fz.offsetMs)), h('b', fz.label),
      h('p', a.frozenNow ? (a.cutOff ? 'Internet cut' : 'Still held') : a.outcome === 'killed' ? 'Killed since' : 'Let go since')));
    const svg = s('svg', { class: 'rt-line', viewBox: '0 0 1200 8', preserveAspectRatio: 'none' }, s('path', { d: 'M0 4H1200', pathLength: 100 }));
    return panel('r-time', dur >= 1000 && before.length > 1 ? `The ${span(dur, true)} that mattered` : 'What happened', dayTime(r.baitAt || a.time),
      h('div.rt', { vars: { '--split': split + '%' } }, h('div.rt-free'), fz ? h('div.rt-ice', line('snow')) : null, svg, revs),
      dropped ? h('p.fine', `${plural(dropped, 'more moment')} in the text at the end.`) : null);
  }

  /* ---- what to do ---- */
  function todo(a, r) {
    const steps = r && r.steps.length ? r.steps : a.checklist; if (!steps.length) return null;
    const urgent = r && r.steps.length ? r.stepsUrgent : a.tier === 'critical';
    const items = steps.map((t, i) => {
      const [title, rest] = splitStep(t); const ic = stepIcon(title || rest);
      const kill = /^kill /i.test(title) && a.buttons.includes('kill') ? button('Kill it', { icon: 'x', cls: 'kill sm', onClick: async () => { const res = await app.answer(a, 'kill'); toast(res.message || (res.ok ? 'Killed.' : "That didn't work."), res.ok ? 'ok' : 'bad'); } }) : null;
      return h('li', h('span.num', String(i + 1)), h('div', title ? h('b', title) : null, rest ? h('p', { class: title ? '' : 'solo' }, rest) : null), kill || (ic ? tile(ic[0], ic[1]) : null));
    });
    // "0 of 3 done" and the ticks have no data yet (absent: checklistTicks)
    return panel('r-todo', urgent ? 'Do these now' : 'To be safe', null, h('ol', items));
  }

  /* ---- where it was sending ---- */
  function sending(a, r) {
    const rows = [];
    if (a.mine) {
      if (a.mine.pool) rows.push({ icon: 'pick', color: COLORS.amber, title: 'A mining pool', sub: 'It tried to mine here, for someone else.', value: a.mine.pool, hint: 'The miner trap answered instead' });
      if (a.mine.wallet) rows.push({ icon: 'wallet', color: COLORS.red, title: 'The wallet it mines for', sub: a.mine.agent ? `Miner: ${a.mine.agent}` : '', value: a.mine.wallet });
    }
    const w = (a.clipper && a.clipper.wallet) || (r && r.attackerWallet);
    if (w) rows.push({ icon: 'wallet', color: COLORS.red, title: "The attacker's address", sub: cap((a.clipper && a.clipper.note) || (r && r.walletNote) || 'what it swapped in for yours') + '.', value: w });
    for (const ad of (r ? r.addresses : [])) {
      const [icon, title, sub] = ADDR[ad.kind] || ADDR.url;
      rows.push({ icon, color: ad.kind === 'url' || ad.kind === 'connection' ? COLORS.amber : COLORS.red, title: ADDR[ad.kind] ? title : (ad.label || title), sub: sub || (ad.shareable ? '' : 'It may be from your own data it collected.'), value: ad.value, hint: WHERE[ad.where] || '' });
    }
    if (!rows.length) return null;
    const [first, ...rest] = rows;
    // "Shut down this webhook" isn't there yet (absent: webhookShutdown); Copy is.
    return panel('r-hook', a.mine ? 'Where it was mining' : 'Where it was sending', first.hint,
      h('div.hook-row', tile(first.icon, first.color, 't-lg', { live: true }), h('div', h('b', first.title), first.sub ? h('p', first.sub) : null)),
      h('div.well.url.sel', first.value),
      h('div.hook-btns', copyButton(app.bridge, () => first.value)),
      rest.length ? h('div.hook-more', rest.slice(0, 5).map(x => h('div.hm', tile(x.icon, x.color, 't-sm'), h('div', h('b', x.title), h('p.mono.sel', x.value)), copyButton(app.bridge, () => x.value, 'Copy', 'sm ghost')))) : null,
      rows.length > 6 ? h('p.fine', `${rows.length - 6} more in the text at the end.`) : null);
  }

  /* ---- what left the PC ---- */
  function flow(a, r) {
    const state = r.dataLeft; let sends = r.sends.slice().sort((x, y) => (y.after - x.after) || (y.bytes - x.bytes));
    if (!state && !sends.length) return null;
    const more = Math.max(0, sends.length - 3); sends = sends.slice(0, 3);
    const says = state === 'nothing' ? h('div.fl-say.good', line('check'), h('div', h('b', 'Nothing left this PC once it had your data.'), sends.length ? h('p', 'What it sent earlier is below.') : null))
      : state === 'cannot-tell' ? h('div.fl-say.warn', line('ask'), h('div', h('b', "ABA can't tell what left this PC."), r.dataLeftWhy.map(t => h('p', t))))
        : state === 'sent' ? null : null;
    const legend = h('div.legend', sends.some(x => x.after) ? h('span', h('i.lg.r'), 'Got out, after it had your data') : null, sends.some(x => !x.after) ? h('span', h('i.lg.a'), 'Sent before it touched anything of yours') : null);
    let diagram = null;
    if (sends.length) {
      const p = a.program; const [ic, c] = alertIcon(a.category === 'miner' ? 'miner' : a.category === 'clipper' ? 'clipper' : 'stealer');
      const src = h('div.fl-src', tile(ic, c, 't-lg'), h('div', h('b', p ? p.name : 'The program'), h('p', p ? (p.signed ? 'signed' : 'unsigned') : '')));
      const dst = h('div.fl-dst', sends.map(x => h('div.fl-card', { class: x.after ? 'red' : 'amber' },
        h('span.fl-h', x.host || x.to), h('b', `${bytes(x.bytes)} ${x.after ? 'got out' : 'went out'}`),
        h('span.fl-s', (x.after ? `${span(Math.abs(x.offsetMs))} ${x.offsetMs <= 0 ? 'before' : 'after'} it opened the bait` : 'Before it had anything of yours') + (x.lan ? ', on your own network' : '')))));
      const svg = s('svg', { class: 'fl-svg', 'aria-hidden': 'true' });
      diagram = h('div.flow', { vars: { '--n': sends.length } }, src, svg, dst);
      flowBox = diagram; flowData = sends;
    } else { flowBox = null; flowData = null; }
    // "3 sends blocked / 194 KB never left" isn't known yet (absent: blockedSends)
    return panel('r-flow', 'What left your PC', sends.length ? legend : null, says, diagram, more ? h('p.fine', `${plural(more, 'more destination')} in the text at the end.`) : null);
  }
  // The ribbons are measured once the panel has a size.
  function drawFlow() {
    flows = [];
    if (!flowBox || !flowBox.isConnected) return;
    const svg = flowBox.querySelector('.fl-svg'), W = svg.clientWidth, H = svg.clientHeight; if (!W || !H) return;
    svg.setAttribute('viewBox', `0 0 ${W} ${H}`); svg.replaceChildren();
    const n = flowData.length, cardH = 78, gap = 14, total = n * cardH + (n - 1) * gap, top = (H - total) / 2, g = s('g', {});
    flowData.forEach((x, i) => {
      const y1 = top + i * (cardH + gap) + cardH / 2, y0 = H / 2 + (i - (n - 1) / 2) * 26;
      const d = `M0 ${y0.toFixed(1)} C${(W * .45).toFixed(1)} ${y0.toFixed(1)} ${(W * .5).toFixed(1)} ${y1.toFixed(1)} ${W} ${y1.toFixed(1)}`;
      const wd = x.after ? clamp(Math.log10(Math.max(10, x.bytes)) * 4.4, 6, 24) : 5;
      const path = s('path', { d, class: x.after ? 'fl-p red' : 'fl-p amber', 'stroke-width': wd.toFixed(1) }); svg.append(path);
      const L = path.getTotalLength(), dots = x.after ? 6 : 3;
      for (let k = 0; k < dots; k++) { const c = s('circle', { r: x.after ? 3.2 : 2.2, class: x.after ? 'fl-d red' : 'fl-d amber' }); g.append(c); const o = { path, L, c, off: k / dots, sp: x.after ? .16 : .1, w: wd, j: ((k * 7 + i * 3) % 5) / 5 - .4 }; flows.push(o); place(o, o.off); }
    });
    svg.append(g);
  }
  function place(f, k) { const p = f.path.getPointAtLength(k * f.L); f.c.setAttribute('cx', p.x.toFixed(1)); f.c.setAttribute('cy', (p.y + f.j * f.w * .7).toFixed(1)); f.c.setAttribute('opacity', (Math.sin(k * Math.PI) * .9 + .1).toFixed(2)); }
  if (!reduced) app.onFrame(t => { if (flows.length && el.classList.contains('on')) for (const f of flows) place(f, (t * f.sp + f.off) % 1); });
  new ResizeObserver(() => drawFlow()).observe(el);

  /* ---- the files it packed ---- */
  function files(r) {
    if (!r.staged.length && !r.unpacked.length) return null;
    const TAG = { 'real-copy': ['Real', 'red'], bait: ['Bait', 'ice'], 'named-like': ['Named like yours', 'amber'] };
    const blocks = r.staged.slice(0, 3).map(f => {
      const big = Math.max(1, ...f.entries.map(e => e.size));
      return h('div.stg', h('div.zip', h('div.zipico', tile(f.archive ? 'zip' : 'doc', COLORS.amber)), h('div', h('b.sel', f.name || baseName(f.path)), h('p', `${bytes(f.size)}${f.folder ? ', in ' + (baseName(f.folder) || f.folder) : ''}${f.heldOpen ? '. It had this open.' : ''}`))),
        f.what && !f.entries.length ? h('p.fine', cap(f.what) + '.') : null,
        f.entries.length ? h('div.bars', f.entries.slice(0, 6).map(e => { const [word, tone] = TAG[e.tag] || ['', 'dim']; return h('div', { class: tone, vars: { '--w': Math.max(2, Math.round(e.size / big * 100)) + '%' } }, h('span', line(e.tag === 'bait' ? 'hook' : e.tag === 'real-copy' ? 'warn' : 'doc'), h('span.bn', e.name)), h('em', bytes(e.size)), word ? h('small', word) : h('small.none'), h('u')); })) : null,
        f.entries.length > 6 || f.more ? h('p.fine', `${plural((f.entries.length > 6 ? f.entries.length - 6 : 0) + (f.more || 0), 'more file')} not shown.`) : null);
    });
    const saved = r.staged.some(f => f.saved);
    return panel('r-files', r.staged.length ? 'Files it packed' : 'Files it left', saved ? 'A copy is kept as evidence' : '', blocks,
      r.staged.length > 3 ? h('p.fine', `${plural(r.staged.length - 3, 'more file')} in the text at the end.`) : null,
      r.unpacked.length ? h('div.unp', h('b', 'Its own code, unpacked while it ran'), list(r.unpacked.slice(0, 4).map(u => `${baseName(u.dir) || u.dir}: ${plural(u.files, 'file')}, ${bytes(u.size)}`))) : null);
  }

  /* ---- the program ---- */
  function program(a) {
    const p = a.program; if (!p) return null;
    const row = (k, v, cls = '') => v ? h('div', h('dt', k), h('dd', { class: cls + ' sel' }, v)) : null;
    const sha = p.sha256 ? p.sha256.replace(/(.{4})/g, '$1 ').trim() : '';
    const copyAll = a.report && a.report.sections && a.report.sections.length
      ? copyButton(app.bridge, () => a.report.sections.map(x => x.title.toUpperCase() + '\n' + x.lines.join('\n')).join('\n\n'), 'Copy the whole report') : null;
    // The program's size isn't known yet (absent: programSize)
    return panel('r-prog', 'The program', copyAll, h('dl',
      row('File', p.path), row('Signature', p.signature, p.signed ? '' : 'redt'),
      row('Started by', p.startedBy), p.commandLine && p.commandLine.replace(/"/g, '') !== p.path ? row('Command line', p.commandLine, 'mono') : null,
      row('Ran as', p.user), p.origin && p.origin.line ? h('div', h('dt', 'Came from'), h('dd.sel', p.origin.line, h('small', 'What the browser recorded: a lead, not proof.'))) : null,
      row('Process', `${p.pid}${p.exited ? ' (it has ended)' : ''}`),
      sha ? h('div', h('dt', 'Fingerprint'), h('dd.mono.sel', sha, copyButton(app.bridge, () => p.sha256, 'Copy', 'sm ghost'))) : null,
      a.baits.length ? row(a.baits.length > 1 ? 'Baits' : 'Bait', a.baits.map(b => b.label).join(', ')) : null));
  }

  /* ---- evidence, what ABA did, what it could see ---- */
  function evidence(a, r) {
    const ev = r && r.evidence; const kids = [];
    if (ev) {
      kids.push(h('div.ev-top', tile(ev.saved ? 'lock' : 'doc', ev.saved ? COLORS.green : COLORS.dim, 't-lg'), h('div', h('b', ev.saved ? 'Saved, for administrators only' : 'Nothing was saved'), ev.saved && ev.folder ? h('p.mono.sel', ev.folder) : null)));
      const notes = [];
      if (ev.memoryImage) notes.push("It includes a copy of the program's memory, which may hold your own passwords and cookies. Keep it to yourself.");
      if (ev.memoryScanned) notes.push(`${bytes(ev.memoryScanned)} of its memory looked through.`);
      if (notes.length) kids.push(list(notes));
    }
    if (a.did.length) kids.push(h('h4', 'What ABA did'), h('ul.r-did', a.did.map(d => h('li', { class: d.ok ? 'ok' : 'bad' }, line(d.ok ? 'check' : 'warn'), h('span', d.words), h('time', clock(d.time))))));
    if (a.reasons.length) kids.push(h('h4', 'Why ABA rated it so'), list(a.reasons.map(cap)));
    return kids.length ? panel('r-evid', 'Evidence', null, kids) : null;
  }
  function seen(r) {
    const kids = [];
    if (r.watched.length) kids.push(h('div.r-watch', r.watched.map(w => h('div', { class: w.state }, line(w.state === 'watched' ? 'check' : w.state === 'absent' ? 'min' : 'ask'),
      h('span', h('b', cap(w.name)), h('small', w.state === 'watched' ? 'watched' : w.state === 'absent' ? 'not on this PC' : 'not seen' + (w.why ? ': ' + w.why : '')))))));
    if (r.notes.length) kids.push(h('h4', "What couldn't be looked at"), list(r.notes));
    if (r.left.length) kids.push(h('h4', 'What would start it again'), list(r.left, 'bad'));
    if (r.openFiles.length) kids.push(h('h4', 'Files it has open'), list(r.openFiles.slice(0, 5).map(f => baseName(f.path) + (f.what ? ` (${f.what})` : '')), 'mono'));
    return kids.length ? panel('r-seen', 'What ABA could see', null, kids) : null;
  }
  function unsure(r) {
    if (!r.unsure.length && !r.leads.length) return null;
    return h('div.panel.r-unsure', { data: { reveal: '1' } }, line('ask'), h('div',
      r.unsure.length ? [h('h3', "Why ABA can't be sure"), list(r.unsure)] : null,
      r.leads.length ? [h('h3', 'Hints, not proof'), list(r.leads)] : null));
  }
  function fullText(r) {
    if (!r.sections.length) return null;
    const body = h('div.r-text', { hidden: true }, r.sections.map(x => h('section', h('h4', x.title), x.lines.map(l => h('p.mono.sel', l)))));
    const tog = h('button.btn.sm', { type: 'button', 'aria-expanded': 'false', on: { click: () => { body.hidden = !body.hidden; tog.setAttribute('aria-expanded', String(!body.hidden)); tog.querySelector('span').textContent = body.hidden ? 'Show it' : 'Hide it'; } } }, h('span', 'Show it'));
    return panel('r-full', 'The whole report, as text', tog, body);
  }

  function update(a) {
    if (!a) return;
    const key = JSON.stringify(a); if (key === last) return; last = key;
    const fresh = !A || A.id !== a.id; A = a; const keep = el.scrollTop;
    const r = a.report, p = a.program, ready = r && !r.pending;
    const title = p ? `What ${p.name} did` : a.title;
    const n = ready ? r.steps.length : 0;
    const head = h('div.r-head', { data: { tone: r ? (r.pending ? 'wait' : r.tone) : 'info' } },
      h('button.back.lnk', { type: 'button', on: { click: () => app.go('caught', { id: a.id }) } }, line('back'), 'Back to the catch'),
      h('h1', { class: title.length > 30 ? 'long' : '' }, title),
      h('p', r && r.pending ? [spinner(), 'ABA is still looking at what it did. This fills in by itself.'] : ready ? [h('span', r.headline), n ? h('span', `${NUM[n] || n} thing${n === 1 ? '' : 's'} to do${r.stepsUrgent ? ' now' : ', to be safe'}.`) : null]
        : [h('span', p ? [h('b', p.name), didWhat(a)] : a.summary), h('span', 'ABA did not look further into this one.')]));
    const two = (cls, ...kids) => { kids = kids.filter(Boolean); return kids.length ? h('div.r-two', { class: cls + (kids.length === 1 ? ' one' : '') }, kids) : null; };
    flowBox = null; flowData = null;
    fill(wrap, head,
      ready ? unsure(r) : null,
      ready ? timeline(a, r) : null,
      two('', todo(a, ready ? r : null), sending(a, ready ? r : null)),
      ready ? flow(a, r) : null,
      two('b', ready ? files(r) : null, program(a)),
      two('c', evidence(a, ready ? r : null), ready ? seen(r) : null),
      ready && r.steps.length && a.checklist.length ? panel('r-after', 'After a catch like this', null, h('ol.r-check', a.checklist.map(t => h('li', t)))) : null,
      ready ? fullText(r) : null);
    for (const pn of wrap.querySelectorAll('[data-reveal]')) { if (fresh && !reduced) io.observe(pn); else pn.classList.add('in'); }
    if (!fresh) el.scrollTop = keep;
    requestAnimationFrame(drawFlow);
  }

  return {
    el, update, get alert() { return A; },
    enterScreen() { el.scrollTop = 0; app.setScroll(0); requestAnimationFrame(drawFlow); },
    revealAll() { for (const pn of wrap.querySelectorAll('[data-reveal]')) pn.classList.add('in'); },
    reset() { last = ''; A = null; },
  };
}
