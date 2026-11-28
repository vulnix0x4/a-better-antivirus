// History: twelve weeks as an ice tray (a cube for every catch), and every
// alert in a list.
import { h, $, fill, day, date, now, monthName, plural } from '../dom.js';
import { tile, line, alertIcon } from '../icons.js';
import { enter } from '../ui.js';

const OUT = { frozen: ['Frozen', 'ice'], 'cut-off': ['Cut off', 'ice'], killed: ['Killed', 'ink'], trusted: ['Trusted', 'green'], resumed: ['Let go', 'ink'], stopped: ['Stopped', 'ink'], alerted: ['Told you', 'amber'], answered: ['Answered', 'ink'] };
const key = d => `${d.getFullYear()}-${d.getMonth() + 1}-${d.getDate()}`;
const isQuiet = it => it.outcome === 'noted';
const isCatch = it => !it.test && it.outcome !== 'noted' && it.outcome !== 'trusted';

export function createHistory(app) {
  const el = $('#history');
  const cal = h('div#cal'), stats = h('div.hi-stats'), rows = h('div.hi-list.panel', { role: 'list' });
  const sub = h('p');
  el.append(enter(h('div.hd', h('h1', 'History'), sub), 'left', .1),
    enter(h('div.panel.hi-cal', cal, h('div.legend.cal-leg', h('span', h('i.cube.s'), 'Caught'), h('span', h('i.cdot.t'), 'Trusted by you'), h('span', h('i.cdot.q'), 'Harmless touch, noted quietly'))), 'up', .25),
    h('div.hi-right', enter(stats, 'right', .35), enter(rows, 'right', .47)));

  let last = '', selected = '', openQuiet = false, H = null;
  function update(hist) {
    if (!hist) return;
    const k = JSON.stringify(hist) + key(now()); if (k === last) return; last = k; H = hist;
    draw();
  }
  function select(id) { selected = id; draw(); const r = rows.querySelector('.row.sel'); if (r) r.scrollIntoView({ block: 'nearest' }); }

  function draw() {
    const hist = H, items = hist.items;
    sub.textContent = items.length ? 'Twelve weeks of watching. Every ice cube is something ABA caught.' : 'Nothing has touched a bait yet. That is the good kind of quiet.';
    if (!selected) { const f = items.find(i => i.outcome === 'frozen' || i.outcome === 'cut-off'); selected = f ? f.id : ''; }

    // ---- the ice tray: 12 weeks, Monday first, ending this week
    const today = now(); today.setHours(0, 0, 0, 0);
    const start = new Date(today); start.setDate(start.getDate() - ((start.getDay() + 6) % 7) - 77);
    const byDay = new Map(); for (const it of items) { const d = date(it.time); if (!d) continue; const kk = key(d); if (!byDay.has(kk)) byDay.set(kk, []); byDay.get(kk).push(it); }
    const cells = [h('span')]; let lastM = -1;
    for (let c = 0; c < 12; c++) { const d0 = new Date(start); d0.setDate(d0.getDate() + c * 7); const m = d0.getDate() <= 7 || c === 0 ? d0.getMonth() : -1; cells.push(h('span.cm', m >= 0 && m !== lastM ? monthName(m) : '')); if (m >= 0) lastM = m; }
    const wd = ['Mon', '', 'Wed', '', 'Fri', '', 'Sun']; let n = 0;
    for (let r = 0; r < 7; r++) {
      cells.push(h('span.cw', wd[r]));
      for (let c = 0; c < 12; c++) {
        const d = new Date(start); d.setDate(d.getDate() + c * 7 + r); const its = byDay.get(key(d)) || [];
        const catchIt = its.find(isCatch), testIt = its.find(i => i.test), trustIt = its.find(i => i.outcome === 'trusted'), quiet = its.filter(isQuiet).length;
        const top = catchIt || testIt || trustIt || its[0];
        let cls = 'cell', inner = null;
        if (d > today) cls += ' fut';
        else if (catchIt || testIt) { cls += ' f' + (catchIt ? '' : ' test'); const g = top.icon === 'miner' ? 'pick' : top.icon === 'clipper' ? 'clipboard' : top.icon === 'system' ? 'warn' : 'snow'; inner = h('i', { vars: { '--k': n++ } }, ...line(g).childNodes); }
        else if (trustIt) cls += ' t';
        else if (quiet) cls += ' q' + (quiet > 1 ? ' q2' : '');
        if (top && its.some(i => i.id === selected)) cls += ' sel';
        const label = `${monthName(d.getMonth())} ${d.getDate()}`;
        cells.push(top && d <= today
          ? h('button', { type: 'button', class: cls, vars: { '--col': c }, 'aria-label': `${label}: ${plural(its.length, 'alert')}`, title: label, on: { click: () => { if (isQuiet(top)) openQuiet = true; select(top.id); } } }, inner)
          : h('div', { class: cls, vars: { '--col': c } }));
      }
    }
    fill(cal, cells);

    // ---- the numbers
    const cn = hist.counts;
    fill(stats, h('div.panel.st.ice', h('b', String(cn.caught)), h('span', 'caught'), h('i.cube.big')), h('div.panel.st', h('b', String(cn.trusted)), h('span', 'trusted')), h('div.panel.st', h('b', String(cn.quiet)), h('span', 'noted quietly')));

    // ---- the list: catches one by one, harmless touches together
    const main = items.filter(i => !isQuiet(i)), quiet = items.filter(isQuiet);
    const row = (it, i) => {
      const [ic, c] = alertIcon(it.icon); const o = OUT[it.outcome];
      return h('button.row', { type: 'button', role: 'listitem', class: it.id === selected ? 'sel' : '', vars: { '--k': Math.min(i, 10) }, data: { id: it.id }, on: { click: () => app.openAlert(it.id) } },
        tile(ic, c), h('div', h('b', it.program || it.title), h('p', it.line)),
        h('span.rt2', h('time', day(it.time)), it.test ? h('span.res', { data: { c: 'ice' } }, 'Test') : o ? h('span.res', { data: { c: o[1] } }, o[0]) : null));
    };
    const list = main.map(row);
    if (quiet.length) {
      const names = [...new Set(quiet.map(q => q.program).filter(Boolean))].slice(0, 2).join(', ');
      list.push(h('button.row.grp', { type: 'button', role: 'listitem', 'aria-expanded': String(openQuiet), vars: { '--k': Math.min(main.length, 10) }, on: { click: () => { openQuiet = !openQuiet; draw(); } } },
        tile('eye', '#57c487'), h('div', h('b', plural(quiet.length, 'harmless touch', 'harmless touches')), h('p', names ? `Signed apps like ${names}. Nothing to do.` : 'Nothing to do.')), line(openQuiet ? 'down' : 'chev')));
      if (openQuiet) list.push(...quiet.map((q, i) => { const r = row(q, main.length + 1 + i); r.classList.add('sub'); return r; }));
    }
    if (!list.length) list.push(h('p.empty', 'No alerts yet.'));
    fill(rows, list);
  }

  return { el, update, select };
}
