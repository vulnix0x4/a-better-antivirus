// Baits: every bait on the web, seen from above; pick one to see how it's
// doing, what touched it, and (for the ones with text) what's inside.
import { h, $, fill, ago, day, bytes, plural, baseName } from '../dom.js';
import { tile, line, baitColor, COLORS } from '../icons.js';
import { enter, button, dialog, toast } from '../ui.js';
import { MAX_BAITS } from '../gfx.js';

const KIND = {
  decoy: ['eye', 'Looks real', 'It sits where the real app keeps its data. A stealer can’t tell the difference.'],
  file: ['hook', 'Only thieves open it', 'Nothing on this PC has a reason to read this file.'],
  canary: ['bell', 'Tells on whoever uses it', 'Fake credentials that report where they were tried.'],
};

export function createBaits(app) {
  const el = $('#baits');
  const sub = h('p'), detail = h('div.panel.b-detail'), health = h('div.panel.b-health'), others = h('div.b-others');
  el.append(enter(h('div.hd', h('h1', 'Baits'), sub), 'left', .1), enter(detail, 'right', .3), enter(health, 'up', .42), others);

  let B = null, last = '', sel = '';
  function update(b) {
    if (!b) return;
    const k = JSON.stringify(b); if (k === last) return; last = k; B = b;
    if (!b.items.some(i => i.id === sel)) { const touched = b.items.find(i => i.touchedBy.length); sel = (touched || b.items[0] || {}).id || ''; }
    draw();
  }
  function select(id) { if (!B || !B.items.some(i => i.id === id)) { sel = id; return; } sel = id; draw(); }

  async function inside(it) {
    const r = await app.bridge.act('bait-show', it.id);
    if (!r.ok) { toast(r.message || "ABA couldn't show it.", 'bad'); return; }
    const fs = (r.details && Array.isArray(r.details.files)) ? r.details.files : [];
    dialog(`Inside “${it.label}”`, [
      h('p.dlg-note', 'This is the fake content ABA wrote. Reading it here never opens the bait itself.'),
      fs.length ? fs.map(f => h('div.bf', h('div.bf-h', h('b.mono.sel', baseName(f.path) || f.path), h('span', bytes(f.size))), f.binary ? h('p.bf-bin', 'Not text: nothing to show.') : h('pre.well.sel', { tabindex: '0' }, f.text || ''))) : h('p', r.message || 'Nothing to show.'),
    ], { wide: true });
  }

  function draw() {
    const b = B; app.selectBait(sel);
    fill(sub, b.total === 0 ? 'No baits are planted.' : [h('b', String(b.total)), ' planted. ', b.healthy === b.total ? 'All healthy.' : `${b.total - b.healthy} need${b.total - b.healthy === 1 ? 's' : ''} a look.`]);

    const it = b.items.find(i => i.id === sel);
    detail.hidden = !it;
    if (it) {
      const tb = it.touchedBy, lastT = tb[0];
      const st = it.health === 'ok' ? ['Armed', 'ok'] : it.health === 'missing' ? ['Missing', 'bad'] : ['Needs a look', 'warn'];
      const [kic, kt, kd] = KIND[it.kind] || KIND.file;
      // The heartbeat line has no data yet (absent: heartbeatTrace): the state and when it was checked.
      fill(detail,
        h('div.bd-top', tile(it.icon, baitColor(it.icon), 't-xl', { live: true }), h('div', h('strong', it.label), h('span', it.description || it.name))),
        h('div.bd-health', { data: { s: st[1] } }, h('span.bd-dot'), h('div', h('b', st[0]), h('span', it.healthNote || (it.lastCheck ? `Checked ${ago(it.lastCheck)}` : 'Not checked yet')))),
        h('div.bd-facts',
          h('div', tile('snow', COLORS.ice, 't-sm'), h('p', h('b', tb.length === 0 ? 'Never touched' : tb.length === 1 ? 'Touched once' : `Touched ${tb.length} times`),
            lastT ? [`${tb.length > 1 ? 'Last by ' : 'By '}`, h('button.lnk', { type: 'button', on: { click: () => app.openAlert(lastT.alertId) } }, lastT.program || 'a program'), `, ${day(lastT.time).toLowerCase()}.`] : 'Nothing has gone for it yet.')),
          h('div', tile(kic, COLORS.ice, 't-sm'), h('p', h('b', it.custom ? 'Your own bait' : kt), it.custom ? 'A file you chose to make a bait.' : kd)),
          h('div', tile('doc', COLORS.ice, 't-sm'), h('p', h('b', plural(it.files.length, 'file')), it.createdAt ? `Planted ${day(it.createdAt).toLowerCase()}.` : ''))),
        // "Replant" isn't there yet (absent: replant)
        it.hasText ? h('div.bd-btns', button("See what's inside", { cls: 'sm', onClick: () => inside(it) })) : null);
    }

    // baits beyond what the web has room for
    const extra = b.items.slice(MAX_BAITS);
    others.hidden = !extra.length;
    fill(others, extra.map(x => h('button.chip', { type: 'button', class: x.id === sel ? 'on' : '', on: { click: () => select(x.id) } }, x.label)));

    const all = b.healthy === b.total;
    fill(health,
      h('div.bh-ring', { data: { s: all ? 'ok' : 'warn' } }, ring(b.total ? b.healthy / b.total : 0), h('b', String(b.total))),
      h('div.bh-txt', h('strong', b.total === 0 ? 'Nothing planted' : all ? `All ${b.total} in place` : `${b.healthy} of ${b.total} in place`),
        h('span', !b.serviceRunning ? "ABA's service isn't running: nothing is watching them." : b.lastCheck ? `Health check ${all ? 'passed' : 'ran'} ${ago(b.lastCheck)}` : 'Not checked yet')),
      h('div.bh-checks', b.checks.slice(0, 4).map(c => h('span', { class: c.ok ? '' : 'bad', title: c.detail || null }, line(c.ok ? 'check' : 'warn'), c.name))),
      button('Refresh', { cls: 'sm', onClick: () => app.reload('baits') }));
  }
  function ring(frac) {
    const NS = 'http://www.w3.org/2000/svg'; const svg = document.createElementNS(NS, 'svg'); svg.setAttribute('viewBox', '0 0 80 80');
    for (const [cls, len] of [['r0', null], ['r1', frac]]) { const c = document.createElementNS(NS, 'circle'); c.setAttribute('cx', 40); c.setAttribute('cy', 40); c.setAttribute('r', 32); c.setAttribute('class', cls); if (len !== null) { c.setAttribute('pathLength', 100); c.setAttribute('stroke-dasharray', `${Math.round(len * 100)} 100`); } svg.append(c); }
    return svg;
  }

  return { el, update, select, get selected() { return sel; } };
}
