// Caught: what ABA caught, what it did about it, and the decision. Opens by
// itself on a catch. Every word about the program is the program's own
// (its name, where it sent): shown as text, never as markup.
import { h, $, fill, offset, span, count, date, dayTime, now, cap } from '../dom.js';
import { tile, line, alertIcon } from '../icons.js';
import { enter, button, spinner } from '../ui.js';

const BTN = {
  kill: { label: 'Kill it', sub: 'Recommended', cls: 'kill', icon: 'x', busy: 'Saving the evidence, then killing it. This can take up to a minute and a half.' },
  resume: { label: 'Unfreeze once', busy: 'Letting it go…' },
  trust: { label: "It's mine", busy: 'Trusting it…' },
  release: { label: 'Reconnect this PC', busy: 'Reconnecting…' },
};
const OUTCOME = { killed: 'Killed', trusted: 'Trusted', resumed: 'Let go once', stopped: 'Stopped', alerted: 'Told you', noted: 'Noted quietly', answered: 'Answered', frozen: 'Frozen', 'cut-off': 'Cut off' };

export function headWord(a) {
  if (a.frozenNow) return ['Frozen.', 'ice'];
  if (a.test) return ['Test passed.', 'ok'];
  if (a.isolated) return ['Offline.', 'ice'];
  switch (a.outcome) {
    case 'cut-off': return ['Cut off.', 'ice'];
    case 'killed': return ['Killed.', 'ink'];
    case 'trusted': return ['Trusted.', 'ok'];
    case 'resumed': return ['Let go.', 'ink'];
    case 'stopped': return ['Stopped.', 'ink'];
    case 'noted': return ['Noted.', 'ok'];
    case 'alerted': return ['Caught.', 'warn'];
    default: return ['Caught.', 'ink'];
  }
}
// "opened your Discord login bait."
export function didWhat(a) {
  const b = a.baits[0]; if (!b) return ' set off an alert.';
  if (b.access === 'swap') return ' swapped a wallet address you copied.';
  if (b.access === 'mine') return ' tried to mine cryptocurrency on this PC.';
  const verb = { read: 'opened', delete: 'deleted', write: 'changed' }[b.access] || 'touched';
  return ` ${verb} your ${b.label}${/bait$/i.test(b.label) ? '' : ' bait'}.`;
}

// The few moments worth showing on the strip: what it did that was bad,
// the bait, the freeze.
function moments(a) {
  const tl = a.report && !a.report.pending ? a.report.timeline : [];
  let bait = tl.find(e => e.kind === 'bait'), fz = tl.find(e => e.kind === 'frozen');
  const start = tl.find(e => e.kind === 'start');
  if (!bait && a.baits[0]) bait = { kind: 'bait', offsetMs: 0, label: cap(didWhat(a).trim().replace(/^(\w+) your /, '$1 the ').replace(/\.$/, '')) };
  if (!fz && (a.frozenNow || a.did.some(d => d.action === 'freeze' && d.ok))) fz = { kind: 'frozen', offsetMs: a.latencyMs || 0, label: 'Frozen', guess: !a.latencyMs };
  const rest = tl.filter(e => e.kind === 'read' || e.kind === 'send');
  const bad = rest.filter(e => e.bad), other = rest.filter(e => !e.bad);
  const pick = [...bad.slice(0, 2), ...other.slice(0, Math.max(0, 2 - bad.length))].sort((x, y) => x.offsetMs - y.offsetMs);
  return { before: bait ? [...pick, bait] : pick, fz, start, more: rest.length - pick.length };
}

export function createCaught(app) {
  const el = $('#caught');
  const h1 = enter(h('h1'), 'left', .15), lede = enter(h('p.c-lede'), 'left', .28), prog = enter(h('div.c-prog'), 'left', .4);
  const verdict = enter(h('div.c-verdict'), 'left', .52), actions = enter(h('div.c-actions'), 'up', .66);
  const fine = enter(h('p.c-fine'), 'up', .72), result = h('p.c-result', { role: 'status' });
  const more = enter(h('div.c-more'), 'up', .78);
  const left = h('div.c-left', h1, lede, prog, verdict, actions, result, fine, more);
  const strip = enter(h('div.panel.c-time'), 'up', .8);
  el.append(left, strip);
  const held = $('#held'), heldT = $('#heldT');

  let A = null, last = '', working = false;
  setInterval(() => { if (A && A.frozenNow && A.frozenSince && el.classList.contains('on')) heldT.textContent = count(now() - date(A.frozenSince)); }, 500);

  async function answer(kind, btn) {
    const a = A; if (!a || working) return;
    working = true; el.classList.add('working'); btn.classList.add('busy');
    fill(result, spinner(), h('span', BTN[kind].busy)); result.dataset.kind = 'busy';
    const r = await app.answer(a, kind);
    working = false; el.classList.remove('working'); btn.classList.remove('busy');
    fill(result, line(r.ok ? 'check' : 'warn'), h('span', r.message || (r.ok ? 'Done.' : "That didn't work."))); result.dataset.kind = r.ok ? 'ok' : 'bad';
    last = ''; // the alert changed (or didn't): draw it again from fresh data
  }

  function update(a) {
    if (!a) return;
    const key = JSON.stringify(a); if (key === last || working) return; last = key;
    if (!A || A.id !== a.id) { fill(result); delete result.dataset.kind; }
    A = a;
    const [word, tone] = headWord(a); h1.textContent = word; el.dataset.tone = tone;
    const p = a.program;

    // what happened, in two sentences
    const l1 = p ? [h('b', p.name), didWhat(a)] : [a.title];
    let l2 = [];
    if (a.frozenNow) {
      l2 = ['ABA froze it', a.latencyMs ? [' ', h('b.icet', span(a.latencyMs)), ' later'] : '', a.cutOff ? ' and cut its internet' : '', a.isolated ? ' and took this PC offline' : '', '.'];
    } else if (a.test) l2 = ['The safe test. ABA caught the fake stealer the way it would a real one', a.latencyMs ? [', ', h('b.icet', span(a.latencyMs)), ' after it opened the bait'] : '', '.'];
    else {
      const done = a.did.filter(d => d.ok).map(d => d.words);
      if (done.length) l2 = ['ABA: ', done.join('. '), '.'];
      else if (a.outcome === 'noted') l2 = ['It looked legitimate, so ABA only noted it.'];
      else if (a.outcome === 'alerted') l2 = ['ABA told you and stopped nothing (that is the protection level it was set to).'];
      if (a.note && a.status === 'resolved' && !/^(killed|test)$/.test(a.note)) l2.push(' ', cap(a.note), '.');
    }
    fill(lede, h('span.c-l1', l1), h('span.c-l2', l2, a.frozenNow ? null : h('time', ' ' + dayTime(a.time) + '.')));

    // the program
    const [ic, c] = alertIcon(a.test ? 'test' : a.outcome === 'trusted' ? 'trusted' : a.outcome === 'noted' ? 'quiet' : a.category === 'miner' ? 'miner' : a.category === 'clipper' ? 'clipper' : p ? 'stealer' : 'system');
    prog.hidden = !p;
    if (p) fill(prog, tile(ic, c, 't-lg', { live: true }), h('div', h('strong', p.name), h('span', (p.signed ? (p.signer ? `Signed by ${p.signer}.` : 'Signed.') : 'Unsigned.') + (p.folder ? ` Ran from ${p.folder}.` : ''))));

    // did it take real data?
    const r = a.report; let tn = 'info', body = null, vicon = 'ask';
    if (r && r.pending) { tn = 'wait'; body = [h('b', 'ABA is still looking at what it did.'), ' This takes a few seconds.']; }
    else if (r) {
      tn = r.tone; vicon = r.tone === 'good' ? 'check' : r.tone === 'bad' ? 'warn' : 'ask';
      const extra = r.summary.length ? r.summary[r.summary.length - 1] : '';
      body = [h('b', r.headline), extra && (r.headline.length + extra.length) < 210 ? ' ' + extra : ''];
    } else if (a.test) { tn = 'good'; vicon = 'check'; body = [h('b', 'Everything worked.'), ' Nothing of yours was touched: the fake stealer only read a bait.']; }
    else if (a.summary) body = [h('b', 'Why ABA noticed: '), a.summary + (/[.!?]$/.test(a.summary) ? '' : '.')];
    verdict.hidden = !body; verdict.dataset.tone = tn;
    if (body) fill(verdict, tn === 'wait' ? spinner() : line(vicon), h('p', body));

    // the answers it takes
    actions.hidden = a.buttons.length === 0;
    fill(actions, a.buttons.filter(b => BTN[b]).map(b => {
      const d = BTN[b]; const btn = button(d.label, { icon: d.icon, sub: d.sub, cls: d.cls || '' });
      btn.dataset.act = b; btn.addEventListener('click', () => answer(b, btn)); return btn;
    }));
    const canTrust = a.buttons.includes('trust');
    fine.hidden = !canTrust;
    fine.textContent = !canTrust ? '' : a.trustForGood ? '“Unfreeze once” lets it run this one time. “It’s mine” trusts it from now on.' : 'Either one lets it run this once. ABA trusts nothing from it.';
    fill(more,
      a.buttons.length === 0 ? h('span.c-out', { data: { o: a.outcome } }, OUTCOME[a.outcome] || 'Answered') : null,
      h('button.lnk', { type: 'button', data: { go: 'report' }, on: { click: () => app.go('report', { id: a.id }) } }, 'See the full report', line('chev')),
      a.buttons.length === 0 ? h('button.lnk.dim', { type: 'button', on: { click: () => app.go('home') } }, 'Back to Home') : null);

    held.dataset.on = a.frozenNow && a.frozenSince ? '1' : '0';
    if (a.frozenNow && a.frozenSince) heldT.textContent = count(now() - date(a.frozenSince));
    drawStrip(a);
  }

  function drawStrip(a) {
    const m = moments(a); const n = m.before.length;
    strip.hidden = n === 0 && !m.fz;
    if (strip.hidden) return;
    const split = m.fz ? 68 : 100; strip.style.setProperty('--split', split + '%');
    const free = m.fz && m.start ? `Ran free for ${span(m.fz.offsetMs - m.start.offsetMs)}` : a.latencyMs && m.fz ? `Stopped ${span(a.latencyMs)} after it opened the bait` : '';
    const after = a.frozenNow ? 'Held in ice.' + (a.cutOff ? ' Internet cut.' : '') + (a.isolated ? ' This PC is offline.' : '')
      : m.fz ? (a.outcome === 'killed' ? 'Then killed.' : a.outcome === 'trusted' ? 'Then let go: you trust it.' : a.outcome === 'resumed' ? 'Then let go, once.' : a.test ? 'Then let go: it was the test.' : 'No longer frozen.') : '';
    const step = Math.min(23, (split - 8) / Math.max(1, n));
    const evs = m.before.map((e, i) => h('div.ev', { class: e.kind === 'bait' ? 'amber' : e.bad ? 'red' : 'dim', vars: { left: (6 + i * step) + '%', '--w': `calc(${step}% - 26px)`, '--k': i } },
      h('time', offset(e.offsetMs)), h('u'), h('p', e.label)));
    if (m.fz) evs.push(h('div.ev.ice', { vars: { left: `calc(${split}% - 8px)`, '--k': n } }, h('time', m.fz.guess ? '' : offset(m.fz.offsetMs)), h('u'), h('p', m.fz.label)));
    fill(strip,
      h('div.ct-free', free ? h('span', free) : null), m.fz ? h('div.ct-ice', { class: a.frozenNow ? '' : 'past' }, h('span', after)) : null,
      h('div.ct-line', h('i')), evs,
      m.more > 0 ? h('span.ct-more', `+${m.more} more in the full report`) : null);
  }

  return { el, update, get alert() { return A; }, reset() { last = ''; } };
}
