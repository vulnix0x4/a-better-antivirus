// Home: is this PC protected, how strictly, which traps are set, and what
// touched a bait lately. While something is frozen it says so and takes you
// to the decision.
import { h, $, fill, plural, day, ago, clamp } from '../dom.js';
import { tile, line, COLORS, alertIcon } from '../icons.js';
import { enter, knob, button } from '../ui.js';
import { reduced } from '../gfx.js';

const STATE_TONE = { protected: 'ok', frozen: 'ice', isolated: 'ice', attention: 'warn', stopped: 'bad' };

export function createHome(app) {
  const el = $('#home');
  const hLive = h('span.live.big'), hText = h('span'), sub = h('p.h-sub'), probs = h('ul.h-probs'), wait = h('div.h-wait');
  const status = enter(h('div.h-status', h('h1', hLive, hText), sub, probs, wait), 'left', .5);

  const k = knob({ onChange: id => app.setPreset(id) });
  const lvName = h('strong'), lvSays = h('span');
  const level = enter(h('div.panel.h-level', h('h3', 'Protection level'), k.el, h('div.g-mid', lvName, lvSays)), 'right', .7);

  const pills = h('div.pills');
  const traps = enter(h('div.panel.h-traps', h('h3', 'Traps'), pills), 'right', .82);

  const recent = h('div.rq');
  const activity = enter(h('div.panel.h-activity', h('div.ph', h('h3', 'Lately at the baits'), h('button.lnk', { type: 'button', on: { click: () => app.go('history') } }, 'See all history', line('chev'))), recent), 'up', .95);

  const play = h('button.play', { type: 'button', 'aria-label': 'Run the safe test', on: { click: () => app.runTest() } }, line('play'));
  const tilt = h('div.panel.tilt', h('div.tl-top', tile('snow', COLORS.ice, '', { live: true }), h('span.dots', h('i'), h('i'), h('i'))),
    h('strong', 'Run the safe test'), h('p', 'A harmless fake stealer goes for a bait. Watch it freeze.'), play);
  const floaty = enter(h('div.floaty', tilt), 'pop', 1.15);

  el.append(status, level, traps, activity, floaty);
  if (!reduced) app.onFrame(t => { if (el.classList.contains('on')) tilt.style.transform = `rotateY(${(-24 + Math.sin(t * .7) * 3).toFixed(2)}deg) rotateX(${(10 + Math.cos(t * .55) * 2).toFixed(2)}deg) rotateZ(-2deg) translateY(${(Math.sin(t * .9) * 4).toFixed(1)}px)`; });

  const num = n => h('b', { data: { count: n } }, String(n));
  function pill(icon, color, value, label, main) {
    return h('div.pill', { class: main ? 'main' : (value === 'Off' ? 'off' : '') }, tile(icon, color, '', { live: true }), h('b', String(value)), h('em', label));
  }

  let last = '';
  function update(sn) {
    if (!sn) return;
    const key = JSON.stringify({ ...sn, now: 0 }); if (key === last) return; last = key;
    const p = sn.protection, tone = STATE_TONE[p.state] || 'warn';
    el.dataset.tone = tone;
    hText.textContent = p.headline; hText.parentElement.classList.toggle('long', p.headline.length > 20);

    // one line under the headline
    const b = sn.baits; const parts = [];
    if (b.total === 0) parts.push('No baits are planted yet.');
    else if (b.healthy === b.total) parts.push(num(b.total), ` bait${b.total === 1 ? '' : 's'} armed.`);
    else parts.push(num(b.healthy), ' of ', num(b.total), ' baits in place.');
    if (!sn.waiting.length) {
      if (sn.quietDays > 0) parts.push(' Quiet for ', num(sn.quietDays), ` day${sn.quietDays === 1 ? '' : 's'}.`);
      else if (sn.quietDays === 0 && sn.lastCatch) parts.push(' Last catch: today.');
    }
    fill(sub, parts);
    const notes = p.problems.slice(0, 3).map(t => h('li', line('warn'), h('span', t)));
    if (p.learning) notes.push(h('li.soft', line('eye'), h('span', 'Learning mode: for now ABA only notes what touches the baits' + (p.learningUntil ? `, until ${day(p.learningUntil)}.` : '.'))));
    if (sn.update && sn.update.available) notes.push(h('li.soft', line('update'), h('button.lnk', { type: 'button', on: { click: () => app.go('settings') } }, `Version ${sn.update.latest} is ready`, line('chev'))));
    fill(probs, notes);

    // something waiting for an answer
    fill(wait, sn.waiting.slice(0, 2).map(w => {
      const [ic, c] = alertIcon(w.icon);
      return h('div.hw', tile(ic, c, 't-lg', { live: true }), h('div.hw-t', h('strong', w.program || w.title), h('span', w.outcome === 'frozen' ? 'Held in ice, waiting for your answer.' : w.line)),
        button('Decide now', { cls: 'ice', onClick: () => app.openAlert(w.id) }));
    }), sn.waiting.length > 2 ? h('p.hw-more', `and ${sn.waiting.length - 2} more in History`) : null);

    // protection level
    k.set(sn.preset.id); lvName.textContent = sn.preset.name; lvSays.textContent = sn.preset.says;

    // traps: the baits, then what else is set (only what this system has)
    const t = sn.traps, list = [pill('hook', COLORS.green, t.baits, 'Baits', true)];
    if (t.clipboard.supported) list.push(pill('clipboard', COLORS.amber, t.clipboard.on ? 'On' : 'Off', 'Clipboard'));
    if (t.miners.supported) list.push(pill('pick', COLORS.green, t.miners.on ? 'On' : 'Off', 'Miner trap'));
    if (list.length < 3) list.push(pill('snow', COLORS.ice, t.instant ? 'On' : 'Off', 'Instant freeze'));
    if (list.length < 3) list.push(pill('tape', COLORS.teal, t.recorder ? 'On' : 'Off', 'Recorder'));
    fill(pills, list);

    // harmless touches, lately (the 30-day chart has no data yet: sn.absent says so)
    const rq = sn.recentQuiet.slice(0, 3);
    activity.hidden = rq.length === 0;
    fill(recent, rq.map(r => h('button.rq-i', { type: 'button', on: { click: () => app.openAlert(r.id) } },
      tile('eye', COLORS.green, 't-sm'), h('div', h('b', r.program || r.title), h('p', `${r.bait ? r.bait + '. ' : ''}${r.line}`)), h('time', ago(r.time)))));
    countUp();
  }

  // The numbers count up the first time Home is shown (on the scene's clock).
  let counted = false, countT0 = null;
  function countUp() {
    if (counted || reduced || !app.hasScene() || !el.classList.contains('enter')) return; counted = true;
    countT0 = app.sceneTime() + 1.0;
    for (const n of el.querySelectorAll('b[data-count]')) n.textContent = '0';
  }
  app.onFrame(t => {
    if (countT0 === null) return;
    const k2 = clamp((t - countT0) / 1.3), e = 1 - Math.pow(1 - k2, 3);
    for (const n of el.querySelectorAll('b[data-count]')) n.textContent = String(Math.round(+n.dataset.count * e));
    if (k2 >= 1) countT0 = null;
  });

  return { el, update, setTestRunning(v) { play.disabled = v; play.classList.toggle('busy', v); } };
}
