// The locked view: what anyone may see when the app runs without
// administrator rights. One button, which asks Windows to open ABA properly.
import { h, $, fill } from '../dom.js';
import { glyph as line } from '../glyphs.js';

export function createLocked(app) {
  const el = $('#locked');
  const title = h('h1'), text = h('p.lk-text'), facts = h('ul.lk-facts'), err = h('p.hint', { role: 'alert' });
  const open = h('button.btn.primary#openAba', { type: 'button' }, line('shield'), h('span', 'Open ABA'));
  open.addEventListener('click', async () => {
    open.disabled = true; err.textContent = '';
    const msg = await app.bridge.openElevated();
    open.disabled = false; err.textContent = msg || '';
  });
  const cube = h('span.lk-cube', { 'aria-hidden': 'true' });
  el.append(h('div.lk-card', h('div.lk-mark', h('span.mark.big'), cube), title, text, open, err, facts));

  function update(l, alertId) {
    const frozen = !!(l && l.somethingFrozen), waiting = frozen || !!alertId || (l && l.openAlerts > 0);
    el.dataset.state = l ? l.state : 'unknown';
    cube.hidden = !frozen;
    title.textContent = frozen ? 'Something is frozen' : alertId || (l && l.openAlerts > 0) ? 'ABA caught something' : l && (l.state === 'stopped' || l.state === 'attention') ? l.headline : 'ABA is protecting this PC';
    text.textContent = waiting ? 'An administrator needs to decide what happens to it. Open ABA to see what it is.'
      : l && l.isolated ? 'This PC was taken offline after a catch. An administrator can reconnect it in ABA.'
        : 'Only an administrator can see the details and change anything.';
    const rows = [];
    if (l) {
      rows.push([l.baitsHealthy === l.baits, `${l.baitsHealthy} of ${l.baits} baits in place`]);
      for (const c of l.health.slice(0, 3)) rows.push([c.ok, c.name]);
    }
    fill(facts, rows.map(([ok, t]) => h('li', { class: ok ? '' : 'bad' }, line(ok ? 'check' : 'warn'), h('span', t))));
  }
  return { el, update };
}
