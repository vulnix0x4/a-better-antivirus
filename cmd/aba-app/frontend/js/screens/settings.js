// Settings: how strict ABA is (the same knob as Home), the traps, the flight
// recorder, phone alerts, updates and the safe test.
import { h, $, fill, ago } from '../dom.js';
import { tile, line, COLORS } from '../icons.js';
import { enter, knob, toggle, button, toast, spinner } from '../ui.js';

const DOES = { alert: ['bell', COLORS.amber], freeze: ['snow', COLORS.ice], cut: ['netoff', COLORS.red], offline: ['pc', COLORS.red] };
const VIA = { ntfy: 'ntfy', pushover: 'Pushover', discord: 'Discord', email: 'email' };

export function createSettings(app) {
  const el = $('#settings');
  const k = knob({ big: true, onChange: id => app.setPreset(id) });
  const opts = h('div.lv-opts'), lvNote = h('p.lv-note');
  const level = enter(h('div.panel.s-level', h('div.ph', h('h3', 'When something goes for a bait')), h('div.lv', h('div.lv-knob', k.el), opts), lvNote), 'up', .2);
  const traps = enter(h('div.s-traps'), 'up', .32);
  const play = h('button.play', { type: 'button', 'aria-label': 'Run the safe test', on: { click: () => app.runTest() } }, line('play'));
  const test = enter(h('div.panel.s-test', tile('snow', COLORS.ice, 't-lg', { live: true }), h('div', h('b', 'Run the safe test'), h('p', 'A harmless fake stealer goes for a bait. Watch ABA freeze it.')), play), 'up', .44);
  const phone = enter(h('div.panel.s-phone'), 'right', .3), upd = enter(h('div.panel.s-upd'), 'right', .42);
  el.append(enter(h('div.hd', h('h1', 'Settings')), 'left', .1), level, traps, test, phone, upd);

  let last = '', updBusy = false, progress = [];
  const sw = (kind, name) => async on => {
    const r = await app.bridge.act(kind, '', on ? 'on' : 'off');
    toast(r.message || (r.ok ? `${name} is ${on ? 'on' : 'off'}.` : `Couldn't change ${name}.`), r.ok ? 'ok' : 'bad');
    app.reload('settings'); return r.ok;
  };
  function trap(icon, color, on, name, text, kind) {
    return h('div.panel.trap', { class: on ? '' : 'off' }, tile(icon, color, 't-lg', { live: true }), toggle(on, name, sw(kind, name)), h('b', name), h('p', text));
  }

  function update(st) {
    if (!st) return;
    const key = JSON.stringify(st) + updBusy + progress.length; if (key === last) return; last = key;

    k.set(st.preset);
    fill(opts, st.presets.map(p => h('button', { type: 'button', class: p.id === st.preset ? 'on' : '', 'aria-pressed': String(p.id === st.preset), data: { preset: p.id }, on: { click: () => k.pick(p.id) } },
      h('b', p.name), h('div.seq', p.does.filter(d => DOES[d]).map(d => tile(DOES[d][0], DOES[d][1], 't-sm'))), h('p', p.says))));
    lvNote.hidden = st.preset !== 'custom' && !st.learning;
    lvNote.textContent = st.preset === 'custom' ? 'Right now it is set by hand (custom). Pick a level to go back to one of these.' : st.learning ? 'Learning mode is on: for now ABA only notes what touches the baits.' : '';

    const cards = [trap('snow', COLORS.ice, st.instant, 'Instant freeze', 'Stops it about 0.1 s after it opens a bait.', 'instant')];
    if (st.clipboard.supported) cards.push(trap('clipboard', COLORS.amber, st.clipboard.on, 'Clipboard bait', 'Catches programs that swap a crypto address you copied.', 'clipboard'));
    if (st.miners.supported) cards.push(trap('pick', COLORS.green, st.miners.on, 'Miner trap', 'A fake mining pool that hidden miners walk into.', 'miners'));
    cards.push(trap('tape', COLORS.teal, st.recorder, 'Flight recorder', 'Remembers what a program did before it was caught.', 'recorder'));
    traps.dataset.n = cards.length; fill(traps, cards);

    // phone alerts: on or off is set up outside the app; here you can see it and test it
    const ph = st.phone;
    fill(phone,
      h('div.ph', h('h3', 'Phone alerts'), h('span.state', { data: { on: ph.on ? '1' : '0' } }, ph.on ? `On, by ${VIA[ph.via] || ph.via}` : 'Not set up')),
      h('div.phone', { class: ph.on ? '' : 'off' }, h('div.ph-notch'), h('div.ph-time', '14:02'),
        h('div.push', h('span.mark'), h('div', h('b', 'ABA froze a program'), h('p', 'It opened one of your baits. Open ABA to decide.')))),
      h('div.sp-foot', h('span', ph.on ? 'Sent the moment something is frozen.' : 'Set them up with “aba configure” in a terminal.'),
        ph.on ? button('Send a test', { icon: 'bell', cls: 'sm', onClick: async () => { const r = await app.bridge.act('phone-test'); toast(r.message || (r.ok ? 'Sent. Check your phone.' : "Couldn't send it."), r.ok ? 'ok' : 'bad'); } }) : null));

    // updates
    const u = st.update;
    const line1 = !u.updatable ? `This is a test build (${u.version}). It doesn't update itself.` : u.available ? `You have ${u.version}. ${u.latest} is ready.` : `Only if signed by ABA. You have ${u.version}${u.latest && u.latest === u.version ? ', the newest' : ''}.`;
    fill(upd,
      tile('update', COLORS.green, 't-lg', { live: true }),
      u.updatable ? toggle(u.auto, 'Updates install themselves', sw('auto-update', 'Automatic updates')) : null,
      h('div', h('b', u.auto && u.updatable ? 'Updates install themselves' : 'Updates'), h('p', line1), u.lastCheck ? h('p.fine', `Checked ${ago(u.lastCheck)}${u.lastResult ? ': ' + u.lastResult : ''}.`) : null),
      updBusy ? h('div.s-prog', spinner(), h('span', progress.length ? progress[progress.length - 1] : 'Working…'))
        : u.updatable ? h('div.s-ubtns',
          button('Check now', { icon: 'refresh', cls: 'sm', onClick: check }),
          u.available ? button(`Install ${u.latest}`, { icon: 'save', cls: 'sm ice', onClick: install }) : null) : null);
  }

  async function check() {
    const r = await app.bridge.act('update-check');
    toast(r.message || (r.ok ? 'Checked.' : "Couldn't check."), r.ok ? 'ok' : 'bad'); app.reload('settings');
  }
  async function install() {
    updBusy = true; progress = []; app.reload('settings');
    const stop = app.watchProgress(evs => { progress = evs.map(e => e.text); last = ''; app.reload('settings', true); });
    const r = await app.bridge.act('update');
    stop(); updBusy = false; progress = [];
    toast(r.message || (r.ok ? 'Updated.' : "The update didn't finish."), r.ok ? 'ok' : 'bad'); app.reload('settings');
  }

  return { el, update, setTestRunning(v) { play.disabled = v; play.classList.toggle('busy', v); } };
}
