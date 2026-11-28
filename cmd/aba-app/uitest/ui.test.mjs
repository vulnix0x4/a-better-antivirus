// UI tests for the ABA desktop app's page: the real ../frontend, served with
// the app's Content-Security-Policy, on the mock bridge (the fixtures of
// internal/appapi/testdata).
//
//   npm ci && npx playwright install chromium && npm test
//
// CHANNEL=chrome uses the installed Chrome (a real GPU on a developer's
// machine); the default is Playwright's Chromium, as in CI (software WebGL).
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from 'playwright';
import { start, FIXTURES, FRONTEND } from './server.mjs';

const fixture = name => JSON.parse(fs.readFileSync(path.join(FIXTURES, name + '.json'), 'utf8'));
const ALERTS = fs.readdirSync(FIXTURES).filter(f => f.startsWith('alert-')).map(f => f.slice(6, -5));
let srv, browser;
before(async () => {
  srv = await start(0);
  const channel = process.env.CHANNEL;
  browser = await chromium.launch({ channel: channel || undefined, headless: true, args: ['--enable-unsafe-swiftshader', '--ignore-gpu-blocklist', '--hide-scrollbars'] });
});
after(async () => { await browser.close(); await srv.close(); });

// Opens the page and fails the test on any console error, page error,
// request that leaves the app, dialog, or CSP violation.
async function open(query, { manual = true, width = 1440, height = 900 } = {}) {
  const ctx = await browser.newContext({ viewport: { width, height } });
  const page = await ctx.newPage();
  const problems = [];
  page.on('console', m => { if (m.type() === 'error') problems.push('console: ' + m.text()); });
  page.on('pageerror', e => problems.push('page error: ' + e.message));
  page.on('dialog', d => { problems.push('dialog: ' + d.message()); d.dismiss(); });
  page.on('request', r => { if (!r.url().startsWith(srv.url)) problems.push('request: ' + r.url()); });
  page.on('popup', () => problems.push('popup'));
  await page.goto(srv.url + '?' + (manual ? 'manual=1&fast=1&' : '') + query);
  await page.waitForFunction(() => window.__abaReady === true, null, { timeout: 30000 });
  await page.evaluate(() => document.fonts.ready);
  const settle = async (from = 0, to = 9) => {
    await page.evaluate(([a, b]) => { for (let t = a; t <= b; t += .25) window.__aba.frame(t); }, [from, to]);
    await page.evaluate(() => new Promise(r => requestAnimationFrame(() => setTimeout(r, 60))));
  };
  if (manual) await settle();
  const done = async () => {
    const v = await page.evaluate(() => window.__aba.violations.map(x => x.directive + ' ' + x.blocked));
    const errs = await page.evaluate(() => window.__abaErrors);
    await ctx.close();
    assert.deepEqual([...problems, ...v.map(x => 'CSP: ' + x), ...errs.map(x => 'error: ' + x)], [], 'the page had problems');
  };
  return { page, settle, done };
}
const text = (page, sel = 'body') => page.evaluate(s => document.querySelector(s).innerText, sel);
const screenText = page => page.evaluate(() => { const s = document.querySelector('.screen.on') || document.querySelector('#locked'); return s.innerText; });

/* ---------------- every screen, every fixture ---------------- */
for (const home of ['protected', 'frozen']) {
  const snap = fixture('home-' + home);
  for (const tier of ['light', 'full', 'none']) {
    test(`home ${home} (${tier})`, async () => {
      const { page, done } = await open(`home=${home}&screen=home&tier=${tier}`);
      const t = await screenText(page);
      assert.ok(t.includes(snap.protection.headline), 'the headline');
      assert.ok(t.includes(snap.preset.name) && t.includes(snap.preset.says), 'the protection level');
      assert.match(t, /Baits\b/); assert.match(t, /Run the safe test/);
      assert.equal(await page.locator('#home .dial').getAttribute('aria-valuetext'), snap.preset.name);
      if (home === 'frozen') { assert.ok(t.includes(snap.waiting[0].program)); assert.match(t, /Decide now/); }
      else assert.match(t, /14 baits armed\. Quiet for 8 days\./);
      for (const r of snap.recentQuiet) assert.ok(t.includes(r.program));
      if (tier !== 'none') assert.equal(await page.locator('#tags .btag.show').count() > 0, true, 'bait labels on the web');
      await done();
    });
  }
  test(`history, baits, settings (${home})`, async () => {
    const hist = fixture('history'), baits = fixture('baits'), st = fixture('settings');
    let o = await open(`home=${home}&screen=history&tier=light`);
    let t = await screenText(o.page);
    for (const it of hist.items.filter(i => i.outcome !== 'noted')) { assert.ok(t.includes(it.program), it.program); assert.ok(t.includes(it.line), it.line); }
    assert.match(t, /2 harmless touches/);
    assert.equal(await o.page.locator('#cal .cell').count(), 84, 'twelve weeks of days');
    assert.equal(await o.page.locator('#cal .cell.f').count(), 5, 'a cube for each catch and the test');
    assert.equal(await o.page.locator('#cal .cell.t').count(), 1); assert.equal(await o.page.locator('#cal .cell.q').count(), 2);
    await o.page.locator('.row.grp').click(); await o.settle(9, 10);
    assert.ok((await screenText(o.page)).includes('SearchProtocolHost.exe'), 'the quiet ones open');
    await o.done();

    o = await open(`home=${home}&screen=baits&tier=light`);
    t = await screenText(o.page);
    assert.match(t, /14 planted\. All healthy\./); assert.match(t, /All 14 in place/);
    for (const c of baits.checks) assert.ok(t.includes(c.name));
    assert.equal(await o.page.locator('#tags .btag.show').count(), baits.items.length, 'every bait has its label');
    for (const it of baits.items) { // each bait's details
      await o.page.evaluate(id => window.__aba.screens.baits.select(id), it.id);
      const d = await text(o.page, '.b-detail');
      assert.ok(d.includes(it.label) && d.includes(it.description), it.id);
      assert.equal(await o.page.locator('.bd-btns button').count(), it.hasText ? 1 : 0, it.id + ': see what is inside');
    }
    await o.done();

    o = await open(`home=${home}&screen=settings&tier=light`);
    t = await screenText(o.page);
    for (const p of st.presets) { assert.ok(t.includes(p.name)); assert.ok(t.includes(p.says)); }
    for (const w of ['Instant freeze', 'Clipboard bait', 'Miner trap', 'Flight recorder', 'Phone alerts', 'On, by ntfy', 'Send a test', 'Updates install themselves', 'v0.10.2', 'Check now', 'Run the safe test']) assert.ok(t.includes(w), w);
    assert.equal(await o.page.locator('#settings .dial').count(), 1, 'the same rotary knob as Home');
    assert.equal(await o.page.locator('#settings .dial').getAttribute('aria-valuetext'), 'Balanced');
    assert.equal(await o.page.locator('#settings .tog[aria-checked=true]').count(), 5);
    await o.done();
  });
}

for (const name of ALERTS) {
  const a = fixture('alert-' + name);
  test(`caught and full report: ${name}`, async () => {
    for (const tier of name === 'frozen-sent' ? ['light', 'full', 'none'] : ['light']) {
      let o = await open(`home=${a.frozenNow ? 'frozen' : 'protected'}&alert=${name}&screen=caught&tier=${tier}`);
      let t = await screenText(o.page);
      if (a.program) assert.ok(t.includes(a.program.name), 'the program');
      assert.match(t, a.frozenNow ? /Frozen\./ : a.test ? /Test passed\./ : /Killed\.|Trusted\.|Noted\.|Stopped\./);
      assert.equal(await o.page.locator('.c-actions button').count(), a.buttons.length, 'its answers');
      if (a.report && !a.report.pending) assert.ok(t.includes(a.report.headline), 'did it take real data');
      if (a.frozenNow) assert.match(await text(o.page, '#held'), /Held in ice for\s+\d+:\d\d/);
      await o.done();

      o = await open(`home=${a.frozenNow ? 'frozen' : 'protected'}&alert=${name}&screen=report&tier=${tier}`);
      await o.page.evaluate(() => window.__aba.revealAll()); await o.settle(9, 12);
      t = await screenText(o.page);
      if (a.program) { assert.ok(t.includes(`What ${a.program.name} did`)); assert.ok(t.includes(a.program.path)); assert.ok(t.includes(a.program.signature)); }
      const r = a.report;
      if (r) {
        assert.ok(t.includes(r.headline));
        for (const s of r.steps) assert.ok(t.includes(s.split(/: |, then /)[0]), 'step: ' + s);
        for (const ad of r.addresses) assert.ok(t.includes(ad.value), 'address: ' + ad.value);
        for (const u of [...r.unsure, ...r.leads, ...r.notes, ...r.dataLeftWhy]) assert.ok(t.includes(u), 'honest about: ' + u);
        for (const f of r.staged) { assert.ok(t.includes(f.name)); for (const e of f.entries.slice(0, 6)) assert.ok(t.includes(e.name), 'packed file ' + e.name); }
        if (r.dataLeft === 'cannot-tell') assert.match(t, /ABA can't tell what left this PC\./);
        if (r.dataLeft === 'nothing') assert.match(t, /Nothing left this PC once it had your data\./);
        if (r.sends.length) for (const s of r.sends.slice(0, 3)) assert.ok(t.includes(s.host || s.to), 'destination');
        if (r.evidence.saved) assert.ok(t.includes(r.evidence.folder));
        // the whole report as text is there to open
        await o.page.locator('.r-full button').click();
        t = await screenText(o.page);
        for (const sec of r.sections) assert.ok(t.includes(sec.lines[0].trim().split('‹')[0].trim().slice(0, 40)), 'section ' + sec.key);
      } else for (const c of a.checklist) assert.ok(t.includes(c.slice(0, 30)), 'what to do: ' + c);
      for (const d of a.did) assert.ok(t.includes(d.words));
      if (a.mine) { assert.ok(t.includes(a.mine.pool)); assert.ok(t.includes(a.mine.wallet)); }
      if (a.clipper) assert.ok(t.includes(a.clipper.wallet));
      await o.done();
    }
  });
}

for (const home of ['protected', 'frozen']) {
  test(`locked view (${home})`, async () => {
    const l = fixture(home === 'frozen' ? 'locked-frozen' : 'locked');
    const { page, done } = await open(`mode=locked&home=${home}`);
    const t = await text(page, '#locked');
    assert.match(t, home === 'frozen' ? /Something is frozen/ : /ABA is protecting this PC/);
    assert.ok(t.includes(`${l.baitsHealthy} of ${l.baits} baits in place`));
    assert.equal(await page.locator('#locked button').count(), 1, 'one button');
    assert.equal(await page.locator('.stage').isVisible(), false, 'nothing of the full app');
    assert.equal(await page.locator('#rail').isVisible(), false);
    assert.ok(!t.includes('NitroGen'), 'nothing about the caught program');
    await page.locator('#openAba').click();
    await page.waitForFunction(() => document.querySelector('#locked .hint').textContent.length > 0);
    assert.match(await text(page, '#locked .hint'), /didn't start ABA as administrator/);
    await done();
  });
}

/* ---------------- hostile strings are text ---------------- */
test('hostile strings render as plain text', async () => {
  const a = fixture('alert-hostile');
  for (const screen of ['caught', 'report']) {
    const { page, settle, done } = await open(`home=frozen&alert=hostile&screen=${screen}&tier=light`);
    if (screen === 'report') { await page.evaluate(() => window.__aba.revealAll()); await page.locator('.r-full button').click(); await settle(9, 12); }
    const t = await screenText(page);
    assert.ok(t.includes('<img src=x onerror=alert(1)>.exe'), 'the name is shown as it is');
    assert.ok(t.includes('<b>your</b>'), 'tags in a headline are shown, not obeyed');
    if (screen === 'report') {
      for (const s of [a.program.commandLine, a.program.origin.line, a.report.addresses[0].value, a.report.addresses[1].value, 'loot<b>.zip', '<iframe src=javascript:alert(6)>.txt']) assert.ok(t.includes(s), 'shown as text: ' + s);
      assert.ok(t.includes('‹U+202E›'), 'the right-to-left override is made visible');
    }
    const dom = await page.evaluate(() => ({
      injected: document.querySelectorAll('img, iframe, textarea, object, embed, form, a[href], base, meta[http-equiv], link:not([href="style.css"]), style').length,
      scripts: [...document.scripts].map(s => s.getAttribute('src') || s.type),
      handlers: [...document.querySelectorAll('*')].filter(e => [...e.attributes].some(at => /^on/i.test(at.name) || /javascript:/i.test(at.value))).length,
      bold: [...document.querySelectorAll('.screen.on b, .screen.on u, .screen.on svg')].filter(e => e.textContent === 'your' || e.textContent === 'bold' || e.textContent === 'x').length,
      hidden: /[‪-‮⁦-⁩​-‏]/.test(document.body.textContent),
    }));
    assert.equal(dom.injected, 0, 'no element came from data');
    assert.deepEqual(dom.scripts, ['/wails/ipc.js', '/wails/runtime.js', 'boot.js', 'importmap', 'app.js'], 'no script came from data');
    assert.equal(dom.handlers, 0, 'no handler or javascript: anywhere');
    assert.equal(dom.bold, 0, 'no markup from data took effect');
    assert.equal(dom.hidden, false, 'no invisible direction characters');
    if (screen === 'report') { // Copy hands Go the address itself
      await page.locator('.r-hook .hook-btns button').click();
      await page.waitForFunction(() => window.__copied !== undefined);
      assert.equal(await page.evaluate(() => window.__copied), a.report.addresses[0].value);
    }
    await done(); // (a dialog, a request or a CSP violation fails here)
  }
  // a bait's contents are text too
  const { page, settle, done } = await open('home=protected&screen=baits&tier=light');
  await page.evaluate(() => window.__aba.screens.baits.select('desktop-passwords'));
  await page.locator('.bd-btns button').click(); await page.waitForSelector('.dlg pre'); await settle(9, 11);
  assert.ok((await text(page, '.dlg')).includes('<img src=x onerror=alert(9)> <script>alert(10)</script>'));
  assert.equal(await page.locator('.dlg img, .dlg script').count(), 0);
  await page.keyboard.press('Escape'); assert.equal(await page.locator('.dlg').count(), 0, 'Escape closes it');
  await done();
});

/* ---------------- what Phase 1 has no data for is not there ---------------- */
test('absent parts are hidden, with no empty boxes', async () => {
  let o = await open('home=protected&screen=home&tier=light');
  assert.ok(fixture('home-protected').absent.includes('touchChart'));
  let t = await screenText(o.page);
  assert.ok(!/last 30 days/i.test(t), 'no 30-day chart'); assert.equal(await o.page.locator('#homeChart, .chart').count(), 0);
  await o.done();
  o = await open('home=protected&screen=home&tier=light&empty=1'); // and nothing lately: no box at all
  assert.equal(await o.page.locator('.h-activity').isVisible(), false);
  assert.match(await screenText(o.page), /No baits are planted yet\./);
  await o.done();

  o = await open('home=frozen&screen=report&tier=light');
  await o.page.evaluate(() => window.__aba.revealAll()); await o.settle(9, 12);
  t = await screenText(o.page);
  for (const [why, re] of [['checklistTicks', /\d of \d done/i], ['webhookShutdown', /shut down this webhook/i], ['blockedSends', /sends? blocked|never left|stopped by the freeze/i], ['programSize', /^Size$/m]]) {
    assert.ok(fixture('alert-frozen-sent').absent.includes(why)); assert.ok(!re.test(t), why + ' is not shown');
  }
  assert.match(t, /Copy/, 'Copy stays');
  assert.equal(await o.page.locator('#report input[type=checkbox], #report .tick').count(), 0);
  // no panel is an empty box
  const empty = await o.page.evaluate(() => [...document.querySelectorAll('.screen.on .panel')].filter(p => p.offsetParent && p.innerText.trim().length < 3).length);
  assert.equal(empty, 0);
  await o.done();

  o = await open('home=protected&screen=baits&tier=light');
  t = await screenText(o.page);
  assert.ok(!/replant/i.test(t), 'no Replant'); assert.equal(await o.page.locator('#ecg, .bd-health svg').count(), 0, 'no heartbeat line');
  assert.match(t, /Armed\s+Checked 2 min ago/);
  await o.done();

  // a trap this system doesn't have isn't offered
  o = await open('home=protected&screen=settings&tier=light&nosupport=1');
  t = await screenText(o.page);
  assert.ok(!/Clipboard bait|Miner trap/.test(t)); assert.match(t, /Instant freeze/); assert.match(t, /Flight recorder/);
  await o.done();
  // a report still being written, and an alert ABA didn't look into
  o = await open('home=protected&alert=quiet&screen=report&tier=light');
  t = await screenText(o.page);
  assert.match(t, /ABA did not look further into this one\./); assert.equal(await o.page.locator('.r-time, .r-flow, .r-files').count(), 0);
  await o.done();
});

/* ---------------- the answers, with what came of them ---------------- */
test('Kill it, Unfreeze once, It’s mine: result feedback', async () => {
  for (const [kind, word, said] of [['kill', 'Killed.', /Killed NitroGen-Free\.exe/], ['resume', 'Let go.', /Unfrozen/], ['trust', 'Trusted.', /Trusted/]]) {
    const { page, settle, done } = await open('home=frozen&screen=caught&tier=light');
    assert.match(await text(page, '#caught h1'), /Frozen\./);
    await page.locator(`button[data-act=${kind}]`).click();
    await page.waitForSelector('.c-result[data-kind=ok]'); await settle(9, 13);
    assert.match(await text(page, '.c-result'), said);
    assert.equal(await text(page, '#caught h1'), word);
    assert.equal(await page.locator('.c-actions button').count(), 0, 'nothing left to answer');
    assert.deepEqual(await page.evaluate(() => window.__abaDev.calls.filter(c => c[0] === 'Act')), [['Act', kind, '20261127-140207-7f3a', '']]);
    assert.equal(await text(page, '#tbState'), 'Protected', 'the title bar follows');
    await done();
  }
  // a failure says so, and the choice is still there
  const { page, done } = await open('home=frozen&screen=caught&tier=light&fail=kill');
  await page.locator('button[data-act=kill]').click();
  await page.waitForSelector('.c-result[data-kind=bad]');
  assert.match(await text(page, '.c-result'), /access is denied/);
  assert.equal(await page.locator('.c-actions button').count(), 3);
  assert.match(await text(page, '#caught h1'), /Frozen\./);
  await done();
});

test('settings: knob, switches, phone test, updates', async () => {
  const { page, settle, done } = await open('home=protected&screen=settings&tier=light&update=1');
  const calls = () => page.evaluate(() => window.__abaDev.calls.filter(c => c[0] === 'Act').map(c => c.slice(1).join(' ').trim()));
  await page.locator('#settings .dial').focus(); await page.keyboard.press('ArrowRight');
  await page.waitForFunction(() => document.querySelector('#settings .dial').getAttribute('aria-valuetext') === 'Strict' && document.querySelector('button[data-preset=strict]').classList.contains('on'));
  assert.equal(await page.locator('#settings .dial').getAttribute('data-level'), 'strict');
  await page.locator('button[data-preset=alert]').click();
  await page.waitForFunction(() => document.querySelector('button[data-preset=alert]').classList.contains('on'));
  assert.equal(await page.locator('#settings .dial').getAttribute('aria-valuetext'), 'Alert only');
  await page.locator('.trap .tog').first().click();
  await page.waitForFunction(() => document.querySelector('.trap .tog').getAttribute('aria-checked') === 'false');
  await page.getByRole('button', { name: 'Send a test' }).click(); await page.waitForSelector('.toast >> text=Check your phone');
  await page.getByRole('button', { name: 'Check now' }).click(); await page.waitForSelector('.toast >> text=v0.10.3 is available');
  await page.getByRole('button', { name: 'Install v0.10.3' }).click(); await page.waitForSelector('.toast >> text=Updated to v0.10.3');
  await settle(9, 11);
  assert.deepEqual(await calls(), ['preset  strict', 'preset  alert', 'instant  off', 'phone-test', 'update-check', 'update']);
  assert.match(await text(page, '.s-upd'), /You have v0\.10\.3, the newest/);
  await done();
  // Home's knob is the same control, and shows the same level
  const o = await open('home=protected&screen=home&tier=light');
  await o.page.locator('#home .dial').focus(); await o.page.keyboard.press('ArrowLeft');
  await o.page.waitForFunction(() => document.querySelector('#home .g-mid strong').textContent === 'Alert only');
  assert.equal(await o.page.locator('#home .dial').getAttribute('data-level'), 'alert');
  await o.done();
});

test('the safe test: live progress, then the catch', async () => {
  const { page, done } = await open('home=protected&screen=home&tier=light&motion=1', { manual: false });
  await page.locator('#home .play').click();
  await page.waitForSelector('#testCard:not([hidden]) .tc-steps li');
  assert.match(await text(page, '#testCard'), /Running the safe test/);
  await page.waitForFunction(() => document.querySelectorAll('.tc-steps li').length >= 2, null, { timeout: 15000 });
  assert.match(await text(page, '#testCard'), /A harmless fake stealer is about to read[\s\S]*Waiting for ABA to catch it/);
  await page.waitForFunction(() => document.body.dataset.screen === 'caught', null, { timeout: 30000 });
  assert.match(await text(page, '#caught'), /Test passed\.[\s\S]*aba-test-8812\.exe/);
  assert.equal(await page.locator('#testCard').isVisible(), false);
  await done();
});

test('a catch while the app is open takes over; opening on a catch goes straight to it', async () => {
  let o = await open('home=protected&screen=settings&tier=light&motion=1', { manual: false });
  await o.page.evaluate(() => window.__abaDev.catchNow('frozen-sent'));
  await o.page.waitForFunction(() => document.body.dataset.screen === 'caught', null, { timeout: 30000 });
  await o.page.waitForFunction(() => /Frozen\./.test(document.querySelector('#caught h1').textContent));
  assert.match(await text(o.page, '#caught'), /NitroGen-Free\.exe/);
  assert.equal(await text(o.page, '#tbState'), 'Something is frozen');
  await o.done();
  o = await open('home=frozen&open=1&tier=light&motion=1', { manual: false });
  assert.equal(await o.page.evaluate(() => document.body.dataset.screen), 'caught');
  await o.page.waitForFunction(() => document.querySelector('#held').classList.contains('show'), null, { timeout: 15000 });
  await o.done();
  // reduced motion: the same, without the show
  o = await open('home=frozen&open=1&tier=light&reduced=1', { manual: false });
  assert.equal(await o.page.evaluate(() => document.body.dataset.screen), 'caught');
  assert.match(await text(o.page, '#caught h1'), /Frozen\./);
  await o.done();
});

/* ---------------- keyboard ---------------- */
test('keyboard: focus order is sane and stays on what is shown', async () => {
  const walk = async (page, n) => {
    const seen = [];
    for (let i = 0; i < n; i++) {
      await page.keyboard.press('Tab');
      seen.push(await page.evaluate(() => {
        const e = document.activeElement; if (!e || e === document.body) return 'body';
        const r = e.getBoundingClientRect(); const scr = e.closest('.screen');
        const shown = r.width > 0 && r.height > 0 && getComputedStyle(e).visibility === 'visible' && (!scr || scr.classList.contains('on'));
        const where = e.closest('#rail') ? 'rail' : e.closest('#wc') ? 'window' : e.closest('#tags') ? 'tags' : scr ? scr.id : e.closest('#locked') ? 'locked' : 'other';
        return (shown ? '' : 'HIDDEN ') + where + ':' + (e.getAttribute('aria-label') || e.textContent.trim().replace(/\s+/g, ' ').slice(0, 28).trim());
      }));
    }
    return seen;
  };
  let o = await open('home=frozen&screen=home&tier=light');
  // A screen puts the focus on its heading, so Tab goes into the screen
  // first: what matters most, then the rest, then the window's buttons.
  let s = await walk(o.page, 9);
  assert.ok(!s.some(x => x.startsWith('HIDDEN') || x === 'body'), s.join(' | '));
  assert.deepEqual(s, ['home:Decide now', 'home:Protection level', 'home:See all history', 'home:SearchProtocolHost.exePasswo', 'home:MsMpEng.exeRecovery phrase.', 'home:Run the safe test', 'window:Minimise', 'window:Maximise', 'window:Close']);
  // and backwards from the heading: the rail, last screen first
  await o.page.locator('#home h1').focus();
  const back = []; for (let i = 0; i < 4; i++) { await o.page.keyboard.press('Shift+Tab'); back.push(await o.page.evaluate(() => document.activeElement.textContent.trim())); }
  assert.deepEqual(back, ['Settings', 'Baits', 'History', 'Home']);
  await o.page.keyboard.press('Enter'); // a rail button works from the keyboard
  await o.done();

  o = await open('home=frozen&screen=caught&tier=light');
  s = await walk(o.page, 5);
  assert.deepEqual(s, ['caught:Kill itRecommended', 'caught:Unfreeze once', "caught:It's mine", 'caught:See the full report', 'window:Minimise'], s.join(' | '));
  await o.page.keyboard.press('Shift+Tab'); await o.page.keyboard.press('Enter'); // the report link, by keyboard
  await o.page.waitForFunction(() => document.body.dataset.screen === 'report');
  await o.done();

  o = await open('mode=locked&home=frozen');
  s = await walk(o.page, 4);
  assert.deepEqual(s, ['locked:Open ABA', 'window:Minimise', 'window:Maximise', 'window:Close']);
  await o.done();

  // every control has a name
  for (const screen of ['home', 'caught', 'report', 'history', 'baits', 'settings']) {
    o = await open(`home=frozen&screen=${screen}&tier=light`);
    const nameless = await o.page.evaluate(() => [...document.querySelectorAll('button, [role=slider], [role=switch]')].filter(e => e.offsetParent && !(e.getAttribute('aria-label') || e.textContent.trim())).map(e => e.className));
    assert.deepEqual(nameless, [], screen);
    await o.done();
  }
});

/* ---------------- layout: icons in their plates, nothing off the window ---------------- */
test('icons sit inside their plates; panels stay inside the window at any size', async () => {
  for (const [w, hgt] of [[1440, 900], [1100, 720], [1920, 1080], [1280, 1024]]) {
    for (const q of ['home=frozen&screen=home', 'home=frozen&screen=caught', 'home=protected&screen=history', 'home=protected&screen=baits', 'home=protected&screen=settings']) {
      const { page, done } = await open(q + '&tier=light', { width: w, height: hgt });
      const bad = await page.evaluate(([W, H]) => {
        const out = [];
        for (const t of document.querySelectorAll('.screen.on .tile, #rail button')) { // an icon never leaves its plate
          const c = t.querySelector('canvas'); if (!c || !t.offsetParent) continue;
          const a = t.getBoundingClientRect(), b = c.getBoundingClientRect();
          if (b.left < a.left - .6 || b.top < a.top - .6 || b.right > a.right + .6 || b.bottom > a.bottom + .6) out.push('icon outside its plate: ' + t.className);
        }
        for (const p of document.querySelectorAll('.screen.on .panel:not(.tilt), .screen.on h1, .screen.on .btn, #rail, #wc')) {
          if (!p.offsetParent) continue; const r = p.getBoundingClientRect();
          if (r.left < -1 || r.top < -1 || r.right > W + 1 || r.bottom > H + 1) out.push(`outside the window: ${p.className || p.tagName} ${Math.round(r.left)},${Math.round(r.top)},${Math.round(r.right)},${Math.round(r.bottom)}`);
        }
        const P = [...document.querySelectorAll('.screen.on .panel:not(.tilt):not(.testcard)')].filter(p => p.offsetParent && !p.parentElement.closest('.panel')).map(p => [p, p.getBoundingClientRect()]);
        for (let i = 0; i < P.length; i++) for (let j = i + 1; j < P.length; j++) { // panels don't lie on each other
          const a = P[i][1], b = P[j][1]; const ox = Math.min(a.right, b.right) - Math.max(a.left, b.left), oy = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
          if (ox > 4 && oy > 4) out.push(`overlap: ${P[i][0].className} / ${P[j][0].className}`);
        }
        return out;
      }, [w, hgt]);
      assert.deepEqual(bad, [], `${q} at ${w}x${hgt}`);
      await done();
    }
  }
});

// The icon family: every icon's drawing stays clear of its plate's edge.
test('3D icons are drawn with a margin all round', async () => {
  const { page, done } = await open('home=protected&screen=settings&tier=light');
  const res = await page.evaluate(async () => {
    const { icon3, COLORS } = await import('./js/icons.js');
    const names = ['home', 'history', 'hook', 'sliders', 'discord', 'chrome', 'firefox', 'globe', 'wallet', 'vault', 'key', 'telegram', 'doc', 'server', 'cloud', 'git', 'grid', 'hashi', 'clipboard', 'pick', 'phone', 'shield', 'snow', 'bell', 'netoff', 'update', 'warn', 'cookie', 'up', 'zip', 'eye', 'pc', 'lock', 'tape', 'virus'];
    const out = {};
    for (const n of names) for (const level of n === 'shield' ? [0, 1, 2] : [1]) {
      const el = icon3(n, COLORS.green, { level }); const cv = el.querySelector('canvas'); if (!cv) { out[n] = 'flat'; continue; }
      const d = cv.getContext('2d').getImageData(0, 0, cv.width, cv.height).data; let edge = 0, ink = 0; const W = cv.width, m = Math.round(W * .05);
      for (let y = 0; y < W; y++) for (let x = 0; x < W; x++) { const a = d[(y * W + x) * 4 + 3]; if (a > 70) { ink++; if (x < m || y < m || x >= W - m || y >= W - m) edge++; } }
      out[n + (n === 'shield' ? level : '')] = { ink: ink / (W * W), edge };
    }
    return out;
  });
  for (const [n, r] of Object.entries(res)) {
    assert.notEqual(r, 'flat', n + ' is rendered'); assert.ok(r.ink > .02, `${n} is drawn (${r.ink})`); assert.equal(r.edge, 0, `${n} touches its plate's edge`);
  }
  assert.ok(res.shield0.ink < res.shield1.ink && res.shield1.ink < res.shield2.ink, 'the shield grows from alert only to strict');
  await done();
});

/* ---------------- performance: no drawing when nobody is looking ---------------- */
test('the scene idles at a capped rate and stops when the window is not in front', async () => {
  const { page, done } = await open('home=protected&screen=history&tier=light&motion=1', { manual: false });
  const frames = () => page.evaluate(() => window.__aba.scene().frames());
  await page.waitForTimeout(5500); // the entrance is over
  let a = await frames(); await page.waitForTimeout(2000); let b = await frames();
  assert.ok(b - a > 5 && b - a <= 48, `idle: ${b - a} frames in 2 s (cap is 20 a second on the light scene)`);
  await page.evaluate(() => { document.hasFocus = () => false; });
  await page.waitForTimeout(600); a = await frames(); await page.waitForTimeout(1500); b = await frames();
  assert.equal(b - a, 0, 'no frames while unfocused');
  await page.evaluate(() => { delete document.hasFocus; window.dispatchEvent(new Event('focus')); });
  await page.waitForTimeout(700);
  assert.ok(await frames() > b, 'and it comes back');
  await done();
});

test('reduced motion: a still scene, drawn only when something changes', async () => {
  const { page, done } = await open('home=protected&screen=home&tier=light&reduced=1', { manual: false });
  const frames = () => page.evaluate(() => window.__aba.scene().frames());
  await page.waitForTimeout(800); const a = await frames(); await page.waitForTimeout(1200);
  assert.equal(await frames(), a, 'nothing is drawn while nothing changes'); assert.ok(a >= 1);
  await page.locator('#rail button[data-nav=baits]').click(); await page.waitForTimeout(500);
  assert.ok(await frames() > a, 'a change draws a frame');
  assert.equal(await page.locator('#tags .btag.show').count(), 14);
  await done();
});

/* ---------------- the files themselves ---------------- */
test('the page has no inline code and never parses data as markup', () => {
  const walk = d => fs.readdirSync(d, { withFileTypes: true }).flatMap(e => e.isDirectory() ? (e.name === 'vendor' ? [] : walk(path.join(d, e.name))) : [path.join(d, e.name)]);
  const files = walk(FRONTEND);
  for (const f of files.filter(x => x.endsWith('.js'))) {
    const src = fs.readFileSync(f, 'utf8');
    for (const bad of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'srcdoc', 'createContextualFragment']) assert.ok(!src.includes(bad), `${path.relative(FRONTEND, f)} uses ${bad}`);
  }
  const html = fs.readFileSync(path.join(FRONTEND, 'index.html'), 'utf8');
  assert.ok(!/\s(style|on[a-z]+)=/i.test(html), 'no inline style or handler');
  assert.equal((html.match(/<script/g) || []).length, 3, 'boot.js, the import map, app.js');
});
