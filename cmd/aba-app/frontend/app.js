// ABA desktop app, phase 0 spike: the Home screen's 3D tripwire web (ported
// from the approved mockup), the locked view, and the self-test.
//
// Rules for everything here: nothing that parses HTML is ever given data;
// text goes in with textContent. Nothing is fetched: the page's CSP allows
// scripts, styles and fonts from the app itself only, and no network at all. The Go side is reached only through the bound API methods.
import * as THREE from 'three';
import { EffectComposer } from 'three/addons/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/addons/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/addons/postprocessing/UnrealBloomPass.js';
import { OutputPass } from 'three/addons/postprocessing/OutputPass.js';
import { RoomEnvironment } from 'three/addons/environments/RoomEnvironment.js';

const $ = s => document.querySelector(s);
const API = window.go.main.API;
const RT = window.runtime;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const clamp = (x, a = 0, b = 1) => Math.min(b, Math.max(a, x));
const lerp = (a, b, k) => a + (b - a) * k;
const easeOut = k => 1 - Math.pow(1 - clamp(k), 3);
const backOut = k => { k = clamp(k); const c = 1.9; return 1 + (c + 1) * Math.pow(k - 1, 3) + c * Math.pow(k - 1, 2); };

// Every CSP violation is recorded; the self-test fails on any it didn't cause on purpose.
const violations = [];
document.addEventListener('securitypolicyviolation', e => violations.push({ directive: e.effectiveDirective, blocked: String(e.blockedURI).slice(0, 120) }));

$('#wMin').onclick = () => RT.WindowMinimise();
$('#wMax').onclick = () => RT.WindowToggleMaximise();
$('#wClose').onclick = () => RT.Quit();

/* ---------------- WebGL: which renderer, and is it software? ---------------- */
function glInfo() {
  const c = document.createElement('canvas');
  const gl = c.getContext('webgl2') || c.getContext('webgl');
  if (!gl) return { ok: false, renderer: '', vendor: '', software: true };
  const ext = gl.getExtension('WEBGL_debug_renderer_info');
  const renderer = String(ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER));
  const vendor = String(ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR));
  const software = /swiftshader|basic render|llvmpipe|warp|software/i.test(renderer);
  gl.getExtension('WEBGL_lose_context')?.loseContext();
  return { ok: true, webgl2: gl instanceof WebGL2RenderingContext, renderer, vendor, software };
}

/* ---------------- the scene ---------------- */
const C = { green: '#6ee7a0', ice: '#a6dbff', amber: '#ffcf66', ink: '#eef1ec', teal: '#8fe3d2' };
const BAITS = [
  { n: 'Discord login', c: C.ice, a: 118, r: 3.4, home: 1 },
  { n: 'Chrome passwords', c: C.amber, a: 52, r: 3.4, home: 1 },
  { n: 'MetaMask wallet', c: C.green, a: 190, r: 3.4, home: 1 },
  { n: 'SSH keys', c: C.ink, a: 262, r: 3.4, home: 1 },
  { n: 'Telegram session', c: C.ice, a: 334, r: 3.4, home: 1 },
  { n: 'Password list', c: C.teal, a: 222, r: 5.6, home: 1 },
  { n: 'Edge profile', c: C.amber, a: 20, r: 5.6 },
  { n: 'Exodus wallet', c: C.green, a: 152, r: 5.6 },
  { n: 'AWS keys', c: C.ink, a: 300, r: 5.6 },
  { n: 'Recovery phrase', c: C.teal, a: 84, r: 5.6 },
  { n: 'Brave profile', c: C.amber, a: 356, r: 7.0 },
  { n: 'Electrum wallet', c: C.green, a: 190, r: 7.0 },
  { n: '2FA backup codes', c: C.teal, a: 122, r: 7.0 },
  { n: 'Opera profile', c: C.amber, a: 262, r: 7.0 },
];

function startScene(gi, reduced) {
  const light = gi.software || reduced;
  const stage = $('#stage'), canvas = $('#gl');
  let GW = stage.clientWidth, GH = stage.clientHeight;
  const DPR = light ? 1 : Math.min(devicePixelRatio || 1, 2);
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: !light, powerPreference: 'high-performance' });
  renderer.setPixelRatio(DPR); renderer.setSize(GW, GH, false);
  renderer.toneMapping = THREE.ACESFilmicToneMapping; renderer.toneMappingExposure = 1.1;
  const scene = new THREE.Scene(); scene.background = new THREE.Color(0x090b0a);
  const pm = new THREE.PMREMGenerator(renderer); scene.environment = pm.fromScene(new RoomEnvironment(), 0.04).texture; scene.environmentIntensity = .55;
  const camera = new THREE.PerspectiveCamera(34, GW / GH, .1, 120);
  let composer = null, bloom = null;
  if (!light) {
    const rt = new THREE.WebGLRenderTarget(GW * DPR, GH * DPR, { type: THREE.HalfFloatType, samples: 4 });
    composer = new EffectComposer(renderer, rt); composer.setPixelRatio(DPR); composer.setSize(GW, GH);
    composer.addPass(new RenderPass(scene, camera));
    bloom = new UnrealBloomPass(new THREE.Vector2(GW, GH), .42, .55, .32); composer.addPass(bloom);
    composer.addPass(new OutputPass());
  }
  const glowTex = (() => { const c = document.createElement('canvas'); c.width = c.height = 128; const g = c.getContext('2d'); const gr = g.createRadialGradient(64, 64, 0, 64, 64, 64); gr.addColorStop(0, 'rgba(255,255,255,1)'); gr.addColorStop(.25, 'rgba(255,255,255,.5)'); gr.addColorStop(1, 'rgba(255,255,255,0)'); g.fillStyle = gr; g.fillRect(0, 0, 128, 128); return new THREE.CanvasTexture(c); })();
  const GREEN = new THREE.Color(0x6ee7a0);

  // the web
  const dispY = (x, z, t) => { const r = Math.hypot(x, z); return .13 * Math.sin(r * 1.15 - t * 1.1) * clamp(r / 2.5) + .07 * Math.sin(x * .55 + t * .6) * Math.cos(z * .45 - t * .5); };
  const webU = { uT: { value: 0 }, uReveal: { value: 30 }, uPx: { value: 2.2 * DPR } };
  const webVS = `uniform float uT,uReveal,uPx;attribute float aB;varying float vA;varying vec3 vC;
float dy(vec2 p,float t){float r=length(p);return .13*sin(r*1.15-t*1.1)*clamp(r/2.5,0.,1.)+.07*sin(p.x*.55+t*.6)*cos(p.y*.45-t*.5);}
void main(){vec3 p=position;float r=length(p.xz);p.y+=dy(p.xz,uT);
float sonar=exp(-pow(r-mod(uT*1.35,15.),2.)*1.6);
vec3 g=vec3(.05,.30,.16),gi=vec3(.30,.80,.50);
vC=g*(.45+aB*1.5)+gi*sonar*.8;
float fade=1.-smoothstep(3.,11.,r);
vA=(.12+.88*fade)*(1.-smoothstep(uReveal-3.,uReveal,r));
vec4 mv=modelViewMatrix*vec4(p,1.);gl_Position=projectionMatrix*mv;gl_PointSize=uPx*(1.+aB*1.5+sonar*2.)*(14./-mv.z);}`;
  const webFS = pts => `varying float vA;varying vec3 vC;void main(){${pts ? 'float d=length(gl_PointCoord-.5);if(d>.5)discard;float m=smoothstep(.5,.1,d);' : 'float m=1.;'}gl_FragColor=vec4(vC*vA*m,1.);}`;
  {
    const SP = 30, RINGS = 13, r0 = 1.2, dr = .8; const pos = [], br = [], ppos = [], pbr = [];
    const P = (k, s) => { const r = r0 + k * dr, a = s / SP * Math.PI * 2; return [Math.cos(a) * r, 0, Math.sin(a) * r]; };
    for (let s = 0; s < SP; s++) {
      for (let k = -1; k < RINGS - 1; k++) { const a = k < 0 ? [0, 0, 0] : P(k, s), b = P(k + 1, s); for (let q = 0; q < 2; q++) { pos.push(lerp(a[0], b[0], q / 2), 0, lerp(a[2], b[2], q / 2), lerp(a[0], b[0], (q + 1) / 2), 0, lerp(a[2], b[2], (q + 1) / 2)); br.push(.25, .25); } }
      for (let k = 0; k < RINGS; k++) { const a = P(k, s), b = P(k, s + 1), m = [(a[0] + b[0]) / 2 * .972, 0, (a[2] + b[2]) / 2 * .972]; const bb = k % 3 === 0 ? .55 : .12; pos.push(...a, ...m, ...m, ...b); br.push(bb, bb, bb, bb); ppos.push(...a); pbr.push(k % 3 === 0 ? .9 : .25); }
    }
    const mk = (p, b) => { const g = new THREE.BufferGeometry(); g.setAttribute('position', new THREE.Float32BufferAttribute(p, 3)); g.setAttribute('aB', new THREE.Float32BufferAttribute(b, 1)); return g; };
    const base = { uniforms: webU, vertexShader: webVS, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending };
    scene.add(new THREE.LineSegments(mk(pos, br), new THREE.ShaderMaterial({ ...base, fragmentShader: webFS(0) })));
    scene.add(new THREE.Points(mk(ppos, pbr), new THREE.ShaderMaterial({ ...base, fragmentShader: webFS(1) })));
  }

  // the core orb
  const core = new THREE.Group(); core.position.set(0, 1.15, 0); scene.add(core);
  const fresVS = `varying vec3 vN,vV;void main(){vN=normalize(normalMatrix*normal);vec4 mv=modelViewMatrix*vec4(position,1.);vV=normalize(-mv.xyz);gl_Position=projectionMatrix*mv;}`;
  const fresFS = `uniform vec3 uC;uniform float uI,uP,uB;varying vec3 vN,vV;void main(){float f=pow(1.-abs(dot(normalize(vN),normalize(vV))),uP);gl_FragColor=vec4(uC*(uB+f*uI),1.);}`;
  core.add(new THREE.Mesh(new THREE.IcosahedronGeometry(.62, light ? 3 : 5), new THREE.ShaderMaterial({ uniforms: { uC: { value: GREEN.clone() }, uI: { value: 1.5 }, uP: { value: 2.4 }, uB: { value: .04 } }, vertexShader: fresVS, fragmentShader: fresFS })));
  const ringMat = new THREE.MeshBasicMaterial({ color: GREEN.clone().multiplyScalar(.9), transparent: true, opacity: .8, blending: THREE.AdditiveBlending, depthWrite: false });
  const rings = [1.0, 1.28, 1.5].map((r, i) => { const m = new THREE.Mesh(new THREE.TorusGeometry(r, i === 2 ? .006 : .012, 8, 120, i === 2 ? Math.PI * 1.4 : Math.PI * 2), ringMat); core.add(m); return m; });
  const coreGlow = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTex, color: GREEN, blending: THREE.AdditiveBlending, depthWrite: false, transparent: true, opacity: .28 })); coreGlow.scale.setScalar(4); core.add(coreGlow);
  const stem = new THREE.Mesh(new THREE.CylinderGeometry(.008, .008, 1.15, 6), ringMat); stem.position.y = -.58; core.add(stem);

  // bait nodes and the tripwires between them
  const NODE_Y = .72;
  const gemGeo = new THREE.OctahedronGeometry(.2, 0); gemGeo.scale(1, 1.45, 1);
  const ringGeo = new THREE.RingGeometry(.34, .37, 48); ringGeo.rotateX(-Math.PI / 2);
  const ring2Geo = new THREE.RingGeometry(.52, .53, 48); ring2Geo.rotateX(-Math.PI / 2);
  const tags = $('#tags');
  BAITS.forEach((b, i) => {
    const ang = b.a * Math.PI / 180; b.x = Math.cos(ang) * b.r; b.z = Math.sin(ang) * b.r;
    const g = new THREE.Group(); g.position.set(b.x, 0, b.z);
    const mat = new THREE.MeshStandardMaterial({ color: 0x0c1a12, emissive: GREEN, emissiveIntensity: .9, flatShading: true, roughness: .25, metalness: .3 });
    const gem = new THREE.Mesh(gemGeo, mat); gem.position.y = NODE_Y; g.add(gem);
    const hm = new THREE.MeshBasicMaterial({ color: GREEN.clone(), transparent: true, opacity: .55, blending: THREE.AdditiveBlending, depthWrite: false, side: THREE.DoubleSide });
    const halo = new THREE.Mesh(ringGeo, hm); g.add(halo); const halo2 = new THREE.Mesh(ring2Geo, hm); g.add(halo2);
    const st = new THREE.Mesh(new THREE.CylinderGeometry(.006, .006, NODE_Y, 5), hm); st.position.y = NODE_Y / 2; g.add(st);
    const sp = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTex, color: GREEN.clone(), blending: THREE.AdditiveBlending, depthWrite: false, transparent: true, opacity: .28 })); sp.scale.setScalar(1.3); sp.position.y = NODE_Y; g.add(sp);
    scene.add(g); Object.assign(b, { g, gem, halo, halo2 });
    if (b.home) { // the label: built with textContent, never markup
      const e = document.createElement('div'); e.className = 'btag';
      const tile = document.createElement('span'); tile.className = 'tile'; tile.style.setProperty('--c', b.c);
      e.append(tile, document.createTextNode(b.n)); tags.append(e); b.el = e;
    }
  });
  const wires = []; const wireMat = new THREE.MeshBasicMaterial({ color: GREEN.clone().multiplyScalar(.38), transparent: true, opacity: .9, blending: THREE.AdditiveBlending, depthWrite: false });
  {
    const done = new Set(); const add = (A, B, lift) => {
      const a = new THREE.Vector3(A.x, A.y ?? NODE_Y, A.z), b = new THREE.Vector3(B.x, B.y ?? NODE_Y, B.z), m = a.clone().add(b).multiplyScalar(.5); m.y += lift;
      const c = new THREE.QuadraticBezierCurve3(a, m, b); scene.add(new THREE.Mesh(new THREE.TubeGeometry(c, 28, .011, 5), wireMat)); wires.push(c);
    };
    BAITS.forEach((b, i) => {
      if (b.r < 4) add({ x: 0, y: 1.15, z: 0 }, b, .5);
      BAITS.map((o, j) => [Math.hypot(o.x - b.x, o.z - b.z), j]).filter(d => d[1] !== i).sort((p, q) => p[0] - q[0]).slice(0, 2).forEach(([d, j]) => { const k = Math.min(i, j) + '-' + Math.max(i, j); if (!done.has(k)) { done.add(k); add(b, BAITS[j], .35 + d * .06); } });
    });
  }
  const PN = wires.length * 2; const pulseGeo = new THREE.BufferGeometry(); pulseGeo.setAttribute('position', new THREE.Float32BufferAttribute(new Float32Array(PN * 3), 3));
  const pulseMat = new THREE.PointsMaterial({ map: glowTex, size: .26, color: new THREE.Color(0xcffff0), transparent: true, blending: THREE.AdditiveBlending, depthWrite: false });
  const pulses = new THREE.Points(pulseGeo, pulseMat); pulses.frustumCulled = false; scene.add(pulses);
  scene.add(new THREE.AmbientLight(0x9fb8a8, .35));
  const keyL = new THREE.DirectionalLight(0xd8ecff, 2.2); keyL.position.set(-4, 7, 5); scene.add(keyL);

  const resize = () => {
    GW = stage.clientWidth; GH = stage.clientHeight; if (!GW || !GH) return;
    renderer.setSize(GW, GH, false); composer?.setSize(GW, GH); bloom?.setSize(GW, GH); camera.aspect = GW / GH;
  };
  addEventListener('resize', resize);

  const v3 = new THREE.Vector3(), pp = {};
  const project = (p, out) => { v3.copy(p).project(camera); out.x = (v3.x * .5 + .5) * GW; out.y = (-v3.y * .5 + .5) * GH; out.z = v3.z; return out; };
  // [camX,camY,camZ, tgtX,tgtY,tgtZ, offX,offY], scaled from the mockup's 1352x856 stage
  const POSE = [0, 10.2, 18, 0, .3, 0, -196, -20];
  let frames = 0;
  function frame(t) {
    const sway = Math.sin(t * .11) * .16 + Math.sin(t * .05) * .06; const cx = POSE[0] - POSE[3], cz = POSE[2] - POSE[5]; const cs = Math.cos(sway), sn = Math.sin(sway);
    camera.position.set(POSE[3] + cx * cs - cz * sn, POSE[1] + Math.sin(t * .17) * .12, POSE[5] + cx * sn + cz * cs); camera.lookAt(POSE[3], POSE[4], POSE[5]);
    camera.setViewOffset(GW, GH, -POSE[6] * GW / 1352, -POSE[7] * GH / 856, GW, GH); camera.updateMatrixWorld(); camera.updateProjectionMatrix();
    webU.uT.value = t; webU.uReveal.value = easeOut(t / 2.6) * 21;
    core.scale.setScalar(Math.max(.001, backOut((t - .3) / 1.1)) * (1 + Math.sin(t * 1.6) * .03));
    rings[0].rotation.set(1.2 + t * .5, t * .35, 0); rings[1].rotation.set(t * .3, 1 + t * .42, .4); rings[2].rotation.set(1.57, 0, t * .7);
    BAITS.forEach((b, i) => {
      b.g.scale.setScalar(Math.max(.001, backOut((t - .9 - b.r * .14 - (i % 5) * .05) / .8)));
      const y = dispY(b.x, b.z, t); b.gem.position.y = NODE_Y + Math.sin(t * 1.3 + i) * .05; b.gem.rotation.y = t * .7 + i;
      b.halo.position.y = y; b.halo2.position.y = y; b.halo2.scale.setScalar(1 + ((t * .5 + i * .37) % 1) * 1.4);
    });
    const pa = pulseGeo.attributes.position; wires.forEach((c, i) => { for (let j = 0; j < 2; j++) { c.getPoint((t * (.16 + (i % 4) * .03) + i * .37 + j * .5) % 1, v3); pa.setXYZ(i * 2 + j, v3.x, v3.y, v3.z); } }); pa.needsUpdate = true;
    pulseMat.opacity = clamp(t - 2);
    if (composer) composer.render(); else renderer.render(scene, camera);
    BAITS.forEach(b => {
      if (!b.el) return; const on = t > 2.4; b.el.classList.toggle('show', on);
      v3.set(b.x, NODE_Y + .42, b.z); project(v3, pp); const sc = clamp(1.12 - (pp.z - .97) * 9, .78, 1.05);
      b.el.style.transform = `translate(${pp.x.toFixed(1)}px,${pp.y.toFixed(1)}px) translate(-50%,-100%) scale(${sc.toFixed(3)})`;
    });
    frames++;
  }
  const t0 = performance.now();
  const loop = () => { frame((performance.now() - t0) / 1000); if (!reduced) requestAnimationFrame(loop); };
  if (reduced) frame(30); else loop();
  return { frames: () => frames, elapsed: () => (performance.now() - t0) / 1000, light };
}

/* ---------------- self-test: things the guard must stop ---------------- */
async function attacks() {
  const r = {};
  // A new window (would be an administrator's browser window).
  try { r.windowOpen = window.open('https://example.com/') === null ? 'blocked' : 'opened'; } catch { r.windowOpen = 'threw'; }
  // The network (CSP connect-src 'none'): this one violation is expected.
  try { await fetch('https://example.com/'); r.fetch = 'allowed'; } catch { r.fetch = 'blocked'; }
  // A download (an administrator saving whatever a page hands it).
  try { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob(['x'])); a.download = 'x.txt'; document.body.append(a); a.click(); a.remove(); r.download = 'tried'; } catch { r.download = 'threw'; }
  // Permissions (Wails grants all of them by default).
  try { r.notifications = await Notification.requestPermission(); } catch { r.notifications = 'threw'; }
  try { await navigator.clipboard.readText(); r.clipboardRead = 'allowed'; } catch (e) { r.clipboardRead = 'blocked:' + e.name; }
  // Wails IPC the app doesn't use: open a URL in the (elevated) browser, events.
  try { window.chrome.webview.postMessage('BO:https://example.com/'); window.chrome.webview.postMessage('EE:x:[]'); r.ipc = 'sent'; } catch { r.ipc = 'threw'; }
  // Navigation away: to the disk, and to the web. If either went through,
  // this page would be gone and the test would time out.
  location.href = 'file:///C:/Windows/win.ini'; await sleep(800);
  location.href = 'https://example.com/'; await sleep(800);
  const f = document.createElement('iframe'); f.src = 'https://example.com/'; document.body.append(f); await sleep(500); f.remove();
  r.stillHere = true;
  return r;
}

/* ---------------- start ---------------- */
(async () => {
  const info = await API.Info(); // waits on the Go side until the guard is in place
  document.body.dataset.mode = info.mode;
  $('#ver').textContent = info.version;
  $('#tbState').textContent = info.mode === 'full' ? 'Protected' : 'Locked';
  if (info.mode === 'locked') {
    if (info.alert) $('#lkText').textContent = 'Something was caught. An administrator needs to decide what happens to it.';
    $('#openAba').onclick = async () => { $('#lkErr').textContent = await API.OpenElevated(); };
  } else if (info.alert) { $('#alertId').textContent = info.alert; $('#alertLine').hidden = false; }

  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const gi = glInfo();
  $('#dMode').textContent = `${info.mode}${info.elevated ? ' (elevated)' : ''}`;
  $('#dGL').textContent = gi.ok ? `${gi.renderer}${gi.software ? ' (software)' : ''}` : 'no WebGL';
  $('#dRT').textContent = info.runtime;
  $('#dGuard').textContent = info.guard.ok ? 'on' : `FAILED: ${info.guard.error}`;
  const sc = info.mode === 'full' && gi.ok ? startScene(gi, reduced) : null;
  if (sc) setInterval(() => { $('#dFPS').textContent = `${sc.frames()} (${(sc.frames() / sc.elapsed()).toFixed(0)} fps${sc.light ? ', light' : ''})`; }, 500);

  if (info.probe) {
    $('#probe').hidden = false;
    const show = c => { $('#pClicks').textContent = c.clicks; $('#pKeys').textContent = c.keys; };
    $('#probeBtn').onclick = async () => show(await API.Probe('click'));
    addEventListener('keydown', async () => show(await API.Probe('key')));
  }

  if (info.selftest) {
    const report = { gl: gi, reducedMotion: reduced, mode: info.mode };
    await sleep(3000);
    report.frames = sc ? sc.frames() : 0;
    report.fps = sc ? +(sc.frames() / sc.elapsed()).toFixed(1) : 0;
    report.light = sc ? sc.light : null;
    report.attacks = await attacks();
    report.cspViolations = violations;
    await API.SelftestDone(JSON.stringify(report));
  }
})().catch(e => { API.SelftestDone(JSON.stringify({ error: String(e && e.stack || e) })); });
