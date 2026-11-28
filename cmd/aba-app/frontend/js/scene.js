// The tripwire web: one three.js scene behind every screen. Baits are gems
// on a web of tripwires (green while calm). A caught program is a red virus
// particle that crawls the web, touches a bait and is shut in a small clear
// ice cube, and an ice wave turns the web blue.
import * as THREE from 'three';
import { EffectComposer } from 'three/addons/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/addons/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/addons/postprocessing/UnrealBloomPass.js';
import { OutputPass } from 'three/addons/postprocessing/OutputPass.js';
import { RoomEnvironment } from 'three/addons/environments/RoomEnvironment.js';
import { RoundedBoxGeometry } from 'three/addons/geometries/RoundedBoxGeometry.js';
import { buildVirus } from './icons3d.js';
import { tile, baitColor, tickIcons } from './icons.js';
import { h, clamp, lerp } from './dom.js';

const ease = k => { k = clamp(k); return k * k * k * (k * (k * 6 - 15) + 10); };
const easeOut = k => 1 - Math.pow(1 - clamp(k), 3);
const backOut = k => { k = clamp(k); const c = 1.9; return 1 + (c + 1) * Math.pow(k - 1, 3) + c * Math.pow(k - 1, 2); };
const hash = (a, b = 0, c = 0) => { const s = Math.sin(a * 127.1 + b * 311.7 + c * 74.7) * 43758.5453; return s - Math.floor(s); };
const col = hx => new THREE.Color(hx);

// Where bait number i sits: [angle in degrees, distance from the centre].
// The first 14 are the approved layout; more baits fill the outer rings.
const SLOTS = [[118, 3.4], [52, 3.4], [190, 3.4], [262, 3.4], [334, 3.4], [222, 5.6], [20, 5.6], [152, 5.6], [300, 5.6], [84, 5.6], [356, 7.0], [190, 7.0], [122, 7.0], [262, 7.0],
  [48, 7.4], [226, 7.4], [312, 7.4], [160, 8.6], [20, 8.8], [88, 8.8], [244, 8.8], [286, 8.8], [334, 8.8], [204, 8.8], [64, 9.6], [138, 9.6], [180, 9.8], [270, 9.9], [0, 9.9], [110, 10]];
const MAX_BAITS = SLOTS.length; // = gfx.js MAX_BAITS
const HOME_TAGS = 6;
const NODE_Y = .72, CUBE_Y = .9, DW = 1352, DH = 856; // the mockup's stage, which the poses were tuned on

export function createScene({ canvas, els, tier, reduced, manual, onTag }) {
  const light = tier !== 'full';
  let GW = DW, GH = DH, PR = 1;
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: !light, preserveDrawingBuffer: manual, powerPreference: 'high-performance' });
  renderer.toneMapping = THREE.ACESFilmicToneMapping; renderer.toneMappingExposure = 1.1;
  const scene = new THREE.Scene(); scene.background = col(0x090b0a);
  const pm = new THREE.PMREMGenerator(renderer); scene.environment = pm.fromScene(new RoomEnvironment(), 0.04).texture; scene.environmentIntensity = .55;
  const camera = new THREE.PerspectiveCamera(34, GW / GH, .1, 120);
  let composer = null, bloom = null, rt = null;
  if (!light) {
    rt = new THREE.WebGLRenderTarget(GW, GH, { type: THREE.HalfFloatType, samples: 4 });
    composer = new EffectComposer(renderer, rt);
    composer.addPass(new RenderPass(scene, camera));
    bloom = new UnrealBloomPass(new THREE.Vector2(GW, GH), .42, .55, .32); composer.addPass(bloom);
    composer.addPass(new OutputPass());
  }

  const glowTex = (() => { const c = document.createElement('canvas'); c.width = c.height = 128; const g = c.getContext('2d'); const gr = g.createRadialGradient(64, 64, 0, 64, 64, 64); gr.addColorStop(0, 'rgba(255,255,255,1)'); gr.addColorStop(.25, 'rgba(255,255,255,.5)'); gr.addColorStop(1, 'rgba(255,255,255,0)'); g.fillStyle = gr; g.fillRect(0, 0, 128, 128); return new THREE.CanvasTexture(c); })();
  const GREEN = col(0x6ee7a0), ICE = col(0xa6dbff), RED = col(0xff5545), AMBER = col(0xffcf66), WHITE = col(0xffffff);

  /* ---- the web ---- */
  const dispY = (x, z, t) => { const r = Math.hypot(x, z); return .13 * Math.sin(r * 1.15 - t * 1.1) * clamp(r / 2.5) + .07 * Math.sin(x * .55 + t * .6) * Math.cos(z * .45 - t * .5); };
  const webU = { uT: { value: 0 }, uWaveT: { value: 0 }, uReveal: { value: 30 }, uFreezeR: { value: 0 }, uIce: { value: 1 }, uDim: { value: 1 }, uPx: { value: 2.2 }, uFC: { value: new THREE.Vector3() } };
  const webVS = `uniform float uT,uWaveT,uReveal,uFreezeR,uIce,uDim,uPx;uniform vec3 uFC;attribute float aB;varying float vA;varying vec3 vC;
float dy(vec2 p,float t){float r=length(p);return .13*sin(r*1.15-t*1.1)*clamp(r/2.5,0.,1.)+.07*sin(p.x*.55+t*.6)*cos(p.y*.45-t*.5);}
void main(){vec3 p=position;float r=length(p.xz);p.y+=dy(p.xz,uWaveT);
float d=distance(p.xz,uFC.xz);float ice=uFreezeR>0.01?smoothstep(uFreezeR,uFreezeR-1.4,d)*uIce:0.;
float front=uFreezeR>0.01?exp(-pow(d-uFreezeR,2.)*1.2)*smoothstep(24.,10.,uFreezeR):0.;
float sonar=exp(-pow(r-mod(uT*1.35,15.),2.)*1.6)*(1.-ice);
vec3 g=vec3(.05,.30,.16),gi=vec3(.30,.80,.50),ic=vec3(.20,.38,.60),w=vec3(.9,.97,1.);
vC=mix(g*(.45+aB*1.5)+gi*sonar*.8,ic*(.4+aB*1.2),ice)+w*front*1.6;
float fade=1.-smoothstep(3.,11.,r);
vA=(.12+.88*fade)*(1.-smoothstep(uReveal-3.,uReveal,r))*uDim;
vec4 mv=modelViewMatrix*vec4(p,1.);gl_Position=projectionMatrix*mv;gl_PointSize=uPx*(1.+aB*1.5+sonar*2.+front*3.)*(14./-mv.z);}`;
  const webFS = pts => `varying float vA;varying vec3 vC;void main(){${pts ? 'float d=length(gl_PointCoord-.5);if(d>.5)discard;float m=smoothstep(.5,.1,d);' : 'float m=1.;'}gl_FragColor=vec4(vC*vA*m,1.);}`;
  {
    const SP = 30, RINGS = 13, r0 = 1.2, dr = .8; const pos = [], br = [], ppos = [], pbr = [];
    const P = (k, s) => { const r = r0 + k * dr, a = s / SP * Math.PI * 2; return [Math.cos(a) * r, 0, Math.sin(a) * r]; };
    for (let s = 0; s < SP; s++) { // spokes (subdivided so they bend with the wave)
      for (let k = -1; k < RINGS - 1; k++) { const a = k < 0 ? [0, 0, 0] : P(k, s), b = P(k + 1, s); for (let q = 0; q < 2; q++) { pos.push(lerp(a[0], b[0], q / 2), 0, lerp(a[2], b[2], q / 2), lerp(a[0], b[0], (q + 1) / 2), 0, lerp(a[2], b[2], (q + 1) / 2)); br.push(.25, .25); } }
      for (let k = 0; k < RINGS; k++) { const a = P(k, s), b = P(k, s + 1), m = [(a[0] + b[0]) / 2 * .972, 0, (a[2] + b[2]) / 2 * .972]; const bb = k % 3 === 0 ? .55 : .12; pos.push(...a, ...m, ...m, ...b); br.push(bb, bb, bb, bb); ppos.push(...a); pbr.push(k % 3 === 0 ? .9 : .25); }
    }
    const mk = (p, b) => { const g = new THREE.BufferGeometry(); g.setAttribute('position', new THREE.Float32BufferAttribute(p, 3)); g.setAttribute('aB', new THREE.Float32BufferAttribute(b, 1)); return g; };
    const base = { uniforms: webU, vertexShader: webVS, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending };
    scene.add(new THREE.LineSegments(mk(pos, br), new THREE.ShaderMaterial({ ...base, fragmentShader: webFS(0) })));
    scene.add(new THREE.Points(mk(ppos, pbr), new THREE.ShaderMaterial({ ...base, fragmentShader: webFS(1) })));
  }

  /* ---- the core ---- */
  const core = new THREE.Group(); core.position.set(0, 1.15, 0); scene.add(core);
  const fresVS = `varying vec3 vN,vV;void main(){vN=normalize(normalMatrix*normal);vec4 mv=modelViewMatrix*vec4(position,1.);vV=normalize(-mv.xyz);gl_Position=projectionMatrix*mv;}`;
  const fresFS = `uniform vec3 uC;uniform float uI,uP,uB;varying vec3 vN,vV;void main(){float f=pow(1.-abs(dot(normalize(vN),normalize(vV))),uP);gl_FragColor=vec4(uC*(uB+f*uI),1.);}`;
  const coreMat = new THREE.ShaderMaterial({ uniforms: { uC: { value: GREEN.clone() }, uI: { value: 1.5 }, uP: { value: 2.4 }, uB: { value: .04 } }, vertexShader: fresVS, fragmentShader: fresFS });
  core.add(new THREE.Mesh(new THREE.IcosahedronGeometry(.62, light ? 3 : 5), coreMat));
  const ringMat = new THREE.MeshBasicMaterial({ color: GREEN.clone(), transparent: true, opacity: .8, blending: THREE.AdditiveBlending, depthWrite: false });
  const rings = [1.0, 1.28, 1.5].map((r, i) => { const m = new THREE.Mesh(new THREE.TorusGeometry(r, i === 2 ? .006 : .012, 8, light ? 72 : 120, i === 2 ? Math.PI * 1.4 : Math.PI * 2), ringMat); core.add(m); return m; });
  const coreGlow = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTex, color: GREEN, blending: THREE.AdditiveBlending, depthWrite: false, transparent: true, opacity: .3 })); coreGlow.scale.setScalar(4); core.add(coreGlow);
  const coreStem = new THREE.Mesh(new THREE.CylinderGeometry(.008, .008, 1.15, 6), ringMat); coreStem.position.y = -.58; core.add(coreStem);

  /* ---- bait gems and the tripwires between them (rebuilt when the baits change) ---- */
  const nodes = new THREE.Group(); scene.add(nodes);
  const wireG = new THREE.Group(); scene.add(wireG);
  const gemGeo = new THREE.OctahedronGeometry(.2, 0); gemGeo.scale(1, 1.45, 1);
  const ringGeo = new THREE.RingGeometry(.34, .37, 48); ringGeo.rotateX(-Math.PI / 2);
  const ring2Geo = new THREE.RingGeometry(.52, .53, 48); ring2Geo.rotateX(-Math.PI / 2);
  const stemGeo = new THREE.CylinderGeometry(.006, .006, NODE_Y, 5);
  const wireMat = new THREE.MeshBasicMaterial({ color: GREEN.clone().multiplyScalar(.4), transparent: true, opacity: .9, blending: THREE.AdditiveBlending, depthWrite: false });
  const pulseMat = new THREE.PointsMaterial({ map: glowTex, size: .26, color: col(0xcffff0), transparent: true, blending: THREE.AdditiveBlending, depthWrite: false });
  let BAITS = [], wires = [], pulses = null, baitKey = null, selected = null;
  const slot = i => { const [a, r] = SLOTS[i]; const ang = a * Math.PI / 180; return { a, r, x: Math.cos(ang) * r, z: Math.sin(ang) * r }; };

  function setBaits(tags) {
    tags = (tags || []).slice(0, MAX_BAITS);
    const key = tags.map(t => t.id + '\u0001' + t.label + '\u0001' + t.icon).join('\u0002');
    if (key === baitKey) { tags.forEach((t, i) => { BAITS[i].health = t.health; BAITS[i].el.dataset.health = t.health || 'ok'; }); return; }
    baitKey = key;
    for (const b of BAITS) { b.mat.dispose(); b.hm.dispose(); b.sp.material.dispose(); b.el.remove(); }
    nodes.clear(); for (const w of wireG.children) w.geometry.dispose(); wireG.clear(); if (pulses) { scene.remove(pulses); pulses.geometry.dispose(); }
    BAITS = tags.map((t, i) => {
      const b = { ...t, ...slot(i), i, home: i < HOME_TAGS };
      const g = new THREE.Group(); g.position.set(b.x, 0, b.z);
      const mat = new THREE.MeshStandardMaterial({ color: 0x0c1a12, emissive: GREEN.clone(), emissiveIntensity: .9, flatShading: true, roughness: .25, metalness: .3 });
      const gem = new THREE.Mesh(gemGeo, mat); gem.position.y = NODE_Y; g.add(gem);
      const hm = new THREE.MeshBasicMaterial({ color: GREEN.clone(), transparent: true, opacity: .55, blending: THREE.AdditiveBlending, depthWrite: false, side: THREE.DoubleSide });
      const halo = new THREE.Mesh(ringGeo, hm); g.add(halo); const halo2 = new THREE.Mesh(ring2Geo, hm); g.add(halo2);
      const stem = new THREE.Mesh(stemGeo, hm); stem.position.y = NODE_Y / 2; g.add(stem);
      const sp = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTex, color: GREEN.clone(), blending: THREE.AdditiveBlending, depthWrite: false, transparent: true, opacity: .3 })); sp.scale.setScalar(1.3); sp.position.y = NODE_Y; g.add(sp);
      nodes.add(g);
      // The label: a button (text only), projected onto its gem every frame.
      const el = h('button.btag', { type: 'button', tabindex: '-1', data: { bait: t.id, health: t.health || 'ok' }, on: { click: () => onTag && onTag(t.id) } }, tile(t.icon, baitColor(t.icon)), h('span.bt-l', t.label), h('u'));
      els.tags.append(el);
      return Object.assign(b, { g, gem, mat, hm, halo, halo2, sp, stem, el, shown: false });
    });
    wires = [];
    const done = new Set(); const add = (A, B, lift) => {
      const a = new THREE.Vector3(A.x, A.y ?? NODE_Y, A.z), b = new THREE.Vector3(B.x, B.y ?? NODE_Y, B.z), m = a.clone().add(b).multiplyScalar(.5); m.y += lift;
      const c = new THREE.QuadraticBezierCurve3(a, m, b); wireG.add(new THREE.Mesh(new THREE.TubeGeometry(c, light ? 16 : 28, .011, 5), wireMat)); wires.push(c);
    };
    BAITS.forEach((b, i) => {
      if (b.r < 4) add({ x: 0, y: 1.15, z: 0 }, b, .5);
      BAITS.map((o, j) => [Math.hypot(o.x - b.x, o.z - b.z), j]).filter(d => d[1] !== i).sort((p, q) => p[0] - q[0]).slice(0, 2).forEach(([d, j]) => { const k = Math.min(i, j) + '-' + Math.max(i, j); if (!done.has(k)) { done.add(k); add(b, BAITS[j], .35 + d * .06); } });
    });
    const pg = new THREE.BufferGeometry(); pg.setAttribute('position', new THREE.Float32BufferAttribute(new Float32Array(Math.max(1, wires.length * 2) * 3), 3));
    pulses = new THREE.Points(pg, pulseMat); pulses.frustumCulled = false; scene.add(pulses);
    if (C) placeCatch();
    invalidate();
  }

  /* ---- the caught program, and the ice cube that shuts around it ---- */
  const vir = buildVirus(1.12, 2.3, light ? 2 : 3); vir.visible = false; scene.add(vir);
  const virL = new THREE.PointLight(0xff3a22, 0, 3.2); vir.add(virL);
  const virGlow = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTex, color: RED, blending: THREE.AdditiveBlending, depthWrite: false, transparent: true, opacity: .5 })); virGlow.scale.setScalar(1.7); vir.add(virGlow);
  const TR = 22; const trailGeo = new THREE.BufferGeometry(); trailGeo.setAttribute('position', new THREE.Float32BufferAttribute(new Float32Array(TR * 3), 3));
  const trail = new THREE.Points(trailGeo, new THREE.PointsMaterial({ map: glowTex, size: .22, color: RED, transparent: true, opacity: .6, blending: THREE.AdditiveBlending, depthWrite: false })); trail.frustumCulled = false; trail.visible = false; scene.add(trail);

  const cube = new THREE.Group(); cube.visible = false; scene.add(cube);
  const CS = 1.36; const cubeGeo = new RoundedBoxGeometry(CS, CS, CS, light ? 4 : 8, .13);
  const iceMat = light
    ? new THREE.MeshStandardMaterial({ color: 0xd6ecff, transparent: true, opacity: .26, roughness: .05, metalness: .1, emissive: 0x16344a, depthWrite: false })
    : new THREE.MeshPhysicalMaterial({ color: 0xe6f4ff, transmission: 1, thickness: .28, roughness: .02, ior: 1.31, metalness: 0, attenuationColor: col(0x9fd4ff), attenuationDistance: 3.5, envMapIntensity: 2.4, emissive: 0x0c2233, clearcoat: 1, clearcoatRoughness: .03, specularIntensity: 1 });
  cube.add(new THREE.Mesh(cubeGeo, iceMat));
  const shellMat = new THREE.ShaderMaterial({ uniforms: { uC: { value: col(0x9fd6ff) }, uI: { value: light ? 1.1 : .8 }, uP: { value: 3.0 }, uB: { value: .0 } }, vertexShader: fresVS, fragmentShader: fresFS, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false });
  cube.add(new THREE.Mesh(cubeGeo, shellMat));
  { // frost only inside the ice: tiny white flecks gathered toward the faces and corners
    const N = light ? 36 : 70, im = new THREE.InstancedMesh(new THREE.IcosahedronGeometry(1, 0), new THREE.MeshBasicMaterial({ color: col(0xeaf6ff).multiplyScalar(1.25) }), N), d = new THREE.Object3D();
    for (let i = 0; i < N; i++) {
      const q = [0, 1, 2].map(k => (hash(i, k, 5) - .5) * 2); const ax = Math.floor(hash(i, 9) * 3); q[ax] = Math.sign(q[ax] || 1) * (.8 + hash(i, 4) * .14); { const b = (ax + 1) % 3; q[b] = Math.sign(q[b] || 1) * (.72 + hash(i, 7) * .22); }
      d.position.set(q[0] * CS * .46, q[1] * CS * .46, q[2] * CS * .46); d.scale.setScalar(.006 + hash(i, 8) * hash(i, 3) * .022); d.rotation.set(i, i * 2, i * 3); d.updateMatrix(); im.setMatrixAt(i, d.matrix);
    }
    cube.add(im);
  }
  const keyL = new THREE.DirectionalLight(0xd8ecff, 2.2); keyL.position.set(-4, 7, 5); scene.add(keyL);
  const iceL = new THREE.PointLight(0x8fd0ff, 0, 9); scene.add(iceL);
  scene.add(new THREE.AmbientLight(0x9fb8a8, .35));
  // the burst of frost when the cube snaps shut
  const moteG = new THREE.Group(); scene.add(moteG); moteG.visible = false;
  const MN = light ? 40 : 90; const moteGeo = new THREE.BufferGeometry(); moteGeo.setAttribute('position', new THREE.Float32BufferAttribute(new Float32Array(MN * 3), 3));
  const motes = new THREE.Points(moteGeo, new THREE.PointsMaterial({ map: glowTex, size: .06, color: col(0xe8f6ff), transparent: true, opacity: .7, blending: THREE.AdditiveBlending, depthWrite: false })); motes.frustumCulled = false; moteG.add(motes);
  const moteSeed = [...Array(MN)].map((_, i) => { const y = 1 - (i + .5) / MN * 2, r = Math.sqrt(1 - y * y), a = i * 2.39996; return [Math.cos(a) * r, y * .6 + .2, Math.sin(a) * r, .5 + hash(i, 2) * 1.6, hash(i, 5) * 6.283]; });

  /* ---- state ---- */
  let T = 0, waveT = 0, lastT = 0, frames = 0;
  const S = { screen: '', screenT0: 0, introT0: null };
  // The catch on show: C.fz is the moment (scene time) the ice shuts, or
  // null while the program is still crawling toward the bait.
  let C = null;
  const waits = []; // {t, done}: things to do when the scene's clock gets there
  const at = t => new Promise(done => { waits.push({ t, done }); });
  const CP = new THREE.Vector3(slot(0).x, CUBE_Y, slot(0).z);

  function crawlTo(b) {
    const pts = []; const A = a => a * Math.PI / 180; const P = (r, a, y = .2) => pts.push(new THREE.Vector3(Math.cos(A(a)) * r, y, Math.sin(A(a)) * r));
    const ring = Math.max(b.r + 1.4, Math.min(b.r + 2.2, 9.4)), a0 = b.a + 26;
    for (let r = Math.max(11, ring + 1.2); r >= ring; r -= .6) P(r, a0);
    for (let a = a0 - 2; a >= b.a; a -= 3) P(ring, a);
    for (let r = ring - .4; r >= b.r + .5; r -= .5) P(r, b.a);
    P(b.r + .25, b.a, .45); pts.push(new THREE.Vector3(b.x, NODE_Y + .1, b.z));
    return new THREE.CatmullRomCurve3(pts, false, 'centripetal');
  }
  function placeCatch() {
    const b = BAITS.find(x => x.id === C.baitId) || null;
    C.bait = b; const at0 = b || slot(0);
    C.a = at0.a; C.r = at0.r; CP.set(at0.x, CUBE_Y, at0.z);
    C.crawl = crawlTo({ a: at0.a, r: at0.r, x: at0.x, z: at0.z });
    cube.position.copy(CP); moteG.position.copy(CP); iceL.position.set(CP.x + 1.4, 2.2, CP.z + 2);
    els.intruder.querySelector('.in-l').textContent = C.program || 'A program';
    if (POSE_NOW) setPoseTargets();
  }
  function newCatch(info) {
    C = { baitId: info.baitId || '', label: info.label || '', program: info.program || '', u: 0, uA: null, fz: null, melt: null, born: T };
    placeCatch();
  }
  const frozen = () => !!C && C.fz !== null && T >= C.fz;

  // [camX,camY,camZ, tgtX,tgtY,tgtZ, offX,offY, webDim]
  const pose = name => {
    switch (name) {
      case 'baits': return [0, 15.6, 18.4, 0, 0, 0, -186, -26, 1];
      case 'caught': return [CP.x - 2.6, 5.4, CP.z + 9.4, CP.x, .75, CP.z, 236, -70, .3];
      case 'report': return [CP.x - 3.2, 5.6, CP.z + 11.6, CP.x, .75, CP.z, 452, -266, .24];
      case 'history': return [0, 5.5, 17, 0, 0, 0, 300, 240, .3];
      case 'settings': return [0, 5.5, 17, 0, 0, 0, -100, 470, .2];
      default: return [0, 10.2, 18, 0, .3, 0, -196, -20, 1];
    }
  };
  let POSE_NOW = null; const P_ = { from: pose('home'), to: pose('home'), t0: -10, d: 1 };
  const poseNow = () => { const k = ease((T - P_.t0) / P_.d); return P_.to.map((v, i) => lerp(P_.from[i], v, k)); };
  function setPoseTargets() { P_.from = poseNow(); P_.to = pose(S.screen); P_.t0 = T; P_.d = Math.max(P_.d, .01); }

  function go(name, opts = {}) {
    if (!['home', 'baits', 'caught', 'report', 'history', 'settings'].includes(name)) name = 'home';
    const first = !S.screen;
    if (S.screen === name && !opts.force) return;
    P_.from = first ? (name === 'home' ? [0, 15, 25, 0, .3, 0, -196, -20, 1] : pose(name)) : poseNow();
    S.screen = name; P_.to = pose(name); P_.t0 = T; P_.d = opts.d || (first ? (name === 'home' ? 3.6 : .01) : 1.5);
    S.screenT0 = T; POSE_NOW = true;
    if (first && name === 'home' && !opts.noIntro) S.introT0 = T;
    busy(P_.d + 3.2); invalidate();
  }

  /* ---- the catch, as a sequence ---- */
  // The program is already in ice (the app opened on an old or open alert).
  function showFrozen(info) { newCatch(info); C.u = 1; C.fz = T - 100; C.born = T - 100; busy(1); invalidate(); }
  // Crawl in, touch the bait, freeze. `from` is where on its path it starts
  // (0 = the edge of the web), `crawl` how long the crawl takes.
  function playCatch(info, { crawl = 2.6, from = 0 } = {}) {
    if (reduced) { showFrozen(info); return Promise.resolve(); }
    newCatch(info); C.u = from; C.uA = { from, to: 1, t0: T, d: crawl, steps: Math.max(2, Math.round(6 * (1 - from))) }; C.fz = T + crawl + .12;
    busy(crawl + 4); return at(C.fz + 1.3);
  }
  // The safe test: the fake stealer comes in and waits near the bait…
  function approach(info) {
    if (reduced) return;
    newCatch(info); C.uA = { from: 0, to: .66, t0: T, d: 2.6, steps: 4 }; busy(60);
  }
  // …until ABA says it caught it.
  function strike(info) {
    if (reduced || !C || C.fz !== null) { if (!frozen()) showFrozen(info || C || {}); return Promise.resolve(); }
    if (info && info.baitId && info.baitId !== C.baitId) { const u = C.u; C.baitId = info.baitId; C.label = info.label; C.program = info.program || C.program; placeCatch(); C.u = u; }
    else if (info && info.program) { C.program = info.program; els.intruder.querySelector('.in-l').textContent = C.program; }
    C.uA = { from: C.u, to: 1, t0: T, d: .9, steps: 2 }; C.fz = T + .9 + .12; busy(5); return at(C.fz + 1.3);
  }
  // Killed, trusted or let go: the ice lets go and the web thaws.
  function melt() {
    if (!C) return Promise.resolve();
    if (reduced || !frozen()) { C = null; invalidate(); return Promise.resolve(); }
    C.melt = T; busy(3); return at(T + 1.7).then(() => { if (C && C.melt !== null) { C = null; if (S.screen === 'caught' || S.screen === 'report') setPoseTargets(); } });
  }
  function clearCatch() { if (C) { C = null; invalidate(); } }
  // Resolves when the program on show is frozen (at once if it already is, or nothing is on show).
  const whenFrozen = () => C && C.fz !== null && T < C.fz ? at(C.fz + .15) : Promise.resolve();

  /* ---- drawing one frame ---- */
  const v3 = new THREE.Vector3(), tmpC = new THREE.Color(), pp = {};
  function project(p, out) { v3.copy(p).project(camera); out.x = (v3.x * .5 + .5) * GW; out.y = (-v3.y * .5 + .5) * GH; out.z = v3.z; return out; }

  function frame(t) {
    const dt = clamp(t - lastT, 0, .25); lastT = t; T = t;
    if (!S.screen) return; // nothing is drawn before the first screen is chosen (no flash of another camera)
    const ts = t - S.screenT0;
    const fr = frozen(); const fk = fr ? t - C.fz : 0; const tc = C ? t - C.born : -1;
    const mk = C && C.melt !== null ? clamp((t - C.melt) / 1.5) : 0; // 0 → 1 while the ice lets go
    const hold = fr ? 1 - mk : 0; // how frozen the web is (waves stop)
    waveT += dt * (1 - hold);
    const P = poseNow();

    // camera
    const sway = Math.sin(t * .11) * .16 + Math.sin(t * .05) * .06; const cx = P[0] - P[3], cz = P[2] - P[5]; const cs = Math.cos(sway), sn = Math.sin(sway);
    camera.position.set(P[3] + cx * cs - cz * sn, P[1] + Math.sin(t * .17) * .12, P[5] + cx * sn + cz * cs); camera.lookAt(P[3], P[4], P[5]);
    camera.setViewOffset(GW, GH, -P[6] * GW / DW, -P[7] * GH / DH, GW, GH); camera.updateMatrixWorld(); camera.updateProjectionMatrix();

    // web
    const open = S.introT0 !== null ? t - S.introT0 : 99;
    webU.uT.value = t; webU.uWaveT.value = waveT; webU.uReveal.value = easeOut(open / 2.6) * 21; webU.uDim.value = P[8];
    webU.uFreezeR.value = fr ? Math.min(.6 + fk * 11, 40) : 0; webU.uIce.value = 1 - mk; webU.uFC.value.set(CP.x, 0, CP.z);
    const iceG = fr ? clamp(fk / 1.1) * (1 - mk) : 0; const dim = P[8]; core.visible = dim > .33;

    // core
    const coreIn = backOut((open - .3) / 1.1);
    core.scale.setScalar(Math.max(.001, coreIn) * clamp((dim - .32) / .2) * (1 + Math.sin(t * 1.6) * .03) * lerp(1, .8, iceG));
    tmpC.copy(GREEN).lerp(ICE, iceG); coreMat.uniforms.uC.value.copy(tmpC); ringMat.color.copy(tmpC).multiplyScalar(.9 * dim); coreGlow.material.color.copy(tmpC); coreGlow.material.opacity = (light ? .5 : .28) * dim;
    const rt_ = waveT;
    rings[0].rotation.set(1.2 + rt_ * .5, rt_ * .35, 0); rings[1].rotation.set(rt_ * .3, 1 + rt_ * .42, .4); rings[2].rotation.set(1.57, 0, rt_ * .7);
    wireMat.color.copy(tmpC).multiplyScalar(.38 * dim);

    // gems
    const touchT = C && C.fz !== null ? C.fz - .12 : Infinity;
    for (const b of BAITS) {
      const i = b.i; const nin = backOut((open - .9 - b.r * .14 - (i % 5) * .05) / .8); const y = dispY(b.x, b.z, waveT);
      const d = Math.hypot(b.x - CP.x, b.z - CP.z); const nice = fr ? clamp((fk * 11 - d) / 1.4) * (1 - mk) : 0;
      const mine = C && C.bait === b;
      b.g.scale.setScalar(Math.max(.001, nin));
      const hide = mine && fr ? clamp(fk / .12) * (1 - mk) : 0; // the gem is inside the cube
      b.gem.scale.setScalar(1 - hide); b.gem.visible = b.sp.visible = b.stem.visible = hide < .99;
      b.gem.position.y = NODE_Y + Math.sin(waveT * 1.3 + i) * .05 * (1 - hold); b.gem.rotation.y = rt_ * .7 + i;
      b.halo.position.y = y; b.halo2.position.y = y; const hp = (t * .5 + i * .37) % 1; b.halo2.scale.setScalar(1 + hp * 1.4);
      tmpC.copy(b.health === 'missing' ? RED : b.health === 'error' ? AMBER : GREEN).lerp(ICE, nice);
      const hot = mine && t > touchT - .1 && t < C.fz + .25;
      if (hot) tmpC.copy(RED).lerp(WHITE, clamp((t - C.fz) * 8));
      b.mat.emissive.copy(tmpC); b.mat.emissiveIntensity = .95 * (.25 + .75 * dim) * (hot ? 3 : 1) * (b.health === 'missing' ? .45 : 1);
      b.hm.color.copy(tmpC).multiplyScalar(dim); b.sp.material.color.copy(tmpC); b.sp.material.opacity = (light ? .5 : .28) * dim;
    }
    // pulses along the wires
    if (pulses && wires.length) {
      const pa = pulses.geometry.attributes.position; wires.forEach((c, i) => { for (let j = 0; j < 2; j++) { const k = (waveT * (.16 + (i % 4) * .03) + i * .37 + j * .5) % 1; c.getPoint(k, v3); pa.setXYZ(i * 2 + j, v3.x, v3.y, v3.z); } }); pa.needsUpdate = true;
      pulseMat.opacity = clamp((open - 2) / 1) * dim; pulseMat.color.set(0xcffff0).lerp(ICE, iceG);
    }

    // the virus: crawls the web, touches the bait, gets shut in ice
    vir.visible = !!C; trail.visible = !!C && !fr; const ie = els.intruder;
    if (C) {
      if (C.uA) { const a = C.uA, k = clamp((t - a.t0) / a.d); const st = a.steps; C.u = lerp(a.from, a.to, (Math.floor(k * st) + ease(clamp((k * st % 1) * 1.5))) / st); if (k >= 1) { C.u = a.to; C.uA = null; } } // scuttle, pause, scuttle
      const kk = fr ? 1 : C.u;
      C.crawl.getPoint(clamp(kk), vir.position); if (kk < .9) vir.position.y = dispY(vir.position.x, vir.position.z, waveT) + .26;
      const lock = fr ? clamp(fk / .1) : 0; vir.position.lerp(v3.copy(CP), lock);
      const near = t > touchT;
      const sc = fr ? 1 : lerp(.62, .8, kk) * (near ? 1.15 : 1); vir.scale.setScalar(sc * clamp(tc * 3) * (1 - easeOut(mk * 1.4)));
      const lv = fr ? Math.exp(-fk * 18) : 1; const pt = fr ? C.fz : t;
      vir.rotation.set(kk * 9 + (fr ? .3 : 0), kk * 14 + .4, Math.sin(pt * 31) * .08 * lv);
      const sp = vir.userData.spikes; for (let i = 0; i < sp.length; i++) sp[i].scale.y = 1 + (fr ? .12 * Math.sin(i * 2.1) : Math.sin(pt * 5 + i * 1.7) * .3);
      virL.intensity = (fr ? 1.3 + Math.sin(t * 1.6) * .3 : 3) * (1 - mk); virGlow.material.opacity = fr ? 0 : .5;
      const ta = trailGeo.attributes.position; for (let j = 0; j < TR; j++) { C.crawl.getPoint(clamp(kk - j * .006), v3); v3.y = dispY(v3.x, v3.z, waveT) + .2; ta.setXYZ(j, v3.x, v3.y, v3.z); } ta.needsUpdate = true;
      const io = fr ? 0 : clamp(tc * 3) * (1 - clamp((t - touchT - .12) * 8));
      if (io > .01) { project(vir.position, pp); ie.style.transform = `translate(${(pp.x + 22).toFixed(1)}px,${(pp.y - 52).toFixed(1)}px)`; }
      ie.style.opacity = io.toFixed(2);
    } else ie.style.opacity = 0;

    // the ice: snaps shut in about a tenth of a second
    const cg = fr ? backOut(fk / .2) * (1 - easeOut(mk * 1.2)) : 0; cube.visible = moteG.visible = cg > .001;
    if (cube.visible) {
      cube.scale.setScalar(Math.max(.001, cg)); cube.rotation.y = -.13 + Math.sin(t * .2) * .05; iceL.intensity = 10 * clamp(cg);
      const ma = moteGeo.attributes.position; const bk = easeOut(fk / .9); for (let i = 0; i < MN; i++) { const m = moteSeed[i], rr = .9 + bk * m[3] + Math.sin(t * .3 + m[4]) * .05; ma.setXYZ(i, m[0] * rr, m[1] * rr + Math.sin(t * .4 + m[4]) * .06, m[2] * rr); } ma.needsUpdate = true;
      motes.material.opacity = (.25 + .65 * Math.exp(-fk * 1.2)) * (1 - mk);
    } else iceL.intensity = 0;
    if (bloom) bloom.strength = .42 + (fr ? Math.exp(-fk * 5) * .7 : 0);
    // (scrolled far down the report, the scene is off the screen: nothing to draw)
    const away = S.screen === 'report' && scrollY_ * .55 > GH;
    if (!away) { if (composer) composer.render(); else renderer.render(scene, camera); }
    frames++;

    // labels
    const scr = S.screen; const icy = scr === 'caught' || scr === 'report';
    const showHome = scr === 'home' && (S.introT0 !== null && open < 60 ? open > 2.4 : ts > .5) && !(C && (fr ? mk === 0 && fk > .3 : t > touchT)), showAll = scr === 'baits' && ts > .5;
    for (const b of BAITS) {
      const mine = C && C.bait === b && fr && mk === 0;
      const cTag = mine && (scr === 'caught' ? fk > 1.6 : scr === 'home');
      const on = showAll || (showHome && b.home) || cTag;
      if (on !== b.shown) { b.shown = on; b.el.classList.toggle('show', on); b.el.tabIndex = on && showAll ? 0 : -1; }
      b.el.classList.toggle('hit', !!cTag); b.el.classList.toggle('sel', showAll && b.id === selected);
      if (!on && !b.el.style.transform) continue;
      v3.set(b.x, cTag ? CUBE_Y + 1.0 : NODE_Y + .42, b.z); project(v3, pp); const sc = clamp(1.12 - (pp.z - .97) * 9, .78, 1.05);
      b.el.style.transform = `translate(${pp.x.toFixed(1)}px,${pp.y.toFixed(1)}px) translate(-50%,-100%) scale(${(showAll ? sc * .94 : sc).toFixed(3)})`;
      b.el.style.zIndex = Math.round((1 - pp.z) * 10000);
    }
    // a caught "bait" that isn't a gem (the miner trap, the clipboard): its own label
    const lone = els.lone; const loneOn = !!C && !C.bait && fr && mk === 0 && !!C.label && (scr === 'caught' ? fk > 1.6 : scr === 'home');
    lone.classList.toggle('show', loneOn);
    if (loneOn) { v3.set(CP.x, CUBE_Y + 1.0, CP.z); project(v3, pp); lone.style.transform = `translate(${pp.x.toFixed(1)}px,${pp.y.toFixed(1)}px) translate(-50%,-100%)`; if (lone.dataset.l !== C.label) { lone.dataset.l = C.label; lone.querySelector('.bt-l').textContent = C.label; } }
    // "Held in ice for 0:50", under the cube
    const heldOn = scr === 'caught' && cube.visible && fk > 1.6 && mk === 0 && els.held.dataset.on === '1';
    els.held.classList.toggle('show', heldOn);
    if (cube.visible && scr === 'caught') { project(v3.set(CP.x, .1, CP.z), pp); els.held.style.transform = `translate(${pp.x.toFixed(1)}px,${(pp.y + 34).toFixed(1)}px) translateX(-50%)`; }
    // the flash as it freezes
    const fl = els.flash;
    if (fr && fk < 1 && !reduced) { project(v3.set(CP.x, NODE_Y, CP.z), pp); fl.style.setProperty('--fx', (pp.x + 88).toFixed(0) + 'px'); fl.style.setProperty('--fy', (pp.y + 44).toFixed(0) + 'px'); fl.style.opacity = (Math.exp(-fk * 7) * .75).toFixed(3); } else if (fl.style.opacity !== '0') fl.style.opacity = '0';
    // the report scrolls over the scene
    canvas.style.transform = scr === 'report' && scrollY_ ? `translateY(${(-scrollY_ * .55).toFixed(1)}px)` : '';
    document.body.classList.toggle('icy', (icy || scr === 'home') && fr && mk < .5);

    tickIcons(t);
    for (let i = waits.length - 1; i >= 0; i--) if (t >= waits[i].t) waits.splice(i, 1)[0].done();
    if (hooks.length) for (const f of hooks) f(t);
  }

  /* ---- the loop: only as fast as needed, and not at all when nobody's looking ---- */
  let raf = 0, lastWall = 0, activeUntil = 0, keepAwake = false, clockT = 0, scrollY_ = 0;
  const hooks = [];
  const busy = sec => { activeUntil = Math.max(activeUntil, clockT + sec); wake(); };
  const idleFps = light ? 20 : 30, busyFps = light ? 30 : 60;
  let slow = 0, measured = 0, downgraded = 0;
  function tick(wall) {
    raf = 0;
    if (document.hidden) return;
    const active = clockT < activeUntil;
    if (!active && !keepAwake && !document.hasFocus()) return; // unfocused and nothing moving: stop until focus comes back
    raf = requestAnimationFrame(tick);
    const want = 1000 / (active ? busyFps : idleFps);
    const since = wall - lastWall; if (since < want - 3) return;
    const dt = Math.min(since, 250) / 1000; lastWall = wall; clockT += dt; // (real time down to 4 frames a second)
    const t0 = performance.now(); frame(clockT);
    // A GPU that can't keep up: drop the sharpness, then the bloom.
    if (!light && downgraded < 2) { slow += performance.now() - t0 > 24 || since > 2.2 * want ? 1 : 0; if (++measured >= 120) { if (slow > 60) { downgraded++; if (downgraded === 1) { maxPR = 1; applySize(); } else { composer = null; } } slow = measured = 0; } }
  }
  function wake() { if (manual || reduced) return; if (!raf && !document.hidden) { lastWall = performance.now() - 16; raf = requestAnimationFrame(tick); } }
  // Still mode (reduced motion): draw once, far enough ahead that every move has ended.
  function invalidate() {
    if (manual) return;
    if (!reduced) { wake(); return; }
    if (invalidate.q) return; invalidate.q = true;
    requestAnimationFrame(() => { invalidate.q = false; clockT += 100; frame(clockT); });
  }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) { wake(); invalidate(); } });
  addEventListener('focus', () => { busy(.5); invalidate(); });

  let maxPR = light ? 1 : 2, uiK = 1;
  function applySize() {
    PR = Math.min(maxPR, (light ? 1 : (devicePixelRatio || 1)) * uiK);
    renderer.setPixelRatio(PR); renderer.setSize(GW, GH, false);
    if (composer) { composer.setPixelRatio(PR); composer.setSize(GW, GH); bloom.setSize(GW * PR, GH * PR); }
    camera.aspect = GW / GH; webU.uPx.value = 2.2 * PR;
  }
  function resize(w, hgt, k) { GW = Math.max(200, Math.round(w)); GH = Math.max(200, Math.round(hgt)); uiK = k; applySize(); invalidate(); }
  applySize();

  return {
    setBaits, go, showFrozen, playCatch, approach, strike, melt, clearCatch, whenFrozen, resize, invalidate, busy, frame,
    select(id) { selected = id; invalidate(); },
    // Point the Caught and Report cameras at a bait when nothing is in ice (an old alert).
    aim(baitId) { if (C) return; const b = BAITS.find(x => x.id === baitId) || slot(0); CP.set(b.x, CUBE_Y, b.z); },
    setScroll(y) { scrollY_ = y; if (reduced) invalidate(); },
    setKeepAwake(v) { keepAwake = v; wake(); },
    onFrame(f) { hooks.push(f); },
    get catching() { return !!C && !frozen(); },
    get hasCatch() { return !!C; },
    get catchBait() { return C ? C.baitId : ''; },
    get time() { return T; },
    frames: () => frames, light,
  };
}
