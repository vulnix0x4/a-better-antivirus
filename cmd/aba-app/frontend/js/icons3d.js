// The icon family: small 3D objects (steel, glass, a glowing accent), drawn
// by one offscreen three.js renderer into ordinary 2D canvases. Every object
// is centred and scaled to the same optical size, so each sits inside its
// plate with the same margin.
import * as THREE from 'three';
import { RoomEnvironment } from 'three/addons/environments/RoomEnvironment.js';
import { RoundedBoxGeometry } from 'three/addons/geometries/RoundedBoxGeometry.js';
import { SVGLoader } from 'three/addons/loaders/SVGLoader.js';
import { glyphSource } from './glyphs.js';

const V3 = THREE.Vector3, Y = new V3(0, 1, 0);
const mesh = (g, m, p, r, s) => { const o = new THREE.Mesh(g, m); if (p) o.position.set(...p); if (r) o.rotation.set(...r); if (s) o.scale.set(...(Array.isArray(s) ? s : [s, s, s])); return o; };

// The caught program: a virus particle. Also used, bigger, in the scene.
export function buildVirus(s = 1, glowK = 2.4, detail = 3) {
  const g = new THREE.Group();
  g.add(new THREE.Mesh(new THREE.IcosahedronGeometry(.3 * s, detail), new THREE.MeshStandardMaterial({ color: 0x3a0c0c, roughness: .28, metalness: .25, emissive: 0x7a1006, emissiveIntensity: 1.3 })));
  const tipM = new THREE.MeshBasicMaterial({ color: new THREE.Color(0xff4530).multiplyScalar(glowK) });
  const stM = new THREE.MeshStandardMaterial({ color: 0x8a1a0c, roughness: .4, emissive: 0x6a0e06 });
  const stG = new THREE.CylinderGeometry(.017 * s, .034 * s, .2 * s, 6), tipG = new THREE.SphereGeometry(.058 * s, 12, 10);
  const N = 24, sp = [];
  for (let i = 0; i < N; i++) {
    const y = 1 - (i + .5) / N * 2, r = Math.sqrt(1 - y * y), a = i * 2.39996, d = new V3(Math.cos(a) * r, y, Math.sin(a) * r);
    const sg = new THREE.Group(); sg.add(mesh(stG, stM, [0, .1 * s, 0]), mesh(tipG, tipM, [0, .225 * s, 0]));
    sg.position.copy(d).multiplyScalar(.27 * s); sg.quaternion.setFromUnitVectors(Y, d); g.add(sg); sp.push(sg);
  }
  g.userData.spikes = sp; return g;
}

const RES = 224;
// How much of the plate an object fills (the camera sees 2.53 units): 66%,
// which leaves room for the slow turn of the moving ones.
const FIT = 1.66;

export function makeIcons() {
  const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, preserveDrawingBuffer: true });
  renderer.setPixelRatio(1); renderer.setSize(RES, RES, false); renderer.setClearColor(0, 0);
  renderer.toneMapping = THREE.ACESFilmicToneMapping; renderer.toneMappingExposure = .95;
  const scene = new THREE.Scene(); scene.environment = new THREE.PMREMGenerator(renderer).fromScene(new RoomEnvironment(), .04).texture; scene.environmentIntensity = .55;
  const cam = new THREE.PerspectiveCamera(24, 1, .1, 50); cam.position.set(0, 0, 5.95);
  const key = new THREE.DirectionalLight(0xffffff, 1.7); key.position.set(-2.5, 3.5, 4); scene.add(key);
  const rim = new THREE.PointLight(0xffffff, 26, 12); rim.position.set(2.6, -1.2, -1.6); scene.add(rim);
  const under = new THREE.PointLight(0xffffff, 8, 10); under.position.set(0, -2.4, 2); scene.add(under);
  const loader = new SVGLoader(); const cache = new Map(), stills = new Map();
  // contact shadow: every object rests on its plate, lit from the top left
  const shTex = (() => { const c = document.createElement('canvas'); c.width = c.height = 128; const x = c.getContext('2d'); const g = x.createRadialGradient(64, 64, 0, 64, 64, 64); g.addColorStop(0, 'rgba(0,0,0,.85)'); g.addColorStop(.55, 'rgba(0,0,0,.35)'); g.addColorStop(1, 'rgba(0,0,0,0)'); x.fillStyle = g; x.fillRect(0, 0, 128, 128); return new THREE.CanvasTexture(c); })();
  const shadow = new THREE.Sprite(new THREE.SpriteMaterial({ map: shTex, transparent: true, depthWrite: false, depthTest: false, opacity: .8 })); shadow.scale.set(2.0, .5, 1); shadow.position.set(.1, -1.0, -.6); shadow.renderOrder = -1; scene.add(shadow);

  const mats = c => {
    const C0 = new THREE.Color(c), C = C0.clone().offsetHSL(0, .2, -.16), dk = C.clone().multiplyScalar(.28), lt = C0.clone().lerp(new THREE.Color(0xffffff), .35);
    const P = (color, o = {}) => new THREE.MeshPhysicalMaterial({ color, roughness: .2, metalness: 0, clearcoat: 1, clearcoatRoughness: .06, ...o });
    return {
      C, rod: P(C, { emissive: C, emissiveIntensity: .75, clearcoat: .6, envMapIntensity: .25, roughness: .3 }), glass: P(C, { emissive: C, emissiveIntensity: .38 }), light: P(lt, { emissive: C, emissiveIntensity: .12 }), deep: P(dk, { roughness: .3 }),
      steel: P(0xe6eef2, { metalness: 1, roughness: .16 }), dark: P(0x161b18, { roughness: .3, metalness: .5 }), paper: P(0xf2f6f3, { roughness: .5, clearcoat: .3 }),
      glow: new THREE.MeshBasicMaterial({ color: C.clone().lerp(new THREE.Color(0xffffff), .25).multiplyScalar(1.9) }), flat: P(C, { flatShading: true, emissive: C, emissiveIntensity: .35, roughness: .1 }),
      faint: P(dk, { emissive: C, emissiveIntensity: .1, roughness: .45, clearcoat: .2, transparent: true, opacity: .55 }),
      bright: P(lt, { emissive: C, emissiveIntensity: .7, roughness: .1 }),
    };
  };
  const rb = (w, h, d, r, m, p, rot) => mesh(new RoundedBoxGeometry(w, h, d, 4, r), m, p, rot);
  const tubeOf = (pts, r, m, closed = false, tension = .5) => new THREE.Mesh(new THREE.TubeGeometry(new THREE.CatmullRomCurve3(pts.map(p => new V3(...p)), closed, 'catmullrom', tension), Math.max(24, pts.length * 10), r, 12, closed), m);
  const ball = (r, m, p) => mesh(new THREE.SphereGeometry(r, 20, 14), m, p);

  function generic(name, m, r = .092) { // bend each stroke of the line glyph into a glossy rod
    const g = new THREE.Group(); const data = loader.parse(glyphSource(name));
    const sG = new THREE.SphereGeometry(r, 14, 10);
    for (const p of data.paths) for (const sp of p.subPaths) {
      const pts = sp.getPoints(8).map(q => new V3((q.x - 12) / 10.5, -(q.y - 12) / 10.5, 0)).filter((q, i, a) => !i || q.distanceTo(a[i - 1]) > 1e-3);
      if (pts.length < 2) continue; const closed = pts[0].distanceTo(pts[pts.length - 1]) < .02 && pts.length > 2; if (closed) pts.pop();
      const tiny = new THREE.Box3().setFromPoints(pts).getSize(new V3()).length() < .3;
      if (tiny) { const c = new THREE.Box3().setFromPoints(pts).getCenter(new V3()); g.add(mesh(new THREE.SphereGeometry(.13, 16, 12), m, [c.x, c.y, .02])); continue; }
      g.add(new THREE.Mesh(new THREE.TubeGeometry(new THREE.CatmullRomCurve3(pts, closed, 'catmullrom', 0), pts.length * 6, r, 10, closed), m));
      pts.forEach((q, i) => { const a = pts[i - 1] || (closed ? pts[pts.length - 1] : null), b = pts[i + 1] || (closed ? pts[0] : null); if (!a || !b || q.clone().sub(a).normalize().dot(b.clone().sub(q).normalize()) < .9) g.add(mesh(sG, m, [q.x, q.y, 0])); });
    }
    return g;
  }

  const shieldShape = k => { const s = new THREE.Shape(); s.moveTo(0, .9 * k); s.lineTo(.72 * k, .62 * k); s.lineTo(.72 * k, .05 * k); s.bezierCurveTo(.72 * k, -.42 * k, .38 * k, -.76 * k, 0, -.92 * k); s.bezierCurveTo(-.38 * k, -.76 * k, -.72 * k, -.42 * k, -.72 * k, .05 * k); s.lineTo(-.72 * k, .62 * k); s.closePath(); return s; };
  const shieldRim = (k, r, m) => tubeOf([[0, .9], [.72, .62], [.72, .05], [.6, -.42], [.3, -.76], [0, -.92], [-.3, -.76], [-.6, -.42], [-.72, .05], [-.72, .62]].map(([x, y]) => [x * k, y * k, 0]), r, m, true, .15);

  const custom = {
    hook(m) {
      const g = new THREE.Group(); g.add(tubeOf([[.32, .62, 0], [.32, .1, 0], [.27, -.42, 0], [-.05, -.74, 0], [-.48, -.56, 0], [-.6, -.08, 0]], .085, m.steel));
      g.add(mesh(new THREE.TorusGeometry(.15, .055, 12, 32), m.steel, [.32, .78, 0])); g.add(mesh(new THREE.ConeGeometry(.1, .3, 12), m.steel, [-.6, .08, 0]));
      g.add(mesh(new THREE.ConeGeometry(.07, .26, 10), m.steel, [-.47, -.12, 0], [0, 0, -2.3]));
      g.add(mesh(new THREE.OctahedronGeometry(.23, 0), m.flat, [-.12, -.46, .12], [.3, .5, .2], [1, 1.35, 1])); g.add(ball(.07, m.glow, [-.12, -.46, .12])); return g;
    },
    clipboard(m) {
      const g = new THREE.Group(); g.add(rb(1.2, 1.5, .16, .1, m.steel, [0, -.08, 0])); g.add(rb(.98, 1.2, .05, .04, m.dark, [0, -.14, .1]));
      g.add(rb(.56, .24, .2, .07, m.steel, [0, .66, .12])); g.add(mesh(new THREE.TorusGeometry(.12, .045, 10, 24), m.steel, [0, .8, .12]));
      [[.26, .68], [-.02, .68], [-.3, .4]].forEach(([y, w]) => g.add(rb(w, .1, .05, .04, m.glow, [-(.68 - w) / 2, y - .14, .14]))); g.add(mesh(new THREE.OctahedronGeometry(.13, 0), m.flat, [.26, -.44, .2], [.3, .5, .2])); return g;
    },
    pick(m) {
      const g = new THREE.Group(); const h = new THREE.Group(); h.add(mesh(new THREE.CylinderGeometry(.09, .105, 1.6, 14), m.dark, [0, .08, 0])); h.add(mesh(new THREE.CylinderGeometry(.13, .13, .2, 14), m.steel, [0, .8, 0]));
      h.add(tubeOf([[-.78, .44, 0], [-.42, .76, 0], [0, .86, 0], [.42, .76, 0], [.78, .44, 0]], .12, m.steel));
      h.add(mesh(new THREE.ConeGeometry(.12, .34, 12), m.steel, [-.88, .31, 0], [0, 0, 2.5])); h.add(mesh(new THREE.ConeGeometry(.12, .34, 12), m.steel, [.88, .31, 0], [0, 0, -2.5]));
      h.rotation.z = -.62; h.position.set(-.12, -.02, 0); g.add(h);
      g.add(mesh(new THREE.IcosahedronGeometry(.3, 0), m.flat, [.5, -.42, .1], [.4, .3, .1])); return g;
    },
    snow(m) {
      const g = new THREE.Group(); g.add(mesh(new THREE.CylinderGeometry(.17, .17, .16, 6), m.light, null, [Math.PI / 2, 0, 0]));
      for (let i = 0; i < 6; i++) { const a = new THREE.Group(); a.add(rb(.12, .9, .12, .05, m.glass, [0, .48, 0])); a.add(rb(.1, .34, .1, .04, m.glass, [.13, .6, 0], [0, 0, -.9])); a.add(rb(.1, .34, .1, .04, m.glass, [-.13, .6, 0], [0, 0, .9])); a.add(mesh(new THREE.OctahedronGeometry(.085, 0), m.light, [0, .96, 0])); a.rotation.z = i * Math.PI / 3; g.add(a); }
      return g;
    },
    virus() { const g = new THREE.Group(); const v = buildVirus(2.0, 1.5); g.add(v); g.userData.spikes = v.userData.spikes; return g; },
    wallet(m) {
      const g = new THREE.Group(); g.add(rb(1.5, 1.08, .4, .16, m.glass, [0, -.06, 0])); g.add(rb(1.3, .2, .3, .06, m.paper, [-.02, .5, -.02])); g.add(rb(1.5, .3, .44, .12, m.deep, [0, .28, 0]));
      g.add(rb(.56, .4, .46, .14, m.light, [.5, -.1, .02])); g.add(mesh(new THREE.CylinderGeometry(.09, .09, .5, 20), m.glow, [.52, -.1, .02], [Math.PI / 2, 0, 0])); return g;
    },
    vault(m) {
      const g = new THREE.Group(); g.add(rb(1.5, 1.3, .5, .14, m.steel)); g.add(rb(1.24, 1.04, .08, .08, m.dark, [0, 0, .24]));
      g.add(mesh(new THREE.TorusGeometry(.3, .07, 12, 36), m.glass, [0, 0, .32])); g.add(ball(.1, m.glow, [0, 0, .34]));
      for (let i = 0; i < 4; i++) g.add(rb(.07, .3, .07, .03, m.glass, [Math.cos(i * 1.5708) * .3, Math.sin(i * 1.5708) * .3, .32], [0, 0, i * 1.5708]));
      g.add(rb(.2, .16, .3, .05, m.dark, [-.5, -.72, 0])); g.add(rb(.2, .16, .3, .05, m.dark, [.5, -.72, 0])); return g;
    },
    key(m) {
      const g = new THREE.Group(), k = new THREE.Group(); k.add(mesh(new THREE.TorusGeometry(.3, .105, 14, 36), m.glass, [0, .52, 0])); k.add(mesh(new THREE.CylinderGeometry(.085, .085, 1.15, 14), m.glass, [0, -.3, 0]));
      k.add(rb(.3, .13, .13, .04, m.glass, [.17, -.62, 0])); k.add(rb(.22, .13, .13, .04, m.glass, [.13, -.36, 0])); k.add(ball(.09, m.glow, [0, .52, 0])); k.rotation.z = -.75; g.add(k); return g;
    },
    globe(m) { const g = new THREE.Group(); g.add(ball(.72, m.glass)); const t = new THREE.TorusGeometry(.74, .045, 8, 48); g.add(mesh(t, m.deep, null, [Math.PI / 2, 0, 0])); g.add(mesh(t, m.deep, null, [0, Math.PI / 2, 0])); g.add(mesh(t, m.deep, null, [0, .5, 0], [.5, 1, 1])); g.add(mesh(t, m.deep, [0, .36, 0], [Math.PI / 2, 0, 0], .87)); g.add(mesh(t, m.deep, [0, -.36, 0], [Math.PI / 2, 0, 0], .87)); return g; },
    chrome(m) { const g = new THREE.Group(); g.add(mesh(new THREE.TorusGeometry(.58, .24, 20, 48), m.glass)); g.add(ball(.32, new THREE.MeshPhysicalMaterial({ color: 0x8fd0ff, emissive: 0x4aa0e0, emissiveIntensity: .6, roughness: .15, clearcoat: 1 }), [0, 0, .06])); for (let i = 0; i < 3; i++) g.add(rb(.5, .07, .08, .03, m.deep, [Math.cos(i * 2.094 + .5) * .56, Math.sin(i * 2.094 + .5) * .56, .23], [0, 0, i * 2.094 + .5 + 1.2])); return g; },
    firefox(m) {
      const g = new THREE.Group(); g.add(ball(.6, m.deep));
      g.add(tubeOf([[-.5, .5, .2], [-.74, .05, .25], [-.5, -.52, .3], [0, -.74, .32], [.52, -.5, .3], [.74, .02, .25], [.5, .5, .2], [.18, .34, .5]], .15, m.glass)); g.add(mesh(new THREE.ConeGeometry(.16, .4, 12), m.glass, [-.52, .66, .2], [0, 0, .35]));
      g.add(ball(.12, m.glow, [.2, .3, .56])); return g;
    },
    telegram(m) {
      const P = { n: [.95, .62, 0], l: [-.95, .12, 0], m: [-.22, -.1, .22], b: [.1, -.82, -.05], c: [-.2, -.52, .12] };
      const tri = (a, b, c, mat) => { const ge = new THREE.BufferGeometry(); ge.setAttribute('position', new THREE.Float32BufferAttribute([...a, ...b, ...c], 3)); ge.computeVertexNormals(); mat = mat.clone(); mat.side = THREE.DoubleSide; mat.flatShading = true; return new THREE.Mesh(ge, mat); };
      const g = new THREE.Group(); g.add(tri(P.n, P.l, P.m, m.light), tri(P.n, P.m, P.b, m.glass), tri(P.m, P.c, P.b, m.deep), tri(P.n, P.m, P.c, m.glass)); return g;
    },
    doc(m) { const g = new THREE.Group(); g.add(rb(1.12, 1.5, .12, .08, m.light)); g.add(rb(.36, .36, .14, .05, m.glass, [.38, .57, .03])); [[.1, .66], [-.16, .66], [-.42, .4]].forEach(([y, w]) => g.add(rb(w, .1, .05, .03, m.deep, [-(.7 - w) / 2 - .02, y, .08]))); return g; },
    zip(m) { const g = new THREE.Group(); g.add(rb(1.12, 1.5, .16, .08, m.light)); for (let i = 0; i < 5; i++) g.add(rb(.16, .1, .06, .02, i % 2 ? m.deep : m.dark, [i % 2 ? .07 : -.07, .56 - i * .19, .1])); g.add(rb(.26, .3, .1, .05, m.steel, [0, -.5, .1])); g.add(ball(.05, m.glow, [0, -.5, .17])); return g; },
    server(m) {
      const g = new THREE.Group();
      [.48, -.48].forEach(y => { g.add(rb(1.6, .7, .7, .1, m.steel, [0, y, 0])); g.add(rb(1.36, .46, .06, .05, m.dark, [0, y, .34])); g.add(ball(.07, m.glow, [-.5, y, .38])); g.add(rb(.5, .06, .05, .02, m.glass, [.26, y + .08, .38])); g.add(rb(.5, .06, .05, .02, m.glass, [.26, y - .08, .38])); });
      return g;
    },
    git(m) {
      const g = new THREE.Group(); const n = [[-.5, .62, 0], [-.5, -.62, 0], [.5, .26, 0]];
      g.add(mesh(new THREE.CylinderGeometry(.07, .07, 1.24, 12), m.steel, [-.5, 0, 0])); g.add(tubeOf([[.5, .26, 0], [.46, -.1, 0], [.1, -.3, 0], [-.5, -.5, 0]], .07, m.steel));
      n.forEach((p, i) => g.add(ball(.2, i === 2 ? m.glass : m.light, p))); g.add(ball(.08, m.glow, [.5, .26, .16])); return g;
    },
    // The knob's shield: thin and unlit when ABA only tells you, solid when
    // it freezes, armoured with a bright rim and core when it takes the PC offline.
    shield(m, level = 1) {
      const g = new THREE.Group();
      if (level <= 0) { g.add(shieldRim(.82, .05, m.faint)); g.add(mesh(new THREE.ExtrudeGeometry(shieldShape(.74), { depth: .03, bevelEnabled: false }), m.faint, [0, 0, -.03])); g.add(mesh(new THREE.BoxGeometry(1.7, 1.9, .01), new THREE.MeshBasicMaterial({ visible: false }))); return g; }
      const ex = { depth: level >= 2 ? .2 : .12, bevelEnabled: true, bevelSize: .06, bevelThickness: .07, bevelSegments: 4 };
      if (level >= 2) {
        g.add(mesh(new THREE.ExtrudeGeometry(shieldShape(1), { ...ex, depth: .1 }), m.steel, [0, 0, -.22])); g.add(mesh(new THREE.ExtrudeGeometry(shieldShape(.8), ex), m.bright, [0, 0, -.06]));
        g.add(shieldRim(1.02, .06, m.glow)); g.add(ball(.17, m.glow, [0, .05, .24])); g.add(rb(.1, .62, .06, .03, m.glow, [0, .05, .22])); g.add(rb(.5, .1, .06, .03, m.glow, [0, .14, .22]));
      } else {
        g.add(mesh(new THREE.ExtrudeGeometry(shieldShape(.9), ex), m.glass, [0, 0, -.1])); g.add(ball(.12, m.glow, [0, .05, .12]));
        g.add(mesh(new THREE.BoxGeometry(1.9, 2.0, .01), new THREE.MeshBasicMaterial({ visible: false })));
      }
      return g;
    },
    bell(m) {
      const pts = [[0, .72], [.16, .7], [.3, .5], [.42, .05], [.5, -.3], [.7, -.5], [.7, -.58], [0, -.58]].map(p => new THREE.Vector2(...p));
      const g = new THREE.Group(); g.add(mesh(new THREE.LatheGeometry(pts, 32), m.glass)); g.add(ball(.15, m.glow, [0, -.68, 0])); g.add(mesh(new THREE.TorusGeometry(.1, .04, 8, 20), m.light, [0, .8, 0])); return g;
    },
    cloud(m) { const g = new THREE.Group(); [[-.42, -.18, .36], [.02, .06, .5], [.46, -.14, .4], [-.05, -.26, .4]].forEach(([x, y, r]) => g.add(ball(r, m.light, [x, y, 0]))); g.add(rb(1.0, .3, .5, .14, m.light, [0, -.42, 0])); g.add(mesh(new THREE.TorusGeometry(.2, .06, 10, 24), m.glow, [.02, -.2, .46])); return g; },
    phone(m) { const g = new THREE.Group(); g.add(rb(.9, 1.66, .14, .14, m.dark)); g.add(rb(.76, 1.48, .04, .09, m.glass, [0, 0, .07])); g.add(rb(.24, .06, .05, .03, m.dark, [0, .6, .1])); return g; },
    cookie(m) { const g = new THREE.Group(); g.add(mesh(new THREE.CylinderGeometry(.78, .78, .2, 40), m.glass, null, [Math.PI / 2, 0, 0])); g.add(mesh(new THREE.TorusGeometry(.78, .1, 12, 48), m.glass)); [[-.3, .28], [.3, .3], [.02, -.08], [-.36, -.3], [.36, -.34]].forEach(([x, y], i) => g.add(ball(.105, i === 2 ? m.glow : m.deep, [x, y, .12]))); return g; },
    tape(m) {
      const g = new THREE.Group(); g.add(rb(1.7, 1.1, .3, .12, m.steel)); g.add(rb(1.44, .62, .06, .08, m.dark, [0, .08, .15]));
      [-.38, .38].forEach(x => { g.add(mesh(new THREE.TorusGeometry(.2, .07, 12, 28), m.glass, [x, .08, .2])); g.add(ball(.07, m.glow, [x, .08, .22])); });
      g.add(rb(.8, .12, .06, .03, m.dark, [0, -.4, .15])); return g;
    },
    lock(m) { const g = new THREE.Group(); g.add(rb(1.2, .96, .4, .14, m.steel, [0, -.3, 0])); g.add(mesh(new THREE.TorusGeometry(.36, .09, 14, 32, Math.PI), m.steel, [0, .2, 0])); g.add(mesh(new THREE.CylinderGeometry(.09, .09, .3, 12), m.steel, [-.36, .1, 0])); g.add(mesh(new THREE.CylinderGeometry(.09, .09, .3, 12), m.steel, [.36, .1, 0])); g.add(ball(.12, m.glow, [0, -.26, .2])); g.add(rb(.08, .24, .06, .03, m.glow, [0, -.42, .2])); return g; },
  };

  const BASE = [.14, -.36, 0];
  function build(name, color, level) { // every object: centred, same optical size, same pose
    const m = mats(color); const g = custom[name] ? custom[name](m, level) : generic(name, m.rod);
    const o = new THREE.Group(); o.add(g); o.rotation.set(...BASE); o.updateMatrixWorld(true);
    const box = new THREE.Box3().setFromObject(o), size = box.getSize(new V3()), c = box.getCenter(new V3());
    const k = FIT / Math.max(size.x, size.y, .001); const w = new THREE.Group(); w.add(o); o.position.set(-c.x * k, -c.y * k + .04, -c.z * k); o.scale.setScalar(k);
    w.userData.o = o; w.userData.spikes = g.userData.spikes; w.userData.sh = Math.min(1, size.x * k / FIT); return w;
  }
  const C = new THREE.Color(), W = new THREE.Color(0xffffff);
  function render(name, color, level, t, live) {
    const k = name + '|' + color + '|' + level; let g = cache.get(k); if (!g) { g = build(name, color, level); cache.set(k, g); }
    scene.add(g); g.userData.o.rotation.set(BASE[0] + (live ? Math.sin(t * .8) * .04 : 0), BASE[1] + (live ? Math.sin(t * .6) * .16 : 0), 0); shadow.scale.x = 1.5 + .5 * g.userData.sh;
    if (g.userData.spikes) g.userData.spikes.forEach((s, i) => { s.scale.y = 1 + Math.sin(t * 3 + i * 1.7) * .22; });
    C.set(color); rim.color.copy(C); under.color.copy(C).lerp(W, .5);
    renderer.render(scene, cam); scene.remove(g);
  }
  return {
    res: RES,
    has: name => !!custom[name],
    // Draw icon `name` into canvas cv. A still icon is rendered once and
    // copied from then on; a live one turns slowly.
    draw(cv, name, color, { t = 0, live = false, level = 1 } = {}) {
      const x = cv.getContext('2d');
      if (!live) {
        const k = name + '|' + color + '|' + level; let still = stills.get(k);
        if (!still) { render(name, color, level, 0, false); still = document.createElement('canvas'); still.width = still.height = RES; still.getContext('2d').drawImage(renderer.domElement, 0, 0); stills.set(k, still); }
        x.clearRect(0, 0, cv.width, cv.height); x.drawImage(still, 0, 0, cv.width, cv.height); return;
      }
      render(name, color, level, t, true); x.clearRect(0, 0, cv.width, cv.height); x.drawImage(renderer.domElement, 0, 0, cv.width, cv.height);
    },
  };
}
