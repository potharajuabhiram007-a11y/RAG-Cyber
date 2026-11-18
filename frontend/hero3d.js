/* CyberIntelliX hero - a real-time 3D cybersecurity scene in Three.js (no other library).
 *
 * Separate animation groups, as specified:
 *   shieldSpin   - the glass shield turns a full 360 degrees around its Y axis, forever
 *   shieldFloat  - it floats gently up and down
 *   orbit        - six entities travel round the shield on an elliptical orbit
 *   entity spin  - every entity's 3D icon also turns around its own axis
 *   particles    - glowing particles run along several elliptical rings
 *   network      - a living knowledge graph behind the shield: pulsing nodes, outward light
 *                  waves and pulses travelling along the links
 *   bursts       - every few seconds an energy ring leaves the shield and ripples the floor
 *   scene tilt   - the whole scene leans a little towards the mouse (parallax)
 *
 * Real geometry and materials throughout: an extruded glass shield with a clear-coat
 * finish and environment reflections, a polished metal frame, glowing edges, circuit
 * traces and a band of blue energy flowing across both faces; entities are modelled
 * (stacked layers, warning triangle, mini shield, wireframe brain, gear, database).
 * Glow is layered additive light rather than a post-processing bloom pass, which keeps
 * the canvas transparent over the page and cheap on phones.
 */
import * as THREE from "three";
import { RoomEnvironment } from "three/addons/environments/RoomEnvironment.js";

const host = document.querySelector(".hx");
const reduce = window.matchMedia("(prefers-reduced-motion: reduce)");
const isDark = () => document.documentElement.getAttribute("data-theme") === "dark";
const small = () => window.innerWidth < 760 || window.matchMedia("(pointer: coarse)").matches;

const ENTITIES = [                               // spin: seconds per turn on the entity's own axis
  { key: "CVE",    text: "CVE",                 tone: 0xef4444, model: "shield",   spin: 6 },
  { key: "CWE",    text: "CWE",                 tone: 0xf59e0b, model: "gear",     spin: 9 },
  { key: "CAPEC",  text: "CAPEC",               tone: 0x8b5cf6, model: "layers",   spin: 7 },
  { key: "ATTACK", text: "ATT&CK",              tone: 0x22d3ee, model: "triangle", spin: 11 },
  { key: "AI",     text: "AI",                  tone: 0xc026d3, model: "brain",    spin: 5 },
  { key: "RAG",    text: "RAG",                 tone: 0x3b82f6, model: "database", spin: 8 },
  { key: "INTEL",  text: "Threat Intelligence", tone: 0x38bdf8, model: "globe",    spin: 12 },
];
const SHOW_ORBIT = false;                        // orbiting labels and rings (off: the reference has none)
const ORBIT = { radius: 3.6, tilt: 1.18, roll: -0.04, speed: 0.17 };
const RINGS = [                                   // wide rings crossing at different angles
  { radius: 3.6,  tilt: 1.18, roll: -0.04, speed: 0.30,  color: 0x60a5fa, opacity: 0.6 },
  { radius: 3.25, tilt: 1.36, roll: 0.24,  speed: -0.42, color: 0x38bdf8, opacity: 0.42 },
  { radius: 3.95, tilt: 1.10, roll: -0.30, speed: 0.22,  color: 0x93c5fd, opacity: 0.3 },
  { radius: 3.0,  tilt: 1.44, roll: -0.16, speed: -0.3,  color: 0x3b82f6, opacity: 0.35 },
];

function supportsWebGL() {
  try {
    const c = document.createElement("canvas");
    return !!(window.WebGLRenderingContext && (c.getContext("webgl2") || c.getContext("webgl")));
  } catch (error) { return false; }
}
const css = (hex) => `#${hex.toString(16).padStart(6, "0")}`;
const rgba = (hex, a) => `rgba(${(hex >> 16) & 255},${(hex >> 8) & 255},${hex & 255},${a})`;

/* ------------------------------------------------------------------ */
/* textures drawn once in canvases                                     */
/* ------------------------------------------------------------------ */
function glowDot() {
  const c = document.createElement("canvas"); c.width = c.height = 64;
  const g = c.getContext("2d"), r = g.createRadialGradient(32, 32, 0, 32, 32, 32);
  r.addColorStop(0, "rgba(255,255,255,1)"); r.addColorStop(0.3, "rgba(255,255,255,0.75)"); r.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = r; g.fillRect(0, 0, 64, 64);
  return new THREE.CanvasTexture(c);
}

/* the faceted face: lighter glass on the left half, deep blue on the right, a bright
   ridge between them and faint network lines across both */
function faceTexture() {
  const c = document.createElement("canvas"); c.width = 512; c.height = 700;
  const g = c.getContext("2d");
  const left = g.createLinearGradient(0, 0, 256, 700);
  left.addColorStop(0, "rgba(191,219,254,0.62)"); left.addColorStop(1, "rgba(59,130,246,0.38)");
  g.fillStyle = left; g.fillRect(0, 0, 256, 700);
  const right = g.createLinearGradient(256, 0, 512, 700);
  right.addColorStop(0, "rgba(37,99,235,0.6)"); right.addColorStop(1, "rgba(8,20,60,0.72)");
  g.fillStyle = right; g.fillRect(256, 0, 256, 700);
  const ridge = g.createLinearGradient(240, 0, 272, 0);
  ridge.addColorStop(0, "rgba(255,255,255,0)"); ridge.addColorStop(0.5, "rgba(224,242,254,0.95)"); ridge.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = ridge; g.fillRect(240, 0, 32, 700);
  // faint network lines and nodes
  const nodes = [[120, 180], [200, 260], [330, 210], [400, 320], [150, 400], [300, 430], [220, 520], [360, 520], [256, 350]];
  g.strokeStyle = "rgba(219,234,254,0.35)"; g.lineWidth = 1.6;
  for (let i = 0; i < nodes.length; i += 1) for (let j = i + 1; j < nodes.length; j += 1) {
    const [a, b] = [nodes[i], nodes[j]];
    if (Math.hypot(a[0] - b[0], a[1] - b[1]) < 190) { g.beginPath(); g.moveTo(...a); g.lineTo(...b); g.stroke(); }
  }
  g.fillStyle = "rgba(224,242,254,0.9)";
  for (const [x, y] of nodes) { g.beginPath(); g.arc(x, y, 4, 0, Math.PI * 2); g.fill(); }
  const tex = new THREE.CanvasTexture(c); tex.colorSpace = THREE.SRGBColorSpace;
  return tex;
}

function circuitTexture() {
  const c = document.createElement("canvas"); c.width = 512; c.height = 700;
  const g = c.getContext("2d"); g.lineCap = "round"; g.lineJoin = "round";
  const traces = [
    [[256, 90], [256, 160], [338, 160], [338, 230], [404, 230]], [[256, 90], [256, 160], [174, 160], [174, 230], [108, 230]],
    [[256, 250], [306, 300], [306, 382], [392, 382]], [[256, 250], [206, 300], [206, 382], [120, 382]],
    [[256, 410], [326, 470], [326, 530]], [[256, 410], [186, 470], [186, 530]], [[256, 540], [256, 610]],
    [[338, 230], [338, 300]], [[174, 230], [174, 300]], [[404, 230], [430, 262], [430, 330]], [[108, 230], [82, 262], [82, 330]],
    [[256, 160], [256, 250], [256, 410], [256, 540]],
  ];
  for (const [w, a] of [[8, 0.16], [2.4, 0.95]]) {
    g.lineWidth = w; g.strokeStyle = `rgba(147,197,253,${a})`;
    for (const t of traces) { g.beginPath(); g.moveTo(...t[0]); t.slice(1).forEach((p) => g.lineTo(...p)); g.stroke(); }
  }
  g.fillStyle = "#DBEAFE";
  for (const t of traces) for (const p of [t[0], t[t.length - 1]]) { g.beginPath(); g.arc(p[0], p[1], 5, 0, Math.PI * 2); g.fill(); }
  const tex = new THREE.CanvasTexture(c); tex.colorSpace = THREE.SRGBColorSpace;
  return tex;
}

/* a soft band of light, repeated vertically; scrolled to look like energy flowing */
function energyTexture() {
  const c = document.createElement("canvas"); c.width = 8; c.height = 256;
  const g = c.getContext("2d"), grad = g.createLinearGradient(0, 0, 0, 256);
  grad.addColorStop(0, "rgba(96,165,250,0)"); grad.addColorStop(0.45, "rgba(96,165,250,0)");
  grad.addColorStop(0.5, "rgba(186,230,253,0.9)"); grad.addColorStop(0.56, "rgba(96,165,250,0.15)"); grad.addColorStop(1, "rgba(96,165,250,0)");
  g.fillStyle = grad; g.fillRect(0, 0, 8, 256);
  const tex = new THREE.CanvasTexture(c); tex.wrapS = tex.wrapT = THREE.RepeatWrapping; tex.repeat.set(1, 1.4);
  return tex;
}

/* glass pill with the entity name; the left part is left free for the 3D icon */
function pillCanvas(entity, hot) {
  const dark = isDark(), k = 3;
  const font = `600 ${18 * k}px "Inter", "Space Grotesk", system-ui, sans-serif`;
  const meas = document.createElement("canvas").getContext("2d"); meas.font = font;
  const h = 54 * k, iconSlot = 50 * k, padR = 24 * k, m = 18 * k;
  const w = Math.ceil(iconSlot + meas.measureText(entity.text).width + padR);
  const c = document.createElement("canvas"); c.width = w + m * 2; c.height = h + m * 2;
  const g = c.getContext("2d");
  const pill = new Path2D(); pill.roundRect(m, m, w, h, h / 2);
  g.shadowColor = dark ? rgba(entity.tone, hot ? 0.95 : 0.7) : rgba(entity.tone, hot ? 0.45 : 0.24);
  g.shadowBlur = (hot ? 28 : 18) * k;
  const fill = g.createLinearGradient(0, m, 0, m + h);
  if (dark) { fill.addColorStop(0, rgba(entity.tone, 0.42)); fill.addColorStop(1, "rgba(4,9,24,0.86)"); }
  else { fill.addColorStop(0, "rgba(255,255,255,0.97)"); fill.addColorStop(1, "rgba(230,239,255,0.94)"); }
  g.fillStyle = fill; g.fill(pill); g.shadowBlur = 0;
  const rim = g.createLinearGradient(m, m, m + w, m + h);
  rim.addColorStop(0, "#E0F2FE"); rim.addColorStop(0.4, rgba(entity.tone, 1)); rim.addColorStop(1, rgba(entity.tone, 0.75));
  g.lineWidth = (hot ? 3.2 : 2.2) * k; g.strokeStyle = rim; g.stroke(pill);
  g.save(); g.clip(pill);
  const shine = g.createLinearGradient(0, m, 0, m + h * 0.6);
  shine.addColorStop(0, dark ? "rgba(255,255,255,0.24)" : "rgba(255,255,255,0.95)"); shine.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = shine; g.fillRect(m, m, w, h * 0.6);
  // a soft well behind the 3D icon
  const well = g.createRadialGradient(m + iconSlot * 0.62, m + h / 2, 0, m + iconSlot * 0.62, m + h / 2, h * 0.5);
  well.addColorStop(0, rgba(entity.tone, dark ? 0.35 : 0.18)); well.addColorStop(1, rgba(entity.tone, 0));
  g.fillStyle = well; g.fillRect(m, m, iconSlot * 1.3, h);
  g.restore();
  g.font = font; g.textBaseline = "middle"; g.fillStyle = dark ? "#EEF4FF" : "#0F172A";
  g.fillText(entity.text, m + iconSlot, m + h / 2 + k);
  return { canvas: c, iconX: (m + iconSlot * 0.6) / c.width };       // icon centre, as a fraction of the width
}

/* ------------------------------------------------------------------ */
/* geometry                                                            */
/* ------------------------------------------------------------------ */
function shieldShape(scale, k = 1 / 46) {
  const s = k * scale, sh = new THREE.Shape(), p = (x, y) => [x * s, y * s];
  sh.moveTo(...p(0, 121)); sh.bezierCurveTo(...p(27, 105), ...p(62, 97), ...p(94, 97)); sh.lineTo(...p(94, 8));
  sh.bezierCurveTo(...p(94, -58), ...p(47, -105), ...p(0, -136)); sh.bezierCurveTo(...p(-47, -105), ...p(-94, -58), ...p(-94, 8));
  sh.lineTo(...p(-94, 97)); sh.bezierCurveTo(...p(-62, 97), ...p(-27, 105), ...p(0, 121));
  return sh;
}
function boxUV(geometry) {
  geometry.computeBoundingBox();
  const b = geometry.boundingBox, pos = geometry.attributes.position, uv = geometry.attributes.uv;
  for (let i = 0; i < pos.count; i += 1) uv.setXY(i, (pos.getX(i) - b.min.x) / (b.max.x - b.min.x), (pos.getY(i) - b.min.y) / (b.max.y - b.min.y));
  uv.needsUpdate = true;
  return geometry;
}
function tubeAlong(shape, radius, z) {
  const pts = shape.getSpacedPoints(180).map((p) => new THREE.Vector3(p.x, p.y, z));
  return new THREE.TubeGeometry(new THREE.CatmullRomCurve3(pts, true), 260, radius, 6, true);
}
function ringPoints(radius, n = 220) {
  return Array.from({ length: n + 1 }, (_, i) => { const a = (i / n) * Math.PI * 2; return new THREE.Vector3(Math.cos(a) * radius, Math.sin(a) * radius, 0); });
}

/* the six entity icons, modelled in 3D (each about 0.5 units across) */
function entityModel(kind, material) {
  const group = new THREE.Group();
  const add = (geometry, x = 0, y = 0, z = 0) => { const m = new THREE.Mesh(geometry, material); m.position.set(x, y, z); group.add(m); return m; };
  if (kind === "layers") {                                         // three stacked plates
    for (let i = 0; i < 3; i += 1) { const m = add(new THREE.BoxGeometry(0.34, 0.06, 0.34), 0, (i - 1) * 0.13, 0); m.rotation.y = Math.PI / 4; }
  } else if (kind === "database") {                                // stacked disks
    for (let i = 0; i < 3; i += 1) add(new THREE.CylinderGeometry(0.2, 0.2, 0.09, 28), 0, (i - 1) * 0.12, 0);
  } else if (kind === "triangle") {                                // warning triangle with a hole and a mark
    const outer = new THREE.Shape(); outer.moveTo(0, 0.27); outer.lineTo(0.27, -0.2); outer.lineTo(-0.27, -0.2); outer.closePath();
    const hole = new THREE.Path(); hole.moveTo(0, 0.14); hole.lineTo(-0.15, -0.12); hole.lineTo(0.15, -0.12); hole.closePath();
    outer.holes.push(hole);
    add(new THREE.ExtrudeGeometry(outer, { depth: 0.08, bevelEnabled: true, bevelSize: 0.012, bevelThickness: 0.012, bevelSegments: 2 }), 0, 0, -0.04);
    add(new THREE.BoxGeometry(0.035, 0.1, 0.05), 0, 0.0, 0); add(new THREE.BoxGeometry(0.035, 0.035, 0.05), 0, -0.08, 0);
  } else if (kind === "shield") {                                  // a small shield with an exclamation mark
    add(new THREE.ExtrudeGeometry(shieldShape(1, 1 / 520), { depth: 0.08, bevelEnabled: true, bevelSize: 0.015, bevelThickness: 0.015, bevelSegments: 2 }), 0, 0, -0.04);
    add(new THREE.BoxGeometry(0.035, 0.12, 0.13), 0, 0.03, 0); add(new THREE.BoxGeometry(0.035, 0.035, 0.13), 0, -0.07, 0);
  } else if (kind === "gear") {                                    // a mechanical gear
    const teeth = 10, gear = new THREE.Shape();
    for (let i = 0; i <= teeth * 4; i += 1) {
      const a = (i / (teeth * 4)) * Math.PI * 2, r = (i % 4 === 0 || i % 4 === 1) ? 0.25 : 0.19;
      const x = Math.cos(a) * r, y = Math.sin(a) * r; if (i === 0) gear.moveTo(x, y); else gear.lineTo(x, y);
    }
    const hole = new THREE.Path(); hole.absarc(0, 0, 0.08, 0, Math.PI * 2, true); gear.holes.push(hole);
    add(new THREE.ExtrudeGeometry(gear, { depth: 0.09, bevelEnabled: true, bevelSize: 0.01, bevelThickness: 0.01, bevelSegments: 1 }), 0, 0, -0.045);
  } else if (kind === "brain") {                                   // a glowing neural "brain"
    const wire = new THREE.LineSegments(new THREE.WireframeGeometry(new THREE.IcosahedronGeometry(0.23, 1)),
      new THREE.LineBasicMaterial({ color: 0xf0abfc, transparent: true, opacity: 0.9 }));
    group.add(wire);
    add(new THREE.IcosahedronGeometry(0.15, 1));
  } else if (kind === "globe") {                                   // a wireframe globe with an orbit ring
    group.add(new THREE.LineSegments(new THREE.WireframeGeometry(new THREE.SphereGeometry(0.22, 10, 7)),
      new THREE.LineBasicMaterial({ color: 0xa5f3fc, transparent: true, opacity: 0.85 })));
    add(new THREE.SphereGeometry(0.13, 20, 14));
    add(new THREE.TorusGeometry(0.29, 0.016, 8, 48)).rotation.x = 1.2;
  }
  return group;
}

function seeded(seed) {                                         // the same network on every load
  return () => {
    seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function raysTexture() {                                         // soft light rays radiating from the centre
  const c = document.createElement("canvas"); c.width = c.height = 512;
  const g = c.getContext("2d"); g.translate(256, 256);
  for (let i = 0; i < 90; i += 1) {
    const a = (i / 90) * Math.PI * 2 + Math.sin(i * 12.9) * 0.03, len = 140 + Math.abs(Math.sin(i * 7.3)) * 110;
    const gr = g.createLinearGradient(0, 0, Math.cos(a) * len, Math.sin(a) * len);
    gr.addColorStop(0, "rgba(255,255,255,0.5)"); gr.addColorStop(1, "rgba(255,255,255,0)");
    g.strokeStyle = gr; g.lineWidth = 1 + Math.abs(Math.sin(i * 3.1)) * 2.5;
    g.beginPath(); g.moveTo(0, 0); g.lineTo(Math.cos(a) * len, Math.sin(a) * len); g.stroke();
  }
  return new THREE.CanvasTexture(c);
}
function sweepTexture() {                                        // a diagonal band of light that crosses the glass
  const c = document.createElement("canvas"); c.width = 256; c.height = 4;
  const g = c.getContext("2d"), gr = g.createLinearGradient(0, 0, 256, 0);
  gr.addColorStop(0, "rgba(255,255,255,0)"); gr.addColorStop(0.43, "rgba(255,255,255,0)");
  gr.addColorStop(0.5, "rgba(255,255,255,0.9)"); gr.addColorStop(0.57, "rgba(255,255,255,0)"); gr.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = gr; g.fillRect(0, 0, 256, 4);
  const t = new THREE.CanvasTexture(c); t.wrapS = t.wrapT = THREE.ClampToEdgeWrapping; t.center.set(0.5, 0.5); t.rotation = 0.45;
  return t;
}

/* The living knowledge graph: two wings of nodes and links spreading out behind the shield.
 * Nodes pulse (about 3 s), waves of light run outward from the shield, nodes flash now and
 * then, and bright pulses travel node to node along the links. Colours are written into small
 * vertex-colour buffers each frame: one draw call for the links, two for the nodes, one for
 * the pulses. */
function buildNetwork(lite, dot, glow) {
  const rand = seeded(11), N = lite ? 90 : 190, nodes = [];
  while (nodes.length < N) {
    const side = rand() < 0.5 ? -1 : 1, d = Math.pow(rand(), 0.9);
    const x = side * (1.25 + d * 5.3);
    nodes.push({ p: new THREE.Vector3(x, 0.25 + (rand() * 2 - 1) * (1.45 - d * 0.55), -0.25 - rand() * 1.1),
      phase: rand() * 6.28, big: rand() < 0.14, k: 0, fade: 1 - THREE.MathUtils.smoothstep(Math.abs(x), 5.3, 6.7) });
  }
  const edges = [], seen = new Set(), adj = nodes.map(() => []);
  nodes.forEach((a, i) => {
    nodes.map((b, j) => [j, a.p.distanceTo(b.p)]).filter(([j, d]) => j !== i && d < 1.55)
      .sort((u, v) => u[1] - v[1]).slice(0, 3)
      .forEach(([j]) => {
        const key = i < j ? i + "-" + j : j + "-" + i;
        if (!seen.has(key)) { seen.add(key); edges.push([i, j]); adj[i].push(j); adj[j].push(i); }
      });
  });
  const group = new THREE.Group();
  const attr = (n) => new THREE.BufferAttribute(new Float32Array(n * 3), 3);

  const lineGeo = new THREE.BufferGeometry();
  lineGeo.setAttribute("position", attr(edges.length * 2)); lineGeo.setAttribute("color", attr(edges.length * 2));
  edges.forEach(([i, j], e) => {
    lineGeo.attributes.position.setXYZ(e * 2, nodes[i].p.x, nodes[i].p.y, nodes[i].p.z);
    lineGeo.attributes.position.setXYZ(e * 2 + 1, nodes[j].p.x, nodes[j].p.y, nodes[j].p.z);
  });
  const lineMat = glow(new THREE.LineBasicMaterial({ vertexColors: true, transparent: true, opacity: 0.9, depthWrite: false }));
  const lines = new THREE.LineSegments(lineGeo, lineMat); lines.renderOrder = 1; group.add(lines);

  const layer = (list, size) => {
    const geo = new THREE.BufferGeometry(); geo.setAttribute("position", attr(list.length)); geo.setAttribute("color", attr(list.length));
    list.forEach((n, i) => geo.attributes.position.setXYZ(i, n.p.x, n.p.y, n.p.z));
    const pts = new THREE.Points(geo, glow(new THREE.PointsMaterial({ map: dot, size, vertexColors: true, transparent: true, depthWrite: false })));
    pts.renderOrder = 2; group.add(pts);
    return { geo, list };
  };
  const layers = [layer(nodes.filter((n) => !n.big), 0.2), layer(nodes.filter((n) => n.big), 0.55)];

  // bright pulses travelling node to node along the links
  const P = lite ? 22 : 46, pulseGeo = new THREE.BufferGeometry();
  pulseGeo.setAttribute("position", attr(P)); pulseGeo.setAttribute("color", attr(P));
  const pulsePts = new THREE.Points(pulseGeo, glow(new THREE.PointsMaterial({ map: dot, size: 0.26, vertexColors: true, transparent: true, depthWrite: false })));
  pulsePts.renderOrder = 3; group.add(pulsePts);
  const hop = (p, from) => {                                      // the next link, mostly heading outward
    const options = adj[from].filter((j) => j !== p.from);
    const outward = options.filter((j) => Math.abs(nodes[j].p.x) > Math.abs(nodes[from].p.x));
    const list = outward.length && rand() < 0.8 ? outward : options;
    if (!list.length) return false;
    p.from = from; p.to = list[Math.floor(rand() * list.length)]; p.s = 0;
    p.len = nodes[p.from].p.distanceTo(nodes[p.to].p);
    return true;
  };
  const spawn = (p) => {
    const [i, j] = edges[Math.floor(rand() * edges.length)];
    const near = Math.abs(nodes[i].p.x) < Math.abs(nodes[j].p.x) ? i : j;
    p.from = near; p.to = near === i ? j : i; p.len = nodes[i].p.distanceTo(nodes[j].p);
    p.s = rand(); p.speed = 0.9 + rand() * 0.9;
    return p;
  };
  const pulses = Array.from({ length: P }, () => spawn({}));

  const hi = new THREE.Color(), lo = new THREE.Color(0xdbeafe), c = new THREE.Color(), v = new THREE.Vector3();
  const paint = (attribute, index, k, dark) => {
    if (dark) c.copy(hi).multiplyScalar(k); else c.copy(lo).lerp(hi, k);
    attribute.setXYZ(index, c.r, c.g, c.b);
  };
  function update(t, dt, dark) {
    hi.setHex(dark ? 0xa5e8ff : 0x1d4ed8);
    lineMat.opacity = dark ? 0.9 : 0.55;
    for (const n of nodes) {
      const wave = 0.5 + 0.5 * Math.sin(t * 2.0 - Math.abs(n.p.x) * 1.3);          // waves running outward
      const beat = 0.5 + 0.5 * Math.sin(t * 2.1 + n.phase);                          // ~3 s pulse
      const flash = Math.pow(Math.max(0, Math.sin(t * 0.45 + n.phase * 5)), 40);     // occasional brightening
      n.k = n.fade * Math.min(1, 0.5 + 0.25 * beat + 0.45 * wave ** 3 + flash);
    }
    for (const l of layers) { l.list.forEach((n, i) => paint(l.geo.attributes.color, i, n.k, dark)); l.geo.attributes.color.needsUpdate = true; }
    edges.forEach(([i, j], e) => { paint(lineGeo.attributes.color, e * 2, nodes[i].k * 0.85, dark); paint(lineGeo.attributes.color, e * 2 + 1, nodes[j].k * 0.85, dark); });
    lineGeo.attributes.color.needsUpdate = true;
    const tip = dark ? 0xcffafe : 0x1e40af;
    pulses.forEach((p, i) => {
      p.s += (dt * p.speed) / Math.max(p.len, 0.2);
      if (p.s >= 1 && !hop(p, p.to)) spawn(p);
      v.copy(nodes[p.from].p).lerp(nodes[p.to].p, Math.min(p.s, 1));
      pulseGeo.attributes.position.setXYZ(i, v.x, v.y, v.z);
      const k = 1 - THREE.MathUtils.smoothstep(Math.abs(v.x), 5.3, 6.7);
      if (dark) c.setHex(tip).multiplyScalar(k); else c.copy(lo).lerp(hi.setHex(tip), k);
      pulseGeo.attributes.color.setXYZ(i, c.r, c.g, c.b);
    });
    pulseGeo.attributes.position.needsUpdate = true; pulseGeo.attributes.color.needsUpdate = true;
  }
  return { group, update };
}

/* ------------------------------------------------------------------ */
async function start() {
  if (!host || !supportsWebGL()) return;
  const lite = small();

  const renderer = new THREE.WebGLRenderer({ antialias: !lite, alpha: true, powerPreference: lite ? "low-power" : "high-performance" });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, lite ? 1.25 : 1.75));
  renderer.setClearColor(0x000000, 0);
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.15;
  renderer.domElement.className = "hx-gl";
  host.appendChild(renderer.domElement);

  const scene = new THREE.Scene();
  // real reflections on the glass and metal: an environment map baked once
  const pmrem = new THREE.PMREMGenerator(renderer);
  scene.environment = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;
  pmrem.dispose();

  const camera = new THREE.PerspectiveCamera(35, 1, 0.1, 100);
  scene.add(new THREE.AmbientLight(0x9cc2ff, 0.5));
  const keyLight = new THREE.DirectionalLight(0xffffff, 1.6); keyLight.position.set(-3, 5, 6); scene.add(keyLight);
  const cyanLight = new THREE.PointLight(0x22d3ee, 14, 14); scene.add(cyanLight);          // these two circle the
  const blueLight = new THREE.PointLight(0x3b82f6, 12, 14); scene.add(blueLight);          // scene: dynamic light

  const dot = glowDot();
  const glowMats = [];
  const glow = (m) => { glowMats.push(m); return m; };

  // everything sits in one group that leans towards the mouse
  const world = new THREE.Group(); scene.add(world);

  /* --- the shield: float group > spin group > parts --- */
  const shieldFloat = new THREE.Group(); world.add(shieldFloat);
  const shieldSpin = new THREE.Group(); shieldFloat.add(shieldSpin);
  const outer = shieldShape(1), inner = shieldShape(0.86);
  const glassMat = new THREE.MeshPhysicalMaterial({ color: 0x1d4ed8, metalness: 0.15, roughness: 0.06, clearcoat: 1,
    clearcoatRoughness: 0.04, transparent: true, opacity: 0.42, envMapIntensity: 1.6, side: THREE.DoubleSide, depthWrite: false });
  const glass = new THREE.Mesh(new THREE.ExtrudeGeometry(inner, { depth: 0.18, bevelEnabled: false, curveSegments: 40 }), glassMat);
  glass.position.z = -0.09; glass.renderOrder = 10;
  const frameShape = shieldShape(1); frameShape.holes.push(new THREE.Path(inner.getPoints(80).reverse()));
  // a white-hot rim: bright, slightly metallic, glowing from within
  const metalMat = new THREE.MeshStandardMaterial({ color: 0xdbeafe, emissive: 0x60a5fa, emissiveIntensity: 1.1,
    metalness: 0.35, roughness: 0.18, envMapIntensity: 1.2 });
  const frame = new THREE.Mesh(new THREE.ExtrudeGeometry(frameShape, { depth: 0.3, bevelEnabled: true, bevelThickness: 0.06,
    bevelSize: 0.05, bevelSegments: 3, curveSegments: 40 }), metalMat);
  frame.position.z = -0.15; frame.renderOrder = 11;
  shieldSpin.add(glass, frame);
  const facets = faceTexture(), energy = energyTexture(), sweep = sweepTexture(), edgeMats = [];
  for (const side of [1, -1]) {                                   // both faces, so the full turn looks right
    const face = new THREE.Mesh(boxUV(new THREE.ShapeGeometry(shieldShape(0.86), 40)),
      new THREE.MeshBasicMaterial({ map: facets, transparent: true, opacity: 0.95, depthWrite: false }));
    const flow = new THREE.Mesh(boxUV(new THREE.ShapeGeometry(shieldShape(0.84), 40)),
      glow(new THREE.MeshBasicMaterial({ map: energy, transparent: true, opacity: 0.8, depthWrite: false })));
    const edge = new THREE.Mesh(tubeAlong(outer, 0.05, 0), glow(new THREE.MeshBasicMaterial({ color: 0xe0f2fe, transparent: true, opacity: 0.95, depthWrite: false })));
    edgeMats.push(edge.material);
    const shine = new THREE.Mesh(boxUV(new THREE.ShapeGeometry(shieldShape(0.86), 40)),
      glow(new THREE.MeshBasicMaterial({ map: sweep, color: 0xcfe8ff, transparent: true, opacity: 0.6, depthWrite: false })));
    shine.position.z = 0.175 * side; if (side < 0) shine.rotation.y = Math.PI; shine.renderOrder = 13; shieldSpin.add(shine);
    const halo2 = new THREE.Mesh(tubeAlong(outer, 0.16, 0), glow(new THREE.MeshBasicMaterial({ color: 0x3b82f6, transparent: true, opacity: 0.28, depthWrite: false })));
    halo2.position.z = 0.17 * side; if (side < 0) halo2.rotation.y = Math.PI; halo2.renderOrder = 12; shieldSpin.add(halo2);
    const innerEdge = new THREE.Mesh(tubeAlong(inner, 0.02, 0), glow(new THREE.MeshBasicMaterial({ color: 0x22d3ee, transparent: true, opacity: 0.7, depthWrite: false })));
    for (const m of [face, flow, edge, innerEdge]) { m.position.z = 0.17 * side; if (side < 0) m.rotation.y = Math.PI; m.renderOrder = 12; shieldSpin.add(m); }
  }
  const halo = new THREE.Sprite(glow(new THREE.SpriteMaterial({ map: dot, color: 0x2563eb, transparent: true, opacity: 0.6, depthWrite: false })));
  halo.scale.set(8, 8, 1); halo.position.z = -1; halo.renderOrder = 1; shieldFloat.add(halo);
  const rays = new THREE.Sprite(glow(new THREE.SpriteMaterial({ map: raysTexture(), color: 0x7cc4ff, transparent: true, opacity: 0.7, depthWrite: false })));
  rays.scale.set(9.5, 9.5, 1); rays.position.z = -1.1; rays.renderOrder = 1; shieldFloat.add(rays);
  // a light pool under the shield
  const pool = new THREE.Mesh(new THREE.CircleGeometry(1.6, 48), glow(new THREE.MeshBasicMaterial({ map: dot, color: 0x3b82f6, transparent: true, opacity: 0.7, depthWrite: false })));
  pool.rotation.x = -Math.PI / 2; pool.position.y = -3.25; pool.scale.set(1.9, 1, 1); pool.renderOrder = 2; world.add(pool);
  // a bright horizon line with a soft glow under the shield
  const horizon = new THREE.Mesh(new THREE.PlaneGeometry(13, 0.035), glow(new THREE.MeshBasicMaterial({ color: 0x93c5fd, transparent: true, opacity: 0.9, depthWrite: false })));
  horizon.position.set(0, -3.2, -0.5); horizon.renderOrder = 2; world.add(horizon);
  const horizonGlow = new THREE.Sprite(glow(new THREE.SpriteMaterial({ map: dot, color: 0x2563eb, transparent: true, opacity: 0.55, depthWrite: false })));
  horizonGlow.scale.set(12, 1.4, 1); horizonGlow.position.set(0, -3.2, -0.6); horizonGlow.renderOrder = 1; world.add(horizonGlow);
  const hotspot = new THREE.Sprite(glow(new THREE.SpriteMaterial({ map: dot, color: 0xe0f2fe, transparent: true, opacity: 1, depthWrite: false })));
  hotspot.scale.set(3.2, 0.7, 1); hotspot.position.set(0, -3.2, -0.4); hotspot.renderOrder = 3; world.add(hotspot);
  const beam = new THREE.Sprite(glow(new THREE.SpriteMaterial({ map: dot, color: 0x3b82f6, transparent: true, opacity: 0.6, depthWrite: false })));
  beam.scale.set(0.9, 2.4, 1); beam.position.set(0, -3.2, -0.45); beam.renderOrder = 3; world.add(beam);

  /* --- the living network behind the shield (its own group, for deeper parallax) --- */
  const net = buildNetwork(lite, dot, glow); world.add(net.group);

  /* --- energy bursts: a ring leaves the shield and a ripple crosses the floor every few seconds --- */
  const ringGeo = new THREE.RingGeometry(0.96, 1, 96);
  const burst = new THREE.Mesh(ringGeo, glow(new THREE.MeshBasicMaterial({ color: 0x7dd3fc, transparent: true, opacity: 0, depthWrite: false, side: THREE.DoubleSide })));
  burst.position.z = -0.3; burst.renderOrder = 6; shieldFloat.add(burst);
  const ripple = new THREE.Mesh(ringGeo, glow(new THREE.MeshBasicMaterial({ color: 0x60a5fa, transparent: true, opacity: 0, depthWrite: false, side: THREE.DoubleSide })));
  ripple.rotation.x = -Math.PI / 2; ripple.position.y = -3.55; ripple.renderOrder = 2; world.add(ripple);
  const BURST_EVERY = 5;

  /* --- rings with particles running along them --- */
  const rings = (SHOW_ORBIT ? RINGS : []).map((spec) => {
    const g = new THREE.Group(); g.rotation.set(spec.tilt, 0, spec.roll); world.add(g);
    const line = new THREE.Line(new THREE.BufferGeometry().setFromPoints(ringPoints(spec.radius)),
      glow(new THREE.LineBasicMaterial({ color: spec.color, transparent: true, opacity: spec.opacity, depthWrite: false })));
    line.renderOrder = 4; g.add(line);
    const n = lite ? 7 : 14, pos = new Float32Array(n * 3), geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    const pts = new THREE.Points(geo, glow(new THREE.PointsMaterial({ map: dot, color: spec.color, size: 0.22, transparent: true, depthWrite: false })));
    pts.renderOrder = 5; g.add(pts);
    return { spec, line, pts, pos, n };
  });

  /* --- the six entities on the orbit --- */
  const orbitGroup = new THREE.Group(); orbitGroup.rotation.set(ORBIT.tilt, 0, ORBIT.roll); world.add(orbitGroup);
  const orbit = new THREE.Group(); orbitGroup.add(orbit);
  const entities = (SHOW_ORBIT ? ENTITIES : []).map((spec, index) => {
    const anchor = new THREE.Group();                              // rides the orbit
    const angle = (index / ENTITIES.length) * Math.PI * 2;
    anchor.position.set(Math.cos(angle) * ORBIT.radius, Math.sin(angle) * ORBIT.radius, 0);
    orbit.add(anchor);
    const face = new THREE.Group(); anchor.add(face);              // always turned to the camera
    const pill = new THREE.Sprite(new THREE.SpriteMaterial({ transparent: true, depthTest: false, depthWrite: false }));
    face.add(pill);
    const mat = new THREE.MeshStandardMaterial({ color: spec.tone, emissive: spec.tone, emissiveIntensity: 0.55,
      metalness: 0.55, roughness: 0.25, envMapIntensity: 1.2, depthTest: false, depthWrite: false, transparent: true });
    const spin = entityModel(spec.model, mat);                      // turns on its own axis
    spin.traverse((o) => { if (o.material) { o.material.depthTest = false; o.material.depthWrite = false; } });
    face.add(spin);
    return { spec, anchor, face, pill, spin, mat, hot: false, rate: (Math.PI * 2) / spec.spin, phase: Math.random() * 6.28, world: new THREE.Vector3(), size: new THREE.Vector2(1, 1), iconX: 0.2 };
  });
  function paintPills() {
    for (const e of entities) {
      const { canvas, iconX } = pillCanvas(e.spec, e.hot);
      const tex = new THREE.CanvasTexture(canvas); tex.colorSpace = THREE.SRGBColorSpace; tex.anisotropy = 4;
      if (e.pill.material.map) e.pill.material.map.dispose();
      e.pill.material.map = tex; e.pill.material.needsUpdate = true;
      const h = 0.95; e.size.set(h * canvas.width / canvas.height, h); e.iconX = iconX;
    }
  }

  /* --- theme --- */
  function applyTheme() {
    const dark = isDark();
    for (const m of glowMats) { m.blending = dark ? THREE.AdditiveBlending : THREE.NormalBlending; m.needsUpdate = true; }
    glassMat.opacity = dark ? 0.42 : 0.55; glassMat.color.setHex(dark ? 0x1d4ed8 : 0x2563eb);
    halo.userData.base = dark ? 0.6 : 0.18; halo.material.opacity = halo.userData.base; halo.material.color.setHex(dark ? 0x2563eb : 0x93c5fd);
    pool.material.opacity = dark ? 0.7 : 0.25;
    horizon.material.color.setHex(dark ? 0x93c5fd : 0x3b82f6); horizon.material.opacity = dark ? 0.9 : 0.5;
    horizonGlow.material.opacity = dark ? 0.55 : 0.15;
    metalMat.emissiveIntensity = dark ? 1.1 : 0.45;
    cyanLight.intensity = dark ? 14 : 4; blueLight.intensity = dark ? 12 : 4;
    renderer.toneMappingExposure = dark ? 1.15 : 1.0;
    for (const r of rings) r.line.material.opacity = dark ? r.spec.opacity : Math.min(0.7, r.spec.opacity + 0.12);
    paintPills();
  }
  applyTheme();
  document.addEventListener("themechange", () => setTimeout(applyTheme, 30));
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(paintPills);

  /* --- size: keep the whole composition in frame --- */
  function resize() {
    const w = renderer.domElement.clientWidth || host.clientWidth, h = renderer.domElement.clientHeight || host.clientHeight;
    if (!w || !h) return;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    const f = Math.tan(THREE.MathUtils.degToRad(camera.fov) / 2);
    const wings = camera.aspect < 1 ? 4.3 : 6.4;
    camera.userData.distance = Math.max(7.6 / 2 / f, wings / (f * camera.aspect));
    camera.updateProjectionMatrix();
  }
  new ResizeObserver(resize).observe(renderer.domElement);
  resize();

  /* --- mouse: parallax and hover --- */
  const pointer = new THREE.Vector2(), ease = new THREE.Vector2(), ndc = new THREE.Vector2(2, 2), ray = new THREE.Raycaster();
  window.addEventListener("pointermove", (e) => {
    pointer.set(e.clientX / window.innerWidth - 0.5, e.clientY / window.innerHeight - 0.5);
    const b = renderer.domElement.getBoundingClientRect();
    ndc.set(((e.clientX - b.left) / b.width) * 2 - 1, -((e.clientY - b.top) / b.height) * 2 + 1);
  }, { passive: true });

  let onScreen = true, frameId = 0;
  new IntersectionObserver((list) => { onScreen = list[0].isIntersecting; }).observe(host);
  const clock = new THREE.Clock(), toCam = new THREE.Vector3(), q = new THREE.Quaternion();
  let last = 0;

  function render() {
    frameId = requestAnimationFrame(render);
    if (!onScreen || !document.body.classList.contains("entry") || !host.offsetParent) return;
    const t = reduce.matches ? 0 : clock.getElapsedTime();
    const dt = Math.min(0.05, Math.max(0, t - last)); last = t;      // delta time: same speed at any frame rate
    const dark = isDark();

    // scene tilt and camera: eased so they never jump
    ease.lerp(pointer, 1 - Math.pow(0.02, dt || 0.016));
    camera.position.set(ease.x * 0.7, 0.55 - ease.y * 0.35, camera.userData.distance || 13);
    camera.lookAt(0, -0.2, 0);
    world.rotation.y = ease.x * 0.28;
    world.rotation.x = ease.y * 0.14;

    shieldSpin.rotation.y = t * 0.45;                              // full 360-degree turn, continuous
    shieldFloat.position.y = 0.2 + Math.sin(t * 0.9) * 0.12;        // floating
    energy.offset.y = -t * 0.35;                                   // energy flowing across the faces
    sweep.offset.x = 1 - ((t % 6.5) / 1.8) * 2;                     // a reflection crosses the glass every 6.5 s
    for (const m of edgeMats) m.opacity = 0.78 + 0.22 * Math.sin(t * 2.2);   // the rim pulses
    const b = (t % BURST_EVERY) / BURST_EVERY, fadeOut = (1 - b) ** 2;
    burst.visible = false; rays.material.rotation = t * 0.03; rays.material.opacity = (dark ? 0.55 : 0.2) * (1 + 0.6 * (1 - b) ** 6);
    ripple.visible = false; hotspot.material.opacity = dark ? 0.85 + 0.15 * Math.sin(t * 2.4) : 0.35; beam.material.opacity = dark ? 0.5 : 0.15;
    halo.material.opacity = (halo.userData.base || 0.6) * (1 + 0.7 * (1 - b) ** 8);
    net.group.position.set(-ease.x * 0.45, ease.y * 0.2, 0);         // deeper layer: more parallax
    net.update(t, reduce.matches ? 0 : dt, dark);
    cyanLight.position.set(Math.cos(t * 0.6) * 4, 1.5, Math.sin(t * 0.6) * 4);
    blueLight.position.set(Math.cos(t * 0.6 + Math.PI) * 4, -1.2, Math.sin(t * 0.6 + Math.PI) * 4);

    orbit.rotation.z = t * ORBIT.speed;                            // orbital motion
    for (const r of rings) {                                       // particles along the rings
      for (let i = 0; i < r.n; i += 1) {
        const a = (i / r.n) * Math.PI * 2 + t * r.spec.speed;
        r.pos[i * 3] = Math.cos(a) * r.spec.radius; r.pos[i * 3 + 1] = Math.sin(a) * r.spec.radius; r.pos[i * 3 + 2] = 0;
      }
      r.pts.geometry.attributes.position.needsUpdate = true;
    }

    ray.setFromCamera(ndc, camera);
    const hit = ray.intersectObjects(entities.map((e) => e.pill), false)[0];
    const hotKey = hit ? entities.find((e) => e.pill === hit.object).spec.key : null;
    let repaint = false;
    camera.getWorldDirection(toCam).negate();
    for (const e of entities) {
      const hot = e.spec.key === hotKey;
      if (hot !== e.hot) { e.hot = hot; repaint = true; }
      // turn the label towards the camera (cancel the orbit's own rotation)
      e.anchor.parent.getWorldQuaternion(q);
      e.face.quaternion.copy(q.invert().multiply(camera.quaternion));
      e.anchor.getWorldPosition(e.world);
      const depth = e.world.dot(toCam), near = THREE.MathUtils.clamp((depth + ORBIT.radius) / (2 * ORBIT.radius), 0, 1);
      const s = (0.78 + 0.3 * near) * (hot ? 1.12 : 1);
      e.face.scale.setScalar(s);
      e.face.position.y = reduce.matches ? 0 : Math.sin(t * 1.3 + e.phase) * 0.08;   // floating
      e.pill.scale.set(e.size.x, e.size.y, 1);
      e.spin.position.set((e.iconX - 0.5) * e.size.x, 0, 0.3);
      e.spin.scale.setScalar(0.82);                                 // the icon sits inside its pill
      e.spin.rotation.y = t * e.rate + e.phase;                       // each entity turns on its own axis
      e.spin.rotation.x = Math.sin(t * 0.7 + e.phase) * 0.25;
      e.pill.material.opacity = 0.55 + 0.45 * near;
      e.mat.opacity = 0.6 + 0.4 * near;
      const front = depth >= 0;
      e.pill.renderOrder = front ? 40 : 3;                          // behind or in front of the shield
      e.spin.traverse((o) => { if (o.isMesh || o.isLineSegments) o.renderOrder = front ? 41 : 3; });
    }
    if (repaint) paintPills();
    renderer.render(scene, camera);
    if (reduce.matches) cancelAnimationFrame(frameId);
  }
  document.addEventListener("visibilitychange", () => { cancelAnimationFrame(frameId); if (!document.hidden) frameId = requestAnimationFrame(render); });

  window.__hx3d = true;
  host.classList.add("hx-webgl");
  frameId = requestAnimationFrame(render);
}

start().catch((error) => console.warn("3D hero unavailable, using the fallback:", error));
