/* CyberIntelliX hero - a cinematic, real-time 3D cybersecurity scene in plain Three.js.
 *
 * The shield is built in layers, all curved (biconvex) rather than flat:
 *   - a bevelled metal frame (PBR, environment reflections)
 *   - thick blue glass on both faces (clear-coat physical material)
 *   - a raised two-tone crystal plate with a centre ridge (two facets that catch light differently)
 *   - animated circuit traces inside (custom shader: energy waves run along the traces)
 *   - a fresnel / rim-light shell with a reflection that sweeps across the glass (custom shader)
 *   - three glowing borders: outer edge, inner frame edge and plate edge
 * Behind it, a three-layer knowledge-graph network with curved links (custom shaders: nodes pulse
 * independently, light runs outward along the links, far layers are softer for depth of field),
 * pulses travelling along the links, volumetric light rays, energy rings, floating particles,
 * a floor glow with a lens-flare streak. Dark theme adds real bloom post-processing.
 *
 * Everything animates on delta time, pauses off-screen / in hidden tabs, and holds still for
 * prefers-reduced-motion. Phones get fewer nodes and no bloom. No WebGL: the CSS hero stays.
 */
import * as THREE from "three";
import { RoomEnvironment } from "three/addons/environments/RoomEnvironment.js";
import { EffectComposer } from "three/addons/postprocessing/EffectComposer.js";
import { RenderPass } from "three/addons/postprocessing/RenderPass.js";
import { UnrealBloomPass } from "three/addons/postprocessing/UnrealBloomPass.js";
import { OutputPass } from "three/addons/postprocessing/OutputPass.js";

const host = document.querySelector(".hx");
const reduce = window.matchMedia("(prefers-reduced-motion: reduce)");
const isDark = () => document.documentElement.getAttribute("data-theme") === "dark";
const small = () => window.innerWidth < 760 || window.matchMedia("(pointer: coarse)").matches;

function supportsWebGL() {
  try {
    const c = document.createElement("canvas");
    return !!(window.WebGLRenderingContext && (c.getContext("webgl2") || c.getContext("webgl")));
  } catch (error) { return false; }
}
function seeded(seed) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/* ------------------------------------------------------------------ */
/* shield geometry                                                     */
/* ------------------------------------------------------------------ */
function shieldShape(scale) {
  const s = scale / 46, sh = new THREE.Shape(), p = (x, y) => [x * s, y * s];
  sh.moveTo(...p(0, 121)); sh.bezierCurveTo(...p(27, 105), ...p(62, 97), ...p(94, 97)); sh.lineTo(...p(94, 8));
  sh.bezierCurveTo(...p(94, -58), ...p(47, -105), ...p(0, -136)); sh.bezierCurveTo(...p(-47, -105), ...p(-94, -58), ...p(-94, 8));
  sh.lineTo(...p(-94, 97)); sh.bezierCurveTo(...p(-62, 97), ...p(-27, 105), ...p(0, 121));
  return sh;
}
// every layer bulges outward (biconvex), so the shield reads as a thick curved object from any angle
const BULGE = 0.3, BW = 2.25;
const bulge = (x) => BULGE * Math.max(0, 1 - (x / BW) ** 2);
const slope = (x) => (Math.abs(x) < BW ? (-2 * BULGE * x) / (BW * BW) : 0);

function bendSolid(geometry) {
  const pos = geometry.attributes.position, nor = geometry.attributes.normal, n = new THREE.Vector3();
  for (let i = 0; i < pos.count; i += 1) {
    const x = pos.getX(i), z = pos.getZ(i);
    pos.setZ(i, z + Math.sign(z || 1) * bulge(x));
    n.set(nor.getX(i), nor.getY(i), nor.getZ(i));
    n.x -= Math.abs(n.z) * slope(x);                                // tilt the normals with the curve
    n.normalize(); nor.setXYZ(i, n.x, n.y, n.z);
  }
  return geometry;
}
// a curved sheet covering the shield's box at this scale; the exact outline comes from a mask texture
const BOX_W = 4.2, BOX_H = 5.7, BOX_Y = -0.165;
function sheet(scale, zOff, ridge = 0) {
  const g = new THREE.PlaneGeometry(BOX_W * scale, BOX_H * scale, 48, 64);
  g.translate(0, BOX_Y * scale, 0);
  const pos = g.attributes.position, nor = g.attributes.normal, n = new THREE.Vector3(), half = 2.04 * scale;
  for (let i = 0; i < pos.count; i += 1) {
    const x = pos.getX(i);
    pos.setZ(i, zOff + bulge(x) + ridge * Math.max(0, 1 - Math.abs(x) / half));
    n.set(-(slope(x) - (ridge * Math.sign(x)) / half), 0, 1).normalize();
    nor.setXYZ(i, n.x, n.y, n.z);
  }
  return g;
}
const sheetZ = (x, zOff, ridge, scale) => zOff + bulge(x) + ridge * Math.max(0, 1 - Math.abs(x) / (2.04 * scale));
function edgeTube(scale, zFn, radius) {
  const pts = shieldShape(scale).getSpacedPoints(220).map((p) => new THREE.Vector3(p.x, p.y, zFn(p.x)));
  return new THREE.TubeGeometry(new THREE.CatmullRomCurve3(pts, true), 360, radius, 8, true);
}

/* ------------------------------------------------------------------ */
/* textures (drawn once on canvases)                                   */
/* ------------------------------------------------------------------ */
const TEX_W = 512, TEX_H = Math.round((512 * BOX_H) / BOX_W);
function toBox(g) { g.translate(TEX_W / 2, TEX_H / 2); g.scale(TEX_W / BOX_W, -TEX_H / BOX_H); g.translate(0, -BOX_Y); }
function canvasTex(draw, srgb) {
  const c = document.createElement("canvas"); c.width = TEX_W; c.height = TEX_H;
  draw(c.getContext("2d"));
  const t = new THREE.CanvasTexture(c); if (srgb) t.colorSpace = THREE.SRGBColorSpace; t.anisotropy = 4;
  return t;
}
const maskTexture = () => canvasTex((g) => {
  g.fillStyle = "#000"; g.fillRect(0, 0, TEX_W, TEX_H); g.save(); toBox(g);
  const pts = shieldShape(1).getPoints(120); g.beginPath(); pts.forEach((p, i) => (i ? g.lineTo(p.x, p.y) : g.moveTo(p.x, p.y)));
  g.closePath(); g.fillStyle = "#fff"; g.fill(); g.restore();
});
const plateTexture = () => canvasTex((g) => {                     // lighter left facet, deep right facet, bright ridge
  const L = g.createLinearGradient(0, 0, TEX_W * 0.3, TEX_H); L.addColorStop(0, "#8fd0ff"); L.addColorStop(0.45, "#3b8cff"); L.addColorStop(1, "#1747c9");
  g.fillStyle = L; g.fillRect(0, 0, TEX_W / 2, TEX_H);
  const R = g.createLinearGradient(TEX_W, 0, TEX_W * 0.6, TEX_H); R.addColorStop(0, "#1d4ed8"); R.addColorStop(0.5, "#0f2f96"); R.addColorStop(1, "#061547");
  g.fillStyle = R; g.fillRect(TEX_W / 2, 0, TEX_W / 2, TEX_H);
  const ridge = g.createLinearGradient(TEX_W / 2 - 14, 0, TEX_W / 2 + 14, 0);
  ridge.addColorStop(0, "rgba(255,255,255,0)"); ridge.addColorStop(0.45, "rgba(224,242,254,0.95)"); ridge.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = ridge; g.fillRect(TEX_W / 2 - 14, 0, 28, TEX_H);
}, true);
const circuitTexture = () => canvasTex((g) => {                   // PCB-style traces with pads and chips
  const rand = seeded(5); g.fillStyle = "#000"; g.fillRect(0, 0, TEX_W, TEX_H); g.lineCap = "round"; g.lineJoin = "round";
  const dirs = [[1, 0], [0, 1], [-1, 0], [0, -1], [0.707, 0.707], [-0.707, 0.707], [0.707, -0.707], [-0.707, -0.707]];
  const paths = [];
  for (let i = 0; i < 70; i += 1) {
    let x = 70 + rand() * (TEX_W - 140), y = 80 + rand() * (TEX_H - 170), d = Math.floor(rand() * 4);
    const pts = [[x, y]];
    for (let k = 0, n = 2 + Math.floor(rand() * 4); k < n; k += 1) {
      if (k) d = rand() < 0.5 ? (d + (rand() < 0.5 ? 4 : 0)) % 8 : Math.floor(rand() * 4);
      const len = 18 + rand() * 60; x += dirs[d][0] * len; y += dirs[d][1] * len; pts.push([x, y]);
    }
    paths.push(pts);
  }
  for (const [w, a] of [[7, 0.22], [2.2, 1]]) {                    // a soft glow pass, then the crisp trace
    g.strokeStyle = `rgba(255,255,255,${a})`; g.lineWidth = w;
    for (const pts of paths) { g.beginPath(); pts.forEach(([x, y], i) => (i ? g.lineTo(x, y) : g.moveTo(x, y))); g.stroke(); }
  }
  g.fillStyle = "#fff"; g.strokeStyle = "#fff"; g.lineWidth = 2;
  for (const pts of paths) {
    const [x, y] = pts[pts.length - 1]; g.beginPath(); g.arc(x, y, rand() < 0.5 ? 4.5 : 3, 0, Math.PI * 2);
    if (rand() < 0.5) g.fill(); else g.stroke();
  }
  for (let i = 0; i < 6; i += 1) {                                 // a few chips with pins
    const cx = 120 + rand() * (TEX_W - 240), cy = 160 + rand() * (TEX_H - 330), w = 34 + rand() * 30, h = 24 + rand() * 24;
    g.strokeRect(cx - w / 2, cy - h / 2, w, h);
    for (let p = -w / 2 + 6; p < w / 2 - 2; p += 8) { g.fillRect(cx + p, cy - h / 2 - 7, 2, 7); g.fillRect(cx + p, cy + h / 2, 2, 7); }
  }
});
const ENTITIES = [                                                 // the knowledge graph's own entity types
  { key: "CVE", label: "CVE", tone: "#ef4444" },
  { key: "CWE", label: "CWE", tone: "#f59e0b" },
  { key: "CAPEC", label: "CAPEC", tone: "#8b5cf6" },
  { key: "ATTACK", label: "ATT&CK", tone: "#22d3ee" },
  { key: "INTEL", label: "Threat Intel", tone: "#38bdf8" },
  { key: "RAG", label: "RAG", tone: "#3b82f6" },
];
function entityLabel(e, dark) {                                    // a glowing node with its name beside it
  const k = 2, font = `700 ${30 * k}px "Space Grotesk", "Inter", system-ui, sans-serif`;
  const meas = document.createElement("canvas").getContext("2d"); meas.font = font;
  const r = 20 * k, pad = 16 * k, gap = 14 * k, w = Math.ceil(pad + r * 2 + gap + meas.measureText(e.label).width + pad), h = 84 * k;
  const c = document.createElement("canvas"); c.width = w; c.height = h; const g = c.getContext("2d");
  const cx = pad + r, cy = h / 2;
  const halo = g.createRadialGradient(cx, cy, 0, cx, cy, r * 2); halo.addColorStop(0, e.tone + "aa"); halo.addColorStop(1, e.tone + "00");
  g.fillStyle = halo; g.fillRect(0, 0, cx + r * 2, h);
  g.beginPath(); g.arc(cx, cy, r * 0.62, 0, Math.PI * 2); g.fillStyle = e.tone; g.fill();
  g.beginPath(); g.arc(cx, cy, r * 0.28, 0, Math.PI * 2); g.fillStyle = "#ffffff"; g.fill();
  g.beginPath(); g.arc(cx, cy, r, 0, Math.PI * 2); g.lineWidth = 2.5 * k; g.strokeStyle = e.tone; g.stroke();
  g.font = font; g.textBaseline = "middle";
  g.shadowColor = dark ? "rgba(8,13,27,0.9)" : "rgba(255,255,255,0.9)"; g.shadowBlur = 10 * k;
  g.fillStyle = dark ? "#e8f1ff" : "#0f172a"; g.fillText(e.label, cx + r + gap, cy + k);
  const t = new THREE.CanvasTexture(c); t.colorSpace = THREE.SRGBColorSpace; t.anisotropy = 4;
  return { tex: t, aspect: w / h, dotX: cx / w };
}
function glowDot() {
  const c = document.createElement("canvas"); c.width = c.height = 128; const g = c.getContext("2d");
  const r = g.createRadialGradient(64, 64, 0, 64, 64, 64);
  r.addColorStop(0, "rgba(255,255,255,1)"); r.addColorStop(0.25, "rgba(255,255,255,0.6)"); r.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = r; g.fillRect(0, 0, 128, 128);
  return new THREE.CanvasTexture(c);
}

/* ------------------------------------------------------------------ */
/* shaders                                                             */
/* ------------------------------------------------------------------ */
const SHEET_VS = `
  varying vec2 vUv; varying vec3 vN; varying vec3 vV;
  void main() {
    vUv = uv; vec4 mv = modelViewMatrix * vec4(position, 1.0);
    vN = normalize(normalMatrix * normal); vV = normalize(-mv.xyz);
    gl_Position = projectionMatrix * mv;
  }`;
const CIRCUIT_FS = `
  uniform sampler2D uCircuit, uMask; uniform float uTime, uStrength; uniform vec3 uA, uB;
  varying vec2 vUv;
  void main() {
    if (texture2D(uMask, vUv).g < 0.5) discard;
    float c = texture2D(uCircuit, vUv).g;
    float r = length((vUv - vec2(0.5, 0.1)) * vec2(1.0, 1.3));
    float wave = pow(0.5 + 0.5 * sin(r * 24.0 - uTime * 3.0), 6.0);           // energy rising through the traces
    float flick = 0.85 + 0.15 * sin(uTime * 7.0 + vUv.y * 40.0);
    float v = c * (0.28 + 0.9 * wave) * flick * uStrength;
    gl_FragColor = vec4(mix(uA, uB, wave), clamp(v, 0.0, 1.0));
  }`;
const FX_FS = `
  uniform sampler2D uMask; uniform float uSweep, uStrength; uniform vec3 uRim;
  varying vec2 vUv; varying vec3 vN; varying vec3 vV;
  void main() {
    if (texture2D(uMask, vUv).g < 0.5) discard;
    float f = pow(1.0 - abs(dot(normalize(vN), normalize(vV))), 2.2);            // fresnel rim light
    float band = exp(-pow((vUv.x * 0.75 + vUv.y * 0.65 - uSweep) * 11.0, 2.0));  // a reflection sweeping across
    float top = smoothstep(0.55, 1.0, vUv.y) * 0.12;                             // sky reflection near the top
    vec3 col = uRim * f * 1.4 + vec3(0.85, 0.95, 1.0) * (band * 0.55 + top);
    float a = clamp((f * 1.4 + band * 0.55 + top) * uStrength, 0.0, 1.0);
    gl_FragColor = vec4(col, a);
  }`;
const RAYS_FS = `
  uniform float uTime, uStrength; varying vec2 vUv;
  void main() {
    vec2 p = vUv - 0.5; float r = length(p) * 2.0, a = atan(p.y, p.x);
    float rays = pow(0.5 + 0.5 * sin(a * 34.0 + sin(a * 5.0 + uTime * 0.25) * 2.5 + uTime * 0.12), 7.0) * 0.7
               + pow(0.5 + 0.5 * sin(a * 11.0 - uTime * 0.18), 12.0) * 0.6;
    float fall = smoothstep(1.0, 0.08, r);
    float core = exp(-r * r * 16.0);
    vec3 col = mix(vec3(0.08, 0.3, 1.0), vec3(0.35, 0.75, 1.0), smoothstep(0.55, 0.0, r));
    float v = (rays * fall * 0.32 + core * 0.3 + exp(-r * 3.2) * 0.12) * uStrength;
    gl_FragColor = vec4(col, clamp(v, 0.0, 1.0));
  }`;
const LINE_VS = `
  attribute float aBright; uniform float uTime; varying float vI; varying float vW;
  void main() {
    vec4 mv = modelViewMatrix * vec4(position, 1.0); gl_Position = projectionMatrix * mv;
    float ax = abs(position.x);
    vW = pow(0.5 + 0.5 * sin(ax * 1.25 - uTime * 1.5), 5.0);                    // light running outward
    vI = aBright * (1.0 - smoothstep(5.0, 6.9, ax)) * (0.3 + 0.95 * vW);
  }`;
const LINE_FS = `
  uniform vec3 uA, uB; uniform float uGain; varying float vI; varying float vW;
  void main() { gl_FragColor = vec4(mix(uA, uB, vW), clamp(vI * uGain, 0.0, 1.0)); }`;
const NODE_VS = `
  attribute float aSize, aPhase, aBright, aSoft; uniform float uTime, uScale, uDrift;
  varying float vI; varying float vSoft;
  void main() {
    vec3 p = position;
    float fadeY = 1.0;
    if (uDrift > 0.5) {                                                          // floating dust
      p.y = -3.4 + mod(position.y + 3.4 + uTime * (0.1 + aPhase * 0.012), 7.2);
      p.x += sin(uTime * 0.3 + aPhase) * 0.18;
      fadeY = smoothstep(-3.4, -2.6, p.y) * (1.0 - smoothstep(2.8, 3.8, p.y));
    }
    vec4 mv = modelViewMatrix * vec4(p, 1.0); gl_Position = projectionMatrix * mv;
    float ax = abs(p.x);
    float beat = 0.5 + 0.5 * sin(uTime * (1.6 + fract(aPhase * 7.13) * 1.5) + aPhase);   // 2-4 s, independent
    float wave = pow(0.5 + 0.5 * sin(ax * 1.25 - uTime * 1.5), 5.0);
    vI = aBright * fadeY * (1.0 - smoothstep(5.2, 7.0, ax)) * (0.75 + 0.35 * beat + 0.6 * wave);
    vSoft = aSoft;
    gl_PointSize = aSize * uScale * (0.85 + 0.3 * beat) / -mv.z;
  }`;
const NODE_FS = `
  uniform vec3 uCore, uGlow; varying float vI; varying float vSoft;
  void main() {
    float d = length(gl_PointCoord - 0.5) * 2.0; if (d > 1.0) discard;
    float core = smoothstep(0.32 + vSoft * 0.45, 0.0, d);                        // far nodes are softer (depth of field)
    float halo = exp(-d * d * 5.0) * 0.55;
    gl_FragColor = vec4(mix(uGlow, uCore, core), clamp((core + halo) * vI, 0.0, 1.0));
  }`;
const RING_VS = `
  attribute float aAng; uniform float uTime, uSpeed; varying float vI;
  void main() {
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
    vI = 0.14 + pow(fract(aAng - uTime * uSpeed), 14.0) * 1.3 + pow(fract(aAng * 2.0 + uTime * uSpeed * 0.6), 40.0) * 0.7;
  }`;
const RING_FS = `uniform vec3 uColor; uniform float uOpacity; varying float vI;
  void main() { gl_FragColor = vec4(uColor, clamp(vI * uOpacity, 0.0, 1.0)); }`;
const PASS_VS = `varying vec2 vUv; void main() { vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }`;

/* ------------------------------------------------------------------ */
/* network: three depth layers, curved links, travelling pulses        */
/* ------------------------------------------------------------------ */
function buildNetwork(lite, nodeMat, lineMat, pulseMat) {
  const rand = seeded(7);
  const LAYERS = [
    { z: [-0.45, -0.9], n: lite ? 44 : 84, bright: 1.0, soft: 0.0, size: 0.11, link: 0.9 },
    { z: [-1.4, -2.1], n: lite ? 32 : 66, bright: 0.62, soft: 0.55, size: 0.14, link: 0.55 },
  ];
  const nodes = [];
  // hubs on the shield's sides, so the network plugs into it
  for (const side of [-1, 1]) for (let i = 0; i < 6; i += 1)
    nodes.push({ p: new THREE.Vector3(side * (1.72 + rand() * 0.15), -1.3 + i * 0.55 + rand() * 0.2, -0.35), layer: 0, size: 0.17, big: false, hub: true });
  LAYERS.forEach((L, li) => {
    let made = 0, tries = 0;
    while (made < L.n && tries < 6000) {
      tries += 1;
      const side = rand() < 0.5 ? -1 : 1, d = Math.pow(rand(), 1.1), ax = 1.95 + d * 5.0;
      const env = 1.8 - 0.14 * (ax - 1.9) + li * 0.25;
      const p = new THREE.Vector3(side * ax, 0.3 + (rand() * 2 - 1) * env, L.z[0] + rand() * (L.z[1] - L.z[0]));
      if (nodes.some((o) => o.layer === li && Math.hypot(o.p.x - p.x, o.p.y - p.y) < 0.46)) continue;
      const big = rand() < 0.12;
      nodes.push({ p, layer: li, size: L.size * (big ? 1.9 : 1), big, hub: false });
      made += 1;
    }
  });
  // links: two or three nearest in the same layer, plus some links into the next layer for depth
  const edges = [], seen = new Set(), adj = nodes.map(() => []);
  const link = (i, j) => {
    const key = i < j ? i + ":" + j : j + ":" + i; if (seen.has(key) || i === j) return;
    seen.add(key); adj[i].push(edges.length); adj[j].push(edges.length); edges.push({ i, j });
  };
  nodes.forEach((a, i) => {
    const close = nodes.map((b, j) => [j, Math.hypot(a.p.x - b.p.x, a.p.y - b.p.y)])
      .filter(([j, d]) => j !== i && nodes[j].layer === a.layer && d < 1.35 && Math.sign(nodes[j].p.x) === Math.sign(a.p.x))
      .sort((u, v) => u[1] - v[1]);
    close.slice(0, a.hub ? 3 : (rand() < 0.4 ? 3 : 2)).forEach(([j]) => link(i, j));
    if (a.layer < 2 && rand() < 0.28) {
      const deeper = nodes.map((b, j) => [j, Math.hypot(a.p.x - b.p.x, a.p.y - b.p.y)])
        .filter(([j, d]) => nodes[j].layer === a.layer + 1 && d < 1.1).sort((u, v) => u[1] - v[1])[0];
      if (deeper) link(i, deeper[0]);
    }
  });
  // each link is a gentle curve (quadratic bezier), never a jagged straight line
  const SEG = 10, mid = new THREE.Vector3(), perp = new THREE.Vector3();
  for (const e of edges) {
    const a = nodes[e.i].p, b = nodes[e.j].p, len = a.distanceTo(b);
    mid.addVectors(a, b).multiplyScalar(0.5);
    perp.set(-(b.y - a.y), b.x - a.x, 0).normalize().multiplyScalar((rand() - 0.5) * 0.45 * len);
    e.c = mid.clone().add(perp); e.len = len;
    e.bright = Math.min(LAYERS[nodes[e.i].layer].link, LAYERS[nodes[e.j].layer].link);
  }
  const bez = (e, s, out) => {
    const a = nodes[e.i].p, b = nodes[e.j].p, u = 1 - s;
    return out.set(u * u * a.x + 2 * u * s * e.c.x + s * s * b.x, u * u * a.y + 2 * u * s * e.c.y + s * s * b.y, u * u * a.z + 2 * u * s * e.c.z + s * s * b.z);
  };
  const linePos = new Float32Array(edges.length * SEG * 6), lineBright = new Float32Array(edges.length * SEG * 2), v = new THREE.Vector3();
  edges.forEach((e, k) => {
    for (let s = 0; s < SEG; s += 1) {
      const o = (k * SEG + s) * 2;
      bez(e, s / SEG, v).toArray(linePos, o * 3); bez(e, (s + 1) / SEG, v).toArray(linePos, o * 3 + 3);
      lineBright[o] = lineBright[o + 1] = e.bright;
    }
  });
  const group = new THREE.Group();
  const lg = new THREE.BufferGeometry();
  lg.setAttribute("position", new THREE.BufferAttribute(linePos, 3)); lg.setAttribute("aBright", new THREE.BufferAttribute(lineBright, 1));
  const lines = new THREE.LineSegments(lg, lineMat); lines.renderOrder = 1; group.add(lines);

  const pointsGeo = (list) => {
    const g = new THREE.BufferGeometry(), n = list.length;
    const pos = new Float32Array(n * 3), size = new Float32Array(n), phase = new Float32Array(n), bright = new Float32Array(n), soft = new Float32Array(n);
    list.forEach((o, i) => { o.p.toArray(pos, i * 3); size[i] = o.size; phase[i] = rand() * 6.28; bright[i] = o.bright; soft[i] = o.soft; });
    g.setAttribute("position", new THREE.BufferAttribute(pos, 3)); g.setAttribute("aSize", new THREE.BufferAttribute(size, 1));
    g.setAttribute("aPhase", new THREE.BufferAttribute(phase, 1)); g.setAttribute("aBright", new THREE.BufferAttribute(bright, 1));
    g.setAttribute("aSoft", new THREE.BufferAttribute(soft, 1));
    return g;
  };
  const nodePts = new THREE.Points(pointsGeo(nodes.map((o) => ({ p: o.p, size: o.size, bright: LAYERS[o.layer].bright * (o.big ? 1.25 : 1), soft: LAYERS[o.layer].soft }))), nodeMat);
  nodePts.renderOrder = 2; group.add(nodePts);

  // pulses: bright sparks running along the links, mostly outward
  const P = lite ? 26 : 64;
  const pulses = Array.from({ length: P }, () => ({ e: 0, from: 0, s: 0, speed: 0 }));
  const pulseGeo = pointsGeo(pulses.map(() => ({ p: new THREE.Vector3(), size: 0.17, bright: 1.6, soft: 0 })));
  const pulsePts = new THREE.Points(pulseGeo, pulseMat); pulsePts.renderOrder = 3; pulsePts.frustumCulled = false; group.add(pulsePts);
  const inner = edges.map((e) => (Math.abs(nodes[e.i].p.x) < Math.abs(nodes[e.j].p.x) ? e.i : e.j));
  const spawn = (p) => { p.e = Math.floor(rand() * edges.length); p.from = inner[p.e]; p.s = rand(); p.speed = 0.8 + rand() * 0.9; };
  pulses.forEach(spawn);
  const hop = (p) => {
    const e = edges[p.e], at = p.from === e.i ? e.j : e.i;
    const options = adj[at].filter((k) => k !== p.e);
    const outward = options.filter((k) => { const o = edges[k], other = o.i === at ? o.j : o.i; return Math.abs(nodes[other].p.x) >= Math.abs(nodes[at].p.x); });
    const list = outward.length && rand() < 0.8 ? outward : options;
    if (!list.length) { spawn(p); p.s = 0; return; }
    p.e = list[Math.floor(rand() * list.length)]; p.from = at; p.s = 0;
  };
  function update(dt) {
    const pos = pulseGeo.attributes.position;
    pulses.forEach((p, i) => {
      p.s += (dt * p.speed) / Math.max(edges[p.e].len, 0.3);
      if (p.s >= 1) hop(p);
      const e = edges[p.e];
      bez(e, p.from === e.i ? p.s : 1 - p.s, v);
      pos.setXYZ(i, v.x, v.y, v.z);
    });
    pos.needsUpdate = true;
  }
  return { group, update };
}

/* ------------------------------------------------------------------ */
async function start() {
  if (!host || !supportsWebGL()) return;
  const lite = small();

  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: lite ? "low-power" : "high-performance" });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, lite ? 1.25 : 1.6));
  renderer.setClearColor(0x000000, 0);
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.1;
  renderer.domElement.className = "hx-gl";
  host.appendChild(renderer.domElement);

  const scene = new THREE.Scene();
  const pmrem = new THREE.PMREMGenerator(renderer);
  scene.environment = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;      // real reflections
  pmrem.dispose();

  const camera = new THREE.PerspectiveCamera(35, 1, 0.1, 100);
  scene.add(new THREE.AmbientLight(0x8fb4ff, 0.35));
  const keyLight = new THREE.DirectionalLight(0xffffff, 1.5); keyLight.position.set(-3, 5, 6); scene.add(keyLight);
  const rimA = new THREE.PointLight(0x22d3ee, 40, 16); scene.add(rimA);             // cyan rim light
  const rimB = new THREE.PointLight(0x3b82f6, 40, 16); scene.add(rimB);             // blue rim light
  const fill = new THREE.PointLight(0x60a5fa, 8, 20); fill.position.set(0, 1, 6); scene.add(fill);

  const glowMats = [];
  const glow = (m) => { glowMats.push(m); return m; };
  const shaderMat = (vs, fs, uniforms) => glow(new THREE.ShaderMaterial({ vertexShader: vs, fragmentShader: fs, uniforms,
    transparent: true, depthWrite: false }));
  const dot = glowDot(), mask = maskTexture(), plateTex = plateTexture(), circuit = circuitTexture();

  const world = new THREE.Group(); scene.add(world);

  /* --- light rays behind everything --- */
  const raysMat = shaderMat(PASS_VS, RAYS_FS, { uTime: { value: 0 }, uStrength: { value: 1 } });
  const rays = new THREE.Mesh(new THREE.PlaneGeometry(13, 13), raysMat);
  rays.position.set(0, 0.15, -3.8); rays.renderOrder = -2; world.add(rays);
  let raysBase = 1;

  /* --- the network --- */
  const nodeUniforms = () => ({ uTime: { value: 0 }, uScale: { value: 1000 }, uDrift: { value: 0 }, uCore: { value: new THREE.Color() }, uGlow: { value: new THREE.Color() } });
  const nodeMat = shaderMat(NODE_VS, NODE_FS, nodeUniforms());
  const pulseMat = shaderMat(NODE_VS, NODE_FS, nodeUniforms());
  const lineMat = shaderMat(LINE_VS, LINE_FS, { uTime: { value: 0 }, uA: { value: new THREE.Color() }, uB: { value: new THREE.Color() }, uGain: { value: 1 } });
  const net = buildNetwork(lite, nodeMat, lineMat, pulseMat); world.add(net.group);

  /* --- the shield --- */
  const shieldFloat = new THREE.Group(); world.add(shieldFloat);
  const shieldSpin = new THREE.Group(); shieldFloat.add(shieldSpin);

  const halo = new THREE.Sprite(glow(new THREE.SpriteMaterial({ map: dot, color: 0x2563eb, transparent: true, opacity: 0.28, depthWrite: false })));
  halo.scale.set(7.5, 8.5, 1); halo.position.z = -1.2; halo.renderOrder = 0; shieldFloat.add(halo);

  // bevelled metal frame
  const frameShape = shieldShape(1); frameShape.holes.push(new THREE.Path(shieldShape(0.88).getPoints(120).reverse()));
  const frameGeo = new THREE.ExtrudeGeometry(frameShape, { depth: 0.3, bevelEnabled: true, bevelThickness: 0.07, bevelSize: 0.06, bevelSegments: 5, curveSegments: 64 });
  frameGeo.translate(0, 0, -0.15);
  const metalMat = new THREE.MeshPhysicalMaterial({ color: 0x8fb3f0, metalness: 1, roughness: 0.26, clearcoat: 1, clearcoatRoughness: 0.1,
    envMapIntensity: 0.55, emissive: 0x1e40af, emissiveIntensity: 0.3 });
  const frame = new THREE.Mesh(bendSolid(frameGeo), metalMat); frame.renderOrder = 5; shieldSpin.add(frame);

  // one face's layers; the back face is the same group turned 180 degrees (the shield is biconvex)
  const face = new THREE.Group();
  const glassMat = new THREE.MeshPhysicalMaterial({ color: 0x1d4ed8, transparent: true, opacity: 0.4, roughness: 0.04, metalness: 0,
    clearcoat: 1, clearcoatRoughness: 0.03, envMapIntensity: 0.9, alphaMap: mask, depthWrite: false });
  const glass = new THREE.Mesh(sheet(0.9, 0.06), glassMat); glass.renderOrder = 1; face.add(glass);
  const plateMat = new THREE.MeshPhysicalMaterial({ map: plateTex, emissiveMap: plateTex, emissive: 0xffffff, emissiveIntensity: 0.16,
    transparent: true, opacity: 0.8, roughness: 0.1, metalness: 0.15, clearcoat: 1, clearcoatRoughness: 0.05, envMapIntensity: 0.8, alphaMap: mask, depthWrite: false });
  const PLATE = { scale: 0.74, z: 0.12, ridge: 0.12 };
  const plate = new THREE.Mesh(sheet(PLATE.scale, PLATE.z, PLATE.ridge), plateMat); plate.renderOrder = 2; face.add(plate);
  const circuitMat = shaderMat(SHEET_VS, CIRCUIT_FS, { uCircuit: { value: circuit }, uMask: { value: mask }, uTime: { value: 0 }, uStrength: { value: 1 },
    uA: { value: new THREE.Color(0x3b82f6) }, uB: { value: new THREE.Color(0xa5f3fc) } });
  const traces = new THREE.Mesh(sheet(PLATE.scale, PLATE.z + 0.008, PLATE.ridge), circuitMat); traces.renderOrder = 3; face.add(traces);
  const fxMat = shaderMat(SHEET_VS, FX_FS, { uMask: { value: mask }, uSweep: { value: -1 }, uStrength: { value: 1 }, uRim: { value: new THREE.Color(0x67e8f9) } });
  const fx = new THREE.Mesh(sheet(0.9, 0.13, (0.12 * 0.74) / 0.9 + 0.03), fxMat); fx.renderOrder = 4; face.add(fx);
  // three glowing borders: outer edge, inner frame edge, plate edge
  const borderOuter = glow(new THREE.MeshBasicMaterial({ color: 0x9fdcff, transparent: true, opacity: 1, depthWrite: false }));
  const borderInner = glow(new THREE.MeshBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.95, depthWrite: false }));
  const borderPlate = glow(new THREE.MeshBasicMaterial({ color: 0x93c5fd, transparent: true, opacity: 0.85, depthWrite: false }));
  const borderHalo = glow(new THREE.MeshBasicMaterial({ color: 0x2563eb, transparent: true, opacity: 0.2, depthWrite: false }));
  for (const [geo, mat] of [
    [edgeTube(1.0, (x) => 0.225 + bulge(x), 0.032), borderOuter],
    [edgeTube(1.0, (x) => 0.2 + bulge(x), 0.12), borderHalo],
    [edgeTube(0.88, (x) => 0.226 + bulge(x), 0.022), borderInner],
    [edgeTube(PLATE.scale, (x) => sheetZ(x, PLATE.z, PLATE.ridge, PLATE.scale) + 0.012, 0.016), borderPlate],
  ]) { const m = new THREE.Mesh(geo, mat); m.renderOrder = 6; face.add(m); }
  const back = face.clone(); back.rotation.y = Math.PI;
  shieldSpin.add(face, back);

  // light pulses travelling along the shield's outline, on both faces
  const outline = shieldShape(1.0).getSpacedPoints(400).map((p) => new THREE.Vector3(p.x, p.y, 0.235 + bulge(p.x)));
  const comets = [];
  for (const [group, offset] of [[face, 0], [back, 0.5]]) {
    for (let k = 0; k < 2; k += 1) {
      const c = new THREE.Sprite(glow(new THREE.SpriteMaterial({ map: dot, color: 0xa5f3fc, transparent: true, opacity: 0.95, depthWrite: false })));
      c.scale.set(0.42, 0.42, 1); c.renderOrder = 7; group.add(c);
      comets.push({ c, offset: offset + k * 0.5, speed: k ? 0.07 : 0.05 });
    }
  }

  /* --- the key entities, orbiting slowly on a wide ellipse and linked like the real graph --- */
  const ORBIT = { rx: 6.3, ry: 1.25, y: -0.2, speed: 0.045 };
  const entityGroup = new THREE.Group(); shieldFloat.add(entityGroup);
  const entities = ENTITIES.map((spec, i) => {
    const sprite = new THREE.Sprite(new THREE.SpriteMaterial({ transparent: true, depthWrite: false, depthTest: false }));
    sprite.renderOrder = 30; entityGroup.add(sprite);
    return { spec, sprite, base: (i / ENTITIES.length) * Math.PI * 2, pos: new THREE.Vector3() };
  });
  function paintEntities() {
    const dark = isDark();
    for (const e of entities) {
      const { tex, aspect, dotX } = entityLabel(e.spec, dark);
      if (e.sprite.material.map) e.sprite.material.map.dispose();
      e.sprite.material.map = tex; e.sprite.material.needsUpdate = true;
      e.sprite.center.set(dotX, 0.5); e.h = 0.95; e.aspect = aspect;
    }
  }
  // links: each entity to the next (CVE-CWE-CAPEC-ATT&CK-Threat Intel-RAG-CVE) and a spoke into the shield
  const linkGeo = new THREE.BufferGeometry();
  linkGeo.setAttribute("position", new THREE.BufferAttribute(new Float32Array(entities.length * 4 * 3), 3));
  const linkMat = glow(new THREE.LineBasicMaterial({ color: 0x60a5fa, transparent: true, opacity: 0.5, depthWrite: false }));
  const links = new THREE.LineSegments(linkGeo, linkMat); links.renderOrder = 7; links.frustumCulled = false; entityGroup.add(links);
  const sparks = entities.map(() => {
    const sp = new THREE.Sprite(glow(new THREE.SpriteMaterial({ map: dot, color: 0xcffafe, transparent: true, opacity: 0.9, depthWrite: false })));
    sp.scale.set(0.32, 0.32, 1); sp.renderOrder = 8; entityGroup.add(sp); return sp;
  });

  /* --- energy rings around the shield, and on the floor --- */
  const rings = [];
  const ringLine = (radius, color, speed, opacity) => {
    const n = 256, pos = new Float32Array((n + 1) * 3), ang = new Float32Array(n + 1);
    for (let i = 0; i <= n; i += 1) { const a = (i / n) * Math.PI * 2; pos.set([Math.cos(a) * radius, Math.sin(a) * radius, 0], i * 3); ang[i] = i / n; }
    const g = new THREE.BufferGeometry(); g.setAttribute("position", new THREE.BufferAttribute(pos, 3)); g.setAttribute("aAng", new THREE.BufferAttribute(ang, 1));
    const mat = shaderMat(RING_VS, RING_FS, { uTime: { value: 0 }, uSpeed: { value: speed }, uColor: { value: new THREE.Color(color) }, uOpacity: { value: opacity } });
    const line = new THREE.Line(g, mat); line.renderOrder = 8; rings.push({ line, mat, base: opacity });
    return line;
  };
  const r1 = ringLine(2.85, 0x7dd3fc, 0.11, 0.9); r1.rotation.set(1.42, 0, 0.08); r1.position.y = -0.5; shieldFloat.add(r1);
  const FLOOR = -3.25;
  for (const [r, c, s, o] of [[1.4, 0x93c5fd, 0.16, 0.8], [2.6, 0x3b82f6, -0.08, 0.4]]) {
    const l = ringLine(r, c, s, o); l.rotation.x = -Math.PI / 2; l.position.y = FLOOR; l.renderOrder = 1; world.add(l);
  }

  /* --- floor: horizon line, light pool, hotspot and a lens-flare streak --- */
  const sprite = (color, opacity, sx, sy, x, y, z, order) => {
    const s = new THREE.Sprite(glow(new THREE.SpriteMaterial({ map: dot, color, transparent: true, opacity, depthWrite: false })));
    s.scale.set(sx, sy, 1); s.position.set(x, y, z); s.renderOrder = order; world.add(s); return s;
  };
  const horizon = new THREE.Mesh(new THREE.PlaneGeometry(14, 0.03), glow(new THREE.MeshBasicMaterial({ color: 0x93c5fd, transparent: true, opacity: 0.85, depthWrite: false })));
  horizon.position.set(0, FLOOR, -0.6); horizon.renderOrder = 1; world.add(horizon);
  const horizonGlow = sprite(0x2563eb, 0.5, 13, 1.3, 0, FLOOR, -0.7, 0);
  const pool = sprite(0x3b82f6, 0.6, 6, 1.1, 0, FLOOR - 0.05, -0.2, 1);
  const hotspot = sprite(0xe0f2fe, 1, 2.6, 0.55, 0, FLOOR, 0.1, 9);
  const streak = sprite(0x7dd3fc, 0.7, 11, 0.09, 0, FLOOR, 0.15, 9);
  const reflect = sprite(0x3b82f6, 0.35, 1.6, 3.2, 0, FLOOR - 1.1, -0.1, 1);             // the shield's glow mirrored on the floor
  const glint = sprite(0xffffff, 0.0, 2.4, 0.07, 0, 0, 0.6, 10); shieldFloat.add(glint);  // a flare across the rim now and then

  /* --- theme --- */
  let bloomOn = false;
  function applyTheme() {
    const dark = isDark();
    for (const m of glowMats) { m.blending = dark ? THREE.AdditiveBlending : THREE.NormalBlending; m.needsUpdate = true; }
    bloomOn = dark && !lite;
    renderer.domElement.classList.toggle("hx-gl--bloom", bloomOn);
    nodeMat.uniforms.uCore.value.setHex(dark ? 0xe0fbff : 0x1e40af); nodeMat.uniforms.uGlow.value.setHex(dark ? 0x2563eb : 0x60a5fa);
    pulseMat.uniforms.uCore.value.setHex(dark ? 0xffffff : 0x1d4ed8); pulseMat.uniforms.uGlow.value.setHex(dark ? 0x22d3ee : 0x38bdf8);
    lineMat.uniforms.uA.value.setHex(dark ? 0x1d4ed8 : 0x93c5fd); lineMat.uniforms.uB.value.setHex(dark ? 0x67e8f9 : 0x1d4ed8);
    lineMat.uniforms.uGain.value = dark ? 1.9 : 0.9;
    raysBase = dark ? 0.42 : 0.2;
    fxMat.uniforms.uStrength.value = dark ? 0.42 : 0.4;
    circuitMat.uniforms.uStrength.value = dark ? 1 : 0.7;
    glassMat.opacity = dark ? 0.4 : 0.42;
    plateMat.emissiveIntensity = dark ? 0.22 : 0.1;
    metalMat.emissiveIntensity = dark ? 0.3 : 0.08;
    halo.material.opacity = dark ? 0.28 : 0.12;
    horizon.material.color.setHex(dark ? 0x93c5fd : 0x3b82f6); horizon.material.opacity = dark ? 0.85 : 0.45;
    horizonGlow.material.opacity = dark ? 0.5 : 0.12; pool.material.opacity = dark ? 0.6 : 0.2;
    hotspot.material.opacity = dark ? 0.75 : 0.35; streak.material.opacity = dark ? 0.7 : 0.25; reflect.material.opacity = dark ? 0.35 : 0.1;
    rimA.intensity = dark ? 16 : 6; rimB.intensity = dark ? 16 : 6;
    for (const r of rings) r.mat.uniforms.uOpacity.value = r.base * (dark ? 1 : 0.6);
    renderer.toneMappingExposure = dark ? 0.92 : 1.0;
  }
  applyTheme();
  paintEntities();
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(paintEntities);
  document.addEventListener("themechange", () => setTimeout(() => { applyTheme(); paintEntities(); }, 30));

  /* --- bloom (dark theme, larger screens) --- */
  const composer = new EffectComposer(renderer);
  composer.addPass(new RenderPass(scene, camera, null, new THREE.Color(0x080d1b), 1));       // the page's dark background
  composer.addPass(new UnrealBloomPass(new THREE.Vector2(256, 256), 0.55, 0.35, 0.68));
  composer.addPass(new OutputPass());

  /* --- size: shield centred, wings extending sideways --- */
  function resize() {
    const w = renderer.domElement.clientWidth || host.clientWidth, h = renderer.domElement.clientHeight || host.clientHeight;
    if (!w || !h) return;
    renderer.setSize(w, h, false);
    composer.setPixelRatio(renderer.getPixelRatio()); composer.setSize(w, h);
    camera.aspect = w / h;
    const f = Math.tan(THREE.MathUtils.degToRad(camera.fov) / 2);
    const wings = camera.aspect < 1 ? 5.2 : 7.4;
    camera.userData.distance = Math.max(10.2 / 2 / f, wings / (f * camera.aspect));
    camera.updateProjectionMatrix();
    const scale = (h * renderer.getPixelRatio()) / (2 * f);
    for (const m of [nodeMat, pulseMat]) m.uniforms.uScale.value = scale;
  }
  new ResizeObserver(resize).observe(renderer.domElement);
  resize();

  /* --- mouse parallax --- */
  const pointer = new THREE.Vector2(), ease = new THREE.Vector2();
  const ndc = new THREE.Vector2(9, 9), centre = new THREE.Vector3(), corner = new THREE.Vector3();
  let hover = 0;
  window.addEventListener("pointermove", (e) => {
    pointer.set(e.clientX / window.innerWidth - 0.5, e.clientY / window.innerHeight - 0.5);
    const b = renderer.domElement.getBoundingClientRect();
    ndc.set(((e.clientX - b.left) / b.width) * 2 - 1, -((e.clientY - b.top) / b.height) * 2 + 1);
  }, { passive: true });

  let onScreen = true, frameId = 0, last = 0;
  new IntersectionObserver((list) => { onScreen = list[0].isIntersecting; }).observe(host);
  const clock = new THREE.Clock();
  const timed = [raysMat, nodeMat, pulseMat, lineMat, circuitMat, ...rings.map((r) => r.mat)];

  function render() {
    frameId = requestAnimationFrame(render);
    if (!onScreen || !document.body.classList.contains("entry") || !host.offsetParent) return;
    if (document.documentElement.classList.contains("vt")) return;   // hold still while the page switches
    const t = reduce.matches ? 2.0 : clock.getElapsedTime();
    const dt = Math.min(0.05, Math.max(0, t - last)); last = t;      // delta time: same speed at any frame rate
    const dark = isDark();

    ease.lerp(pointer, 1 - Math.pow(0.03, dt || 0.016));
    camera.position.set(ease.x * 0.8, 0.45 - ease.y * 0.4, camera.userData.distance || 14);
    camera.lookAt(0, -0.85, 0);
    world.rotation.y = ease.x * 0.12;
    shieldFloat.rotation.x = ease.y * 0.08;                          // the shield leans toward the mouse a little
    net.group.position.set(-ease.x * 0.35, ease.y * 0.15, 0);        // the background graph drifts a little (parallax)
    net.group.rotation.y = Math.sin(t * 0.08) * 0.12;                // and sways slowly, opposite to the orbits

    shieldSpin.rotation.y = t * ((Math.PI * 2) / 15);                // one full turn every 15 s
    shieldFloat.position.y = 0.15 + Math.sin(t * 0.8) * 0.12;        // floating
    const facing = Math.cos(shieldSpin.rotation.y) >= 0;             // draw the face toward the camera last
    face.renderOrder = facing ? 20 : 10; back.renderOrder = facing ? 10 : 20;

    for (const m of timed) m.uniforms.uTime.value = t;
    fxMat.uniforms.uSweep.value = -0.5 + ((t % 7) / 2.4) * 2.6;      // a reflection crosses the glass every 7 s
    const flare = (1 - (t % 6) / 6) ** 6;                            // an energy flare every 6 s
    raysMat.uniforms.uStrength.value = raysBase * (0.9 + 0.5 * flare + 0.5 * hover);
    // hover: is the pointer over the shield? (its projected box)
    shieldFloat.getWorldPosition(centre).project(camera);
    corner.set(2.1, 2.7, 0).add(shieldFloat.getWorldPosition(new THREE.Vector3())).project(camera);
    const over = Math.abs(ndc.x - centre.x) < Math.abs(corner.x - centre.x) && Math.abs(ndc.y - centre.y) < Math.abs(corner.y - centre.y) * 1.05;
    hover += ((over ? 1 : 0) - hover) * Math.min(1, dt * 4);
    const breathe = 0.5 + 0.5 * Math.sin(t * 0.9);                   // a slow breathing glow
    borderOuter.opacity = Math.min(1, 0.6 + 0.25 * breathe + 0.25 * hover);
    halo.material.opacity = (dark ? 0.28 : 0.12) * (0.8 + 0.4 * breathe + 0.9 * hover);
    for (const k of comets) {                                        // pulses along the outline
      const u = ((t * k.speed + k.offset) % 1 + 1) % 1, pt = outline[Math.floor(u * (outline.length - 1))];
      k.c.position.copy(pt); k.c.material.opacity = (dark ? 0.95 : 0.6) * (0.7 + 0.3 * hover);
    }
    // entities: orbit, depth (behind the shield = dimmer, smaller), fade while passing behind the text
    const lp = linkGeo.attributes.position;
    entities.forEach((e, i) => {
      const a = e.base + t * ORBIT.speed;
      e.pos.set(Math.cos(a) * ORBIT.rx, ORBIT.y + Math.sin(a) * ORBIT.ry * 0.35 + Math.sin(t * 0.7 + i) * 0.08, Math.sin(a) * ORBIT.ry * 2.2);
      e.sprite.position.copy(e.pos);
      const front = e.pos.z > 0, sideways = THREE.MathUtils.smoothstep(Math.abs(e.pos.x), 1.6, 3.8);
      const s = (front ? 1 : 0.8) * (1 + 0.12 * hover);
      e.sprite.scale.set(e.h * e.aspect * s, e.h * s, 1);
      e.sprite.material.opacity = (front ? 1 : 0.55) * (0.25 + 0.75 * sideways);
      e.sprite.renderOrder = front ? 30 : 2;
    });
    entities.forEach((e, i) => {
      const n = entities[(i + 1) % entities.length];
      lp.setXYZ(i * 4, e.pos.x, e.pos.y, e.pos.z); lp.setXYZ(i * 4 + 1, n.pos.x, n.pos.y, n.pos.z);
      lp.setXYZ(i * 4 + 2, e.pos.x, e.pos.y, e.pos.z); lp.setXYZ(i * 4 + 3, e.pos.x * 0.32, e.pos.y * 0.5 + 0.2, e.pos.z * 0.2);
      const u = (t * 0.35 + i / entities.length) % 1;               // a pulse running along each relation
      sparks[i].position.lerpVectors(e.pos, n.pos, u);
      sparks[i].material.opacity = (dark ? 0.9 : 0.55) * Math.sin(u * Math.PI);
    });
    lp.needsUpdate = true;
    linkMat.opacity = (dark ? 0.42 : 0.35) * (0.8 + 0.3 * breathe);
    borderHalo.opacity = (dark ? 0.16 : 0.1) * (1 + 1.2 * flare);
    glint.material.opacity = (dark ? 0.8 : 0.3) * Math.pow(Math.max(0, Math.sin(t * 0.9)), 30);
    glint.position.y = 2.1 + Math.sin(t * 0.45) * 0.3;
    rimA.position.set(Math.cos(t * 0.5) * 3.6, 1.6, -1.8 + Math.sin(t * 0.5) * 1.5);
    rimB.position.set(Math.cos(t * 0.5 + Math.PI) * 3.6, -0.8, -1.8 + Math.sin(t * 0.5 + Math.PI) * 1.5);
    r1.rotation.z = t * 0.05;                                        // the ring turns
    net.update(reduce.matches ? 0 : dt);

    if (bloomOn) composer.render(); else renderer.render(scene, camera);
    if (reduce.matches) cancelAnimationFrame(frameId);
  }
  document.addEventListener("visibilitychange", () => { cancelAnimationFrame(frameId); if (!document.hidden) frameId = requestAnimationFrame(render); });

  try { await renderer.compileAsync(scene, camera); } catch (error) { /* older browsers compile on first draw */ }
  window.__hx3d = true;
  host.classList.add("hx-webgl");
  frameId = requestAnimationFrame(render);
  requestAnimationFrame(() => requestAnimationFrame(() => renderer.domElement.classList.add("ready")));
}

start().catch((error) => console.warn("3D hero unavailable, using the fallback:", error));
