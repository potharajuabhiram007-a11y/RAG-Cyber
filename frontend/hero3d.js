/* CyberIntelliX hero, rendered with Three.js only.
 *
 * A glass security shield (extruded 3D shape with glowing rims, a centre ridge and
 * circuit traces) stands in the middle and sways gently. Wide glowing orbit rings
 * circle it with light dots running along them, and seven glass "pill" labels -
 * CVE, CWE, CAPEC, ATT&CK, RAG, AI, Threat Intel - rotate around it, evenly spaced,
 * passing behind the shield on the far side.
 *
 * Kept light: a few dozen draw calls, no shadows, no post-processing, pixel ratio
 * capped, and the loop pauses while the hero is off screen or the tab is hidden.
 * If WebGL or Three.js is unavailable, the CSS hero (fx.js) stays on screen.
 */
import * as THREE from "https://cdn.jsdelivr.net/npm/three@0.170.0/build/three.module.min.js";

const host = document.querySelector(".hx");
const reduce = window.matchMedia("(prefers-reduced-motion: reduce)");
const isDark = () => document.documentElement.getAttribute("data-theme") === "dark";

const LABELS = [
  { key: "CVE",    text: "CVE",          tone: "#F43F5E", icon: "M12 3 4.5 6v5.5c0 4.6 3.2 8.2 7.5 9.5 4.3-1.3 7.5-4.9 7.5-9.5V6L12 3Zm0 5v5m0 3v.5" },
  { key: "CWE",    text: "CWE",          tone: "#F59E0B", icon: "M12 3 3 7.5 12 12l9-4.5L12 3ZM3 12l9 4.5 9-4.5M3 16.5 12 21l9-4.5" },
  { key: "CAPEC",  text: "CAPEC",        tone: "#A855F7", icon: "M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16Zm0 4a4 4 0 1 0 0 8 4 4 0 0 0 0-8Zm0 3.2a.8.8 0 1 0 0 1.6.8.8 0 0 0 0-1.6Z" },
  { key: "ATTACK", text: "ATT&CK",       tone: "#22D3EE", icon: "M12 3 2.5 20h19L12 3Zm0 6.5 4.2 7.5H7.8L12 9.5Z" },
  { key: "RAG",    text: "RAG",          tone: "#60A5FA", icon: "M5 6c0-1.7 3.1-3 7-3s7 1.3 7 3-3.1 3-7 3-7-1.3-7-3Zm0 0v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3" },
  { key: "AI",     text: "AI",           tone: "#C084FC", icon: "M9 4a3 3 0 0 0-3 3 3 3 0 0 0-2 5 3 3 0 0 0 2 5 3 3 0 0 0 3 3 2 2 0 0 0 3-1.7V5.7A2 2 0 0 0 9 4Zm6 0a3 3 0 0 1 3 3 3 3 0 0 1 2 5 3 3 0 0 1-2 5 3 3 0 0 1-3 3 2 2 0 0 1-3-1.7M9 9h1m-1 6h1m5-6h-1m1 6h-1" },
  { key: "INTEL",  text: "Threat Intel", tone: "#38BDF8", icon: "M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7ZM12 2v3m0 14v3M2 12h3m14 0h3M4.9 4.9 7 7m10 10 2.1 2.1M19.1 4.9 17 7M7 17l-2.1 2.1" },
];

// main orbit: the labels ride on it; a second, slightly different ring is decoration
const ORBIT = { radius: 3.45, tilt: 1.12, roll: -0.06, speed: 0.16 };
const DECOR = { radius: 3.05, tilt: 1.28, roll: 0.14, speed: -0.25 };
const BLUE = { rim: 0x3b82f6, bright: 0x60a5fa, cyan: 0x22d3ee, deep: 0x1e3a8a };

function supportsWebGL() {
  try {
    const c = document.createElement("canvas");
    return !!(window.WebGLRenderingContext && (c.getContext("webgl2") || c.getContext("webgl")));
  } catch (error) { return false; }
}

function hexA(hex, alpha) {
  const m = /^#?([\da-f]{2})([\da-f]{2})([\da-f]{2})$/i.exec(hex);
  return m ? `rgba(${parseInt(m[1], 16)},${parseInt(m[2], 16)},${parseInt(m[3], 16)},${alpha})` : hex;
}

/* ---------------- the shield ---------------- */
const S = 1 / 46;                                         // SVG units -> world units
function shieldShape(scale = 1) {
  const k = S * scale, sh = new THREE.Shape();
  const p = (x, y) => [x * k, y * k];
  sh.moveTo(...p(0, 121));
  sh.bezierCurveTo(...p(27, 105), ...p(62, 97), ...p(94, 97));
  sh.lineTo(...p(94, 8));
  sh.bezierCurveTo(...p(94, -58), ...p(47, -105), ...p(0, -136));
  sh.bezierCurveTo(...p(-47, -105), ...p(-94, -58), ...p(-94, 8));
  sh.lineTo(...p(-94, 97));
  sh.bezierCurveTo(...p(-62, 97), ...p(-27, 105), ...p(0, 121));
  return sh;
}

function circuitTexture() {
  const c = document.createElement("canvas");
  c.width = 512; c.height = 700;
  const g = c.getContext("2d");
  g.lineCap = "round"; g.lineJoin = "round";
  // traces: right-angled runs from the centre ridge outwards, ending in nodes
  const traces = [
    [[256, 120], [256, 170], [330, 170], [330, 230], [390, 230]], [[256, 120], [256, 170], [182, 170], [182, 230], [122, 230]],
    [[256, 260], [300, 300], [300, 380], [380, 380]], [[256, 260], [212, 300], [212, 380], [132, 380]],
    [[256, 420], [320, 470], [320, 520]], [[256, 420], [192, 470], [192, 520]],
    [[256, 540], [256, 600]], [[330, 230], [330, 300]], [[182, 230], [182, 300]],
    [[390, 230], [420, 260], [420, 330]], [[122, 230], [92, 260], [92, 330]],
  ];
  for (const [width, alpha] of [[7, 0.18], [2.2, 0.95]]) {
    g.lineWidth = width; g.strokeStyle = `rgba(147,197,253,${alpha})`;
    for (const t of traces) { g.beginPath(); g.moveTo(...t[0]); t.slice(1).forEach((pt) => g.lineTo(...pt)); g.stroke(); }
  }
  g.fillStyle = "#BFDBFE";
  for (const t of traces) { const [x, y] = t[t.length - 1]; g.beginPath(); g.arc(x, y, 5, 0, Math.PI * 2); g.fill(); }
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  return tex;
}

/* map a shape geometry's UVs onto its bounding box, so a texture covers it once */
function boxUV(geometry) {
  geometry.computeBoundingBox();
  const b = geometry.boundingBox, pos = geometry.attributes.position, uv = geometry.attributes.uv;
  for (let i = 0; i < pos.count; i += 1) {
    uv.setXY(i, (pos.getX(i) - b.min.x) / (b.max.x - b.min.x), (pos.getY(i) - b.min.y) / (b.max.y - b.min.y));
  }
  uv.needsUpdate = true;
}

function tubeAlong(shape, radius, segments = 240) {
  const pts = shape.getSpacedPoints(160).map((p) => new THREE.Vector3(p.x, p.y, 0));
  return new THREE.TubeGeometry(new THREE.CatmullRomCurve3(pts, true), segments, radius, 6, true);
}

/* ---------------- glass pill labels ---------------- */
function pillCanvas(spec, hot) {
  const dark = isDark(), k = 3;
  const font = `600 ${17 * k}px "Inter", "Space Grotesk", system-ui, sans-serif`;
  const measure = document.createElement("canvas").getContext("2d");
  measure.font = font;
  const h = 50 * k, padL = 16 * k, icon = 24 * k, gap = 11 * k, padR = 22 * k;
  const w = Math.ceil(padL + icon + gap + measure.measureText(spec.text).width + padR);
  const m = 16 * k;                                                   // margin for the glow
  const c = document.createElement("canvas");
  c.width = w + m * 2; c.height = h + m * 2;
  const g = c.getContext("2d");
  const pill = new Path2D();
  pill.roundRect(m, m, w, h, h / 2);
  // body
  g.shadowColor = dark ? hexA("#3B82F6", hot ? 0.9 : 0.6) : hexA("#2563EB", hot ? 0.45 : 0.22);
  g.shadowBlur = (hot ? 26 : 16) * k;
  const fill = g.createLinearGradient(0, m, 0, m + h);
  if (dark) { fill.addColorStop(0, "rgba(30,58,138,0.55)"); fill.addColorStop(1, "rgba(6,12,30,0.82)"); }
  else { fill.addColorStop(0, "rgba(255,255,255,0.97)"); fill.addColorStop(1, "rgba(234,241,255,0.95)"); }
  g.fillStyle = fill; g.fill(pill);
  g.shadowBlur = 0;
  // rim
  g.lineWidth = (hot ? 3 : 2) * k;
  const rim = g.createLinearGradient(m, m, m + w, m + h);
  rim.addColorStop(0, dark ? "#93C5FD" : "#60A5FA"); rim.addColorStop(0.5, dark ? "#3B82F6" : "#2563EB"); rim.addColorStop(1, dark ? "#22D3EE" : "#0EA5E9");
  g.strokeStyle = rim; g.stroke(pill);
  // glass highlight
  g.save(); g.clip(pill);
  const shine = g.createLinearGradient(0, m, 0, m + h * 0.6);
  shine.addColorStop(0, dark ? "rgba(255,255,255,0.22)" : "rgba(255,255,255,0.9)"); shine.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = shine; g.fillRect(m, m, w, h * 0.6);
  g.restore();
  // icon in the entity's colour
  g.save();
  g.translate(m + padL, m + (h - icon) / 2); g.scale(icon / 24, icon / 24);
  g.lineWidth = 2; g.lineCap = "round"; g.lineJoin = "round"; g.strokeStyle = spec.tone;
  if (dark) { g.shadowColor = spec.tone; g.shadowBlur = 6; }
  g.stroke(new Path2D(spec.icon));
  g.restore();
  // text
  g.font = font; g.textBaseline = "middle";
  g.fillStyle = dark ? "#EEF4FF" : "#0F172A";
  g.fillText(spec.text, m + padL + icon + gap, m + h / 2 + k);
  return c;
}

function dotTexture() {
  const c = document.createElement("canvas");
  c.width = c.height = 64;
  const g = c.getContext("2d");
  const grad = g.createRadialGradient(32, 32, 0, 32, 32, 32);
  grad.addColorStop(0, "rgba(255,255,255,1)"); grad.addColorStop(0.3, "rgba(255,255,255,0.8)"); grad.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = grad; g.fillRect(0, 0, 64, 64);
  return new THREE.CanvasTexture(c);
}

function ringPoints(radius, count = 200) {
  const pts = [];
  for (let i = 0; i <= count; i += 1) { const a = (i / count) * Math.PI * 2; pts.push(new THREE.Vector3(Math.cos(a) * radius, Math.sin(a) * radius, 0)); }
  return pts;
}

async function start() {
  if (!host || !supportsWebGL()) return;

  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "low-power" });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.75));
  renderer.setClearColor(0x000000, 0);
  renderer.domElement.className = "hx-gl";
  host.appendChild(renderer.domElement);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(36, 1, 0.1, 100);
  const lookAt = new THREE.Vector3(0, 0, 0);
  scene.add(new THREE.AmbientLight(0x9cc2ff, 1.1));
  const key = new THREE.DirectionalLight(0xffffff, 2.2); key.position.set(-3, 4, 6); scene.add(key);
  const rimLight = new THREE.PointLight(0x22d3ee, 18, 12); rimLight.position.set(3, -1, 3); scene.add(rimLight);

  const dots = dotTexture();
  const glowMaterials = [];                        // switched between additive (dark) and normal (light)
  const glow = (material) => { glowMaterials.push(material); return material; };

  /* --- shield --- */
  const shield = new THREE.Group();
  shield.position.y = 0.25;
  const outer = shieldShape(1);
  const body = new THREE.Mesh(
    new THREE.ExtrudeGeometry(outer, { depth: 0.32, bevelEnabled: true, bevelThickness: 0.12, bevelSize: 0.1, bevelSegments: 4, curveSegments: 48 }),
    new THREE.MeshPhongMaterial({ color: BLUE.deep, emissive: 0x0b1a4a, specular: 0x9cc8ff, shininess: 140,
                                  transparent: true, opacity: 0.55, depthWrite: false }));
  body.position.z = -0.22;
  body.renderOrder = 10;
  shield.add(body);
  // circuit face, slightly in front of the glass
  const faceGeo = new THREE.ShapeGeometry(shieldShape(0.84), 48);
  boxUV(faceGeo);
  const face = new THREE.Mesh(faceGeo, glow(new THREE.MeshBasicMaterial({ map: circuitTexture(), transparent: true, opacity: 0.85, depthWrite: false })));
  face.position.set(0, 0.15 * S * 46 * 0, 0.24); face.renderOrder = 12;
  shield.add(face);
  // glowing rims: outer edge, inner edge, centre ridge
  const rimMat = glow(new THREE.MeshBasicMaterial({ color: BLUE.bright, transparent: true, opacity: 0.95, depthWrite: false }));
  const outerRim = new THREE.Mesh(tubeAlong(outer, 0.05), rimMat); outerRim.position.z = 0.26; outerRim.renderOrder = 13;
  const innerRim = new THREE.Mesh(tubeAlong(shieldShape(0.84), 0.022), glow(new THREE.MeshBasicMaterial({ color: BLUE.cyan, transparent: true, opacity: 0.7, depthWrite: false })));
  innerRim.position.z = 0.26; innerRim.renderOrder = 13;
  const ridge = new THREE.Mesh(new THREE.TubeGeometry(new THREE.LineCurve3(new THREE.Vector3(0, 121 * S * 0.84, 0.27), new THREE.Vector3(0, -136 * S * 0.84, 0.27)), 8, 0.018, 6),
    glow(new THREE.MeshBasicMaterial({ color: BLUE.bright, transparent: true, opacity: 0.55, depthWrite: false })));
  ridge.renderOrder = 13;
  shield.add(outerRim, innerRim, ridge);
  // halo behind the shield
  const halo = new THREE.Sprite(glow(new THREE.SpriteMaterial({ map: dots, color: BLUE.rim, transparent: true, opacity: 0.55, depthWrite: false })));
  halo.scale.set(7.5, 7.5, 1); halo.position.z = -0.6; halo.renderOrder = 2;
  shield.add(halo);
  scene.add(shield);

  /* --- rings --- */
  function makeRing(spec, color, opacity) {
    const group = new THREE.Group();
    group.rotation.set(spec.tilt, 0, spec.roll);
    const line = new THREE.Line(new THREE.BufferGeometry().setFromPoints(ringPoints(spec.radius)),
      glow(new THREE.LineBasicMaterial({ color, transparent: true, opacity, depthWrite: false })));
    line.renderOrder = 5;
    group.add(line);
    // light dots running along the ring
    const n = 10, pos = new Float32Array(n * 3);
    const dotsGeo = new THREE.BufferGeometry(); dotsGeo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    const pts = new THREE.Points(dotsGeo, glow(new THREE.PointsMaterial({ map: dots, color, size: 0.2, transparent: true, depthWrite: false })));
    pts.renderOrder = 6;
    group.add(pts);
    scene.add(group);
    return { spec, group, line, pts, n, pos };
  }
  const mainRing = makeRing(ORBIT, BLUE.bright, 0.55);
  const decorRing = makeRing(DECOR, BLUE.cyan, 0.32);
  const carrier = new THREE.Group();
  mainRing.group.add(carrier);

  /* --- labels --- */
  const labels = LABELS.map((spec, index) => {
    const sprite = new THREE.Sprite(new THREE.SpriteMaterial({ transparent: true, depthTest: false, depthWrite: false }));
    const angle = (index / LABELS.length) * Math.PI * 2;
    sprite.position.set(Math.cos(angle) * ORBIT.radius, Math.sin(angle) * ORBIT.radius, 0);
    sprite.userData.key = spec.key;
    carrier.add(sprite);
    return { spec, sprite, hot: false, world: new THREE.Vector3(), base: new THREE.Vector2(1, 1), bob: Math.random() * 6.28 };
  });
  function paintLabels() {
    for (const label of labels) {
      const canvas = pillCanvas(label.spec, label.hot);
      const texture = new THREE.CanvasTexture(canvas);
      texture.colorSpace = THREE.SRGBColorSpace;
      texture.anisotropy = 4;
      if (label.sprite.material.map) label.sprite.material.map.dispose();
      label.sprite.material.map = texture;
      label.sprite.material.needsUpdate = true;
      const height = 0.92;
      label.base.set(height * canvas.width / canvas.height, height);
    }
  }

  /* --- theme: glows add light on dark backgrounds, but vanish on white, so they
         switch to normal blending (and deeper colours) in the light theme --- */
  function applyTheme() {
    const dark = isDark();
    for (const m of glowMaterials) { m.blending = dark ? THREE.AdditiveBlending : THREE.NormalBlending; m.needsUpdate = true; }
    rimMat.color.setHex(dark ? BLUE.bright : 0x2563eb);
    halo.material.opacity = dark ? 0.55 : 0.22;
    halo.material.color.setHex(dark ? BLUE.rim : 0x93c5fd);
    body.material.opacity = dark ? 0.55 : 0.62;
    body.material.color.setHex(dark ? BLUE.deep : 0x2563eb);
    body.material.emissive.setHex(dark ? 0x0b1a4a : 0x1e3a8a);
    rimLight.intensity = dark ? 18 : 3;                            // a strong cyan hotspot looks wrong on white
    key.intensity = dark ? 2.2 : 1.4;
    mainRing.line.material.color.setHex(dark ? BLUE.bright : 0x2563eb);
    mainRing.line.material.opacity = dark ? 0.55 : 0.6;
    decorRing.line.material.color.setHex(dark ? BLUE.cyan : 0x0ea5e9);
    decorRing.line.material.opacity = dark ? 0.32 : 0.42;
    paintLabels();
  }
  applyTheme();
  document.addEventListener("themechange", () => setTimeout(applyTheme, 30));
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(paintLabels);

  /* --- size: keep the whole orbit and its labels in frame --- */
  function resize() {
    const w = renderer.domElement.clientWidth || host.clientWidth, h = renderer.domElement.clientHeight || host.clientHeight;
    if (!w || !h) return;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    const fov = THREE.MathUtils.degToRad(camera.fov);
    const needH = 7.8, needW = 2 * (ORBIT.radius + 1.35);
    camera.userData.distance = Math.max(needH / 2 / Math.tan(fov / 2), needW / 2 / (Math.tan(fov / 2) * camera.aspect));
    camera.updateProjectionMatrix();
  }
  new ResizeObserver(resize).observe(renderer.domElement);
  resize();

  /* --- pointer: a little parallax, and hover on labels --- */
  const pointer = new THREE.Vector2(), ndc = new THREE.Vector2(2, 2), raycaster = new THREE.Raycaster();
  window.addEventListener("pointermove", (e) => {
    pointer.set(e.clientX / window.innerWidth - 0.5, e.clientY / window.innerHeight - 0.5);
    const box = renderer.domElement.getBoundingClientRect();
    ndc.set(((e.clientX - box.left) / box.width) * 2 - 1, -((e.clientY - box.top) / box.height) * 2 + 1);
  }, { passive: true });

  /* --- only animate while the hero is visible --- */
  let onScreen = true, frame = 0;
  new IntersectionObserver((entries) => { onScreen = entries[0].isIntersecting; }).observe(host);

  const clock = new THREE.Clock(), toCamera = new THREE.Vector3();
  function render() {
    frame = requestAnimationFrame(render);
    if (!onScreen || !document.body.classList.contains("entry") || !host.offsetParent) return;
    const t = reduce.matches ? 0 : clock.getElapsedTime();
    const d = camera.userData.distance || 12;
    camera.position.set(pointer.x * 0.8, 0.35 - pointer.y * 0.5, d);
    camera.lookAt(lookAt);

    shield.rotation.y = Math.sin(t * 0.45) * 0.32;                 // the glass shield sways
    shield.position.y = 0.25 + Math.sin(t * 0.9) * 0.06;
    carrier.rotation.z = t * ORBIT.speed;                          // the labels rotate
    for (const ring of [mainRing, decorRing]) {                    // light dots run along the rings
      for (let i = 0; i < ring.n; i += 1) {
        const a = (i / ring.n) * Math.PI * 2 + t * ring.spec.speed * 1.6;
        ring.pos.set([Math.cos(a) * ring.spec.radius, Math.sin(a) * ring.spec.radius, 0], i * 3);
      }
      ring.pts.geometry.attributes.position.needsUpdate = true;
    }

    raycaster.setFromCamera(ndc, camera);
    const hit = raycaster.intersectObjects(labels.map((l) => l.sprite), false)[0];
    const hotKey = hit ? hit.object.userData.key : null;
    let repaint = false;
    camera.getWorldDirection(toCamera).negate();
    for (const label of labels) {
      const hot = label.spec.key === hotKey;
      if (hot !== label.hot) { label.hot = hot; repaint = true; }
      label.sprite.getWorldPosition(label.world);
      const depth = label.world.dot(toCamera);                     // + in front of the shield
      const near = THREE.MathUtils.clamp((depth + ORBIT.radius) / (2 * ORBIT.radius), 0, 1);
      const s = (0.74 + 0.34 * near) * (hot ? 1.14 : 1);
      label.sprite.scale.set(label.base.x * s, label.base.y * s, 1);
      label.sprite.position.z = reduce.matches ? 0 : Math.sin(t * 1.4 + label.bob) * 0.05;
      label.sprite.material.opacity = 0.5 + 0.5 * near;
      label.sprite.renderOrder = depth >= 0 ? 30 : 1;               // behind or in front of the shield
    }
    if (repaint) paintLabels();
    renderer.render(scene, camera);
    if (reduce.matches) cancelAnimationFrame(frame);
  }
  document.addEventListener("visibilitychange", () => {
    cancelAnimationFrame(frame);
    if (!document.hidden) frame = requestAnimationFrame(render);
  });

  window.__hx3d = true;                                            // the CSS hero gives way
  host.classList.add("hx-webgl");
  frame = requestAnimationFrame(render);
}

start().catch((error) => console.warn("3D hero unavailable, using the fallback:", error));
