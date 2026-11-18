/* CyberIntelliX hero, rendered with Three.js (no other library).
 *
 * The shield artwork is a fixed plane in the middle of the scene. Seven labels -
 * CVE, CWE, CAPEC, ATT&CK, RAG, AI and Threat Intel - ride on three tilted orbit
 * rings centred on the shield's lock. Each ring turns at its own speed and its
 * labels are spaced evenly on it, so they never bunch up. Labels are sprites, so
 * they always face the viewer; they are drawn behind or in front of the shield
 * according to their depth. Light lines join every label to the lock, particles
 * of light travel along them, and the camera follows the mouse a little.
 *
 * If WebGL is not available, or Three.js cannot be loaded, nothing here runs and
 * the CSS version of the hero (fx.js) stays on screen.
 */
import * as THREE from "https://cdn.jsdelivr.net/npm/three@0.170.0/build/three.module.min.js";

const host = document.querySelector(".hx");
const reduce = window.matchMedia("(prefers-reduced-motion: reduce)");

const LABELS = {
  CVE:    { text: "CVE",          tone: ["#F43F5E", "#E11D48"], icon: "M9 9V7.5a3 3 0 0 1 6 0V9M7 9h10v6a5 5 0 0 1-10 0V9Zm-3 2h3m10 0h3M4 17h3.5m9 0H20M5 5l2 2.5m12-2.5-2 2.5M12 12v4" },
  CWE:    { text: "CWE",          tone: ["#F59E0B", "#D97706"], icon: "m8 7-5 5 5 5m8-10 5 5-5 5M14 4l-4 16" },
  CAPEC:  { text: "CAPEC",        tone: ["#A855F7", "#9333EA"], icon: "M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16Zm0 3.5a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9ZM12 2v3m0 14v3M2 12h3m14 0h3" },
  ATTACK: { text: "ATT&CK",       tone: ["#22D3EE", "#0891B2"], icon: "M12 3 2.5 20h19L12 3Zm0 6.5 4.2 7.5H7.8L12 9.5Z" },
  RAG:    { text: "RAG",          tone: ["#60A5FA", "#2563EB"], icon: "M6 4.8a2.2 2.2 0 1 0 0 4.4 2.2 2.2 0 0 0 0-4.4Zm12 0a2.2 2.2 0 1 0 0 4.4 2.2 2.2 0 0 0 0-4.4Zm-6 9.6a2.6 2.6 0 1 0 0 5.2 2.6 2.6 0 0 0 0-5.2ZM8 8.2 10.4 15M16 8.2 13.6 15M8.2 7h7.6" },
  AI:     { text: "AI",           tone: ["#A78BFA", "#7C3AED"], icon: "M8 6h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2Zm2.5 3.5h3a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-3a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1ZM9 3v3m6-3v3M9 18v3m6-3v3M3 9h3m-3 6h3m12-6h3m-3 6h3" },
  INTEL:  { text: "Threat Intel", tone: ["#38BDF8", "#0284C7"], icon: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18ZM3 12h18M12 3c2.6 2.5 3.9 5.5 3.9 9s-1.3 6.5-3.9 9c-2.6-2.5-3.9-5.5-3.9-9S9.4 5.5 12 3Z" },
};
// three rings: radius (world units), tilt towards the viewer, roll, speed (rad/s), labels
const RINGS = [
  // three nested rings leaning the same way, each a little smaller and steeper (different depth).
  // All seven labels are spaced evenly around the orbit (360/7 degrees apart) and every ring
  // turns at the same rate, so the spacing never changes and labels never bunch together.
  { radius: 3.00, tilt: 1.32, roll: -0.10, color: "#60A5FA" },
  { radius: 2.62, tilt: 1.22, roll: -0.10, color: "#A78BFA" },
  { radius: 2.26, tilt: 1.12, roll: -0.10, color: "#22D3EE" },
];
const ORDER = ["CVE", "CWE", "CAPEC", "ATTACK", "RAG", "AI", "INTEL"];   // label i rides ring i % 3
const SPEED = 0.18;                                                      // radians per second
const IMAGE = { src: "assets/hero-shield.jpg", width: 640, height: 941, lock: [0.555, 0.45] };
const PLANE_H = 6.0;
const PLANE_W = PLANE_H * IMAGE.width / IMAGE.height;
const CENTER = new THREE.Vector3((IMAGE.lock[0] - 0.5) * PLANE_W, (0.5 - IMAGE.lock[1]) * PLANE_H, 0);

function supportsWebGL() {
  try {
    const c = document.createElement("canvas");
    return !!(window.WebGLRenderingContext && (c.getContext("webgl2") || c.getContext("webgl")));
  } catch (error) { return false; }
}

const isDark = () => document.documentElement.getAttribute("data-theme") === "dark";

/* the shield artwork with soft, faded edges (drawn once into a canvas) */
function loadShieldTexture() {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => {
      const c = document.createElement("canvas");
      c.width = IMAGE.width; c.height = IMAGE.height;
      const g = c.getContext("2d");
      g.drawImage(img, 0, 0);
      // keep the centre, fade the edges: an elliptical mask the shape of the image
      g.globalCompositeOperation = "destination-in";
      g.save();
      g.translate(c.width / 2, c.height / 2);
      g.scale(1, c.height / c.width);
      const fade = g.createRadialGradient(0, 0, c.width * 0.2, 0, 0, c.width * 0.5);
      fade.addColorStop(0, "rgba(0,0,0,1)"); fade.addColorStop(0.65, "rgba(0,0,0,0.85)"); fade.addColorStop(1, "rgba(0,0,0,0)");
      g.fillStyle = fade;
      g.fillRect(-c.width, -c.width, c.width * 2, c.width * 2);
      g.restore();
      const texture = new THREE.CanvasTexture(c);
      texture.colorSpace = THREE.SRGBColorSpace;
      texture.anisotropy = 4;
      resolve(texture);
    };
    img.onerror = reject;
    img.src = IMAGE.src;
  });
}

/* a glass label panel: icon + text, drawn into a canvas for a sprite texture */
function labelCanvas(key, hot) {
  const spec = LABELS[key], dark = isDark(), scale = 3;
  const font = `700 ${18 * scale}px "Space Grotesk", "Inter", system-ui, sans-serif`;
  const measure = document.createElement("canvas").getContext("2d");
  measure.font = font;
  const padX = 18 * scale, icon = 26 * scale, gap = 10 * scale, h = 52 * scale;
  const w = Math.ceil(padX * 2 + icon + gap + measure.measureText(spec.text).width);
  const c = document.createElement("canvas");
  c.width = w + 24 * scale; c.height = h + 24 * scale;                      // room for the glow
  const g = c.getContext("2d");
  const x = 12 * scale, y = 12 * scale, r = 14 * scale;
  const panel = new Path2D();
  panel.roundRect(x, y, w, h, r);
  g.shadowColor = spec.tone[0]; g.shadowBlur = (hot ? 26 : 14) * scale;
  const fill = g.createLinearGradient(x, y, x + w, y + h);
  if (dark) { fill.addColorStop(0, hexA(spec.tone[1], 0.42)); fill.addColorStop(1, "rgba(8,14,32,0.78)"); }
  else { fill.addColorStop(0, "rgba(255,255,255,0.96)"); fill.addColorStop(1, hexA(spec.tone[0], 0.16)); }
  g.fillStyle = fill; g.fill(panel);
  g.shadowBlur = 0;
  g.lineWidth = (hot ? 2.6 : 1.6) * scale; g.strokeStyle = hexA(spec.tone[0], hot ? 1 : 0.75); g.stroke(panel);
  // glass highlight along the top edge
  const shine = g.createLinearGradient(0, y, 0, y + h * 0.55);
  shine.addColorStop(0, "rgba(255,255,255,0.35)"); shine.addColorStop(1, "rgba(255,255,255,0)");
  g.save(); g.clip(panel); g.fillStyle = shine; g.fillRect(x, y, w, h * 0.55); g.restore();
  // icon
  g.save();
  g.translate(x + padX, y + (h - icon) / 2); g.scale(icon / 24, icon / 24);
  g.lineWidth = 1.9; g.lineCap = "round"; g.lineJoin = "round"; g.strokeStyle = spec.tone[0];
  g.shadowColor = spec.tone[0]; g.shadowBlur = 6;
  g.stroke(new Path2D(spec.icon));
  g.restore();
  // text
  g.font = font; g.textBaseline = "middle";
  g.fillStyle = dark ? "#F1F5FF" : "#0F172A";
  g.fillText(spec.text, x + padX + icon + gap, y + h / 2 + scale);
  return c;
}

function hexA(hex, alpha) {
  const m = /^#?([\da-f]{2})([\da-f]{2})([\da-f]{2})$/i.exec(hex);
  return m ? `rgba(${parseInt(m[1], 16)},${parseInt(m[2], 16)},${parseInt(m[3], 16)},${alpha})` : hex;
}

function dotTexture() {
  const c = document.createElement("canvas");
  c.width = c.height = 64;
  const g = c.getContext("2d");
  const grad = g.createRadialGradient(32, 32, 0, 32, 32, 32);
  grad.addColorStop(0, "rgba(255,255,255,1)"); grad.addColorStop(0.25, "rgba(255,255,255,0.85)"); grad.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = grad; g.fillRect(0, 0, 64, 64);
  return new THREE.CanvasTexture(c);
}

async function start() {
  if (!host || !supportsWebGL()) return;
  const shieldTexture = await loadShieldTexture();

  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "low-power" });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.setClearColor(0x000000, 0);
  renderer.domElement.className = "hx-gl";
  host.appendChild(renderer.domElement);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 100);
  const lookAt = CENTER.clone().add(new THREE.Vector3(0, -0.15, 0));

  // the shield: a fixed plane facing the viewer
  const shield = new THREE.Mesh(
    new THREE.PlaneGeometry(PLANE_W, PLANE_H),
    new THREE.MeshBasicMaterial({ map: shieldTexture, transparent: true, depthTest: false, depthWrite: false }));
  shield.renderOrder = 10;
  scene.add(shield);

  // a soft glow behind the lock
  const dots = dotTexture();
  const glow = new THREE.Sprite(new THREE.SpriteMaterial({ map: dots, color: 0x3b82f6, transparent: true, opacity: 0.45,
    depthTest: false, depthWrite: false, blending: THREE.AdditiveBlending }));
  glow.scale.set(5.5, 5.5, 1); glow.position.copy(CENTER); glow.renderOrder = 5;
  scene.add(glow);

  // rings, labels and their connecting lines
  const labels = [];
  const rings = RINGS.map((spec) => {
    const group = new THREE.Group();
    group.position.copy(CENTER);
    group.rotation.set(spec.tilt, 0, spec.roll);
    const path = [];
    for (let i = 0; i <= 160; i += 1) {
      const a = (i / 160) * Math.PI * 2;
      path.push(new THREE.Vector3(Math.cos(a) * spec.radius, Math.sin(a) * spec.radius, 0));
    }
    const ring = new THREE.LineLoop(new THREE.BufferGeometry().setFromPoints(path),
      new THREE.LineBasicMaterial({ color: spec.color, transparent: true, opacity: 0.35, depthTest: false, depthWrite: false }));
    ring.renderOrder = 4;
    group.add(ring);
    // a carrier that spins inside the ring; the labels sit on it, evenly spaced
    const carrier = new THREE.Group();
    group.add(carrier);
    ORDER.forEach((key, index) => {
      if (index % RINGS.length !== RINGS.indexOf(spec)) return;
      const angle = (index / ORDER.length) * Math.PI * 2;
      const material = new THREE.SpriteMaterial({ transparent: true, depthTest: false, depthWrite: false });
      const sprite = new THREE.Sprite(material);
      sprite.position.set(Math.cos(angle) * spec.radius, Math.sin(angle) * spec.radius, 0);
      sprite.userData.key = key;
      carrier.add(sprite);
      const line = new THREE.Line(new THREE.BufferGeometry().setFromPoints([CENTER.clone(), CENTER.clone()]),
        new THREE.LineBasicMaterial({ color: LABELS[key].tone[0], transparent: true, opacity: 0.5, depthTest: false, depthWrite: false }));
      scene.add(line);
      labels.push({ key, sprite, line, sparks: [], bob: Math.random() * Math.PI * 2, world: new THREE.Vector3(), hot: false });
    });
    scene.add(group);
    return { spec, group, carrier, ring };
  });

  function paintLabels() {
    labels.forEach((label) => {
      const canvas = labelCanvas(label.key, label.hot);
      const texture = new THREE.CanvasTexture(canvas);
      texture.colorSpace = THREE.SRGBColorSpace;
      texture.anisotropy = 4;
      if (label.sprite.material.map) label.sprite.material.map.dispose();
      label.sprite.material.map = texture;
      label.sprite.material.needsUpdate = true;
      const height = 0.78;
      label.baseScale = new THREE.Vector2(height * canvas.width / canvas.height, height);
    });
  }
  paintLabels();
  document.addEventListener("themechange", () => setTimeout(paintLabels, 30));
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(paintLabels);

  // particles of light travelling from the lock to each label
  const MAX_SPARKS = 90;
  const sparkGeometry = new THREE.BufferGeometry();
  const sparkPositions = new Float32Array(MAX_SPARKS * 3), sparkColors = new Float32Array(MAX_SPARKS * 3);
  sparkGeometry.setAttribute("position", new THREE.BufferAttribute(sparkPositions, 3));
  sparkGeometry.setAttribute("color", new THREE.BufferAttribute(sparkColors, 3));
  const sparkPoints = new THREE.Points(sparkGeometry, new THREE.PointsMaterial({
    size: 0.16, map: dots, vertexColors: true, transparent: true, depthTest: false, depthWrite: false,
    blending: THREE.AdditiveBlending }));
  sparkPoints.renderOrder = 20;
  scene.add(sparkPoints);

  // slow dust around the scene
  const DUST = 140;
  const dustPositions = new Float32Array(DUST * 3);
  for (let i = 0; i < DUST; i += 1) {
    dustPositions[i * 3] = (Math.random() - 0.5) * 9;
    dustPositions[i * 3 + 1] = (Math.random() - 0.5) * 8;
    dustPositions[i * 3 + 2] = (Math.random() - 0.5) * 4;
  }
  const dustGeometry = new THREE.BufferGeometry();
  dustGeometry.setAttribute("position", new THREE.BufferAttribute(dustPositions, 3));
  const dust = new THREE.Points(dustGeometry, new THREE.PointsMaterial({ size: 0.05, map: dots, color: 0x7dd3fc,
    transparent: true, opacity: 0.55, depthTest: false, depthWrite: false, blending: THREE.AdditiveBlending }));
  dust.renderOrder = 1;
  scene.add(dust);

  // pointer: camera parallax and hover
  const pointer = new THREE.Vector2(0, 0), ndc = new THREE.Vector2(2, 2);
  const raycaster = new THREE.Raycaster();
  window.addEventListener("pointermove", (e) => {
    pointer.set(e.clientX / window.innerWidth - 0.5, e.clientY / window.innerHeight - 0.5);
    const box = renderer.domElement.getBoundingClientRect();
    ndc.set(((e.clientX - box.left) / box.width) * 2 - 1, -((e.clientY - box.top) / box.height) * 2 + 1);
  }, { passive: true });

  function resize() {
    // the canvas is a little larger than its box (see .hx-gl), so measure the canvas itself
    const w = renderer.domElement.clientWidth || host.clientWidth, h = renderer.domElement.clientHeight || host.clientHeight;
    if (!w || !h) return;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    // keep the outer ring and its labels inside the frame, whatever the shape of the box
    const needH = 7.0, needW = 2 * (2.95 + 0.7);
    const fov = THREE.MathUtils.degToRad(camera.fov);
    const distH = needH / 2 / Math.tan(fov / 2);
    const distW = needW / 2 / (Math.tan(fov / 2) * camera.aspect);
    camera.userData.distance = Math.max(distH, distW);
    camera.updateProjectionMatrix();
  }
  new ResizeObserver(resize).observe(renderer.domElement);
  resize();

  const clock = new THREE.Clock();
  const tmp = new THREE.Vector3(), toCamera = new THREE.Vector3();
  let frame = 0;

  function render() {
    frame = requestAnimationFrame(render);
    if (!document.body.classList.contains("entry") || !host.offsetParent) return;
    const t = reduce.matches ? 0 : clock.getElapsedTime();
    const dark = isDark();

    // the camera drifts a little with the pointer; the shield itself never moves
    const d = camera.userData.distance || 12;
    camera.position.set(lookAt.x + pointer.x * 0.9, lookAt.y - pointer.y * 0.6, d);
    camera.lookAt(lookAt);
    shield.quaternion.copy(camera.quaternion);                             // keep facing the viewer
    glow.material.opacity = (dark ? 0.55 : 0.35) + Math.sin(t * 1.4) * 0.08;

    rings.forEach(({ spec, carrier, ring }) => {
      carrier.rotation.z = t * SPEED;                                      // every ring turns at the same rate
      ring.material.opacity = dark ? 0.32 : 0.42;
    });

    // hover: which label is under the pointer
    raycaster.setFromCamera(ndc, camera);
    const hit = raycaster.intersectObjects(labels.map((l) => l.sprite), false)[0];
    const hotKey = hit ? hit.object.userData.key : null;
    let repaint = false;

    camera.getWorldDirection(toCamera).negate();
    let n = 0;
    for (const label of labels) {
      const hot = label.key === hotKey;
      if (hot !== label.hot) { label.hot = hot; repaint = true; }
      label.sprite.getWorldPosition(label.world);
      const depth = label.world.clone().sub(CENTER).dot(toCamera);          // + in front of the shield
      const near = THREE.MathUtils.clamp((depth + 3) / 6, 0, 1);
      const bob = reduce.matches ? 0 : Math.sin(t * 1.5 + label.bob) * 0.06;
      label.sprite.position.z = bob;
      const grow = hot ? 1.15 : 1;
      label.sprite.scale.set(label.baseScale.x * (0.82 + 0.3 * near) * grow, label.baseScale.y * (0.82 + 0.3 * near) * grow, 1);
      label.sprite.material.opacity = 0.55 + 0.45 * near;
      label.sprite.renderOrder = depth >= 0 ? 30 : 2;                       // in front of / behind the shield
      // the connecting line
      const positions = label.line.geometry.attributes.position;
      positions.setXYZ(0, CENTER.x, CENTER.y, CENTER.z);
      positions.setXYZ(1, label.world.x, label.world.y, label.world.z);
      positions.needsUpdate = true;
      label.line.renderOrder = depth >= 0 ? 25 : 3;
      label.line.material.opacity = (hot ? 0.95 : 0.45) * (hotKey && !hot ? 0.45 : 1) * (0.5 + 0.5 * near);
      // sparks
      if (!reduce.matches && Math.random() < (hot ? 0.25 : 0.045)) label.sparks.push({ k: 0, v: 0.006 + Math.random() * 0.008 });
      const color = new THREE.Color(LABELS[label.key].tone[0]);
      for (const s of label.sparks) {
        s.k += s.v;
        if (n >= MAX_SPARKS) break;
        tmp.copy(CENTER).lerp(label.world, s.k);
        sparkPositions.set([tmp.x, tmp.y, tmp.z], n * 3);
        sparkColors.set([color.r, color.g, color.b], n * 3);
        n += 1;
      }
      label.sparks = label.sparks.filter((s) => s.k < 1);
    }
    for (let i = n; i < MAX_SPARKS; i += 1) sparkPositions.set([0, 0, -50], i * 3);   // park unused ones
    sparkGeometry.attributes.position.needsUpdate = true;
    sparkGeometry.attributes.color.needsUpdate = true;
    if (repaint) paintLabels();
    renderer.domElement.style.cursor = hotKey ? "pointer" : "";

    if (!reduce.matches) dust.rotation.y = t * 0.02;
    renderer.render(scene, camera);
    if (reduce.matches) cancelAnimationFrame(frame);                      // one still frame
  }

  document.addEventListener("visibilitychange", () => {
    cancelAnimationFrame(frame);
    if (!document.hidden) frame = requestAnimationFrame(render);
  });
  // hand over from the CSS version
  window.__hx3d = true;
  host.classList.add("hx-webgl");
  frame = requestAnimationFrame(render);
}

start().catch((error) => {
  // keep the CSS hero if anything goes wrong
  console.warn("3D hero unavailable, using the fallback:", error);
});
