/* CyberIntelliX hero: three floating 3D security panels (network, lock, fingerprint) with glass,
 * metal and neon lighting, drawn with Three.js (vendor/three.module.min.js, MIT).
 *
 * The flat SVG that ships in index.html stays in place as a fallback: it is only hidden once
 * this scene has rendered, so a browser without WebGL (or a blocked import) still shows art. */
const art = document.querySelector(".hero-art");
const canvas = document.getElementById("hero3d");

async function start() {
  if (!art || !canvas) return;
  const THREE = await import("./vendor/three.module.min.js");
  const LIME = 0xa3e635;
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true, powerPreference: "high-performance" });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.setClearColor(0x000000, 0);
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.0;

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(28, 1, 0.1, 100);

  /* ---------- reflections: a small studio of soft boxes baked into an environment map ---------- */
  const studio = new THREE.Scene();
  const box = (w, h, x, y, z, rgb) => {
    const m = new THREE.Mesh(new THREE.PlaneGeometry(w, h), new THREE.MeshBasicMaterial({ side: THREE.DoubleSide }));
    m.material.color.setRGB(...rgb);
    m.position.set(x, y, z);
    m.lookAt(0, 0, 0);
    studio.add(m);
  };
  box(14, 5, -8, 7, 6, [7, 7.4, 7]);
  box(6, 14, 11, 1, 3, [2.4, 4.8, 0.6]);
  box(10, 4, 0, -8, 5, [1.4, 3.4, 0.3]);
  box(8, 8, 0, 2, -12, [0.5, 1.4, 0.15]);
  box(5, 5, -11, -2, 2, [3, 3.2, 3]);
  const pmrem = new THREE.PMREMGenerator(renderer);
  scene.environment = pmrem.fromScene(studio, 0.03).texture;
  pmrem.dispose();

  /* ---------- lights ---------- */
  scene.add(new THREE.AmbientLight(0x20300a, 0.8));
  const key = new THREE.DirectionalLight(0xffffff, 2.2);
  key.position.set(-4, 6, 8);
  scene.add(key);
  const rim = new THREE.PointLight(LIME, 20, 18, 1.4);
  rim.position.set(0, -1.2, 4.2);
  scene.add(rim);
  const sideLeft = new THREE.PointLight(LIME, 14, 14, 1.8);
  sideLeft.position.set(-5, -2, 3);
  scene.add(sideLeft);
  const sideRight = new THREE.PointLight(LIME, 14, 14, 1.8);
  sideRight.position.set(5, 2, 3);
  scene.add(sideRight);

  /* ---------- helpers ---------- */
  function roundedDiamond(target, r, round = 0.2) {
    const pts = [[0, r], [r, 0], [0, -r], [-r, 0]];
    const lerp = (a, b, t) => [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t];
    pts.forEach((cur, i) => {
      const prev = pts[(i + 3) % 4], next = pts[(i + 1) % 4];
      const a = lerp(cur, prev, round), b = lerp(cur, next, round);
      if (i === 0) target.moveTo(a[0], a[1]); else target.lineTo(a[0], a[1]);
      target.quadraticCurveTo(cur[0], cur[1], b[0], b[1]);
    });
    target.closePath();
    return target;
  }
  const centered = (geometry) => {
    geometry.computeBoundingBox();
    geometry.translate(0, 0, -(geometry.boundingBox.max.z + geometry.boundingBox.min.z) / 2);
    return geometry;
  };
  const stick = (a, b, radius, material) => {
    const va = new THREE.Vector3(...a), vb = new THREE.Vector3(...b);
    const mesh = new THREE.Mesh(new THREE.CylinderGeometry(radius, radius, va.distanceTo(vb), 8), material);
    mesh.position.copy(va).add(vb).multiplyScalar(0.5);
    mesh.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), vb.clone().sub(va).normalize());
    return mesh;
  };

  /* ---------- design: a shield guarding a knowledge graph ----------
   * centre: lime shield with a lock; two thin orbits with travelling beads;
   * around them a slowly turning network whose nodes use the site's entity colours
   * (CVE, CWE, CAPEC, ATT&CK) so the artwork reads as the Knowledge Graph. */
  const ENTITY = [0xff8a96, 0xf5c451, 0xb9a6ff, 0x6fd3e6];
  const limeBody = new THREE.MeshStandardMaterial({ color: 0x9fdc2e, emissive: LIME, emissiveIntensity: 0.32, roughness: 0.24, metalness: 0.55, envMapIntensity: 1.1 });
  const limeFrame = new THREE.MeshStandardMaterial({ color: 0x4c7d12, emissive: 0x6fb20f, emissiveIntensity: 0.9, metalness: 0.85, roughness: 0.22, envMapIntensity: 1.6 });
  const blackGlass = new THREE.MeshPhysicalMaterial({ color: 0x020402, metalness: 0.2, roughness: 0.08, clearcoat: 1, clearcoatRoughness: 0.05, envMapIntensity: 1.2 });
  const dark = new THREE.MeshStandardMaterial({ color: 0x050805, roughness: 0.5, metalness: 0.2 });

  function shieldShape(target, k) {
    target.moveTo(0, 1.55 * k);
    target.bezierCurveTo(0.35 * k, 1.35 * k, 0.8 * k, 1.25 * k, 1.2 * k, 1.25 * k);
    target.lineTo(1.2 * k, 0.1 * k);
    target.bezierCurveTo(1.2 * k, -0.75 * k, 0.6 * k, -1.35 * k, 0, -1.75 * k);
    target.bezierCurveTo(-0.6 * k, -1.35 * k, -1.2 * k, -0.75 * k, -1.2 * k, 0.1 * k);
    target.lineTo(-1.2 * k, 1.25 * k);
    target.bezierCurveTo(-0.8 * k, 1.25 * k, -0.35 * k, 1.35 * k, 0, 1.55 * k);
    return target;
  }

  /* shield: thick bevelled frame with a black glass face */
  const shield = new THREE.Group();
  const outer = shieldShape(new THREE.Shape(), 1.15);
  outer.holes.push(shieldShape(new THREE.Path(), 0.93));
  shield.add(new THREE.Mesh(centered(new THREE.ExtrudeGeometry(outer, {
    depth: 0.55, bevelEnabled: true, bevelThickness: 0.12, bevelSize: 0.09, bevelSegments: 6, curveSegments: 24 })), limeFrame));
  shield.add(new THREE.Mesh(centered(new THREE.ExtrudeGeometry(shieldShape(new THREE.Shape(), 0.94), {
    depth: 0.1, bevelEnabled: true, bevelThickness: 0.03, bevelSize: 0.03, bevelSegments: 3, curveSegments: 24 })), blackGlass));

  /* lock on the glass */
  const lock = new THREE.Group();
  const rr = new THREE.Shape();
  const w = 0.6, h = 0.48, k = 0.15;
  rr.moveTo(-w + k, -h); rr.lineTo(w - k, -h); rr.quadraticCurveTo(w, -h, w, -h + k);
  rr.lineTo(w, h - k); rr.quadraticCurveTo(w, h, w - k, h); rr.lineTo(-w + k, h);
  rr.quadraticCurveTo(-w, h, -w, h - k); rr.lineTo(-w, -h + k); rr.quadraticCurveTo(-w, -h, -w + k, -h);
  const lockBody = new THREE.Mesh(centered(new THREE.ExtrudeGeometry(rr, {
    depth: 0.22, bevelEnabled: true, bevelThickness: 0.06, bevelSize: 0.06, bevelSegments: 5, curveSegments: 12 })), limeBody);
  lockBody.position.y = -0.2;
  const shackle = new THREE.Mesh(new THREE.TorusGeometry(0.34, 0.1, 16, 40, Math.PI), limeBody);
  shackle.position.y = 0.26;
  lock.add(lockBody, shackle);
  [-0.34, 0.34].forEach((x) => {
    const leg = new THREE.Mesh(new THREE.CylinderGeometry(0.1, 0.1, 0.2, 16), limeBody);
    leg.position.set(x, 0.17, 0);
    lock.add(leg);
  });
  const hole = new THREE.Mesh(new THREE.CylinderGeometry(0.1, 0.1, 0.1, 24), dark);
  hole.rotation.x = Math.PI / 2; hole.position.set(0, -0.12, 0.2);
  const slot = new THREE.Mesh(new THREE.CylinderGeometry(0.05, 0.085, 0.3, 4), dark);
  slot.rotation.set(0, Math.PI / 4, 0); slot.scale.set(1, 1, 0.5); slot.position.set(0, -0.32, 0.2);
  lock.add(hole, slot);
  lock.position.set(0, 0.05, 0.34);
  shield.add(lock);

  /* two orbits, each with a bead that travels around it */
  const orbitMat = (opacity) => new THREE.MeshBasicMaterial({ color: LIME, transparent: true, opacity, blending: THREE.AdditiveBlending, depthWrite: false });
  function orbit(radius, tube, opacity, tiltX, tiltY, beadColor) {
    const tilt = new THREE.Group();
    tilt.rotation.set(tiltX, tiltY, 0);
    const spin = new THREE.Group();
    spin.add(new THREE.Mesh(new THREE.TorusGeometry(radius, tube, 8, 200), orbitMat(opacity)));
    const bead = new THREE.Mesh(new THREE.SphereGeometry(0.11, 16, 16), new THREE.MeshBasicMaterial({ color: beadColor }));
    bead.position.set(radius, 0, 0);
    spin.add(bead);
    tilt.add(spin);
    return { tilt, spin };
  }
  const orbitA = orbit(3.1, 0.02, 0.6, 1.15, 0.3, 0xe9ffc9);
  const orbitB = orbit(3.9, 0.014, 0.35, -0.9, 0.5, ENTITY[3]);

  /* the knowledge graph: nodes on a shell, joined to near neighbours */
  const network = new THREE.Group();
  const shell = [];
  const COUNT = 20;
  for (let i = 0; i < COUNT; i++) {
    const y = 1 - (i / (COUNT - 1)) * 2, r = Math.sqrt(1 - y * y), theta = i * 2.399963;
    shell.push(new THREE.Vector3(Math.cos(theta) * r, y, Math.sin(theta) * r).multiplyScalar(3.7));
  }
  shell.forEach((p, i) => {
    const colour = ENTITY[i % 4];
    const node = new THREE.Mesh(new THREE.SphereGeometry(0.13, 16, 16),
      new THREE.MeshStandardMaterial({ color: colour, emissive: colour, emissiveIntensity: 0.5, roughness: 0.35 }));
    node.position.copy(p);
    network.add(node);
  });
  const edgePoints = [];
  for (let i = 0; i < COUNT; i++) for (let j = i + 1; j < COUNT; j++) if (shell[i].distanceTo(shell[j]) < 3.4) edgePoints.push(shell[i], shell[j]);
  network.add(new THREE.LineSegments(new THREE.BufferGeometry().setFromPoints(edgePoints),
    new THREE.LineBasicMaterial({ color: LIME, transparent: true, opacity: 0.28 })));

  const panels = new THREE.Group();
  panels.add(shield, orbitA.tilt, orbitB.tilt, network);
  scene.add(panels);

  /* ---------- glowing bar behind the panels, circuit board lines and glow sprites ---------- */
  const neon = new THREE.MeshBasicMaterial({ color: LIME, transparent: true, opacity: 0.8, blending: THREE.AdditiveBlending, depthWrite: false });
  const dim = new THREE.MeshBasicMaterial({ color: LIME, transparent: true, opacity: 0.4, blending: THREE.AdditiveBlending, depthWrite: false });
  const circuit = new THREE.Group();
  circuit.position.z = -1.1;
  const paths = [
    [[-1.6, 6], [-1.6, 3.9], [-0.7, 3], [-0.7, 2]], [[0.9, 6], [0.9, 4.6], [2.1, 3.4], [2.1, 2.4]],
    [[3.6, 6], [3.6, 4.4], [4.6, 3.4], [6, 3.4]], [[5.2, 6], [5.2, 4.6], [6.2, 3.6]],
    [[-0.1, 2.1], [-0.1, 4.2], [-2.6, 4.2], [-3.4, 3.4]], [[-6, 1.4], [-4.2, 1.4], [-3.6, 2]],
    [[-6, -1.1], [-4.6, -1.1], [-3.7, -1.8]], [[6.2, 0.9], [4.8, 0.9], [4.2, 1.5]],
    [[6.2, -1.1], [4.9, -1.1], [4, -1.9], [4, -2.6]], [[-3.3, -2], [-3.3, -3.4], [-4.6, -4.7], [-6, -4.7]],
    [[-0.8, -2.2], [-0.8, -3.6], [-1.8, -4.6], [-1.8, -6]], [[0.7, -2.2], [0.7, -4.2], [1.5, -5], [1.5, -6]],
    [[2.4, -2.2], [2.4, -3.6], [3.8, -5], [6.2, -5]], [[-2, -2], [-2, -6]],
    [[-6.2, 0], [6.2, 0]],
  ];
  const dots = [];
  paths.forEach((path, p) => {
    for (let i = 1; i < path.length; i++) circuit.add(stick([...path[i - 1], 0], [...path[i], 0], p === paths.length - 1 ? 0.012 : 0.02, p === paths.length - 1 ? dim : neon));
    dots.push(path[path.length - 1]);
  });
  dots.forEach(([x, y]) => {
    const dot = new THREE.Mesh(new THREE.SphereGeometry(0.05, 12, 12), neon);
    dot.position.set(x, y, 0);
    circuit.add(dot);
  });
  scene.add(circuit);

  const glowTexture = (() => {
    const c = document.createElement("canvas");
    c.width = c.height = 256;
    const g = c.getContext("2d");
    const grad = g.createRadialGradient(128, 128, 0, 128, 128, 128);
    grad.addColorStop(0, "rgba(190,255,90,1)");
    grad.addColorStop(0.25, "rgba(163,230,53,0.55)");
    grad.addColorStop(0.6, "rgba(163,230,53,0.14)");
    grad.addColorStop(1, "rgba(163,230,53,0)");
    g.fillStyle = grad;
    g.fillRect(0, 0, 256, 256);
    return new THREE.CanvasTexture(c);
  })();
  const glow = (scale, opacity, z) => {
    const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTexture, transparent: true, opacity, blending: THREE.AdditiveBlending, depthWrite: false }));
    s.scale.set(scale, scale, 1);
    s.position.set(0, 0, z);
    scene.add(s);
    return s;
  };
  const bigGlow = glow(11, 0.5, -1.5);
  const coreGlow = glow(7.2, 0.55, -0.5);
  const halo = glow(2.6, 0.12, 1.0);

  /* ---------- sizing: keep all three panels in view whatever the box shape ---------- */
  function resize() {
    const width = art.clientWidth, height = art.clientHeight;
    if (!width || !height) return;
    renderer.setSize(width, height, false);
    camera.aspect = width / height;
    const halfWidth = 5.7;
    const distance = Math.max(halfWidth / (Math.tan(THREE.MathUtils.degToRad(camera.fov / 2)) * camera.aspect), 17);
    camera.position.set(0, 0.2, distance);
    camera.lookAt(0, 0, 0);
    camera.updateProjectionMatrix();
  }
  new ResizeObserver(resize).observe(art);
  resize();

  /* ---------- animation ---------- */
  const MAX_TILT = THREE.MathUtils.degToRad(6);            // mouse parallax: at most +-6 degrees
  const pointer = { x: 0, y: 0 };
  if (!reduceMotion) {
    window.addEventListener("pointermove", (e) => {
      pointer.x = (e.clientX / window.innerWidth - 0.5) * 2;
      pointer.y = (e.clientY / window.innerHeight - 0.5) * 2;
    }, { passive: true });
  }
  const clock = new THREE.Clock();
  let revealed = false;

  function draw() {
    if (!art.clientWidth) return;                           // hero not laid out (chat open, other view)
    const t = reduceMotion ? 0 : clock.getElapsedTime();
    if (!reduceMotion) {
      shield.position.y = Math.sin(t * 0.9) * 0.12;                  // the shield floats gently
      shield.rotation.y = Math.sin(t * 0.5) * 0.18;
      orbitA.spin.rotation.z = t * 0.45;                              // beads travel round their orbits
      orbitB.spin.rotation.z = -t * 0.3;
      network.rotation.y = t * 0.1;                                   // the graph turns slowly
      network.rotation.x = Math.sin(t * 0.25) * 0.12;
      panels.rotation.y += (pointer.x * MAX_TILT - panels.rotation.y) * 0.05;
      panels.rotation.x += (pointer.y * MAX_TILT - panels.rotation.x) * 0.05;
    }
    const pulse = 0.5 + 0.5 * Math.sin(t * 1.6);
    coreGlow.material.opacity = 0.5 + pulse * 0.12;
    halo.material.opacity = 0.1 + pulse * 0.06;
    rim.intensity = 20 + pulse * 8;
    renderer.render(scene, camera);
    if (!revealed) { revealed = true; art.classList.add("hero3d-ready"); }
  }

  /* the render loop only runs while the tab is visible and the hero is on screen; with reduced motion it renders one still frame */
  let running = false, onScreen = true, tabVisible = !document.hidden;
  function loop() {
    if (!running) return;
    draw();
    requestAnimationFrame(loop);
  }
  function sync() {
    const should = onScreen && tabVisible && !reduceMotion;
    if (should && !running) { running = true; requestAnimationFrame(loop); }
    else if (!should) running = false;
  }
  new IntersectionObserver((entries) => { onScreen = entries[entries.length - 1].isIntersecting; sync(); if (reduceMotion && onScreen) draw(); }).observe(art);
  document.addEventListener("visibilitychange", () => { tabVisible = !document.hidden; sync(); });
  if (reduceMotion) { new ResizeObserver(() => draw()).observe(art); draw(); } else sync();
}

start().catch((error) => console.warn("3D hero unavailable, using the flat artwork:", error));
