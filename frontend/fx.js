/* CyberIntelliX visual effects.
   Purely decorative: nothing here changes data or behaviour, and every effect is skipped
   when the system asks for reduced motion (numbers are still shown, just without counting). */
(() => {
  "use strict";
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)");
  const finePointer = window.matchMedia("(hover: hover) and (pointer: fine)");

  /* ------------------------------------------------------------------ *
   * 1. Animated background: a slow, light network of nodes and links.
   * ------------------------------------------------------------------ */
  function startBackground() {
    const canvas = document.createElement("canvas");
    canvas.className = "fx-bg";
    canvas.setAttribute("aria-hidden", "true");
    document.body.prepend(canvas);
    const ctx = canvas.getContext("2d");
    const colors = ["139,235,0", "85,169,0", "85,169,0", "215,255,117"];
    let width = 0, height = 0, dpr = 1, nodes = [], frame = 0, last = 0;
    const mouse = { x: -1e4, y: -1e4 };

    function resize() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = window.innerWidth; height = window.innerHeight;
      canvas.width = width * dpr; canvas.height = height * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const count = Math.round(Math.min(70, Math.max(26, (width * height) / 26000)));
      nodes = Array.from({ length: count }, () => ({
        x: Math.random() * width, y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.22, vy: (Math.random() - 0.5) * 0.22,
        r: 1.2 + Math.random() * 1.8, c: colors[(Math.random() * colors.length) | 0],
      }));
    }

    function draw(time) {
      frame = requestAnimationFrame(draw);
      if (time - last < 33) return;                      // about 30 frames a second is plenty
      last = time;
      ctx.clearRect(0, 0, width, height);
      const linkDist = Math.min(150, width / 7);
      for (const n of nodes) {
        n.x += n.vx; n.y += n.vy;
        if (n.x < -20) n.x = width + 20; else if (n.x > width + 20) n.x = -20;
        if (n.y < -20) n.y = height + 20; else if (n.y > height + 20) n.y = -20;
        const dx = mouse.x - n.x, dy = mouse.y - n.y, d2 = dx * dx + dy * dy;
        if (d2 < 22000) { n.x -= dx * 0.004; n.y -= dy * 0.004; }   // nodes drift away from the pointer
      }
      for (let i = 0; i < nodes.length; i += 1) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j += 1) {
          const b = nodes[j], dx = a.x - b.x, dy = a.y - b.y, d = Math.hypot(dx, dy);
          if (d < linkDist) {
            ctx.strokeStyle = `rgba(${a.c},${0.16 * (1 - d / linkDist)})`;
            ctx.lineWidth = 1;
            ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
          }
        }
      }
      for (const n of nodes) {
        ctx.fillStyle = `rgba(${n.c},0.45)`;
        ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2); ctx.fill();
      }
    }

    resize();
    window.addEventListener("resize", resize);
    window.addEventListener("pointermove", (e) => { mouse.x = e.clientX; mouse.y = e.clientY; }, { passive: true });
    document.addEventListener("visibilitychange", () => {
      cancelAnimationFrame(frame);
      if (!document.hidden) frame = requestAnimationFrame(draw);
    });
    frame = requestAnimationFrame(draw);
  }

  /* ------------------------------------------------------------------ *
   * 2. Scroll reveals: cards rise in as they come into view.
   * ------------------------------------------------------------------ */
  // only elements that stay put: lists the app re-renders on every refresh would flicker
  const REVEAL = ".block, .feature, .stat, .link-list li";
  let revealer = null;
  function setupReveal(root) {
    if (!revealer) return;
    root.querySelectorAll(REVEAL).forEach((el) => {
      if (el.classList.contains("fx-reveal")) return;
      const siblings = el.parentElement ? [...el.parentElement.children] : [el];
      el.style.setProperty("--fx-delay", `${Math.min(siblings.indexOf(el), 8) * 70}ms`);
      el.classList.add("fx-reveal");
      revealer.observe(el);
    });
  }

  /* ------------------------------------------------------------------ *
   * 3. Counters: dashboard numbers count up when they change.
   * ------------------------------------------------------------------ */
  const counting = new WeakMap();
  function parseNumber(text) {
    const clean = (text || "").replace(/[,\s]/g, "");
    return /^\d+$/.test(clean) ? Number(clean) : null;
  }
  function countUp(el) {
    const state = counting.get(el);
    if (state && state.writing) return;                   // our own update
    const target = parseNumber(el.textContent);
    if (target === null || (state && state.target === target)) return;
    const from = state ? state.target : 0;
    counting.set(el, { target, writing: false });
    if (reduce.matches || target === from) return;
    const start = performance.now(), duration = 1100;
    el.classList.add("fx-counting");
    const step = (now) => {
      const t = Math.min(1, (now - start) / duration), eased = 1 - Math.pow(1 - t, 3);
      const s = counting.get(el);
      if (!s || s.target !== target) return;              // a newer value arrived
      s.writing = true;
      el.textContent = Math.round(from + (target - from) * eased).toLocaleString("en-US");
      s.writing = false;
      if (t < 1) requestAnimationFrame(step);
      else el.classList.remove("fx-counting");
    };
    requestAnimationFrame(step);
  }
  function watchCounters() {
    document.querySelectorAll(".stat-value").forEach((el) => {
      countUp(el);
      new MutationObserver(() => countUp(el)).observe(el, { childList: true, characterData: true, subtree: true });
    });
  }

  /* ------------------------------------------------------------------ *
   * 4. Micro-interactions: ripples, spotlight, tilt, hero parallax.
   * ------------------------------------------------------------------ */
  const RIPPLE = ".btn, .gbtn, .mini, .kg-mode, .nav-link, .tab";
  function ripple(e) {
    const target = e.target.closest(RIPPLE);
    if (!target || target.disabled) return;
    const rect = target.getBoundingClientRect(), size = Math.max(rect.width, rect.height) * 2;
    const dot = document.createElement("span");
    dot.className = "fx-ripple";
    dot.style.cssText = `width:${size}px;height:${size}px;left:${e.clientX - rect.left - size / 2}px;top:${e.clientY - rect.top - size / 2}px`;
    if (getComputedStyle(target).position === "static") target.style.position = "relative";
    target.appendChild(dot);
    dot.animate([{ transform: "scale(0)", opacity: 0.22 }, { transform: "scale(1)", opacity: 0 }],
                { duration: 600, easing: "cubic-bezier(.2,.7,.2,1)" }).onfinish = () => dot.remove();
  }

  function spotlight(e) {
    const card = e.target.closest(".fx-spot");
    if (!card) return;
    const rect = card.getBoundingClientRect();
    card.style.setProperty("--mx", `${e.clientX - rect.left}px`);
    card.style.setProperty("--my", `${e.clientY - rect.top}px`);
  }
  function markSpots(root) {
    root.querySelectorAll(".block:not(.feature), .kg-start").forEach((el) => el.classList.add("fx-spot"));
  }

  function tilt(e) {
    const card = e.target.closest(".feature");
    if (!card) return;
    const rect = card.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width - 0.5, y = (e.clientY - rect.top) / rect.height - 0.5;
    card.style.transform = `perspective(900px) rotateX(${(-y * 4).toFixed(2)}deg) rotateY(${(x * 5).toFixed(2)}deg)`;
  }
  function untilt(e) {
    const card = e.target.closest && e.target.closest(".feature");
    if (card && !card.contains(e.relatedTarget)) card.style.transform = "";
  }

  function parallax(e) {
    if (!document.body.classList.contains("entry")) return;
    const rig = document.querySelector(".h3d-rig");
    if (!rig) return;
    const x = e.clientX / window.innerWidth - 0.5, y = e.clientY / window.innerHeight - 0.5;
    rig.style.setProperty("--ry", `${(x * 16).toFixed(2)}deg`);   // the scene turns towards the pointer
    rig.style.setProperty("--rx", `${(-y * 10).toFixed(2)}deg`);
  }

  /* ------------------------------------------------------------------ *
   * 5. 3D hero: shield thickness, and light lines to the orbiting nodes.
   * ------------------------------------------------------------------ */
  function buildShieldDepth() {
    const depth = document.querySelector(".h3d-depth");
    if (!depth || depth.childElementCount) return;
    const layers = 14;
    for (let i = 1; i <= layers; i += 1) {
      const slab = document.createElement("i");
      slab.style.transform = `translateZ(${-i * 1.6}px)`;
      slab.style.filter = `brightness(${(1 - i / (layers * 1.6)).toFixed(3)})`;
      depth.appendChild(slab);
    }
  }

  function startHeroLinks() {
    const canvas = document.querySelector(".h3d-links");
    const host = document.querySelector(".h3d");
    if (!canvas || !host) return;
    const ctx = canvas.getContext("2d");
    const sparks = [];
    let frame = 0, last = 0;
    const draw = (time) => {
      frame = requestAnimationFrame(draw);
      if (time - last < 33) return;
      last = time;
      if (!document.body.classList.contains("entry") || !host.offsetParent) return;   // hero not shown
      const box = host.getBoundingClientRect(), dpr = Math.min(window.devicePixelRatio || 1, 2);
      if (canvas.width !== Math.round(box.width * dpr) || canvas.height !== Math.round(box.height * dpr)) {
        canvas.width = Math.round(box.width * dpr); canvas.height = Math.round(box.height * dpr);
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, box.width, box.height);
      const shield = document.querySelector(".h3d-face");
      if (!shield) return;
      const s = shield.getBoundingClientRect();
      const cx = s.left + s.width / 2 - box.left, cy = s.top + s.height / 2 - box.top;
      const dark = document.documentElement.getAttribute("data-theme") === "dark";
      document.querySelectorAll(".h3d-node b").forEach((label, index) => {
        const r = label.getBoundingClientRect();
        const x = r.left + r.width / 2 - box.left, y = r.top + r.height / 2 - box.top;
        const color = getComputedStyle(label).color;
        const grad = ctx.createLinearGradient(cx, cy, x, y);
        grad.addColorStop(0, dark ? "rgba(163,255,0,0.05)" : "rgba(139,235,0,0.04)");
        grad.addColorStop(1, color.replace("rgb(", "rgba(").replace(")", dark ? ",0.55)" : ",0.4)"));
        ctx.strokeStyle = grad; ctx.lineWidth = 1.2;
        ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(x, y); ctx.stroke();
        if (Math.random() < 0.06) sparks.push({ i: index, t: 0, speed: 0.012 + Math.random() * 0.012, color });
        for (const spark of sparks) {
          if (spark.i !== index) continue;
          const px = cx + (x - cx) * spark.t, py = cy + (y - cy) * spark.t;
          ctx.fillStyle = spark.color; ctx.shadowColor = spark.color; ctx.shadowBlur = 10;
          ctx.beginPath(); ctx.arc(px, py, 2.4, 0, Math.PI * 2); ctx.fill();
          ctx.shadowBlur = 0;
        }
      });
      for (let k = sparks.length - 1; k >= 0; k -= 1) { sparks[k].t += sparks[k].speed; if (sparks[k].t > 1) sparks.splice(k, 1); }
    };
    document.addEventListener("visibilitychange", () => {
      cancelAnimationFrame(frame);
      if (!document.hidden) frame = requestAnimationFrame(draw);
    });
    frame = requestAnimationFrame(draw);
  }

  /* ------------------------------------------------------------------ *
   * 6. Light / dark theme (the head script applies the saved one before paint).
   * ------------------------------------------------------------------ */
  const THEME_KEY = "ragcyber.theme";
  function syncThemeButton() {
    const button = document.getElementById("theme-toggle");
    if (!button) return;
    const dark = document.documentElement.getAttribute("data-theme") === "dark";
    const label = dark ? "Switch to light mode" : "Switch to dark mode";
    button.setAttribute("aria-label", label);
    button.title = label;
    button.setAttribute("aria-pressed", String(dark));
  }
  function toggleTheme() {
    const root = document.documentElement;
    const next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    if (!reduce.matches) {
      root.classList.add("theme-switching");                 // colours glide instead of jumping
      clearTimeout(toggleTheme.timer);
      toggleTheme.timer = setTimeout(() => root.classList.remove("theme-switching"), 550);
    }
    root.setAttribute("data-theme", next);
    try { localStorage.setItem(THEME_KEY, next); } catch (error) { /* private mode */ }
    syncThemeButton();
    document.dispatchEvent(new CustomEvent("themechange", { detail: { theme: next } }));
  }

  /* ------------------------------------------------------------------ *
   * 7. Search boxes type example questions while they are empty.
   * ------------------------------------------------------------------ */
  function typingPlaceholder(field, examples, prefix) {
    if (!field) return;
    const original = field.placeholder;
    let item = 0, chars = 0, deleting = false, timer = 0;
    const step = () => {
      const idle = !field.value && document.activeElement !== field && field.offsetParent;
      if (!idle) { field.placeholder = original; timer = setTimeout(step, 600); return; }
      const text = examples[item];
      chars += deleting ? -1 : 1;
      field.placeholder = prefix + text.slice(0, chars) + (chars < text.length || deleting ? "|" : "");
      let wait = deleting ? 28 : 55;
      if (!deleting && chars >= text.length) { deleting = true; wait = 1800; }
      else if (deleting && chars <= 0) { deleting = false; item = (item + 1) % examples.length; wait = 350; }
      timer = setTimeout(step, wait);
    };
    field.addEventListener("focus", () => { field.placeholder = original; });
    timer = setTimeout(step, 1200);
    return () => clearTimeout(timer);
  }

  /* ------------------------------------------------------------------ *
   * 8. Magnetic buttons: they lean a little towards the pointer.
   * ------------------------------------------------------------------ */
  const MAGNETIC = "#send, #new-chat, .btn-primary, .theme-toggle, .hero-foot li";
  function magnetic(e) {
    document.querySelectorAll(".magnetic").forEach((el) => {
      const r = el.getBoundingClientRect();
      const dx = e.clientX - (r.left + r.width / 2), dy = e.clientY - (r.top + r.height / 2);
      const reach = Math.max(r.width, r.height) * 1.1;
      if (Math.hypot(dx, dy) < reach) {
        el.style.setProperty("--mgx", `${(dx * 0.18).toFixed(1)}px`);
        el.style.setProperty("--mgy", `${(dy * 0.22).toFixed(1)}px`);
      } else if (el.style.getPropertyValue("--mgx")) {
        el.style.removeProperty("--mgx"); el.style.removeProperty("--mgy");
      }
    });
  }

  /* ------------------------------------------------------------------ *
   * start
   * ------------------------------------------------------------------ */
  /* The question box sizes itself to its text, but its first measurement happens while
     the page is still laying out (fonts loading), which can make the empty box very tall.
     Measure again once everything is ready and whenever the window is resized. */
  function remeasureComposer() {
    const input = document.getElementById("input");
    if (input) input.dispatchEvent(new Event("input"));
  }

  function init() {
    watchCounters();
    syncThemeButton();
    const themeButton = document.getElementById("theme-toggle");
    if (themeButton) themeButton.addEventListener("click", toggleTheme);
    buildShieldDepth();
    window.addEventListener("load", remeasureComposer);
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(remeasureComposer);
    window.addEventListener("resize", remeasureComposer);
    requestAnimationFrame(remeasureComposer);
    if (reduce.matches) return;

    startBackground();
    startHeroLinks();
    typingPlaceholder(document.getElementById("input"), [
      "Explain CVE-2026-44523", "Which CVEs are linked to T1110?", "What is SQL injection?",
      "How do I mitigate CWE-79?", "Show the attack chain for CAPEC-66"], "Ask: ");
    typingPlaceholder(document.getElementById("kg-search"), ["CVE-2026-44523", "CWE-79", "CAPEC-66", "T1110 Brute Force"], "Find ");

    revealer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) { entry.target.classList.add("fx-in"); revealer.unobserve(entry.target); }
      });
    }, { threshold: 0.08 });
    setupReveal(document);
    markSpots(document);
    // content the app adds later (data sources, history, entity details)
    new MutationObserver((records) => {
      for (const record of records) {
        record.addedNodes.forEach((node) => {
          if (node.nodeType !== 1) return;
          if (node.matches && node.matches(REVEAL)) setupReveal(node.parentElement || document);
          else setupReveal(node);
          markSpots(node.parentElement || node);
        });
      }
    }).observe(document.querySelector(".views") || document.body, { childList: true, subtree: true });

    document.addEventListener("pointerdown", ripple);
    if (finePointer.matches) {
      document.addEventListener("pointermove", spotlight, { passive: true });
      document.addEventListener("pointermove", tilt, { passive: true });
      document.addEventListener("pointerout", untilt);
      window.addEventListener("pointermove", parallax, { passive: true });
      document.querySelectorAll(MAGNETIC).forEach((el) => el.classList.add("magnetic"));
      window.addEventListener("pointermove", magnetic, { passive: true });
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
