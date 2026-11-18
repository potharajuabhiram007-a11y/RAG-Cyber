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
    const colors = ["37,99,235", "79,70,229", "14,165,233", "124,58,237"];
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
    const art = document.querySelector(".hero-art");
    if (!art) return;
    const x = e.clientX / window.innerWidth - 0.5, y = e.clientY / window.innerHeight - 0.5;
    art.style.translate = `${(x * -14).toFixed(1)}px ${(y * -10).toFixed(1)}px`;
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
    window.addEventListener("load", remeasureComposer);
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(remeasureComposer);
    window.addEventListener("resize", remeasureComposer);
    requestAnimationFrame(remeasureComposer);
    if (reduce.matches) return;

    startBackground();

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
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
