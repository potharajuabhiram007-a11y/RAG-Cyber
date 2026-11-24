/* RAG-Cyber frontend: vanilla JavaScript chat client for the FastAPI backend.
 *
 * - All backend text is inserted with textContent (never innerHTML), so answers,
 *   evidence and source names cannot inject markup into the page.
 * - The relationship graphs are drawn on <canvas>; no external libraries.
 * - Animations stop when the tab is hidden and are reduced to static frames when
 *   the user prefers reduced motion.
 */
(() => {
  "use strict";

  const NO_SOLUTION = "THERE IS NO SOLUTION FOR THIS QUESTION";
  const NOT_FOUND = "RESULT NOT FOUND";
  const DATASET_CATEGORIES = ["CVE", "CWE", "CAPEC", "ATTACK"];
  const CATEGORY_LABELS = {
    CVE: "CVE (NVD)", CWE: "CWE (MITRE)", CAPEC: "CAPEC (MITRE)", ATTACK: "MITRE ATT&CK",
    FUNDAMENTALS: "Cybersecurity & networking fundamentals", GENERAL: "General",
    UNSUPPORTED: "Unsupported",
  };
  const TYPE_COLORS = { CVE: "#a8261e", CWE: "#a0620a", CAPEC: "#5f3d94", ATTACK: "#0b6480",
                        FUNDAMENTALS: "#2f7d4f" };
  const TYPE_NAMES = { CVE: "CVE", CWE: "CWE", CAPEC: "CAPEC", ATTACK: "ATT&CK" };
  const LAYER_ORDER = ["CVE", "CWE", "CAPEC", "ATTACK"];
  const SOURCE_NAMES = { foundation: "Reference documents", cwe: "MITRE CWE", capec: "MITRE CAPEC",
                         attack: "MITRE ATT&CK", nvd: "NVD CVE" };
  const ID_PATTERN = "CVE-\\d{4}-\\d{4,7}|CWE-\\d{1,5}|CAPEC-\\d{1,5}|T\\d{4}(?:\\.\\d{3})?";
  const INLINE_RE = new RegExp("(\\*\\*[^*]+\\*\\*|`[^`]+`|\\b(?:" + ID_PATTERN + ")\\b)", "g");
  const ID_RE = new RegExp("^(?:" + ID_PATTERN + ")$");
  const FALLBACK_API = "http://127.0.0.1:8000";
  const HISTORY_KEY = "ragcyber.history.v1";
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  /* Colours the canvas drawings need come from the active design's CSS tokens. */
  const PAL = { surface: "#fff", lane: "#f4f4f4", text: "#111", muted: "#666", border: "#ccc", borderStrong: "#999",
                accent: "#2563eb" };
  function cssVar(name, fallback) {
    const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return value || fallback;
  }
  function refreshPalette() {
    TYPE_COLORS.CVE = cssVar("--c-cve", TYPE_COLORS.CVE);
    TYPE_COLORS.CWE = cssVar("--c-cwe", TYPE_COLORS.CWE);
    TYPE_COLORS.CAPEC = cssVar("--c-capec", TYPE_COLORS.CAPEC);
    TYPE_COLORS.ATTACK = cssVar("--c-attack", TYPE_COLORS.ATTACK);
    TYPE_COLORS.FUNDAMENTALS = cssVar("--c-fund", TYPE_COLORS.FUNDAMENTALS);
    PAL.surface = cssVar("--surface-solid", PAL.surface);
    PAL.lane = cssVar("--surface-2", PAL.lane);
    PAL.text = cssVar("--text", PAL.text);
    PAL.muted = cssVar("--muted", PAL.muted);
    PAL.border = cssVar("--border", PAL.border);
    PAL.borderStrong = cssVar("--border-strong", PAL.borderStrong);
    PAL.accent = cssVar("--accent", PAL.accent);
  }
  refreshPalette();
  // fx.js switches between the light and dark theme without a reload: re-read the colours
  // (graphs in answers redraw every frame; reduced-motion pages are redrawn once)
  document.addEventListener("themechange", () => {
    refreshPalette();
    if (reducedMotion.matches) drawStatic();
  });

  /* spring-like ease: overshoots a little, then settles (used when graph nodes pop in) */
  const easeOutBack = (t) => { const c1 = 1.70158, c3 = c1 + 1; return 1 + c3 * Math.pow(t - 1, 3) + c1 * Math.pow(t - 1, 2); };

  /* Shortens a label with an ellipsis so it fits a box. */
  function fitLabel(context, text, maxWidth) {
    if (context.measureText(text).width <= maxWidth) return text;
    let end = text.length;
    while (end > 1 && context.measureText(text.slice(0, end) + "\u2026").width > maxWidth) end -= 1;
    return text.slice(0, end) + "\u2026";
  }

  const chat = document.getElementById("chat");
  const form = document.getElementById("composer");
  const input = document.getElementById("input");
  const counter = document.getElementById("counter");
  const sendButton = document.getElementById("send");
  const clearButton = document.getElementById("clear");
  const jumpButton = document.getElementById("jump");
  const statusPill = document.getElementById("status");
  const statusText = document.getElementById("status-text");
  const sourcesList = document.getElementById("sources");
  const welcomeTemplate = document.getElementById("welcome").cloneNode(true);

  let apiBase = (document.querySelector('meta[name="rag-cyber-api"]')?.content || "").replace(/\/$/, "");
  let busy = false;
  let lastEntityIds = [];           // entities of the previous answer: lets follow-ups say "it"
  let history = [];
  let panelTimer = null;

  /* ------------------------------------------------------------------ */
  /* small helpers                                                       */
  /* ------------------------------------------------------------------ */
  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function typeOf(id) {
    if (id.startsWith("CVE-")) return "CVE";
    if (id.startsWith("CWE-")) return "CWE";
    if (id.startsWith("CAPEC-")) return "CAPEC";
    return "ATTACK";
  }

  function timeLabel(date) {
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  function relativeTime(iso) {
    if (!iso) return "";
    const ms = new Date(iso).getTime();
    if (!Number.isFinite(ms)) return "";
    const seconds = Math.max(0, (Date.now() - ms) / 1000);
    if (seconds < 90) return "just now";
    if (seconds < 3600) return Math.round(seconds / 60) + " min ago";
    if (seconds < 86400) return Math.round(seconds / 3600) + " h ago";
    return Math.round(seconds / 86400) + " d ago";
  }

  function distanceFromBottom() {
    return chat.scrollHeight - chat.scrollTop - chat.clientHeight;
  }

  function scrollToBottom(smooth) {
    chat.scrollTo({ top: chat.scrollHeight, behavior: smooth && !reducedMotion.matches ? "smooth" : "auto" });
  }

  function toast(message) {
    const node = el("div", "toast", message);
    node.setAttribute("role", "status");
    document.body.appendChild(node);
    setTimeout(() => node.remove(), 1800);
  }

  function idButton(id, className) {
    const button = el("button", className, id);
    button.type = "button";
    button.dataset.ask = "Explain " + id;
    button.dataset.type = typeOf(id);
    button.title = "Ask about " + id;
    return button;
  }

  /* **bold**, `code` and clickable identifiers; everything else stays plain text. */
  function appendInline(parent, text) {
    for (const part of text.split(INLINE_RE)) {
      if (!part) continue;
      if (part.startsWith("**") && part.endsWith("**") && part.length > 4) {
        const strong = el("strong");
        appendInline(strong, part.slice(2, -2));
        parent.appendChild(strong);
      } else if (part.startsWith("`") && part.endsWith("`") && part.length > 2) {
        parent.appendChild(el("code", null, part.slice(1, -1)));
      } else if (ID_RE.test(part)) {
        parent.appendChild(idButton(part, "link-id"));
      } else {
        parent.appendChild(document.createTextNode(part));
      }
    }
  }

  function isTableRow(line) {
    return line.split(" | ").length >= 2 && !line.startsWith("- ");
  }

  /* Minimal, safe renderer: paragraphs, "- " bullet lists and "a | b" tables. */
  function renderAnswer(container, text) {
    const lines = text.replace(/\r/g, "").split("\n");
    let index = 0;
    while (index < lines.length) {
      const line = lines[index].trim();
      if (!line) { index += 1; continue; }
      if (/^[-*•]\s+/.test(line)) {
        const list = el("ul");
        while (index < lines.length && /^[-*•]\s+/.test(lines[index].trim())) {
          const item = el("li");
          appendInline(item, lines[index].trim().replace(/^[-*•]\s+/, ""));
          list.appendChild(item);
          index += 1;
        }
        container.appendChild(list);
        continue;
      }
      if (isTableRow(line) && index + 1 < lines.length && isTableRow(lines[index + 1].trim())) {
        const rows = [];
        while (index < lines.length && isTableRow(lines[index].trim())) {
          rows.push(lines[index].trim().split(" | "));
          index += 1;
        }
        const width = Math.max(...rows.map((row) => row.length));
        const table = el("table");
        rows.forEach((cells, rowIndex) => {
          if (rowIndex > 0 && cells.join("|") === rows[0].join("|")) return; // repeated header
          if (rowIndex > 0 && cells.every((c) => /^:?-{2,}:?$/.test(c.trim()))) return; // Markdown separator row
          const tr = el("tr");
          for (let c = 0; c < width; c += 1) {
            const cell = el(rowIndex === 0 ? "th" : "td");
            appendInline(cell, cells[c] || "");
            tr.appendChild(cell);
          }
          table.appendChild(tr);
        });
        const wrap = el("div", "table-wrap");
        wrap.appendChild(table);
        container.appendChild(wrap);
        continue;
      }
      const paragraph = el("p");
      appendInline(paragraph, line);
      container.appendChild(paragraph);
      index += 1;
    }
  }

  /* ------------------------------------------------------------------ */
  /* 3D maths shared by the backdrop and the relationship graph          */
  /* ------------------------------------------------------------------ */
  function rotate(point, rotY, rotX) {
    const cosY = Math.cos(rotY), sinY = Math.sin(rotY);
    const x = point.x * cosY + point.z * sinY;
    const z0 = -point.x * sinY + point.z * cosY;
    const cosX = Math.cos(rotX), sinX = Math.sin(rotX);
    return { x, y: point.y * cosX - z0 * sinX, z: point.y * sinX + z0 * cosX };
  }

  function fitCanvas(canvas, width, height) {
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    if (canvas.width !== Math.round(width * ratio) || canvas.height !== Math.round(height * ratio)) {
      canvas.width = Math.round(width * ratio);
      canvas.height = Math.round(height * ratio);
    }
    const context = canvas.getContext("2d");
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    return context;
  }

  const GROUP_LIMIT = 8;        // more neighbours of one type than this are grouped
  const GROUP_KEEP = 6;         // how many stay visible next to the "+N" node
  const GRAPH_MODE_KEY = "ragcyber.graph.view.v2";
  const GRAPH_MODES = ["flow", "2d", "3d"];
  const MODE_LABELS = { flow: "Flow", "2d": "Tree", "3d": "3D" };
  const FLOW_COL_W = 215, FLOW_SUB_W = 172, FLOW_ROW_H = 46, FLOW_MAX_ROWS = 10, FLOW_BOX_W = 152, FLOW_BOX_H = 36;
  const TYPE_TITLES = { CVE: "CVE \u00b7 Vulnerability", CWE: "CWE \u00b7 Weakness", CAPEC: "CAPEC \u00b7 Attack pattern",
                        ATTACK: "ATT&CK \u00b7 Technique" };
  const SPACING_X = 210, SPACING_Y = 30, FOCAL = 900;

  function storedGraphMode() {
    try {
      const value = localStorage.getItem(GRAPH_MODE_KEY);
      return GRAPH_MODES.includes(value) ? value : null;
    } catch (error) { return null; }
  }

  class RelationGraph {
    constructor(wrap, canvas, tip, relationships, names, focusIds, handlers) {
      this.wrap = wrap;
      this.canvas = canvas;
      this.tip = tip;
      this.handlers = handlers;
      this.nodes = new Map();           // id -> { id, type, name, focus }
      this.adjacent = new Map();        // id -> Set of neighbour ids
      this.edges = [];                  // { a, b, rel }  (a -> b)
      const seen = new Set();
      relationships.forEach((rel) => {
        if (rel.source === rel.target || seen.has(rel.source + ">" + rel.target + ">" + rel.type)) return;
        seen.add(rel.source + ">" + rel.target + ">" + rel.type);
        [rel.source, rel.target].forEach((id) => {
          if (!this.nodes.has(id)) {
            this.nodes.set(id, { id, type: typeOf(id), name: names.get(id) || "", focus: focusIds.includes(id) });
            this.adjacent.set(id, new Set());
          }
        });
        this.adjacent.get(rel.source).add(rel.target);
        this.adjacent.get(rel.target).add(rel.source);
        this.edges.push({ a: rel.source, b: rel.target, rel: rel.type });
      });
      this.types = LAYER_ORDER.filter((type) => [...this.nodes.values()].some((n) => n.type === type));
      this.expanded = new Set();        // keys of expanded groups
      this.display = new Map();         // id -> drawable node (keeps positions between rebuilds)
      this.mode = storedGraphMode() || "flow";
      this.rotY = -0.45;
      this.rotX = 0.28;
      this.view = { zoom: 1, panX: 0, panY: 0 };
      this.target = { zoom: 1, panX: 0, panY: 0 };
      this.userView = false;            // true once the user zooms or pans by hand
      this.snap = true;                 // next draw jumps straight to the target layout
      this.hover = null;
      this.hoverEdge = null;
      this.drag = null;
      this.visible = true;
      this.time = 0;
      this.computeDepths(focusIds);
      this.rebuild();
      this.bind();
    }

    /* Breadth-first depth from the root entity (the one the question was about). */
    computeDepths(focusIds) {
      this.depth = new Map();
      this.roots = [];
      const byDegree = [...this.nodes.keys()].sort((a, b) => this.adjacent.get(b).size - this.adjacent.get(a).size);
      const candidates = [...focusIds.filter((id) => this.nodes.has(id)), ...byDegree];
      for (const start of candidates) {
        if (this.depth.has(start)) continue;
        this.roots.push(start);
        this.depth.set(start, 0);
        const queue = [start];
        while (queue.length) {
          const id = queue.shift();
          for (const next of this.adjacent.get(id)) {
            if (!this.depth.has(next)) { this.depth.set(next, this.depth.get(id) + 1); queue.push(next); }
          }
        }
      }
      this.root = this.roots[0];
    }

    /* Decide which nodes are shown, create the "+N" aggregate nodes, then lay out and fit. */
    rebuild() {
      const shown = new Set(this.roots);
      const parent = new Map();
      const groups = [];
      const queue = [...this.roots];
      while (queue.length) {
        const id = queue.shift();
        const byType = new Map();
        for (const next of this.adjacent.get(id)) {
          if (this.depth.get(next) !== this.depth.get(id) + 1) continue;
          const type = this.nodes.get(next).type;
          if (!byType.has(type)) byType.set(type, []);
          byType.get(type).push(next);
        }
        for (const [type, children] of byType) {
          let visibleChildren = children;
          if (children.length > GROUP_LIMIT) {
            // No edge weight or score is returned by the API, so "most relevant" is the
            // order the backend sent them in; entities named in the question always stay.
            const pinned = children.filter((child) => this.nodes.get(child).focus);
            const kept = [...new Set([...pinned, ...children])].slice(0, Math.max(GROUP_KEEP, pinned.length));
            const key = id + "|" + type;
            const group = { key, hub: id, type, rest: children.filter((child) => !kept.includes(child)),
                            expanded: this.expanded.has(key) };
            groups.push(group);
            visibleChildren = group.expanded ? children : kept;
          }
          for (const child of visibleChildren) {
            if (!shown.has(child)) { shown.add(child); parent.set(child, id); queue.push(child); }
          }
        }
      }

      const next = new Map();
      const place = (id, props) => {
        const node = this.display.get(id) || { id, x: null };
        next.set(id, Object.assign(node, props));
        return node;
      };
      shown.forEach((id) => place(id, { ...this.nodes.get(id), aggregate: false, parent: parent.get(id) || null,
                                          depth: this.depth.get(id), root: this.roots.includes(id) }));
      this.groups = [];
      groups.forEach((group) => {
        const hidden = group.rest.filter((id) => !shown.has(id));
        if (!group.expanded && !hidden.length) return;      // all members visible through another hub
        const count = group.expanded ? group.rest.length : hidden.length;
        const label = group.expanded ? `Hide ${count} ${TYPE_NAMES[group.type]}` : `+${count} ${TYPE_NAMES[group.type]}`;
        place("agg:" + group.key, { type: group.type, name: "", aggregate: true, group, label, count,
                                    parent: group.hub, depth: this.depth.get(group.hub) + 1, root: false, focus: false });
        this.groups.push({ ...group, count, label });
      });
      this.display = next;

      // drawable edges: real relationships between shown nodes + one dashed edge per aggregate
      this.links = this.edges.filter((edge) => next.has(edge.a) && next.has(edge.b))
        .map((edge) => ({ a: next.get(edge.a), b: next.get(edge.b), rel: edge.rel, aggregate: false }));
      next.forEach((node) => {
        if (node.aggregate) this.links.push({ a: next.get(node.parent), b: node, rel: "", aggregate: true });
      });
      this.neighbours = new Map([...next.keys()].map((id) => [id, new Set()]));
      this.links.forEach((link) => {
        this.neighbours.get(link.a.id).add(link.b.id);
        this.neighbours.get(link.b.id).add(link.a.id);
      });
      this.labelled = new Set([...this.roots, ...(this.neighbours.get(this.root) || [])]);

      this.layout();
      this.userView = false;
      this.fit();
      if (this.handlers.onGroups) this.handlers.onGroups(this.groups);
    }

    /* Tidy tree: depth on the x axis, leaves stacked on the y axis, parents centred on children. */
    layout() {
      const children = new Map();
      this.display.forEach((node) => {
        if (node.parent && this.display.has(node.parent)) {
          if (!children.has(node.parent)) children.set(node.parent, []);
          children.get(node.parent).push(node);
        }
      });
      let slot = 0, index = 0;
      const assign = (node) => {
        const kids = children.get(node.id) || [];
        kids.sort((a, b) => Number(a.aggregate) - Number(b.aggregate));     // "+N" nodes last
        kids.forEach(assign);
        node.ty = kids.length ? (kids[0].ty + kids[kids.length - 1].ty) / 2 : slot++;
        node.tx = node.depth * SPACING_X;
        node.tz = node.depth === 0 ? 0 : Math.sin((index++) * 2.4) * 95;
      };
      this.roots.forEach((id) => { assign(this.display.get(id)); slot += 1; });
      // Rows are 30px apart; an expanded group with dozens of leaves is packed tighter so the
      // fitted graph does not shrink to a thin vertical line.
      const rows = Math.max(1, slot - this.roots.length);
      const spacing = rows <= 14 ? SPACING_Y : Math.max(12, 440 / rows);
      this.display.forEach((node) => {
        node.ty *= spacing;
        if (node.x === null) {                               // new node: grow out of its parent
          const origin = node.parent && this.display.get(node.parent);
          const from = origin && origin.x !== null ? origin : { x: node.tx, y: node.ty, z: node.tz };
          node.x = from.x; node.y = from.y; node.z = from.z;
        }
      });
      if (this.mode === "flow") this.flowLayout();
      this.leafCount = Math.max(1, slot - this.roots.length);
      if (!document.fullscreenElement) {
        const wanted = this.mode === "flow" ? this.flowRows * FLOW_ROW_H + 140 : this.leafCount * 26 + 96;
        this.canvas.style.height = Math.max(300, Math.min(580, wanted)) + "px";
      }
    }

    bounds() {
      const nodes = [...this.display.values()];
      const xs = nodes.map((n) => n.tx), ys = nodes.map((n) => n.ty);
      const box = { minX: Math.min(...xs), maxX: Math.max(...xs), minY: Math.min(...ys), maxY: Math.max(...ys) };
      box.cx = (box.minX + box.maxX) / 2;
      box.cy = (box.minY + box.maxY) / 2;
      return box;
    }

    /* Zoom-to-fit with padding (room for labels, the control bar and the tooltip). */
    fit() {
      const width = this.canvas.clientWidth || 600, height = this.canvas.clientHeight || 320;
      const box = this.bounds();
      this.centre = { x: box.cx, y: box.cy };
      const pad = this.mode === "flow" ? { left: 14, right: 14, top: 82, bottom: 18 }
        : { left: 30, right: this.mode === "2d" ? 150 : 60, top: 48, bottom: 34 };
      const availableW = Math.max(60, width - pad.left - pad.right);
      const availableH = Math.max(60, height - pad.top - pad.bottom);
      let zoom;
      if (this.mode === "flow") {
        zoom = Math.min(1.2, availableW / (box.maxX - box.minX + FLOW_BOX_W + 28),
                        availableH / (box.maxY - box.minY + FLOW_BOX_H + 12));
      } else if (this.mode === "2d") {
        zoom = Math.min(1.15, availableW / Math.max(1, box.maxX - box.minX), availableH / Math.max(1, box.maxY - box.minY));
      } else {
        // The graph turns around its vertical axis, so measure the projected extent over a
        // full turn at the current tilt: the fit then holds while it rotates.
        let extentX = 1, extentY = 1;
        for (let step = 0; step < 24; step += 1) {
          const angle = (step / 24) * Math.PI * 2;
          this.display.forEach((n) => {
            const p = rotate({ x: n.tx - box.cx, y: n.ty - box.cy, z: n.tz }, angle, this.rotX);
            const s = FOCAL / Math.max(140, FOCAL + p.z);
            extentX = Math.max(extentX, Math.abs(p.x * s));
            extentY = Math.max(extentY, Math.abs(p.y * s));
          });
        }
        zoom = Math.min(1.15, availableW / (2 * extentX), availableH / (2 * extentY));
      }
      this.target = { zoom, panX: (pad.left - pad.right) / 2, panY: (pad.top - pad.bottom) / 2 };
    }

    /* Classic flow layout: one lane per entity type, ordered CVE -> CWE -> CAPEC -> ATT&CK. */
    flowLayout() {
      const all = [...this.display.values()];
      let x = 0, rowsMax = 1;
      this.flowColumns = [];
      this.types.forEach((type) => {
        const members = all.filter((n) => n.type === type).sort((a, b) => a.ty - b.ty);
        if (!members.length) return;
        const subs = Math.ceil(members.length / FLOW_MAX_ROWS);     // a long lane wraps into sub-columns
        const per = Math.ceil(members.length / subs);
        const col = this.flowColumns.length;
        for (let s = 0; s < subs; s += 1) {
          const slice = members.slice(s * per, (s + 1) * per);
          slice.forEach((node, row) => {
            node.tx = x + s * FLOW_SUB_W;
            node.ty = (row - (slice.length - 1) / 2) * FLOW_ROW_H;
            node.tz = 0;
            node.col = col;
          });
          rowsMax = Math.max(rowsMax, slice.length);
        }
        this.flowColumns.push({ type, x0: x, x1: x + (subs - 1) * FLOW_SUB_W, index: col });
        x += (subs - 1) * FLOW_SUB_W + FLOW_COL_W;
      });
      this.flowRows = rowsMax;
    }

    /* The flow diagram: swimlanes, curved arrows that march from source to target, boxed nodes.
     * Lanes and their nodes appear one after another, left to right. */
    drawFlow(context, width, height, nodes) {
      const zoom = this.view.zoom, still = reducedMotion.matches, seconds = this.time / 1000;
      const sx = (cx) => width / 2 + this.view.panX + (cx - this.centre.x) * zoom;
      const bw = FLOW_BOX_W * zoom, bh = FLOW_BOX_H * zoom;
      const STEP = 0.5, FADE = 0.4;
      const sans = '"Segoe UI", system-ui, sans-serif', mono = 'ui-monospace, Consolas, monospace';
      const fade = (delay) => (still ? 1 : Math.max(0, Math.min(1, (seconds - delay) / FADE)));
      const LEAD = 0.45;                                   // edges fade in first, then the nodes pop in
      nodes.forEach((n) => { n.alpha = fade(n.col * STEP + LEAD); n.edgeIn = fade(n.col * STEP); });
      let lit = null;
      if (this.hover) lit = new Set([this.hover.id, ...this.neighbours.get(this.hover.id)]);
      else if (this.hoverEdge) lit = new Set([this.hoverEdge.a.id, this.hoverEdge.b.id]);
      const DIM = 0.2;

      // lanes with a header per entity type and a chevron between neighbouring lanes
      const lanes = this.flowColumns.map((col) => ({
        col, left: sx(col.x0) - bw / 2 - 12 * zoom, right: sx(col.x1) + bw / 2 + 12 * zoom }));
      lanes.forEach((lane, i) => {
        const mid = (lane.left + lane.right) / 2, color = TYPE_COLORS[lane.col.type];
        context.globalAlpha = fade(lane.col.index * STEP - 0.25);
        context.fillStyle = PAL.lane;
        context.beginPath();
        context.roundRect(lane.left, 42, lane.right - lane.left, Math.max(20, height - 50), 10);
        context.fill();
        context.fillStyle = color;
        context.font = `600 11.5px ${sans}`;
        context.textAlign = "center";
        context.fillText(TYPE_TITLES[lane.col.type] || lane.col.type, mid, 60);
        context.fillRect(mid - 16, 67, 32, 2);
        const next = lanes[i + 1];
        if (next && next.left - lane.right > 12) {
          const cx = (lane.right + next.left) / 2;
          context.strokeStyle = PAL.muted;
          context.lineWidth = 1.6;
          context.beginPath();
          context.moveTo(cx - 3, 55);
          context.lineTo(cx + 2, 59);
          context.lineTo(cx - 3, 63);
          context.stroke();
        }
      });

      // edges: curved arrows; the dashes travel in the direction of the relationship
      const bez = (p0, c1, c2, p3, t) => {
        const u = 1 - t;
        return { x: u * u * u * p0.x + 3 * u * u * t * c1.x + 3 * u * t * t * c2.x + t * t * t * p3.x,
                 y: u * u * u * p0.y + 3 * u * u * t * c1.y + 3 * u * t * t * c2.y + t * t * t * p3.y };
      };
      const pills = [];
      this.links.forEach((link, index) => {
        const a = link.a, b = link.b, A = a.screen, B = b.screen;
        let p0, c1, c2, p3;
        if (Math.abs(a.tx - b.tx) < 1) {                    // same column: loop out on the right
          const out = bw / 2 + 46 * zoom;
          p0 = { x: A.x + bw / 2, y: A.y }; c1 = { x: A.x + out, y: A.y };
          c2 = { x: B.x + out, y: B.y }; p3 = { x: B.x + bw / 2, y: B.y };
        } else {
          const dir = B.x >= A.x ? 1 : -1;
          p0 = { x: A.x + dir * bw / 2, y: A.y }; p3 = { x: B.x - dir * bw / 2, y: B.y };
          const dx = Math.max(36 * zoom, Math.abs(p3.x - p0.x) * 0.5) * dir;
          c1 = { x: p0.x + dx, y: p0.y }; c2 = { x: p3.x - dx, y: p3.y };
        }
        const active = this.hoverEdge === link || (this.hover && (a === this.hover || b === this.hover));
        const color = active ? PAL.accent : PAL.borderStrong;
        context.globalAlpha = Math.min(a.edgeIn, b.edgeIn) * (lit && !active ? DIM : 1);
        context.strokeStyle = color;
        context.lineWidth = (active ? 2.2 : 1.4) * Math.max(0.75, Math.min(1.2, zoom));
        context.setLineDash(link.aggregate ? [4, 4] : [7, 5]);
        context.lineDashOffset = link.aggregate || still ? 0 : -seconds * 26;
        context.beginPath();
        context.moveTo(p0.x, p0.y);
        context.bezierCurveTo(c1.x, c1.y, c2.x, c2.y, p3.x, p3.y);
        context.stroke();
        context.setLineDash([]);
        if (link.aggregate) { link.pts = null; return; }
        link.pts = Array.from({ length: 17 }, (_, k) => bez(p0, c1, c2, p3, k / 16));
        const angle = Math.atan2(p3.y - c2.y, p3.x - c2.x), size = 7 * Math.max(zoom, 0.75);
        context.fillStyle = color;
        context.beginPath();
        context.moveTo(p3.x, p3.y);
        context.lineTo(p3.x - size * Math.cos(angle - 0.45), p3.y - size * Math.sin(angle - 0.45));
        context.lineTo(p3.x - size * Math.cos(angle + 0.45), p3.y - size * Math.sin(angle + 0.45));
        context.closePath();
        context.fill();
        if (active) {
          if (!still) {
            const dot = bez(p0, c1, c2, p3, (seconds * 0.5 + index * 0.13) % 1);
            context.beginPath();
            context.arc(dot.x, dot.y, 3, 0, Math.PI * 2);
            context.fill();
          }
          pills.push({ text: link.rel, at: bez(p0, c1, c2, p3, 0.5) });
        }
      });
      context.globalAlpha = 1;

      // nodes
      const ordered = [...nodes].sort((m, n) => Number(m === this.hover) - Number(n === this.hover));
      const idPx = Math.max(8, Math.min(14, 12 * zoom)), namePx = Math.max(7.5, Math.min(12.5, 10.5 * zoom));
      for (const n of ordered) {
        const { x, y } = n.screen, color = TYPE_COLORS[n.type], hovered = n === this.hover;
        const bx = x - bw / 2, by = y - bh / 2, r = 7 * zoom;
        const base = n.alpha * (lit && !lit.has(n.id) ? DIM : 1);
        const pop = still ? 1 : 0.8 + 0.2 * easeOutBack(n.alpha);     // scale 0.8 -> 1 with a spring
        context.save();
        context.translate(x, y); context.scale(pop, pop); context.translate(-x, -y);
        n.box = { x: bx, y: by, w: bw, h: bh };
        context.globalAlpha = base;
        context.shadowColor = hovered || n.root ? color : "transparent";
        context.shadowBlur = hovered || n.root ? 12 : 0;
        context.beginPath();
        context.roundRect(bx, by, bw, bh, r);
        context.fillStyle = PAL.surface;
        context.fill();
        context.shadowBlur = 0;
        if (n.root || n.focus) {
          context.globalAlpha = base * 0.12;
          context.fillStyle = color;
          context.fill();
          context.globalAlpha = base;
        }
        context.strokeStyle = color;
        context.lineWidth = hovered ? 2.6 : n.root || n.focus ? 2.2 : 1.2;
        if (n.aggregate) context.setLineDash([4, 3]);
        context.stroke();
        context.setLineDash([]);
        if ((n.root || n.focus) && !still && n.alpha >= 1) {         // slow soft ring around the selected node
          const p = (((seconds % 2.5) + 2.5) % 2.5) / 2.5, grow = 3 + 9 * p;
          context.globalAlpha = base * 0.35 * (1 - p);
          context.strokeStyle = color;
          context.lineWidth = 1.5;
          context.beginPath();
          context.roundRect(bx - grow, by - grow, bw + grow * 2, bh + grow * 2, r + grow);
          context.stroke();
          context.globalAlpha = base;
        }
        if (n.aggregate) {
          context.fillStyle = color;
          context.font = `600 ${idPx}px ${sans}`;
          context.textAlign = "center";
          context.fillText(n.label, x, y + idPx * 0.35);
          context.restore();
          continue;
        }
        context.fillStyle = color;
        context.beginPath();
        context.roundRect(bx, by, 5 * zoom, bh, [r, 0, 0, r]);
        context.fill();
        const pad = 12 * zoom, room = bw - pad - 6 * zoom, showName = zoom >= 0.62 && n.name && n.name !== n.id;
        context.textAlign = "left";
        context.fillStyle = PAL.text;
        context.font = `600 ${idPx}px ${mono}`;
        context.fillText(n.id, bx + pad, showName ? by + bh * 0.43 : by + bh / 2 + idPx * 0.35);
        if (showName) {
          context.font = `400 ${namePx}px ${sans}`;
          const key = Math.round(room) + "|" + namePx;
          if (n.fitKey !== key) { n.fitKey = key; n.fitName = fitLabel(context, n.name, room); }
          context.fillStyle = PAL.muted;
          context.fillText(n.fitName, bx + pad, by + bh * 0.8);
        }
        context.restore();
      }
      context.globalAlpha = 1;

      // relationship names next to the arrows of the hovered node / edge
      context.font = `600 10.5px ${mono}`;
      context.textAlign = "center";
      pills.forEach((pill) => {
        const w = context.measureText(pill.text).width + 12;
        context.fillStyle = PAL.surface;
        context.strokeStyle = PAL.accent;
        context.lineWidth = 1;
        context.beginPath();
        context.roundRect(pill.at.x - w / 2, pill.at.y - 9, w, 18, 9);
        context.fill();
        context.stroke();
        context.fillStyle = PAL.accent;
        context.fillText(pill.text, pill.at.x, pill.at.y + 3.5);
      });
    }

    /* ---------------- controls ---------------- */
    zoomBy(factor) {
      this.target.zoom = Math.max(0.08, Math.min(4, this.target.zoom * factor));
      this.target.panX *= factor;
      this.target.panY *= factor;
      this.userView = true;
      this.redraw();
    }

    reset() {
      this.rotY = -0.45;
      this.rotX = 0.28;
      this.userView = false;
      this.fit();
      this.redraw();
    }

    setMode(mode) {
      this.mode = mode;
      try { localStorage.setItem(GRAPH_MODE_KEY, mode); } catch (error) { /* preference is optional */ }
      this.userView = false;
      this.hover = null;
      this.hoverEdge = null;
      this.hideTip();
      this.layout();
      this.fit();
      this.redraw();
    }

    toggleGroup(key) {
      if (this.expanded.has(key)) this.expanded.delete(key); else this.expanded.add(key);
      this.hover = null;
      this.hoverEdge = null;
      this.hideTip();
      this.rebuild();
      this.redraw();
    }

    resized() {
      this.layout();
      this.userView = false;
      this.lastWidth = 0;                 // forces a fresh fit on the next draw
      this.redraw();
    }

    redraw() {
      if (reducedMotion.matches || document.hidden) this.draw(0);
    }

    /* ---------------- pointer interaction ---------------- */
    bind() {
      const canvas = this.canvas;
      canvas.addEventListener("pointerdown", (event) => {
        this.drag = { x: event.clientX, y: event.clientY, moved: 0 };
        try { canvas.setPointerCapture(event.pointerId); } catch (error) { /* pointer already gone */ }
        canvas.classList.add("dragging");
      });
      canvas.addEventListener("pointermove", (event) => {
        const box = canvas.getBoundingClientRect();
        const x = event.clientX - box.left, y = event.clientY - box.top;
        if (this.drag) {
          const dx = event.clientX - this.drag.x, dy = event.clientY - this.drag.y;
          this.drag.moved += Math.abs(dx) + Math.abs(dy);
          if (this.mode === "3d") {
            this.rotY += dx * 0.01;
            this.rotX = Math.max(-1.2, Math.min(1.2, this.rotX + dy * 0.008));
          } else if (this.drag.moved >= 6) {
            this.view.panX += dx; this.view.panY += dy;
            this.target.panX += dx; this.target.panY += dy;
            this.userView = true;
          }
          this.drag.x = event.clientX;
          this.drag.y = event.clientY;
        }
        this.hover = this.pickNode(x, y);
        this.hoverEdge = this.hover ? null : this.pickEdge(x, y);
        canvas.classList.toggle("pointing", Boolean(this.hover) && !(this.drag && this.drag.moved >= 6));
        this.showTip(x, y);
        this.redraw();
      });
      const release = (event) => {
        const clicked = this.drag && this.drag.moved < 6 && event.type === "pointerup";
        this.drag = null;
        canvas.classList.remove("dragging");
        if (!clicked || !this.hover) return;
        if (this.hover.aggregate) this.toggleGroup(this.hover.group.key);
        else this.handlers.onPick(this.hover.id);
      };
      canvas.addEventListener("pointerup", release);
      canvas.addEventListener("pointercancel", release);
      canvas.addEventListener("pointerleave", () => {
        if (this.drag) return;
        this.hover = null;
        this.hoverEdge = null;
        this.hideTip();
        this.redraw();
      });
    }

    pickNode(x, y) {
      if (this.mode === "flow") {                       // boxes: rectangle hit test, last drawn wins
        let hit = null;
        this.display.forEach((node) => {
          const b = node.box;
          if (b && node.alpha > 0.4 && x >= b.x && x <= b.x + b.w && y >= b.y && y <= b.y + b.h) hit = node;
        });
        return hit;
      }
      let best = null, bestDistance = 16 * 16;
      this.display.forEach((node) => {
        if (!node.screen) return;
        const d = (node.screen.x - x) ** 2 + (node.screen.y - y) ** 2;
        if (d < bestDistance) { best = node; bestDistance = d; }
      });
      return best;
    }

    pickEdge(x, y) {
      let best = null, bestDistance = 7;
      for (const link of this.links) {
        if (link.aggregate) continue;
        const pts = this.mode === "flow" ? link.pts : (link.a.screen && link.b.screen ? [link.a.screen, link.b.screen] : null);
        if (!pts) continue;
        for (let i = 0; i < pts.length - 1; i += 1) {
          const ax = pts[i].x, ay = pts[i].y, bx = pts[i + 1].x, by = pts[i + 1].y;
          const length2 = (bx - ax) ** 2 + (by - ay) ** 2 || 1;
          const t = Math.max(0, Math.min(1, ((x - ax) * (bx - ax) + (y - ay) * (by - ay)) / length2));
          const d = Math.hypot(x - (ax + (bx - ax) * t), y - (ay + (by - ay) * t));
          if (d < bestDistance) { best = link; bestDistance = d; }
        }
      }
      return best;
    }

    showTip(x, y) {
      const tip = this.tip;
      tip.replaceChildren();
      if (this.hover && this.hover.aggregate) {
        tip.append(el("b", null, this.hover.label),
                   el("span", null, this.hover.group.expanded ? "Click to collapse" : "Click to show them"));
      } else if (this.hover) {
        tip.append(el("b", null, this.hover.id), el("i", null, TYPE_NAMES[this.hover.type]));
        if (this.hover.name) tip.appendChild(el("span", null, this.hover.name.length > 90 ? this.hover.name.slice(0, 88) + "…" : this.hover.name));
        tip.style.setProperty("--tone", TYPE_COLORS[this.hover.type]);
      } else if (this.hoverEdge) {
        tip.append(el("b", null, this.hoverEdge.rel), el("span", null, `${this.hoverEdge.a.id} → ${this.hoverEdge.b.id}`));
        tip.style.removeProperty("--tone");
      } else {
        this.hideTip();
        return;
      }
      tip.hidden = false;
      const width = this.canvas.clientWidth, height = this.canvas.clientHeight;
      const left = Math.max(8, Math.min(x + 14, width - tip.offsetWidth - 8));
      const top = y + 18 + tip.offsetHeight > height ? Math.max(8, y - tip.offsetHeight - 12) : y + 18;
      tip.style.left = left + "px";
      tip.style.top = top + "px";
    }

    hideTip() {
      this.tip.hidden = true;
    }

    /* ---------------- drawing ---------------- */
    project(node, width, height) {
      const dx = node.x - this.centre.x, dy = node.y - this.centre.y;
      if (this.mode !== "3d") {
        return { x: width / 2 + this.view.panX + dx * this.view.zoom,
                 y: height / 2 + this.view.panY + dy * this.view.zoom, s: 1, z: 0 };
      }
      const p = rotate({ x: dx, y: dy, z: node.z }, this.rotY, this.rotX);
      const s = FOCAL / Math.max(140, FOCAL + p.z);
      return { x: width / 2 + this.view.panX + p.x * this.view.zoom * s,
               y: height / 2 + this.view.panY + p.y * this.view.zoom * s, s, z: p.z };
    }

    draw(delta) {
      const width = this.canvas.clientWidth, height = this.canvas.clientHeight;
      if (!width || !height) return;
      if (width !== this.lastWidth || height !== this.lastHeight) {     // container resized
        this.lastWidth = width;
        this.lastHeight = height;
        if (!this.userView) { this.fit(); this.snap = true; }
      }
      const context = fitCanvas(this.canvas, width, height);
      context.clearRect(0, 0, width, height);
      this.time += delta;

      // ease node positions and the camera towards their targets
      const k = this.snap || reducedMotion.matches ? 1 : 1 - Math.exp(-delta / 110);
      this.snap = false;
      this.display.forEach((node) => {
        node.x += (node.tx - node.x) * k;
        node.y += (node.ty - node.y) * k;
        node.z += (node.tz - node.z) * k;
      });
      ["zoom", "panX", "panY"].forEach((key) => { this.view[key] += (this.target[key] - this.view[key]) * k; });
      if (this.mode === "3d" && !this.drag && !this.hover && !this.hoverEdge) this.rotY += delta * 0.00016;

      const nodes = [...this.display.values()];
      nodes.forEach((node) => { node.screen = this.project(node, width, height); });
      if (this.mode === "flow") { this.drawFlow(context, width, height, nodes); return; }

      // hover: the node, its direct neighbours and their edges stay lit; the rest drops to 20%
      let lit = null;
      if (this.hover) lit = new Set([this.hover.id, ...this.neighbours.get(this.hover.id)]);
      else if (this.hoverEdge) lit = new Set([this.hoverEdge.a.id, this.hoverEdge.b.id]);
      const DIM = 0.2;

      this.links.forEach((link, index) => {
        const a = link.a.screen, b = link.b.screen;
        const active = this.hoverEdge === link || (this.hover && (link.a === this.hover || link.b === this.hover));
        context.globalAlpha = lit && !active ? DIM : 1;
        context.strokeStyle = active ? PAL.accent : PAL.borderStrong;
        context.lineWidth = active ? 2 : 1;
        context.setLineDash(link.aggregate ? [4, 4] : []);
        context.beginPath();
        context.moveTo(a.x, a.y);
        context.lineTo(b.x, b.y);
        context.stroke();
        if (!link.aggregate && !reducedMotion.matches) {     // a light travels source -> target
          const t = (this.time * 0.00045 + index * 0.137) % 1;
          context.fillStyle = active ? PAL.text : PAL.accent;
          context.beginPath();
          context.arc(a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t, active ? 2.4 : 1.5, 0, Math.PI * 2);
          context.fill();
        }
      });
      context.setLineDash([]);

      nodes.sort((m, n) => n.screen.z - m.screen.z);       // back to front
      context.font = "11px ui-monospace, Consolas, monospace";
      for (const node of nodes) {
        const { x, y, s } = node.screen;
        const hovered = node === this.hover;
        const color = TYPE_COLORS[node.type];
        const scale = Math.max(0.55, Math.min(1.5, this.mode === "2d" ? Math.sqrt(this.view.zoom) : s * Math.sqrt(this.view.zoom)));
        const radius = (node.aggregate ? 9 : node.root || node.focus ? 8.5 : 5.5) * scale * (hovered ? 1.3 : 1);
        context.globalAlpha = lit && !lit.has(node.id) ? DIM : 1;
        context.shadowColor = color;
        context.shadowBlur = hovered || node.root ? 16 : 7;
        context.beginPath();
        context.arc(x, y, radius, 0, Math.PI * 2);
        if (node.aggregate) {
          context.fillStyle = PAL.surface;
          context.fill();
          context.shadowBlur = 0;
          context.setLineDash([3, 3]);
          context.strokeStyle = color;
          context.lineWidth = 1.6;
          context.stroke();
          context.setLineDash([]);
          context.fillStyle = color;
          context.textAlign = "center";
          context.fillText(node.group.expanded ? "−" : "+", x, y + 4);
        } else {
          context.fillStyle = color;
          context.fill();
          context.shadowBlur = 0;
          if (node.root || node.focus) {
            context.strokeStyle = PAL.text;
            context.lineWidth = 1.5;
            context.beginPath();
            context.arc(x, y, radius + 3.5, 0, Math.PI * 2);
            context.stroke();
          }
        }
        // labels only for the root, its direct neighbours, "+N" nodes and whatever is hovered
        if (node.aggregate || hovered || this.labelled.has(node.id)) {
          context.fillStyle = hovered ? PAL.text : PAL.muted;
          const text = node.aggregate ? node.label : node.id;
          if (this.mode === "2d") {
            context.textAlign = "left";
            context.fillText(text, x + radius + 6, y + 4);
          } else {
            context.textAlign = "center";
            context.fillText(text, x, y + radius + 13);
          }
        }
      }
      context.globalAlpha = 1;
    }
  }

  /* ------------------------------------------------------------------ */
  /* one animation loop for everything                                   */
  /* ------------------------------------------------------------------ */
  const graphs = new Set();
  const graphObserver = new IntersectionObserver((entries) => {
    entries.forEach((entry) => { if (entry.target.relationGraph) entry.target.relationGraph.visible = entry.isIntersecting; });
  });
  let lastFrame = performance.now();

  function frame(now) {
    const delta = Math.min(50, now - lastFrame);
    lastFrame = now;
    if (!document.hidden && !reducedMotion.matches) {
      graphs.forEach((graph) => { if (graph.visible) graph.draw(delta); });
    }
    requestAnimationFrame(frame);
  }

  function drawStatic() {
    graphs.forEach((graph) => graph.draw(0));
  }

  requestAnimationFrame(frame);
  if (reducedMotion.matches) drawStatic();
  window.addEventListener("resize", () => { if (reducedMotion.matches) drawStatic(); });

  /* ------------------------------------------------------------------ */
  /* message rendering                                                   */
  /* ------------------------------------------------------------------ */
  function addUserMessage(text, when, animate) {
    const wrapper = el("div", animate ? "msg msg-user" : "msg msg-user no-anim");
    wrapper.appendChild(el("div", "meta-line", `You · ${timeLabel(when)}`));
    wrapper.appendChild(el("div", "bubble", text));
    chat.appendChild(wrapper);
  }

  function addLoading() {
    const wrapper = el("div", "msg msg-ai");
    wrapper.appendChild(el("div", "meta-line", "CyberIntelliX"));
    const card = el("div", "card");
    const loading = el("div", "loading");
    loading.setAttribute("role", "status");
    const text = el("div", "loading-text");
    const headline = el("b", null, "Classifying your question");
    text.append(headline, document.createTextNode("Answers are built only from retrieved evidence."));
    loading.append(el("div", "spinner"), text);
    card.appendChild(loading);
    wrapper.appendChild(card);
    chat.appendChild(wrapper);
    const steps = ["Searching the knowledge graph", "Traversing relationships", "Validating the evidence",
                   "Writing the answer"];
    let step = 0;
    wrapper.loadingTimer = setInterval(() => {
      if (step < steps.length) headline.textContent = steps[step];
      else clearInterval(wrapper.loadingTimer);
      step += 1;
    }, 900);
    scrollToBottom();
    return wrapper;
  }

  function metricsSection(metrics) {
    const valid = (value) => typeof value === "number" && Number.isFinite(value);
    const percent = (value) => {
      if (!valid(value)) return "--";
      const scaled = value * 100;
      return (Number.isInteger(Math.round(scaled * 10) / 10) ? Math.round(scaled).toString() : scaled.toFixed(1)) + "%";
    };
    const category = CATEGORY_LABELS[metrics.category] || metrics.category || "";
    const hasBenchmark = metrics.scope === "offline_benchmark" && metrics.sample_size;
    const cards = [["Precision", metrics.precision]];
    if (valid(metrics.recall)) cards.push(["Recall", metrics.recall]);
    cards.push(["F1 Score", metrics.f1_score], ["Accuracy", metrics.accuracy]);

    // Collapsed by default: one summary line, the cards open on demand.
    const details = el("details", "metrics-block");
    const summaryText = hasBenchmark
      ? `Benchmark: Precision ${percent(metrics.precision)} · F1 ${percent(metrics.f1_score)} · ` +
        `Accuracy ${percent(metrics.accuracy)} (n = ${metrics.sample_size})`
      : "Benchmark: not run yet";
    details.appendChild(el("summary", "metrics-summary", summaryText));
    const body = el("div", "details-body");
    const grid = el("div", "metrics");
    cards.forEach(([label, value]) => {
      const card = el("div", "metric");
      card.appendChild(el("div", "label", label));
      card.appendChild(el("div", valid(value) ? "value" : "value empty", percent(value)));
      const bar = el("div", "bar");
      const fill = el("i");
      if (valid(value)) fill.style.width = Math.round(value * 100) + "%";
      bar.appendChild(fill);
      card.appendChild(bar);
      card.appendChild(el("div", "sample", hasBenchmark ? `n = ${metrics.sample_size} · ${category}` : "no benchmark yet"));
      grid.appendChild(card);
    });
    body.appendChild(grid);
    if (hasBenchmark) {
      const when = metrics.evaluated_at ? new Date(metrics.evaluated_at).toLocaleDateString() : "";
      body.appendChild(el("p", "metrics-note",
        `Offline benchmark for ${category} ` +
        `(${metrics.sample_size} labelled questions${when ? ", run " + when : ""}). ` +
        "It describes the system on the test set, not the correctness of this answer."));
    } else {
      body.appendChild(el("p", "metrics-note",
        "Run the labelled benchmark (python -m backend.manage evaluate) to fill these in."));
    }
    details.appendChild(body);
    return details;
  }

  /* ---- "Recommended actions": the backend hint is one paragraph; it is parsed here ---- */
  const URL_RE = /https?:\/\/[^\s<>"']+/g;
  const MITIGATION_BLOCK_RE = /Mitigations documented for[^:]*:\s*([\s\S]*?)(?=\s+(?:Next step:|These measures come\b)|$)/;
  const MITIGATION_SPLIT_RE = new RegExp("(?=\\[(?:" + ID_PATTERN + ")\\]\\s)");
  const MITIGATION_ENTRY_RE = new RegExp("^\\[(" + ID_PATTERN + ")\\]\\s*(?:\\[([A-Z][^\\]]{2,70})\\]\\s*)?([\\s\\S]*)$");
  const RICH_RE = new RegExp("(\\u0001\\d+\\u0001|\\[(?:" + ID_PATTERN + ")\\]|\\b(?:" + ID_PATTERN + ")\\b)", "g");

  /* Split the hint text into steps: sentences, plus one step per documented mitigation. */
  function parseHint(text) {
    const urls = [];
    // URLs contain dots, so they are swapped for placeholders before sentence splitting.
    let work = text.replace(URL_RE, (match) => {
      let url = match, tail = "";
      while (/[.,;:)\]]$/.test(url)) { tail = url.slice(-1) + tail; url = url.slice(0, -1); }
      urls.push(url);
      return "\u0001" + (urls.length - 1) + "\u0001" + tail;
    });
    let mitigations = [];
    work = work.replace(MITIGATION_BLOCK_RE, (_, block) => {
      mitigations = block.split(MITIGATION_SPLIT_RE).map((part) => part.trim()).filter(Boolean).map((part) => {
        const entry = MITIGATION_ENTRY_RE.exec(part);
        return entry ? { id: entry[1], phase: entry[2] || "", text: (entry[3] || "").trim() } : { text: part };
      });
      return "\u0002";
    });
    const sentences = (chunk) => chunk.split(/(?<=[.!?])\s+(?=[A-Z])/).map((s) => s.trim()).filter(Boolean)
      .map((s) => ({ text: s }));
    const [before, ...rest] = work.split("\u0002");
    const after = rest.join(" ");
    const steps = [...sentences(before), ...mitigations, ...sentences(after)];
    const notes = steps.filter((step) => /^These measures come from/.test(step.text));
    return { steps: steps.filter((step) => !notes.includes(step)), notes, urls };
  }

  function linkChip(url) {
    let host;
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
      host = parsed.hostname.replace(/^www\./, "");
    } catch (error) { return null; }
    const link = el("a", "link-chip", host + " ↗");
    link.href = url;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.title = url;
    link.setAttribute("aria-label", `${host} (opens in a new tab): ${url}`);
    return link;
  }

  /* Text with link chips (each URL once), entity-ID chips without brackets, and plain text. */
  function appendRich(parent, text, urls, seenUrls) {
    let afterChip = false;
    for (const part of text.split(RICH_RE)) {
      if (!part) continue;
      const placeholder = /^\u0001(\d+)\u0001$/.exec(part);
      if (placeholder) {
        const url = urls[Number(placeholder[1])];
        if (seenUrls.has(url)) continue;                 // repeated URL: shown once only
        seenUrls.add(url);
        const chip = linkChip(url);
        parent.appendChild(chip || document.createTextNode(url));
        afterChip = true;
      } else if (ID_RE.test(part.replace(/^\[|\]$/g, ""))) {
        parent.appendChild(idButton(part.replace(/^\[|\]$/g, ""), "link-id"));
        afterChip = false;
      } else if (afterChip && /^[\s;,.]*$/.test(part)) {
        parent.appendChild(document.createTextNode(" "));   // drop "; " / "." left between link chips
      } else {
        parent.appendChild(document.createTextNode(afterChip ? part.replace(/^[;,.]\s*/, " ") : part));
        afterChip = false;
      }
    }
  }

  function hintSection(data) {
    const section = el("div", "section hint");
    const head = el("div", "section-head");
    head.appendChild(el("h3", "section-title", "Recommended actions"));
    section.appendChild(head);
    const { steps, notes, urls } = parseHint(data.hint);
    const seenUrls = new Set();
    const list = el(steps.length > 1 ? "ol" : "div", "actions");
    const clamps = [];
    steps.forEach((step, k) => {
      const item = el(steps.length > 1 ? "li" : "p");
      item.style.setProperty("--k", String(k));
      const body = el("div", "clamp");
      if (step.id) {
        body.appendChild(idButton(step.id, "link-id"));
        body.appendChild(document.createTextNode(" "));
        if (step.phase) body.append(el("span", "phase", step.phase), document.createTextNode(" "));
      }
      appendRich(body, step.text, urls, seenUrls);
      item.appendChild(body);
      list.appendChild(item);
      clamps.push(body);
    });
    section.appendChild(list);
    notes.forEach((note) => {
      const paragraph = el("p", "actions-note");
      appendRich(paragraph, note.text, urls, seenUrls);
      section.appendChild(paragraph);
    });

    // Each step is clamped to 4 lines; one toggle expands or collapses them all.
    const toggle = el("button", "mini", "Show more");
    toggle.type = "button";
    toggle.hidden = true;
    toggle.setAttribute("aria-expanded", "false");
    head.appendChild(toggle);
    const setExpanded = (expanded) => {
      list.classList.toggle("expanded", expanded);
      toggle.textContent = expanded ? "Show less" : "Show more";
      toggle.setAttribute("aria-expanded", String(expanded));
    };
    toggle.addEventListener("click", () => setExpanded(!list.classList.contains("expanded")));
    // A chip reached with the keyboard inside clipped text must not stay invisible.
    list.addEventListener("focusin", (event) => {
      const clamp = event.target.closest(".clamp");
      if (!clamp || list.classList.contains("expanded")) return;
      if (event.target.getBoundingClientRect().bottom > clamp.getBoundingClientRect().bottom + 1) setExpanded(true);
    });
    const measure = () => {
      if (list.classList.contains("expanded")) return;
      toggle.hidden = !clamps.some((clamp) => clamp.scrollHeight > clamp.clientHeight + 1);
    };
    requestAnimationFrame(measure);
    if ("ResizeObserver" in window) new ResizeObserver(measure).observe(list);
    return section;
  }

  function graphSection(data) {
    const names = new Map();
    (data.related_entities || []).forEach((entity) => { if (entity.name) names.set(entity.id, entity.name); });
    (data.sources || []).forEach((source) => {
      if (source.identifier && ID_RE.test(source.identifier) && source.title) names.set(source.identifier, source.title);
    });
    const section = el("div", "section");
    const head = el("div", "section-head");
    head.appendChild(el("h3", "section-title", "Relationship graph"));
    section.appendChild(head);

    const wrap = el("div", "graph-wrap");
    const canvas = el("canvas", "graph");
    canvas.setAttribute("role", "img");
    canvas.setAttribute("aria-label",
      `Graph of ${data.relationships.length} relationships. The same entities are listed under Related entities.`);
    const tip = el("div", "graph-tip");
    tip.hidden = true;
    tip.setAttribute("aria-hidden", "true");

    // control bar (top right): zoom in / out, fit, 2D <-> 3D, fullscreen
    const controls = el("div", "graph-controls");
    controls.setAttribute("role", "toolbar");
    controls.setAttribute("aria-label", "Graph view controls");
    const control = (text, label, action) => {
      const button = el("button", "gbtn", text);
      button.type = "button";
      button.title = label;
      button.setAttribute("aria-label", label);
      button.addEventListener("click", action);
      controls.appendChild(button);
      return button;
    };
    control("+", "Zoom in", () => graph.zoomBy(1.25));
    control("−", "Zoom out", () => graph.zoomBy(0.8));
    control("Fit", "Reset the view and fit the whole graph", () => graph.reset());
    const modeButton = control("Flow", "", () => {
      graph.setMode(GRAPH_MODES[(GRAPH_MODES.indexOf(graph.mode) + 1) % GRAPH_MODES.length]);
      syncMode();
    });
    const fullButton = control("Full", "Fullscreen", () => {
      if (document.fullscreenElement === wrap) document.exitFullscreen();
      else wrap.requestFullscreen().catch(() => toast("Fullscreen is not available here"));
    });
    if (!wrap.requestFullscreen) fullButton.hidden = true;
    wrap.append(canvas, tip, controls);
    section.appendChild(wrap);

    // Keyboard-accessible twins of the "+N" nodes drawn on the canvas.
    const groupRow = el("div", "graph-groups");
    const renderGroups = (groups) => {
      groupRow.replaceChildren();
      groups.forEach((group) => {
        const button = el("button", "mini",
          `${group.expanded ? "Hide" : "Show"} ${group.count} more ${TYPE_NAMES[group.type]} linked to ${group.hub}`);
        button.type = "button";
        button.dataset.type = group.type;
        button.setAttribute("aria-expanded", String(group.expanded));
        button.addEventListener("click", () => graph.toggleGroup(group.key));
        groupRow.appendChild(button);
      });
      groupRow.hidden = !groups.length;
    };

    const graph = new RelationGraph(wrap, canvas, tip, data.relationships, names, data.identifiers || [], {
      onPick: (id) => openEntityPanel(id, wrap),
      onGroups: renderGroups,
    });
    canvas.relationGraph = graph;
    graphs.add(graph);
    graphObserver.observe(canvas);

    const hint = el("span", "graph-hint");
    function syncMode() {
      const next = MODE_LABELS[GRAPH_MODES[(GRAPH_MODES.indexOf(graph.mode) + 1) % GRAPH_MODES.length]];
      modeButton.textContent = MODE_LABELS[graph.mode];
      modeButton.title = `Switch to the ${next} view`;
      modeButton.setAttribute("aria-label", `${MODE_LABELS[graph.mode]} view. Switch to the ${next} view`);
      hint.textContent = (graph.mode === "flow" ? "Follow the arrows left to right \u00b7 drag to pan"
        : graph.mode === "2d" ? "Drag to pan" : "Drag to rotate") + " \u00b7 click a node to see its details";
    }
    syncMode();
    wrap.addEventListener("fullscreenchange", () => {
      const full = document.fullscreenElement === wrap;
      fullButton.textContent = full ? "Exit" : "Full";
      fullButton.title = full ? "Exit fullscreen" : "Fullscreen";
      fullButton.setAttribute("aria-label", fullButton.title);
      graph.resized();
    });

    const legend = el("div", "graph-legend");
    graph.types.forEach((type) => {
      const item = el("span");
      item.dataset.type = type;
      item.append(el("i"), document.createTextNode(TYPE_NAMES[type]));
      legend.appendChild(item);
    });
    legend.appendChild(hint);
    section.append(groupRow, legend);
    requestAnimationFrame(() => graph.draw(0));
    return section;
  }

  /* ---- Answer details: one tab bar instead of stacked accordions ---- */
  let tabGroupCounter = 0;

  function relatedPanel(body, data) {
    const groups = new Map();
    data.related_entities.forEach((entity) => {
      const key = entity.relation || entity.type;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(entity);
    });
    groups.forEach((entities, relation) => {
      body.appendChild(el("div", "group-title", relation));
      const list = el("ul");
      entities.forEach((entity) => {
        const item = el("li");
        item.appendChild(idButton(entity.id, "link-id"));
        item.appendChild(document.createTextNode(entity.name ? `  ${entity.name}` : ""));
        if (entity.via && entity.via.length && relation.includes("->")) {
          item.appendChild(document.createTextNode(` (via ${entity.via.join(", ")})`));
        }
        list.appendChild(item);
      });
      body.appendChild(list);
    });
  }

  function relationshipsPanel(body, data) {
    if (data.relationships.length) {
      const list = el("ul");
      data.relationships.forEach((rel) => {
        const item = el("li", "edge");
        item.append(document.createTextNode(`(${rel.source})-[`), el("span", "rel", rel.type),
                    document.createTextNode(`]->(${rel.target})`));
        list.appendChild(item);
      });
      body.appendChild(list);
    }
    if (data.missing_relationships.length) {
      body.appendChild(el("div", "group-title", "Not found in the current graph"));
      const list = el("ul");
      data.missing_relationships.forEach((note) => list.appendChild(el("li", "note-missing", note)));
      body.appendChild(list);
    }
  }

  function mitigationsPanel(body, data) {
    const list = el("ul");
    data.mitigations.forEach((text) => {
      const item = el("li");
      appendInline(item, text);
      list.appendChild(item);
    });
    body.appendChild(list);
  }

  function sourcesPanel(body, data) {
    const list = el("ul");
    data.sources.forEach((source) => {
      const item = el("li");
      let label = source.source;
      if (source.identifier) label += ` - ${source.identifier}`;
      if (source.page_number) label += `, p. ${source.page_number}`;
      if (source.url && /^https?:\/\//i.test(source.url)) {
        const link = el("a", null, label);
        link.href = source.url;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        item.appendChild(link);
      } else {
        item.textContent = label;
      }
      list.appendChild(item);
    });
    body.appendChild(list);
  }

  function evidencePanel(body, data) {
    data.evidence.forEach((evidence) => {
      const item = el("div", "evidence-item");
      let headText = evidence.source;
      if (evidence.title) headText += ` | ${evidence.title}`;
      if (evidence.page_number) headText += ` | p. ${evidence.page_number}`;
      const head = el("div", "head");
      head.appendChild(el("span", null, headText));
      // The API's optional `score` is only set for chunks found by similarity / name search.
      if (typeof evidence.score === "number" && Number.isFinite(evidence.score)) {
        const badge = el("span", "score-badge", "score " + evidence.score.toFixed(2));
        badge.title = "Retrieval score reported by the backend for this chunk";
        head.appendChild(badge);
      }
      item.appendChild(head);
      item.appendChild(el("div", "body", evidence.text));
      body.appendChild(item);
    });
  }

  function addDetails(card, data) {
    const safe = { ...data };
    ["related_entities", "relationships", "missing_relationships", "mitigations", "sources", "evidence"]
      .forEach((key) => { safe[key] = Array.isArray(data[key]) ? data[key] : []; });
    const tabs = [
      { label: "Related entities", count: safe.related_entities.length, build: relatedPanel },
      { label: "Graph relationships", count: safe.relationships.length, build: relationshipsPanel,
        show: safe.relationships.length + safe.missing_relationships.length > 0 },
      { label: "Mitigations", count: safe.mitigations.length, build: mitigationsPanel },
      { label: "Source references", count: safe.sources.length, build: sourcesPanel },
      { label: "Retrieved evidence", count: safe.evidence.length, build: evidencePanel },
    ].filter((tab) => (tab.show !== undefined ? tab.show : tab.count > 0));
    if (!tabs.length) return;

    const group = ++tabGroupCounter;
    const wrapper = el("div", "tabs");
    const tablist = el("div", "tablist");
    tablist.setAttribute("role", "tablist");
    tablist.setAttribute("aria-label", "Answer details");
    const buttons = [], panels = [];
    const indicator = el("span", "tab-indicator");
    indicator.setAttribute("aria-hidden", "true");
    tablist.appendChild(indicator);
    let active = 0;
    const place = () => {                                   // the underline slides to the selected tab (transform only)
      const button = buttons[active];
      if (!button || !button.offsetWidth) return;
      indicator.style.transform = `translateX(${button.offsetLeft}px) scaleX(${button.offsetWidth / 100})`;
      tablist.classList.add("has-indicator");
    };

    const select = (index, focus) => {
      active = index;
      buttons.forEach((button, i) => {
        const selected = i === index;
        button.setAttribute("aria-selected", String(selected));
        button.tabIndex = selected ? 0 : -1;
        panels[i].hidden = !selected;
        if (selected && !panels[i].dataset.built) {       // build a panel the first time it is shown
          tabs[i].build(panels[i], safe);
          panels[i].dataset.built = "1";
        }
      });
      place();
      if (focus) buttons[index].focus();
    };

    tabs.forEach((tab, index) => {
      const button = el("button", "tab");
      button.type = "button";
      button.id = `tab-${group}-${index}`;
      button.setAttribute("role", "tab");
      button.setAttribute("aria-controls", `panel-${group}-${index}`);
      button.append(document.createTextNode(tab.label), el("span", "count", `(${tab.count})`));
      button.addEventListener("click", () => select(index, false));
      button.addEventListener("keydown", (event) => {
        const last = tabs.length - 1;
        const next = { ArrowRight: index === last ? 0 : index + 1, ArrowLeft: index === 0 ? last : index - 1,
                       Home: 0, End: last }[event.key];
        if (next === undefined) return;
        event.preventDefault();
        select(next, true);
      });
      tablist.appendChild(button);
      buttons.push(button);

      const panel = el("div", "tabpanel details-body");
      panel.id = `panel-${group}-${index}`;
      panel.setAttribute("role", "tabpanel");
      panel.setAttribute("aria-labelledby", button.id);
      panel.tabIndex = 0;
      panels.push(panel);
    });
    wrapper.appendChild(tablist);
    panels.forEach((panel) => wrapper.appendChild(panel));
    select(0, false);
    card.appendChild(wrapper);
    new ResizeObserver(place).observe(tablist);
  }

  function renderResponse(wrapper, data, animate = true) {
    clearInterval(wrapper.loadingTimer);
    wrapper.replaceChildren();
    const stamp = data.timestamp ? new Date(data.timestamp) : new Date();
    wrapper.appendChild(el("div", "meta-line", `CyberIntelliX · ${timeLabel(stamp)}`));
    const card = el("div", "card");
    if (TYPE_COLORS[data.category]) card.style.setProperty("--tone", TYPE_COLORS[data.category]);

    const answerSection = el("div", "section");
    const head = el("div", "section-head");
    head.appendChild(el("h3", "section-title", "Answer"));
    const answerText = typeof data?.answer === "string" ? data.answer : "";
    const notFound = answerText.trim() === NOT_FOUND;
    if (!notFound && navigator.clipboard) {
      const copy = el("button", "mini", "Copy");
      copy.type = "button";
      copy.addEventListener("click", () => {
        navigator.clipboard.writeText(answerText.replace(/\*\*/g, "")).then(
          () => {
            toast("Answer copied");
            copy.textContent = "\u2713";
            copy.classList.add("copied");
            setTimeout(() => { copy.textContent = "Copy"; copy.classList.remove("copied"); }, 1500);
          }, () => toast("Could not copy"));
      });
      head.appendChild(copy);
    }
    answerSection.appendChild(head);
    const answer = el("div", notFound ? "answer not-found" : "answer");
    renderAnswer(answer, answerText);
    [...answer.children].slice(0, 16).forEach((block, j) => block.style.setProperty("--j", String(j)));
    answerSection.appendChild(answer);

    // Technical metadata is only relevant for knowledge answers, not for greetings.
    const isKnowledge = data.category !== "GENERAL" && data.category !== "UNSUPPORTED";
    if (isKnowledge) {
      const tags = el("div", "tags");
      tags.appendChild(el("span", "tag tag-category", CATEGORY_LABELS[data.category] || data.category));
      (data.identifiers || []).forEach((id) => {
        tags.appendChild(ID_RE.test(id) ? idButton(id, "tag tag-id") : el("span", "tag", id));
      });
      if (data.result_found && data.generation_mode && data.generation_mode !== "llm") {
        const modes = { extractive: "Extractive answer (no LLM configured)",
                        extractive_fallback: "Extractive answer (LLM unavailable)",
                        llm_knowledge: "General knowledge (not verified in the knowledge graph)" };
        if (modes[data.generation_mode]) tags.appendChild(el("span", "tag tag-mode" + (data.generation_mode === "llm_knowledge" ? " tag-warn" : ""), modes[data.generation_mode]));
      }
      if (data.corrections && data.corrections.length) {
        tags.appendChild(el("span", "tag tag-spelling",
          "Interpreted: " + data.corrections.slice(0, 5).map(([a, b]) => a + " → " + b).join(", ")));
      }
      if (data.confidence) {
        const c = data.confidence;
        const tag = el("span", "tag tag-confidence conf-" + c.label,
          `Confidence ${Math.round(c.score * 100)}% (${c.label})`);
        tag.title = c.basis;
        tags.appendChild(tag);
      }
      const first = (data.identifiers || []).find((id) => ID_RE.test(id));
      if (first && data.result_found) {
        const open = el("button", "tag tag-open", "Open in Knowledge Graph");
        open.type = "button";
        open.dataset.graph = first;
        tags.appendChild(open);
      }
      answerSection.appendChild(tags);
    }
    card.appendChild(answerSection);

    if (isKnowledge && data.result_found) {
      if (data.relationships && data.relationships.length) card.appendChild(graphSection(data));
      addDetails(card, data);
    }

    // Metrics and recommended actions exist only for CVE / CWE / CAPEC / ATT&CK answers that
    // retrieved evidence.  Small talk, RESULT NOT FOUND and fundamentals show the answer (and
    // its sources) only: no empty "--" metric cards and no placeholder hint text.
    const answered = data.result_found && DATASET_CATEGORIES.includes(data.category);
    if (answered) {
      // the offline benchmark scores are no longer shown with each answer (they stay on
      // the backend and in the evaluation report); only the recommended actions are added
      if (data.hint_applicable && data.hint && data.hint !== NO_SOLUTION) card.appendChild(hintSection(data));
    }
    if (animate && !reducedMotion.matches) {
      // sections appear one after another: answer, graph, details, metrics, actions
      [...card.children].forEach((child, i) => {
        child.classList.add("reveal");
        child.style.setProperty("--i", String(i));
      });
      const canvas = card.querySelector("canvas.graph");
      if (canvas && canvas.relationGraph) {
        const section = canvas.closest(".reveal");
        canvas.relationGraph.time = -(Number(section.style.getPropertyValue("--i")) * 450 + 400);
      }
    } else {
      const canvas = card.querySelector("canvas.graph");      // restored answers appear fully drawn
      if (canvas && canvas.relationGraph) canvas.relationGraph.time = 1e6;
    }
    wrapper.appendChild(card);
  }

  function renderError(wrapper, message) {
    clearInterval(wrapper.loadingTimer);
    wrapper.replaceChildren();
    wrapper.appendChild(el("div", "meta-line", `CyberIntelliX · ${timeLabel(new Date())}`));
    const card = el("div", "card error-card");
    card.appendChild(el("div", "section", message));
    wrapper.appendChild(card);
  }

  /* ------------------------------------------------------------------ */
  /* conversation history (this browser tab only)                        */
  /* ------------------------------------------------------------------ */
  function saveHistory() {
    try {
      sessionStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(-25)));
    } catch (error) { /* storage unavailable or full: the chat still works */ }
  }

  function restoreHistory() {
    try {
      history = JSON.parse(sessionStorage.getItem(HISTORY_KEY) || "[]");
    } catch (error) { history = []; }
    if (!Array.isArray(history) || !history.length) { history = []; return; }
    const welcome = document.getElementById("welcome");
    if (welcome) welcome.remove();
    history.forEach((entry) => {
      try {
        addUserMessage(entry.q, new Date(entry.t), false);
        const wrapper = el("div", "msg msg-ai no-anim");
        chat.appendChild(wrapper);
        renderResponse(wrapper, entry.data, false);
      } catch (error) { /* a damaged saved entry must not block the others */ }
    });
    scrollToBottom();
  }

  /* ------------------------------------------------------------------ */
  /* backend communication                                               */
  /* ------------------------------------------------------------------ */
  async function api(path, options) {
    const response = await fetch(apiBase + path, options);
    let body = null;
    try { body = await response.json(); } catch (error) { body = null; }
    if (!response.ok) {
      let detail = body && body.detail;
      if (Array.isArray(detail)) detail = detail.map((d) => d.msg).join("; ");
      throw new Error(detail || `The server answered HTTP ${response.status}`);
    }
    return body;
  }

  async function checkStatus() {
    const candidates = apiBase ? [apiBase] : ["", FALLBACK_API];
    for (const base of candidates) {
      try {
        const response = await fetch(base + "/api/status");
        if (!response.ok) continue;
        const body = await response.json();
        if (body.service !== "RAG-Cyber") continue;
        apiBase = base;
        const ok = body.status === "ok";
        statusPill.className = "status " + (ok ? "status-ok" : "status-degraded");
        statusText.textContent = ok ? "Knowledge graph online" : "Database unavailable";
        statusPill.title = ok ? "Backend and Neo4j are reachable" : (body.error || "Neo4j is not reachable");
        return ok;
      } catch (error) { /* try the next candidate */ }
    }
    statusPill.className = "status status-down";
    statusText.textContent = "Backend offline";
    statusPill.title = "Start the backend: uvicorn backend.main:app --port 8000";
    return false;
  }

  const countRuns = new WeakMap();
  function countUp(node, target) {
    const from = Number(node.dataset.value || 0);
    node.dataset.value = String(target);
    const run = (countRuns.get(node) || 0) + 1;      // a newer count stops the older one
    countRuns.set(node, run);
    if (reducedMotion.matches || from === target) { node.textContent = target.toLocaleString(); return; }
    const start = performance.now();
    const step = (now) => {
      if (countRuns.get(node) !== run) return;
      const t = Math.max(0, Math.min(1, (now - start) / 600));
      node.textContent = Math.round(from + (target - from) * (1 - Math.pow(1 - t, 3))).toLocaleString();
      if (t < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  function renderSources(sync) {
    sourcesList.replaceChildren();
    sync.sources.forEach((source) => {
      const item = el("li", "state-" + source.status);
      const row = el("div", "source-row");
      const name = el("span", "source-name");
      name.append(el("i"), document.createTextNode(SOURCE_NAMES[source.source] || source.source));
      let state = "Not synced yet";
      if (source.status === "running") state = "Syncing";
      else if (source.status === "failed") state = "Failed";
      else if (source.status === "success") state = "Updated " + relativeTime(source.last_checked_at || source.last_success_at);
      const stateNode = el("span", "source-state", state);
      if (source.last_error) stateNode.title = source.last_error;
      row.append(name, stateNode);
      item.appendChild(row);
      const progress = source.initial_sync_progress;
      if (source.status === "running" && progress && progress.total) {
        const percent = Math.min(100, (progress.next_index / progress.total) * 100);
        const bar = el("div", "progress");
        const fill = el("i");
        fill.style.width = percent.toFixed(1) + "%";
        bar.appendChild(fill);
        item.appendChild(bar);
        item.appendChild(el("div", "progress-note",
          `${progress.next_index.toLocaleString()} of ${progress.total.toLocaleString()} CVEs (${percent.toFixed(1)}%)`));
      }
      sourcesList.appendChild(item);
    });
  }

  async function refreshPanel() {
    clearTimeout(panelTimer);
    let delay = 60000;
    try {
      const [database, sync] = await Promise.all([api("/api/database/status"), api("/api/sync/status")]);
      renderRelTable(database.relationships);
      document.querySelectorAll("[data-stat]").forEach((node) => {
        const key = node.dataset.stat;
        const value = key === "relationships"
          ? Object.values(database.relationships).reduce((sum, n) => sum + n, 0)
          : database.nodes[key];
        if (typeof value === "number") countUp(node, value);
      });
      renderSources(sync);
      if (sync.running && sync.running.length) delay = 8000;
    } catch (error) {
      sourcesList.replaceChildren(el("li", "source-empty", "Status is not available right now"));
      delay = 20000;
    }
    panelTimer = setTimeout(refreshPanel, delay);
  }

  /* Ask through the streaming endpoint: onDelta gets the answer piece by piece while
     the model writes, the returned promise resolves with the complete response. */
  async function streamChat(message, onDelta) {
    const request = { method: "POST", headers: { "Content-Type": "application/json" },
                      body: JSON.stringify({ message, history_ids: lastEntityIds.slice(0, 6) }) };
    const response = await fetch(apiBase + "/api/chat/stream", request);
    if (response.status === 404 || response.status === 405 || !response.body) {
      return api("/api/chat", request);          // older backend without streaming
    }
    if (!response.ok) {
      let detail = null;
      try { detail = (await response.json()).detail; } catch (error) { detail = null; }
      if (Array.isArray(detail)) detail = detail.map((d) => d.msg).join("; ");
      throw new Error(detail || `The server answered HTTP ${response.status}`);
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let final = null;
    const handle = (line) => {
      if (!line.trim()) return;
      let event;
      try { event = JSON.parse(line); } catch (error) { return; }   // ignore a damaged line
      if (!event || typeof event !== "object") return;
      if (event.type === "delta") { if (typeof event.text === "string") onDelta(event.text); }
      else if (event.type === "final") final = event.response;
      else if (event.type === "error") throw new Error(event.detail || "The answer could not be produced.");
    };
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop();
        lines.forEach(handle);
      }
      handle(buffer + decoder.decode());
    } finally {
      try { reader.releaseLock(); } catch (error) { /* already released */ }
    }
    if (!final) throw new Error("The connection closed before the answer was complete.");
    return final;
  }

  const LINE_IN_MS = 600;          // length of the .line-in animation in style.css
  const TYPE_CPS = 70;             // live typing pace (characters a second) when the model keeps up

  /* Replace the loading card with the answer as it is being written. */
  function showStreaming(wrapper, preview, piece) {
    preview.text += piece;
    if (!preview.node) {
      clearInterval(wrapper.loadingTimer);
      wrapper.replaceChildren();
      wrapper.appendChild(el("div", "meta-line", `CyberIntelliX · ${timeLabel(new Date())}`));
      const card = el("div", "card");
      const section = el("div", "section");
      const head = el("div", "section-head");
      head.appendChild(el("h3", "section-title", "Answer"));
      head.appendChild(el("span", "streaming-note", "Writing"));
      preview.node = el("div", "answer streaming");
      preview.node.setAttribute("aria-live", "off");
      section.append(head, preview.node);
      card.appendChild(section);
      wrapper.appendChild(card);
    }
    if (preview.frame) return;                    // the typing loop is already running
    // Typewriter: the streamed text is revealed character by character at a steady
    // pace. Only text the model has really sent is shown; when it arrives faster than
    // it is typed, the pace rises so the screen stays within about half a second.
    preview.typed = preview.typed || 0;
    preview.last = performance.now();
    const typeFrame = (now) => {
      const dt = Math.min(0.1, (now - preview.last) / 1000);
      preview.last = now;
      const pending = preview.text.length - preview.typed;
      const speed = Math.max(TYPE_CPS, pending * 2.2);          // characters per second
      preview.typed = reducedMotion.matches ? preview.text.length
        : Math.min(preview.text.length, preview.typed + Math.max(1, speed * dt));
      paintPreview(preview);
      if (preview.typed < preview.text.length) preview.frame = requestAnimationFrame(typeFrame);
      else {
        preview.frame = 0;
        if (preview.drained) { preview.drained(); preview.drained = null; }
      }
    };
    preview.frame = requestAnimationFrame(typeFrame);
  }

  /* Waits until everything that was streamed has been typed on screen. */
  function finishTyping(preview) {
    if (!preview.node || !preview.frame) return Promise.resolve();
    return new Promise((resolve) => { preview.drained = resolve; });
  }

  function paintPreview(preview) {
    {
      const nearBottom = chat.scrollHeight - chat.scrollTop - chat.clientHeight < 140;
      preview.node.replaceChildren();             // renderAnswer appends
      // small models sometimes echo the prompt's tags; the server removes them from
      // the final answer, so they are hidden in the preview as well
      renderAnswer(preview.node, preview.text.slice(0, Math.floor(preview.typed)).replace(
        /<\/?(?:question|answer|evidence|confirmed[_-]relationships|relationships[_-]not[_-]found)>/gi, ""));
      // Lines appear one by one. Every repaint rebuilds the text, so each line remembers
      // when it first appeared and its entry animation continues from that moment
      // (a negative delay) instead of restarting; lines arriving in the same frame are
      // staggered. Finished lines are left alone.
      if (!reducedMotion.matches) {
        const now = performance.now();
        preview.seen = preview.seen || [];
        let fresh = 0;
        preview.node.querySelectorAll("p, li, h1, h2, h3, h4, pre, tr").forEach((line, index) => {
          if (preview.seen[index] === undefined) { preview.seen[index] = now + fresh * 90; fresh += 1; }
          const elapsed = now - preview.seen[index];
          if (elapsed < LINE_IN_MS) {
            line.classList.add("line-in");
            line.style.animationDelay = `${-elapsed}ms`;
          }
        });
      }
      if (nearBottom) chat.scrollTop = chat.scrollHeight;
    }
  }

  async function send(text) {
    const message = text.trim();
    if (!message || busy) return;
    if (atHome) resetChat();                     // asked from the home page: a new chat
    const welcome = document.getElementById("welcome");
    if (welcome) welcome.remove();
    busy = true;
    sendButton.disabled = true;
    const asked = new Date();
    addUserMessage(message, asked, true);
    syncEntry();
    const placeholder = addLoading();
    try {
      const preview = { node: null, text: "", frame: 0 };
      let data = null;
      try {
        data = await streamChat(message, (piece) => showStreaming(placeholder, preview, piece));
      } catch (error) {
        cancelAnimationFrame(preview.frame);
        const offline = error instanceof TypeError;
        renderError(placeholder, offline
          ? "The CyberIntelliX backend could not be reached. Make sure it is running and try again."
          : `The request failed: ${error.message}`);
        checkStatus();
      }
      if (data) {
        await finishTyping(preview);              // let the typewriter reach the end first
        cancelAnimationFrame(preview.frame);
        try {
          // text that was already read while streaming is not animated in a second time
          renderResponse(placeholder, data, !preview.node);
          history.push({ q: message, t: asked.toISOString(), data });
          lastEntityIds = (Array.isArray(data.identifiers) ? data.identifiers : []).filter((id) => ID_RE.test(id));
          saveHistory();
          archiveAdd(message, asked, data);
        } catch (error) {
          // a rendering bug is not a connection problem
          renderError(placeholder, `The answer could not be displayed: ${error.message}`);
        }
      }
    } finally {
      busy = false;
      sendButton.disabled = !input.value.trim();
      // bring the start of the new answer into view rather than its end
      placeholder.scrollIntoView({ block: "start", behavior: reducedMotion.matches ? "auto" : "smooth" });
      updateJump();
      input.focus({ preventScroll: true });
    }
  }

  /* ------------------------------------------------------------------ */
  /* events                                                              */
  /* ------------------------------------------------------------------ */
  function autoGrow() {
    input.style.height = "auto";
    input.style.height = Math.min(input.scrollHeight, 160) + "px";
    input.style.overflowY = input.scrollHeight > 160 ? "auto" : "hidden";
    sendButton.disabled = busy || !input.value.trim();
    const length = input.value.length;
    counter.hidden = length < 1500;
    counter.textContent = `${length}/2000`;
    counter.classList.toggle("near", length > 1900);
  }

  /* "Latest" only appears once the reader is more than ~200px above the newest message. */
  function updateJump() {
    jumpButton.hidden = distanceFromBottom() <= 200 || !chat.querySelector(".msg");
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const text = input.value;
    if (!text.trim() || busy) return;
    input.value = "";
    autoGrow();
    send(text);
  });

  input.addEventListener("input", autoGrow);
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      form.requestSubmit();
    }
  });

  // Starter cards, identifier chips and identifier links all carry data-ask.
  document.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-ask]");
    if (trigger) { go("assistant"); send(trigger.dataset.ask); return; }
    const open = event.target.closest("[data-graph]");
    if (open) go("graph", open.dataset.graph);
  });

  chat.addEventListener("scroll", updateJump, { passive: true });
  jumpButton.addEventListener("click", () => scrollToBottom(true));

  /* Home (the menu entry and the logo) always shows the home page. A chat that is open is
   * kept behind it: "Back to your chat" returns to it, a new question starts a new chat. */
  function leaveHome() {
    if (!atHome) return;
    atHome = false;
    const welcome = document.getElementById("welcome");
    if (welcome) welcome.remove();
  }

  function showHome() {
    if (chat.querySelector(".msg") && !atHome) {
      atHome = true;
      const welcome = welcomeTemplate.cloneNode(true);
      const back = el("button", "btn home-back", "Back to your chat");
      back.type = "button";
      back.addEventListener("click", () => {
        leaveHome();
        syncEntry();
        scrollToBottom(true);
        updateJump();
      });
      welcome.appendChild(back);
      chat.prepend(welcome);
    }
    closeEntityPanel();
    go("assistant");
    chat.scrollTop = 0;
    updateJump();
  }

  document.addEventListener("click", (event) => {
    if (event.defaultPrevented || event.button || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    if (!event.target.closest('a.brand, a.nav-link[data-view="assistant"]')) return;
    event.preventDefault();
    showHome();
  });

  /* A chat holds as many questions as you like; "New chat" goes back to the empty entry screen. */
  function syncEntry() {
    const answered = Boolean(chat.querySelector(".msg")) && !atHome;
    chat.classList.toggle("at-home", atHome);
    document.body.classList.toggle("entry", currentView === "assistant" && !answered);
    document.body.classList.toggle("answered", answered);
    placeIndicator();
    if (!answered) autoGrow();                 // the box was hidden: measure it again
  }

  function resetChat() {
    releaseGraphs(chat);
    history = [];
    lastEntityIds = [];
    atHome = false;
    saveHistory();
    chat.replaceChildren(welcomeTemplate.cloneNode(true));
    input.value = "";
    autoGrow();
    updateJump();
    syncEntry();
  }

  clearButton.addEventListener("click", () => {
    if (busy) return;
    resetChat();
    input.focus();
  });
  document.getElementById("new-chat").addEventListener("click", () => clearButton.click());

  document.addEventListener("keydown", (event) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
    if (event.key === "/" && !typing && currentView === "assistant") { event.preventDefault(); input.focus(); }
  });

  /* ------------------------------------------------------------------ */
  /* navigation between the four views                                   */
  /* ------------------------------------------------------------------ */
  const VIEW_META = {
    assistant: ["Home", ""],
    features: ["Features", "What CyberIntelliX does, and how it keeps its answers grounded."],
    history: ["History", "Questions you have asked in this browser, with their answers."],
    graph: ["Knowledge Graph", "Browse CVE, CWE, CAPEC and ATT&CK records and how they are connected."],
    data: ["Resources", "What the knowledge base contains, where it comes from and when it was last updated."],
  };
  const navLinks = [...document.querySelectorAll(".nav-link")];
  const navIndicator = document.getElementById("nav-indicator");
  const viewbar = document.querySelector(".viewbar");
  let currentView = null;
  let atHome = false;              // the home page is shown while a chat is open behind it
  let countedUp = false;

  function replay(node, className) {
    node.classList.remove(className);
    void node.offsetWidth;                       // restart the CSS animation
    node.classList.add(className);
  }

  function go(name, entity) {
    const target = "#/" + name + (entity ? "?e=" + encodeURIComponent(entity) : "");
    if (location.hash === target) route(); else location.hash = target;
  }

  function placeIndicator() {
    const active = navLinks.find((link) => link.dataset.view === currentView);
    if (!active) return;
    // a pill behind the active link that slides to the next one
    navIndicator.style.transform = `translateX(${active.offsetLeft}px)`;
    navIndicator.style.width = active.offsetWidth + "px";
  }

  function route() {
    const match = location.hash.match(/^#\/([a-z]+)(?:\?e=(.+))?$/);
    const name = match && VIEW_META[match[1]] ? match[1] : "assistant";
    if (name !== currentView) {
      currentView = name;
      document.querySelectorAll(".view").forEach((view) => {
        const on = view.id === "view-" + name;
        view.hidden = !on;
        if (on) replay(view, "enter");
      });
      navLinks.forEach((link) => {
        if (link.dataset.view === name) link.setAttribute("aria-current", "page");
        else link.removeAttribute("aria-current");
      });
      placeIndicator();
      document.getElementById("view-title").textContent = VIEW_META[name][0];
      document.getElementById("view-sub").textContent = VIEW_META[name][1];
      viewbar.hidden = name === "assistant";
      replay(viewbar, "swap");
      clearButton.hidden = name !== "assistant";
      document.title = name === "assistant" ? "CyberIntelliX" : VIEW_META[name][0] + " · CyberIntelliX";
      if (name === "history") renderHistoryList();
      if (name === "data" && !countedUp) {                  // count the record numbers up the first time Resources opens
        countedUp = true;
        document.querySelectorAll("[data-stat]").forEach((node) => {
          const value = Number(node.dataset.value || 0);
          if (value) { node.dataset.value = "0"; countUp(node, value); }
        });
      }
      if (name === "assistant") { input.focus({ preventScroll: true }); updateJump(); }
    }
    syncEntry();
    if (name === "graph") {
      let entity = null;
      try { entity = match && match[2] ? decodeURIComponent(match[2]) : null; } catch (error) { entity = null; }
      explorer.open(entity);
    }
  }
  window.addEventListener("hashchange", () => {
    // Switch at once; the new view fades and rises in (.view.enter). The View Transitions
    // API was dropped here: snapshotting the page (3D canvas included) delayed the switch
    // and crossfaded two whole pages over each other.
    route();
  });
  window.addEventListener("resize", placeIndicator);

  /* ------------------------------------------------------------------ */
  /* history: kept in this browser (localStorage), newest first          */
  /* ------------------------------------------------------------------ */
  const ARCHIVE_KEY = "ragcyber.archive.v1";
  const ARCHIVE_MAX = 80;
  const histList = document.getElementById("hist-list");
  const histDetail = document.getElementById("hist-detail");
  const histSearch = document.getElementById("hist-search");
  const histFilter = document.getElementById("hist-filter");
  const histTotal = document.getElementById("hist-total");
  const histClear = document.getElementById("hist-clear");
  const histCount = document.getElementById("nav-history-count");
  let archive = [];
  let histSelected = null;

  function loadArchive() {
    try { archive = JSON.parse(localStorage.getItem(ARCHIVE_KEY) || "[]"); } catch (error) { archive = []; }
    if (!Array.isArray(archive)) archive = [];
  }

  function saveArchive() {
    for (;;) {
      try { localStorage.setItem(ARCHIVE_KEY, JSON.stringify(archive)); return; }
      catch (error) {                           // storage full: forget the oldest entries
        if (error?.name !== "QuotaExceededError" || archive.length <= 1) return;
        archive = archive.slice(0, Math.max(1, archive.length - 10));
      }
    }
  }

  function updateHistoryCount() {
    histCount.hidden = !archive.length;
    histCount.textContent = String(archive.length);
  }

  function archiveAdd(question, when, data) {
    archive.unshift({ id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
                      q: question, t: when.toISOString(), data });
    archive = archive.slice(0, ARCHIVE_MAX);
    saveArchive();
    updateHistoryCount();
  }

  function dayLabel(date) {
    const startOf = (d) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
    const days = Math.round((startOf(new Date()) - startOf(date)) / 86400000);
    if (days === 0) return "Today";
    if (days === 1) return "Yesterday";
    return date.toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "long", year: "numeric" });
  }

  function releaseGraphs(container) {
    container.querySelectorAll("canvas.graph").forEach((canvas) => {
      graphObserver.unobserve(canvas);
      if (canvas.relationGraph) graphs.delete(canvas.relationGraph);
    });
  }

  function showHistoryPlaceholder(text) {
    releaseGraphs(histDetail);
    histDetail.replaceChildren(el("p", "placeholder", text));
  }

  function renderHistoryDetail(entry) {
    releaseGraphs(histDetail);
    const box = el("div", "enter");
    const head = el("div", "hist-head");
    const text = el("div");
    text.appendChild(el("h2", null, entry.q));
    text.appendChild(el("p", null, new Date(entry.t).toLocaleString(undefined, { dateStyle: "long", timeStyle: "short" })));
    const actions = el("div", "hist-actions");
    const again = el("button", "btn", "Ask again");
    again.type = "button";
    again.dataset.ask = entry.q;
    const remove = el("button", "btn", "Delete");
    remove.type = "button";
    remove.addEventListener("click", () => {
      archive = archive.filter((item) => item.id !== entry.id);
      saveArchive();
      updateHistoryCount();
      histSelected = null;
      showHistoryPlaceholder("Select a question to review its answer.");
      renderHistoryList();
    });
    actions.append(again, remove);
    head.append(text, actions);
    const wrapper = el("div", "msg msg-ai no-anim");
    box.append(head, wrapper);
    histDetail.replaceChildren(box);
    renderResponse(wrapper, entry.data, false);
    histDetail.scrollTop = 0;
  }

  function renderHistoryList() {
    const needle = histSearch.value.trim().toLowerCase();
    const filter = histFilter.value;
    const shown = archive.filter((entry) => {
      const data = entry.data || {};
      if (needle && !entry.q.toLowerCase().includes(needle)) return false;
      if (filter === "NOTFOUND") return !data.result_found;
      return !filter || data.category === filter;
    });
    histList.replaceChildren();
    histTotal.textContent = archive.length
      ? `${shown.length} of ${archive.length} question${archive.length === 1 ? "" : "s"}` : "";
    histClear.hidden = !archive.length;
    if (!shown.length) {
      histList.appendChild(el("p", "placeholder", archive.length ? "No questions match." : "Nothing here yet. Questions you ask appear in this list."));
      return;
    }
    let lastDay = "";
    shown.forEach((entry, index) => {
      const when = new Date(entry.t);
      const day = dayLabel(when);
      if (day !== lastDay) { histList.appendChild(el("h3", "hist-day", day)); lastDay = day; }
      const data = entry.data || {};
      const item = el("button", "hist-item");
      item.type = "button";
      item.style.setProperty("--n", String(Math.min(index, 14)));
      if (TYPE_COLORS[data.category]) item.dataset.type = data.category;
      if (entry.id === histSelected) item.setAttribute("aria-current", "true");
      item.appendChild(el("span", "hist-q", entry.q));
      const meta = el("span", "hist-meta");
      meta.appendChild(el("b", null, data.result_found ? (TYPE_NAMES[data.category] || CATEGORY_LABELS[data.category] || "Answer") : "Not found"));
      meta.appendChild(el("span", null, timeLabel(when)));
      item.appendChild(meta);
      item.addEventListener("click", () => {
        histSelected = entry.id;
        histList.querySelectorAll("[aria-current]").forEach((node) => node.removeAttribute("aria-current"));
        item.setAttribute("aria-current", "true");
        renderHistoryDetail(entry);
      });
      histList.appendChild(item);
    });
  }

  histSearch.addEventListener("input", renderHistoryList);
  histFilter.addEventListener("change", renderHistoryList);
  histClear.addEventListener("click", () => {
    if (!archive.length || !window.confirm(`Delete all ${archive.length} saved questions? This cannot be undone.`)) return;
    archive = [];
    saveArchive();
    updateHistoryCount();
    histSelected = null;
    showHistoryPlaceholder("Select a question to review its answer.");
    renderHistoryList();
  });

  /* ------------------------------------------------------------------ */
  /* data & sources: relationship counts                                 */
  /* ------------------------------------------------------------------ */
  const REL_TEXT = {
    CVE_CWE: ["Vulnerability has weakness", "CVE → CWE"], CWE_CHILD: ["Weakness is a child of", "CWE → CWE"],
    CWE_CAPEC: ["Weakness is exploited by", "CWE → CAPEC"], CAPEC_CHILD: ["Attack pattern is a child of", "CAPEC → CAPEC"],
    CAN_PRECEDE: ["Attack pattern can precede", "CAPEC → CAPEC"], CAPEC_ATTACK: ["Attack pattern maps to technique", "CAPEC → ATT&CK"],
    SUBTECHNIQUE_OF: ["Sub-technique of", "ATT&CK → ATT&CK"],
    AFFECTS: ["Vulnerability affects product", "CVE → Product"], MADE_BY: ["Product is made by", "Product → Vendor"],
    HAS_TACTIC: ["Technique serves tactic", "ATT&CK → Tactic"], MITIGATES: ["Mitigation applies to", "Mitigation → ATT&CK"],
  };
  function renderRelTable(relationships) {
    const body = document.getElementById("rel-table");
    body.replaceChildren();
    Object.keys(relationships || {}).forEach((rel) => {
      const row = el("tr");
      const name = el("td", null, (REL_TEXT[rel] || [rel])[0]);
      name.appendChild(el("small", null, (REL_TEXT[rel] || ["", rel])[1]));
      row.append(name, el("td", null, Number(relationships[rel]).toLocaleString()));
      body.appendChild(row);
    });
  }

  /* ------------------------------------------------------------------ */
  /* knowledge graph explorer                                            */
  /* ------------------------------------------------------------------ */
  const explorer = (() => {
    const KIND = { CVE: "CVE · Vulnerability", CWE: "CWE · Weakness", CAPEC: "CAPEC · Attack pattern", ATTACK: "ATT&CK · Technique" };
    const GROUP_TITLES = {
      CVE_CWE: ["Weaknesses (CWE)", "Vulnerabilities (CVE)"], CWE_CHILD: ["Parent weaknesses", "Child weaknesses"],
      CWE_CAPEC: ["Attack patterns (CAPEC)", "Related weaknesses (CWE)"], CAPEC_CHILD: ["Parent patterns", "Child patterns"],
      CAN_PRECEDE: ["Can precede", "Can follow"], CAPEC_ATTACK: ["ATT&CK techniques", "Attack patterns (CAPEC)"],
      SUBTECHNIQUE_OF: ["Parent technique", "Sub-techniques"],
    };
    const LISTS = [["mitigations", "Mitigations"], ["consequences", "Consequences"], ["prerequisites", "Prerequisites"],
                   ["alternate_terms", "Also known as"], ["member_of_categories", "Member of categories"],
                   ["affected_products", "Affected products"], ["patch_urls", "Patches and advisories"],
                   ["reference_urls", "References"]];
    const canvas = document.getElementById("kg-canvas");
    const context = canvas.getContext("2d");
    const stage = document.getElementById("kg-stage");
    const detail = document.getElementById("kg-detail");
    const tip = document.getElementById("kg-tip");
    const emptyBox = document.getElementById("kg-empty");
    const startList = document.getElementById("kg-start");
    const searchInput = document.getElementById("kg-search");
    const resultsList = document.getElementById("kg-results");
    const nodes = new Map();
    const edges = new Map();
    const cache = new Map();
    const view = { x: 0, y: 0, k: 1 };
    let target = null;              // where the view is gliding to
    let selected = null, hover = null, drag = null, energy = 0, running = false, width = 0, height = 0;
    let overviewLoaded = false, searchTimer = null, results = [], activeResult = -1, requestId = 0;

    /* views: lanes by entity type (Flow), a tidy tree, or rings around the selected entity */
    const KG_MODES = ["flow", "tree", "radial"];
    const FLOW_LANES = ["CVE", "CWE", "CAPEC", "ATTACK"];
    const FLOW_TITLES = { CVE: "CVE \u00b7 Vulnerabilities", CWE: "CWE \u00b7 Weaknesses", CAPEC: "CAPEC \u00b7 Attack patterns", ATTACK: "ATT&CK \u00b7 Techniques" };
    const FLOW_W = 140, FLOW_H = 28;                        // size of one entity box
    let flowLanes = [];
    const KG_MODE_KEY = "ragcyber.kgmode.v1";
    const KG_HINTS = {
      flow: "Flow view: one lane per entity type, CVE to CWE to CAPEC to ATT&CK. Select a box to load its neighbours.",
      tree: "Tree view: entities are laid out left to right from the first one you searched. Drag to move, scroll to zoom.",
      radial: "Radial view: the selected entity sits in the centre with its neighbours on rings around it.",
      "3d": "3D view: drag to rotate the graph, scroll to zoom, select a node to load its neighbours.",
    };
    let mode = "flow";
    try { const saved = localStorage.getItem(KG_MODE_KEY); if (KG_MODES.includes(saved)) mode = saved; } catch (error) { /* no storage */ }
    const hiddenTypes = new Set();                          // entity types switched off in the legend
    const rot = { x: -0.3, y: 0.5 };                        // 3D rotation
    const visible = (node) => Boolean(node) && !hiddenTypes.has(node.label);
    const laidOut = () => mode === "flow" || mode === "tree" || mode === "radial";

    function resize() {
      const box = stage.getBoundingClientRect();
      if (!box.width || !box.height) return;
      width = box.width; height = box.height;
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.round(width * ratio);
      canvas.height = Math.round(height * ratio);
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
      wake(0.05);
    }

    function wake(amount) {
      energy = Math.max(energy, amount);
      if (!running) { running = true; requestAnimationFrame(tick); }
    }
    document.addEventListener("themechange", () => wake(0.15));   // repaint in the new colours

    function addNode(info, near) {
      let node = nodes.get(info.id);
      if (node) { if (info.name && !info.more) node.name = info.name; return node; }
      const angle = Math.random() * Math.PI * 2, reach = 50 + Math.random() * 50;
      node = { ...info, x: (near ? near.x : 0) + Math.cos(angle) * reach, y: (near ? near.y : 0) + Math.sin(angle) * reach,
               z: (near ? near.z : 0) + (Math.random() - 0.5) * 160, vx: 0, vy: 0, vz: 0, born: performance.now() };
      nodes.set(info.id, node);
      return node;
    }

    function addEdge(from, to, rel) {
      const key = from + "|" + rel + "|" + to;
      if (!edges.has(key)) edges.set(key, { from, to, rel });
    }

    function merge(data) {
      const center = addNode({ id: data.id, label: data.label, name: data.properties.name || data.id }, null);
      center.expanded = true;
      data.groups.forEach((group) => {
        group.nodes.forEach((info) => {
          addNode(info, center);
          if (group.outgoing) addEdge(data.id, info.id, group.rel); else addEdge(info.id, data.id, group.rel);
        });
        const moreId = `more:${data.id}:${group.rel}:${group.outgoing}`;
        const rest = group.total - group.nodes.length;
        if (rest > 0) {
          const more = addNode({ id: moreId, label: group.label, more: true, parent: data.id }, center);
          more.count = rest;
          more.name = `${rest.toLocaleString()} more ${TYPE_NAMES[group.label] || group.label} records`;
          addEdge(data.id, moreId, "more");
        } else if (nodes.has(moreId)) {
          nodes.delete(moreId);
          edges.delete(data.id + "|more|" + moreId);
        }
      });
      emptyBox.hidden = true;
      layout();
      wake(1);
    }

    /* Tree and Radial views: every node gets a target position (tx, ty) and glides to it. */
    function layout() {
      if (!laidOut()) return;
      const list = [...nodes.values()].filter(visible);
      if (!list.length) return;
      const adjacent = new Map(list.map((n) => [n.id, []]));
      edges.forEach((e) => {
        if (adjacent.has(e.from) && adjacent.has(e.to)) { adjacent.get(e.from).push(e.to); adjacent.get(e.to).push(e.from); }
      });
      if (mode === "flow") {                                // one lane per type, left to right
        const ROWS = 14, ROW_H = 40, SUB_W = FLOW_W + 26, GAP = 120;
        const lanes = FLOW_LANES.map((label) => ({ label, items: [] }));
        list.forEach((n) => { const at = FLOW_LANES.indexOf(n.label); lanes[at < 0 ? lanes.length - 1 : at].items.push(n); });
        const used = lanes.filter((lane) => lane.items.length);
        const rank = (n) => (n.more ? "2" : n.expanded ? "0" : "1") + n.id;
        used.forEach((lane) => lane.items.sort((a, b) => rank(a) < rank(b) ? -1 : 1));
        const place = () => {
          let x = 0;
          used.forEach((lane) => {
            const subs = Math.ceil(lane.items.length / ROWS);
            lane.items.forEach((n, index) => {
              const column = Math.floor(index / ROWS), inColumn = Math.min(ROWS, lane.items.length - column * ROWS);
              n.tx = x + column * SUB_W;
              n.ty = ((index % ROWS) - (inColumn - 1) / 2) * ROW_H;
            });
            lane.x = x + (subs - 1) * SUB_W / 2;
            lane.top = -(Math.min(ROWS, lane.items.length) - 1) / 2 * ROW_H;
            x += subs * SUB_W + GAP;
          });
          const shift = (x - GAP - SUB_W) / 2;
          used.forEach((lane) => { lane.x -= shift; lane.items.forEach((n) => { n.tx -= shift; }); });
        };
        place();
        for (let pass = 0; pass < 2; pass += 1) {           // keep linked boxes near each other: fewer crossings
          used.forEach((lane) => {
            const score = new Map(lane.items.map((n) => {
              const others = adjacent.get(n.id).map((id) => nodes.get(id)).filter((o) => o.label !== n.label);
              return [n.id, n.more ? Infinity : others.length ? others.reduce((sum, o) => sum + o.ty, 0) / others.length : n.ty];
            }));
            lane.items.sort((a, b) => score.get(a.id) - score.get(b.id) || (a.id < b.id ? -1 : 1));
          });
          place();
        }
        const top = Math.min(...used.map((lane) => lane.top));
        flowLanes = used.map((lane) => ({ label: lane.label, x: lane.x, y: top - 46 }));
        wake(0.05);
        return;
      }
      const order = [];
      if (mode === "radial" && selected && adjacent.has(selected)) order.push(selected);
      list.forEach((n) => { if (n.expanded) order.push(n.id); });
      list.forEach((n) => order.push(n.id));
      const kids = new Map(), depth = new Map(), roots = [];
      order.forEach((id) => {                               // breadth-first: a spanning forest
        if (depth.has(id)) return;
        roots.push(id); depth.set(id, 0); kids.set(id, []);
        const queue = [id];
        for (let i = 0; i < queue.length; i += 1) {
          const current = queue[i];
          adjacent.get(current).forEach((next) => {
            if (depth.has(next)) return;
            depth.set(next, depth.get(current) + 1); kids.set(next, []);
            kids.get(current).push(next); queue.push(next);
          });
        }
      });
      const typeRank = (id) => { const n = nodes.get(id); return (n.more ? "~" : "") + (n.label || "") + ":" + id; };
      kids.forEach((children) => children.sort((a, b) => typeRank(a) < typeRank(b) ? -1 : 1));
      const leaves = new Map();
      const count = (id) => {
        const children = kids.get(id);
        const total = children.length ? children.reduce((sum, child) => sum + count(child), 0) : 1;
        leaves.set(id, total);
        return total;
      };
      roots.forEach(count);
      if (mode === "tree") {
        let cursor = 0;
        const ROWS = 12, ROW_H = 30, COL_W = 136;            // many leaves wrap into columns so the tree is not one tall strip
        const place = (id) => {
          const node = nodes.get(id), children = kids.get(id);
          node.tx = depth.get(id) * 240;
          if (!children.length) { node.ty = cursor; cursor += ROW_H; return; }
          const top = cursor;
          const branches = children.filter((child) => kids.get(child).length);
          const ends = children.filter((child) => !kids.get(child).length);
          branches.forEach(place);
          ends.forEach((child, index) => {
            const leaf = nodes.get(child);
            leaf.tx = (depth.get(id) + 1) * 240 + Math.floor(index / ROWS) * COL_W;
            leaf.ty = cursor + (index % ROWS) * ROW_H;
          });
          cursor += Math.min(ends.length, ROWS) * ROW_H;
          node.ty = (top + cursor - ROW_H) / 2;
        };
        roots.forEach((id) => { place(id); cursor += 26; });
        let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
        list.forEach((n) => { minX = Math.min(minX, n.tx); maxX = Math.max(maxX, n.tx); minY = Math.min(minY, n.ty); maxY = Math.max(maxY, n.ty); });
        list.forEach((n) => { n.tx -= (minX + maxX) / 2; n.ty -= (minY + maxY) / 2; });
      } else {
        const total = roots.reduce((sum, id) => sum + leaves.get(id), 0);
        const single = roots.length === 1;
        const ring = Math.max(140, total * 24 / (2 * Math.PI));
        const unit = (2 * Math.PI) / total;
        const place = (id, start) => {
          const node = nodes.get(id), level = depth.get(id) + (single ? 0 : 1);
          const middle = start + leaves.get(id) * unit / 2;
          const reach = level <= 1 ? level * ring : ring * (1 + (level - 1) * 0.62);
          node.tx = Math.cos(middle) * reach; node.ty = Math.sin(middle) * reach;
          let angle = start;
          kids.get(id).forEach((child) => { place(child, angle); angle += leaves.get(child) * unit; });
        };
        let angle = -Math.PI / 2;
        roots.forEach((id) => { place(id, angle); angle += leaves.get(id) * unit; });
      }
      wake(0.05);
    }

    /* Where each node is drawn.  In 3D the positions are rotated and given perspective. */
    function project(list) {
      if (mode !== "3d") { list.forEach((n) => { n.sx = n.x; n.sy = n.y; n.ss = 1; n.depth = 0; }); return; }
      const cy = Math.cos(rot.y), sy = Math.sin(rot.y), cx = Math.cos(rot.x), sx = Math.sin(rot.x);
      list.forEach((n) => {
        const x1 = n.x * cy + n.z * sy, z1 = -n.x * sy + n.z * cy;
        const y1 = n.y * cx - z1 * sx, z2 = n.y * sx + z1 * cx;
        n.ss = Math.max(0.45, Math.min(1.7, 900 / (900 + z2)));
        n.sx = x1 * n.ss; n.sy = y1 * n.ss; n.depth = z2;
      });
    }

    function setMode(next) {
      if (!KG_MODES.includes(next)) return;
      mode = next;
      try { localStorage.setItem(KG_MODE_KEY, mode); } catch (error) { /* no storage */ }
      modeButtons.forEach((button) => button.setAttribute("aria-pressed", String(button.dataset.mode === mode)));
      if (footHint) footHint.textContent = KG_HINTS[mode];
      canvas.dataset.mode = mode;
      if (laidOut()) { layout(); fit(); }
      else { wake(1); setTimeout(fit, mode === "3d" ? 700 : 900); }
    }

    async function fetchEntity(id, perGroup) {
      const key = id + ":" + perGroup;
      if (!cache.has(key)) {
        cache.set(key, await api(`/api/graph/entity/${encodeURIComponent(id)}?per_group=${perGroup}`));
      }
      return cache.get(key);
    }

    /* ---- layout (a small force simulation) and drawing ---- */
    function tick() {
      const list = [...nodes.values()].filter(visible);
      const spatial = mode === "3d";
      if (laidOut()) {                                      // glide to the positions the layout chose
        let moving = 0;
        list.forEach((node) => {
          if (node.tx === undefined || (drag && drag.node === node && drag.moved)) return;
          const dx = node.tx - node.x, dy = node.ty - node.y;
          if (reducedMotion.matches) { node.x = node.tx; node.y = node.ty; return; }
          node.x += dx * 0.16; node.y += dy * 0.16;
          moving = Math.max(moving, Math.abs(dx) + Math.abs(dy));
        });
        energy = moving > 0.6 ? Math.max(energy, 0.05) : 0;
      } else if (energy > 0.02) {
        for (let i = 0; i < list.length; i += 1) {
          const a = list[i];
          for (let j = i + 1; j < list.length; j += 1) {
            const b = list[j];
            let dx = a.x - b.x, dy = a.y - b.y, dz = spatial ? a.z - b.z : 0;
            let d2 = dx * dx + dy * dy + dz * dz;
            if (d2 < 1) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; dz = spatial ? Math.random() - 0.5 : 0; d2 = 1; }
            if (d2 > 160000) continue;
            const force = 1500 / d2;
            a.vx += dx * force; a.vy += dy * force; b.vx -= dx * force; b.vy -= dy * force;
            if (spatial) { a.vz += dz * force; b.vz -= dz * force; }
          }
          a.vx -= a.x * 0.0035; a.vy -= a.y * 0.0035;
          if (spatial) a.vz -= a.z * 0.0035;
        }
        edges.forEach((edge) => {
          const a = nodes.get(edge.from), b = nodes.get(edge.to);
          if (!visible(a) || !visible(b)) return;
          const dx = b.x - a.x, dy = b.y - a.y, dz = spatial ? b.z - a.z : 0, distance = Math.hypot(dx, dy, dz) || 1;
          const pull = (distance - 105) * 0.04;
          a.vx += (dx / distance) * pull; a.vy += (dy / distance) * pull;
          b.vx -= (dx / distance) * pull; b.vy -= (dy / distance) * pull;
          if (spatial) { a.vz += (dz / distance) * pull; b.vz -= (dz / distance) * pull; }
        });
        const step = Math.min(1, energy * 2);
        list.forEach((node) => {
          if (drag && drag.node === node && !spatial) { node.vx = 0; node.vy = 0; return; }
          node.vx *= 0.8; node.vy *= 0.8; node.vz *= 0.8;
          const speed = Math.hypot(node.vx, node.vy, spatial ? node.vz : 0);
          const cap = speed > 14 ? 14 / speed : 1;
          node.x += node.vx * cap * step; node.y += node.vy * cap * step;
          if (spatial) node.z += node.vz * cap * step;
        });
        energy *= 0.98;
      }
      const turning = spatial && !reducedMotion.matches && nodes.size > 0;
      if (turning && !drag && !hover) rot.y += 0.0022;       // the 3D graph turns slowly while idle
      if (target) {
        view.x += (target.x - view.x) * 0.14; view.y += (target.y - view.y) * 0.14; view.k += (target.k - view.k) * 0.14;
        if (Math.abs(target.x - view.x) + Math.abs(target.y - view.y) < 0.5 && Math.abs(target.k - view.k) < 0.002) target = null;
      }
      draw();
      const settling = energy > 0.02 || target || drag || list.some((n) => performance.now() - n.born < 700)
        || (selected && !reducedMotion.matches) || turning;            // keeps the pulse ring and the 3D turn going
      if (settling && !document.hidden && currentView === "graph") requestAnimationFrame(tick);
      else running = false;
    }

    function radius(node) { return node.more ? 13 : node.id === selected ? 11 : 8; }

    function draw() {
      context.clearRect(0, 0, width, height);
      context.save();
      context.translate(width / 2 + view.x, height / 2 + view.y);
      context.scale(view.k, view.k);
      const now = performance.now();
      const focus = hover || selected;
      const still = reducedMotion.matches;
      const near = hover ? new Set([hover]) : null;                  // the hovered node and its direct neighbours
      if (near) edges.forEach((e) => { if (e.from === hover) near.add(e.to); else if (e.to === hover) near.add(e.from); });
      const shown = [...nodes.values()].filter(visible);
      project(shown);
      if (mode === "3d") shown.sort((p, q) => q.depth - p.depth);    // far nodes first
      if (mode === "flow" && shown.length) {                         // lane titles above each column
        context.textAlign = "center"; context.textBaseline = "middle";
        context.font = "600 12px " + cssVar("--sans", "sans-serif");
        flowLanes.forEach((lane) => {
          context.globalAlpha = 0.9;
          context.fillStyle = TYPE_COLORS[lane.label] || PAL.muted;
          context.fillText(FLOW_TITLES[lane.label] || lane.label, lane.x, lane.y);
        });
        context.globalAlpha = 1;
      }
      edges.forEach((edge) => {
        const a = nodes.get(edge.from), b = nodes.get(edge.to);
        if (!visible(a) || !visible(b)) return;
        const drawn = still ? 1 : 1 - Math.pow(1 - Math.min(1, (now - Math.max(a.born || 0, b.born || 0)) / 300), 3);
        const lit = focus && (edge.from === focus || edge.to === focus);
        if (mode === "flow") {                                         // a curve from box side to box side
          const half = FLOW_W / 2, side = Math.abs(b.sx - a.sx) < 1 ? 0 : Math.sign(b.sx - a.sx);
          const x0 = a.sx + (side || 1) * half, x3 = b.sx + (side ? -side : 1) * (half + 3);
          const bend = side ? Math.max(30, Math.abs(x3 - x0) * 0.45) : 34 + Math.min(60, Math.abs(b.sy - a.sy) * 0.15);
          context.strokeStyle = lit ? PAL.accent : PAL.borderStrong;
          context.fillStyle = context.strokeStyle;
          context.globalAlpha = (lit ? 1 : (hover ? 0.14 : 0.6)) * drawn;
          context.lineWidth = (lit ? 1.8 : 1) / Math.max(0.6, view.k);
          context.setLineDash(edge.rel === "more" ? [4, 4] : []);
          context.beginPath(); context.moveTo(x0, a.sy);
          context.bezierCurveTo(x0 + (side || 1) * bend, a.sy, x3 + (side ? -side : 1) * bend, b.sy, x3, b.sy);
          context.stroke(); context.setLineDash([]);
          if (edge.rel !== "more") {
            const point = side ? side : -1, size = 6;                  // arrowhead points into the box
            context.beginPath(); context.moveTo(x3 + point * 3, b.sy);
            context.lineTo(x3 - point * size, b.sy - size * 0.55); context.lineTo(x3 - point * size, b.sy + size * 0.55);
            context.closePath(); context.fill();
          }
          return;
        }
        const dx = b.sx - a.sx, dy = b.sy - a.sy, distance = Math.hypot(dx, dy) || 1;
        const ux = dx / distance, uy = dy / distance;
        const startX = a.sx + ux * radius(a) * a.ss, startY = a.sy + uy * radius(a) * a.ss;
        const endX = b.sx - ux * (radius(b) * b.ss + 2), endY = b.sy - uy * (radius(b) * b.ss + 2);
        context.strokeStyle = lit ? PAL.accent : PAL.borderStrong;
        context.fillStyle = context.strokeStyle;
        context.globalAlpha = (lit ? 1 : (hover ? 0.18 : 0.75)) * (mode === "3d" ? Math.min(1, 0.25 + 0.6 * Math.min(a.ss, b.ss)) : 1);
        context.lineWidth = (lit ? 1.6 : 1) / view.k;
        context.setLineDash(edge.rel === "more" ? [4, 4] : []);
        context.beginPath(); context.moveTo(startX, startY);
        context.lineTo(startX + (endX - startX) * drawn, startY + (endY - startY) * drawn); context.stroke();
        context.setLineDash([]);
        if (edge.rel !== "more" && drawn >= 1) {
          const size = 6;
          context.beginPath();
          context.moveTo(endX, endY);
          context.lineTo(endX - ux * size - uy * size * 0.5, endY - uy * size + ux * size * 0.5);
          context.lineTo(endX - ux * size + uy * size * 0.5, endY - uy * size - ux * size * 0.5);
          context.closePath(); context.fill();
        }
      });
      context.globalAlpha = 1;
      context.textAlign = "center";
      const sans = cssVar("--sans", "sans-serif"), mono = cssVar("--mono", "monospace");
      shown.forEach((node) => {
        const grow = still ? 1 : Math.max(0, Math.min(1, (now - node.born - 200) / 400));   // edges first, then the node pops in
        const r = radius(node) * (0.8 + 0.2 * easeOutBack(grow)) * node.ss;
        const colour = TYPE_COLORS[node.label] || PAL.muted;
        const x = node.sx, y = node.sy;
        const fade = mode === "3d" ? Math.min(1, 0.3 + 0.7 * node.ss) : 1;     // far nodes are fainter
        context.textAlign = "center";
        context.globalAlpha = grow * fade * (near && !near.has(node.id) ? 0.4 : 1);
        if (mode === "flow") {                                         // a labelled box
          const pop = 0.85 + 0.15 * easeOutBack(grow), w = FLOW_W * pop, h = FLOW_H * pop;
          const chosen = node.id === selected;
          context.beginPath(); context.roundRect(x - w / 2, y - h / 2, w, h, 8);
          context.fillStyle = PAL.surface; context.fill();
          if (!node.more) { const alpha = context.globalAlpha; context.globalAlpha = alpha * (chosen ? 0.24 : 0.1); context.fillStyle = colour; context.fill(); context.globalAlpha = alpha; }
          context.setLineDash(node.more ? [4, 3] : []);
          context.strokeStyle = chosen ? PAL.accent : colour; context.lineWidth = chosen ? 2 : 1.3; context.stroke();
          context.setLineDash([]);
          if (chosen && !still) {                                      // slow soft ring, 2.5 s loop
            const p = (now % 2500) / 2500, alpha = context.globalAlpha;
            context.beginPath(); context.roundRect(x - w / 2 - 3 - 8 * p, y - h / 2 - 3 - 8 * p, w + 6 + 16 * p, h + 6 + 16 * p, 11 + 8 * p);
            context.globalAlpha = alpha * 0.4 * (1 - p); context.lineWidth = 1.5; context.stroke();
            context.globalAlpha = alpha;
          }
          if (view.k > 0.32 || chosen || node.id === hover) {
            context.fillStyle = node.more ? colour : PAL.text; context.textBaseline = "middle";
            context.font = (chosen ? "600 " : "500 ") + "11.5px " + (node.more ? sans : mono);
            const text = node.more ? "+" + Number(node.count || 0).toLocaleString() + " more" : node.id;
            context.fillText(text.length > 18 ? text.slice(0, 17) + "\u2026" : text, x, y + 0.5);
          }
          return;
        }
        context.beginPath(); context.arc(x, y, r, 0, Math.PI * 2);
        if (node.more) {
          context.fillStyle = PAL.surface; context.fill();
          context.setLineDash([3, 3]); context.strokeStyle = colour; context.lineWidth = 1.4; context.stroke(); context.setLineDash([]);
          context.fillStyle = colour; context.font = "600 9px " + sans; context.textBaseline = "middle";
          context.fillText("+" + (node.count > 999 ? Math.round(node.count / 1000) + "k" : node.count), x, y + 0.5);
        } else {
          context.fillStyle = colour; context.fill();
          context.strokeStyle = PAL.surface; context.lineWidth = 2; context.stroke();
          if (node.id === selected) {
            context.beginPath(); context.arc(x, y, r + 4, 0, Math.PI * 2);
            context.strokeStyle = PAL.accent; context.lineWidth = 1.5; context.stroke();
            if (!still) {                                              // slow soft pulse ring, 2.5 s loop
              const p = (now % 2500) / 2500;
              context.beginPath(); context.arc(x, y, r + 4 + 10 * p, 0, Math.PI * 2);
              context.globalAlpha = grow * 0.35 * (1 - p); context.stroke();
              context.globalAlpha = grow * fade;
            }
          }
          const labelled = mode === "3d" ? node.ss > 0.95 && view.k > 0.5 : view.k > 0.5;
          if (labelled || node.id === selected || node.id === hover) {
            context.fillStyle = PAL.text;
            context.font = (node.id === selected ? "600 " : "") + Math.min(20, 11 / Math.min(1, view.k)).toFixed(1) + "px " + mono;
            if (mode === "tree") {                                     // beside the node, so rows stay readable
              context.textAlign = "left"; context.textBaseline = "middle";
              context.fillText(node.id, x + r + 7, y + 0.5);
            } else {
              context.textBaseline = "top";
              context.fillText(node.id, x, y + r + 5);
            }
          }
        }
      });
      context.restore();
      context.globalAlpha = 1;
    }

    /* ---- pointer ---- */
    function toWorld(event) {
      const box = canvas.getBoundingClientRect();
      return { x: (event.clientX - box.left - width / 2 - view.x) / view.k, y: (event.clientY - box.top - height / 2 - view.y) / view.k,
               sx: event.clientX - box.left, sy: event.clientY - box.top };
    }

    function pick(point) {
      let best = null, bestDistance = Infinity;
      nodes.forEach((node) => {
        if (!visible(node)) return;
        if (mode === "flow") {
          const px = node.sx === undefined ? node.x : node.sx, py = node.sy === undefined ? node.y : node.sy;
          const dx = Math.abs(px - point.x), dy = Math.abs(py - point.y);
          if (dx <= FLOW_W / 2 + 3 && dy <= FLOW_H / 2 + 3 && dx + dy < bestDistance) { best = node; bestDistance = dx + dy; }
          return;
        }
        const scale = node.ss || 1;
        const distance = Math.hypot((node.sx === undefined ? node.x : node.sx) - point.x, (node.sy === undefined ? node.y : node.sy) - point.y);
        if (distance < radius(node) * scale + 7 / view.k && distance < bestDistance) { best = node; bestDistance = distance; }
      });
      return best;
    }

    function showTip(node, point) {
      if (!node) { tip.hidden = true; return; }
      tip.replaceChildren(el("b", null, node.more ? "More" : node.id));
      if (node.name && node.name !== node.id) tip.appendChild(el("span", null, node.name));
      if (node.more) tip.appendChild(el("span", null, "Select to load more of them"));
      tip.dataset.type = node.label;
      tip.hidden = false;
      tip.style.left = Math.max(4, Math.min(point.sx + 14, width - 240)) + "px";
      tip.style.top = Math.max(4, Math.min(point.sy + 14, height - 60)) + "px";
    }

    canvas.addEventListener("pointerdown", (event) => {
      const node = pick(toWorld(event));
      drag = { node, startX: event.clientX, startY: event.clientY, viewX: view.x, viewY: view.y, rotX: rot.x, rotY: rot.y, moved: false };
      target = null;
      try { canvas.setPointerCapture(event.pointerId); } catch (error) { /* synthetic events */ }
      canvas.classList.add("dragging");
      wake(0.05);
    });
    canvas.addEventListener("pointermove", (event) => {
      const point = toWorld(event);
      if (drag) {
        if (Math.hypot(event.clientX - drag.startX, event.clientY - drag.startY) > 4) drag.moved = true;
        if (mode === "3d") {                                           // dragging turns the graph
          if (drag.moved) {
            rot.y = drag.rotY + (event.clientX - drag.startX) * 0.006;
            rot.x = Math.max(-1.35, Math.min(1.35, drag.rotX + (event.clientY - drag.startY) * 0.006));
            wake(0.05);
          }
        }
        else if (drag.node && drag.moved) {
          drag.node.x = point.x; drag.node.y = point.y;
          if (laidOut()) { drag.node.tx = point.x; drag.node.ty = point.y; }
          wake(0.3);
        }
        else if (!drag.node) { view.x = drag.viewX + event.clientX - drag.startX; view.y = drag.viewY + event.clientY - drag.startY; wake(0.05); }
        tip.hidden = true;
        return;
      }
      const node = pick(point);
      const id = node ? node.id : null;
      if (id !== hover) { hover = id; wake(0.03); }
      canvas.classList.toggle("pointing", Boolean(node));
      showTip(node, point);
    });
    canvas.addEventListener("pointerup", () => {
      canvas.classList.remove("dragging");
      const finished = drag;
      drag = null;
      if (finished && finished.node && !finished.moved) activate(finished.node);
    });
    canvas.addEventListener("pointercancel", () => { drag = null; canvas.classList.remove("dragging"); });
    canvas.addEventListener("pointerleave", () => { hover = null; tip.hidden = true; wake(0.03); });
    canvas.addEventListener("wheel", (event) => {
      event.preventDefault();
      const box = canvas.getBoundingClientRect();
      zoom(event.deltaY < 0 ? 1.15 : 1 / 1.15, event.clientX - box.left - width / 2, event.clientY - box.top - height / 2);
    }, { passive: false });

    function zoom(factor, originX = 0, originY = 0) {
      const next = Math.min(3, Math.max(0.2, view.k * factor));
      const scale = next / view.k;
      view.x = originX - (originX - view.x) * scale;
      view.y = originY - (originY - view.y) * scale;
      view.k = next;
      target = null;
      wake(0.05);
    }

    function fit() {
      const list = [...nodes.values()].filter(visible);
      if (!list.length) return;
      if (mode === "3d") {                                             // it turns, so fit the whole ball around the centre
        const reach = Math.max(60, ...list.map((n) => Math.hypot(n.x, n.y, n.z)));
        target = { k: Math.min(1.4, Math.max(0.2, (Math.min(width, height) / 2 - 40) / (reach * 1.3))), x: 0, y: 0 };
        wake(0.05);
        return;
      }
      let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
      list.forEach((node) => {
        const n = laidOut() && node.tx !== undefined ? { x: node.tx, y: node.ty } : node;
        minX = Math.min(minX, n.x); maxX = Math.max(maxX, n.x); minY = Math.min(minY, n.y); maxY = Math.max(maxY, n.y);
      });
      const k = Math.min(1.4, Math.max(0.2, Math.min((width - 120) / (maxX - minX || 1), (height - 120) / (maxY - minY || 1))));
      target = { k, x: -((minX + maxX) / 2) * k, y: -((minY + maxY) / 2) * k };
      wake(0.05);
    }

    /* ---- selection and the details panel ---- */
    function activate(node) {
      if (node.more) select(node.parent, 25); else select(node.id);
    }

    async function select(id, perGroup = 10) {
      const wanted = String(id).trim().toUpperCase();
      const ticket = ++requestId;
      selected = wanted;
      closeResults();
      if (!nodes.has(wanted) || !nodes.get(wanted).expanded) {
        const loading = el("div", "detail-loading");
        loading.append(el("div", "spinner"), document.createTextNode("Loading " + wanted));
        detail.replaceChildren(loading);
      }
      wake(0.05);
      let data;
      try { data = await fetchEntity(wanted, perGroup); }
      catch (error) {
        if (ticket !== requestId) return;
        selected = null;
        detail.replaceChildren(el("p", "placeholder", error instanceof TypeError
          ? "The backend could not be reached." : error.message));
        return;
      }
      if (ticket !== requestId) return;
      merge(data);
      renderDetail(data);
      const node = nodes.get(wanted);
      if (laidOut()) { layout(); fit(); }                              // radial re-centres on the selection
      else if (mode === "3d") target = { k: view.k, x: 0, y: 0 };
      else target = { k: view.k, x: -node.x * view.k, y: -node.y * view.k };
      try { window.history.replaceState(null, "", "#/graph?e=" + encodeURIComponent(wanted)); } catch (error) { /* file:// */ }
      wake(0.4);
    }

    function fact(list, label, value) {
      if (value === undefined || value === null || value === "" || (Array.isArray(value) && !value.length)) return;
      list.appendChild(el("dt", null, label));
      const cell = el("dd");
      if (value instanceof Node) cell.appendChild(value); else cell.textContent = Array.isArray(value) ? value.join(", ") : String(value);
      list.appendChild(cell);
    }

    function dateText(value) {
      const date = new Date(value);
      return Number.isNaN(date.getTime()) ? null
        : date.toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" });
    }

    function severityNode(severity, score) {
      const box = el("span");
      if (severity) box.appendChild(el("span", "sev sev-" + String(severity).toLowerCase().replace(/\s+/g, "-"), severity));
      if (score !== undefined && score !== null) box.appendChild(document.createTextNode(String(score)));
      return box.childNodes.length ? box : null;
    }

    function buildDetail(data, pick) {
      const p = data.properties;
      const box = el("div", "entity");
      box.dataset.type = data.label;
      box.appendChild(el("span", "entity-kind", KIND[data.label] || data.label));
      box.appendChild(el("h2", null, data.id));
      if (p.name && p.name !== data.id) box.appendChild(el("p", "entity-name", p.name));

      const facts = el("dl", "facts");
      if (data.label === "CVE") {
        fact(facts, "Severity", severityNode(p.severity, p.base_score));
        fact(facts, "CVSS vector", p.cvss_vector);
        fact(facts, "Exploitability", p.exploitability_score);
        fact(facts, "Impact", p.impact_score);
        fact(facts, "Published", p.published && dateText(p.published));
        fact(facts, "Last modified", p.last_modified && dateText(p.last_modified));
        fact(facts, "Status", p.vuln_status);
      } else if (data.label === "ATTACK") {
        fact(facts, "Type", p.type);
        fact(facts, "Tactics", p.tactics);
        fact(facts, "Platforms", p.platforms);
        fact(facts, "Domains", p.domains);
        fact(facts, "Last modified", p.modified && dateText(p.modified));
      } else {
        fact(facts, "Abstraction", p.category);
        if (data.label === "CAPEC") fact(facts, "Severity", severityNode(p.severity));
        fact(facts, "Likelihood", p.likelihood);
        fact(facts, "Structure", p.structure);
        fact(facts, "Status", p.status);
      }
      fact(facts, "Source", p.source);
      if (facts.children.length) box.appendChild(facts);
      if (p.description) box.appendChild(el("p", "entity-desc", p.description));

      const actions = el("div", "entity-actions");
      const ask = el("button", "btn btn-primary", "Ask the assistant");
      ask.type = "button";
      ask.dataset.ask = "Explain " + data.id;
      actions.appendChild(ask);
      if (/^https:\/\//.test(p.source_url || "")) {
        const link = el("a", "btn", "Official record");
        link.href = p.source_url; link.target = "_blank"; link.rel = "noopener noreferrer";
        actions.appendChild(link);
      }
      box.appendChild(actions);

      if (data.groups.length) {
        box.appendChild(el("h3", null, "Relationships"));
        data.groups.forEach((group) => {
          const section = el("div", "rel-group");
          const title = el("h4", null, (GROUP_TITLES[group.rel] || [group.rel, group.rel])[group.outgoing ? 0 : 1]);
          title.appendChild(el("span", null, group.total.toLocaleString()));
          section.appendChild(title);
          const list = el("div", "rel-list");
          group.nodes.forEach((info) => {
            const item = el("button", "rel-item");
            item.type = "button";
            item.dataset.type = info.label;
            item.appendChild(el("b", null, info.id));
            const text = info.label === "CVE"
              ? [info.severity, info.base_score].filter((v) => v !== null && v !== undefined).join(" ") : info.name;
            if (text && text !== info.id) item.appendChild(el("span", null, text));
            item.addEventListener("click", () => pick(info.id));
            list.appendChild(item);
          });
          section.appendChild(list);
          const rest = group.total - group.nodes.length;
          if (rest > 0) section.appendChild(el("p", "rel-more", `${rest.toLocaleString()} more not shown`));
          box.appendChild(section);
        });
      }

      const extra = LISTS.filter(([key]) => Array.isArray(p[key]) && p[key].length);
      if (extra.length) box.appendChild(el("h3", null, "More detail"));
      extra.forEach(([key, label]) => {
        const block = el("details");
        const summary = el("summary", null, label);
        const total = (data.list_sizes && data.list_sizes[key]) || p[key].length;
        summary.appendChild(el("span", null, total.toLocaleString()));
        block.appendChild(summary);
        const list = el("ul");
        p[key].forEach((entry) => {
          const item = el("li");
          if (/^https?:\/\/\S+$/.test(entry)) {
            const link = el("a", null, entry);
            link.href = entry; link.target = "_blank"; link.rel = "noopener noreferrer";
            item.appendChild(link);
          } else item.textContent = String(entry);
          list.appendChild(item);
        });
        if (total > p[key].length) list.appendChild(el("li", null, `and ${(total - p[key].length).toLocaleString()} more`));
        block.appendChild(list);
        box.appendChild(block);
      });

      return box;
    }

    function renderDetail(data) {
      detail.replaceChildren(buildDetail(data, (id) => select(id)));
      detail.scrollTop = 0;
    }

    /* ---- search ---- */
    function closeResults() {
      resultsList.hidden = true;
      searchInput.setAttribute("aria-expanded", "false");
      activeResult = -1;
    }

    function showResults() {
      resultsList.replaceChildren();
      if (!results.length) resultsList.appendChild(el("li", "none", "No matching entity"));
      results.forEach((info, index) => {
        const row = el("li");
        row.setAttribute("role", "option");
        row.setAttribute("aria-selected", String(index === activeResult));
        row.dataset.type = info.label;
        row.appendChild(el("b", null, info.id));
        if (info.name && info.name !== info.id) row.appendChild(el("span", null, info.name));
        row.addEventListener("mousedown", (event) => { event.preventDefault(); choose(info.id); });
        resultsList.appendChild(row);
      });
      resultsList.hidden = false;
      searchInput.setAttribute("aria-expanded", "true");
    }

    /* Several entities can be searched at once: separate them with commas (or spaces
     * between identifiers).  Every one is added to the same graph. */
    function searchTerms() {
      const raw = searchInput.value;
      let parts = raw.split(/[,;]+/).map((t) => t.trim()).filter(Boolean);
      if (parts.length === 1) {
        const words = parts[0].split(/\s+/);
        if (words.length > 1 && words.every((w) => ID_RE.test(w.toUpperCase()))) parts = words;
      }
      return parts;
    }
    const lastTerm = () => { const parts = searchInput.value.split(/[,;]+/); return parts[parts.length - 1].trim(); };

    function choose(id) {                                   // a suggestion replaces only the term being typed
      const parts = searchInput.value.split(/[,;]+/).map((t) => t.trim());
      parts[parts.length - 1] = id;
      searchInput.value = parts.filter(Boolean).join(", ");
      select(id);
    }

    async function loadMany(ids) {                          // one after another, all into the same graph
      const unique = [...new Set(ids)];
      for (const id of unique) await select(id);
      if (unique.length > 1) setTimeout(fit, 900);          // once the layout has spread out, show everything
    }

    searchInput.addEventListener("input", () => {
      clearTimeout(searchTimer);
      const text = lastTerm();
      if (text.length < 2) { closeResults(); return; }
      searchTimer = setTimeout(async () => {
        try {
          const body = await api("/api/graph/search?q=" + encodeURIComponent(text));
          if (lastTerm() !== text) return;
          results = body.results || [];
        } catch (error) { results = []; }
        activeResult = -1;
        showResults();
      }, 220);
    });
    searchInput.addEventListener("keydown", (event) => {
      if (event.key === "Escape") { closeResults(); return; }
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        if (resultsList.hidden || !results.length) return;
        event.preventDefault();
        activeResult = (activeResult + (event.key === "ArrowDown" ? 1 : -1) + results.length) % results.length;
        showResults();
        return;
      }
      if (event.key !== "Enter") return;
      event.preventDefault();
      const terms = searchTerms();
      if (!terms.length) return;
      if (terms.length === 1) {
        const text = terms[0].toUpperCase();
        const choice = results[activeResult] || (ID_RE.test(text) ? { id: text } : results[0]);
        if (choice) choose(choice.id);
        return;
      }
      closeResults();
      (async () => {
        const ids = [];
        for (let i = 0; i < terms.length; i += 1) {
          const text = terms[i].toUpperCase();
          if (ID_RE.test(text)) { ids.push(text); continue; }
          if (i === terms.length - 1 && (results[activeResult] || results[0])) { ids.push((results[activeResult] || results[0]).id); continue; }
          try {                                             // a name: use its best match
            const body = await api("/api/graph/search?q=" + encodeURIComponent(terms[i]));
            if (body.results && body.results[0]) ids.push(body.results[0].id);
          } catch (error) { /* skipped */ }
        }
        if (!ids.length) return;
        searchInput.value = ids.join(", ");
        loadMany(ids);
      })();
    });
    searchInput.addEventListener("blur", () => setTimeout(closeResults, 120));

    const modeButtons = [...document.querySelectorAll(".kg-mode")];
    const footHint = document.querySelector(".kg-foot");
    modeButtons.forEach((button) => button.addEventListener("click", () => setMode(button.dataset.mode)));
    modeButtons.forEach((button) => button.setAttribute("aria-pressed", String(button.dataset.mode === mode)));
    if (footHint) footHint.textContent = KG_HINTS[mode];
    canvas.dataset.mode = mode;

    document.querySelectorAll(".kg-legend [data-type]").forEach((button) => {      // show or hide one entity type
      button.addEventListener("click", () => {
        const type = button.dataset.type;
        if (hiddenTypes.has(type)) hiddenTypes.delete(type); else hiddenTypes.add(type);
        button.setAttribute("aria-pressed", String(!hiddenTypes.has(type)));
        if (hover && !visible(nodes.get(hover))) hover = null;
        tip.hidden = true;
        layout();
        wake(0.6);
      });
    });

    const kgBox = document.querySelector(".kg");
    const fullButton = document.getElementById("kg-full");
    const isFull = () => kgBox.classList.contains("kg-full");
    function showFull(on) {                                 // keeps the button and the canvas in step
      kgBox.classList.toggle("kg-full", on);
      fullButton.setAttribute("aria-pressed", String(on));
      fullButton.textContent = on ? "Exit fullscreen" : "Fullscreen";
      resize();
      setTimeout(() => { resize(); fit(); }, 120);
    }
    function setFull(on) {                                  // fills the browser window; Esc leaves
      if (on !== isFull()) showFull(on);
    }
    fullButton.addEventListener("click", () => setFull(!isFull()));
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && isFull() && resultsList.hidden) setFull(false);
    });
    window.addEventListener("hashchange", () => {            // leaving the page ends fullscreen
      if (!location.hash.startsWith("#/graph") && isFull()) setFull(false);
    });

    document.getElementById("kg-in").addEventListener("click", () => zoom(1.25));
    document.getElementById("kg-out").addEventListener("click", () => zoom(0.8));
    document.getElementById("kg-fit").addEventListener("click", fit);
    document.getElementById("kg-reset").addEventListener("click", () => {
      requestId += 1;
      nodes.clear(); edges.clear(); cache.clear();
      selected = null; hover = null; target = null;
      view.x = 0; view.y = 0; view.k = 1;
      searchInput.value = "";
      detail.replaceChildren(el("p", "placeholder", "Entity details appear here when you select a node."));
      emptyBox.hidden = false;
      try { window.history.replaceState(null, "", "#/graph"); } catch (error) { /* file:// */ }
      wake(0.05);
    });
    if ("ResizeObserver" in window) new ResizeObserver(resize).observe(stage);
    else window.addEventListener("resize", resize);

    async function loadOverview() {
      if (overviewLoaded) return;
      overviewLoaded = true;
      try {
        const body = await api("/api/graph/overview");
        startList.replaceChildren();
        (body.results || []).forEach((info) => {
          const item = el("button", "rel-item");
          item.type = "button";
          item.dataset.type = info.label;
          item.appendChild(el("b", null, info.id));
          item.appendChild(el("span", null, info.name));
          item.addEventListener("click", () => select(info.id));
          startList.appendChild(item);
        });
      } catch (error) { overviewLoaded = false; }
    }

    return {
      /* the same details, for the panel an answer's graph opens */
      async details(id, pick) { return buildDetail(await fetchEntity(id, 10), pick); },
      open(entity) {
        resize();
        if (entity && entity.toUpperCase() !== selected) select(entity);
        else if (!nodes.size) loadOverview();
        wake(0.05);
      },
    };
  })();

  /* ------------------------------------------------------------------ */
  /* details of a node clicked in an answer's relationship graph          */
  /* ------------------------------------------------------------------ */
  let entityPanel = null, panelTicket = 0, panelReturn = null;

  function closeEntityPanel() {
    panelTicket += 1;
    if (!entityPanel) return;
    entityPanel.remove();
    entityPanel = null;
    if (panelReturn && panelReturn.isConnected) panelReturn.focus({ preventScroll: true });
    panelReturn = null;
  }

  async function openEntityPanel(id, wrap) {
    // a fullscreen graph only shows its own children
    const host = document.fullscreenElement === wrap ? wrap : document.body;
    if (entityPanel && entityPanel.parentNode !== host) closeEntityPanel();
    if (!entityPanel) {
      panelReturn = document.activeElement;
      entityPanel = el("aside", "entity-panel kg-detail");
      entityPanel.setAttribute("role", "dialog");
      entityPanel.setAttribute("aria-label", "Entity details");
      const bar = el("div", "entity-panel-bar");
      const graphButton = el("button", "btn", "Open in Knowledge Graph");
      graphButton.type = "button";
      const close = el("button", "btn btn-square", "\u00d7");
      close.type = "button";
      close.setAttribute("aria-label", "Close details");
      close.addEventListener("click", closeEntityPanel);
      bar.append(graphButton, close);
      const body = el("div", "entity-panel-body");
      body.setAttribute("aria-live", "polite");
      entityPanel.append(bar, body);
      host.appendChild(entityPanel);
      close.focus({ preventScroll: true });
    }
    const body = entityPanel.querySelector(".entity-panel-body");
    const graphButton = entityPanel.querySelector(".entity-panel-bar .btn");
    graphButton.dataset.graph = id;
    const ticket = ++panelTicket;
    const loading = el("div", "detail-loading");
    loading.append(el("div", "spinner"), document.createTextNode("Loading " + id));
    body.replaceChildren(loading);
    let content;
    try { content = await explorer.details(id, (next) => openEntityPanel(next, wrap)); }
    catch (error) {
      content = el("p", "placeholder", error instanceof TypeError
        ? "The backend could not be reached." : error.message);
    }
    if (ticket !== panelTicket || !entityPanel) return;
    body.replaceChildren(content);
    body.scrollTop = 0;
  }

  document.addEventListener("click", (event) => {            // "Ask" and "Open in Knowledge Graph" lead elsewhere
    if (!entityPanel || !event.target.closest(".entity-panel [data-ask], .entity-panel [data-graph]")) return;
    if (document.fullscreenElement) document.exitFullscreen();
    closeEntityPanel();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && entityPanel) closeEntityPanel();
  });
  document.addEventListener("fullscreenchange", closeEntityPanel);
  window.addEventListener("hashchange", closeEntityPanel);

  loadArchive();
  updateHistoryCount();

  restoreHistory();
  checkStatus().then((ok) => {
    if (ok) refreshPanel(); else panelTimer = setTimeout(refreshPanel, 20000);
    if (currentView === "graph") route();
  });
  setInterval(checkStatus, 60000);
  route();
})();
