/* ==========================================================================
   Smart QR Attendance — theme.js
   Vanilla JS, no dependencies. Load with `defer` after Bootstrap.
   Provides: aurora background, custom 3D cursor, magnetic hover,
   card tilt ([data-tilt]) and gentle aurora parallax.
   Nothing here touches forms, routes, IDs or existing listeners.
   ========================================================================== */
(function () {
  "use strict";
  if (window.__qaTheme) return; // guard against double-loading
  window.__qaTheme = true;

  var root = document.documentElement;

  /* Selector groups — extend freely. Priority: native > qr > hover. */
  var NATIVE_SEL = [
    "input", "textarea", "select", "video", "iframe", "[contenteditable='true']",
    "[data-cursor='native']", "[id*='reader' i]", "[id*='scanner' i]", "[class*='scanner' i]"
  ].join(",");
  var QR_SEL = [
    "[data-cursor='qr']", ".qa-qr-frame", "[id*='qr' i]", "[class*='qr-' i]", "a[href*='qr' i]"
  ].join(",");
  var HOVER_SEL = [
    "a[href]", "button", ".btn", "[role='button']", "summary", "label[for]",
    ".nav-link", ".dropdown-item", ".page-link", "[data-cursor='hover']", ".is-interactive", "[onclick]"
  ].join(",");
  var MAGNETIC_SEL = ".btn, [data-magnetic]";

  /* ---------- Aurora background (works on every device) ---------------- */
  var auroraLayers = [];
  function buildAurora() {
    if (document.querySelector(".qa-aurora")) return;
    var wrap = document.createElement("div");
    wrap.className = "qa-aurora";
    wrap.setAttribute("aria-hidden", "true");
    ["teal", "amber", "ecru"].forEach(function (name) {
      var l = document.createElement("div");
      l.className = "qa-aurora__layer qa-aurora__layer--" + name;
      wrap.appendChild(l);
      auroraLayers.push(l);
    });
    var v = document.createElement("div");
    v.className = "qa-aurora__vignette";
    wrap.appendChild(v);
    document.body.insertBefore(wrap, document.body.firstChild);
  }

  /* ---------- Pointer-driven effects (desktop mouse only) -------------- */
  var fineQuery = window.matchMedia("(hover: hover) and (pointer: fine)");
  var reduceQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
  var ac = null; // AbortController for the listener set

  function enable() {
    if (ac) return;
    ac = new AbortController();
    var sig = { signal: ac.signal };
    var sigPassive = { signal: ac.signal, passive: true };

    var reduced = reduceQuery.matches;

    // Create cursor elements once
    var ringWrap = document.createElement("div");
    ringWrap.className = "qa-cursor qa-cursor--ring";
    ringWrap.setAttribute("aria-hidden", "true");
    var ring = document.createElement("div");
    ring.className = "qa-cursor__ring";
    ringWrap.appendChild(ring);

    var dotWrap = document.createElement("div");
    dotWrap.className = "qa-cursor qa-cursor--dot";
    dotWrap.setAttribute("aria-hidden", "true");
    var dot = document.createElement("div");
    dot.className = "qa-cursor__dot";
    dotWrap.appendChild(dot);

    document.body.appendChild(ringWrap);
    document.body.appendChild(dotWrap);

    // State
    var px = 0, py = 0;           // pointer
    var rx = 0, ry = 0;           // ring (smoothed)
    var ax = 0, ay = 0;           // aurora parallax (smoothed, -1..1)
    var seen = false;             // first pointer event received?
    var raf = 0, last = 0;
    var magnetEl = null;
    var tiltEl = null, tiltRect = null, tiltX = 0, tiltY = 0;
    var lastTarget = null;

    function setState(el) {
      var native = false, qr = false, hover = false;
      if (el && el.closest) {
        if (el.closest(NATIVE_SEL)) native = true;
        else if (el.closest(QR_SEL)) qr = true;
        else if (el.closest(HOVER_SEL)) hover = true;
      }
      root.classList.toggle("qa-cursor-native", native);
      root.classList.toggle("qa-cursor-qr", qr && !native);
      root.classList.toggle("qa-cursor-hover", (hover || qr) && !native);

      var m = !native && el && el.closest ? el.closest(MAGNETIC_SEL) : null;
      magnetEl = reduced ? null : m;

      // Tilt target
      var t = !native && !reduced && el && el.closest ? el.closest("[data-tilt]") : null;
      if (t !== tiltEl) {
        if (tiltEl) { tiltEl.style.setProperty("--qa-tilt-x", "0deg"); tiltEl.style.setProperty("--qa-tilt-y", "0deg"); }
        tiltEl = t;
        tiltRect = t ? t.getBoundingClientRect() : null;
      }
    }

    function frame(now) {
      raf = 0;
      var dt = Math.min(now - (last || now), 50) || 16.7;
      last = now;
      var k = reduced ? 1 : 1 - Math.pow(1 - 0.2, dt / 16.7);

      // Magnetic pull: ring drifts partly toward the element's centre
      var tx = px, ty = py;
      if (magnetEl) {
        var r = magnetEl.getBoundingClientRect();
        tx = px + (r.left + r.width / 2 - px) * 0.22;
        ty = py + (r.top + r.height / 2 - py) * 0.22;
      }
      rx += (tx - rx) * k;
      ry += (ty - ry) * k;

      dotWrap.style.transform = "translate3d(" + px + "px," + py + "px,0)";
      ringWrap.style.transform = "translate3d(" + rx.toFixed(2) + "px," + ry.toFixed(2) + "px,0)";

      var busy = Math.abs(tx - rx) > 0.1 || Math.abs(ty - ry) > 0.1;

      // Aurora parallax
      if (!reduced && auroraLayers.length) {
        var gx = (px / window.innerWidth - 0.5) * 2;
        var gy = (py / window.innerHeight - 0.5) * 2;
        var ka = 1 - Math.pow(1 - 0.05, dt / 16.7);
        ax += (gx - ax) * ka;
        ay += (gy - ay) * ka;
        for (var i = 0; i < auroraLayers.length; i++) {
          var depth = (i + 1) * 14; // px of travel per layer
          auroraLayers[i].style.translate = (-ax * depth).toFixed(1) + "px " + (-ay * depth).toFixed(1) + "px";
        }
        if (Math.abs(gx - ax) > 0.002 || Math.abs(gy - ay) > 0.002) busy = true;
      }

      // Card tilt (max 4°)
      if (tiltEl && tiltRect) {
        var nx = (px - tiltRect.left) / tiltRect.width - 0.5;
        var ny = (py - tiltRect.top) / tiltRect.height - 0.5;
        tiltX = (-ny * 8).toFixed(2);
        tiltY = (nx * 8).toFixed(2);
        tiltEl.style.setProperty("--qa-tilt-x", tiltX + "deg");
        tiltEl.style.setProperty("--qa-tilt-y", tiltY + "deg");
      }

      if (busy) raf = requestAnimationFrame(frame); // otherwise sleep until next move
    }
    function wake() { if (!raf) { last = 0; raf = requestAnimationFrame(frame); } }

    function show() { ringWrap.classList.add("is-visible"); dotWrap.classList.add("is-visible"); }
    function hide() { ringWrap.classList.remove("is-visible"); dotWrap.classList.remove("is-visible"); }

    document.addEventListener("pointermove", function (e) {
      if (e.pointerType && e.pointerType !== "mouse") return;
      px = e.clientX; py = e.clientY;
      if (!seen) {
        seen = true; rx = px; ry = py;
        root.classList.add("qa-cursor-active"); // native cursor hidden only now, once we're live
        show();
      } else if (!ringWrap.classList.contains("is-visible")) {
        show();
      }
      if (e.target !== lastTarget) { lastTarget = e.target; setState(e.target); }
      wake();
    }, sigPassive);

    document.addEventListener("pointerdown", function (e) {
      if (e.pointerType === "mouse") root.classList.add("qa-cursor-down");
    }, sigPassive);
    var up = function () { root.classList.remove("qa-cursor-down"); };
    document.addEventListener("pointerup", up, sigPassive);
    document.addEventListener("pointercancel", up, sigPassive);
    window.addEventListener("blur", function () { up(); hide(); }, sig);

    // Pointer leaves / re-enters the window
    root.addEventListener("mouseleave", hide, sig);
    root.addEventListener("mouseenter", function () { if (seen) show(); }, sig);
    document.addEventListener("visibilitychange", function () { if (document.hidden) hide(); }, sig);

    // Layout changes invalidate cached rects
    window.addEventListener("scroll", function () { if (tiltEl) tiltRect = tiltEl.getBoundingClientRect(); lastTarget = null; }, sigPassive);
    window.addEventListener("resize", function () { if (tiltEl) tiltRect = tiltEl.getBoundingClientRect(); }, sigPassive);

    // Teardown handle
    ac.signal.addEventListener("abort", function () {
      if (raf) cancelAnimationFrame(raf);
      ringWrap.remove(); dotWrap.remove();
      root.classList.remove("qa-cursor-active", "qa-cursor-hover", "qa-cursor-qr", "qa-cursor-native", "qa-cursor-down");
      auroraLayers.forEach(function (l) { l.style.translate = ""; });
      if (tiltEl) { tiltEl.style.removeProperty("--qa-tilt-x"); tiltEl.style.removeProperty("--qa-tilt-y"); }
    });
  }

  function disable() { if (ac) { ac.abort(); ac = null; } }
  function sync() { if (fineQuery.matches) { disable(); enable(); } else disable(); }

  function init() {
    buildAurora();
    sync();
    var onChange = sync;
    (fineQuery.addEventListener ? fineQuery.addEventListener("change", onChange) : fineQuery.addListener(onChange));
    (reduceQuery.addEventListener ? reduceQuery.addEventListener("change", onChange) : reduceQuery.addListener(onChange));
  }

  if (document.body) init();
  else document.addEventListener("DOMContentLoaded", init, { once: true });
})();
