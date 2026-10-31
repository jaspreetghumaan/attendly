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

/* ==========================================================================
   Attendly | Homepage effects (added at the end of theme.js)
   Runs only on the homepage, because the <body> there has class "page--home".
   ========================================================================== */
(function () {
  "use strict";
  if (!document.body || !document.body.classList.contains("page--home")) return;

  var root = document.documentElement;
  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var finePointer = window.matchMedia("(hover: hover) and (pointer: fine)").matches;
  var canObserve = "IntersectionObserver" in window;

  /* 1. Header shadow + scroll progress bar */
  var header = document.querySelector(".site-header");
  var progress = null;

  if (!reduceMotion) {
    progress = document.createElement("div");
    progress.className = "fx-progress";
    progress.setAttribute("aria-hidden", "true");
    document.body.appendChild(progress);
  }

  var scrollQueued = false;
  function updateOnScroll() {
    if (scrollQueued) return;
    scrollQueued = true;
    requestAnimationFrame(function () {
      var y = window.scrollY;
      var max = root.scrollHeight - window.innerHeight;
      if (header) header.classList.toggle("is-scrolled", y > 8);
      if (progress) progress.style.transform = "scaleX(" + (max > 0 ? y / max : 0) + ")";
      scrollQueued = false;
    });
  }
  window.addEventListener("scroll", updateOnScroll, { passive: true });
  window.addEventListener("resize", updateOnScroll);
  updateOnScroll();

  /* 2. Highlight the nav link for the section in view */
  var navLinks = Array.prototype.slice.call(document.querySelectorAll('.site-nav__link[href^="#"]'));
  var linkBySection = new Map();

  navLinks.forEach(function (link) {
    var section = document.getElementById(link.getAttribute("href").slice(1));
    if (section) linkBySection.set(section, link);
  });

  if (canObserve && linkBySection.size) {
    var navObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        navLinks.forEach(function (link) {
          link.classList.remove("is-active");
          link.removeAttribute("aria-current");
        });
        var active = linkBySection.get(entry.target);
        if (active) {
          active.classList.add("is-active");
          active.setAttribute("aria-current", "true");
        }
      });
    }, { rootMargin: "-45% 0px -50% 0px" });

    linkBySection.forEach(function (_, section) { navObserver.observe(section); });
  }

  // Everything below is motion. Skip it for users who asked for reduced motion.
  if (reduceMotion) return;

  /* 3. Scroll reveal with a small stagger */
  if (canObserve) {
    root.classList.add("fx-ready");

    var revealTargets = document.querySelectorAll([
      ".hero__content > *",
      ".section__header",
      ".feature-grid__item",
      ".steps-list__item",
      ".access-card",
      ".benefits-list__item",
      ".about > *",
      ".activity-list__item"
    ].join(", "));

    var revealObserver = new IntersectionObserver(function (entries, observer) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        entry.target.classList.remove("fx-pending");
        entry.target.classList.add("fx-in");
        observer.unobserve(entry.target);
      });
    }, { threshold: 0.15, rootMargin: "0px 0px -40px 0px" });

    // Siblings in the same parent start one after another.
    var countPerParent = new Map();
    revealTargets.forEach(function (el) {
      var index = countPerParent.get(el.parentElement) || 0;
      countPerParent.set(el.parentElement, index + 1);
      el.style.setProperty("--fx-delay", Math.min(index, 5) * 90 + "ms");
      el.classList.add("fx-pending");
      revealObserver.observe(el);
    });
  }

  /* 4. Count-up numbers in the dashboard preview */
  function countUp(el) {
    // Only the first text node is changed, so the "%" span stays as it is.
    var node = Array.from(el.childNodes).find(function (n) {
      return n.nodeType === Node.TEXT_NODE && /\d/.test(n.nodeValue);
    });
    var end = node ? parseInt(node.nodeValue, 10) : NaN;
    if (isNaN(end)) return;

    var duration = 1100;
    var start = performance.now();
    node.nodeValue = "0";

    function tick(now) {
      var t = Math.min((now - start) / duration, 1);
      node.nodeValue = String(Math.round(end * (1 - Math.pow(1 - t, 3))));
      if (t < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  if (canObserve) {
    var countObserver = new IntersectionObserver(function (entries, observer) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        countUp(entry.target);
        observer.unobserve(entry.target);
      });
    }, { threshold: 0.6 });

    document.querySelectorAll(".summary-block h2, .rate-value").forEach(function (el) {
      countObserver.observe(el);
    });
  }

  /* 5. Cursor spotlight on cards */
  document.querySelectorAll(".feature-card, .step-card, .benefit-card, .access-card, .summary-block")
    .forEach(function (card) {
      card.classList.add("fx-glow");

      var spotlight = document.createElement("span");
      spotlight.className = "fx-spotlight";
      spotlight.setAttribute("aria-hidden", "true");
      card.insertBefore(spotlight, card.firstChild);

      card.addEventListener("pointermove", function (e) {
        var rect = card.getBoundingClientRect();
        card.style.setProperty("--fx-x", (e.clientX - rect.left) + "px");
        card.style.setProperty("--fx-y", (e.clientY - rect.top) + "px");
      });
    });

  /* 6. Click ripple on buttons */
  document.querySelectorAll(".btn").forEach(function (btn) {
    btn.addEventListener("pointerdown", function (e) {
      var rect = btn.getBoundingClientRect();
      var size = Math.max(rect.width, rect.height) * 2;

      var ripple = document.createElement("span");
      ripple.className = "fx-ripple";
      ripple.style.width = size + "px";
      ripple.style.height = size + "px";
      ripple.style.left = (e.clientX - rect.left - size / 2) + "px";
      ripple.style.top = (e.clientY - rect.top - size / 2) + "px";

      btn.appendChild(ripple);
      setTimeout(function () { ripple.remove(); }, 700);
    });
  });

  /* 7. Magnetic pull on primary buttons (mouse only) */
  if (finePointer) {
    document.querySelectorAll(".btn--primary").forEach(function (btn) {
      btn.addEventListener("pointermove", function (e) {
        var rect = btn.getBoundingClientRect();
        var x = e.clientX - (rect.left + rect.width / 2);
        var y = e.clientY - (rect.top + rect.height / 2);
        btn.style.setProperty("--fx-mx", (x * 0.2).toFixed(1) + "px");
        btn.style.setProperty("--fx-my", (y * 0.25).toFixed(1) + "px");
      });

      btn.addEventListener("pointerleave", function () {
        btn.style.setProperty("--fx-mx", "0px");
        btn.style.setProperty("--fx-my", "0px");
      });
    });
  }
})();