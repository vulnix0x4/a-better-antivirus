// A Better Antivirus: website script.
// The page works without it. This adds: OS detection for the download area,
// copy buttons, the "be the stealer" game, the 158 ms reaction pad, the
// slowed-down instant-freeze diagram and the aba test terminal.
// Nothing here talks to the network.
(function () {
  "use strict";

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)");
  var calm = function () { return reduce.matches; };
  var wait = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };
  var rand = function (a, b) { return a + Math.floor(Math.random() * (b - a + 1)); };
  var el = function (tag, cls, html) { var e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; };

  /* ───────── Which system is the visitor on? ───────── */
  (function os() {
    var ua = navigator.userAgent || "";
    var plat = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "";
    var touchMac = /Mac/.test(plat) && navigator.maxTouchPoints > 1; // iPad asking for the desktop site
    var kind = "other";
    if (/Android|iPhone|iPad|iPod/i.test(ua) || touchMac) kind = "mobile";
    else if (/Win/i.test(plat) || /Windows/i.test(ua)) kind = "windows";
    else if (/Mac/i.test(plat) || /Macintosh/.test(ua)) kind = "mac";
    else if (/Linux|X11|CrOS/i.test(plat + ua)) kind = "linux";
    document.documentElement.setAttribute("data-os", kind);
    $$("[data-os-show]").forEach(function (n) {
      if (n.getAttribute("data-os-show").split(" ").indexOf(kind) >= 0) n.hidden = false;
    });
    var mine = $('.os[data-os="' + kind + '"]');
    if (mine) { mine.classList.add("is-yours"); var p = $(".pill-you", mine); if (p) p.hidden = false; }
  })();

  /* ───────── Copy buttons ───────── */
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    return new Promise(function (ok, fail) {
      var t = el("textarea"); t.value = text; t.setAttribute("readonly", ""); t.className = "sr-only";
      document.body.appendChild(t); t.select();
      try { document.execCommand("copy") ? ok() : fail(); } catch (e) { fail(e); }
      t.remove();
    });
  }
  $$("[data-copy]").forEach(function (b) {
    var src = document.getElementById(b.getAttribute("data-copy"));
    if (!src) return;
    b.hidden = false;
    b.setAttribute("aria-label", "Copy command");
    b.addEventListener("click", function () {
      copyText(src.textContent.trim()).then(function () { b.textContent = "Copied"; }, function () { b.textContent = "Select it"; });
      setTimeout(function () { b.textContent = "Copy"; }, 1800);
    });
  });

  /* ───────── Frost: ice crystals growing in from the edges ───────── */
  function Frost(canvas) {
    var ctx = canvas.getContext("2d");
    var segs = [], raf = 0, start = 0, dur = 420;
    function size() {
      var r = canvas.getBoundingClientRect(), d = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.round(r.width * d); canvas.height = Math.round(r.height * d);
      ctx.setTransform(d, 0, 0, d, 0, 0);
      return r;
    }
    var dots = [];
    // A dendrite: a main arm with side arms at 60 degrees, like frost on glass.
    function branch(x, y, a, len, depth, t0) {
      var step = 4, n = Math.max(2, Math.round(len / step)), px = x, py = y, t = t0, every = depth ? 3 : 2;
      for (var i = 0; i < n; i++) {
        a += (Math.random() - .5) * .08;
        var nx = px + Math.cos(a) * step, ny = py + Math.sin(a) * step;
        t += .9 / n * (1 + depth * .3);
        segs.push([px, py, nx, ny, t, depth]);
        if (depth < 2 && i > 1 && i % every === 0) {
          var rest = (n - i) * step * (depth ? .5 : .42) * (.6 + Math.random() * .5);
          if (rest > 5) {
            branch(nx, ny, a + Math.PI / 3, rest, depth + 1, t);
            branch(nx, ny, a - Math.PI / 3, rest * (.7 + Math.random() * .4), depth + 1, t);
          }
        }
        px = nx; py = ny;
      }
    }
    this.grow = function () {
      var r = size(); segs = []; dots = [];
      var w = r.width, h = r.height, n = Math.round((w + h) / 40);
      for (var i = 0; i < n; i++) {
        var edge = i % 4, x, y, a;
        if (edge === 0) { x = Math.random() * w; y = 0; a = Math.PI / 2; }
        else if (edge === 1) { x = w; y = Math.random() * h; a = Math.PI; }
        else if (edge === 2) { x = Math.random() * w; y = h; a = -Math.PI / 2; }
        else { x = 0; y = Math.random() * h; a = 0; }
        branch(x, y, a + (Math.random() - .5) * 1.1, 28 + Math.random() * 70, 0, Math.random() * .35);
      }
      for (var k = 0; k < (w + h) * .6; k++) { // rime: specks thick at the edges, thinning inwards
        var d = -Math.log(1 - Math.random() * .98) * 22, e = k % 4, px, py;
        if (e === 0) { px = Math.random() * w; py = d; } else if (e === 1) { px = w - d; py = Math.random() * h; }
        else if (e === 2) { px = Math.random() * w; py = h - d; } else { px = d; py = Math.random() * h; }
        dots.push([px, py, Math.random() * 1.3 + .3, Math.min(1, d / 90 + Math.random() * .4)]);
      }
      canvas.classList.add("is-on");
      var light = window.matchMedia("(prefers-color-scheme: light)").matches;
      var col = light ? "35,98,143" : "200,232,255";
      cancelAnimationFrame(raf);
      start = performance.now();
      var full = calm();
      (function frame(now) {
        var p = full ? 3 : (now - start) / dur * 1.4;
        ctx.clearRect(0, 0, w, h);
        // icy vignette
        var g = ctx.createRadialGradient(w / 2, h / 2, Math.min(w, h) * .25, w / 2, h / 2, Math.max(w, h) * .75);
        g.addColorStop(0, "rgba(" + col + ",0)");
        g.addColorStop(1, "rgba(" + col + "," + (Math.min(1, p) * (light ? .16 : .2)) + ")");
        ctx.fillStyle = g; ctx.fillRect(0, 0, w, h);
        ctx.lineCap = "round";
        for (var j = 0; j < dots.length; j++) {
          var q = dots[j];
          if (q[3] > p) continue;
          ctx.fillStyle = "rgba(" + col + "," + (light ? .35 : .32) + ")";
          ctx.fillRect(q[0], q[1], q[2], q[2]);
        }
        for (var depth = 0; depth < 3; depth++) {
          ctx.strokeStyle = "rgba(" + col + "," + ((light ? .7 : .62) - depth * .16) + ")";
          ctx.lineWidth = [1.5, 1, .7][depth];
          ctx.beginPath();
          for (var i = 0; i < segs.length; i++) {
            var s = segs[i];
            if (s[5] !== depth || s[4] > p) continue;
            ctx.moveTo(s[0], s[1]); ctx.lineTo(s[2], s[3]);
          }
          ctx.stroke();
        }
        if (p < 2.4) raf = requestAnimationFrame(frame);
      })(start);
    };
    this.count = function () { return segs.length; };
    this.clear = function () { cancelAnimationFrame(raf); canvas.classList.remove("is-on"); ctx.clearRect(0, 0, canvas.width, canvas.height); };
  }

  /* ───────── The game: be the stealer ───────── */
  (function heist() {
    var root = $("[data-heist]");
    if (!root) return;
    var win = $(".heist-win", root), filesBox = $("[data-files]", root);
    var clockEl = $("[data-clock]", root), lootBox = $("[data-loot]", root), lootTxt = $("[data-loot-txt]", root);
    var upBtn = $("[data-upload]", root), modal = $("[data-modal]", root), stamp = $("[data-stamp]", root);
    var stampMs = $("[data-stamp-ms]", root), announce = $("[data-announce]", root), intro = $("[data-intro]", root);
    var frost = new Frost($("[data-frost]", root));
    var files = $$(".file", root);
    lootBox.hidden = false;

    // Turn each row into a button. The "why" text is shown after the round.
    files.forEach(function (li) {
      var b = el("button", "f-btn"); b.type = "button";
      var main = el("span", "f-main"), sub = $(".f-sub", li);
      main.appendChild($(".f-name", li)); if (sub) main.appendChild(sub);
      b.appendChild($(".f-ico", li)); b.appendChild(main); b.appendChild($(".tag", li));
      li.textContent = "";
      var act = el("span", "f-act", "take"); b.appendChild(act);
      var why = el("span", "f-why", li.getAttribute("data-why")); b.appendChild(why);
      li.appendChild(b);
      b.addEventListener("click", function () {
        if (S.state === "over") { // after the round: a row shows why it is there
          var open = li.classList.toggle("is-open"); b.setAttribute("aria-expanded", open); return;
        }
        if (attract.on) stopAttract();
        take(li);
      });
    });

    var S, round = 0; // round state; timers from an old round check the round number
    function reset() {
      round++;
      S = { state: "idle", loot: [], t0: 0, raf: 0, frozenAt: 0, ms: 0, hits: 0, unfrozen: false, busy: null };
      root.classList.remove("is-frozen", "is-revealed", "is-uploading");
      document.documentElement.classList.remove("world-frozen");
      files.forEach(function (li) {
        li.classList.remove("is-taken", "is-reading", "is-hit", "is-open");
        var b = $(".f-btn", li); $(".f-act", li).textContent = "take"; b.removeAttribute("aria-expanded");
        b.setAttribute("aria-label", "Take " + $(".f-name", li).textContent);
      });
      frost.clear(); stamp.hidden = true; modal.hidden = true; modal.innerHTML = ""; modal.className = "heist-modal";
      clockEl.textContent = "t+0.000s";
      upBtn.disabled = true;
      lootTxt.innerHTML = "Nothing taken yet.";
      var t = $(".heist-toast", root); if (t) t.remove();
      modal.style.top = modal.style.bottom = stamp.style.top = "";
    }

    // Put an overlay (stamp, alert) next to the row that was hit, inside the
    // window, and make sure the visitor can see it.
    function placeNear(node, li, mode) {
      var wh = win.clientHeight, top = li.offsetTop + $(".f-btn", li).offsetTop, rh = li.offsetHeight, nh = node.offsetHeight;
      var y;
      if (mode === "center") y = Math.max(nh / 2 + 50, Math.min(wh - nh / 2 - 20, top + rh / 2));
      else { y = top + rh + 10; if (y + nh > wh - 12) y = top - nh - 10; y = Math.max(12, Math.min(wh - nh - 12, y)); }
      node.style.top = Math.round(y) + "px"; if (mode !== "center") node.style.bottom = "auto";
      if (mode !== "center") {
        var r = node.getBoundingClientRect(), vh = window.innerHeight;
        if (r.top < 70 || r.bottom > vh - 10) window.scrollBy({ top: r.top < 70 ? r.top - 80 : r.bottom - vh + 24, behavior: calm() ? "auto" : "smooth" });
      }
    }

    function clockRun() {
      if (!S.t0) S.t0 = performance.now();
      cancelAnimationFrame(S.raf);
      (function tick() {
        clockEl.textContent = "t+" + ((performance.now() - S.t0) / 1000).toFixed(3) + "s";
        S.raf = requestAnimationFrame(tick);
      })();
    }
    function clockStop() { cancelAnimationFrame(S.raf); }

    function sizeOf(li) { return li.getAttribute("data-size"); }
    function lootLine() {
      var n = S.loot.length;
      if (!n) return "Nothing taken yet.";
      var kb = S.loot.reduce(function (a, li) { var s = sizeOf(li); var v = parseFloat(s); return a + (/MB/.test(s) ? v * 1024 : v); }, 0);
      var size = kb >= 1024 ? (kb / 1024).toFixed(1) + " MB" : Math.round(kb) + " KB";
      return "Loot: <b>" + n + " file" + (n > 1 ? "s" : "") + "</b> · " + size + " · not sent yet";
    }

    function toast(msg, ms, li) {
      var old = $(".heist-toast", root); if (old) old.remove();
      var t = el("div", "heist-toast", msg); win.appendChild(t);
      if (li) t.style.top = Math.min(win.clientHeight - t.offsetHeight - 12, li.offsetTop + li.offsetHeight + 6) + "px";
      setTimeout(function () { if (t.parentNode) t.remove(); }, ms || 3200);
    }

    function readTime(li) { var s = sizeOf(li); return /MB/.test(s) ? 520 : 260; }

    function take(li) {
      if (S.busy || S.state === "frozen" || S.state === "over" || S.state === "uploading") return;
      if (li.classList.contains("is-taken")) return;
      if (S.state === "idle") { S.state = "playing"; clockRun(); }
      var bait = li.getAttribute("data-kind") === "bait";
      li.classList.add("is-reading");
      S.busy = li;
      var my = round;
      if (bait) {
        // A bait open. Windows pauses the opener inside the open; ABA freezes it.
        li.style.setProperty("--read", (readTime(li) / 1000) + "s");
        var ms = rand(72, 151);
        S.openAt = performance.now();
        setTimeout(function () { if (my === round) freeze(li, ms); }, calm() ? 0 : ms);
        return;
      }
      li.style.setProperty("--read", (readTime(li) / 1000) + "s");
      setTimeout(function () {
        if (my !== round) return;
        li.classList.remove("is-reading"); li.classList.add("is-taken");
        $(".f-act", li).textContent = "✓ taken";
        $(".f-btn", li).setAttribute("aria-label", $(".f-name", li).textContent + ", taken");
        S.loot.push(li); S.busy = null;
        lootTxt.innerHTML = lootLine();
        upBtn.disabled = false;
        if (li.getAttribute("data-hint") === "profiles") toast('Local State lists Chrome\'s profiles: <b>"Default"</b>. Nothing else.', 4200, li);
      }, calm() ? 0 : readTime(li));
    }

    function freeze(li, ms) { // severity: unsigned program in Downloads = critical; Balanced: freeze + cut its internet
      var old = $(".heist-toast", root); if (old) old.remove();
      S.state = "frozen"; S.busy = null; S.ms = ms; S.hits++;
      S.hitWhat = li.getAttribute("data-what");
      S.hitName = $(".f-name", li).textContent;
      clockStop();
      li.classList.add("is-hit");
      root.classList.add("is-frozen");
      document.documentElement.classList.add("world-frozen");
      frost.grow();
      stampMs.innerHTML = "<b>" + ms + " ms</b> after it opened the bait";
      stamp.hidden = false;
      placeNear(stamp, li, "center");
      S.hitLi = li;
      upBtn.disabled = true;
      lootTxt.innerHTML = S.loot.length ? "<b>Frozen</b> holding " + S.loot.length + " file" + (S.loot.length > 1 ? "s" : "") + ". <b>0 sent</b>: its internet is cut." : "<b>Frozen</b> before it took anything.";
      if (navigator.vibrate && !calm() && !attract.on && (!navigator.userActivation || navigator.userActivation.hasBeenActive)) try { navigator.vibrate(40); } catch (e) {}
      announce.textContent = "Frozen " + ms + " milliseconds after opening a bait, the " + S.hitWhat + ". ABA's alert is open.";
      if (attract.on) return;
      var my = round;
      setTimeout(function () { if (my === round && S.state === "frozen") alertBox(); }, calm() ? 200 : 1100);
    }

    function alertBox() {
      stamp.hidden = true;
      modal.className = "heist-modal";
      modal.setAttribute("role", "alertdialog");
      modal.setAttribute("aria-labelledby", "m-title");
      modal.innerHTML =
        '<p class="m-title" id="m-title"><span class="m-x" aria-hidden="true">✕</span>ABA: game_setup.exe opened a bait</p>' +
        "<p>Caught the moment it opened the bait (instant freeze). game_setup.exe is an unsigned program running from a user-writable folder: typical of stealers.</p>" +
        '<dl class="m-rows">' +
        "<dt>Program</dt><dd>C:\\Users\\sam\\Downloads\\game_setup.exe</dd>" +
        "<dt>Signature</dt><dd>not signed</dd>" +
        "<dt>It read</dt><dd>" + esc(S.hitWhat) + " (" + esc(S.hitName) + ")</dd>" +
        '<dt>ABA did</dt><dd class="m-did">✓ Froze it (' + S.ms + " ms) · ✓ Cut off its internet</dd>" +
        "</dl>" +
        '<p class="m-q">Kill it? Games, mods, cheats and cracks never need to read this.</p>' +
        '<div class="m-btns"><button type="button" class="btn btn-solid btn-sm" data-a="kill">Kill it</button>' +
        '<button type="button" class="btn btn-line btn-sm" data-a="once">Unfreeze, just this once</button>' +
        '<button type="button" class="btn btn-line btn-sm" data-a="later">Decide later</button></div>';
      modal.hidden = false;
      placeNear(modal, S.hitLi);
      $$("[data-a]", modal).forEach(function (b) { b.addEventListener("click", function () { answer(b.getAttribute("data-a")); }); });
      $("[data-a]", modal).focus({ preventScroll: true });
    }

    function answer(a) {
      if (a === "once") {
        // Unsigned: one click can't trust it for good, only unfreeze it once.
        modal.hidden = true; modal.innerHTML = "";
        root.classList.remove("is-frozen");
        document.documentElement.classList.remove("world-frozen");
        frost.clear();
        S.state = "playing"; S.unfrozen = true;
        S.t0 = performance.now() - (parseFloat(clockEl.textContent.slice(2)) * 1000);
        clockRun();
        upBtn.disabled = !S.loot.length;
        lootTxt.innerHTML = lootLine();
        toast("Unfrozen, this once. It isn't signed, so ABA won't trust it for good.", 4200, S.hitLi);
        announce.textContent = "Unfrozen this once. You can keep going.";
        var f = $(".file.is-hit .f-btn", root); if (f) f.focus({ preventScroll: true });
        return;
      }
      over(a === "kill" ? "killed" : "pending");
    }

    function over(how) {
      S.state = "over";
      stamp.hidden = true;
      root.classList.remove("is-frozen");
      document.documentElement.classList.remove("world-frozen");
      frost.clear();
      root.classList.add("is-revealed");
      files.forEach(function (li) {
        var b = $(".f-btn", li);
        b.setAttribute("aria-label", $(".f-name", li).textContent + ": " + (li.getAttribute("data-kind") === "bait" ? "bait" : "real") + ". Show why");
        b.setAttribute("aria-expanded", li.classList.contains("is-hit"));
        if (li.classList.contains("is-hit")) li.classList.add("is-open");
      });
      files.forEach(function (li) { $(".f-btn", li).disabled = false; });
      var baits = files.filter(function (li) { return li.getAttribute("data-kind") === "bait"; }).length;
      var took = S.loot.length;
      var head, body, cls = "heist-modal is-good";
      if (how === "killed") {
        head = 'frozen <span aria-hidden="true">→</span> <span class="red">killed.</span>';
        body = (took ? "It had collected " + took + " file" + (took > 1 ? "s" : "") + " and sent none of them" : "It took nothing and sent nothing") + ". What it opened was a fake " + esc(S.hitWhat) + ".";
      } else if (how === "pending") {
        head = "Still frozen.";
        body = "It stays frozen, internet cut, until someone decides (<code>aba alerts</code>). It sent nothing.";
      } else {
        cls = "heist-modal is-escape";
        var chromeOnly = S.loot.some(function (li) { return li.getAttribute("data-hint") === "profiles"; });
        head = "You got away.";
        body = "That's ABA's real limit, and the README says so: a stealer that only takes real data and never touches a bait doesn't trip it." +
          (chromeOnly ? " Reading Chrome's own list of profiles, like you did, is exactly how one could skip Profile 23." : "") +
          " Most stealers grab everything they know at once, which is what ABA counts on. And it's why you keep Windows Defender on.";
      }
      modal.className = cls;
      modal.setAttribute("role", "dialog");
      modal.setAttribute("aria-labelledby", "m-big");
      modal.innerHTML =
        '<p class="m-big" id="m-big">' + head + "</p><p>" + body + "</p>" +
        '<p class="m-stats"><span><b>' + baits + "</b> of " + files.length + " things on Sam's PC were baits</span>" + (S.ms ? "<span>frozen in <b>" + S.ms + " ms</b></span>" : "") + "</p>" +
        '<div class="m-btns"><button type="button" class="btn btn-solid btn-sm" data-a="again">Play again</button>' +
        (S.ms ? '<button type="button" class="btn btn-line btn-sm" data-a="share">Share</button>' : "") +
        '<button type="button" class="btn btn-line btn-sm" data-a="see">See the baits</button></div>' +
        '<p class="m-note">A simulation. Tap any file to see why it\'s there, or <a href="#proof">watch a real stealer get frozen</a>.</p>';
      modal.hidden = false;
      if (S.hitLi) placeNear(modal, S.hitLi); else { modal.style.top = modal.style.bottom = ""; }
      $('[data-a="again"]', modal).addEventListener("click", function () { reset(); var f = $(".f-btn", root); if (f) f.focus({ preventScroll: true }); });
      $('[data-a="see"]', modal).addEventListener("click", function () { modal.hidden = true; frost.clear(); root.classList.remove("is-frozen"); document.documentElement.classList.remove("world-frozen"); var f = $(".f-btn", root); if (f) f.focus({ preventScroll: true }); showAgain(); });
      var sh = $('[data-a="share"]', modal);
      if (sh) sh.addEventListener("click", function () {
        var text = "I played the stealer against A Better Antivirus and got frozen " + S.ms + " ms after I opened a fake " + S.hitWhat + ".";
        var url = location.href.split("#")[0];
        if (navigator.share) navigator.share({ title: "A Better Antivirus", text: text, url: url }).catch(function () {});
        else copyText(text + " " + url).then(function () { sh.textContent = "Copied"; }, function () {});
      });
      $("[data-a]", modal).focus({ preventScroll: true });
      announce.textContent = modal.textContent.slice(0, 200);
    }
    function showAgain() {
      lootTxt.innerHTML = "Every bait is marked. Each says why it's there.";
      upBtn.hidden = true;
      var again = el("button", "btn btn-solid btn-sm loot-up", "Play again"); again.type = "button";
      again.addEventListener("click", function () { again.remove(); upBtn.hidden = false; reset(); });
      lootBox.appendChild(again);
    }

    upBtn.addEventListener("click", function () {
      if (S.state !== "playing" || !S.loot.length || S.busy) return;
      S.state = "uploading";
      root.classList.add("is-uploading");
      lootTxt.innerHTML = "Uploading " + S.loot.length + " file" + (S.loot.length > 1 ? "s" : "") + "…";
      var my = round;
      setTimeout(function () {
        if (my !== round) return;
        clockStop(); root.classList.remove("is-uploading");
        lootTxt.innerHTML = "<b>Sent.</b> " + S.loot.length + " file" + (S.loot.length > 1 ? "s" : "") + " left the PC.";
        over("escaped");
      }, calm() ? 0 : 1350);
    });

    function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }

    /* Attract mode: once, before the visitor touches anything, a ghost
       stealer takes two files, opens a bait and gets frozen. */
    var attract = { on: false, cancelled: false };
    var ghost = el("div", "ghost", '<svg viewBox="0 0 22 22" aria-hidden="true"><path d="M3 2 L3 18 L7.5 14 L10.5 20.5 L13.2 19.3 L10.3 12.9 L16.5 12.9 Z"/></svg>');
    win.appendChild(ghost);
    function moveGhost(li) {
      var w = win.getBoundingClientRect(), r = li.getBoundingClientRect();
      ghost.style.transform = "translate(" + Math.round(r.left - w.left + Math.min(r.width * .45, 170)) + "px," + Math.round(r.top - w.top + r.height * .55) + "px)";
    }
    function stopAttract() {
      if (!attract.on) { attract.cancelled = true; return; }
      attract.cancelled = true; attract.on = false;
      ghost.classList.remove("is-on");
      reset();
    }
    async function runAttract() {
      if (attract.cancelled || calm()) return;
      attract.on = true;
      var pick = function (name) { return files.filter(function (li) { return $(".f-name", li).textContent === name; })[0]; };
      var plan = [pick("invoice_march.pdf"), pick("Default"), pick("discord\\Local Storage\\leveldb")];
      ghost.style.transition = "none";
      var w = win.getBoundingClientRect();
      ghost.style.transform = "translate(" + Math.round(w.width * .8) + "px," + Math.round(w.height * .9) + "px)";
      ghost.getBoundingClientRect();
      ghost.style.transition = "";
      ghost.classList.add("is-on");
      for (var i = 0; i < plan.length; i++) {
        if (attract.cancelled) return;
        moveGhost(plan[i]);
        await wait(650);
        if (attract.cancelled) return;
        take(plan[i]);
        await wait(i < 2 ? 700 : 300);
      }
      await wait(2600);
      if (attract.cancelled) return;
      ghost.classList.remove("is-on");
      attract.on = false;
      reset();
      $(".heist-h", root).textContent = "Your turn.";
    }
    ["pointerdown", "keydown", "focusin"].forEach(function (ev) {
      root.addEventListener(ev, function (e) { if (attract.on || !attract.cancelled) { if (attract.on) { e.preventDefault(); } stopAttract(); } }, true);
    });

    reset();
    if ("IntersectionObserver" in window) {
      var io = new IntersectionObserver(function (es) {
        if (es[0].isIntersecting) { io.disconnect(); setTimeout(runAttract, 900); }
      }, { threshold: .55 });
      io.observe(win);
    }
  })();

  /* ───────── 158 ms, felt ───────── */
  (function react() {
    var box = $("[data-react]"); if (!box) return;
    var pad = $("[data-react-pad]", box), big = $("[data-react-big]", box), small = $("[data-react-small]", box);
    var score = $("[data-react-score]", box), you = $("[data-react-you]", box);
    pad.hidden = false;
    var st = "idle", timer = 0, t0 = 0, best = 0;
    var live = el("p", "sr-only"); live.setAttribute("aria-live", "assertive"); box.appendChild(live);
    function set(cls, b, s) { pad.className = "react-pad " + cls; big.textContent = b; small.textContent = s; live.textContent = b + ". " + s; }
    function hit() {
      if (st === "idle" || st === "done" || st === "early") {
        st = "wait"; set("is-wait", "Wait for red…", "Don't click yet");
        timer = setTimeout(function () { st = "go"; t0 = performance.now(); set("is-go", "NOW", "Click!"); }, rand(1300, 3400));
      } else if (st === "wait") {
        clearTimeout(timer); st = "early"; set("", "Too soon.", "Click to try again");
      } else if (st === "go") {
        var ms = Math.round(performance.now() - t0);
        st = "done";
        best = best ? Math.min(best, ms) : ms;
        score.hidden = false;
        you.textContent = best + " ms";
        var msg = ms > 158 ? (ms - 158) + " ms slower than ABA in the video" : "Faster than the video's 158 ms. Nice.";
        set("is-done", ms + " ms", msg + " · again?");
      }
    }
    pad.addEventListener("pointerdown", function (e) { if (e.button === 0) { e.preventDefault(); hit(); } });
    pad.addEventListener("keydown", function (e) { if ((e.key === " " || e.key === "Enter") && !e.repeat) { e.preventDefault(); hit(); } });
    pad.addEventListener("click", function (e) { if (e.detail === 0) hit(); });
  })();

  /* ───────── The instant freeze, slowed down ───────── */
  (function oplock() {
    var box = $("[data-oplock]"); if (!box) return;
    var ctl = $("[data-op-ctl]", box), btn = $("[data-op-play]", box), clock = $("[data-op-clock]", box);
    ctl.hidden = false;
    var running = false;
    async function play() {
      if (running) return; running = true; btn.disabled = true;
      for (var s = 1; s <= 5; s++) {
        box.setAttribute("data-step", s);
        clock.textContent = "step " + s + " of 5 · slowed down";
        await wait(s === 2 ? 2000 : 1700);
      }
      clock.textContent = "real time: about 0.1 s";
      running = false; btn.disabled = false; btn.textContent = "Replay";
    }
    btn.addEventListener("click", play);
    if (calm()) { btn.textContent = "Step through"; return; } // final state shows; the button still steps
    box.setAttribute("data-step", "1");
    if ("IntersectionObserver" in window) {
      var io = new IntersectionObserver(function (es) { if (es[0].isIntersecting) { io.disconnect(); play(); } }, { threshold: .5 });
      io.observe(box);
    }
  })();

  /* ───────── aba test, in the browser ───────── */
  (function term() {
    var box = $("[data-term]"); if (!box) return;
    var out = $("[data-term-out]", box), form = $("[data-term-form]", box), input = $("input", form), help = $("[data-term-help]", box), body = $("[data-term-body]", box);
    var original = out.innerHTML;
    form.hidden = false; help.hidden = false;
    out.innerHTML = "";
    var busy = false;
    function print(html) { out.insertAdjacentHTML("beforeend", html); body.scrollTop = body.scrollHeight; }
    var P = '<span class="t-prompt">PS C:\\Users\\you&gt;</span> ';
    var test = original.split("\n").slice(1); // the README's output, minus the command line
    async function run(cmd) {
      cmd = cmd.trim();
      if (busy) return;
      busy = true; input.disabled = true;
      print((out.innerHTML ? "\n" : "") + P + esc(cmd) + "\n");
      var c = cmd.toLowerCase().replace(/\s+/g, " ");
      if (c === "aba test") {
        for (var i = 0; i < test.length; i++) {
          print(test[i] + "\n");
          if (/✓/.test(test[i])) await wait(calm() ? 0 : (i === test.length - 4 ? 900 : 420));
          else await wait(calm() ? 0 : 60);
        }
      } else if (c === "clear" || c === "cls") {
        out.innerHTML = "";
      } else if (c === "aba help" || c === "help" || c === "aba --help") {
        print([
          ' <span class="t-k">aba</span>              live dashboard',
          ' <span class="t-k">aba test</span>         simulate a stealer safely and watch it get caught',
          ' <span class="t-k">aba alerts</span>       what touched your baits',
          ' <span class="t-k">aba doctor</span>       check everything is armed (--fix to repair)',
          ' <span class="t-k">aba trust</span> &lt;id&gt;   it\'s yours: undo everything and stop alerting about it',
          ' <span class="t-k">aba kill</span> &lt;id&gt;    it\'s malware: end what the alert froze',
          ' <span class="t-k">aba release</span>      undo all responses',
          ' <span class="t-k">aba uninstall</span>    remove ABA and everything it changed',
          '',
          '<span class="t-dim"> (Only aba test runs in this demonstration.)</span>'
        ].join("\n") + "\n");
      } else if (/\b(irm|iex|invoke-expression|iwr)\b/.test(c)) {
        print('<span class="t-red"> Nice try.</span> Only paste irm … | iex from sources you trust: it\'s how many stealers get installed.\n');
      } else if (c === "aba" || c.indexOf("aba ") === 0) {
        print('<span class="t-dim"> This demonstration only runs aba test. On your PC, aba ' + (c === "aba" ? "opens a live dashboard" : "can do more: see aba help") + '.</span>\n');
      } else if (c) {
        print('<span class="t-dim"> This is a demonstration in your browser, not a shell. Try aba test.</span>\n');
      }
      busy = false; input.disabled = false;
    }
    function esc(s) { return s.replace(/[&<>]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]; }); }
    form.addEventListener("submit", function (e) { e.preventDefault(); var v = input.value; input.value = ""; run(v).then(function () { input.focus({ preventScroll: true }); }); });
    $$("[data-cmd]", box).forEach(function (b) { b.addEventListener("click", function () { run(b.getAttribute("data-cmd")); }); });
    if ("IntersectionObserver" in window) {
      var io = new IntersectionObserver(function (es) { if (es[0].isIntersecting) { io.disconnect(); run("aba test"); } }, { threshold: .6 });
      io.observe(box);
    } else run("aba test");
  })();
})();
