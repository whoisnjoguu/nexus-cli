"use strict";
// nexus-cli approvals UI. All request fields are agent-controlled: they are only ever rendered via
// textContent, never as HTML.
(function () {
  var CSRF_KEY = "nexus_csrf";
  var csrf = sessionStorage.getItem(CSRF_KEY) || "";
  var state = null;
  var skew = 0; // server clock − local clock (ms)
  var es = null;
  var polling = false;
  var stopped = false;
  var refreshing = null;
  var refreshAgain = false;

  function $(id) {
    return document.getElementById(id);
  }

  function setConn(text, cls) {
    var el = $("conn");
    el.textContent = text;
    el.className = "pill " + (cls || "");
  }

  function fatal(msg) {
    stopped = true;
    if (es) es.close();
    var b = $("banner");
    b.textContent = msg;
    b.hidden = false;
    setConn("signed out", "down");
    $("logout").hidden = true;
  }

  function api(path, opts) {
    opts = opts || {};
    opts.credentials = "same-origin";
    opts.cache = "no-store";
    opts.headers = Object.assign({ "X-Nexus-CSRF": csrf }, opts.headers || {});
    return fetch(path, opts).then(function (r) {
      if (r.status === 401 || r.status === 403) {
        sessionStorage.removeItem(CSRF_KEY);
        fatal("Your session has expired. Run `nexus-cli approve --web` again to sign in.");
        throw new Error("unauthorized");
      }
      return r;
    });
  }

  function login() {
    var m = /(?:^#|&)login=([A-Za-z0-9]+)/.exec(location.hash);
    history.replaceState(null, "", location.pathname);
    if (!m) return Promise.resolve(!!csrf);
    return fetch("/v1/ui/session", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: m[1] }),
    }).then(function (r) {
      if (!r.ok) return !!csrf;
      return r.json().then(function (j) {
        csrf = j.csrf;
        sessionStorage.setItem(CSRF_KEY, csrf);
        return true;
      });
    });
  }

  function fmtDur(ms) {
    var s = Math.max(0, Math.round(ms / 1000));
    if (s < 60) return s + "s";
    var m = Math.floor(s / 60);
    if (m < 60) return m + "m " + (s % 60) + "s";
    return Math.floor(m / 60) + "h " + (m % 60) + "m";
  }

  function text(el, sel, value) {
    var t = el.querySelector(sel);
    t.textContent = value || "—";
    t.title = value || "";
    return t;
  }

  function render() {
    if (!state) return;
    var ep = state.endpoint || {};
    var where = (ep.kind || "?") + " · pid " + ep.pid;
    if (ep.listen) where += " · " + ep.listen;
    if (ep.cwd) where += " · " + ep.cwd;
    $("endpoint").textContent = where;

    var list = $("pending");
    var tpl = $("card-tpl");
    var keep = {};
    (state.pending || []).forEach(function (req) {
      keep[req.id] = true;
      var card = list.querySelector('[data-id="' + CSS.escape(req.id) + '"]');
      if (card) return;
      card = tpl.content.firstElementChild.cloneNode(true);
      card.dataset.id = req.id;
      card.dataset.created = req.created;
      text(card, ".tool", req.tool);
      text(card, ".target", req.target);
      text(card, ".agent", req.agent_id);
      text(card, ".actas", req.act_as);
      text(card, ".reason", req.reason);
      if (req.params) {
        text(card, ".params", req.params);
      } else {
        card.querySelector(".params").remove();
        card.querySelector(".params-dt").remove();
      }
      card.querySelectorAll("button[data-decision]").forEach(function (b) {
        b.addEventListener("click", function () {
          decide(card, req, b.dataset.decision);
        });
      });
      list.appendChild(card);
    });
    Array.prototype.slice.call(list.children).forEach(function (c) {
      if (!keep[c.dataset.id]) c.remove();
    });
    var n = (state.pending || []).length;
    $("pending-count").textContent = String(n);
    $("pending-empty").style.display = n ? "none" : "";
    document.title = (n ? "(" + n + ") " : "") + "nexus-cli approvals";

    var body = $("recent");
    body.textContent = "";
    (state.recent || []).forEach(function (ev) {
      var tr = document.createElement("tr");
      var outcome = ev.type === "decided" ? ev.decision : ev.type;
      var by = ev.by || (ev.type === "cancelled" ? "elsewhere / caller gone" : "—");
      [
        new Date(ev.at).toLocaleTimeString(),
        outcome,
        by,
        ev.request.agent_id,
        ev.request.tool,
        ev.request.target,
      ].forEach(function (v, i) {
        var td = document.createElement("td");
        td.textContent = v || "—";
        td.title = v || "";
        if (i === 1) td.className = ev.type === "decided" && ev.decision !== "deny" ? "ok" : "no";
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    $("recent-empty").style.display = (state.recent || []).length ? "none" : "";
    tick();
  }

  function tick() {
    if (!state) return;
    var now = Date.now() + skew;
    var timeout = state.timeout_ms;
    $("pending")
      .querySelectorAll(".card")
      .forEach(function (card) {
        var created = Date.parse(card.dataset.created);
        var age = now - created;
        var left = timeout - age;
        card.querySelector(".age").textContent = "waiting " + fmtDur(age);
        var cd = card.querySelector(".countdown");
        cd.textContent = left > 0 ? "auto-deny in " + fmtDur(left) : "timing out…";
        cd.className = "countdown" + (left < 10000 ? " soon" : "");
        card.querySelector(".fill").style.width = Math.max(0, Math.min(100, (left / timeout) * 100)) + "%";
      });
  }

  function decide(card, req, decision) {
    if (card.classList.contains("busy")) return;
    if (
      decision === "always" &&
      !confirm("Always allow this and save a rule to the policy file?\n\n" + req.tool + " " + req.target)
    )
      return;
    card.classList.add("busy");
    card.querySelectorAll("button").forEach(function (b) {
      b.disabled = true;
    });
    api("/v1/approvals/" + encodeURIComponent(req.id), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ decision: decision }),
    })
      .then(function (r) {
        if (r.status === 404) {
          var b = $("banner");
          b.textContent = "That request was already decided, timed out, or was cancelled.";
          b.hidden = false;
          setTimeout(function () {
            b.hidden = true;
          }, 4000);
        }
        refresh();
      })
      .catch(function () {
        card.classList.remove("busy");
        card.querySelectorAll("button").forEach(function (b) {
          b.disabled = false;
        });
      });
  }

  function fetchState(qs) {
    return api("/v1/ui/state" + (qs || ""))
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (s) {
        state = s;
        skew = Date.parse(s.now) - Date.now();
        render();
      });
  }

  // refresh coalesces overlapping refreshes into at most one in flight plus one queued.
  function refresh() {
    if (stopped) return Promise.resolve();
    if (refreshing) {
      refreshAgain = true;
      return refreshing;
    }
    refreshing = fetchState().finally(function () {
      refreshing = null;
      if (refreshAgain) {
        refreshAgain = false;
        refresh();
      }
    });
    return refreshing;
  }

  function connect() {
    if (stopped) return;
    if (!window.EventSource) return poll();
    es = new EventSource("/v1/events?csrf=" + encodeURIComponent(csrf));
    ["hello", "added", "decided", "expired", "cancelled"].forEach(function (t) {
      es.addEventListener(t, function () {
        setConn("live", "live");
        refresh();
      });
    });
    es.onerror = function () {
      if (stopped) return;
      if (es.readyState === EventSource.CLOSED) {
        // Probe the session (shows the sign-in message on 401) and fall back to long-polling.
        refresh()
          .then(poll)
          .catch(function () {});
      } else {
        setConn("reconnecting…", "down");
      }
    };
  }

  function poll() {
    if (polling || stopped) return;
    polling = true;
    setConn("polling", "poll");
    (function loop() {
      if (stopped) return;
      var since = state ? "&since=" + state.version : "";
      fetchState("?wait=25s" + since)
        .then(function () {
          setConn("polling", "poll");
          loop();
        })
        .catch(function () {
          if (stopped) return;
          setConn("offline", "down");
          setTimeout(loop, 2000);
        });
    })();
  }

  $("logout").addEventListener("click", function () {
    api("/v1/ui/logout", { method: "POST" })
      .catch(function () {})
      .finally(function () {
        sessionStorage.removeItem(CSRF_KEY);
        fatal("Signed out. Run `nexus-cli approve --web` to sign in again.");
      });
  });

  login().then(function (ok) {
    if (!ok) {
      fatal("Not signed in. Run `nexus-cli approve --web` to open this page with a one-time login link.");
      return;
    }
    $("logout").hidden = false;
    refresh()
      .then(connect)
      .catch(function () {});
    setInterval(tick, 1000);
  });
})();
