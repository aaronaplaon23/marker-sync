"use strict";

(() => {
  const CFG = window.MARKER_SYNC_CONFIG || {};
  const APP_KEY = String(CFG.dropboxAppKey || "").trim();
  const API = CFG.apiBase || "https://api.dropboxapi.com";
  const CONTENT = CFG.contentBase || "https://content.dropboxapi.com";
  const AUTHORIZE = CFG.authorizeUrl || "https://www.dropbox.com/oauth2/authorize";
  const ZOOMS = [10, 30, 120, 600];
  const SPEEDS = [1, 1.5, 2];

  /* ---------- helpers ---------- */

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));
  const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function button(cls, text, onClick) {
    const b = el("button", cls, text);
    b.type = "button";
    if (onClick) b.addEventListener("click", onClick);
    return b;
  }

  function fmtTime(sec, tenths) {
    sec = Math.max(0, Number(sec) || 0);
    if (tenths) sec = Math.floor(sec * 10 + 1e-6) / 10;
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    const ss = tenths ? s.toFixed(1).padStart(4, "0") : String(Math.floor(s)).padStart(2, "0");
    return h ? `${h}:${String(m).padStart(2, "0")}:${ss}` : `${m}:${ss}`;
  }

  const stripExt = (name) => String(name || "").replace(/\.[^.]+$/, "");
  const parseJson = (text) => { try { return JSON.parse(text); } catch { return null; } };

  const store = {
    get(k, d = null) {
      try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch { return d; }
    },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage full or blocked */ } },
    del(k) { try { localStorage.removeItem(k); } catch { /* ignore */ } },
  };

  /* ---------- errors ---------- */

  class AuthError extends Error {}
  class NetError extends Error {}
  class ApiError extends Error {
    constructor(status, summary) {
      super(summary || `Dropbox error ${status}`);
      this.status = status;
      this.summary = summary || "";
    }
  }
  const notFound = (e) => e instanceof ApiError && e.status === 409 && /not_found/.test(e.summary);

  function errText(e) {
    if (e instanceof NetError) return "Can't reach Dropbox. Check your connection and try again.";
    if (e instanceof AuthError) return "Dropbox needs you to connect again.";
    return (e && e.message) || String(e);
  }

  /* ---------- Dropbox sign-in (PKCE, paste-the-code) ----------
     No redirect: Dropbox shows a code that gets pasted back here. That works the
     same in Safari and in the home-screen app, which keeps its own storage. */

  function b64url(bytes) {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function tokenRequest(body) {
    let r;
    try {
      r = await fetch(`${API}/oauth2/token`, { method: "POST", body });
    } catch (e) {
      throw new NetError(e.message);
    }
    let j = {};
    try { j = await r.json(); } catch { /* not JSON */ }
    if (!r.ok) {
      const msg = j.error_description || j.error || `Dropbox said ${r.status}`;
      if (j.error === "invalid_grant") {
        if (body.get("grant_type") === "refresh_token") store.del("ms.auth");
        throw new AuthError(msg);
      }
      throw new ApiError(r.status, msg);
    }
    return j;
  }

  const auth = {
    refreshing: null,
    data() { return store.get("ms.auth"); },
    signedIn() { const a = this.data(); return !!(a && a.refresh); },

    async authorizeUrl() {
      let verifier = store.get("ms.pkce");
      if (!verifier) {
        verifier = b64url(crypto.getRandomValues(new Uint8Array(48)));
        store.set("ms.pkce", verifier);
      }
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
      const q = new URLSearchParams({
        client_id: APP_KEY,
        response_type: "code",
        code_challenge: b64url(new Uint8Array(digest)),
        code_challenge_method: "S256",
        token_access_type: "offline",
      });
      return `${AUTHORIZE}?${q}`;
    },

    async finish(code) {
      const verifier = store.get("ms.pkce");
      if (!verifier) throw new Error("Tap Connect Dropbox first, then paste the code.");
      const j = await tokenRequest(new URLSearchParams({
        code: code.trim(), grant_type: "authorization_code", code_verifier: verifier, client_id: APP_KEY,
      }));
      store.set("ms.auth", { refresh: j.refresh_token, access: j.access_token, exp: Date.now() + (j.expires_in - 120) * 1000 });
      store.del("ms.pkce");
    },

    async token(force) {
      const a = this.data();
      if (!a || !a.refresh) throw new AuthError("Not connected");
      if (!force && a.access && Date.now() < a.exp) return a.access;
      if (!this.refreshing) {
        this.refreshing = (async () => {
          try {
            const j = await tokenRequest(new URLSearchParams({
              grant_type: "refresh_token", refresh_token: a.refresh, client_id: APP_KEY,
            }));
            const cur = this.data() || a;
            cur.access = j.access_token;
            cur.exp = Date.now() + (j.expires_in - 120) * 1000;
            store.set("ms.auth", cur);
            return cur.access;
          } finally {
            this.refreshing = null;
          }
        })();
      }
      return this.refreshing;
    },
  };

  /* ---------- Dropbox API ---------- */

  // Dropbox-API-Arg must be ASCII; anything else goes in as \uXXXX.
  const headerJson = (obj) =>
    JSON.stringify(obj).replace(/[\u007f-￿]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));

  async function call(url, init, retried) {
    const token = await auth.token();
    let r;
    try {
      r = await fetch(url, { ...init, headers: { ...(init.headers || {}), Authorization: `Bearer ${token}` } });
    } catch (e) {
      throw new NetError(e.message);
    }
    if (r.status === 401 && !retried) {
      await auth.token(true);
      return call(url, init, true);
    }
    if (r.status === 429 && !retried) {
      await sleep(1000 * (Number(r.headers.get("Retry-After")) || 2));
      return call(url, init, true);
    }
    if (!r.ok) {
      let summary = "";
      try {
        const t = await r.text();
        summary = (parseJson(t) || {}).error_summary || t;
      } catch { /* no body */ }
      if (r.status === 401) throw new AuthError(summary);
      throw new ApiError(r.status, String(summary).slice(0, 300));
    }
    return r;
  }

  const dbx = {
    async rpc(name, args) {
      const r = await call(`${API}/2/${name}`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(args),
      });
      return r.json();
    },
    download(path) {
      return call(`${CONTENT}/2/files/download`, { method: "POST", headers: { "Dropbox-API-Arg": headerJson({ path }) } });
    },
    async upload(path, text) {
      const r = await call(`${CONTENT}/2/files/upload`, {
        method: "POST",
        headers: {
          "Content-Type": "application/octet-stream",
          "Dropbox-API-Arg": headerJson({ path, mode: "overwrite", mute: true, autorename: false }),
        },
        body: new Blob([text]),
      });
      return r.json();
    },
    async list(path, recursive) {
      let res;
      try {
        res = await this.rpc("files/list_folder", { path, recursive: !!recursive, include_deleted: false });
      } catch (e) {
        if (notFound(e)) return [];
        throw e;
      }
      const out = res.entries.slice();
      while (res.has_more) {
        res = await this.rpc("files/list_folder/continue", { cursor: res.cursor });
        out.push(...res.entries);
      }
      return out;
    },
    async meta(path) {
      try { return await this.rpc("files/get_metadata", { path }); } catch (e) { if (notFound(e)) return null; throw e; }
    },
    async tempLink(path) {
      return (await this.rpc("files/get_temporary_link", { path })).link;
    },
    async remove(path) {
      try { await this.rpc("files/delete_v2", { path }); } catch (e) { if (!notFound(e)) throw e; }
    },
  };

  /* ---------- small-file cache, keyed by Dropbox rev ---------- */

  const cache = {
    map: store.get("ms.cache", {}) || {},
    timer: 0,
    get(entry) {
      const c = this.map[entry.path_lower];
      return c && c.rev === entry.rev ? c.text : null;
    },
    put(pathLower, rev, text) { this.map[pathLower] = { rev, text }; this.persist(); },
    drop(pathLower) { delete this.map[pathLower]; this.persist(); },
    retain(paths) {
      for (const k of Object.keys(this.map)) if (k.startsWith("/clips/") && !paths.has(k)) delete this.map[k];
      this.persist();
    },
    persist() {
      clearTimeout(this.timer);
      this.timer = setTimeout(() => store.set("ms.cache", this.map), 400);
    },
  };

  async function readText(entry) {
    const hit = cache.get(entry);
    if (hit != null) return hit;
    const r = await dbx.download(entry.path_display || entry.path_lower);
    const text = await r.text();
    cache.put(entry.path_lower, entry.rev, text);
    return text;
  }

  async function pool(items, n, fn) {
    let i = 0;
    const worker = async () => { while (i < items.length) await fn(items[i++]); };
    await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
  }

  /* ---------- outbox: every write lands here first, then goes to Dropbox ----------
     Survives reloads and dead zones. Later writes to the same file replace earlier
     queued ones, so a marker edited three times offline uploads once. */

  const outbox = {
    ops: store.get("ms.outbox", []) || [],
    inflight: null,
    timer: 0,
    backoff: 2000,
    failing: false,

    save() { store.set("ms.outbox", this.ops); renderSync(); },
    put(path, text) { this.add({ kind: "put", path, text }); },
    del(path) { this.add({ kind: "del", path }); },
    add(op) {
      op.seq = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      const key = op.path.toLowerCase();
      this.ops = this.ops.filter((o) => o.path.toLowerCase() !== key || o.seq === this.inflight);
      this.ops.push(op);
      this.save();
      this.flush();
    },
    pendingFor(prefix) {
      const p = prefix.toLowerCase();
      return this.ops.filter((o) => o.path.toLowerCase().startsWith(p));
    },
    async flush() {
      if (this.inflight || !this.ops.length || !auth.signedIn()) return;
      clearTimeout(this.timer);
      const op = this.ops[0];
      this.inflight = op.seq;
      renderSync();
      let retry = false;
      try {
        if (op.kind === "put") {
          const meta = await dbx.upload(op.path, op.text);
          cache.put(meta.path_lower, meta.rev, op.text);
        } else {
          await dbx.remove(op.path);
          cache.drop(op.path.toLowerCase());
        }
        this.ops = this.ops.filter((o) => o.seq !== op.seq);
        this.failing = false;
        this.backoff = 2000;
      } catch (e) {
        if (e instanceof AuthError) {
          this.inflight = null;
          this.save();
          needSignIn();
          return;
        }
        if (e instanceof ApiError && e.status >= 400 && e.status < 500 && e.status !== 429) {
          this.ops = this.ops.filter((o) => o.seq !== op.seq);
          toast(`A change couldn't be saved: ${e.summary || e.message}`);
        } else {
          retry = true;
          this.failing = true;
        }
      }
      this.inflight = null;
      this.save();
      if (retry) {
        this.timer = setTimeout(() => this.flush(), this.backoff);
        this.backoff = Math.min(60000, this.backoff * 2);
      } else if (this.ops.length) {
        this.flush();
      }
    },
  };

  function renderSync() {
    const n = outbox.ops.length;
    let cls = "";
    let text = "Saved";
    if (n && (outbox.failing || !navigator.onLine)) {
      cls = "offline";
      text = `${navigator.onLine ? "Retrying" : "Offline"}, ${n} waiting`;
    } else if (n || outbox.inflight) {
      cls = "saving";
      text = "Saving";
    }
    for (const id of ["#clip-sync", "#clips-sync"]) {
      const s = $(id);
      s.className = cls ? `sync ${cls}` : "sync";
      s.textContent = text;
    }
    $("#clips-sync").hidden = !n;
  }

  /* ---------- screens, toast ---------- */

  const SCREENS = ["#screen-setup", "#screen-connect", "#screen-clips", "#screen-clip"];
  let current = null;
  function show(id) {
    for (const s of SCREENS) $(s).hidden = s !== id;
    current = id;
    $("#toast").hidden = true;
  }

  let toastTimer = 0;
  function toast(msg, action) {
    const t = $("#toast");
    t.replaceChildren(el("span", null, msg));
    if (action) {
      t.append(button("btn btn-ghost btn-small", action.label, () => { t.hidden = true; action.run(); }));
    }
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, action ? 6000 : 3500);
  }

  /* ---------- connect screen ---------- */

  async function showConnect(message) {
    show("#screen-connect");
    const link = $("#connect-link");
    const err = $("#connect-error");
    link.setAttribute("aria-disabled", "true");
    err.hidden = !message;
    err.textContent = message || "";
    try {
      link.href = await auth.authorizeUrl();
      link.setAttribute("aria-disabled", "false");
    } catch {
      err.hidden = false;
      err.textContent = "This browser can't run the Dropbox sign-in. Open the page over https.";
    }
  }

  function needSignIn() {
    showConnect("Dropbox needs you to connect again. Nothing you marked is lost.");
  }

  $("#connect-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const code = $("#connect-code").value.trim();
    const err = $("#connect-error");
    if (!code) {
      err.hidden = false;
      err.textContent = "Paste the code Dropbox showed you first.";
      return;
    }
    const btn = $("#connect-finish");
    btn.setAttribute("aria-disabled", "true");
    btn.textContent = "Connecting";
    try {
      await auth.finish(code);
      $("#connect-code").value = "";
      await ensureTags().catch(() => {});
      outbox.flush();
      showClips();
    } catch (e) {
      err.hidden = false;
      err.textContent = e instanceof NetError
        ? errText(e)
        : `Dropbox didn't accept that code (${e.message}). Tap Connect Dropbox again for a fresh one.`;
    } finally {
      btn.removeAttribute("aria-disabled");
      btn.textContent = "Finish";
    }
  });

  /* ---------- tags ---------- */

  let tags = [];
  let tagsLoaded = false;

  function normalizeTags(list) {
    const out = [];
    const seen = new Set();
    for (const t of Array.isArray(list) ? list : []) {
      const name = String((t && t.name) || "").trim();
      const suffix = String((t && t.suffix) || "").trim();
      if (name && !seen.has(name.toLowerCase())) {
        seen.add(name.toLowerCase());
        out.push({ name, suffix });
      }
    }
    return out;
  }

  async function ensureTags() {
    const pending = outbox.pendingFor("/tags.json").filter((o) => o.kind === "put").pop();
    if (pending) {
      tags = normalizeTags((parseJson(pending.text) || {}).tags);
    } else {
      const meta = await dbx.meta("/tags.json");
      if (meta) {
        tags = normalizeTags((parseJson(await readText(meta)) || {}).tags);
      } else {
        // First run: writing it also makes Dropbox create the app folder on the PC.
        tags = [];
        saveTags();
      }
    }
    tagsLoaded = true;
  }

  function saveTags() {
    outbox.put("/tags.json", JSON.stringify({ version: 1, tags }, null, 2));
  }

  function validateTag(name, suffix) {
    name = String(name || "").trim().replace(/\s+/g, " ");
    suffix = String(suffix || "").trim().replace(/\s+/g, " ").toUpperCase();
    if (!name) return "Give the tag a name.";
    if (!suffix) return "Give the tag a suffix. It's what gets added to the marker in Premiere.";
    if (tags.some((t) => t.name.toLowerCase() === name.toLowerCase())) return "You already have a tag with that name.";
    return { name, suffix };
  }

  async function tagsReady(errEl) {
    if (tagsLoaded) return true;
    try {
      await ensureTags();
      return true;
    } catch (e) {
      errEl.textContent = `Couldn't load your tags yet. ${errText(e)}`;
      errEl.hidden = false;
      return false;
    }
  }

  function tagSuffixFor(name, m) {
    const t = tags.find((x) => x.name === name);
    if (t) return t.suffix;
    return m && m.tag === name ? m.tag_suffix || null : null;
  }

  function renderTagList() {
    const ul = $("#tags-list");
    ul.replaceChildren();
    if (!tags.length) {
      const li = el("li");
      li.append(el("span", "empty", "No tags yet. Add your first one above."));
      ul.append(li);
      return;
    }
    for (const t of tags) {
      const li = el("li");
      li.append(el("span", "tag-name", t.name), el("span", "suffix", t.suffix));
      li.append(button("btn btn-ghost btn-danger btn-small", "Delete", () => {
        tags = tags.filter((x) => x !== t);
        saveTags();
        renderTagList();
      }));
      ul.append(li);
    }
  }

  $("#clips-tags").addEventListener("click", async () => {
    $("#tags-error").hidden = true;
    $("#sheet-tags").hidden = false;
    renderTagList();
    if (await tagsReady($("#tags-error"))) renderTagList();
  });
  $("#tags-done").addEventListener("click", () => { $("#sheet-tags").hidden = true; });
  $("#tags-name").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); $("#tags-suffix").focus(); }
  });
  $("#tags-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = $("#tags-error");
    err.hidden = true;
    if (!(await tagsReady(err))) return;
    const r = validateTag($("#tags-name").value, $("#tags-suffix").value);
    if (typeof r === "string") {
      err.textContent = r;
      err.hidden = false;
      return;
    }
    tags.push(r);
    saveTags();
    $("#tags-name").value = "";
    $("#tags-suffix").value = "";
    renderTagList();
  });

  /* ---------- clip list ---------- */

  let clips = [];
  let clipsTimer = 0;

  function showClips() {
    show("#screen-clips");
    $("#watch-folder-label").textContent = CFG.watchFolderLabel || "the watch folder";
    renderSync();
    refreshClips();
  }

  async function refreshClips() {
    clearTimeout(clipsTimer);
    if (current !== "#screen-clips") return;
    if (!document.hidden) {
      const banner = $("#clips-banner");
      try {
        clips = await loadClips();
        banner.hidden = true;
        if (current === "#screen-clips") renderClips();
      } catch (e) {
        if (e instanceof AuthError) return needSignIn();
        banner.replaceChildren(el("div", null, errText(e)), button("btn btn-small", "Try again", refreshClips));
        banner.hidden = false;
      }
    }
    if (current === "#screen-clips") clipsTimer = setTimeout(refreshClips, 20000);
  }

  async function loadClips() {
    const entries = await dbx.list("/clips", true);
    const byKey = new Map();
    const seen = new Set();
    for (const e of entries) {
      seen.add(e.path_lower);
      const parts = e.path_display.split("/");
      if (parts.length < 3 || !parts[2]) continue;
      const key = parts[2].toLowerCase();
      let c = byKey.get(key);
      if (!c) {
        c = { id: parts[2], folder: `/clips/${parts[2]}`, files: {}, markerCount: 0 };
        byKey.set(key, c);
      }
      if (e[".tag"] !== "file") continue;
      const rel = e.path_lower.split("/").slice(3).join("/");
      if (rel.startsWith("markers/")) {
        if (rel.endsWith(".json") && !e.name.startsWith("~")) c.markerCount++;
      } else {
        c.files[rel] = e;
      }
    }
    cache.retain(seen);
    const list = [...byKey.values()];
    await pool(list, 6, async (c) => {
      try {
        if (c.files["manifest.json"]) c.manifest = parseJson(await readText(c.files["manifest.json"]));
        if (!c.manifest && c.files["status.json"]) c.status = parseJson(await readText(c.files["status.json"]));
      } catch (e) {
        if (e instanceof AuthError) throw e;
      }
    });
    for (const c of list) describeClip(c);
    return list
      .filter((c) => c.state !== "empty")
      .sort((a, b) => String(b.created || "").localeCompare(String(a.created || "")));
  }

  function describeClip(c) {
    const m = c.manifest;
    const s = c.status;
    if (m) {
      const pf = c.files["proxy.mp4"];
      const wf = c.files["waveform.bin"];
      const complete = pf && wf && pf.size === (m.proxy || {}).size && wf.size === (m.waveform || {}).size;
      const stale = m.created && Date.now() - Date.parse(m.created) > 6 * 3600e3;
      c.state = complete ? "ready" : stale ? "missing" : "uploading";
      c.name = stripExt(m.source_name) || c.id;
      c.duration = m.duration;
      c.created = m.created;
    } else if (s) {
      c.state = s.state === "failed" ? "failed" : "processing";
      c.name = stripExt(s.source_name) || c.id;
      c.duration = s.duration;
      c.progress = s.progress;
      c.error = s.error;
      c.created = s.started || s.updated;
    } else {
      c.state = c.markerCount ? "missing" : "empty";
      c.name = c.id;
    }
  }

  const CLIP_STATES = {
    ready: { cls: "state-ready", text: () => "Ready" },
    processing: {
      cls: "state-busy",
      text: (c) => (c.progress ? `Processing on PC, ${Math.round(c.progress * 100)}%` : "Processing on PC"),
      hint: "The PC is still making this clip's phone copy.",
    },
    uploading: {
      cls: "state-busy", text: () => "Uploading from PC",
      hint: "Dropbox is still uploading the phone copy from the PC.",
    },
    failed: { cls: "state-failed", text: () => "Failed on PC", hint: "The PC couldn't make a phone copy of this clip." },
    missing: {
      cls: "state-failed", text: () => "No phone copy",
      hint: "This clip's phone copy isn't in Dropbox. Its markers are still saved.",
    },
  };

  function renderClips() {
    const ul = $("#clips-list");
    ul.replaceChildren();
    $("#clips-empty").hidden = clips.length > 0;
    for (const c of clips) {
      const st = CLIP_STATES[c.state] || CLIP_STATES.missing;
      const card = button("clip-card", null, () => {
        if (c.state === "ready") openClip(c);
        else toast(st.hint);
      });
      card.append(el("span", "clip-name", c.name));
      const meta = el("span", "clip-meta");
      meta.append(el("span", `state ${st.cls}`, st.text(c)));
      if (c.duration) meta.append(el("span", null, fmtTime(c.duration)));
      if (c.markerCount) meta.append(el("span", null, `${c.markerCount} marker${c.markerCount === 1 ? "" : "s"}`));
      card.append(meta);
      if (c.state === "failed" && c.error) card.append(el("span", "clip-error", c.error));
      if (c.state !== "ready") card.classList.add("clip-card-wait");
      const li = el("li");
      li.append(card);
      ul.append(li);
    }
  }

  $("#clips-refresh").addEventListener("click", refreshClips);

  $("#sign-out").addEventListener("click", () => {
    const n = outbox.ops.length;
    if (n && !window.confirm(`${n} change(s) haven't reached Dropbox yet and will be lost. Sign out anyway?`)) return;
    outbox.ops = [];
    outbox.save();
    store.del("ms.auth");
    store.del("ms.cache");
    cache.map = {};
    tags = [];
    tagsLoaded = false;
    showConnect();
  });

  /* ---------- marking workspace ---------- */

  const video = $("#video");
  const ov = $("#wave-overview");
  const dt = $("#wave-detail");
  const octx = ov.getContext("2d");
  const dctx = dt.getContext("2d");

  const S = {
    clip: null,
    peaks: null,
    rate: 50,
    ref: 64,
    duration: 0,
    markers: [],
    markersError: null,
    zoom: 30,
    speed: 1,
    linkAt: 0,
    wantPlay: false,
    pendingSeek: null,
    dragTime: null,
    lastTime: 0,
    posSaved: 0,
    openToken: 0,
  };

  function now() {
    if (S.dragTime != null) return S.dragTime;
    if (S.pendingSeek != null) return S.pendingSeek;
    return video.currentTime || S.lastTime || 0;
  }

  function clipEnd() {
    return Number.isFinite(video.duration) && video.duration > 0 ? video.duration : S.duration;
  }

  function seek(t) {
    t = clamp(Number(t) || 0, 0, Math.max(0, clipEnd() - 0.05));
    if (video.readyState >= 1) video.currentTime = t;
    else S.pendingSeek = t;
    S.lastTime = t;
    requestDraw();
  }

  let seekAt = 0;
  let seekTimer = 0;
  let seekWant = 0;
  function seekSoon(t) {
    seekWant = t;
    const wait = 120 - (performance.now() - seekAt);
    if (wait <= 0) {
      seekAt = performance.now();
      seek(seekWant);
    } else if (!seekTimer) {
      seekTimer = setTimeout(() => {
        seekTimer = 0;
        seekAt = performance.now();
        if (S.dragTime != null) seek(seekWant);
      }, wait);
    }
  }

  function videoMsg(text) {
    const m = $("#video-msg");
    m.hidden = !text;
    m.textContent = text || "";
  }

  function setVideo(link, at, play) {
    S.linkAt = Date.now();
    S.pendingSeek = at;
    S.wantPlay = play;
    video.src = link;
    video.load();
  }

  async function refreshLink(play) {
    if (!S.clip) return;
    const clip = S.clip;
    const at = now();
    try {
      const link = await dbx.tempLink(`${clip.folder}/proxy.mp4`);
      if (S.clip === clip) setVideo(link, at, play);
    } catch (e) {
      if (S.clip === clip) videoMsg(errText(e));
    }
  }

  function savePos() {
    if (!S.clip) return;
    const all = store.get("ms.pos", {}) || {};
    all[S.clip.id] = Math.round(now() * 10) / 10;
    store.set("ms.pos", all);
  }

  async function openClip(c) {
    const token = ++S.openToken;
    S.clip = c;
    S.peaks = null;
    S.markers = [];
    S.markersError = null;
    S.dragTime = null;
    S.pendingSeek = (store.get("ms.pos", {}) || {})[c.id] || 0;
    S.lastTime = S.pendingSeek;
    S.duration = c.duration || 0;
    S.rate = ((c.manifest || {}).waveform || {}).rate || 50;
    overviewBars = null;
    nearId = null;
    show("#screen-clip");
    $("#clip-title").textContent = c.name;
    $("#t-dur").textContent = fmtTime(S.duration);
    setZoomButtons();
    renderSync();
    renderMarkers("Loading markers");
    videoMsg("Loading");
    resizeCanvases();
    requestDraw();
    ensureTags().catch(() => {});
    try {
      const [link, wave] = await Promise.all([
        dbx.tempLink(`${c.folder}/proxy.mp4`),
        dbx.download(`${c.folder}/waveform.bin`).then((r) => r.arrayBuffer()),
      ]);
      if (token !== S.openToken) return;
      S.peaks = new Uint8Array(wave);
      S.ref = peakRef(S.peaks);
      setVideo(link, S.pendingSeek, false);
      requestDraw();
    } catch (e) {
      if (token !== S.openToken) return;
      if (e instanceof AuthError) return needSignIn();
      videoMsg(`Couldn't load this clip. ${errText(e)}`);
    }
    try {
      await loadMarkers(c);
    } catch (e) {
      if (e instanceof AuthError) return needSignIn();
      S.markersError = errText(e);
    }
    if (token !== S.openToken) return;
    renderMarkers();
    requestDraw();
  }

  function closeClip() {
    savePos();
    S.openToken++;
    S.clip = null;
    video.pause();
    video.removeAttribute("src");
    video.load();
    showClips();
  }

  $("#clip-back").addEventListener("click", closeClip);

  video.addEventListener("loadedmetadata", () => {
    if (S.pendingSeek != null) {
      video.currentTime = clamp(S.pendingSeek, 0, Math.max(0, clipEnd() - 0.05));
      S.lastTime = video.currentTime;
      S.pendingSeek = null;
    }
    video.playbackRate = S.speed;
    videoMsg(null);
    if (S.wantPlay) video.play().catch(() => {});
    requestDraw();
  });

  video.addEventListener("error", () => {
    if (!S.clip || !video.getAttribute("src")) return;
    // Temporary links expire after 4 hours; anything older is probably that.
    if (Date.now() - S.linkAt > 20000) refreshLink(S.wantPlay);
    else videoMsg("The video couldn't load. Check your connection, then go back and reopen the clip.");
  });

  video.addEventListener("timeupdate", () => {
    if (S.pendingSeek == null) S.lastTime = video.currentTime;
    if (Date.now() - S.posSaved > 3000) {
      S.posSaved = Date.now();
      savePos();
    }
    requestDraw();
  });
  video.addEventListener("seeked", requestDraw);

  const playBtn = $("#play");
  video.addEventListener("play", () => {
    S.wantPlay = true;
    playBtn.textContent = "Pause";
    playBtn.setAttribute("aria-label", "Pause");
    requestDraw();
  });
  video.addEventListener("pause", () => {
    S.wantPlay = false;
    playBtn.textContent = "Play";
    playBtn.setAttribute("aria-label", "Play");
    requestDraw();
  });

  function togglePlay() {
    if (!video.getAttribute("src")) return;
    if (video.paused) video.play().catch(() => {});
    else video.pause();
  }
  playBtn.addEventListener("click", togglePlay);
  video.addEventListener("click", togglePlay);

  for (const b of $$("[data-skip]")) b.addEventListener("click", () => seek(now() + Number(b.dataset.skip)));

  $("#speed").addEventListener("click", () => {
    S.speed = SPEEDS[(SPEEDS.indexOf(S.speed) + 1) % SPEEDS.length];
    video.playbackRate = S.speed;
    $("#speed").textContent = `${S.speed}x`;
  });

  function setZoomButtons() {
    for (const b of $$("[data-zoom]")) b.setAttribute("aria-pressed", String(Number(b.dataset.zoom) === S.zoom));
  }
  for (const b of $$("[data-zoom]")) {
    b.addEventListener("click", () => {
      S.zoom = Number(b.dataset.zoom);
      store.set("ms.zoom", S.zoom);
      setZoomButtons();
      requestDraw();
    });
  }

  /* ---------- waveform ---------- */

  let overviewBars = null;
  let raf = 0;
  let dirty = true;
  let lastDrawn = -1;

  // The mic is silent most of the time with short loud spikes, so scale to the
  // 99.5th percentile and draw on a square-root curve: normal talking stays
  // visible instead of being flattened by the one scream.
  function peakRef(p) {
    const hist = new Uint32Array(256);
    for (let i = 0; i < p.length; i++) hist[p[i]]++;
    const target = p.length * 0.995;
    let acc = 0;
    for (let v = 0; v < 256; v++) {
      acc += hist[v];
      if (acc >= target) return Math.max(16, v);
    }
    return 255;
  }
  const amp = (v) => Math.sqrt(Math.min(1, v / S.ref));

  function resizeCanvases() {
    const dpr = Math.min(3, window.devicePixelRatio || 1);
    for (const cv of [ov, dt]) {
      const r = cv.getBoundingClientRect();
      const w = Math.max(1, Math.round(r.width * dpr));
      const h = Math.max(1, Math.round(r.height * dpr));
      if (cv.width !== w || cv.height !== h) {
        cv.width = w;
        cv.height = h;
        overviewBars = null;
      }
    }
    dirty = true;
  }
  window.addEventListener("resize", () => {
    if (current === "#screen-clip") {
      resizeCanvases();
      requestDraw();
    }
  });

  function requestDraw() {
    dirty = true;
    if (!raf) raf = requestAnimationFrame(frame);
  }

  function frame() {
    raf = 0;
    if (current !== "#screen-clip") return;
    const t = now();
    if (dirty || t !== lastDrawn) {
      dirty = false;
      lastDrawn = t;
      drawOverview(t);
      drawDetail(t);
      $("#t-now").textContent = fmtTime(t, true);
      updateNear(t);
    }
    if (!video.paused || S.dragTime != null) raf = requestAnimationFrame(frame);
  }

  function drawOverview(t) {
    const W = ov.width;
    const H = ov.height;
    const c = octx;
    c.clearRect(0, 0, W, H);
    const dur = S.duration;
    if (!dur) return;
    if (S.peaks && (!overviewBars || overviewBars.length !== W)) {
      const p = S.peaks;
      const n = p.length;
      overviewBars = new Float32Array(W);
      for (let x = 0; x < W; x++) {
        const a = Math.floor((x / W) * dur * S.rate);
        const b = Math.max(a + 1, Math.floor(((x + 1) / W) * dur * S.rate));
        let m = 0;
        for (let i = a; i < b && i < n; i++) if (p[i] > m) m = p[i];
        overviewBars[x] = amp(m);
      }
    }
    const mid = H / 2;
    const half = H / 2 - 2;
    if (overviewBars) {
      c.fillStyle = "rgba(34, 211, 238, 0.7)";
      for (let x = 0; x < W; x++) {
        const h = Math.max(0.5, overviewBars[x] * half);
        c.fillRect(x, mid - h, 1, h * 2);
      }
    }
    const x0 = ((t - S.zoom / 2) / dur) * W;
    const x1 = ((t + S.zoom / 2) / dur) * W;
    c.fillStyle = "rgba(230, 237, 243, 0.12)";
    c.fillRect(x0, 0, Math.max(3, x1 - x0), H);
    const unit = Math.max(1, Math.round(W / 390));
    c.fillStyle = "#e3b341";
    for (const m of S.markers) c.fillRect(Math.round((m.timestamp / dur) * W - unit / 2), 0, unit, H);
    c.fillStyle = "#ffffff";
    c.fillRect(Math.round((t / dur) * W - unit), 0, unit * 2, H);
  }

  const TICK_STEPS = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600];

  function drawDetail(t) {
    const W = dt.width;
    const H = dt.height;
    const c = dctx;
    const dpr = W / Math.max(1, dt.clientWidth);
    c.clearRect(0, 0, W, H);
    const span = S.zoom;
    const t0 = t - span / 2;
    const pps = W / span;
    const top = Math.round(18 * dpr);
    const mid = Math.round(top + (H - top) / 2);
    const half = (H - top) / 2 - 3 * dpr;
    const dur = S.duration;

    if (dur) {
      c.fillStyle = "rgba(255, 255, 255, 0.035)";
      if (t0 < 0) c.fillRect(0, top, -t0 * pps, H - top);
      const endX = (dur - t0) * pps;
      if (endX < W) c.fillRect(endX, top, W - endX, H - top);
    }

    const step = TICK_STEPS.find((s) => s * pps >= 64 * dpr) || 3600;
    c.font = `${Math.round(11 * dpr)}px ui-monospace, Menlo, monospace`;
    c.textBaseline = "top";
    for (let k = Math.ceil(Math.max(0, t0) / step) * step; k <= t0 + span && k <= dur; k += step) {
      const x = Math.round((k - t0) * pps);
      c.fillStyle = "#30363d";
      c.fillRect(x, top - 5 * dpr, Math.max(1, Math.round(dpr)), 5 * dpr);
      c.fillStyle = "#8b949e";
      c.fillText(fmtTime(k), x + 3 * dpr, 2 * dpr);
    }

    c.fillStyle = "#21262d";
    c.fillRect(0, mid, W, Math.max(1, Math.round(dpr)));

    if (S.peaks) {
      const p = S.peaks;
      const n = p.length;
      const rate = S.rate;
      const bw = Math.max(1, Math.round(dpr));
      c.fillStyle = "#22d3ee";
      for (let x = 0; x < W; x += bw) {
        const ta = t0 + x / pps;
        const tb = t0 + (x + bw) / pps;
        if (tb <= 0 || ta >= dur) continue;
        let a = Math.floor(ta * rate);
        let b = Math.floor(tb * rate);
        if (b <= a) b = a + 1;
        a = Math.max(0, a);
        b = Math.min(n, b);
        let m = 0;
        for (let i = a; i < b; i++) if (p[i] > m) m = p[i];
        const h = Math.max(0.5 * dpr, amp(m) * half);
        c.fillRect(x, mid - h, bw, h * 2);
      }
    }

    c.fillStyle = "#e3b341";
    for (const m of S.markers) {
      if (m.timestamp < t0 || m.timestamp > t0 + span) continue;
      const x = Math.round((m.timestamp - t0) * pps);
      c.fillRect(x - dpr, top, 2 * dpr, H - top);
      c.beginPath();
      c.moveTo(x - dpr, top);
      c.lineTo(x + 10 * dpr, top + 5 * dpr);
      c.lineTo(x - dpr, top + 10 * dpr);
      c.closePath();
      c.fill();
    }

    const px = Math.round(W / 2);
    c.fillStyle = "#ffffff";
    c.fillRect(px - dpr, top, 2 * dpr, H - top);
    c.beginPath();
    c.moveTo(px - 6 * dpr, top - 2 * dpr);
    c.lineTo(px + 6 * dpr, top - 2 * dpr);
    c.lineTo(px, top + 6 * dpr);
    c.closePath();
    c.fill();
  }

  // Overview: tap or drag anywhere to jump.
  let ovDrag = false;
  function ovTime(e) {
    const r = ov.getBoundingClientRect();
    return clamp((e.clientX - r.left) / r.width, 0, 1) * S.duration;
  }
  ov.addEventListener("pointerdown", (e) => {
    if (!S.duration) return;
    ov.setPointerCapture(e.pointerId);
    ovDrag = true;
    S.dragTime = ovTime(e);
    seekSoon(S.dragTime);
    requestDraw();
  });
  ov.addEventListener("pointermove", (e) => {
    if (!ovDrag) return;
    S.dragTime = ovTime(e);
    seekSoon(S.dragTime);
    requestDraw();
  });
  const ovEnd = () => {
    if (!ovDrag) return;
    ovDrag = false;
    const t = S.dragTime;
    S.dragTime = null;
    seek(t);
  };
  ov.addEventListener("pointerup", ovEnd);
  ov.addEventListener("pointercancel", ovEnd);

  // Detail: drag the waveform under the fixed playhead to scrub, tap to jump there.
  let dd = null;
  dt.addEventListener("pointerdown", (e) => {
    if (!S.duration) return;
    dt.setPointerCapture(e.pointerId);
    dd = { id: e.pointerId, x: e.clientX, t: now(), moved: false };
  });
  dt.addEventListener("pointermove", (e) => {
    if (!dd || e.pointerId !== dd.id) return;
    const dx = e.clientX - dd.x;
    if (!dd.moved && Math.abs(dx) < 6) return;
    dd.moved = true;
    S.dragTime = clamp(dd.t - (dx * S.zoom) / dt.clientWidth, 0, S.duration);
    seekSoon(S.dragTime);
    requestDraw();
  });
  function ddEnd(e, cancelled) {
    if (!dd || e.pointerId !== dd.id) return;
    let t;
    if (dd.moved) {
      t = S.dragTime;
    } else if (!cancelled) {
      const r = dt.getBoundingClientRect();
      t = dd.t + ((e.clientX - r.left) / r.width - 0.5) * S.zoom;
    }
    dd = null;
    S.dragTime = null;
    if (t != null) seek(t);
    else requestDraw();
  }
  dt.addEventListener("pointerup", (e) => ddEnd(e, false));
  dt.addEventListener("pointercancel", (e) => ddEnd(e, true));

  /* ---------- markers ---------- */

  let nearId = null;

  const newId = () => `m${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
  const sortMarkers = () => S.markers.sort((a, b) => a.timestamp - b.timestamp);

  async function loadMarkers(c) {
    S.markersError = null;
    const entries = await dbx.list(`${c.folder}/markers`, false);
    const files = entries.filter((e) => e[".tag"] === "file" && /\.json$/i.test(e.name) && !e.name.startsWith("~"));
    const found = new Map();
    let failed = 0;
    await pool(files, 6, async (e) => {
      try {
        const m = parseJson(await readText(e));
        if (!m || typeof m.timestamp !== "number") return;
        const id = m.id || e.name.replace(/\.json$/i, "");
        const prev = found.get(id);
        if (!prev || String(m.updated || "") > String(prev.updated || "")) found.set(id, { ...m, id, _path: e.path_display });
      } catch (err) {
        if (err instanceof AuthError) throw err;
        failed++;
      }
    });
    // Edits still waiting in the outbox win over what Dropbox has.
    for (const op of outbox.pendingFor(`${c.folder}/markers/`)) {
      const id = op.path.split("/").pop().replace(/\.json$/i, "");
      if (op.kind === "del") {
        found.delete(id);
      } else {
        const m = parseJson(op.text);
        if (m) found.set(id, { ...m, _path: op.path });
      }
    }
    S.markers = [...found.values()];
    sortMarkers();
    if (failed) S.markersError = `${failed} marker(s) couldn't be loaded. Go back and reopen the clip to retry.`;
  }

  function persistMarker(m) {
    m.updated = new Date().toISOString();
    if (!m._path) m._path = `${S.clip.folder}/markers/${m.id}.json`;
    const clean = {};
    for (const [k, v] of Object.entries(m)) if (!k.startsWith("_")) clean[k] = v;
    outbox.put(m._path, JSON.stringify(clean, null, 1));
  }

  function removeMarker(m) {
    S.markers = S.markers.filter((x) => x !== m);
    outbox.del(m._path);
  }

  function renderMarkers(loadingText) {
    const ul = $("#markers");
    ul.replaceChildren();
    $("#marker-count").textContent = S.markers.length ? String(S.markers.length) : "";
    if (S.markersError) {
      const li = el("li", "empty", S.markersError);
      li.classList.add("error-text");
      ul.append(li);
    }
    if (!S.markers.length) {
      if (!S.markersError) ul.append(el("li", "empty", loadingText || "No markers yet. Tap + at a moment worth keeping."));
      return;
    }
    for (const m of S.markers) {
      const li = el("li", m.id === nearId ? "mrow near" : "mrow");
      li.dataset.id = m.id;
      const main = button("mrow-main", null, () => seek(m.timestamp));
      main.append(el("span", "mrow-time", fmtTime(m.timestamp, true)));
      main.append(el("span", m.note ? "mrow-note" : "mrow-note dim", m.note || "No note"));
      const suffix = m.tag ? tagSuffixFor(m.tag, m) : null;
      if (suffix) main.append(el("span", "suffix", suffix));
      const edit = button("mrow-edit", "Edit", () => openEditor(m, false));
      edit.setAttribute("aria-label", `Edit marker at ${fmtTime(m.timestamp, true)}`);
      li.append(main, edit);
      ul.append(li);
    }
  }

  function updateNear(t) {
    let best = null;
    let bestD = 1.5;
    for (const m of S.markers) {
      const d = Math.abs(m.timestamp - t);
      if (d <= bestD) {
        bestD = d;
        best = m.id;
      }
    }
    if (best === nearId) return;
    nearId = best;
    for (const li of $$("#markers .mrow")) li.classList.toggle("near", li.dataset.id === nearId);
  }

  $("#add").addEventListener("click", () => {
    if (!S.clip) return;
    const t = Math.round(now() * 1000) / 1000;
    const resume = !video.paused;
    video.pause();
    const stamp = new Date().toISOString();
    const m = {
      version: 1, id: newId(), clip_id: S.clip.id, timestamp: t,
      note: "", tag: null, tag_suffix: null, created: stamp, updated: stamp,
    };
    S.markers.push(m);
    sortMarkers();
    persistMarker(m);
    renderMarkers();
    requestDraw();
    openEditor(m, resume);
  });

  /* ---------- marker editor ---------- */

  let ed = null;

  function openEditor(m, resume) {
    ed = { m, resume, tag: m.tag || null };
    $("#ed-time").textContent = `Marker at ${fmtTime(m.timestamp, true)}`;
    $("#ed-note").value = m.note || "";
    $("#ed-newtag").hidden = true;
    $("#ed-newtag-error").hidden = true;
    renderEditorTags();
    $("#sheet-editor").hidden = false;
    // Same tap that opened it, so iOS brings the keyboard up.
    $("#ed-note").focus();
  }

  function closeEditor(keep) {
    if (!ed) return;
    const { m, resume } = ed;
    if (keep) {
      const note = $("#ed-note").value.trim().replace(/\s+/g, " ");
      const tag = ed.tag;
      const suffix = tag ? tagSuffixFor(tag, m) : null;
      if (note !== (m.note || "") || tag !== (m.tag || null) || suffix !== (m.tag_suffix || null)) {
        m.note = note;
        m.tag = tag;
        m.tag_suffix = suffix;
        persistMarker(m);
      }
    }
    ed = null;
    $("#ed-note").blur();
    $("#sheet-editor").hidden = true;
    renderMarkers();
    requestDraw();
    if (resume) video.play().catch(() => {});
  }

  function renderEditorTags() {
    const box = $("#ed-tags");
    box.replaceChildren();
    if (!ed) return;
    const chip = (name, suffix) => {
      const b = button("chip", null, () => {
        ed.tag = ed.tag === name ? null : name;
        renderEditorTags();
      });
      b.setAttribute("aria-pressed", String(ed.tag === name));
      b.append(el("span", null, name));
      if (suffix) b.append(el("span", "suffix", suffix));
      return b;
    };
    // A tag deleted from the list still shows on markers that carry it.
    if (ed.tag && !tags.some((t) => t.name === ed.tag)) box.append(chip(ed.tag, ed.m.tag_suffix));
    for (const t of tags) box.append(chip(t.name, t.suffix));
    box.append(button("chip chip-add", "+ New tag", async () => {
      const err = $("#ed-newtag-error");
      err.hidden = true;
      $("#ed-newtag-name").value = "";
      $("#ed-newtag-suffix").value = "";
      $("#ed-newtag").hidden = false;
      $("#ed-newtag-name").focus();
      await tagsReady(err);
    }));
  }

  async function addTagFromEditor() {
    const err = $("#ed-newtag-error");
    err.hidden = true;
    if (!(await tagsReady(err))) return;
    const r = validateTag($("#ed-newtag-name").value, $("#ed-newtag-suffix").value);
    if (typeof r === "string") {
      err.textContent = r;
      err.hidden = false;
      return;
    }
    tags.push(r);
    saveTags();
    if (ed) ed.tag = r.name;
    $("#ed-newtag").hidden = true;
    renderEditorTags();
  }

  $("#editor-form").addEventListener("submit", (e) => {
    e.preventDefault();
    closeEditor(true);
  });
  $("#ed-newtag-add").addEventListener("click", addTagFromEditor);
  $("#ed-newtag-name").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); $("#ed-newtag-suffix").focus(); }
  });
  $("#ed-newtag-suffix").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); addTagFromEditor(); }
  });

  $("#ed-delete").addEventListener("click", () => {
    if (!ed) return;
    const m = ed.m;
    removeMarker(m);
    closeEditor(false);
    toast(`Marker at ${fmtTime(m.timestamp, true)} deleted`, {
      label: "Undo",
      run: () => {
        persistMarker(m);
        if (S.clip && S.clip.id === m.clip_id) {
          S.markers.push(m);
          sortMarkers();
          renderMarkers();
          requestDraw();
        }
      },
    });
  });

  for (const b of $$(".sheet-backdrop")) {
    b.addEventListener("click", () => {
      if (b.dataset.close === "editor") closeEditor(true);
      else $("#sheet-tags").hidden = true;
    });
  }

  /* ---------- lifecycle ---------- */

  window.addEventListener("online", () => { renderSync(); outbox.flush(); });
  window.addEventListener("offline", renderSync);
  window.addEventListener("pagehide", savePos);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      savePos();
      return;
    }
    outbox.flush();
    if (current === "#screen-clips") refreshClips();
    if (current === "#screen-clip" && S.clip && Date.now() - S.linkAt > 3.5 * 3600e3) refreshLink(false);
  });

  function init() {
    const z = store.get("ms.zoom", 30);
    S.zoom = ZOOMS.includes(z) ? z : 30;
    renderSync();
    if (!APP_KEY) return show("#screen-setup");
    if (!auth.signedIn()) return showConnect();
    showClips();
    ensureTags().catch(() => {});
    outbox.flush();
  }

  init();
})();
