"use strict";

(() => {
  const CFG = window.MARKER_SYNC_CONFIG || {};
  const APP_KEY = String(CFG.dropboxAppKey || "").trim();
  const API = CFG.apiBase || "https://api.dropboxapi.com";
  const CONTENT = CFG.contentBase || "https://content.dropboxapi.com";
  const AUTHORIZE = CFG.authorizeUrl || "https://www.dropbox.com/oauth2/authorize";

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
    for (const id of ["#clip-sync", "#clips-sync", "#script-sync", "#home-sync", "#vl-sync", "#ve-sync"]) {
      const s = $(id);
      s.className = cls ? `sync ${cls}` : "sync";
      s.textContent = text;
    }
    $("#clips-sync").hidden = !n;
    $("#home-sync").hidden = !n;
    $("#vl-sync").hidden = !n;
  }

  /* ---------- screens, toast ---------- */

  const SCREENS = ["#screen-setup", "#screen-connect", "#screen-home", "#screen-clips", "#screen-clip", "#screen-script",
    "#screen-vlist", "#screen-vedit"];
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
      showHome();
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

  /* ---------- press and hold ---------- */
  // iPhone's "hard press" is a press and hold: it fires after ms if the finger
  // stays put, and the tap that ends it is swallowed.

  function onLongPress(node, fire, ms = 450) {
    let timer = 0;
    let x = 0;
    let y = 0;
    let fired = false;
    const cancel = () => clearTimeout(timer);
    node.addEventListener("pointerdown", (e) => {
      fired = false;
      x = e.clientX;
      y = e.clientY;
      clearTimeout(timer);
      timer = setTimeout(() => {
        fired = true;
        fire(e);
      }, ms);
    });
    node.addEventListener("pointermove", (e) => {
      if (Math.hypot(e.clientX - x, e.clientY - y) > 8) cancel();
    });
    for (const n of ["pointerup", "pointercancel"]) node.addEventListener(n, cancel);
    node.addEventListener("click", (e) => {
      if (!fired) return;
      fired = false;
      e.preventDefault();
      e.stopPropagation();
    }, true);
    node.addEventListener("contextmenu", (e) => e.preventDefault());
  }

  // A sheet opened as a finger lifts: the tap's own click comes a moment later
  // and would land on whatever the sheet put under the finger (a tag, a color).
  function swallowClick(ms = 600) {
    const until = performance.now() + ms;
    const eat = (e) => {
      document.removeEventListener("click", eat, true);
      if (performance.now() > until) return;
      e.preventDefault();
      e.stopPropagation();
    };
    document.addEventListener("click", eat, true);
    setTimeout(() => document.removeEventListener("click", eat, true), ms);
  }

  /* ---------- tags ---------- */
  // Every tag has a permanent id and markers point at it, so renaming a tag or
  // changing its suffix changes it on every marker that has it, here and in
  // the PC's CSVs. Tags from before ids get one made from their name, which is
  // also how old markers (name only) find them.

  let tags = [];
  let tagsLoaded = false;
  let tagsRev = null;                 // Dropbox revision of tags.json last read
  let editingTag = null;              // id of the tag open for editing in the Tags sheet

  const cleanName = (s) => String(s || "").trim().replace(/\s+/g, " ");
  const legacyTagId = (name) => `n:${cleanName(name).toLowerCase()}`;
  const newTagId = () => `t${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
  const tagById = (id) => tags.find((t) => t.id === id) || null;

  // Marker and tag colors, by name (the PC's marker_sync.COLORS); none is the
  // usual amber. A marker's color is its flag, its tick and its row in the
  // list; a tag's is only that tag's chips.
  const COLORS = [
    { id: "", label: "Default", hex: "#e3b341" },
    { id: "red", label: "Red", hex: "#f87171" },
    { id: "orange", label: "Orange", hex: "#fb923c" },
    { id: "green", label: "Green", hex: "#4ade80" },
    { id: "cyan", label: "Cyan", hex: "#22d3ee" },
    { id: "blue", label: "Blue", hex: "#60a5fa" },
    { id: "purple", label: "Purple", hex: "#a78bfa" },
    { id: "pink", label: "Pink", hex: "#f472b6" },
  ];
  const cleanColor = (c) => (c && COLORS.some((x) => x.id === c) ? c : "");
  const colorHex = (id) => (COLORS.find((c) => c.id === (id || "")) || COLORS[0]).hex;
  const tintTag = (node, t) => {
    if (t && cleanColor(t.color)) node.style.setProperty("--tc", colorHex(t.color));
  };

  // A row of color dots, Default first.
  function swatches(current, onPick) {
    return COLORS.map((c) => {
      const b = button("swatch", null, () => onPick(c.id));
      b.style.setProperty("--c", c.hex);
      b.setAttribute("role", "radio");
      b.setAttribute("aria-label", c.label);
      b.setAttribute("aria-checked", String((current || "") === c.id));
      return b;
    });
  }

  // Returns [tags, whether any were missing an id].
  function normalizeTags(list) {
    const out = [];
    const names = new Set();
    const ids = new Set();
    let added = false;
    for (const t of Array.isArray(list) ? list : []) {
      const name = cleanName(t && t.name);
      const suffix = cleanName(t && t.suffix);
      if (!name || names.has(name.toLowerCase())) continue;
      let id = String((t && t.id) || "");
      if (!id) {
        id = legacyTagId(name);
        added = true;
      }
      if (ids.has(id)) id = newTagId();
      names.add(name.toLowerCase());
      ids.add(id);
      const tag = { id, name, suffix };
      if (cleanColor(t.color)) tag.color = t.color;
      out.push(tag);
    }
    return [out, added];
  }

  async function ensureTags() {
    const pending = outbox.pendingFor("/tags.json").filter((o) => o.kind === "put").pop();
    let added = false;
    if (pending) {
      [tags, added] = normalizeTags((parseJson(pending.text) || {}).tags);
    } else {
      const meta = await dbx.meta("/tags.json");
      if (meta) {
        [tags, added] = normalizeTags((parseJson(await readText(meta)) || {}).tags);
        tagsRev = meta.rev;
      } else {
        // First run: writing it also makes Dropbox create the app folder on the PC.
        tags = [];
        added = true;
      }
    }
    tagsLoaded = true;
    if (added) saveTags();          // gives older tags their ids
  }

  function saveTags() {
    outbox.put("/tags.json", JSON.stringify({ version: 2, tags }, null, 2));
  }

  function validateTag(name, suffix, except) {
    name = cleanName(name);
    suffix = cleanName(suffix).toUpperCase();
    if (!name) return "Give the tag a name.";
    if (!suffix) return "Give the tag a suffix. It's what gets added to the marker in Premiere.";
    if (tags.some((t) => t !== except && t.name.toLowerCase() === name.toLowerCase())) return "You already have a tag with that name.";
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

  // What a marker carries: [{id, name, suffix}] as saved. Old markers have a
  // single tag by name.
  function markerTagRefs(m) {
    const raw = Array.isArray(m.tags) ? m.tags : m.tag ? [{ name: m.tag, suffix: m.tag_suffix }] : [];
    const out = [];
    for (const r of raw) {
      if (!r) continue;
      const name = cleanName(r.name);
      const id = String(r.id || "") || (name ? legacyTagId(name) : "");
      if (id && !out.some((x) => x.id === id)) out.push({ id, name, suffix: cleanName(r.suffix) });
    }
    return out;
  }

  // The same tags as they're called now; a deleted tag keeps its saved name.
  function markerTags(m) {
    return markerTagRefs(m).map((r) => tagById(r.id)
      || tags.find((t) => r.name && t.name.toLowerCase() === r.name.toLowerCase()) || r);
  }

  function setMarkerTags(m, list) {
    const order = (t) => {
      const i = tags.findIndex((x) => x.id === t.id);
      return i < 0 ? 1e9 : i;
    };
    const sorted = list.slice().sort((a, b) => order(a) - order(b));
    m.tags = sorted.map((t) => ({ id: t.id, name: t.name, suffix: t.suffix }));
    m.tag = sorted.length ? sorted[0].name : null;          // for older versions of the PC side
    m.tag_suffix = sorted.length ? sorted[0].suffix : null;
    m.version = 3;
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
      if (t.id === editingTag) {
        ul.append(tagEditRow(t));
        continue;
      }
      const li = el("li", "tag-row");
      li.dataset.id = t.id;
      const sx = el("span", "suffix", t.suffix);
      tintTag(sx, t);
      li.append(el("span", "tag-name", t.name), sx);
      li.append(button("btn btn-ghost btn-danger btn-small", "Delete", () => {
        tags = tags.filter((x) => x !== t);
        saveTags();
        renderTagList();
      }));
      onLongPress(li, () => {
        editingTag = t.id;
        renderTagList();
        const input = $("#tags-list .tag-edit input");
        if (input) input.focus();
      });
      ul.append(li);
    }
  }

  function tagEditRow(t) {
    const li = el("li", "tag-edit");
    const name = el("input", "input");
    name.value = t.name;
    name.maxLength = 40;
    name.setAttribute("aria-label", "Tag name");
    name.enterKeyHint = "next";
    const suffix = el("input", "input input-suffix");
    suffix.value = t.suffix;
    suffix.maxLength = 12;
    suffix.setAttribute("aria-label", "Suffix");
    suffix.autocapitalize = "characters";
    suffix.spellcheck = false;
    suffix.enterKeyHint = "done";
    const err = el("p", "error-text");
    err.hidden = true;
    let color = cleanColor(t.color);
    const colors = el("div", "swatches");
    colors.setAttribute("role", "radiogroup");
    colors.setAttribute("aria-label", "Tag color");
    const paint = () => colors.replaceChildren(...swatches(color, (id) => {
      color = id;
      paint();
    }));
    paint();
    const save = () => {
      const r = validateTag(name.value, suffix.value, t);
      if (typeof r === "string") {
        err.textContent = r;
        err.hidden = false;
        return;
      }
      const changed = r.name !== t.name || r.suffix !== t.suffix || color !== cleanColor(t.color);
      Object.assign(t, r);
      if (color) t.color = color;
      else delete t.color;
      editingTag = null;
      if (changed) {
        saveTags();
        toast(`${t.name} (${t.suffix}) updated on every marker that has it`);
      }
      renderTagList();
      if (S.clip) {
        renderMarkers();
        requestDraw();
      }
    };
    name.addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); suffix.focus(); }
    });
    suffix.addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); save(); }
    });
    const row = el("div", "newtag-row");
    row.append(suffix, button("btn btn-primary", "Save", save));
    const foot = el("div", "tag-edit-foot");
    foot.append(el("span", "muted small", "Changes it on every marker with this tag."),
      button("btn btn-ghost btn-small", "Cancel", () => {
        editingTag = null;
        renderTagList();
      }));
    li.append(name, row, el("span", "muted small", "Color, only on this tag's chips"), colors, err, foot);
    return li;
  }

  $("#clips-tags").addEventListener("click", async () => {
    $("#tags-error").hidden = true;
    editingTag = null;
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
    tags.push({ id: newTagId(), ...r });
    saveTags();
    $("#tags-name").value = "";
    $("#tags-suffix").value = "";
    renderTagList();
  });

  /* ---------- home ----------
     The app opens on a menu of what it can do, like the clip editor's tabs on
     the PC: Markers (mark a clip while its VOD plays) and Script (write a
     clip's script from its markers). Both pick a clip from the same list. */

  function showHome() {
    show("#screen-home");
    renderSync();
  }

  $("#home-markers").addEventListener("click", () => showClips("markers"));
  $("#home-script").addEventListener("click", () => showClips("script"));
  $("#clips-home").addEventListener("click", showHome);

  /* ---------- clip list ---------- */
  // Markers lists the clips sent to the phone. Script lists those plus clips
  // marked only on the PC: their markers and script are in Dropbox, their
  // video isn't.

  let clips = [];
  let clipsLoaded = false;
  let clipsTimer = 0;
  let listFor = "markers";             // which tool the list is picking a clip for

  function showClips(tool) {
    if (tool) listFor = tool;
    show("#screen-clips");
    $("#clips-title").textContent = listFor === "script" ? "Script" : "Markers";
    $("#clips-tags").hidden = listFor !== "markers";
    renderSync();
    renderClips();
    refreshClips();
  }

  const hasVideo = (c) => !!(c.manifest && !c.manifest.pc_only && c.manifest.twitch && c.manifest.twitch.vod_id);
  const fmtWhen = (iso) => new Date(iso).toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });

  async function refreshClips() {
    clearTimeout(clipsTimer);
    if (current !== "#screen-clips") return;
    if (!document.hidden) {
      const banner = $("#clips-banner");
      try {
        clips = await loadClips();
        clipsLoaded = true;
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
    if (m && m.pc_only) {
      c.state = "pc";             // marked in the clip editor, not sent to the phone
      c.name = stripExt(m.source_name) || c.id;
      c.duration = m.duration;
      c.created = m.created;
    } else if (m) {
      const wf = c.files["waveform.bin"];
      const twitch = m.twitch && Array.isArray(m.twitch.sync) && m.twitch.sync.length;
      const complete = wf && wf.size === (m.waveform || {}).size;
      const stale = m.created && Date.now() - Date.parse(m.created) > 6 * 3600e3;
      c.state = !twitch ? "old" : complete ? "ready" : stale ? "missing" : "uploading";
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
      text: (c) => (c.progress ? `Lining up on PC, ${Math.round(c.progress * 100)}%` : "Lining up on PC"),
      hint: "The PC is still lining this clip up with its Twitch VOD.",
    },
    uploading: {
      cls: "state-busy", text: () => "Syncing from PC",
      hint: "Dropbox is still bringing over the waveform from the PC.",
    },
    failed: { cls: "state-failed", text: () => "Failed on PC", hint: "The PC couldn't line this clip up. See the clip editor's Phone tab." },
    missing: {
      cls: "state-failed", text: () => "Waveform missing",
      hint: "This clip's waveform isn't in Dropbox. Send it again from the clip editor; its markers are still saved.",
    },
    old: {
      cls: "state-failed", text: () => "Send again from the PC",
      hint: "This clip was made by the old phone-copy version. Open the clip editor's Phone tab and send it again.",
    },
  };

  function renderClips() {
    const ul = $("#clips-list");
    ul.replaceChildren();
    const script = listFor === "script";
    const shown = clips.filter((c) => script || c.state !== "pc");
    $("#clips-empty").hidden = !clipsLoaded || shown.length > 0;
    $("#clips-empty-text").replaceChildren(...(script
      ? ["Mark a clip here or in the clip editor's ", el("b", null, "Markers"), " tab on the PC, and it shows up here."]
      : ["On the PC, open the clip editor's ", el("b", null, "Phone"), " tab and add a clip. It shows up here a minute or two later."]));
    for (const c of shown) {
      const st = CLIP_STATES[c.state] || CLIP_STATES.missing;
      const card = button("clip-card", null, () => {
        if (script) openScript(c);
        else if (c.state === "ready") openClip(c);
        else toast(st.hint);
      });
      card.append(el("span", "clip-name", c.name));
      const meta = el("span", "clip-meta");
      if (script) {
        const f = c.files["script.md"];
        const tb = c.files["but-therefore.md"];
        meta.append(el("span", `state ${f || tb ? "state-ready" : "state-none"}`, f ? `Script, edited ${fmtWhen(f.server_modified)}`
          : tb ? `But / Therefore, edited ${fmtWhen(tb.server_modified)}` : "No script yet"));
      } else {
        meta.append(el("span", `state ${st.cls}`, st.text(c)));
      }
      if (c.duration) meta.append(el("span", null, fmtTime(c.duration)));
      if (c.markerCount) meta.append(el("span", null, `${c.markerCount} marker${c.markerCount === 1 ? "" : "s"}`));
      if (script && !hasVideo(c)) meta.append(el("span", null, c.state === "pc" ? "marked on the PC, no video here" : "no video yet"));
      card.append(meta);
      if (!script && c.state === "failed" && c.error) card.append(el("span", "clip-error", c.error));
      if (!script && c.state !== "ready") card.classList.add("clip-card-wait");
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
    clips = [];
    clipsLoaded = false;
    if (window.MSEDIT) window.MSEDIT.reset();
    showConnect();
  });

  /* ---------- marking workspace ---------- */
  // The video plays from the Twitch VOD. Clip time is what the waveform,
  // markers and Premiere use; VOD time is what the player uses. The manifest's
  // sync map converts between them, stream drops included.

  const ov = $("#wave-overview");
  const dt = $("#wave-detail");
  const octx = ov.getContext("2d");
  const dctx = dt.getContext("2d");
  const playBtn = $("#play");

  const S = {
    clip: null,
    vodId: null,
    sync: [{ clip: 0, vod: 0 }],
    vodDuration: 0,
    streams: [],
    duration: 0,
    markers: [],
    markersError: null,
    zoom: 30,
    quality: 480,
    tracks: [],
    view: [],                // track numbers shown as waveform lanes
    waveCache: new Map(),    // file -> {peaks, ref, rate}
    waveLoads: new Map(),    // file -> its download in flight
    dragClip: null,
    moving: null,            // a marker being moved: {m, from, at, resume}
    posSaved: 0,
    openToken: 0,
  };

  // Anchors [{clip, vod}]: from each anchor on, VOD = clip + (vod - clip) until
  // the next one. Time that only one side has (a stream drop, or VOD time the
  // clip lacks) snaps to the next anchor.
  function clipToVod(c) {
    const A = S.sync;
    let k = 0;
    for (let i = 0; i < A.length; i++) if (A[i].clip <= c) k = i;
    let v = A[k].vod + (c - A[k].clip);
    if (k + 1 < A.length && v > A[k + 1].vod) v = A[k + 1].vod;
    return v;
  }

  function vodToClip(v) {
    const A = S.sync;
    let k = 0;
    for (let i = 0; i < A.length; i++) if (A[i].vod <= v) k = i;
    let c = A[k].clip + (v - A[k].vod);
    if (k + 1 < A.length && c > A[k + 1].clip) c = A[k + 1].clip;
    return c;
  }

  // Markers remember the VOD moment they were placed at, so a re-alignment on
  // the PC moves them all with it. Markers placed in the clip editor on the PC
  // are pinned to the recording itself ("clock": "clip"), which also covers
  // stretches the VOD doesn't have.
  const onClipClock = (m) => m.clock === "clip" || typeof m.vod_time !== "number";
  const mClip = (m) => (onClipClock(m) ? m.timestamp : vodToClip(m.vod_time));

  /* ---------- the video ---------- */
  // Two players sit behind the same few functions (vodNow, playVideo,
  // pauseVideo, seekVod, videoActive):
  //  - Direct: the phone's own video player streams the VOD straight from
  //    Twitch's video servers, using links the PC saved in the manifest. It
  //    knows its position exactly, seeks at once (paused too) and draws
  //    nothing over the picture. Needs a browser that plays HLS itself, which
  //    every iPhone does.
  //  - Twitch: Twitch's embedded player, steered by messages. The backup for
  //    clips sent before the links existed, other browsers, or a stream that
  //    won't load.

  let mode = null;                 // what's playing this clip: "direct" or "twitch"
  let playerPref = "direct";       // the sheet's choice; Direct whenever it can
  const PLOG = [];                 // recent player events, for the Player check

  function plog(name) {
    PLOG.push(name);
    if (PLOG.length > 8) PLOG.shift();
  }

  let hlsOk = null;
  function canPlayHls() {
    if (hlsOk == null) {
      try { hlsOk = !!document.createElement("video").canPlayType("application/vnd.apple.mpegurl"); } catch { hlsOk = false; }
    }
    return hlsOk;
  }

  // Why Direct can't be used for this clip, or null if it can.
  function directBlocker() {
    if (!S.streams.length) return "This clip has no direct links yet. Send it again from the PC's Phone tab to use Direct.";
    if (!canPlayHls()) return "This browser can't play the direct stream, so Twitch's player is used.";
    if (DV.failed) return "The direct stream didn't load this time, so Twitch's player is used.";
    return null;
  }

  function startPlayer(at) {
    destroyPlayer();
    // A recording can start before the stream went live (negative VOD time).
    at = clamp(Number(at) || 0, 0, S.vodDuration ? S.vodDuration - 0.5 : Infinity);
    mode = playerPref === "direct" && !directBlocker() ? "direct" : "twitch";
    if (mode === "direct") directCreate(at);
    else twitchCreate(at);
    renderSpeed();
  }

  function destroyPlayer() {
    clearTimeout(TP.hintTimer);
    stopFastWatch();
    if (DV.el) {
      try {
        DV.el.pause();
        DV.el.removeAttribute("src");
        DV.el.load();               // stops the download
      } catch { /* ignore */ }
    }
    Object.assign(DV, { el: null, want: null, src: null });
    $("#player").replaceChildren();
    $("#player-hint").hidden = true;
    Object.assign(TP, { player: null, ready: false, playing: false, starting: false, everPlayed: false,
      lastReport: null, offCount: 0, seeking: false, stalled: false, want: null, resends: 0 });
    PLOG.length = 0;
    mode = null;
    showPlaying(false);
  }

  const vodNow = () => (mode === "direct" ? directNow() : twitchNow());
  const videoActive = () => (mode === "direct" ? !!DV.el && !DV.el.paused : TP.playing || TP.starting);

  function playVideo() {
    if (mode === "direct") directPlay();
    else if (mode === "twitch") twitchPlay();
  }

  function pauseVideo() {
    if (mode === "direct") {
      FW.pausedAt = performance.now();
      if (DV.el) DV.el.pause();
    } else if (mode === "twitch") {
      twitchPause();
    }
  }

  function togglePlay() {
    if (videoActive()) pauseVideo();
    else playVideo();
  }

  // fast: a quick, roughly placed seek for the middle of a drag.
  function seekVod(v, fast) {
    const end = S.vodDuration ? S.vodDuration - 0.5 : Infinity;
    v = clamp(Number(v) || 0, 0, end);
    if (mode === "direct") directSeek(v, fast);
    else if (mode === "twitch") twitchSeek(v);
    requestDraw();
  }

  const seekClip = (c) => seekVod(clipToVod(clamp(c, 0, S.duration)));

  function reconcile() {
    if (mode === "twitch") twitchReconcile();
  }

  function applyQuality() {
    if (mode === "direct") directQuality();
    else if (mode === "twitch") twitchQuality();
  }

  function now() {
    return S.dragClip != null ? S.dragClip : vodToClip(vodNow());
  }

  function videoMsg(text) {
    const m = $("#video-msg");
    m.hidden = !text;
    m.textContent = text || "";
  }

  function showPlaying(on) {
    for (const b of [playBtn, $("#sv-play")]) {
      b.textContent = on ? "Pause" : "Play";
      b.setAttribute("aria-label", on ? "Pause" : "Play");
    }
  }

  /* Direct: a plain <video> whose currentTime is the VOD time, exact at any
     moment, so there's no clock to keep. An iPhone loads nothing until the
     first Play; a seek before that is remembered and applied once the video
     knows its length. */
  const DV = { el: null, want: null, src: null, failed: null };

  function pickStream() {
    const list = S.streams;
    return list.filter((s) => s.height <= S.quality).sort((a, b) => b.height - a.height)[0]
      || list.slice().sort((a, b) => a.height - b.height)[0];
  }

  function directCreate(at) {
    const v = document.createElement("video");
    v.playsInline = true;
    v.setAttribute("playsinline", "");
    v.setAttribute("webkit-playsinline", "");
    v.preload = "metadata";
    for (const name of ["loadedmetadata", "loadeddata", "playing", "pause", "waiting", "seeked", "ended", "error"]) {
      v.addEventListener(name, () => plog(name));
    }
    v.addEventListener("loadedmetadata", applyWant);
    v.addEventListener("loadedmetadata", applyRate);
    v.addEventListener("loadeddata", () => videoMsg(null));
    v.addEventListener("play", () => { showPlaying(true); requestDraw(); });
    v.addEventListener("playing", () => {
      videoMsg(null);
      showPlaying(true);
      requestDraw();
      if (FW.v !== v) checkFast();          // back from a stall: the watch carries on
    });
    v.addEventListener("pause", () => {
      showPlaying(false);
      requestDraw();
      // Stopped by itself right after starting at 4x: the phone won't play it.
      const t = performance.now();
      if (rate > 2 && DV.el === v && !v.ended && t - FW.pausedAt > 400 && (FW.v === v || t - FW.playAt < 3000)) {
        fastCapped("stopped by itself", null, true);
      } else if (FW.v === v) {
        stopFastWatch();
      }
    });
    v.addEventListener("waiting", () => { if (FW.v === v) FW.stalls++; });
    v.addEventListener("seeking", () => { if (FW.v === v) stopFastWatch(); });
    v.addEventListener("seeked", () => {
      requestDraw();
      if (!v.paused && FW.v !== v) checkFast();
    });
    v.addEventListener("error", () => directFailed());
    v.addEventListener("click", togglePlay);
    DV.el = v;
    VZ.s = 1;
    VZ.x = 0;
    VZ.y = 0;
    vzApply();
    $("#player").append(v);
    videoMsg("Tap Play to start the VOD");
    directSource(at);
    applyVolume();
  }

  function directSource(at) {
    const s = pickStream();
    DV.src = s;
    DV.want = at;
    stopFastWatch();
    FW.pausedAt = performance.now();      // a new source stops it; that's not the phone refusing 4x
    // #t= starts it at the right spot in browsers that read it; applyWant
    // makes sure once the video has loaded.
    DV.el.src = `${s.url}#t=${Math.max(0, at).toFixed(2)}`;
    applyRate();
  }

  function applyWant() {
    const v = DV.el;
    if (!v || DV.want == null || v.readyState < 1) return;
    const t = DV.want;
    DV.want = null;
    if (Math.abs(v.currentTime - t) > 0.05) {
      try { v.currentTime = t; } catch { DV.want = t; }
    }
    requestDraw();
  }

  const directNow = () => (!DV.el ? 0 : DV.want != null ? DV.want : DV.el.currentTime);

  function directPlay() {
    const v = DV.el;
    if (!v) return;
    applyWant();
    showPlaying(true);
    if (rate > 2) FW.playAt = performance.now();
    let p;
    try { p = v.play(); } catch (e) { p = Promise.reject(e); }
    if (p && p.catch) {
      p.catch((e) => {
        if (v !== DV.el || (e && e.name === "AbortError")) return;   // paused or replaced before it started
        showPlaying(!v.paused);
        if (e && e.name === "NotAllowedError") toast("The phone didn't let it start. Tap Play again.");
        else if (rate > 2) fastCapped("wouldn't start", null, true);   // the stream is fine; 4x isn't
        else directFailed(e && e.name);
      });
    }
    requestDraw();
  }

  function directSeek(t, fast) {
    const v = DV.el;
    if (!v) return;
    if (v.readyState < 1) {
      DV.want = t;
      return;
    }
    DV.want = null;
    try {
      if (fast && typeof v.fastSeek === "function") v.fastSeek(t);
      else v.currentTime = t;
    } catch {
      DV.want = t;
    }
  }

  function directQuality() {
    const s = pickStream();
    if (!DV.el || !s || (DV.src && DV.src.url === s.url)) return;
    const at = vodNow();
    const playing = !DV.el.paused;
    directSource(at);
    if (playing) directPlay();
  }

  function directFailed(why) {
    if (mode !== "direct" || DV.failed) return;
    const v = DV.el;
    DV.failed = (v && v.error && `error ${v.error.code}`) || why || "error";
    const at = vodNow();
    toast("The direct stream didn't load, so this clip is on Twitch's player for now.");
    startPlayer(at);
  }

  /* Twitch: its player reports its position about twice a second while
     playing, and its "playing" message arrives before its state says so, so
     the app keeps its own clock: set on every seek, run by the wall clock
     while playing, held still while Twitch buffers, and nudged when Twitch's
     reports disagree. Commands go out whether or not Twitch has said it's
     ready (an iPhone may never say so), and a seek Twitch didn't take is sent
     again. */
  const TP = {
    player: null, ready: false, playing: false, starting: false, everPlayed: false,
    base: 0, at: 0, guardUntil: 0, lastReport: null, offCount: 0, hintTimer: 0,
    seeking: false, sawBuffer: false, seekAt: 0, stalled: false,
    playAsked: -1e9, pauseAsked: -1e9, sentAt: -1e9, want: null, resends: 0,
  };

  const running = () => TP.playing && !TP.seeking && !TP.stalled;
  const twitchNow = () => (running() ? TP.base + (performance.now() - TP.at) / 1000 : TP.base);

  function setClock(v) {
    TP.base = v;
    TP.at = performance.now();
  }

  function twitchTime(t) {
    t = Math.max(0, Math.floor(t));
    return `${Math.floor(t / 3600)}h${Math.floor((t % 3600) / 60)}m${t % 60}s`;
  }

  function twitchCreate(at) {
    setClock(at);
    const P = window.Twitch && window.Twitch.Player;
    if (!P) {
      videoMsg("The Twitch player didn't load. Check your connection, then reopen the clip.");
      return;
    }
    videoMsg("Loading the Twitch VOD");
    // controls: false keeps Twitch's title, follow/sub buttons and bar off the
    // video; the waveforms and buttons below do the controlling.
    TP.player = new P("player", {
      video: S.vodId, time: twitchTime(at), autoplay: false, controls: false,
      width: "100%", height: "100%", parent: [location.hostname],
    });
    TP.want = at;                 // "time" is whole seconds; the exact spot follows on ready
    const player = TP.player;
    const poll = setInterval(() => {
      if (TP.player !== player || TP.ready) clearInterval(poll);
      else checkReady();
    }, 250);
    const on = (name, fn) => {
      if (P[name]) TP.player.addEventListener(P[name], (arg) => { plog(P[name]); fn(arg); });
    };
    on("READY", markReady);
    on("VIDEO_READY", markReady);
    on("PLAY", onPlay);
    on("PLAYING", onPlaying);
    on("PAUSE", onPauseMessage);
    on("ENDED", onPaused);
    on("SEEK", onSeekMessage);
    on("PLAYBACK_BLOCKED", () => {
      TP.starting = false;
      showPlaying(false);
      $("#player-hint").hidden = false;
    });
  }

  function markReady() {
    if (TP.ready || !TP.player) return;
    TP.ready = true;
    videoMsg(null);
    applyVolume();
    if (TP.want != null) sendSeek(TP.want);
  }

  function sendSeek(v) {
    TP.sentAt = performance.now();
    try { TP.player.seek(v); } catch { /* not loaded yet; sent again when it is */ }
  }

  // Moves the clock and Twitch to v. While playing, the clock holds at v until
  // Twitch is actually playing from there again (see twitchReconcile).
  function twitchGo(v) {
    setClock(v);
    TP.seeking = TP.playing;
    TP.sawBuffer = false;
    TP.seekAt = performance.now();
    TP.guardUntil = performance.now() + 2000;
    TP.offCount = 0;
    if (TP.player) sendSeek(v);
  }

  function twitchSeek(v) {
    TP.want = v;
    TP.resends = 0;
    twitchGo(v);
  }

  // Twitch confirms each seek with its position.
  function onSeekMessage(arg) {
    markReady();
    if (arg && typeof arg.position === "number" && TP.want != null && Math.abs(arg.position - TP.want) < 0.25) {
      TP.want = null;
    }
  }

  // A seek still unconfirmed when playback starts may have been dropped (an
  // iPhone can't seek a video it hasn't loaded yet), so it goes again now.
  function resendSeek() {
    if (TP.want == null) return;
    const w = TP.want;
    TP.want = null;
    if (performance.now() - TP.sentAt > 700) twitchGo(w);
  }

  function onPlay() {
    markReady();
    // A "play" from before a pause we asked for is old news.
    if (!TP.starting && !TP.playing && performance.now() - TP.pauseAsked < 1500) return;
    TP.starting = true;
    showPlaying(true);
    resendSeek();
    requestDraw();
  }

  function onPlaying() {
    markReady();
    const t = performance.now();
    if (!TP.starting && !TP.playing && t - TP.pauseAsked < 1500) {
      try { TP.player.pause(); } catch { /* ignore */ }     // old news; make sure it's paused
      return;
    }
    clearTimeout(TP.hintTimer);
    $("#player-hint").hidden = true;
    resendSeek();
    if (!TP.playing) {
      TP.playing = true;
      setClock(TP.base);       // the clock starts when the picture does, not when play was pressed
      // Twitch's next report or two can still be from before it started.
      TP.guardUntil = Math.max(TP.guardUntil, t + 1500);
    }
    TP.starting = false;
    showPlaying(true);
    if (!TP.everPlayed) {
      TP.everPlayed = true;
      setTimeout(applyQuality, 600);
    }
    requestDraw();
  }

  function onPaused() {
    if (TP.playing) setClock(twitchNow());
    TP.playing = false;
    TP.starting = false;
    TP.seeking = false;
    TP.stalled = false;
    showPlaying(false);
    requestDraw();
  }

  function onPauseMessage() {
    const t = performance.now();
    // Twitch pauses for a moment inside every seek made while playing, and a
    // pause from before a play we asked for is old news.
    if ((TP.playing || TP.starting) && (t - TP.sentAt < 1200 || t - TP.playAsked < 1500)) return;
    onPaused();
  }

  function twitchPlay() {
    if (!TP.player) return;
    TP.starting = true;
    TP.playAsked = performance.now();
    showPlaying(true);
    try { TP.player.play(); } catch { /* not loaded yet */ }
    clearTimeout(TP.hintTimer);
    // An iPhone may only let a tap on the video itself start it the first time.
    TP.hintTimer = setTimeout(() => {
      if (!TP.playing && TP.starting) $("#player-hint").hidden = false;
    }, 2500);
    requestDraw();
  }

  function twitchPause() {
    if (!TP.player) return;
    TP.pauseAsked = performance.now();
    onPaused();                // freeze the clock at the moment of the tap
    try { TP.player.pause(); } catch { /* not loaded yet */ }
  }

  function playbackState() {
    try {
      const s = TP.player.getPlayerState && TP.player.getPlayerState();
      return (s && s.playback) || null;
    } catch {
      return null;
    }
  }

  // Twitch is talking to us once its state has the VOD's length, "ready"
  // message or not. Checked on a timer too, since nothing redraws while paused.
  function checkReady() {
    if (!TP.player || TP.ready) return;
    let dur = 0;
    try { dur = TP.player.getDuration() || 0; } catch { /* ignore */ }
    if (dur > 0) markReady();
  }

  function twitchReconcile() {
    if (!TP.player) return;
    const t = performance.now();
    checkReady();
    const state = playbackState();
    if (TP.playing) {
      const since = t - TP.seekAt;
      if (TP.seeking) {
        if (state === "Buffering") TP.sawBuffer = true;
        // Resume once Twitch has buffered and is playing again. If it never
        // reported buffering (the spot was already loaded), go after a moment.
        const resumed = state === "Playing" && (TP.sawBuffer || since > 350);
        if (resumed || since > (state ? 6000 : 600)) {
          TP.seeking = false;
          setClock(TP.base);
        }
      } else if (state === "Buffering" && !TP.stalled) {
        setClock(twitchNow());    // stalled mid-play (slow connection): hold the playhead
        TP.stalled = true;
      } else if (state === "Playing" && TP.stalled) {
        TP.stalled = false;
        setClock(TP.base);
      } else if (state === "Idle" && t - TP.sentAt > 1500 && t - TP.playAsked > 1500) {
        onPaused();               // paused some way we didn't hear about
        return;
      }
    }
    let r;
    try { r = TP.player.getCurrentTime(); } catch { return; }
    if (typeof r !== "number" || !Number.isFinite(r) || r === TP.lastReport) return;
    const prev = TP.lastReport;
    TP.lastReport = r;
    // A report that lands during a seek or a stall is noted, so the next one
    // counts as new, but not acted on: it can be from before.
    if (t < TP.guardUntil || TP.seeking || TP.stalled) return;
    if (!TP.playing) {
      // The time is moving, so it's playing, "playing" message or not.
      const moving = prev !== null && r > prev + 0.2;
      if (moving && (TP.starting || (state === "Playing" && t - TP.pauseAsked > 1500))) {
        TP.starting = true;
        setClock(r);
        onPlaying();
      }
      return;
    }
    // Past the guard, a changed report is from after the last seek, and fresh
    // (Twitch sends its time with each state message).
    const d = r - twitchNow();
    if (Math.abs(d) < 3) {
      TP.want = null;
      TP.offCount = 0;
      if (Math.abs(d) >= 0.1) setClock(r);
      return;
    }
    // Far off: Twitch didn't take the last seek. Send it again (twice at
    // most), then believe Twitch.
    if (TP.resends < 2) {
      TP.resends++;
      twitchGo(twitchNow());
    } else if (++TP.offCount >= 3) {
      setClock(r);
      TP.offCount = 0;
    }
  }

  const QUALITIES = [720, 480, 360];

  function twitchQuality() {
    if (!TP.player || !TP.everPlayed) return;
    let qs = [];
    try { qs = TP.player.getQualities() || []; } catch { return; }
    const sized = qs.filter((q) => q.height);
    const pick = sized.filter((q) => q.height <= S.quality).sort((a, b) => b.height - a.height)[0]
      || sized.sort((a, b) => a.height - b.height)[0];
    if (pick) {
      try { TP.player.setQuality(pick.group || pick.name); } catch { /* ignore */ }
    }
  }

  /* The sheet's Player check: what the player is telling the app, live, so a
     problem on the phone can be screenshotted. */
  function renderPlayerCheck() {
    const at = (x) => (typeof x === "number" && Number.isFinite(x) ? fmtTime(x, true) : "?");
    const lines = [];
    if (mode === "direct" && DV.el) {
      const v = DV.el;
      const st = v.error ? `error ${v.error.code}` : v.paused ? "paused" : v.readyState < 3 ? "loading" : "playing";
      lines.push(`Direct ${DV.src ? `${DV.src.height}p` : ""} · ${st} · loaded ${v.readyState}/4`);
      lines.push(`video ${at(v.currentTime)} · app ${at(vodNow())}${DV.want != null ? " · waiting for Play" : ""}`);
    } else if (mode === "twitch" && TP.player) {
      let r = null;
      try { r = TP.player.getCurrentTime(); } catch { /* ignore */ }
      const st = TP.playing ? "playing" : TP.starting ? "starting" : "paused";
      lines.push(`Twitch · ${TP.ready ? "ready" : "not ready"} · says ${playbackState() || "nothing"} · ${st}`);
      lines.push(`twitch ${at(r)} · app ${at(vodNow())}${TP.want != null ? ` · seek to ${at(TP.want)} unconfirmed` : ""}`);
      if (DV.failed) lines.push(`direct stream failed (${DV.failed})`);
    } else {
      lines.push("No video");
    }
    lines.push(`events: ${PLOG.join(", ") || "none yet"}`);
    $("#player-check").textContent = lines.join("\n");
  }

  /* ---------- waveform tracks ---------- */
  // Every OBS track has its own waveform file. Any number can be shown at
  // once, each in its own lane and color; Mic alone is the default each time
  // the app opens, and a pick sticks for the rest of the session.

  let sessionView = null;

  function trackList(manifest) {
    if (Array.isArray(manifest.waveforms) && manifest.waveforms.length) return manifest.waveforms;
    const w = manifest.waveform || {};
    return [{ track: 0, label: "Mic", short: "Mic", file: w.file || "waveform.bin", size: w.size, rate: w.rate }];
  }

  const trackByNum = (n) => S.tracks.find((t) => t.track === n) || null;

  // Each track draws in its own color, so the waveform says which one it is.
  const TRACK_RGB = { "Mic": [34, 211, 238], "Game": [77, 168, 255], "Voice chat": [110, 231, 160],
    "VOD mix": [176, 124, 255], "Music": [244, 114, 182] };
  const rgbOf = (t) => TRACK_RGB[(t || {}).label] || TRACK_RGB.Mic;
  const rgba = (rgb, a) => `rgba(${rgb[0]}, ${rgb[1]}, ${rgb[2]}, ${a})`;

  // The shown tracks, in the manifest's order: [{t, w: {peaks, ref, rate} or undefined while loading, rgb}].
  function lanes() {
    const out = [];
    for (const n of S.view) {
      const t = trackByNum(n);
      if (t) out.push({ t, w: S.waveCache.get(t.file), rgb: rgbOf(t) });
    }
    return out;
  }

  const LANE_HEIGHTS = [112, 148, 176];      // the zoomed strip grows a little for more lanes

  // One download per waveform file per clip, shared by the lanes and the talk finder.
  function waveFor(t) {
    const clip = S.clip;
    if (S.waveCache.has(t.file)) return Promise.resolve(S.waveCache.get(t.file));
    const loads = S.waveLoads;
    let job = loads.get(t.file);
    if (!job) {
      job = (async () => {
        const peaks = new Uint8Array(await (await dbx.download(`${clip.folder}/${t.file}`)).arrayBuffer());
        const w = { peaks, ref: peakRef(peaks), rate: t.rate || 50 };
        if (S.clip === clip) S.waveCache.set(t.file, w);
        return w;
      })();
      loads.set(t.file, job);
      job.catch(() => {}).then(() => { if (loads.get(t.file) === job) loads.delete(t.file); });
    }
    return job;
  }

  async function showTracks(nums) {
    S.view = S.tracks.map((t) => t.track).filter((n) => nums.includes(n));
    if (!S.view.length) S.view = [S.tracks[0].track];
    const h = `${LANE_HEIGHTS[Math.min(S.view.length, LANE_HEIGHTS.length) - 1]}px`;
    if (dt.style.height !== h) {
      dt.style.height = h;
      resizeCanvases();
    }
    overviewBars = null;
    requestDraw();
    const clip = S.clip;
    await Promise.all(S.view.map(async (n) => {
      const t = trackByNum(n);
      if (!t || S.waveCache.has(t.file)) return;
      try {
        await waveFor(t);
      } catch (e) {
        if (S.clip !== clip) return;
        if (e instanceof AuthError) return needSignIn();
        toast(`Couldn't load the ${t.label} waveform. ${errText(e)}`);
        return;
      }
      if (S.clip !== clip) return;
      overviewBars = null;
      requestDraw();
    }));
  }

  /* ---------- settings sheet: waveforms, talking parts, video ---------- */

  let checkTimer = 0;

  function renderViewSheet() {
    const ul = $("#track-list");
    ul.replaceChildren();
    for (const t of S.tracks) {
      const on = S.view.includes(t.track);
      // Tap to add or remove a track; the last one stays.
      const b = button("", null, () => {
        if (on && S.view.length === 1) return;
        sessionView = on ? S.view.filter((n) => n !== t.track) : [...S.view, t.track];
        showTracks(sessionView);
        renderViewSheet();
      });
      b.setAttribute("aria-pressed", String(on));
      if (on) b.style.color = rgba(rgbOf(t), 1);
      b.append(el("span", null, t.label));
      b.append(el("span", "pick-sub", t.track ? `OBS track ${t.track}` : ""));
      const li = el("li");
      li.append(b);
      ul.append(li);
    }
    const blocker = directBlocker();
    for (const b of $$("[data-player]")) b.setAttribute("aria-pressed", String(b.dataset.player === mode));
    // A failed stream can be retried; no links or no HLS can't.
    $("[data-player='direct']").disabled = !!blocker && !DV.failed;
    $("#player-note").textContent = mode === "direct"
      ? "Direct plays the VOD in the phone's own player: exact time, nothing over the picture. Twitch is the backup."
      : blocker || "Twitch's own player, the backup. Direct is more exact.";
    for (const q of $$("[data-quality]")) q.setAttribute("aria-pressed", String(Number(q.dataset.quality) === S.quality));
    $("#speed-note").textContent = mode !== "direct" ? "Speed works with the Direct player."
      : topRate > 2 ? "Tap the speed button for 1x, your speed (hold it for 1.25x to 2x), then 4x."
        : "Tops out at 2x on this phone: Safari only plays a stream faster than 2x when the stream has fast-forward "
          + "tracks, and Twitch's VODs don't. The arrows by -10 and +10 skip the quiet parts instead.";
    $("#speed-retry").hidden = mode !== "direct" || topRate > 2;
    renderTalkCount();
    renderPlayerCheck();
  }

  function openViewSheet() {
    renderViewSheet();
    $("#sheet-view").hidden = false;
    clearInterval(checkTimer);
    checkTimer = setInterval(renderPlayerCheck, 500);
  }

  function closeViewSheet() {
    $("#sheet-view").hidden = true;
    clearInterval(checkTimer);
  }

  $("#settings").addEventListener("click", openViewSheet);
  $("#view-done").addEventListener("click", closeViewSheet);
  for (const q of $$("[data-quality]")) {
    q.addEventListener("click", () => {
      S.quality = Number(q.dataset.quality);
      store.set("ms.quality", S.quality);
      applyQuality();
      renderViewSheet();
    });
  }
  for (const b of $$("[data-player]")) {
    b.addEventListener("click", () => {
      const want = b.dataset.player;
      if (want === mode) return;
      playerPref = want;
      store.set("ms.player", want);
      if (want === "direct") DV.failed = null;       // try the stream again
      const at = S.dragClip != null ? clipToVod(S.dragClip) : vodNow();
      const resume = videoActive();
      startPlayer(at);
      if (resume) playVideo();
      renderViewSheet();
    });
  }

  function savePos() {
    if (!S.clip || !mode) return;
    const all = store.get("ms.vodpos", {}) || {};
    all[S.clip.id] = Math.round((S.dragClip != null ? clipToVod(S.dragClip) : vodNow()) * 10) / 10;
    store.set("ms.vodpos", all);
  }

  // What the marking and script screens share: the clip's clock, its markers,
  // the one video player (moved into the screen being opened), and the
  // check for changes from the PC.
  function enterClip(c, screen) {
    const token = ++S.openToken;
    const tw = (c.manifest && c.manifest.twitch) || {};
    S.clip = c;
    S.vodId = tw.vod_id || null;
    S.sync = Array.isArray(tw.sync) && tw.sync.length ? tw.sync : [{ clip: 0, vod: tw.start || 0 }];
    S.vodDuration = tw.vod_duration || 0;
    S.streams = (Array.isArray(tw.streams) ? tw.streams : [])
      .filter((s) => s && typeof s.url === "string" && /^https:\/\//.test(s.url) && s.height > 0);
    DV.failed = null;
    vzReset();
    S.markers = [];
    S.markersError = null;
    S.dragClip = null;
    S.moving = null;
    S.span = null;
    S.duration = c.duration || 0;
    nearId = null;
    show(screen);
    $(screen === "#screen-clip" ? ".clip-top" : "#script-video").prepend($("#video-box"));
    renderSync();
    return token;
  }

  function startClipVideo(c) {
    const saved = (store.get("ms.vodpos", {}) || {})[c.id];
    startPlayer(typeof saved === "number" ? saved : clipToVod(0));
  }

  async function loadClipMarkers(c, token) {
    try {
      await loadMarkers(c);
    } catch (e) {
      if (e instanceof AuthError) return needSignIn();
      S.markersError = errText(e);
    }
    if (token !== S.openToken) return;
    renderMarkers();
    requestDraw();
    clearInterval(syncTimer);
    syncTimer = setInterval(syncOpenClip, CFG.syncMs || 10000);
  }

  async function openClip(c) {
    const token = enterClip(c, "#screen-clip");
    S.waveCache = new Map();
    S.waveLoads = new Map();
    Object.assign(talk, { peaks: null, regions: [], atIndex: null, anchorAt: null, threshold: null });
    S.tracks = trackList(c.manifest);
    S.view = [];
    overviewBars = null;
    $("#clip-title").textContent = c.name;
    $("#t-dur").textContent = fmtTime(S.duration);
    setZoomLabel();
    renderMarkers("Loading markers");
    resizeCanvases();
    startClipVideo(c);
    requestDraw();
    ensureTags().catch(() => {});
    loadTalk();
    await showTracks(sessionView || [S.tracks[0].track]);
    if (token !== S.openToken) return;
    await loadClipMarkers(c, token);
  }

  // The script screen: the video when the clip has one on the phone, then
  // the script, with the markers on the other side of a switch.
  async function openScript(c) {
    const token = enterClip(c, "#screen-script");
    const video = hasVideo(c);
    $("#script-title").textContent = c.name;
    for (const id of ["#script-video", "#sv-transport", "#sc-insert", "#sc-goto"]) $(id).hidden = !video;
    $("#sv-novideo").hidden = video;
    $("#sv-novideo").textContent = c.state === "pc"
      ? "Marked on the PC, so its video is there, not here. The markers and both scripts are here."
      : "This clip's video isn't on the phone yet. The markers and both scripts are.";
    if (video) startClipVideo(c);
    else destroyPlayer();
    setView(c.files["script.md"] ? "script" : "beats");
    renderMarkers("Loading markers");
    requestDraw();
    ensureTags().catch(() => {});
    loadScript();
    await loadClipMarkers(c, token);
  }

  /* The clip editor's Markers tab writes to the same folder. While a clip is
     open, look for changes every 10 s and on coming back to the app: one
     folder listing, and only files whose revision changed are downloaded.
     Skipped while a marker is open or being moved, so nothing shifts under a
     finger; the next round picks it up. */
  let syncTimer = 0;
  let syncBusy = false;

  async function refreshTags() {
    if (editingTag || outbox.pendingFor("/tags.json").length) return false;
    const meta = await dbx.meta("/tags.json");
    if (!meta || meta.rev === tagsRev) return false;
    const [list] = normalizeTags((parseJson(await readText(meta)) || {}).tags);
    tagsRev = meta.rev;
    tagsLoaded = true;
    if (JSON.stringify(list) === JSON.stringify(tags)) return false;
    tags = list;
    return true;
  }

  async function syncOpenClip() {
    const c = S.clip;
    if (!c || syncBusy || document.hidden || ed || S.moving || !navigator.onLine) return;
    syncBusy = true;
    const token = S.openToken;
    const keep = S.markers;
    const key = (list) => list.map((m) => `${m.id}:${m.updated || ""}`).sort().join("|");
    try {
      const tagsChanged = await refreshTags();
      await loadMarkers(c);
      if (token !== S.openToken) return;
      if (ed || S.moving) {
        S.markers = keep;          // busy now; try again next round
        return;
      }
      if (tagsChanged || key(keep) !== key(S.markers)) {
        renderMarkers();
        requestDraw();
      } else {
        S.markers = keep;          // same markers: keep the objects the screen points at
      }
      if (current === "#screen-script") await loadScript();
    } catch (e) {
      if (token === S.openToken) S.markers = keep;
      if (e instanceof AuthError) needSignIn();
    } finally {
      syncBusy = false;
    }
  }

  function leaveClip() {
    saveScript();
    clearInterval(syncTimer);
    savePos();
    S.openToken++;
    destroyPlayer();
    S.clip = null;
  }

  $("#clip-back").addEventListener("click", () => {
    leaveClip();
    showClips("markers");
  });
  $("#script-back").addEventListener("click", () => {
    for (const d of Object.keys(DOCS)) DOCS[d].box.blur();
    leaveClip();
    showClips("script");
  });
  playBtn.addEventListener("click", togglePlay);
  $("#sv-play").addEventListener("click", togglePlay);
  for (const b of $$("[data-skip]")) b.addEventListener("click", () => seekVod(vodNow() + Number(b.dataset.skip)));

  /* ---------- talking parts ----------
     The clip editor's talk finder: wherever the mic waveform is louder than a
     threshold is talking, short blips are dropped and a breath doesn't split a
     sentence. The arrows beside -10 and +10 jump to the previous and next
     part, a moment early so the first word isn't cut off. The threshold is a
     fraction of this clip's loudest moment, suggested from the clip's own
     levels until the slider in the settings sheet sets it (then it stays). */

  const TALK = { MIN_S: 0.4, MERGE_S: 0.7, PREROLL_S: 0.3, FLOOR_PCT: 0.2, FLOOR_MULT: 2.5, TALK_FRAC: 0.06,
    LO: 0.005, HI: 0.6 };
  const talk = { peaks: null, rate: 50, max: 1, threshold: null, regions: [], atIndex: null, anchorAt: null };

  const micTrack = () => S.tracks.find((t) => t.label === "Mic") || null;

  // The slider runs 0 to 100, right is more sensitive (a lower threshold), on a
  // log scale so the useful middle isn't squeezed into one end.
  const sensToThr = (v) => Math.exp(Math.log(TALK.HI) + (Math.log(TALK.LO) - Math.log(TALK.HI)) * (v / 100));
  const thrToSens = (t) =>
    Math.round(clamp((Math.log(t) - Math.log(TALK.HI)) / (Math.log(TALK.LO) - Math.log(TALK.HI)), 0, 1) * 100);

  // The PC's suggestThreshold: clear of the room noise, or a fraction of
  // talking level, whichever is higher. The mic is gated, so the silence
  // between words is left out when measuring the noise.
  function suggestThreshold(p, max) {
    const hist = new Uint32Array(256);
    for (let i = 0; i < p.length; i++) hist[p[i]]++;
    const nth = (k) => {
      let acc = 0;
      for (let v = 0; v < 256; v++) {
        acc += hist[v];
        if (acc > k) return v;
      }
      return 255;
    };
    const loud = nth(Math.floor(p.length * 0.995)) / max || 1;
    const sounding = p.length - hist[0];
    const floor = sounding > 0 ? nth(hist[0] + Math.floor(sounding * TALK.FLOOR_PCT)) / max : 0;
    return clamp(Math.max(floor * TALK.FLOOR_MULT, loud * TALK.TALK_FRAC), TALK.LO, Math.max(0.01, loud * 0.6));
  }

  function findTalk() {
    talk.regions = [];
    talk.atIndex = null;
    talk.anchorAt = null;
    const p = talk.peaks;
    if (p) {
      const raw = talk.threshold * talk.max;
      const gap = TALK.MERGE_S * talk.rate;
      const min = TALK.MIN_S * talk.rate;
      const keep = (r) => {
        if (r && r[1] - r[0] >= min) talk.regions.push({ start: r[0] / talk.rate, end: r[1] / talk.rate });
      };
      let cur = null;
      let start = -1;
      for (let i = 0; i <= p.length; i++) {
        if (i < p.length && p[i] >= raw) {
          if (start < 0) start = i;
        } else if (start >= 0) {
          if (cur && start - cur[1] <= gap) cur[1] = i;        // a breath: same sentence
          else {
            keep(cur);
            cur = [start, i];
          }
          start = -1;
        }
      }
      keep(cur);
    }
    renderTalkCount();
    requestDraw();
  }

  async function loadTalk() {
    const clip = S.clip;
    const t = micTrack();
    if (!t) return renderTalkCount();
    let w;
    try {
      w = await waveFor(t);
    } catch {
      return;                     // the lanes say so; the arrows explain when pressed
    }
    if (S.clip !== clip) return;
    let max = 1;
    for (let i = 0; i < w.peaks.length; i++) if (w.peaks[i] > max) max = w.peaks[i];
    Object.assign(talk, { peaks: w.peaks, rate: w.rate, max });
    const saved = store.get("ms.talk", null);
    talk.threshold = typeof saved === "number" && saved >= TALK.LO && saved <= TALK.HI ? saved : suggestThreshold(w.peaks, max);
    findTalk();
  }

  function renderTalkCount() {
    const out = $("#talk-count");
    const input = $("#talk-sens");
    input.disabled = !talk.peaks;
    if (talk.threshold != null) input.value = String(thrToSens(talk.threshold));
    if (!talk.peaks) {
      out.textContent = micTrack() ? "loading the mic waveform" : "this clip has no mic waveform";
      return;
    }
    const total = talk.regions.reduce((a, r) => a + r.end - r.start, 0);
    out.textContent = talk.regions.length ? `${talk.regions.length} parts, ${fmtTime(total)} of talk` : "none at this sensitivity";
  }

  // Remembers where it sent the playhead, so pressing again goes on to the
  // next part rather than finding the same one (the jump lands a moment
  // before it). Anywhere else, it's the next one from the playhead.
  function jumpTalk(dir) {
    if (!S.clip) return;
    if (!talk.peaks) {
      toast(micTrack() ? "The mic waveform is still loading." : "This clip has no mic waveform to find talking in.");
      return;
    }
    const R = talk.regions;
    if (!R.length) {
      toast("No talking parts at this sensitivity. Turn it up with the gear button.");
      return;
    }
    const t = now();
    let i;
    if (Number.isInteger(talk.atIndex) && R[talk.atIndex] && talk.anchorAt != null && Math.abs(t - talk.anchorAt) < 0.5) {
      i = talk.atIndex + dir;
    } else {
      const x = t + TALK.PREROLL_S;
      if (dir > 0) i = R.findIndex((r) => r.start > x + 0.05);
      else {
        i = -1;
        for (let k = 0; k < R.length && R[k].start < x - 0.05; k++) i = k;
      }
    }
    if (i < 0 || i >= R.length) {
      toast(dir > 0 ? "No more talking after this." : "No talking before this.");
      return;
    }
    talk.atIndex = i;
    talk.anchorAt = Math.max(0, R[i].start - TALK.PREROLL_S);
    seekClip(talk.anchorAt);
  }

  for (const b of $$("[data-talk]")) b.addEventListener("click", () => jumpTalk(Number(b.dataset.talk)));
  $("#talk-sens").addEventListener("input", (e) => {
    if (!talk.peaks) return;
    talk.threshold = sensToThr(Number(e.target.value));
    findTalk();
  });
  $("#talk-sens").addEventListener("change", () => {
    if (talk.peaks && talk.threshold != null) store.set("ms.talk", talk.threshold);
  });

  /* ---------- video zoom ----------
     Pinch the video to zoom into it, even while it plays, and drag with one
     finger to look around while zoomed. Only the picture moves; the page, the
     waveforms and the buttons stay put. A tap still plays and pauses. The pill
     in the corner (or pinching back out) puts it back. Direct player only:
     Twitch's player is another site's frame and keeps its own touches. */
  const VZ = { s: 1, x: 0, y: 0, pts: new Map(), g: null, swallow: false };
  const vwrap = $(".video-wrap");
  const VZ_MAX = 6;

  function vzApply() {
    if (DV.el) DV.el.style.transform = VZ.s > 1 ? `translate(${VZ.x}px, ${VZ.y}px) scale(${VZ.s})` : "";
    const pill = $("#video-zoom");
    pill.hidden = VZ.s <= 1;
    pill.textContent = `${VZ.s.toFixed(1)}x · Reset`;
  }

  // Keeps the picture covering the whole box: no black gaps at the edges.
  function vzClamp() {
    const W = $("#player").clientWidth;
    const H = $("#player").clientHeight;
    VZ.s = clamp(VZ.s, 1, VZ_MAX);
    VZ.x = clamp(VZ.x, W - W * VZ.s, 0);
    VZ.y = clamp(VZ.y, H - H * VZ.s, 0);
  }

  function vzReset() {
    Object.assign(VZ, { s: 1, x: 0, y: 0, g: null });
    VZ.pts.clear();
    vzApply();
  }

  function vzPoint(e) {
    const r = $("#player").getBoundingClientRect();
    return { x: e.clientX - r.left, y: e.clientY - r.top };
  }

  // A gesture starts over whenever a finger comes or goes.
  function vzBegin() {
    const p = [...VZ.pts.values()];
    if (p.length >= 2) {
      const [a, b] = p;
      VZ.g = { pinch: true, d0: Math.max(10, Math.hypot(a.x - b.x, a.y - b.y)), s0: VZ.s,
        cx: ((a.x + b.x) / 2 - VZ.x) / VZ.s, cy: ((a.y + b.y) / 2 - VZ.y) / VZ.s };
      VZ.swallow = true;
    } else if (p.length === 1) {
      VZ.g = { pinch: false, p0: p[0], x0: VZ.x, y0: VZ.y, moved: VZ.swallow };
    } else {
      VZ.g = null;
    }
  }

  vwrap.addEventListener("pointerdown", (e) => {
    if (!VZ.pts.size) VZ.swallow = false;          // a new touch: only its own moves count
    if (mode !== "direct" || e.target.closest("#video-zoom")) return;
    VZ.pts.set(e.pointerId, vzPoint(e));
    try { vwrap.setPointerCapture(e.pointerId); } catch { /* ignore */ }
    vzBegin();
  });
  vwrap.addEventListener("pointermove", (e) => {
    if (!VZ.pts.has(e.pointerId) || !VZ.g) return;
    VZ.pts.set(e.pointerId, vzPoint(e));
    const g = VZ.g;
    const p = [...VZ.pts.values()];
    if (g.pinch && p.length >= 2) {
      // The spot of the picture that was between the fingers stays there.
      const [a, b] = p;
      VZ.s = clamp(g.s0 * (Math.hypot(a.x - b.x, a.y - b.y) / g.d0), 1, VZ_MAX);
      VZ.x = (a.x + b.x) / 2 - g.cx * VZ.s;
      VZ.y = (a.y + b.y) / 2 - g.cy * VZ.s;
    } else if (!g.pinch) {
      const dx = p[0].x - g.p0.x;
      const dy = p[0].y - g.p0.y;
      if (!g.moved && Math.hypot(dx, dy) < 8) return;
      g.moved = true;
      if (VZ.s <= 1) return;
      VZ.swallow = true;
      VZ.x = g.x0 + dx;
      VZ.y = g.y0 + dy;
    }
    vzClamp();
    vzApply();
  });
  const vzEnd = (e) => {
    if (!VZ.pts.delete(e.pointerId)) return;
    if (!VZ.pts.size && VZ.s < 1.05) {
      VZ.s = 1;
      VZ.x = 0;
      VZ.y = 0;
      vzApply();
    }
    vzBegin();
  };
  vwrap.addEventListener("pointerup", vzEnd);
  vwrap.addEventListener("pointercancel", vzEnd);
  // A pinch or a drag isn't a tap: the video's play/pause doesn't hear it.
  vwrap.addEventListener("click", (e) => {
    if (!VZ.swallow || e.target.closest("#video-zoom")) return;
    VZ.swallow = false;
    e.stopPropagation();
    e.preventDefault();
  }, true);
  $("#video-zoom").addEventListener("click", (e) => {
    e.stopPropagation();
    vzReset();
  });
  window.addEventListener("resize", () => {
    vzClamp();
    vzApply();
  });

  // No page zoom: a stray pinch used to zoom the whole page. The video (above)
  // and the waveform strip have their own.
  for (const name of ["gesturestart", "gesturechange", "gestureend"]) {
    document.addEventListener(name, (e) => e.preventDefault(), { passive: false });
  }

  /* ---------- zoom ---------- */
  // The zoomed strip shows S.zoom seconds across. − / + step through these;
  // pinching on the strip zooms smoothly between them.

  const ZOOM_STEPS = [5, 10, 20, 30, 60, 120, 300, 600, 1800, 3600];
  const ZOOM_MIN = 3;
  const ZOOM_MAX = 3600;

  function fmtSpan(s) {
    if (s < 60) return `${Math.round(s)}s`;
    if (s < 3600) return `${Math.round(s / 60)}m`;
    return `${Math.round(s / 3600)}h`;
  }

  function setZoomLabel() {
    $("#zoom-label").textContent = fmtSpan(S.zoom);
  }

  function setZoom(span, persist) {
    S.zoom = clamp(span, ZOOM_MIN, ZOOM_MAX);
    setZoomLabel();
    if (persist !== false) store.set("ms.zoom", S.zoom);
    requestDraw();
  }

  function zoomStep(dir) {
    // From wherever a pinch left it, step to the next preset that way.
    let next = dir > 0 ? ZOOM_STEPS.find((s) => s > S.zoom * 1.01) : [...ZOOM_STEPS].reverse().find((s) => s < S.zoom * 0.99);
    if (next == null) next = dir > 0 ? ZOOM_MAX : ZOOM_STEPS[0];
    setZoom(next);
  }

  for (const b of $$("[data-zoom-step]")) b.addEventListener("click", () => zoomStep(Number(b.dataset.zoomStep)));

  /* ---------- speed ---------- */
  // Tap steps 1x -> the chosen speed (2x to start) -> 4x -> 1x. Press and
  // hold for 1.25 to 2x, slide to one and let go: it plays at that speed and
  // becomes the tap's middle stop. Direct player only: Twitch's player can't
  // be sped up from outside. On a phone that can't do 4x (an iPhone, below)
  // the top stop is 2x.

  const RATES = [2, 1.75, 1.5, 1.25];
  const FAST = 4;
  let rate = 1;
  let altRate = 2;
  let topRate = FAST;
  const speedBtn = $("#speed");
  const speedMenu = $("#speed-menu");
  let speedPress = null;
  let speedSwallow = false;

  function applyRate() {
    if (!DV.el) return;
    try {
      DV.el.defaultPlaybackRate = rate;        // survives a reload (quality change)
      DV.el.playbackRate = rate;
    } catch { /* ignore */ }
  }

  function setRate(r) {
    rate = r;
    applyRate();
    renderSpeed();
  }

  function renderSpeed() {
    const on = mode === "direct";
    speedBtn.textContent = `${on ? rate : 1}x`;
    speedBtn.classList.toggle("on", on && rate !== 1);
    speedBtn.classList.toggle("off", !on);
    speedBtn.setAttribute("aria-label", on ? `Playback speed ${rate}x. Hold for other speeds.` : "Playback speed (Direct player only)");
  }

  /* An iPhone plays Twitch's stream at up to 2x: Safari's player only goes
     past 2x on a stream with fast-forward (I-frame) tracks, and Twitch's VODs
     have none (Apple's QA1772: rates over 2.0 need canPlayFastForward). Other
     phones may manage, so 4x is tried and its first 3 s of playing watched.
     If the video won't take 4x, stops by itself, or moves slower than 2.6x
     without stalling, that's the phone: it goes to 2x and remembers 2x as its
     top speed, so the button skips 4x from then on (the gear menu can try 4x
     again). Moving slowly because it keeps stalling is the connection: 2x for
     now, nothing remembered. Stalls don't restart the watch (they used to,
     so a 4x that kept stalling was never caught). Each verdict goes to
     logs/phone-speed.json in Dropbox, to look at on the PC. */
  const FW = { v: null, timer: 0, t0: 0, at0: 0, stalls: 0, playAt: -1e9, pausedAt: -1e9 };

  function stopFastWatch() {
    clearInterval(FW.timer);
    FW.v = null;
  }

  function checkFast() {
    stopFastWatch();
    const v = DV.el;
    if (rate <= 2 || mode !== "direct" || !v) return;
    if (Math.abs(v.playbackRate - rate) > 0.01) {
      fastCapped("rate not taken", null, false);
      return;
    }
    if (v.paused || v.seeking || v.readyState < 3) return;     // watched from "playing"
    Object.assign(FW, { v, t0: v.currentTime, at0: performance.now(), stalls: 0 });
    FW.timer = setInterval(() => {
      if (FW.v !== v || DV.el !== v || rate <= 2) {
        stopFastWatch();
        return;
      }
      const secs = (performance.now() - FW.at0) / 1000;
      if (v.paused || secs < 3) return;
      const speed = (v.currentTime - FW.t0) / secs;
      const stalls = FW.stalls;
      stopFastWatch();
      if (speed >= 2.6) fastLog("ok", speed, stalls);
      else if (stalls) fastSlow(speed, stalls);
      else fastCapped("plays slower", speed, false);
    }, 250);
  }

  function fastCapped(why, speed, resume) {
    stopFastWatch();
    fastLog(why, speed, 0);
    topRate = 2;
    store.set("ms.topRate", 2);
    setRate(2);
    if (resume && DV.el && DV.el.paused) directPlay();
    toast("This phone plays Twitch's stream at up to 2x, so the speed button stops at 2x now. The gear button says why.");
  }

  function fastSlow(speed, stalls) {
    fastLog("kept stalling", speed, stalls);
    setRate(2);
    toast("4x kept stopping to load, so it's at 2x. A lower video quality (gear button) gives it more room.");
  }

  function fastLog(why, speed, stalls) {
    const v = DV.el;
    const list = store.get("ms.speedlog", []) || [];
    list.push({ when: new Date().toISOString(), why, speed: speed == null ? null : Math.round(speed * 100) / 100, stalls,
      asked: rate, took: v ? v.playbackRate : null, quality: DV.src ? DV.src.height : null, browser: navigator.userAgent });
    while (list.length > 30) list.shift();
    store.set("ms.speedlog", list);
    outbox.put("/logs/phone-speed.json", JSON.stringify({ entries: list }, null, 1));
  }

  $("#speed-retry").addEventListener("click", () => {
    topRate = FAST;
    store.del("ms.topRate");
    renderViewSheet();
    toast("The speed button goes to 4x again. If this phone still can't, it drops back to 2x.");
  });

  function openSpeedMenu() {
    for (const o of speedMenu.querySelectorAll("[data-rate]")) {
      o.setAttribute("aria-checked", String(Number(o.dataset.rate) === altRate));
      o.classList.remove("hover");
    }
    speedMenu.hidden = false;
    const r = speedBtn.getBoundingClientRect();
    const w = speedMenu.offsetWidth;
    speedMenu.style.left = `${clamp(r.left + r.width / 2 - w / 2, 8, window.innerWidth - w - 8)}px`;
    speedMenu.style.top = `${Math.max(8, r.top - speedMenu.offsetHeight - 8)}px`;
  }

  function speedOptionAt(e) {
    const hit = document.elementFromPoint(e.clientX, e.clientY);
    return hit && hit.closest ? hit.closest("#speed-menu [data-rate]") : null;
  }

  speedBtn.addEventListener("pointerdown", (e) => {
    if (mode !== "direct") return;
    try { speedBtn.setPointerCapture(e.pointerId); } catch { /* ignore */ }
    const press = { id: e.pointerId, menu: false };
    press.hold = setTimeout(() => {
      if (speedPress !== press) return;
      press.menu = true;
      openSpeedMenu();
    }, 400);
    speedPress = press;
  });
  speedBtn.addEventListener("pointermove", (e) => {
    if (!speedPress || !speedPress.menu) return;
    const o = speedOptionAt(e);
    for (const x of speedMenu.querySelectorAll("[data-rate]")) x.classList.toggle("hover", x === o);
  });
  const speedEnd = (e, cancelled) => {
    const p = speedPress;
    speedPress = null;
    if (!p) return;
    clearTimeout(p.hold);
    if (!p.menu) return;                       // a tap: the click does it
    speedSwallow = true;
    const o = cancelled ? null : speedOptionAt(e);
    speedMenu.hidden = true;
    if (o) {
      altRate = Number(o.dataset.rate);
      store.set("ms.speed", altRate);
      setRate(altRate);
    }
  };
  speedBtn.addEventListener("pointerup", (e) => speedEnd(e, false));
  speedBtn.addEventListener("pointercancel", (e) => speedEnd(e, true));
  speedBtn.addEventListener("contextmenu", (e) => e.preventDefault());
  speedBtn.addEventListener("click", () => {
    if (speedSwallow) {
      speedSwallow = false;
      return;
    }
    if (mode !== "direct") {
      toast("Speed works with the Direct player (the gear button, Video player).");
      return;
    }
    setRate(rate === 1 ? altRate : rate < topRate ? topRate : 1);
    checkFast();
  });

  /* ---------- volume ----------
     The slider sets how loud the video plays (a square curve, so the middle
     sounds about half as loud) and the speaker mutes. The level is
     remembered, mute isn't. An iPhone won't let a web page set a video's
     volume, only its side buttons can, so there it's the speaker alone. (Web
     Audio could do it, but only on a stream the page may read, and Twitch's
     video servers allow that for twitch.tv only. Checked 2026-10-03.) */
  const VOL = { v: 1, muted: false };
  const SPEAKER = {
    on: '<path d="M4 9h4l5-4v14l-5-4H4z"/><path d="M16.5 8.5a5 5 0 0 1 0 7"/><path d="M19 6a8.5 8.5 0 0 1 0 12"/>',
    low: '<path d="M4 9h4l5-4v14l-5-4H4z"/><path d="M16.5 8.5a5 5 0 0 1 0 7"/>',
    off: '<path d="M4 9h4l5-4v14l-5-4H4z"/><path d="M17 9l5 6"/><path d="M22 9l-5 6"/>',
  };

  let nativeVol = null;
  function canSetVolume() {
    if (nativeVol == null) {
      try {
        const a = document.createElement("audio");
        a.volume = 0.5;
        nativeVol = Math.abs(a.volume - 0.5) < 0.01;      // an iPhone keeps it at 1
      } catch {
        nativeVol = false;
      }
      if (CFG.debug && store.get("ms.likeIphone", false)) nativeVol = false;    // automated tests
    }
    return nativeVol;
  }

  function renderVolume() {
    const slider = canSetVolume();
    const level = slider ? VOL.v : 1;
    $(".vol").classList.toggle("mute-only", !slider);
    $("#mute svg").innerHTML = SPEAKER[VOL.muted || level === 0 ? "off" : level < 0.5 ? "low" : "on"];
    $("#mute").setAttribute("aria-label", VOL.muted ? "Unmute" : "Mute");
    $("#mute").classList.toggle("on", VOL.muted);
    $("#volume").value = String(Math.round(VOL.v * 100));
  }

  function applyVolume() {
    renderVolume();
    const gain = canSetVolume() ? VOL.v * VOL.v : 1;
    if (mode === "twitch") {
      try {
        TP.player.setVolume(gain);
        TP.player.setMuted(VOL.muted);
      } catch { /* not loaded yet; sent again when it's ready */ }
    } else if (DV.el) {
      DV.el.muted = VOL.muted;
      if (canSetVolume()) DV.el.volume = gain;
    }
  }

  $("#volume").addEventListener("input", (e) => {
    VOL.v = Number(e.target.value) / 100;
    VOL.muted = false;
    store.set("ms.volume", VOL.v);
    applyVolume();
  });
  $("#mute").addEventListener("click", () => {
    VOL.muted = !VOL.muted;
    applyVolume();
  });

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
  const amp = (v, ref) => Math.sqrt(Math.min(1, v / ref));

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
    const marking = current === "#screen-clip";
    if (!marking && current !== "#screen-script") return;
    reconcile();
    const t = now();
    if (dirty || t !== lastDrawn) {
      dirty = false;
      lastDrawn = t;
      if (marking) {
        drawOverview(t);
        drawDetail(t);
        $("#t-now").textContent = fmtTime(t, true);
      } else {
        $("#sv-now").textContent = fmtTime(t, true);
      }
      updateNear(t);
    }
    const active = videoActive();
    if (active && performance.now() - S.posSaved > 3000) {
      S.posSaved = performance.now();
      savePos();
    }
    if (active || S.dragClip != null) raf = requestAnimationFrame(frame);
  }

  function drawOverview(t) {
    const W = ov.width;
    const H = ov.height;
    const c = octx;
    c.clearRect(0, 0, W, H);
    const dur = S.duration;
    if (!dur) return;
    const L = lanes();
    const laneH = H / Math.max(1, L.length);
    if (!overviewBars || overviewBars.W !== W) overviewBars = { W, by: new Map() };
    L.forEach((lane, i) => {
      if (!lane.w) return;
      let bars = overviewBars.by.get(lane.t.file);
      if (!bars) {
        const { peaks: p, rate, ref } = lane.w;
        const n = p.length;
        bars = new Float32Array(W);
        for (let x = 0; x < W; x++) {
          const a = Math.floor((x / W) * dur * rate);
          const b = Math.max(a + 1, Math.floor(((x + 1) / W) * dur * rate));
          let m = 0;
          for (let j = a; j < b && j < n; j++) if (p[j] > m) m = p[j];
          bars[x] = amp(m, ref);
        }
        overviewBars.by.set(lane.t.file, bars);
      }
      const mid = laneH * i + laneH / 2;
      const half = laneH / 2 - (L.length > 1 ? 1 : 2);
      c.fillStyle = rgba(lane.rgb, 0.7);
      for (let x = 0; x < W; x++) {
        const h = Math.max(0.5, bars[x] * half);
        c.fillRect(x, mid - h, 1, h * 2);
      }
    });
    const x0 = ((t - S.zoom / 2) / dur) * W;
    const x1 = ((t + S.zoom / 2) / dur) * W;
    c.fillStyle = "rgba(230, 237, 243, 0.12)";
    c.fillRect(x0, 0, Math.max(3, x1 - x0), H);
    const unit = Math.max(1, Math.round(W / 390));
    for (const m of S.markers) {
      const r = mRegion(m);
      if (!r) continue;
      c.globalAlpha = passesFilter(m) ? 0.35 : 0.1;
      c.fillStyle = colorHex(m.color);
      c.fillRect((r[0] / dur) * W, H * 0.2, Math.max(unit, ((r[1] - r[0]) / dur) * W), H * 0.6);
    }
    for (const m of S.markers) {
      if (S.moving && S.moving.m === m) continue;
      c.globalAlpha = passesFilter(m) ? 1 : 0.25;
      c.fillStyle = colorHex(m.color);
      c.fillRect(Math.round((mClip(m) / dur) * W - unit / 2), 0, unit, H);
    }
    c.globalAlpha = 1;
    c.fillStyle = "#ffffff";
    c.fillRect(Math.round((t / dur) * W - unit), 0, unit * 2, H);
    if (S.moving) {
      const x = Math.round((S.moving.at / dur) * W);
      c.fillStyle = "#fde68a";
      c.fillRect(x - unit * 1.5, 0, unit * 3, H);
    }
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
    const dur = S.duration;

    if (dur) {
      c.fillStyle = "rgba(255, 255, 255, 0.035)";
      if (t0 < 0) c.fillRect(0, top, -t0 * pps, H - top);
      const endX = (dur - t0) * pps;
      if (endX < W) c.fillRect(endX, top, W - endX, H - top);
    }

    // Talking parts, faintly: what the arrows by -10 and +10 jump between.
    c.fillStyle = "rgba(230, 237, 243, 0.07)";
    for (const r of talk.regions) {
      if (r.end < t0) continue;
      if (r.start > t0 + span) break;
      const a = Math.max(0, (r.start - t0) * pps);
      const b = Math.min(W, (r.end - t0) * pps);
      c.fillRect(a, top, Math.max(1, b - a), H - top);
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

    // One lane per shown track, each in its own color.
    const L = lanes();
    const laneH = (H - top) / Math.max(1, L.length);
    const bw = Math.max(1, Math.round(dpr));
    L.forEach((lane, i) => {
      const y0 = top + laneH * i;
      const mid = Math.round(y0 + laneH / 2);
      const half = laneH / 2 - 3 * dpr;
      if (i > 0) {
        c.fillStyle = "#30363d";
        c.fillRect(0, Math.round(y0), W, Math.max(1, Math.round(dpr)));
      }
      c.fillStyle = "#21262d";
      c.fillRect(0, mid, W, Math.max(1, Math.round(dpr)));
      if (lane.w) {
        const { peaks: p, rate, ref } = lane.w;
        const n = p.length;
        c.fillStyle = rgba(lane.rgb, 1);
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
          for (let j = a; j < b; j++) if (p[j] > m) m = p[j];
          const h = Math.max(0.5 * dpr, amp(m, ref) * half);
          c.fillRect(x, mid - h, bw, h * 2);
        }
      }
      if (L.length > 1) {
        // Lane name on a dark tab so it reads over its own waveform.
        const name = lane.t.short || lane.t.label;
        c.font = `700 ${Math.round(10 * dpr)}px -apple-system, system-ui, sans-serif`;
        const w = c.measureText(name).width + 8 * dpr;
        c.fillStyle = "rgba(13, 17, 23, 0.85)";
        c.fillRect(2 * dpr, y0 + 2 * dpr, w, 14 * dpr);
        c.fillStyle = rgba(lane.rgb, 1);
        c.fillText(name, 6 * dpr, y0 + 4 * dpr);
      }
    });

    const flag = (x, color) => {
      c.fillStyle = color;
      c.fillRect(x - dpr, top, 2 * dpr, H - top);
      c.beginPath();
      c.moveTo(x - dpr, top);
      c.lineTo(x + 10 * dpr, top + 5 * dpr);
      c.lineTo(x - dpr, top + 10 * dpr);
      c.closePath();
      c.fill();
    };
    // Clips: a tinted band from where each marker's clip starts to where it ends.
    for (const m of S.markers) {
      const r = mRegion(m);
      if (!r || r[1] < t0 || r[0] > t0 + span) continue;
      const a = Math.max(0, (r[0] - t0) * pps);
      const b = Math.min(W, (r[1] - t0) * pps);
      const dim = passesFilter(m) ? 1 : 0.35;
      c.fillStyle = colorHex(m.color);
      c.globalAlpha = 0.2 * dim;
      c.fillRect(a, top, Math.max(2 * dpr, b - a), H - top);
      c.globalAlpha = 0.9 * dim;
      c.fillRect(a, top, Math.max(2 * dpr, b - a), 2 * dpr);
      if (r[0] >= t0) c.fillRect(a, top, 2 * dpr, H - top);
      if (r[1] <= t0 + span) c.fillRect(b - 2 * dpr, top, 2 * dpr, H - top);
    }
    c.globalAlpha = 1;
    for (const m of S.markers) {
      if (S.moving && S.moving.m === m) continue;
      const mt = mClip(m);
      if (mt < t0 || mt > t0 + span) continue;
      c.globalAlpha = passesFilter(m) ? 1 : 0.3;
      flag(Math.round((mt - t0) * pps), colorHex(m.color));
    }
    c.globalAlpha = 1;
    // A clip being set: its length over the marker.
    if (S.span) {
      const r = mRegion(S.span.m);
      const x = Math.round((mClip(S.span.m) - t0) * pps);
      const label = r ? fmtLen(r[1] - r[0]) : "0s";
      c.font = `700 ${Math.round(12 * dpr)}px ui-monospace, Menlo, monospace`;
      const tw = c.measureText(label).width + 10 * dpr;
      const lx = clamp(x - tw / 2, 0, W - tw);
      c.fillStyle = colorHex(S.span.m.color);
      c.fillRect(lx, 0, tw, top - 2 * dpr);
      c.fillStyle = "#0d1117";
      c.fillText(label, lx + 5 * dpr, 2 * dpr);
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

    // A marker being moved: brighter, wider, with where it'll land.
    if (S.moving && S.moving.at >= t0 && S.moving.at <= t0 + span) {
      const x = Math.round((S.moving.at - t0) * pps);
      c.fillStyle = "rgba(253, 230, 138, 0.18)";
      c.fillRect(x - 8 * dpr, top, 16 * dpr, H - top);
      flag(x, "#fde68a");
      c.fillRect(x - 2 * dpr, top, 4 * dpr, H - top);
      const label = fmtTime(S.moving.at, true);
      c.font = `700 ${Math.round(12 * dpr)}px ui-monospace, Menlo, monospace`;
      const tw = c.measureText(label).width + 10 * dpr;
      const lx = clamp(x - tw / 2, 0, W - tw);
      c.fillStyle = "#fde68a";
      c.fillRect(lx, 0, tw, top - 2 * dpr);
      c.fillStyle = "#0d1117";
      c.fillText(label, lx + 5 * dpr, 2 * dpr);
    }
  }

  /* Scrubbing: dragging either strip pauses playback, moves the picture along
     with your finger, and picks playback back up when you let go. The phone's
     own player can take a quick seek every few frames; every Twitch seek
     re-buffers, so Twitch gets one about twice a second plus one when you
     rest, or it would only stutter. The exact seek comes on release. */
  const SCRUB = { active: false, resume: false, last: 0, timer: 0 };

  function scrubStart() {
    if (SCRUB.active) return;
    SCRUB.active = true;
    SCRUB.resume = videoActive();
    if (SCRUB.resume) pauseVideo();
  }

  function scrubTo(c) {
    S.dragClip = clamp(c, 0, S.duration);
    requestDraw();
    clearTimeout(SCRUB.timer);
    const t = performance.now();
    if (t - SCRUB.last > (mode === "direct" ? 120 : 450)) {
      SCRUB.last = t;
      seekVod(clipToVod(S.dragClip), true);
    } else {
      SCRUB.timer = setTimeout(() => {
        if (S.dragClip == null) return;
        SCRUB.last = performance.now();
        seekVod(clipToVod(S.dragClip), true);
      }, 160);
    }
  }

  function scrubEnd(c) {
    clearTimeout(SCRUB.timer);
    S.dragClip = null;
    if (c != null) seekClip(c);
    else requestDraw();
    if (SCRUB.active && SCRUB.resume) playVideo();
    SCRUB.active = false;
  }

  function capture(cv, e) {
    try { cv.setPointerCapture(e.pointerId); } catch { /* synthetic or already gone */ }
  }

  /* Moving a marker: press and hold its flag on either waveform until it
     lifts, slide, let go. Playback pauses while it's held. */
  const HOLD_MS = 450;

  // The marker whose flag is under the finger, if any.
  function markerAt(cv, clientX, slop) {
    const r = cv.getBoundingClientRect();
    const center = now();
    const xOf = cv === dt
      ? (mt) => r.left + ((mt - center) / S.zoom + 0.5) * r.width
      : (mt) => r.left + (mt / S.duration) * r.width;
    let best = null;
    let bestD = slop;
    for (const m of S.markers) {
      const d = Math.abs(xOf(mClip(m)) - clientX);
      if (d <= bestD) {
        bestD = d;
        best = m;
      }
    }
    return best;
  }

  function pickUp(m) {
    const resume = videoActive();
    if (resume) pauseVideo();
    S.moving = { m, from: mClip(m), at: mClip(m), resume };
    if (navigator.vibrate) navigator.vibrate(12);
    holdRow(m.id);
    requestDraw();
  }

  /* The marker being held is lit up in the list and scrolled into view, and
     after a move the list follows it to its new place for a moment. */
  let heldId = null;
  let heldTimer = 0;

  function holdRow(id) {
    clearTimeout(heldTimer);
    heldId = id;
    for (const li of $$("#markers .mrow")) li.classList.toggle("held", li.dataset.id === id);
    revealRow(id);
  }

  function letGoRow(id, moved) {
    if (moved) holdRow(id);
    clearTimeout(heldTimer);
    heldTimer = setTimeout(() => {
      heldId = null;
      for (const li of $$("#markers .mrow.held")) li.classList.remove("held");
    }, moved ? 1500 : 0);
  }

  // Scrolls the marker list only (never the screen) so the row is in view,
  // centered when it has to move.
  function revealRow(id) {
    const box = $("#screen-clip .markers-wrap");
    const row = box.querySelector(`.mrow[data-id="${CSS.escape(id)}"]`);
    if (!row) return;
    const b = box.getBoundingClientRect();
    const r = row.getBoundingClientRect();
    if (r.top >= b.top && r.bottom <= b.bottom) return;
    box.scrollTo({ top: box.scrollTop + (r.top - b.top) - (b.height - r.height) / 2, behavior: "smooth" });
  }

  function moveTo(c) {
    if (!S.moving) return;
    S.moving.at = clamp(c, 0, S.duration);
    requestDraw();
  }

  // Moved on the phone: back on the VOD clock, whoever placed it.
  function placeMarker(m, c) {
    const v = Math.round(clipToVod(c) * 1000) / 1000;
    delete m.clock;
    m.vod_time = v;
    m.vod_id = m.vod_id || S.vodId;
    m.timestamp = Math.round(vodToClip(v) * 1000) / 1000;
    persistMarker(m);
  }

  function drop(cancel) {
    const mv = S.moving;
    S.moving = null;
    if (!mv) return;
    const moved = !cancel && Math.abs(mv.at - mv.from) >= 0.05;
    if (moved) {
      const m = mv.m;
      const before = { had: typeof m.vod_time === "number", vod_time: m.vod_time, vod_id: m.vod_id,
        timestamp: m.timestamp, clock: m.clock };
      placeMarker(m, mv.at);
      sortMarkers();
      renderMarkers();
      toast(`Marker moved to ${fmtTime(mClip(m), true)}`, {
        label: "Undo",
        run: () => {
          if (before.had) Object.assign(m, { vod_time: before.vod_time, vod_id: before.vod_id });
          else delete m.vod_time;
          if (before.clock) m.clock = before.clock;
          m.timestamp = before.timestamp;
          persistMarker(m);
          if (S.clip && S.clip.id === m.clip_id) {
            sortMarkers();
            renderMarkers();
            requestDraw();
          }
        },
      });
    }
    letGoRow(mv.m.id, moved);
    requestDraw();
    if (mv.resume) playVideo();
  }

  // Overview: tap or drag anywhere to jump. On a marker's flag, a hold moves
  // the marker instead; so there it waits to see which it is.
  let ovDrag = false;
  let ovPress = null;
  function ovTime(e) {
    const r = ov.getBoundingClientRect();
    return clamp((e.clientX - r.left) / r.width, 0, 1) * S.duration;
  }
  ov.addEventListener("pointerdown", (e) => {
    if (!S.duration) return;
    capture(ov, e);
    const m = markerAt(ov, e.clientX, 12);
    if (m) {
      const press = { id: e.pointerId, x: e.clientX, moving: false };
      press.hold = setTimeout(() => {
        if (ovPress !== press) return;
        press.moving = true;
        pickUp(m);
      }, HOLD_MS);
      ovPress = press;
      return;
    }
    ovDrag = true;
    scrubStart();
    scrubTo(ovTime(e));
  });
  ov.addEventListener("pointermove", (e) => {
    if (ovPress && e.pointerId === ovPress.id) {
      if (ovPress.moving) {
        moveTo(ovTime(e));
        return;
      }
      if (Math.abs(e.clientX - ovPress.x) < 6) return;
      clearTimeout(ovPress.hold);         // moved first: it's a scrub
      ovPress = null;
      ovDrag = true;
      scrubStart();
    }
    if (ovDrag) scrubTo(ovTime(e));
  });
  const ovEnd = (e, cancelled) => {
    if (ovPress) {
      const p = ovPress;
      ovPress = null;
      clearTimeout(p.hold);
      if (p.moving) drop(cancelled);
      else if (!cancelled) seekClip(ovTime(e));
      return;
    }
    if (!ovDrag) return;
    ovDrag = false;
    scrubEnd(S.dragClip);
  };
  ov.addEventListener("pointerup", (e) => ovEnd(e, false));
  ov.addEventListener("pointercancel", (e) => ovEnd(e, true));

  // Zoomed strip: drag the waveform under the fixed playhead to scrub, tap to
  // jump there, pinch with two fingers to zoom, hold a marker's flag to move it.
  const touches = new Map();
  let dd = null;
  let pinch = null;

  const spread = () => {
    const [a, b] = [...touches.values()];
    return Math.max(16, Math.hypot(a.x - b.x, a.y - b.y));
  };

  function ddTime(e) {
    const r = dt.getBoundingClientRect();
    return dd.t + ((e.clientX - r.left) / r.width - 0.5) * S.zoom;
  }

  dt.addEventListener("pointerdown", (e) => {
    if (!S.duration) return;
    capture(dt, e);
    touches.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (touches.size === 2) {
      // A second finger turns it into a pinch; the first finger's drag or move is dropped.
      if (dd) {
        clearTimeout(dd.hold);
        if (dd.region) endSpan(true);
        else if (dd.moving) drop(true);
        else if (dd.moved) {
          S.dragClip = null;
          requestDraw();
        }
      }
      dd = null;
      pinch = { start: spread(), zoom: S.zoom };
      return;
    }
    if (touches.size !== 1) return;
    const press = { id: e.pointerId, x: e.clientX, t: now(), moved: false, moving: false, hold: 0 };
    const m = markerAt(dt, e.clientX, 16);
    // The second tap of a double tap on a flag: lift and the marker opens;
    // keep the finger down and drag, and it sets the marker's clip.
    if (m && flagTap && flagTap.m === m && performance.now() - flagTap.at < DOUBLE_MS) {
      clearTimeout(flagTap.timer);
      flagTap = null;
      press.second = m;
      dd = press;
      return;
    }
    press.flag = m;
    if (m) {
      press.hold = setTimeout(() => {
        if (dd !== press || press.moved) return;
        press.moving = true;
        pickUp(m);
        press.t = now();                   // the strip stops where it is
      }, HOLD_MS);
    }
    dd = press;
  });
  dt.addEventListener("pointermove", (e) => {
    if (!touches.has(e.pointerId)) return;
    touches.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (pinch && touches.size === 2) {
      setZoom(pinch.zoom * (pinch.start / spread()), false);
      return;
    }
    if (!dd || e.pointerId !== dd.id) return;
    if (dd.second && !dd.region) {
      if (Math.abs(e.clientX - dd.x) < 6) return;
      dd.region = true;
      startSpan(dd.second);
    }
    if (dd.region) {
      spanTo(ddTime(e));
      return;
    }
    if (dd.moving) {
      moveTo(ddTime(e));
      return;
    }
    const dx = e.clientX - dd.x;
    if (!dd.moved && Math.abs(dx) < 6) return;
    clearTimeout(dd.hold);
    if (!dd.moved) scrubStart();
    dd.moved = true;
    scrubTo(dd.t - (dx * S.zoom) / dt.clientWidth);
  });
  function ddEnd(e, cancelled) {
    touches.delete(e.pointerId);
    if (pinch) {
      if (touches.size < 2) {
        pinch = null;
        store.set("ms.zoom", S.zoom);
      }
      return;
    }
    if (!dd || e.pointerId !== dd.id) return;
    clearTimeout(dd.hold);
    if (dd.region) {
      endSpan(cancelled);
    } else if (dd.second) {
      if (!cancelled) editFromWave(dd.second);
    } else if (dd.moving) {
      drop(cancelled);
    } else if (dd.moved) {
      scrubEnd(S.dragClip);
    } else if (!cancelled && dd.flag) {
      // A tap on a flag waits a moment: a second tap makes it a double tap.
      const c = ddTime(e);
      const tap = { m: dd.flag, at: performance.now() };
      tap.timer = setTimeout(() => {
        if (flagTap === tap) flagTap = null;
        seekClip(c);
      }, DOUBLE_MS);
      flagTap = tap;
    } else if (!cancelled) {
      seekClip(ddTime(e));
    }
    dd = null;
  }
  dt.addEventListener("pointerup", (e) => ddEnd(e, false));
  dt.addEventListener("pointercancel", (e) => ddEnd(e, true));
  for (const cv of [ov, dt]) cv.addEventListener("contextmenu", (e) => e.preventDefault());

  /* ---------- clips (regions) ----------
     LosslessCut-style: a marker can carry a clip, from a little before it to
     a little after. Double-tap its flag on the zoomed waveform and, on the
     second tap, keep the finger down and drag: left of the marker sets where
     the clip starts, right of it where it ends. Saved as pre / post (seconds
     before and after the marker), so it moves with the marker. The clip
     editor's Markers tab exports them; in Premiere they're range markers.
     A plain double tap (no drag) opens the marker instead. */
  const DOUBLE_MS = 300;
  let flagTap = null;                 // {m, at, timer}: a tap on a flag, waiting for a second

  // Double-tapped: the marker opens, paused like + Marker, playing on after.
  function editFromWave(m) {
    const resume = videoActive();
    if (resume) pauseVideo();
    swallowClick();
    openEditor(m, resume);
  }

  const spanOf = (v) => (typeof v === "number" && v > 0 && v < 1e7 ? v : 0);
  const fmtLen = (sec) => (sec < 60 ? `${sec.toFixed(1)}s` : fmtTime(sec));

  function mRegion(m) {
    const live = S.span && S.span.m === m ? S.span : m;
    const pre = spanOf(live.pre);
    const post = spanOf(live.post);
    if (!(pre || post)) return null;
    const t = S.moving && S.moving.m === m ? S.moving.at : mClip(m);
    return [Math.max(0, t - pre), Math.min(S.duration || Infinity, t + post)];
  }

  function startSpan(m) {
    const resume = videoActive();
    if (resume) pauseVideo();
    S.span = { m, pre: spanOf(m.pre), post: spanOf(m.post), resume, moved: false };
    if (navigator.vibrate) navigator.vibrate(12);
    holdRow(m.id);
    requestDraw();
  }

  function spanTo(c) {
    const sp = S.span;
    if (!sp) return;
    const t = mClip(sp.m);
    c = clamp(c, 0, S.duration);
    if (c < t) sp.pre = t - c;
    else sp.post = c - t;
    sp.moved = true;
    requestDraw();
  }

  function setSpan(m, pre, post) {
    pre = Math.round(spanOf(pre) * 1000) / 1000;
    post = Math.round(spanOf(post) * 1000) / 1000;
    if (pre) m.pre = pre;
    else delete m.pre;
    if (post) m.post = post;
    else delete m.post;
  }

  function endSpan(cancel) {
    const sp = S.span;
    S.span = null;
    if (!sp) return;
    const m = sp.m;
    const before = { pre: spanOf(m.pre), post: spanOf(m.post) };
    const changed = Math.abs(sp.pre - before.pre) > 0.01 || Math.abs(sp.post - before.post) > 0.01;
    if (!cancel && sp.moved && changed) {
      setSpan(m, sp.pre, sp.post);
      persistMarker(m);
      renderMarkers();
      const r = mRegion(m);
      toast(r ? `Clip ${fmtTime(r[0], true)} to ${fmtTime(r[1], true)} (${fmtLen(r[1] - r[0])})` : "Clip removed", {
        label: "Undo",
        run: () => {
          setSpan(m, before.pre, before.post);
          persistMarker(m);
          if (S.clip && S.clip.id === m.clip_id) {
            renderMarkers();
            requestDraw();
          }
        },
      });
    }
    letGoRow(m.id, !cancel && sp.moved && changed);
    requestDraw();
    if (sp.resume) playVideo();
  }

  /* ---------- markers ---------- */

  let nearId = null;

  const newId = () => `m${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
  const sortMarkers = () => S.markers.sort((a, b) => mClip(a) - mClip(b));
  const seekMarker = (m) => (onClipClock(m) ? seekClip(m.timestamp) : seekVod(m.vod_time));

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

  /* Filter: show only markers with any of the picked tags ("No tag" counts as
     one). It stays set while the app is open; markers it hides are dimmed on
     the waveforms rather than removed. */
  const NO_TAG = "__none";
  const markerFilter = new Set();
  let filterOpen = false;

  function passesFilter(m) {
    if (!markerFilter.size) return true;
    const ts = markerTags(m);
    return ts.length ? ts.some((t) => markerFilter.has(t.id)) : markerFilter.has(NO_TAG);
  }

  // The marking screen and the script screen's Markers each have a Filter;
  // they share what's picked.
  function renderFilter() {
    const sv = current === "#screen-script";
    const btn = $(sv ? "#sv-filter" : "#filter");
    btn.textContent = markerFilter.size ? `Filter · ${markerFilter.size}` : "Filter";
    btn.classList.toggle("on", markerFilter.size > 0);
    btn.setAttribute("aria-expanded", String(filterOpen));
    const box = $(sv ? "#sv-filter-chips" : "#filter-chips");
    box.hidden = !filterOpen;
    if (box.hidden) return;
    box.replaceChildren();
    // The tags on this clip's markers, plus any picked ones, in tag-list order.
    const seen = new Map();
    let untagged = false;
    for (const m of S.markers) {
      const ts = markerTags(m);
      if (!ts.length) untagged = true;
      for (const t of ts) if (!seen.has(t.id)) seen.set(t.id, t);
    }
    for (const id of markerFilter) if (id !== NO_TAG && !seen.has(id) && tagById(id)) seen.set(id, tagById(id));
    const order = (t) => {
      const i = tags.findIndex((x) => x.id === t.id);
      return i < 0 ? 1e9 : i;
    };
    const chip = (id, label, suffix, t) => {
      const b = button("chip chip-small", null, () => {
        if (markerFilter.has(id)) markerFilter.delete(id);
        else markerFilter.add(id);
        renderMarkers();
        requestDraw();
      });
      b.setAttribute("aria-pressed", String(markerFilter.has(id)));
      b.append(el("span", null, label));
      if (suffix) b.append(el("span", "suffix", suffix));
      tintTag(b, t);
      return b;
    };
    for (const t of [...seen.values()].sort((a, b) => order(a) - order(b))) box.append(chip(t.id, t.name, t.suffix, t));
    if (untagged || markerFilter.has(NO_TAG)) box.append(chip(NO_TAG, "No tag"));
    if (!box.children.length) box.append(el("span", "muted small", "No tags on this clip's markers yet."));
    if (markerFilter.size) {
      box.append(button("chip chip-small chip-add", "Clear", () => {
        markerFilter.clear();
        renderMarkers();
        requestDraw();
      }));
    }
  }

  for (const id of ["#filter", "#sv-filter"]) {
    $(id).addEventListener("click", () => {
      filterOpen = !filterOpen;
      renderFilter();
    });
  }

  // A marker's row: time, clip length, note, tag suffixes. Tapping it does onTap.
  function markerRow(m, onTap) {
    const li = el("li", "mrow" + (m.id === nearId ? " near" : "") + (m.id === heldId ? " held" : ""));
    li.dataset.id = m.id;
    li.style.setProperty("--mc", colorHex(m.color));
    const main = button("mrow-main", null, onTap);
    main.append(el("span", "mrow-time", fmtTime(mClip(m), true)));
    const reg = mRegion(m);
    if (reg) main.append(el("span", "mrow-len", fmtLen(reg[1] - reg[0])));
    main.append(el("span", m.note ? "mrow-note" : "mrow-note dim", m.note || "No note"));
    const sx = markerTags(m).filter((t) => t.suffix);
    if (sx.length) {
      const box = el("span", "mrow-tags");
      for (const t of sx) {
        const x = el("span", "suffix", t.suffix);
        tintTag(x, t);
        box.append(x);
      }
      main.append(box);
    }
    li.append(main);
    return li;
  }

  // Whichever screen is showing: the marking list, or the script screen's.
  function renderMarkers(loadingText) {
    const sv = current === "#screen-script";
    // A marker's note changed, or one came or went: the docs' links follow.
    if (sv) for (const d of Object.keys(DOCS)) highlight(DOCS[d].box);
    const ul = $(sv ? "#sv-markers" : "#markers");
    ul.replaceChildren();
    const shown = S.markers.filter(passesFilter);
    $(sv ? "#sv-count" : "#marker-count").textContent = !S.markers.length ? ""
      : markerFilter.size ? `${shown.length} of ${S.markers.length}` : String(S.markers.length);
    renderFilter();
    if (S.markersError) {
      const li = el("li", "empty", S.markersError);
      li.classList.add("error-text");
      ul.append(li);
    }
    if (!S.markers.length) {
      if (!S.markersError) {
        ul.append(el("li", "empty", loadingText
          || (sv ? "No markers on this clip yet. Mark it from Markers on the home screen." : "No markers yet. Tap + at a moment worth keeping.")));
      }
      return;
    }
    if (!shown.length) ul.append(el("li", "empty", "No markers with those tags."));
    for (const m of shown) {
      const at = fmtTime(mClip(m), true);
      if (sv) {
        const li = markerRow(m, mode ? () => watchMarker(m) : null);
        const add = button("mrow-edit sv-add", "+", () => addToScript(m));
        add.setAttribute("aria-label", `Put the marker at ${at} in ${DOCS[SCR.doc].name}`);
        li.append(add);
        ul.append(li);
        continue;
      }
      const li = markerRow(m, () => seekMarker(m));
      const edit = button("mrow-edit", "Edit", () => openEditor(m, false));
      edit.setAttribute("aria-label", `Edit marker at ${at}`);
      li.append(edit);
      ul.append(li);
    }
  }

  function updateNear(t) {
    let best = null;
    let bestD = 1.5;
    for (const m of S.markers) {
      const d = Math.abs(mClip(m) - t);
      if (d <= bestD) {
        bestD = d;
        best = m.id;
      }
    }
    if (best === nearId) return;
    nearId = best;
    for (const li of $$("#markers .mrow, #sv-markers .mrow")) li.classList.toggle("near", li.dataset.id === nearId);
  }

  $("#add").addEventListener("click", () => {
    if (!S.clip) return;
    const v = Math.round((S.dragClip != null ? clipToVod(S.dragClip) : vodNow()) * 1000) / 1000;
    const resume = videoActive();
    pauseVideo();
    const stamp = new Date().toISOString();
    const m = {
      version: 3, id: newId(), clip_id: S.clip.id, vod_id: S.vodId, vod_time: v,
      timestamp: Math.round(vodToClip(v) * 1000) / 1000,
      note: "", tags: [], tag: null, tag_suffix: null, created: stamp, updated: stamp,
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
    const current = markerTags(m);
    // picked: tag ids on; extra: tags deleted from the list that this marker still has.
    ed = { m, resume, picked: new Set(current.map((t) => t.id)), extra: current.filter((t) => !tagById(t.id)),
      color: cleanColor(m.color), clearClip: false };
    $("#ed-time").textContent = `Marker at ${fmtTime(mClip(m), true)}`;
    $("#ed-note").value = m.note || "";
    $("#ed-newtag").hidden = true;
    $("#ed-newtag-error").hidden = true;
    renderEditorTags();
    renderEditorColor();
    renderEditorClip();
    $("#sheet-editor").hidden = false;
    // Same tap that opened it, so iOS brings the keyboard up.
    $("#ed-note").focus();
  }

  function closeEditor(keep) {
    if (!ed) return;
    const { m, resume } = ed;
    if (keep) {
      const note = $("#ed-note").value.trim().replace(/\s+/g, " ");
      const list = [...tags, ...ed.extra].filter((t) => ed.picked.has(t.id));
      const before = markerTagRefs(m).map((t) => t.id).sort().join("|");
      const after = list.map((t) => t.id).sort().join("|");
      if (note !== (m.note || "") || before !== after || ed.color !== cleanColor(m.color) || ed.clearClip) {
        m.note = note;
        setMarkerTags(m, list);
        if (ed.color) m.color = ed.color;
        else delete m.color;
        if (ed.clearClip) setSpan(m, 0, 0);
        persistMarker(m);
      }
    }
    ed = null;
    $("#ed-note").blur();
    $("#sheet-editor").hidden = true;
    renderMarkers();
    requestDraw();
    if (resume) playVideo();
  }

  function renderEditorTags() {
    const box = $("#ed-tags");
    box.replaceChildren();
    if (!ed) return;
    // Any number of tags; each chip toggles on its own.
    const chip = (t) => {
      const b = button("chip", null, () => {
        if (ed.picked.has(t.id)) ed.picked.delete(t.id);
        else ed.picked.add(t.id);
        renderEditorTags();
      });
      b.setAttribute("aria-pressed", String(ed.picked.has(t.id)));
      b.append(el("span", null, t.name));
      if (t.suffix) b.append(el("span", "suffix", t.suffix));
      tintTag(b, t);
      return b;
    };
    // A tag deleted from the list still shows on markers that carry it.
    for (const t of ed.extra) box.append(chip(t));
    for (const t of tags) box.append(chip(t));
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

  function renderEditorClip() {
    const box = $("#ed-clip");
    box.replaceChildren();
    if (!ed) return;
    const r = mRegion(ed.m);
    if (!r || ed.clearClip) {
      box.append(el("span", "muted small", ed.clearClip ? "The clip goes when you tap Done."
        : "No clip. Double-tap the marker's flag on the waveform, keep your finger down, and drag left or right."));
      return;
    }
    box.append(el("span", "mono", `${fmtTime(r[0], true)} to ${fmtTime(r[1], true)} · ${fmtLen(r[1] - r[0])}`));
    box.append(button("btn btn-ghost btn-danger btn-small", "Remove", () => {
      ed.clearClip = true;
      renderEditorClip();
    }));
  }

  function renderEditorColor() {
    if (!ed) return;
    $("#ed-color").replaceChildren(...swatches(ed.color, (id) => {
      ed.color = id;
      renderEditorColor();
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
    const t = { id: newTagId(), ...r };
    tags.push(t);
    saveTags();
    if (ed) ed.picked.add(t.id);
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

  /* ---------- script ----------
     The Script screen (Script on the home screen): a clip's two docs, next to
     its markers in Dropbox and the same files as the clip editor's 5 · Script
     tab. The But / Therefore (but-therefore.md) is the beats written from the
     markers, "But: …" / "Therefore: …" pairs; the script (script.md) is
     written from those. Each is saved a moment after you stop typing (through
     the outbox, so offline is fine), and picked up from the PC on the 10 s
     check while you're not typing in it. Neither can be typed in until it has
     loaded, so a slow load can't be saved over. The switch under the video
     flips between the two and the clip's markers: tap one to watch it, + to
     put it in the doc you came from. */
  const DOCS = {
    beats: { file: "but-therefore.md", box: $("#beats-text"), name: "the But / Therefore" },
    script: { file: "script.md", box: $("#script-text"), name: "the script" },
  };
  const docState = () => ({ rev: null, dirty: false, timer: 0, loading: false, loaded: false, note: "",
    paint: [], prev: "" });   // paint: color highlights [start, end, color]; prev: the text they're on
  const SCR = { view: "script", doc: "script", clipId: null, docs: { beats: docState(), script: docState() } };
  const docPath = (d) => `${S.clip.folder}/${DOCS[d].file}`;

  /* "But:" red and "Therefore:" green at the start of a line, in both docs.
     A textarea can't color its own text, so each sits on a layer (.st-hl)
     with the same box, font and wrapping holding the same text invisibly,
     the two words marked; it follows the box's scroll. */
  const HL_RE = /^([ \t]*)(but|therefore)([ \t]*:)/gim;

  /* The layer has to wrap at the same word as the textarea, or every long
     line that wraps differently pushes the marks below it down a row. Some
     iOS versions keep padding inside a textarea that CSS can't remove (3px a
     side on older ones, none on current ones), so it's measured, not
     guessed: a hidden textarea and layer wrap the same text, and the layer
     takes the extra padding at which the two come out the same height. The
     text is long runs of one narrow letter, which break letter by letter,
     so a few px less room is always a row more. */
  function measureInset() {
    const ed = document.createElement("div");
    ed.className = "st-ed";
    ed.style.cssText = "position: absolute; left: -9999px; top: 0; width: 180px; height: 60px; visibility: hidden;";
    const hl = document.createElement("div");
    hl.className = "st-hl";
    const ta = document.createElement("textarea");
    ta.className = "script-text";
    ta.tabIndex = -1;
    ta.setAttribute("aria-hidden", "true");
    ed.append(hl, ta);
    document.body.append(ed);
    const text = ["i", "l", "1", "t", "f"].map((c) => c.repeat(3000)).join("\n");
    ta.value = text;
    hl.textContent = text + " ";
    let inset = 0;
    for (const px of [0, 3, 1, 2, 4, 5, 6]) {
      hl.style.setProperty("--ta-inset", `${px}px`);
      if (hl.scrollHeight === ta.scrollHeight) { inset = px; break; }
    }
    ed.remove();
    document.documentElement.style.setProperty("--ta-inset", `${inset}px`);
    return inset;
  }
  measureInset();

  /* A marker in a doc ("[0:40] dies to lava") is underlined yellow and is a
     link: a tap is Go to for it. Any [time] or [time to time] is one; the
     text after it is too while it's still that marker's own note. */
  const MK_RE = /\[(\d{1,2}(?::\d{2}){1,2}(?:\.\d+)?)(?:\s+to\s+\d{1,2}(?::\d{2}){1,2}(?:\.\d+)?)?\]/g;
  const clockSecs = (s) => s.split(":").reduce((acc, p) => acc * 60 + Number(p), 0);
  const escHtml = (s) => s.replace(/[&<>"]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[ch]);

  /* Color highlights, put on in the clip editor (select, right-click, a
     color). Shown here on the same layer, and kept: they're saved in the doc's
     file as a comment line at its end, which stays out of the text box, and
     typing here moves them along with the text. */
  const PAINT = ["yellow", "orange", "red", "green", "blue", "purple"];
  const PAINT_RE = /\n<!-- clip editor highlights: (\[[^\n]*\]) -->\n?$/;

  // Line ends as the text box has them (\r\n reads as \n there).
  function splitDoc(file) {
    file = (file || "").replace(/\r\n?/g, "\n");
    const hit = PAINT_RE.exec(file);
    if (!hit) return [file, []];
    let list;
    try { list = JSON.parse(hit[1]); } catch { return [file, []]; }
    const text = file.slice(0, hit.index);
    return [text, cleanPaint(list, text.length)];
  }

  const joinDoc = (text, paint) =>
    paint.length ? `${text}\n<!-- clip editor highlights: ${JSON.stringify(paint)} -->\n` : text;

  // In order, inside the text, apart, and two of a color that touch made one.
  function cleanPaint(list, len) {
    const rs = [];
    for (const r of Array.isArray(list) ? list : []) {
      if (!Array.isArray(r) || !Number.isInteger(r[0]) || !Number.isInteger(r[1]) || !PAINT.includes(r[2])) continue;
      const a = Math.max(0, r[0]);
      const b = Math.min(len, r[1]);
      if (b > a) rs.push([a, b, r[2]]);
    }
    rs.sort((x, y) => x[0] - y[0]);
    const out = [];
    for (const r of rs) {
      const last = out[out.length - 1];
      if (last && r[0] < last[1]) {
        if (r[1] <= last[1]) continue;
        r[0] = last[1];
      }
      if (last && last[1] === r[0] && last[2] === r[2]) last[1] = r[1];
      else out.push(r);
    }
    return out;
  }

  // What an edit changed: [start, old end, new end]. The text after the
  // cursor is what's untouched; else the longest common ends.
  function editSpan(old, now, caret) {
    let suf = -1;
    if (caret != null && caret <= now.length) {
      const tail = now.slice(caret);
      if (tail.length <= old.length && old.endsWith(tail)) suf = tail.length;
    }
    if (suf < 0) {
      suf = 0;
      const most = Math.min(old.length, now.length);
      while (suf < most && old[old.length - 1 - suf] === now[now.length - 1 - suf]) suf++;
    }
    const most = Math.min(old.length, now.length) - suf;
    let p = 0;
    while (p < most && old[p] === now[p]) p++;
    return [p, old.length - suf, now.length - suf];
  }

  // Typed inside one: in it. Just before or after: not. Over its start or
  // end (a selection replaced): the new text keeps the color.
  function paintEdit(d) {
    const st = SCR.docs[d];
    const box = DOCS[d].box;
    const old = st.prev;
    const now = box.value;
    st.prev = now;
    if (!st.paint.length || old === now) return;
    const [p, oldEnd, newEnd] = editSpan(old, now, box.selectionEnd);
    const delta = newEnd - oldEnd;
    const start = (x) => (x < p ? x : x === p ? (oldEnd === p ? newEnd : p) : x < oldEnd ? newEnd : x + delta);
    const end = (x) => (x <= p ? x : x < oldEnd ? p : x + delta);
    st.paint = cleanPaint(st.paint.map(([a, b, c]) => [start(a), end(b), c]), now.length);
  }

  function highlight(box) {
    const hl = box.previousElementSibling;
    const v = box.value;
    const spans = [];     // [start, end, opening tag]
    for (const m of v.matchAll(HL_RE)) {
      const a = m.index + m[1].length;
      spans.push([a, a + m[2].length + m[3].length, `<mark class="hl-${m[2].toLowerCase()}">`]);
    }
    const lines = new Map();   // "[0:40]" -> that time's marker lines
    for (const m of S.clip ? S.markers : []) {
      const l = scriptLine(m);
      const key = l.slice(0, l.indexOf("]") + 1);
      lines.set(key, [...(lines.get(key) || []), l]);
    }
    for (const m of v.matchAll(MK_RE)) {
      let end = m.index + m[0].length;
      for (const l of lines.get(m[0]) || []) {
        if (m.index + l.length > end && v.startsWith(l, m.index)) end = m.index + l.length;
      }
      spans.push([m.index, end, `<mark class="hl-mk" data-t="${clockSecs(m[1])}">`]);
    }
    spans.sort((x, y) => x[0] - y[0]);
    const marks = [];
    let at = 0;
    for (const sp of spans) {
      if (sp[0] < at) continue;   // a [time] inside a marker's note
      marks.push(sp);
      at = sp[1];
    }
    // Color highlights go around the marks: the text is cut wherever either
    // starts or ends, and each piece gets the ones it's in.
    const paint = SCR.docs[box === DOCS.beats.box ? "beats" : "script"].paint;
    const cuts = [...new Set([0, v.length, ...marks.flatMap((x) => [x[0], x[1]]), ...paint.flatMap((r) => [r[0], r[1]])])]
      .filter((x) => x <= v.length).sort((x, y) => x - y);
    let html = "";
    let mi = 0;
    let pi = 0;
    for (let i = 0; i + 1 < cuts.length; i++) {
      const a = cuts[i];
      while (mi < marks.length && marks[mi][1] <= a) mi++;
      while (pi < paint.length && paint[pi][1] <= a) pi++;
      let piece = escHtml(v.slice(a, cuts[i + 1]));
      if (marks[mi] && marks[mi][0] <= a) piece = marks[mi][2] + piece + "</mark>";
      if (paint[pi] && paint[pi][0] <= a) piece = `<span class="pt pt-${paint[pi][2]}">${piece}</span>`;
      html += piece;
    }
    // The trailing space keeps a last empty line as tall as the textarea's.
    hl.innerHTML = html + " ";
    hl.scrollTop = box.scrollTop;
  }
  const docBox = (d = SCR.doc) => DOCS[d].box;
  const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

  // v: "beats" or "script" (that doc), or "markers" (the list, + into the doc
  // you came from).
  function setView(v) {
    SCR.view = v;
    if (v !== "markers") SCR.doc = v;
    for (const [id, on] of [["#tab-beats", v === "beats"], ["#tab-script", v === "script"], ["#tab-markers", v === "markers"]]) {
      $(id).setAttribute("aria-selected", String(on));
      $(id).setAttribute("aria-pressed", String(on));
    }
    $("#script-view").hidden = v === "markers";
    $("#sv-markers-view").hidden = v !== "markers";
    for (const d of Object.keys(DOCS)) DOCS[d].box.parentElement.hidden = d !== SCR.doc;
    $("#sc-beat").hidden = SCR.doc !== "beats";
    $("#sc-outline").hidden = SCR.doc !== "script";
    const video = S.clip && hasVideo(S.clip);
    $("#sv-hint").textContent = `${video ? "Tap to watch, + puts it in " : "+ puts it in "}${DOCS[SCR.doc].name}`;
    if (v === "markers") {
      renderMarkers();
    } else {
      scriptStatus();
      scriptCaret();
    }
  }

  function scriptReady(d, on) {
    SCR.docs[d].loaded = on;
    DOCS[d].box.readOnly = !on;
  }

  // From the region's start if it has one, else a couple of seconds before.
  function watchMarker(m) {
    const r = mRegion(m);
    seekClip(r ? r[0] : Math.max(0, mClip(m) - 2));
    playVideo();
  }

  function addToScript(m) {
    const d = SCR.doc;
    if (addMarkerTo(d, m)) toast(`Added to ${DOCS[d].name}`, { label: "Show", run: () => setView(d) });
  }

  function scriptStatus() {
    const d = SCR.doc;
    const st = SCR.docs[d];
    if (st.note) {
      $("#script-status").textContent = st.note;
      return;
    }
    const v = docBox(d).value.trim();
    const words = plural(v ? v.split(/\s+/).length : 0, "word");
    const beats = d === "beats" ? `${plural(beatCount(parseBeats(v)), "beat")} · ` : "";
    $("#script-status").textContent = beats + words + (st.dirty ? " · editing" : "");
  }

  async function loadScript() {
    const c = S.clip;
    if (!c) return;
    if (SCR.clipId !== c.id) {
      SCR.clipId = c.id;
      for (const d of Object.keys(DOCS)) {
        clearTimeout(SCR.docs[d].timer);
        Object.assign(SCR.docs[d], docState(), { note: `Loading ${DOCS[d].name}` });
        scriptReady(d, false);
        DOCS[d].box.value = "";
        highlight(DOCS[d].box);
      }
      scriptStatus();
      scriptCaret();
    }
    await Promise.all(Object.keys(DOCS).map((d) => loadDoc(c, d)));
  }

  function docLoaded(d) {
    SCR.docs[d].note = "";
    scriptReady(d, true);
    if (d === SCR.doc) {
      scriptStatus();
      scriptCaret();
    }
  }

  async function loadDoc(c, d) {
    const st = SCR.docs[d];
    const box = DOCS[d].box;
    // Not under your fingers: typing (or about to save) wins.
    if (st.loading || (st.loaded && (st.dirty || document.activeElement === box))) return;
    const path = docPath(d);
    const pending = outbox.ops.filter((o) => o.kind === "put" && o.path.toLowerCase() === path.toLowerCase()).pop();
    if (pending && !st.dirty && document.activeElement !== box) {
      const [text, paint] = splitDoc(pending.text);
      if (box.value !== text) box.value = text;
      Object.assign(st, { paint, prev: box.value });
      highlight(box);
      docLoaded(d);
      return;
    }
    st.loading = true;
    try {
      const meta = await dbx.meta(path);
      if (S.clip !== c || SCR.clipId !== c.id) return;
      if (!meta || meta.rev === st.rev) {
        docLoaded(d);
        return;
      }
      const [text, paint] = splitDoc(await readText(meta));
      if (S.clip !== c) return;
      if (st.dirty || (document.activeElement === box && box.value !== text && st.rev)) return;
      st.rev = meta.rev;
      if (box.value !== text) box.value = text;
      Object.assign(st, { paint, prev: box.value });
      highlight(box);
      docLoaded(d);
    } catch (e) {
      if (e instanceof AuthError) return needSignIn();
      st.note = `Couldn't load ${DOCS[d].name}. ${errText(e)}`;
      if (d === SCR.doc) scriptStatus();
    } finally {
      st.loading = false;
    }
  }

  function saveDoc(d) {
    const st = SCR.docs[d];
    clearTimeout(st.timer);
    if (!st.dirty || !S.clip || SCR.clipId !== S.clip.id) return;
    st.dirty = false;
    outbox.put(docPath(d), joinDoc(DOCS[d].box.value, st.paint));
    if (d === SCR.doc) scriptStatus();
  }

  function saveScript() {
    for (const d of Object.keys(DOCS)) saveDoc(d);
  }

  // Typing: the waveforms and buttons step aside (the video stays) and the
  // screen fits above the keyboard, so the doc gets the room. Back on blur.
  function fitViewport() {
    const vv = window.visualViewport;
    document.documentElement.style.setProperty("--vvh", `${Math.round(vv ? vv.height : window.innerHeight)}px`);
    if ($("#screen-script").classList.contains("writing")) window.scrollTo(0, 0);
  }
  if (window.visualViewport) window.visualViewport.addEventListener("resize", fitViewport);
  for (const d of Object.keys(DOCS)) {
    const box = DOCS[d].box;
    box.addEventListener("scroll", () => { box.previousElementSibling.scrollTop = box.scrollTop; });
    box.addEventListener("input", () => {
      paintEdit(d);
      highlight(box);
      const st = SCR.docs[d];
      st.dirty = true;
      clearTimeout(st.timer);
      st.timer = setTimeout(() => saveDoc(d), 1000);
      scriptStatus();
      scriptCaret();
    });
    box.addEventListener("focus", () => {
      fitViewport();
      $("#screen-script").classList.add("writing");
    });
    box.addEventListener("blur", () => {
      saveDoc(d);
      $("#screen-script").classList.remove("writing");
    });
    for (const n of ["click", "keyup", "select"]) box.addEventListener(n, scriptCaret);
  }

  function scriptLine(m) {
    const r = mRegion(m);
    const when = r ? `${fmtTime(r[0])} to ${fmtTime(r[1])}` : fmtTime(mClip(m));
    const sfx = markerTags(m).filter((t) => t.suffix).map((t) => t.suffix).join(" ");
    return `[${when}] ${m.note || "(no note)"}${sfx ? ` (${sfx})` : ""}`;
  }

  function typeInto(box, text, a, b) {
    box.setRangeText(text, a, b, "end");
    box.dispatchEvent(new Event("input"));
  }

  // The line pos is on, as [start, end) in the text.
  function lineAt(v, pos) {
    const a = v.lastIndexOf("\n", pos - 1) + 1;
    const b = v.indexOf("\n", pos);
    return [a, b < 0 ? v.length : b];
  }

  function docReady(d) {
    if (SCR.docs[d].loaded) return true;
    const name = DOCS[d].name;
    toast(`${name[0].toUpperCase()}${name.slice(1)} is still loading.`);
    return false;
  }

  // Whole lines: with the cursor partway along a line they go after that
  // line, never into the middle of it.
  function insertScript(text, d = SCR.doc) {
    if (!docReady(d)) return false;
    const box = DOCS[d].box;
    const v = box.value;
    let a = box.selectionStart ?? v.length;
    let b = box.selectionEnd ?? a;
    if (a === b && a > 0 && v[a - 1] !== "\n") {
      const eol = v.indexOf("\n", a);
      a = b = eol < 0 ? v.length : eol;
      text = "\n" + text.replace(/\n$/, "");
    }
    typeInto(box, text, a, b);
    return true;
  }

  /* In the But / Therefore, a marker fills the cursor's line when it's an
     empty "But:" or "Therefore:" (lay out the beat, then point it at the
     moment); anywhere else it's a line of its own. */
  function addMarkerTo(d, m) {
    if (!docReady(d)) return false;
    if (d === "beats") {
      const box = DOCS[d].box;
      const v = box.value;
      const [a, b] = lineAt(v, box.selectionStart ?? v.length);
      const line = v.slice(a, b);
      const hit = BEAT_RE.exec(line);
      if (hit && (box.selectionEnd ?? b) <= b && !line.slice(hit[0].length).trim()) {
        typeInto(box, (/\s$/.test(line) ? "" : " ") + scriptLine(m), b, b);
        return true;
      }
    }
    return insertScript(scriptLine(m) + "\n", d);
  }

  /* ---------- But / Therefore ----------
     Same rules as the clip editor's: beats are blocks of lines, a blank line
     or a new "But:" starts the next one. */
  const BEAT_RE = /^(\s*)(therefore|but)\s*:\s*/i;

  function parseBeats(text) {
    const beats = [];
    let cur = null;
    for (const raw of text.split("\n")) {
      const line = raw.trim();
      if (!line) {
        cur = null;
        continue;
      }
      const hit = BEAT_RE.exec(line);
      const kind = hit ? hit[2].toLowerCase() : "text";
      if (!cur || kind === "but") {
        cur = { kinds: [], lines: [] };
        beats.push(cur);
      }
      cur.kinds.push(kind);
      cur.lines.push(line);
    }
    return beats.map((b) => ({ ...b, text: b.lines.join("\n") }));
  }

  const beatCount = (beats) => beats.filter((b) => b.kinds.some((k) => k !== "text")).length;

  /* Enter after a But line starts its Therefore (or goes to it, if it's
     there), Enter after a Therefore starts the next beat, Enter on an empty
     But / Therefore clears it. Text after the cursor: a plain Enter. */
  DOCS.beats.box.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" || e.shiftKey || e.ctrlKey || e.metaKey || e.altKey || e.isComposing) return;
    const box = DOCS.beats.box;
    const v = box.value;
    const pos = box.selectionStart;
    if (pos !== box.selectionEnd) return;
    const [a, b] = lineAt(v, pos);
    if (v.slice(pos, b).trim()) return;
    const line = v.slice(a, pos);
    const hit = BEAT_RE.exec(line);
    if (!hit) return;
    e.preventDefault();
    if (!line.slice(hit[0].length).trim()) {
      typeInto(box, "", a, b);
      return;
    }
    if (hit[2].toLowerCase() === "therefore") {
      typeInto(box, "\n\nBut: ", pos, pos);
      return;
    }
    const thenEnd = b < v.length ? lineAt(v, b + 1)[1] : -1;
    if (thenEnd >= 0 && /^\s*therefore\s*:/i.test(v.slice(b + 1, thenEnd))) {
      box.setSelectionRange(thenEnd, thenEnd);
      scriptCaret();
      return;
    }
    typeInto(box, "\nTherefore: ", pos, pos);
  });

  // + Beat: a new empty pair after the beat the cursor is in, the cursor on
  // its But.
  $("#sc-beat").addEventListener("click", () => {
    if (!docReady("beats")) return;
    const box = DOCS.beats.box;
    const v = box.value;
    let end = lineAt(v, box.selectionEnd ?? v.length)[1];
    while (end < v.length) {
      const nextEnd = lineAt(v, end + 1)[1];
      const next = v.slice(end + 1, nextEnd);
      if (!next.trim() || /^\s*but\s*:/i.test(next)) break;
      end = nextEnd;
    }
    const before = v.slice(0, end);
    const after = v.slice(end);
    const lead = !before.trim() ? "" : before.endsWith("\n\n") ? "" : before.endsWith("\n") ? "\n" : "\n\n";
    const tail = !after.trim() || after.startsWith("\n\n") ? "" : "\n";
    box.focus();
    typeInto(box, `${lead}But: \nTherefore: ${tail}`, end, end);
    const at = end + lead.length + "But: ".length;
    box.setSelectionRange(at, at);
    scriptCaret();
  });

  $("#sc-insert").addEventListener("click", () => {
    const t = now();
    let best = null;
    for (const m of S.markers) if (!best || Math.abs(mClip(m) - t) < Math.abs(mClip(best) - t)) best = m;
    if (!best) {
      toast("No markers on this clip yet.");
      return;
    }
    addMarkerTo(SCR.doc, best);
  });
  // The script's Outline: every beat of the But / Therefore.
  $("#sc-outline").addEventListener("click", () => {
    if (!docReady("beats")) return;
    const beats = parseBeats(DOCS.beats.box.value);
    if (!beats.length) {
      toast("No But / Therefore yet. Write it first, from the markers.", { label: "Open", run: () => setView("beats") });
      return;
    }
    insertScript(beats.map((b) => b.text).join("\n\n") + "\n", "script");
  });

  // Go to: the first [time] on the line the cursor is on.
  function caretTime() {
    const box = docBox();
    const v = box.value;
    const [a, b] = lineAt(v, box.selectionStart || 0);
    const hit = /\[(\d{1,2}(?::\d{2}){1,2}(?:\.\d+)?)/.exec(v.slice(a, b));
    return hit ? clockSecs(hit[1]) : null;
  }

  function scriptCaret() {
    const t = caretTime();
    $("#sc-goto").disabled = t == null;
    $("#sc-goto").textContent = t == null ? "Go to" : `Go to ${fmtTime(t)}`;
  }

  $("#sc-goto").addEventListener("click", () => {
    const t = caretTime();
    if (t != null) seekClip(t);
  });

  /* A tap on a marker's yellow underline is Go to for it. With the keyboard
     down it only goes there (the keyboard stays down); while typing, the
     cursor lands there too. A drag, a long press or a double tap is plain
     editing. The underline is on the layer under the text, so the tap is
     found by where it lands on that layer. */
  function linkAt(box, x, y) {
    for (const mk of box.previousElementSibling.querySelectorAll(".hl-mk")) {
      for (const r of mk.getClientRects()) {
        if (x >= r.left - 3 && x <= r.right + 3 && y >= r.top - 3 && y <= r.bottom + 3) return mk;
      }
    }
    return null;
  }
  const linksOn = () => !!(S.clip && hasVideo(S.clip));
  for (const d of Object.keys(DOCS)) {
    const box = DOCS[d].box;
    let tap = null;
    box.addEventListener("touchstart", (e) => {
      const t = e.touches[0];
      tap = e.touches.length === 1 && document.activeElement !== box
        ? { x: t.clientX, y: t.clientY, at: Date.now() } : null;
    }, { passive: true });
    box.addEventListener("touchend", (e) => {
      const was = tap;
      tap = null;
      const t = e.changedTouches[0];
      if (!was || !linksOn() || Date.now() - was.at > 500 || Math.hypot(t.clientX - was.x, t.clientY - was.y) > 10) return;
      const mk = linkAt(box, t.clientX, t.clientY);
      if (!mk) return;
      e.preventDefault();       // no focus, no keyboard, no click after
      seekClip(Number(mk.dataset.t));
    });
    box.addEventListener("click", (e) => {
      if (e.detail > 1 || box.selectionStart !== box.selectionEnd || !linksOn()) return;
      const mk = linkAt(box, e.clientX, e.clientY);
      if (mk) seekClip(Number(mk.dataset.t));
    });
  }
  // The doc's buttons leave the typing where it is (focus, keyboard, layout).
  for (const b of $$(".script-tools button")) b.addEventListener("mousedown", (e) => e.preventDefault());
  $("#tab-beats").addEventListener("click", () => setView("beats"));
  $("#tab-script").addEventListener("click", () => setView("script"));
  $("#tab-markers").addEventListener("click", () => setView("markers"));

  for (const b of $$(".sheet-backdrop")) {
    b.addEventListener("click", () => {
      if (b.dataset.close === "editor") closeEditor(true);
      else if (b.dataset.close === "view") closeViewSheet();
      else $("#sheet-tags").hidden = true;
    });
  }

  /* ---------- lifecycle ---------- */

  window.addEventListener("online", () => { renderSync(); outbox.flush(); });
  window.addEventListener("offline", renderSync);
  window.addEventListener("pagehide", savePos);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      // Leaving the app stops the video; pausing here keeps the clock honest.
      if (videoActive()) pauseVideo();
      savePos();
      return;
    }
    outbox.flush();
    if (current === "#screen-clips") refreshClips();
    if (current === "#screen-clip" || current === "#screen-script") syncOpenClip();
  });
  window.addEventListener("pagehide", saveScript);

  // The Edit screens (edit.js) share the sign-in, the outbox and the screens.
  window.MSAPP = {
    $, $$, el, button, clamp, sleep, fmtTime, stripExt, parseJson, store, dbx, outbox, toast, show, errText,
    AuthError, NetError, ApiError, notFound, needSignIn, swallowClick, renderSync, showHome,
    current: () => current, debug: !!CFG.debug,
  };

  function init() {
    if (CFG.debug) {   // automated tests only
      window.__ms = { TP, DV, S, VZ, VOL, SCR, FW, talk, vodNow, now, mRegion, mode: () => mode, rate: () => rate,
        topRate: () => topRate, tags: () => tags, syncOpenClip, jumpTalk, current: () => current };
    }
    const z = store.get("ms.zoom", 30);
    S.zoom = typeof z === "number" && z >= ZOOM_MIN && z <= ZOOM_MAX ? z : 30;
    const q = store.get("ms.quality", 480);
    S.quality = QUALITIES.includes(q) ? q : 480;
    playerPref = store.get("ms.player", "direct") === "twitch" ? "twitch" : "direct";
    const sp = store.get("ms.speed", 2);
    altRate = RATES.includes(sp) ? sp : 2;
    topRate = store.get("ms.topRate", FAST) === 2 ? 2 : FAST;
    const vol = store.get("ms.volume", 1);
    VOL.v = typeof vol === "number" && vol >= 0 && vol <= 1 ? vol : 1;
    renderVolume();
    renderSync();
    if (!APP_KEY) return show("#screen-setup");
    if (!auth.signedIn()) return showConnect();
    showHome();
    ensureTags().catch(() => {});
    outbox.flush();
  }

  init();
})();
