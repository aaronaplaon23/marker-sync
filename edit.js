"use strict";

/* Edit: the clip editor's 2 · Edit tab on the phone.

   The clips are the ones waiting in the PC's Stage 1 folder. For each, the
   PC (the Clip Catcher worker, phone_edit.py) puts a lighter copy in Dropbox:
   the video at 1080p with no sound, every audio track on its own, and the
   waveforms. The phone streams those, draws the vertical version live on a
   canvas, and plays the tracks through Web Audio so mute and volume are
   heard. Export sends the edit (the same fields the Edit tab sends) to the
   PC, which renders it from the real clip into the Stage 2 folder (TikTok
   Finals). Nothing big is ever saved on the phone.

   Ported from the clip editor's static/editor.js; the layout, crop and
   overlay math is kept identical so a look reads the same on both. */

(() => {
  const A = window.MSAPP;
  if (!A) return;
  const { $, $$, el, button, clamp, fmtTime, store, dbx, outbox, toast, show, errText, AuthError, notFound } = A;

  const STATE_PATH = "/edit/state.json";
  const INBOX = "/edit/inbox";
  const DRAFTS = "/edit/drafts";
  const PC_STALE_S = 180;               // the PC checks in every minute
  const LIST_POLL_MS = 4000;
  const EDIT_POLL_MS = 6000;
  const TRACK_COLORS = ["#4cc2ff", "#b07cff", "#ffd166", "#6ee7a0", "#ff9e7d", "#7de3ff"];
  const OUT_W = { landscape: 1920, portrait: 1080, stacked: 1080 };
  const OUT_H = { landscape: 1080, portrait: 1920, stacked: 1920 };
  const LEGACY_LAYOUTS = {
    blur: { layout: "portrait", blurBg: true, facecam: false },
    facecam: { layout: "portrait", blurBg: false, facecam: true },
    full: { layout: "portrait", blurBg: false, facecam: false },
  };
  const ROLE_TAG = { landscape: "CROP", stackTop: "FACECAM", stackBottom: "GAMEPLAY", facecamMain: "MAIN", facecamFace: "FACECAM" };
  const ROLE_CLASS = { stackTop: "top", stackBottom: "bottom", facecamFace: "top" };
  const LAYOUT_NAMES = { landscape: "Landscape 1920x1080", stacked: "Portrait Stacked 1080x1920" };
  const GUIDES = { "4:5": { r: 4 / 5, label: "4:5 FEED" }, "1:1": { r: 1, label: "1:1" }, "16:9": { r: 16 / 9, label: "16:9" } };
  const OUT_BOX_MIN_VIS = 0.1;
  const ZOOMS = [0, 30, 10, 3];         // seconds on screen; 0 is the whole clip

  const vid = $("#ve-video");
  const canvas = $("#ve-canvas");
  const ctx = canvas.getContext("2d");
  const tl = $("#ve-timeline");
  const tctx = tl.getContext("2d");

  /* ---------- the PC's side: edit/state.json ---------- */

  const ST = { doc: null, at: 0, err: null, timer: 0, busy: false };
  let sent = store.get("ve.sent", {}) || {};     // requests sent from here: id -> {type, clip, name, at}

  async function fetchState() {
    if (ST.busy) return;
    ST.busy = true;
    try {
      const r = await dbx.download(STATE_PATH);
      const doc = JSON.parse(await r.text());
      if (doc && typeof doc === "object" && doc.clips) {
        ST.doc = doc;
        ST.err = null;
        ST.at = Date.now();
      }
    } catch (e) {
      if (e instanceof AuthError) {
        A.needSignIn();
        throw e;
      }
      ST.err = notFound(e) ? "none" : errText(e);
    } finally {
      ST.busy = false;
    }
    pruneSent();
  }

  function pruneSent() {
    const jobs = new Set(((ST.doc || {}).jobs || []).map((j) => j.id));
    let changed = false;
    for (const [id, s] of Object.entries(sent)) {
      if ((s.type === "export" && jobs.has(id)) || Date.now() - s.at > 3 * 86400e3
          || (s.type !== "export" && Date.now() - s.at > 600e3)) {
        delete sent[id];
        changed = true;
      }
    }
    if (changed) store.set("ve.sent", sent);
  }

  const pcAge = () => (ST.doc && ST.doc.pc && ST.doc.pc.seen_at ? (Date.now() - Date.parse(ST.doc.pc.seen_at)) / 1000 : Infinity);
  const pcOn = () => pcAge() < PC_STALE_S;

  function ago(sec) {
    if (sec < 90) return "a minute ago";
    if (sec < 3600) return `${Math.round(sec / 60)} minutes ago`;
    if (sec < 2 * 86400) return `${Math.round(sec / 3600)} hours ago`;
    return `${Math.round(sec / 86400)} days ago`;
  }

  function pcLine() {
    const d = ST.doc;
    if (!d) {
      if (ST.err === "none") return { cls: "off", text: "The PC hasn't set up phone editing yet. It does once the clip editor's worker restarts on the PC." };
      return { cls: "off", text: ST.err || "Loading" };
    }
    if (!pcOn()) return { cls: "off", text: `The PC is off or asleep. It last checked in ${ago(pcAge())}.` };
    if (d.pc.waiting) return { cls: "wait", text: d.pc.waiting };
    if (d.pc.dropbox) return { cls: "wait", text: d.pc.dropbox };
    return { cls: "on", text: "The PC is on." };
  }

  function sendRequest(req) {
    const id = req.id || `r${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
    const body = { v: 1, at: new Date().toISOString(), ...req, id };
    outbox.put(`${INBOX}/${id}.json`, JSON.stringify(body));
    sent[id] = { type: req.type, clip: req.clip || null, name: req.name || null, at: Date.now() };
    store.set("ve.sent", sent);
    return id;
  }

  const outboxHas = (path) => outbox.ops.some((o) => o.path.toLowerCase() === path.toLowerCase());

  function schedule(ms) {
    clearTimeout(ST.timer);
    ST.timer = setTimeout(tickPoll, ms);
  }

  async function tickPoll() {
    const cur = A.current();
    if (cur !== "#screen-vlist" && cur !== "#screen-vedit") return;
    if (!document.hidden) {
      try {
        await fetchState();
      } catch {
        return;
      }
      if (A.current() === "#screen-vlist") renderList();
      else if (A.current() === "#screen-vedit") onStateWhileEditing();
    }
    schedule(A.current() === "#screen-vedit" ? EDIT_POLL_MS : LIST_POLL_MS);
  }

  /* ---------- the clip list ---------- */

  function showList() {
    leaveEditor();
    show("#screen-vlist");
    A.renderSync();
    renderList();
    tickPoll();
  }

  function jobLine(j) {
    if (j.status === "rendering") return { cls: "state-busy", text: `Rendering on the PC, ${Math.round((j.progress || 0) * 100)}%` };
    if (j.status === "queued") {
      if (!pcOn()) return { cls: "state-busy", text: "Waiting for the PC to turn on" };
      return { cls: "state-busy", text: (ST.doc.pc && ST.doc.pc.waiting) ? "Waiting: OBS is recording" : "Waiting its turn on the PC" };
    }
    if (j.status === "done") return { cls: "state-ready", text: `Saved to ${stage2Name()} as ${j.file || j.name}` };
    if (j.status === "cancelled") return { cls: "state-none", text: "Cancelled" };
    if (j.status === "sending") return { cls: "state-busy", text: j.offline ? "Waiting to reach Dropbox" : "Sending" };
    if (j.status === "sent") return { cls: "state-busy", text: pcOn() ? "Sent. The PC picks it up in a few seconds" : "Sent. The PC picks it up when it's on" };
    return { cls: "state-failed", text: `Didn't export: ${j.error || "unknown error"}` };
  }

  const stage2Name = () => ((ST.doc && ST.doc.stage2 && ST.doc.stage2.name) || "TikTok Finals");

  // The PC's exports, plus this phone's that it hasn't picked up yet.
  function allJobs(clipId) {
    const jobs = ((ST.doc || {}).jobs || []).slice();
    const known = new Set(jobs.map((j) => j.id));
    for (const [id, s] of Object.entries(sent)) {
      if (s.type !== "export" || known.has(id)) continue;
      const path = `${INBOX}/${id}.json`;
      jobs.push({ id, clip: s.clip, name: s.name, status: outboxHas(path) ? "sending" : "sent",
                  offline: outbox.failing || !navigator.onLine, queued_at: new Date(s.at).toISOString() });
    }
    return jobs.filter((j) => !clipId || j.clip === clipId)
      .sort((a, b) => String(b.queued_at || "").localeCompare(String(a.queued_at || "")));
  }

  function jobRow(j, withCancel) {
    const li = el("li", "ve-job");
    const main = el("div", "ve-job-main");
    main.append(el("span", "ve-job-name", j.name || "(no name)"));
    const st = jobLine(j);
    main.append(el("span", `state ${st.cls}`, st.text));
    if (j.note) main.append(el("span", "muted small", j.note));
    li.append(main);
    if (withCancel && j.status === "queued") {
      li.append(button("btn btn-ghost btn-small", "Cancel", () => {
        sendRequest({ type: "cancel", job: j.id, clip: j.clip });
        toast("Asked the PC to cancel it.");
      }));
    }
    return li;
  }

  function copyLine(c) {
    const cp = c.copy || { status: "none" };
    const asked = Object.values(sent).some((s) => s.type === "prepare" && s.clip === c.id);
    if (cp.status === "ready") return c.done ? { cls: "state-ready", text: `In ${stage2Name()}. Ready to edit again` } : { cls: "state-ready", text: "Ready to edit" };
    if (cp.status === "making") return { cls: "state-busy", text: `${cp.step || "Getting it ready on the PC"}, ${Math.round((cp.progress || 0) * 100)}%` };
    if (cp.status === "waiting") return { cls: "state-busy", text: pcOn() ? `Getting it ready on the PC: ${cp.why || "in line"}` : "Gets ready once the PC is on" };
    if (cp.status === "failed") return { cls: "state-failed", text: `Couldn't get it ready: ${cp.error || "unknown error"}` };
    if (asked) return { cls: "state-busy", text: "Asked the PC to get it ready" };
    return c.done ? { cls: "state-none", text: `In ${stage2Name()}. Tap to edit it again` } : { cls: "state-none", text: "Not ready yet" };
  }

  function renderList() {
    const d = ST.doc;
    const pc = pcLine();
    $("#vl-pc").className = `pc-status pc-${pc.cls}`;
    $("#vl-pc").textContent = pc.text;
    const banner = $("#vl-banner");
    banner.hidden = !(ST.err && ST.err !== "none");
    if (!banner.hidden) banner.replaceChildren(el("div", null, ST.err), button("btn btn-small", "Try again", tickPoll));

    const jobs = allJobs().filter((j) => j.status !== "done" || Date.now() - Date.parse(j.finished_at || j.queued_at) < 86400e3).slice(0, 8);
    const jbox = $("#vl-jobs");
    jbox.hidden = !jobs.length;
    if (jobs.length) {
      const ul = el("ul", "ve-jobs");
      for (const j of jobs) ul.append(jobRow(j, true));
      jbox.replaceChildren(el("div", "vl-head", "Exports"), ul);
    }

    const list = $("#vl-list");
    list.replaceChildren();
    const groups = d ? d.groups || [] : [];
    let shown = 0;
    for (const g of groups) {
      const ids = g.clips.filter((id) => d.clips[id]);
      if (!ids.length) continue;
      const pending = ids.filter((id) => !d.clips[id].done).length;
      list.append(el("div", "vl-head", `${g.vod}${pending ? `  ·  ${pending} to edit` : ""}`));
      const ul = el("ul", "clip-list vl-clips");
      for (const id of ids) {
        const c = { id, ...d.clips[id] };
        const st = copyLine(c);
        const card = button(`clip-card${c.done ? " vl-done" : ""}`, null, () => tapClip(c));
        card.append(el("span", "clip-name", c.name));
        const meta = el("span", "clip-meta");
        meta.append(el("span", `state ${st.cls}`, st.text));
        if (c.duration) meta.append(el("span", null, fmtTime(c.duration)));
        card.append(meta);
        const li = el("li");
        li.append(card);
        ul.append(li);
        shown++;
      }
      list.append(ul);
    }
    $("#vl-empty").hidden = !d || shown > 0;
  }

  function tapClip(c) {
    const cp = c.copy || {};
    if (cp.status === "ready") return openEditor(c.id);
    if (cp.status === "making" || cp.status === "waiting") {
      toast(pcOn() ? "The PC is still getting this one ready." : "This one gets ready once the PC is on.");
      return;
    }
    const again = cp.status === "failed" ? "Try getting it ready again?" : "Get this clip ready to edit on the phone? The PC makes a copy for the phone, which takes a minute.";
    if (!window.confirm(again)) return;
    sendRequest({ type: "prepare", clip: c.id });
    toast("Asked the PC.");
    renderList();
  }

  $("#home-edit").addEventListener("click", showList);
  $("#vl-home").addEventListener("click", () => { clearTimeout(ST.timer); A.showHome(); });
  $("#vl-refresh").addEventListener("click", tickPoll);

  /* ---------- the edit itself (ported from the clip editor) ---------- */

  const E = {
    id: null, clip: null, copy: null,
    layout: "portrait", crops: {}, divider: 0.35, mainScale: 1, outH: 1920, blurBg: true, facecam: false,
    faceBox: { x: 0.05, y: 0.62, w: 0.28 },
    watermark: { enabled: false, x: 0, y: 0, w: 1 }, wmTouched: false, wmAspect: 0.5625, wmExists: false,
    tracks: [], inS: 0, outS: 0, dur: 0, fps: 60, srcW: 1920, srcH: 1080,
    name: "", view: "out", tab: store.get("ve.tab", "look"), loop: true,
    zoom: 0, viewStart: 0, viewEnd: 1, peaks: null, peakMax: [],
    raf: 0, dirty: true, tlDirty: true, open: false, from: "",
  };
  let guideMode = store.get("ve.guide", "");
  if (guideMode !== "all" && !GUIDES[guideMode]) guideMode = "";

  function outW() { return OUT_W[E.layout]; }
  function outHpx() { return E.layout === "portrait" ? E.outH : OUT_H[E.layout]; }
  function outRatio() { return outW() / outHpx(); }
  function srcAspect() { return E.srcW / E.srcH; }

  function roleRatio(role) {
    switch (role) {
      case "landscape": case "facecamMain": return 16 / 9;
      case "stackTop": return 1080 / (1920 * E.divider);
      case "stackBottom": return 1080 / (1920 * (1 - E.divider));
      case "facecamFace": return 1;
    }
    return 16 / 9;
  }

  function fitBox(r) {
    const a = srcAspect();
    let w, h;
    if (r >= a) { w = 1; h = a / r; } else { w = r / a; h = 1; }
    return { x: (1 - w) / 2, y: (1 - h) / 2, w, h };
  }

  function defaultBox(role) {
    if (role === "stackTop" || role === "facecamFace") {
      const r = roleRatio(role);
      const w = 0.35;
      const h = Math.min(1, w * srcAspect() / r);
      return { x: 0.03, y: 0.05, w, h };
    }
    return fitBox(roleRatio(role));
  }

  function activeRoles() {
    if (E.layout === "portrait") return E.facecam ? ["facecamMain", "facecamFace"] : ["facecamMain"];
    return { landscape: ["landscape"], stacked: ["stackTop", "stackBottom"] }[E.layout];
  }

  /* ---- crop boxes, on the source ---- */

  function renderCropBoxes() {
    const layer = $("#ve-crops");
    layer.replaceChildren();
    for (const role of activeRoles()) {
      if (!E.crops[role]) E.crops[role] = defaultBox(role);
      const box = el("div", `crop-box ${ROLE_CLASS[role] || ""}`);
      box.dataset.role = role;
      box.append(el("div", "tag", ROLE_TAG[role]));
      for (const c of ["nw", "ne", "sw", "se"]) {
        const g = el("div", `grip ${c}`);
        g.dataset.grip = c;
        box.append(g);
      }
      layer.append(box);
      positionBox(box, E.crops[role]);
      bindBoxDrag(box, role);
    }
  }

  function positionBox(node, b) {
    node.style.left = `${b.x * 100}%`;
    node.style.top = `${b.y * 100}%`;
    node.style.width = `${b.w * 100}%`;
    node.style.height = `${b.h * 100}%`;
  }

  function bindBoxDrag(node, role) {
    node.addEventListener("pointerdown", (ev) => {
      ev.preventDefault();
      const grip = ev.target.dataset.grip;
      const stage = $("#ve-crops").getBoundingClientRect();
      const start = { ...E.crops[role] };
      const x0 = ev.clientX;
      const y0 = ev.clientY;
      const r = roleRatio(role);
      const a = srcAspect();
      const MIN_W = 0.06;
      node.setPointerCapture(ev.pointerId);
      $("#ve-stage").classList.add("dragging");
      const onMove = (mv) => {
        const dx = (mv.clientX - x0) / stage.width;
        const dy = (mv.clientY - y0) / stage.height;
        const b = E.crops[role];
        if (!grip) {
          b.x = clamp(start.x + dx, 0, 1 - start.w);
          b.y = clamp(start.y + dy, 0, 1 - start.h);
        } else {
          const anchorX = grip.includes("w") ? start.x + start.w : start.x;
          const anchorY = grip.includes("n") ? start.y + start.h : start.y;
          const px = clamp((mv.clientX - stage.left) / stage.width, 0, 1);
          let w = Math.abs(px - anchorX);
          const maxWx = grip.includes("w") ? anchorX : 1 - anchorX;
          const maxHy = grip.includes("n") ? anchorY : 1 - anchorY;
          const maxWfromH = maxHy * r / a;
          w = clamp(w, MIN_W, Math.min(maxWx, maxWfromH));
          const h = w * a / r;
          b.w = w;
          b.h = h;
          b.x = grip.includes("w") ? anchorX - w : anchorX;
          b.y = grip.includes("n") ? anchorY - h : anchorY;
        }
        positionBox(node, b);
        if (role === "facecamFace") renderOutOverlays();       // the placement box keeps its aspect
        changed();
      };
      const onUp = () => {
        $("#ve-stage").classList.remove("dragging");
        node.removeEventListener("pointermove", onMove);
        node.removeEventListener("pointerup", onUp);
        node.removeEventListener("pointercancel", onUp);
      };
      node.addEventListener("pointermove", onMove);
      node.addEventListener("pointerup", onUp);
      node.addEventListener("pointercancel", onUp);
    });
  }

  /* ---- layout ---- */

  function setLayout(layout, force) {
    if (LEGACY_LAYOUTS[layout]) layout = LEGACY_LAYOUTS[layout].layout;
    if (!OUT_W[layout]) layout = "portrait";
    if (E.layout === layout && !force) return;
    E.layout = layout;
    for (const b of $$("#ve-layouts button")) b.setAttribute("aria-pressed", String(b.dataset.layout === layout));
    $("#ve-stacked").hidden = layout !== "stacked";
    $("#ve-portrait").hidden = layout !== "portrait";
    renderCropBoxes();
    syncOutFrame();
    changed();
  }

  function syncOutFrame() {
    if (E.layout === "landscape") { canvas.width = 960; canvas.height = 540; }
    else { canvas.width = 540; canvas.height = Math.round(540 / outRatio()); }
    refitWatermarkIfUntouched();
    renderOutOverlays();
    renderGuides();
    layoutStage();
  }

  function syncLookControls() {
    for (const b of $$("#ve-layouts button")) b.setAttribute("aria-pressed", String(b.dataset.layout === E.layout));
    $("#ve-blur").checked = E.blurBg;
    $("#ve-facecam").checked = E.facecam;
    $("#ve-main").value = String(Math.round(E.mainScale * 100));
    $("#ve-main-val").textContent = `${Math.round(E.mainScale * 100)}%`;
    $("#ve-45").checked = E.outH === 1350;
    $("#ve-divider").value = String(Math.round(E.divider * 100));
    $("#ve-divider-val").textContent = `${Math.round(E.divider * 100)}%`;
    $("#ve-wm").checked = E.watermark.enabled;
    $("#ve-wm").disabled = !E.wmExists;
    $("#ve-wm-note").textContent = E.wmExists ? "" : "(the PC has no watermark.png)";
    $("#ve-wm-size").hidden = !E.watermark.enabled;
    $("#ve-wm-scale").value = String(Math.round(E.watermark.w * 100));
    $("#ve-wm-val").textContent = `${Math.round(E.watermark.w * 100)}%`;
    for (const b of $$("#ve-guide-seg button")) b.setAttribute("aria-pressed", String(b.dataset.guide === guideMode));
    $("#ve-stacked").hidden = E.layout !== "stacked";
    $("#ve-portrait").hidden = E.layout !== "portrait";
    $("#ve-look-note").textContent = E.from;
  }

  for (const b of $$("#ve-layouts button")) b.addEventListener("click", () => setLayout(b.dataset.layout));
  $("#ve-blur").addEventListener("change", (e) => { E.blurBg = e.target.checked; changed(); });
  $("#ve-facecam").addEventListener("change", (e) => {
    E.facecam = e.target.checked;
    renderCropBoxes();
    renderOutOverlays();
    changed();
  });
  $("#ve-main").addEventListener("input", (e) => {
    E.mainScale = parseInt(e.target.value, 10) / 100;
    $("#ve-main-val").textContent = `${e.target.value}%`;
    changed();
  });
  $("#ve-45").addEventListener("change", (e) => {
    E.outH = e.target.checked ? 1350 : 1920;
    syncOutFrame();
    changed();
  });
  $("#ve-divider").addEventListener("input", (e) => {
    E.divider = parseInt(e.target.value, 10) / 100;
    $("#ve-divider-val").textContent = `${e.target.value}%`;
    for (const role of ["stackTop", "stackBottom"]) {
      const b = E.crops[role];
      if (!b) continue;
      const r = roleRatio(role);
      b.h = clamp(b.w * srcAspect() / r, 0.02, 1);
      b.w = b.h * r / srcAspect();
      b.x = clamp(b.x, 0, 1 - b.w);
      b.y = clamp(b.y, 0, 1 - b.h);
    }
    renderCropBoxes();
    syncOutFrame();
    changed();
  });
  $("#ve-wm").addEventListener("change", (e) => {
    E.watermark.enabled = e.target.checked && E.wmExists;
    $("#ve-wm-size").hidden = !E.watermark.enabled;
    renderOutOverlays();
    changed();
  });
  $("#ve-wm-scale").addEventListener("input", (e) => {
    E.watermark.w = parseInt(e.target.value, 10) / 100;
    $("#ve-wm-val").textContent = `${e.target.value}%`;
    E.wmTouched = true;
    renderOutOverlays();
    changed();
  });
  for (const b of $$("#ve-guide-seg button")) {
    b.addEventListener("click", () => {
      guideMode = b.dataset.guide;
      store.set("ve.guide", guideMode);
      for (const x of $$("#ve-guide-seg button")) x.setAttribute("aria-pressed", String(x === b));
      renderGuides();
    });
  }

  /* ---- the vertical version, drawn live (mirrors export.py's filter graph) ---- */

  const BLUR = document.createElement("canvas");
  const bctx = BLUR.getContext("2d");

  function drawPreview() {
    if (vid.readyState < 2 || !vid.videoWidth) return;
    const cv = canvas;
    const vw = vid.videoWidth;
    const vh = vid.videoHeight;
    const px = (b) => [b.x * vw, b.y * vh, b.w * vw, b.h * vh];
    ctx.clearRect(0, 0, cv.width, cv.height);
    if (E.layout === "landscape") {
      ctx.drawImage(vid, ...px(E.crops.landscape), 0, 0, cv.width, cv.height);
    } else if (E.layout === "stacked") {
      const hTop = Math.round(cv.height * E.divider);
      ctx.drawImage(vid, ...px(E.crops.stackTop), 0, 0, cv.width, hTop);
      ctx.drawImage(vid, ...px(E.crops.stackBottom), 0, hTop, cv.width, cv.height - hTop);
    } else {
      if (E.blurBg) {
        // The export's boxblur, approximated by drawing small and scaling up:
        // cheap enough for every frame on a phone, unlike a canvas blur filter.
        const k = 12;
        const sw = Math.max(8, Math.round(cv.width / k));
        const sh = Math.max(8, Math.round(cv.height / k));
        if (BLUR.width !== sw || BLUR.height !== sh) { BLUR.width = sw; BLUR.height = sh; }
        const scale = Math.max(sw / vw, sh / vh);
        const bw = vw * scale;
        const bh = vh * scale;
        bctx.drawImage(vid, 0, 0, vw, vh, (sw - bw) / 2, (sh - bh) / 2, bw, bh);
        ctx.imageSmoothingEnabled = true;
        ctx.imageSmoothingQuality = "high";
        ctx.drawImage(BLUR, 0, 0, cv.width, cv.height);
      } else {
        ctx.fillStyle = "#000";
        ctx.fillRect(0, 0, cv.width, cv.height);
      }
      const [mx, my, mw, mh] = px(E.crops.facecamMain);
      const dw = cv.width * E.mainScale;
      const dh = dw * (mh / mw);
      ctx.drawImage(vid, mx, my, mw, mh, (cv.width - dw) / 2, (cv.height - dh) / 2, dw, dh);
      if (E.facecam && E.crops.facecamFace) {
        const [fx, fy, fw, fh] = px(E.crops.facecamFace);
        const fdw = cv.width * E.faceBox.w;
        const fdh = fdw * (fh / fw);
        ctx.drawImage(vid, fx, fy, fw, fh, E.faceBox.x * cv.width, E.faceBox.y * cv.height, fdw, fdh);
      }
    }
    if (E.watermark.enabled && WM.loaded) {
      const w = cv.width * E.watermark.w;
      const h = w / (E.wmAspect || 4);
      ctx.drawImage(WM.img, E.watermark.x * cv.width, E.watermark.y * cv.height, w, h);
    }
  }

  /* ---- watermark + facecam placement, on the output ---- */

  const WM = { img: new Image(), loaded: false, hash: null, url: null };
  WM.img.onload = () => { WM.loaded = true; E.dirty = true; };

  async function loadWatermark() {
    const w = (ST.doc && ST.doc.watermark) || {};
    E.wmExists = !!w.exists;
    E.wmAspect = w.aspect || 0.5625;
    if (!w.exists || WM.hash === w.hash) return;
    try {
      const r = await dbx.download(w.path);
      const blob = await r.blob();
      if (WM.url) URL.revokeObjectURL(WM.url);
      WM.url = URL.createObjectURL(blob);
      WM.loaded = false;
      WM.hash = w.hash;
      WM.img.src = WM.url;
    } catch {
      E.wmExists = false;
    }
  }

  function fitWatermarkBox() {
    const outAspect = outRatio();
    const w = Math.min(1, (E.wmAspect || 0.5625) / outAspect);
    const h = (w * outAspect) / (E.wmAspect || 0.5625);
    return { x: (1 - w) / 2, y: (1 - h) / 2, w };
  }

  function refitWatermarkIfUntouched() {
    if (E.wmTouched) return;
    const b = fitWatermarkBox();
    E.watermark.x = b.x;
    E.watermark.y = b.y;
    E.watermark.w = b.w;
    $("#ve-wm-scale").value = String(Math.round(b.w * 100));
    $("#ve-wm-val").textContent = `${Math.round(b.w * 100)}%`;
  }

  // The facecam goes on top of the watermark here: the watermark is a
  // full-frame plate, and under it the facecam couldn't be grabbed at all.
  function outBoxes() {
    const list = [];
    if (E.watermark.enabled && E.wmExists) {
      list.push({ key: "wm", tag: "WATERMARK", box: E.watermark, aspect: E.wmAspect || 0.5625, cls: "wm", loose: true });
    }
    if (E.layout === "portrait" && E.facecam) {
      const c = E.crops.facecamFace;
      const aspect = c ? (c.w * srcAspect()) / c.h : 1;
      list.push({ key: "face", tag: "FACECAM", box: E.faceBox, aspect, cls: "face" });
    }
    return list;
  }

  const outBoxH = (o, outAspect) => (o.box.w * outAspect) / o.aspect;

  function renderOutOverlays() {
    const layer = $("#ve-outboxes");
    layer.replaceChildren();
    const outAspect = outRatio();
    for (const o of outBoxes()) {
      const node = el("div", `out-box ${o.cls}`);
      node.append(el("div", "tag", o.tag));
      const g = el("div", "grip se");
      g.dataset.grip = "se";
      node.append(g);
      layer.append(node);
      positionOutBox(node, o, outAspect);
      bindOutBoxDrag(node, o, outAspect);
    }
  }

  function positionOutBox(node, o, outAspect) {
    node.style.left = `${o.box.x * 100}%`;
    node.style.top = `${o.box.y * 100}%`;
    node.style.width = `${o.box.w * 100}%`;
    node.style.height = `${outBoxH(o, outAspect) * 100}%`;
  }

  function bindOutBoxDrag(node, o, outAspect) {
    node.addEventListener("pointerdown", (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      const grip = ev.target.dataset.grip;
      const stage = $("#ve-outboxes").getBoundingClientRect();
      const start = { ...o.box };
      const x0 = ev.clientX;
      const y0 = ev.clientY;
      node.setPointerCapture(ev.pointerId);
      const onMove = (mv) => {
        const dx = (mv.clientX - x0) / stage.width;
        const dy = (mv.clientY - y0) / stage.height;
        if (grip) {
          const w = clamp(start.w + dx, 0.05, 1 - o.box.x);
          const h = (w * outAspect) / o.aspect;
          o.box.w = h > 1 - o.box.y ? ((1 - o.box.y) * o.aspect) / outAspect : w;
        } else {
          const h = outBoxH(o, outAspect);
          if (o.loose) {
            const keepX = Math.max(0.02, o.box.w * OUT_BOX_MIN_VIS);
            const keepY = Math.max(0.02, h * OUT_BOX_MIN_VIS);
            o.box.x = clamp(start.x + dx, keepX - o.box.w, 1 - keepX);
            o.box.y = clamp(start.y + dy, keepY - h, 1 - keepY);
          } else {
            o.box.x = clamp(start.x + dx, 0, 1 - o.box.w);
            o.box.y = clamp(start.y + dy, 0, 1 - h);
          }
        }
        positionOutBox(node, o, outAspect);
        if (o.key === "wm") {
          E.wmTouched = true;
          $("#ve-wm-scale").value = String(Math.round(o.box.w * 100));
          $("#ve-wm-val").textContent = `${Math.round(o.box.w * 100)}%`;
        }
        changed();
      };
      const onUp = () => {
        node.removeEventListener("pointermove", onMove);
        node.removeEventListener("pointerup", onUp);
        node.removeEventListener("pointercancel", onUp);
      };
      node.addEventListener("pointermove", onMove);
      node.addEventListener("pointerup", onUp);
      node.addEventListener("pointercancel", onUp);
    });
  }

  function renderGuides() {
    const layer = $("#ve-guides");
    const keys = guideMode === "all" ? Object.keys(GUIDES) : GUIDES[guideMode] ? [guideMode] : [];
    const outAspect = outRatio();
    layer.replaceChildren(...keys.map((k) => {
      const g = GUIDES[k];
      const w = Math.min(1, g.r / outAspect);
      const h = (w * outAspect) / g.r;
      const box = el("div", "guide-box");
      box.style.left = `${((1 - w) / 2) * 100}%`;
      box.style.top = `${((1 - h) / 2) * 100}%`;
      box.style.width = `${w * 100}%`;
      box.style.height = `${h * 100}%`;
      box.append(el("span", null, g.label));
      return box;
    }));
  }

  /* ---- what the video area shows: the vertical version, or the crops ---- */

  function fit(w, h, aspect) {
    return w / h > aspect ? { w: h * aspect, h } : { w, h: w / aspect };
  }

  function layoutStage() {
    const stage = $("#ve-stage");
    const sw = stage.clientWidth;
    const sh = stage.clientHeight;
    if (!sw || !sh) return;
    const src = $("#ve-src");
    const out = $("#ve-out");
    const crop = E.view === "src";
    // The source keeps playing full size in both views (a phone stops drawing
    // a video it thinks is out of sight); in Preview it's covered.
    const s = fit(sw, sh, srcAspect());
    src.style.width = `${s.w}px`;
    src.style.height = `${s.h}px`;
    src.style.left = `${(sw - s.w) / 2}px`;
    src.style.top = crop ? "0px" : `${(sh - s.h) / 2}px`;
    $("#ve-cover").hidden = crop;
    out.classList.toggle("ve-inset", crop);
    if (!crop) {
      const o = fit(sw, sh, outRatio());
      Object.assign(out.style, { width: `${o.w}px`, height: `${o.h}px`, left: `${(sw - o.w) / 2}px`, top: `${(sh - o.h) / 2}px` });
    } else {
      // A small live preview: under the source when there's room, else in the corner.
      const free = sh - s.h;
      const roomy = free >= 110;
      const ih = roomy ? free - 8 : Math.round(sh * 0.42);
      const o = fit(sw * 0.5, ih, outRatio());
      Object.assign(out.style, { width: `${o.w}px`, height: `${o.h}px`,
        left: `${sw - o.w - 6}px`, top: `${roomy ? s.h + 4 : sh - o.h - 6}px` });
    }
    for (const b of $$(".ve-view button")) b.setAttribute("aria-pressed", String(b.dataset.view === E.view));
    E.dirty = true;
  }

  for (const b of $$(".ve-view button")) {
    b.addEventListener("click", () => {
      E.view = b.dataset.view;
      store.set("ve.view", E.view);
      layoutStage();
    });
  }

  /* ---- audio: every track through Web Audio, so mute and volume are heard ---- */

  const AE = { ctx: null, gains: [], buffers: [], sources: null, startedCtx: 0, startedVid: 0, driftTimer: 0, ready: false, token: 0 };

  function audioCtx() {
    if (!AE.ctx) {
      const AC = window.AudioContext || window.webkitAudioContext;
      AE.ctx = new AC();
      // iPhone: play through the ring/silent switch, like a video does.
      try { if (navigator.audioSession) navigator.audioSession.type = "playback"; } catch { /* older iOS */ }
    }
    return AE.ctx;
  }

  async function loadAudio(token) {
    const ac = audioCtx();
    AE.gains.forEach((g) => g.disconnect());
    AE.gains = E.tracks.map(() => {
      const g = ac.createGain();
      g.connect(ac.destination);
      return g;
    });
    applyGains();
    AE.buffers = [];
    const files = E.copy.tracks || [];
    await Promise.all(files.map(async (f, i) => {
      if (f.silent) return;                 // nothing to hear, and it'd cost memory
      const url = await link(`${E.copy.folder}/${f.file}`);
      const r = await fetch(url);
      if (!r.ok) throw new Error(`track ${i + 1}: ${r.status}`);
      const buf = await ac.decodeAudioData(await r.arrayBuffer());
      if (token === AE.token) AE.buffers[i] = buf;
    }));
    if (token !== AE.token) return;
    AE.ready = true;
    clearInterval(AE.driftTimer);
    AE.driftTimer = setInterval(driftCheck, 800);
  }

  function applyGains() {
    E.tracks.forEach((t, i) => {
      if (AE.gains[i]) AE.gains[i].gain.value = t.enabled ? t.volume : 0;
    });
  }

  function startSources() {
    if (!AE.ready) return;
    stopSources();
    const t0 = AE.ctx.currentTime + 0.03;
    const off = vid.currentTime;
    AE.sources = AE.buffers.map((buf, i) => {
      if (!buf) return null;
      const s = AE.ctx.createBufferSource();
      s.buffer = buf;
      s.connect(AE.gains[i]);
      if (off >= 0 && off < buf.duration) s.start(t0, off);
      return s;
    }).filter(Boolean);
    AE.startedCtx = t0;
    AE.startedVid = off;
  }

  function stopSources() {
    if (AE.sources) for (const s of AE.sources) { try { s.stop(); } catch { /* not started */ } }
    AE.sources = null;
  }

  function driftCheck() {
    if (!E.open || vid.paused || !AE.sources) return;
    const expected = AE.startedVid + (AE.ctx.currentTime - AE.startedCtx);
    if (Math.abs(vid.currentTime - expected) > 0.08) startSources();
  }

  vid.addEventListener("play", () => { if (AE.ctx) AE.ctx.resume(); startSources(); $("#ve-play").textContent = "Pause"; });
  vid.addEventListener("pause", () => { stopSources(); $("#ve-play").textContent = "Play"; E.tlDirty = true; });
  vid.addEventListener("seeked", () => { if (!vid.paused) startSources(); E.dirty = true; E.tlDirty = true; });

  function trackLabel(i) {
    const cfgTrack = ((ST.doc || {}).tracks || [])[i];
    const title = (E.clip.audio || [])[i];
    return cfgTrack && cfgTrack.label ? cfgTrack.label : (title || `Track ${i + 1}`);
  }

  function renderTracks() {
    const ul = $("#ve-tracks");
    ul.replaceChildren();
    E.tracks.forEach((t, i) => {
      const li = el("li", `ve-track${t.enabled ? "" : " muted-track"}`);
      li.style.setProperty("--tc", TRACK_COLORS[i % TRACK_COLORS.length]);
      const top = el("div", "ve-track-top");
      const name = el("span", "ve-track-name", trackLabel(i));
      const cfgTrack = ((ST.doc || {}).tracks || [])[i];
      if (cfgTrack && cfgTrack.obs_track) name.append(el("small", null, ` T${cfgTrack.obs_track}`));
      if (t.silent) name.append(el("small", "muted", "  silent"));
      top.append(el("span", "ve-swatch"), name);
      const wave = button(`ve-tbtn${t.wave ? " on" : ""}`, "Wave", () => {
        t.wave = !t.wave;
        store.set("ve.waves", E.tracks.map((x) => x.wave));
        renderTracks();
        sizeTimeline();
      });
      wave.setAttribute("aria-pressed", String(t.wave));
      const mute = button(`ve-tbtn mute${t.enabled ? "" : " on"}`, "M", () => {
        t.enabled = !t.enabled;
        applyGains();
        renderTracks();
        changed();
      });
      mute.setAttribute("aria-label", t.enabled ? `Mute ${trackLabel(i)}` : `Unmute ${trackLabel(i)}`);
      mute.setAttribute("aria-pressed", String(!t.enabled));
      top.append(wave, mute);
      const row = el("div", "ve-track-vol");
      const slider = el("input");
      Object.assign(slider, { type: "range", min: "0", max: "200", step: "1", value: String(Math.round(t.volume * 100)) });
      slider.setAttribute("aria-label", `${trackLabel(i)} volume`);
      const val = el("span", "mono", `${Math.round(t.volume * 100)}%`);
      slider.addEventListener("input", () => {
        t.volume = Number(slider.value) / 100;
        val.textContent = `${slider.value}%`;
        applyGains();
        changed();
      });
      row.append(slider, val);
      li.append(top, row);
      ul.append(li);
    });
    const on = E.tracks.filter((t) => t.enabled).length;
    $("#ve-audio-note").textContent = on ? "" : "Every track is muted, so the export will be silent.";
  }

  /* ---- the timeline: waveforms, trim handles, playhead ---- */

  function sizeTimeline() {
    const lanes = E.tracks.filter((t) => t.wave).length;
    tl.style.height = `${lanes ? Math.min(118, 30 + 30 * lanes) : 44}px`;
    E.tlDirty = true;
  }

  function setView(start, end) {
    const span = end - start;
    start = clamp(start, 0, Math.max(0, E.dur - span));
    E.viewStart = start;
    E.viewEnd = Math.min(E.dur, start + span);
    E.tlDirty = true;
  }

  function applyZoom(center) {
    const span = zoomLevels()[E.zoom] || E.dur;
    const c = center == null ? vid.currentTime : center;
    setView(c - span / 2, c - span / 2 + span);
    $("#ve-zoom-label").textContent = span >= E.dur ? "All" : `${span}s`;
  }

  // The zoom steps this clip has: the whole clip, then each one shorter than it.
  const zoomLevels = () => [0, ...ZOOMS.slice(1).filter((s) => s < E.dur)];
  for (const b of $$("[data-vzoom]")) {
    b.addEventListener("click", () => {
      E.zoom = clamp(E.zoom + Number(b.dataset.vzoom), 0, zoomLevels().length - 1);
      applyZoom();
    });
  }

  const span = () => Math.max(0.01, E.viewEnd - E.viewStart);
  const xOfT = (t, w) => ((t - E.viewStart) / span()) * w;
  const tOfX = (x, w) => clamp(E.viewStart + (x / w) * span(), 0, E.dur);

  function drawTimeline() {
    const dpr = window.devicePixelRatio || 1;
    const w = tl.clientWidth;
    const h = tl.clientHeight;
    if (!w || !h) return;
    if (tl.width !== Math.round(w * dpr) || tl.height !== Math.round(h * dpr)) {
      tl.width = Math.round(w * dpr);
      tl.height = Math.round(h * dpr);
    }
    const c = tctx;
    c.setTransform(dpr, 0, 0, dpr, 0, 0);
    c.clearRect(0, 0, w, h);
    c.fillStyle = "#0b0f14";
    c.fillRect(0, 0, w, h);
    const lanes = E.tracks.map((t, i) => (t.wave ? i : -1)).filter((i) => i >= 0);
    const peaks = E.peaks;
    if (lanes.length && peaks) {
      const laneH = h / lanes.length;
      const bps = peaks.buckets / (peaks.duration || E.dur || 1);
      lanes.forEach((ti, li) => {
        const p = peaks.tracks[ti] || [];
        const ref = E.peakMax[ti] || 32768;
        const mid = laneH * li + laneH / 2;
        c.fillStyle = E.tracks[ti].enabled ? TRACK_COLORS[ti % TRACK_COLORS.length] : "#3a4048";
        c.globalAlpha = 0.9;
        const step = 1 / dpr;
        for (let x = 0; x < w; x += step) {
          const t0 = E.viewStart + (x / w) * span();
          const t1 = E.viewStart + ((x + step) / w) * span();
          const b0 = Math.floor(t0 * bps);
          const b1 = Math.max(b0 + 1, Math.ceil(t1 * bps));
          let m = 0;
          for (let b = b0; b < b1 && b < p.length; b++) if (p[b] > m) m = p[b];
          const a = Math.sqrt(Math.min(1, m / ref));
          const bh = Math.max(step, a * (laneH / 2 - 2));
          c.fillRect(x, mid - bh, step, bh * 2);
        }
        c.globalAlpha = 1;
        if (li) {
          c.fillStyle = "#21262d";
          c.fillRect(0, laneH * li, w, 1);
        }
      });
    }
    // Outside the trim, dimmed; the handles at its edges.
    const xi = xOfT(E.inS, w);
    const xo = xOfT(E.outS, w);
    c.fillStyle = "rgba(0, 0, 0, 0.62)";
    if (xi > 0) c.fillRect(0, 0, Math.min(w, xi), h);
    if (xo < w) c.fillRect(Math.max(0, xo), 0, w - Math.max(0, xo), h);
    c.fillStyle = "#22d3ee";
    for (const [x, inward] of [[xi, 1], [xo, -1]]) {
      if (x < -12 || x > w + 12) continue;
      c.fillRect(x - 1.5, 0, 3, h);
      c.beginPath();                       // a tab to grab, pointing into the trim
      const ty = h / 2;
      c.moveTo(x, ty - 14);
      c.lineTo(x + inward * 11, ty - 8);
      c.lineTo(x + inward * 11, ty + 8);
      c.lineTo(x, ty + 14);
      c.closePath();
      c.fill();
    }
    E.tlDirty = false;
  }

  function placePlayhead() {
    const w = tl.clientWidth;
    const x = xOfT(vid.currentTime, w);
    const ph = $("#ve-playhead");
    ph.hidden = x < 0 || x > w;
    ph.style.transform = `translateX(${x}px)`;
  }

  // Dragging: the handles trim, anywhere else scrubs.
  const DRAG = { mode: null, resume: false, lastSeek: 0, pending: null };

  function scrubTo(t, final) {
    DRAG.pending = t;
    const now = performance.now();
    if (!final && now - DRAG.lastSeek < 70) return;
    DRAG.lastSeek = now;
    if (!final && typeof vid.fastSeek === "function") vid.fastSeek(t);
    else vid.currentTime = t;
    E.dirty = true;
  }

  tl.addEventListener("pointerdown", (ev) => {
    if (!E.open) return;
    ev.preventDefault();
    const r = tl.getBoundingClientRect();
    const x = ev.clientX - r.left;
    const xi = xOfT(E.inS, r.width);
    const xo = xOfT(E.outS, r.width);
    const di = Math.abs(x - xi);
    const dO = Math.abs(x - xo);
    DRAG.mode = di < 22 && di <= dO ? "in" : dO < 22 ? "out" : "scrub";
    DRAG.resume = !vid.paused;
    if (DRAG.resume) vid.pause();
    tl.setPointerCapture(ev.pointerId);
    move(ev);
  });

  function move(ev) {
    if (!DRAG.mode) return;
    const r = tl.getBoundingClientRect();
    const t = tOfX(ev.clientX - r.left, r.width);
    if (DRAG.mode === "in") {
      E.inS = clamp(t, 0, E.outS - 0.2);
      scrubTo(E.inS);
      trimChanged();
    } else if (DRAG.mode === "out") {
      E.outS = clamp(t, E.inS + 0.2, E.dur);
      scrubTo(E.outS);
      trimChanged();
    } else {
      scrubTo(t);
    }
    E.tlDirty = true;
  }

  function endDrag() {
    if (!DRAG.mode) return;
    if (DRAG.pending != null) scrubTo(DRAG.pending, true);
    if (DRAG.mode !== "scrub") changed();
    if (DRAG.resume) playVideo();
    DRAG.mode = null;
    DRAG.pending = null;
  }

  tl.addEventListener("pointermove", move);
  tl.addEventListener("pointerup", endDrag);
  tl.addEventListener("pointercancel", endDrag);
  tl.addEventListener("contextmenu", (e) => e.preventDefault());

  function trimChanged() {
    $("#ve-trim").textContent = `Trim ${(E.outS - E.inS).toFixed(1)}s`;
    E.tlDirty = true;
    renderSummary();
  }

  /* ---- transport ---- */

  function playVideo() {
    if (!AE.ready) {
      toast("The audio is still loading.");
      return;
    }
    audioCtx().resume();
    const p = vid.play();
    if (p && p.catch) p.catch(() => {});
  }

  $("#ve-play").addEventListener("click", () => (vid.paused ? playVideo() : vid.pause()));
  const frameStep = (dir) => {
    vid.pause();
    vid.currentTime = clamp(vid.currentTime + dir / (E.fps || 60), 0, E.dur);
  };
  $("#ve-back1").addEventListener("click", () => frameStep(-1));
  $("#ve-fwd1").addEventListener("click", () => frameStep(1));
  $("#ve-in").addEventListener("click", () => { E.inS = clamp(vid.currentTime, 0, E.outS - 0.2); trimChanged(); changed(); });
  $("#ve-outpt").addEventListener("click", () => { E.outS = clamp(vid.currentTime, E.inS + 0.2, E.dur); trimChanged(); changed(); });
  $("#ve-loop").addEventListener("click", () => {
    E.loop = !E.loop;
    store.set("ve.loop", E.loop);
    $("#ve-loop").setAttribute("aria-pressed", String(E.loop));
  });

  function frame() {
    if (!E.open) return;
    const t = vid.currentTime;
    // Loop plays the trim over and over; without it playback runs past it.
    if (!vid.paused && E.loop && E.outS > E.inS && t >= E.outS) vid.currentTime = E.inS;
    if (!vid.paused && E.zoom > 0 && (t < E.viewStart || t > E.viewEnd - 0.05)) {
      const s = span();
      setView(t - s * 0.1, t - s * 0.1 + s);
    }
    $("#ve-now").textContent = fmtTime(t, true);
    if (E.tlDirty) drawTimeline();
    placePlayhead();
    if (!vid.paused || E.dirty) {
      drawPreview();
      E.dirty = false;
    }
    E.raf = requestAnimationFrame(frame);
  }

  /* ---- the look as the exporter takes it ---- */

  function mixPayload() {
    return {
      layout: E.layout,
      crops: E.crops,
      divider: E.divider,
      audio: E.tracks.map((t) => ({ enabled: t.enabled, volume: t.volume })),
      main_scale: E.mainScale,
      out_h: E.outH,
      blur_bg: E.blurBg,
      facecam: E.facecam,
      face_box: { ...E.faceBox },
      watermark: { enabled: E.watermark.enabled, x: E.watermark.x, y: E.watermark.y, scale: E.watermark.w },
    };
  }

  // A preset, a draft or the last clip's look, onto this clip (presetApply on the PC).
  function applyLook(p) {
    E.crops = JSON.parse(JSON.stringify(p.crops || {}));
    E.divider = typeof p.divider === "number" ? p.divider : 0.35;
    E.mainScale = Math.max(1, typeof p.main_scale === "number" ? p.main_scale : 1);
    E.outH = p.out_h === 1350 ? 1350 : 1920;
    if (p.face_box) E.faceBox = { ...E.faceBox, ...p.face_box };
    const legacy = LEGACY_LAYOUTS[p.layout];
    if (legacy && E.crops.blur && !E.crops.facecamMain) E.crops.facecamMain = { ...E.crops.blur };
    E.blurBg = legacy ? legacy.blurBg : p.blur_bg !== false;
    E.facecam = legacy ? legacy.facecam : !!p.facecam;
    const w = p.watermark || {};
    E.watermark = {
      enabled: !!w.enabled && E.wmExists,
      x: typeof w.x === "number" ? w.x : E.watermark.x,
      y: typeof w.y === "number" ? w.y : E.watermark.y,
      w: typeof w.scale === "number" ? w.scale : E.watermark.w,
    };
    E.wmTouched = true;
    if (Array.isArray(p.audio)) {
      E.tracks.forEach((t, i) => {
        const a = p.audio[i];
        if (!a) return;
        t.enabled = a.enabled !== false;
        t.volume = typeof a.volume === "number" ? a.volume : 1;
      });
    }
    applyGains();
    setLayout(p.layout || E.layout, true);
    syncLookControls();
    renderTracks();
    E.tlDirty = true;
  }

  function layoutSummary() {
    if (E.layout !== "portrait") return LAYOUT_NAMES[E.layout] || E.layout;
    const bits = [E.blurBg ? "blur bg" : "black bg"];
    if (E.facecam) bits.push("facecam");
    if (E.mainScale !== 1) bits.push(`main ${Math.round(E.mainScale * 100)}%`);
    return `Portrait 1080x${E.outH} · ${bits.join(", ")}`;
  }

  function renderSummary() {
    if (!E.open) return;
    const on = E.tracks.map((t, i) => (t.enabled ? trackLabel(i) + (t.volume !== 1 ? ` ${Math.round(t.volume * 100)}%` : "") : null)).filter(Boolean);
    $("#ve-summary").replaceChildren(
      el("div", null, layoutSummary()),
      el("div", null, `Trim: ${fmtTime(E.inS, true)} to ${fmtTime(E.outS, true)} (${(E.outS - E.inS).toFixed(1)}s)`),
      el("div", null, `Audio: ${on.length ? on.join(", ") : "none (silent)"}`));
  }

  /* ---- saving the edit: a draft per clip, in Dropbox ---- */

  let draftTimer = 0;
  function changed() {
    E.dirty = true;
    if (!E.open || E.loading) return;
    E.touched = true;
    renderSummary();
    clearTimeout(draftTimer);
    draftTimer = setTimeout(saveDraft, 1200);
  }

  function draftDoc() {
    return { v: 1, clip: E.id, saved_at: new Date().toISOString(), name: $("#ve-name").value, in: E.inS, out: E.outS,
             duration: E.dur, look: mixPayload() };
  }

  function saveDraft() {
    clearTimeout(draftTimer);
    if (!E.open || !E.id || !E.touched) return;
    const doc = draftDoc();
    outbox.put(`${DRAFTS}/${E.id}.json`, JSON.stringify(doc));
    store.set("ve.lastLook", doc.look);
  }

  async function loadDraft(id) {
    const path = `${DRAFTS}/${id}.json`;
    const queued = outbox.ops.filter((o) => o.kind === "put" && o.path.toLowerCase() === path.toLowerCase()).pop();
    if (queued) return JSON.parse(queued.text);
    try {
      const r = await dbx.download(path);
      return JSON.parse(await r.text());
    } catch (e) {
      if (notFound(e)) return null;
      throw e;
    }
  }

  /* ---- presets (the PC's presets.json, through the worker) ---- */

  let presetOps = [];          // sent but not yet in state.json: {op, name, look, at}

  function presetList() {
    let list = ((ST.doc || {}).presets || []).slice();
    for (const op of presetOps) {
      list = list.filter((p) => p.name.toLowerCase() !== op.name.toLowerCase());
      if (op.op === "save") list.push({ name: op.name, ...op.look, pending: true });
    }
    return list.sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
  }

  function settlePresets() {
    const have = new Map(((ST.doc || {}).presets || []).map((p) => [p.name.toLowerCase(), p]));
    presetOps = presetOps.filter((op) => {
      if (Date.now() - op.at > 120e3) return false;
      const p = have.get(op.name.toLowerCase());
      return op.op === "save" ? !p || JSON.stringify(p.crops) !== JSON.stringify(op.look.crops) : !!p;
    });
  }

  function renderPresets() {
    const ul = $("#ve-presets");
    ul.replaceChildren();
    const list = presetList();
    if (!list.length) ul.append(el("li", "muted small", "No presets yet."));
    for (const p of list) {
      const li = el("li", "ve-preset");
      li.append(el("span", "ve-preset-name", p.name + (p.pending ? "  (saving)" : "")));
      li.append(button("btn btn-small", "Apply", () => {
        applyLook(p);
        E.from = `Look: the "${p.name}" preset.`;
        $("#ve-look-note").textContent = E.from;
        $("#ve-preset-note").textContent = `Applied "${p.name}".`;
        changed();
      }));
      li.append(button("btn btn-ghost btn-small btn-danger", "Delete", () => {
        if (!window.confirm(`Delete the preset "${p.name}"? It's gone from the PC too.`)) return;
        sendRequest({ type: "preset_delete", name: p.name });
        presetOps.push({ op: "delete", name: p.name, at: Date.now() });
        $("#ve-preset-note").textContent = `Deleting "${p.name}".`;
        renderPresets();
      }));
      ul.append(li);
    }
  }

  $("#ve-preset-save").addEventListener("click", () => {
    const name = (window.prompt("Save preset as", "") || "").trim().slice(0, 60);
    if (!name) return;
    const old = presetList().find((p) => p.name.toLowerCase() === name.toLowerCase());
    if (old && !window.confirm(`Replace the preset "${old.name}"?`)) return;
    // Keep the PC's lane choices for a preset it already had; the phone's
    // own waveform picks stay on the phone.
    const look = { ...mixPayload(), audio: E.tracks.map((t, i) => ({
      enabled: t.enabled, solo: false, volume: t.volume,
      hidden: old && Array.isArray(old.audio) && old.audio[i] ? !!old.audio[i].hidden : true })) };
    sendRequest({ type: "preset_save", name, look });
    presetOps.push({ op: "save", name, look, at: Date.now() });
    $("#ve-preset-note").textContent = `Saving "${name}". The PC has it in a few seconds.`;
    renderPresets();
  });

  /* ---- exporting ---- */

  // Mirrors export.py's sanitize_name, so the name shown is the file's.
  function safeStem(name) {
    return (name || "").replace(/[<>:"/\\|?*]/g, "_").replace(/[\x00-\x1f]/g, "_")
      .trim().split(/\s+/).join(" ").replace(/^[. ]+|[. ]+$/g, "").slice(0, 80);
  }

  function renderPath() {
    const stem = safeStem($("#ve-name").value);
    const finals = new Set((ST.doc || {}).finals || []);
    let text = stem ? `Saves to ${stage2Name()}/${stem}.mp4` : "It needs a name.";
    if (stem && finals.has(stem.toLowerCase())) {
      let n = 2;
      while (finals.has(`${stem} (${n})`.toLowerCase())) n++;
      text = `${stage2Name()} already has "${stem}". This one saves as "${stem} (${n})".`;
    }
    $("#ve-path").textContent = text;
    $("#ve-export").disabled = !stem;
  }

  function renderJobs() {
    const ul = $("#ve-jobs");
    ul.replaceChildren(...allJobs(E.id).slice(0, 6).map((j) => jobRow(j, true)));
  }

  $("#ve-name").addEventListener("input", () => { renderPath(); changed(); });
  $("#ve-name").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); e.target.blur(); } });

  $("#ve-export").addEventListener("click", () => {
    const name = safeStem($("#ve-name").value);
    if (!name) return;
    if (E.outS - E.inS < 0.199) {           // 0.2 s is the shortest the handles allow
      toast("The trim is too short.");
      return;
    }
    if (!E.tracks.some((t) => t.enabled) && !window.confirm("Every track is muted. Export it silent?")) return;
    const id = `j${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
    sendRequest({ type: "export", id, clip: E.id, name, in: Math.round(E.inS * 1000) / 1000,
                  out: Math.round(E.outS * 1000) / 1000, look: mixPayload() });
    E.touched = true;                       // keep this edit with the clip, for a redo
    saveDraft();
    renderJobs();
    $("#ve-next").hidden = !nextClip();
    toast(`Sent "${name}" to the PC.`, nextClip() ? { label: "Next clip", run: openNext } : null);
  });

  function nextClip() {
    const d = ST.doc;
    if (!d) return null;
    const flat = [];
    for (const g of d.groups || []) for (const id of g.clips) if (d.clips[id]) flat.push(id);
    const i = flat.indexOf(E.id);
    const order = i >= 0 ? [...flat.slice(i + 1), ...flat.slice(0, i)] : flat;
    const busy = new Set(allJobs().filter((j) => !["done", "failed", "cancelled"].includes(j.status)).map((j) => j.clip));
    return order.find((id) => !d.clips[id].done && d.clips[id].copy && d.clips[id].copy.status === "ready" && !busy.has(id)) || null;
  }

  function openNext() {
    const id = nextClip();
    if (id) openEditor(id);
  }
  $("#ve-next").addEventListener("click", openNext);

  /* ---- tabs ---- */

  function openTab(tab) {
    E.tab = tab;
    store.set("ve.tab", tab);
    $("#ve-panel").hidden = false;
    for (const p of $$(".ve-pane")) p.hidden = p.dataset.pane !== tab;
    for (const b of $$(".ve-tabs button")) b.setAttribute("aria-selected", String(b.dataset.tab === tab));
    if (tab === "presets") renderPresets();
    if (tab === "export") { renderSummary(); renderPath(); renderJobs(); }
    requestAnimationFrame(layoutStage);
  }

  // Tapping the open tab folds the panel away, for a bigger preview.
  function setTab(tab) {
    if (E.tab === tab && !$("#ve-panel").hidden) {
      $("#ve-panel").hidden = true;
      for (const b of $$(".ve-tabs button")) b.setAttribute("aria-selected", "false");
      requestAnimationFrame(layoutStage);
      return;
    }
    openTab(tab);
  }
  for (const b of $$(".ve-tabs button")) b.addEventListener("click", () => setTab(b.dataset.tab));

  /* ---- opening and leaving a clip ---- */

  const LINKS = new Map();
  async function link(path, fresh) {
    const hit = LINKS.get(path);
    if (!fresh && hit && Date.now() - hit.at < 3.5 * 3600e3) return hit.url;
    const r = await dbx.rpc("files/get_temporary_link", { path });
    LINKS.set(path, { url: r.link, at: Date.now() });
    return r.link;
  }

  function msg(text) {
    $("#ve-msg").hidden = !text;
    $("#ve-msg").textContent = text || "";
  }

  async function openEditor(id) {
    const d = ST.doc;
    const c = d && d.clips[id];
    if (!c || !c.copy || c.copy.status !== "ready") return;
    leaveEditor();
    clearTimeout(ST.timer);
    E.id = id;
    E.clip = c;
    E.copy = c.copy;
    E.open = true;
    E.loading = true;                       // what opening sets up isn't an edit
    E.touched = false;
    show("#screen-vedit");
    A.renderSync();
    $("#ve-title").textContent = c.name;
    msg("Loading the clip");
    $("#ve-play").textContent = "Loading audio";
    E.dur = E.copy.duration || c.duration;
    E.fps = c.fps || E.copy.fps || 60;
    E.srcW = c.width || 1920;
    E.srcH = c.height || 1080;
    E.view = store.get("ve.view", "out") === "src" ? "src" : "out";
    E.loop = store.get("ve.loop", true) !== false;
    $("#ve-loop").setAttribute("aria-pressed", String(E.loop));
    // Defaults, as the PC opens a clip: then the draft, or the last clip's look.
    Object.assign(E, { layout: "portrait", crops: {}, divider: 0.35, mainScale: 1, outH: 1920, blurBg: true, facecam: false,
      faceBox: { x: 0.05, y: 0.62, w: 0.28 }, watermark: { enabled: false, x: 0, y: 0, w: 1 }, wmTouched: false,
      inS: 0, outS: E.dur, zoom: 0, peaks: null, peakMax: [] });
    const waves = store.get("ve.waves", null);
    const micIdx = (d.tracks || []).findIndex((t) => t.obs_track === d.mic_obs_track);
    E.tracks = (c.audio || []).map((_, i) => ({
      enabled: true, volume: 1, silent: !!((E.copy.tracks || [])[i] || {}).silent,
      wave: Array.isArray(waves) && waves.length === (c.audio || []).length ? !!waves[i] : i === micIdx,
    }));
    await loadWatermark();
    let draft = null;
    try { draft = await loadDraft(id); } catch { /* offline: start fresh */ }
    if (E.id !== id) return;
    const last = store.get("ve.lastLook", null);
    const presets = d.presets || [];
    if (draft && draft.look) {
      applyLook(draft.look);
      E.inS = clamp(Number(draft.in) || 0, 0, Math.max(0, E.dur - 0.2));
      E.outS = clamp(Number(draft.out) || E.dur, E.inS + 0.2, E.dur);
      E.from = "Look: where you left this clip.";
    } else if (last) {
      applyLook(last);
      E.from = "Look: from the last clip you edited here.";
    } else if (presets.length) {
      applyLook(presets[0]);
      E.from = `Look: the "${presets[0].name}" preset.`;
    } else {
      setLayout("portrait", true);
      syncLookControls();
      renderTracks();
      E.from = "";
    }
    $("#ve-name").value = draft && typeof draft.name === "string" && draft.name ? draft.name : c.name;
    syncLookControls();
    renderTracks();
    sizeTimeline();
    applyZoom(0);
    trimChanged();
    openTab(["look", "audio", "presets", "export"].includes(E.tab) ? E.tab : "look");
    $("#ve-next").hidden = true;
    E.loading = false;
    layoutStage();

    const token = ++AE.token;
    try {
      vid.crossOrigin = "anonymous";
      vid.src = await link(`${E.copy.folder}/${E.copy.video}`);
      vid.load();
    } catch (e) {
      msg(`Couldn't load the video: ${errText(e)}`);
    }
    dbx.download(`${E.copy.folder}/${E.copy.peaks}`).then((r) => r.json()).then((p) => {
      if (token !== AE.token) return;
      E.peaks = p;
      E.peakMax = (p.tracks || []).map((t) => t.reduce((m, v) => (v > m ? v : m), 0) || 32768);
      E.tlDirty = true;
    }).catch(() => {});
    loadAudio(token).then(() => {
      if (token === AE.token) $("#ve-play").textContent = vid.paused ? "Play" : "Pause";
    }).catch((e) => {
      if (token !== AE.token) return;
      $("#ve-play").textContent = "Play";
      AE.ready = true;                     // play on without sound rather than not at all
      toast(`The audio didn't load (${errText(e)}). Playing without it.`);
    });
    cancelAnimationFrame(E.raf);
    E.raf = requestAnimationFrame(frame);
    schedule(EDIT_POLL_MS);
  }

  let linkRetry = 0;
  vid.addEventListener("loadeddata", () => { msg(""); E.dirty = true; });
  vid.addEventListener("error", async () => {
    if (!E.open || !vid.getAttribute("src")) return;
    // Dropbox's links last 4 hours; past that, get a fresh one and carry on.
    if (Date.now() - linkRetry > 30e3) {
      linkRetry = Date.now();
      const at = vid.currentTime;
      try {
        vid.src = await link(`${E.copy.folder}/${E.copy.video}`, true);
        vid.currentTime = at;
        return;
      } catch { /* fall through */ }
    }
    msg("The video didn't load. Go back and open the clip again.");
  });

  function leaveEditor() {
    if (!E.open) return;
    saveDraft();
    E.open = false;
    AE.token++;
    cancelAnimationFrame(E.raf);
    stopSources();
    clearInterval(AE.driftTimer);
    AE.buffers = [];
    AE.ready = false;
    vid.pause();
    vid.removeAttribute("src");
    vid.load();
  }

  function onStateWhileEditing() {
    settlePresets();
    if (!$("#ve-panel").hidden) {
      if (E.tab === "presets") renderPresets();
      if (E.tab === "export") { renderPath(); renderJobs(); }
    }
    const c = ST.doc && ST.doc.clips[E.id];
    if (c && c.copy && c.copy.status === "ready" && c.copy.stamp !== E.copy.stamp) {
      toast("The PC remade this clip's copy (the clip changed). Open it again to see the new one.");
      E.copy = { ...E.copy, stamp: c.copy.stamp };
    }
  }

  $("#ve-back").addEventListener("click", showList);

  window.addEventListener("resize", () => { if (E.open) { layoutStage(); E.tlDirty = true; } });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      if (E.open) {
        vid.pause();
        saveDraft();
      }
      return;
    }
    const cur = A.current();
    if (cur === "#screen-vlist" || cur === "#screen-vedit") tickPoll();
  });
  window.addEventListener("pagehide", () => { if (E.open) saveDraft(); });

  window.MSEDIT = {
    reset() {
      leaveEditor();
      ST.doc = null;
      sent = {};
      store.del("ve.sent");
    },
  };
  if (A.debug) window.__ve = { E, ST, AE, WM, mixPayload, applyLook, fetchState, renderList, openEditor, nextClip, sent: () => sent };
})();
