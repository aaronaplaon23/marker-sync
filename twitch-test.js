"use strict";

(() => {
  // Aaron's Sept 16 stream (RLCraft part starts around 1:11:52 of the VOD).
  const VOD = "2876359365";
  const $ = (s) => document.querySelector(s);
  const fmt = (t) => {
    t = Math.max(0, t || 0);
    const h = Math.floor(t / 3600), m = Math.floor((t % 3600) / 60), s = (t % 60).toFixed(1).padStart(4, "0");
    return `${h}:${String(m).padStart(2, "0")}:${s}`;
  };
  const log = (msg) => {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = `${new Date().toLocaleTimeString()}  ${msg}`;
    $("#tt-log").prepend(li);
  };

  if (!window.Twitch || !window.Twitch.Player) {
    $("#tt-state").textContent = "Twitch script blocked";
    log("The Twitch player script did not load.");
    return;
  }

  const player = new window.Twitch.Player("player", {
    video: VOD,
    time: "1h12m0s",
    autoplay: false,
    width: "100%",
    height: "100%",
    parent: [location.hostname],
  });

  const P = window.Twitch.Player;
  const events = ["READY", "PLAY", "PLAYING", "PAUSE", "SEEK", "ENDED", "OFFLINE", "ONLINE", "CAPTIONS"];
  for (const name of events) {
    if (P[name]) player.addEventListener(P[name], () => {
      log(`event ${name} at ${fmt(player.getCurrentTime())}`);
      $("#tt-state").textContent = name.toLowerCase();
    });
  }
  player.addEventListener(P.READY, () => {
    try { log(`qualities: ${(player.getQualities() || []).map((q) => q.name || q.group || q).join(", ") || "(none yet)"}`); } catch (e) { log(`getQualities failed: ${e.message}`); }
    try { log(`duration: ${fmt(player.getDuration())}`); } catch (e) { log(`getDuration failed: ${e.message}`); }
  });

  const tick = () => {
    try { $("#tt-now").textContent = fmt(player.getCurrentTime()); } catch { /* not ready */ }
    requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);

  $("#tt-play").addEventListener("click", () => player.play());
  $("#tt-pause").addEventListener("click", () => player.pause());
  for (const b of document.querySelectorAll("[data-skip]")) {
    b.addEventListener("click", () => player.seek(player.getCurrentTime() + Number(b.dataset.skip)));
  }
  $("#tt-jump").addEventListener("click", () => player.seek(4800));
  $("#tt-mark").addEventListener("click", () => {
    const t = player.getCurrentTime();
    player.pause();
    log(`MARK at ${fmt(t)} (player paused)`);
  });
  $("#tt-360").addEventListener("click", () => {
    const qs = player.getQualities() || [];
    const q = qs.find((x) => /360/.test(x.name || x.group || "")) || qs[0];
    if (!q) return log("no qualities reported");
    player.setQuality(q.group || q.name);
    log(`asked for ${q.name || q.group}; now ${player.getQuality()}`);
  });
})();
