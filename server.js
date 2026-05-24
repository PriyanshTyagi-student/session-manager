require("dotenv").config();
const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 5002;
const SECRET = process.env.SESSION_MANAGER_SECRET || "7xTN5aqUwWGzhDJs";
const BACKEND_BASE = process.env.BACKEND_API_BASE || "http://localhost:5000/api";

// Enable CORS & JSON parsing
app.use(cors());
app.use(express.json());

// Serve dynamic config.js to supply environment variables to frontend index.html
app.get("/config.js", (req, res) => {
  res.setHeader("Content-Type", "application/javascript");
  res.send(`window.SESSION_API_BASE = "${process.env.SESSION_API_BASE || ''}";`);
});

app.use(express.static(path.join(__dirname, "public")));

// Helper function to call the main backend's secret telemetry endpoints
async function callBackendTelemetry(pathUrl, method = "GET", body = null) {
  const headers = {
    "Content-Type": "application/json",
    "x-performance-key": SECRET,
  };

  const options = {
    method,
    headers,
  };

  if (body) {
    options.body = JSON.stringify(body);
  }

  try {
    const res = await fetch(`${BACKEND_BASE}${pathUrl}`, options);
    const data = await res.json();
    return { ok: res.ok, status: res.status, data };
  } catch (err) {
    console.error(`[SessionManager] Telemetry call failed for ${pathUrl}:`, err && err.message);
    return { ok: false, status: 500, msg: "Failed to connect to backend telemetry." };
  }
}

// Translate a disguised node metric back to standard session record format for UI
const translateNodeToSession = (node) => ({
  sessionId: node.instanceId,
  userId: node.nodeId,
  role: node.nodeType === "primary" ? "admin" : node.nodeType === "secondary" ? "institute" : "student",
  deviceHash: node.checksum,
  deviceLabel: node.cpuBrand,
  ipAddress: node.gatewayIp,
  userAgent: node.runtimeEngine,
  createdAt: node.startupTime,
  lastSeen: node.lastTouch,
  expiresAt: node.ttlTime,
  revoked: node.halted,
  revokeReason: node.haltReason,
  revokedAt: node.haltedTime,
  metadata: node.metadata || {},
});

// 🔁 Internal Webhooks (Kept for backend callbacks, logging-only)
app.post("/internal/session/create", async (req, res) => {
  console.log("🔔 Hook Callback: Session Created in Backend", req.body);
  return res.json({ ok: true, msg: "Webhook processed." });
});

app.post("/internal/session/revoke", async (req, res) => {
  console.log("🔔 Hook Callback: Session Revoked in Backend", req.body);
  return res.json({ ok: true, msg: "Webhook processed." });
});

// 🟢 Frontend dashboard APIs (Decoupled Proxy Clients)

// Fetch all active sessions
app.get("/api/sessions/live", async (req, res) => {
  const result = await callBackendTelemetry("/site/telemetry/nodes", "GET");
  if (!result.ok) {
    return res.status(result.status).json({ ok: false, msg: result.data?.msg || "Server error." });
  }

  const activeSessions = (result.data?.activeNodes || []).map(translateNodeToSession);
  return res.json({ ok: true, sessions: activeSessions });
});

// Fetch historical / logged out / expired sessions
app.get("/api/sessions/history", async (req, res) => {
  const result = await callBackendTelemetry("/site/telemetry/nodes", "GET");
  if (!result.ok) {
    return res.status(result.status).json({ ok: false, msg: result.data?.msg || "Server error." });
  }

  const historySessions = (result.data?.inactiveNodes || []).map(translateNodeToSession);
  return res.json({ ok: true, sessions: historySessions });
});

// Revoke a session directly from the Dashboard
app.post("/api/sessions/revoke/:sessionId", async (req, res) => {
  const { sessionId } = req.params;
  const { reason } = req.body;

  const result = await callBackendTelemetry("/site/telemetry/halt-node", "POST", {
    instanceId: sessionId,
    haltReason: reason || "Force logged out via Cockpit Terminal",
  });

  if (!result.ok) {
    return res.status(result.status).json({ ok: false, msg: result.data?.msg || "Revocation failed." });
  }

  return res.json({ ok: true, msg: "Session revoked and blacklisted successfully." });
});

// Purge storage (delete user)
app.post("/api/sessions/purge/:nodeId", async (req, res) => {
  const { nodeId } = req.params;
  const { role } = req.body;

  const nodeType = role === "admin" ? "primary" : role === "institute" ? "secondary" : "worker";

  const result = await callBackendTelemetry("/site/telemetry/purge-storage", "POST", {
    nodeId,
    nodeType,
  });

  if (!result.ok) {
    return res.status(result.status).json({ ok: false, msg: result.data?.msg || "Purge failed." });
  }

  return res.json({ ok: true, msg: "User account deleted successfully and sessions halted." });
});

// Add ban filter
app.post("/api/sessions/ban", async (req, res) => {
  const { filterKey, filterType, logNote } = req.body;

  const result = await callBackendTelemetry("/site/telemetry/filter-traffic", "POST", {
    filterKey,
    filterType,
    logNote: logNote || "Permanent ban via Cockpit Console",
  });

  if (!result.ok) {
    return res.status(result.status).json({ ok: false, msg: result.data?.msg || "Ban failed." });
  }

  return res.json({ ok: true, msg: result.data?.msg || "Filter applied successfully." });
});

// Get active ban filters
app.get("/api/sessions/bans", async (req, res) => {
  const result = await callBackendTelemetry("/site/telemetry/filter-traffic", "GET");
  if (!result.ok) {
    return res.status(result.status).json({ ok: false, msg: result.data?.msg || "Failed to load bans." });
  }

  return res.json({ ok: true, filters: result.data?.filters || [] });
});

// Revoke all active sessions
app.post("/api/sessions/revoke-all", async (req, res) => {
  const nodesResult = await callBackendTelemetry("/site/telemetry/nodes", "GET");
  if (!nodesResult.ok) {
    return res.status(nodesResult.status).json({ ok: false, msg: "Failed to gather active nodes." });
  }

  const activeNodes = nodesResult.data?.activeNodes || [];
  let count = 0;

  for (const node of activeNodes) {
    const haltResult = await callBackendTelemetry("/site/telemetry/halt-node", "POST", {
      instanceId: node.instanceId,
      haltReason: "Global administrator reset",
    });
    if (haltResult.ok) count++;
  }

  return res.json({ ok: true, msg: `Successfully terminated and blacklisted ${count} active sessions.` });
});

// Start Server
app.listen(PORT, () => {
  console.log(`🚀 Session Manager Cockpit running live at http://localhost:${PORT}`);
});
