const BASE = "/api";

async function request(method, path, body, type = "application/json") {
  const raw = type !== "application/json";
  const res = await fetch(BASE + path, {
    method,
    headers: body ? { "content-type": type } : undefined,
    body: body ? (raw ? body : JSON.stringify(body)) : undefined,
  });
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      detail = (await res.json()).error ?? detail;
    } catch {
    }
    throw new Error(detail);
  }
  if (res.status === 204 || res.status === 304) return null;

  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

export const api = {
  status: () => request("GET", "/status"),
  setPosture: (posture) => request("PUT", "/status", { posture }),

  metrics: () => request("GET", "/metrics"),
  connections: () => request("GET", "/connections"),

  rules: () => request("GET", "/rules"),
  createRule: (rule) => request("POST", "/rules", rule),
  updateRule: (id, patch) => request("PATCH", `/rules/${id}`, patch),
  deleteRule: (id) => request("DELETE", `/rules/${id}`),

  apps: () => request("GET", "/apps"),
  blockedApps: () => request("GET", "/apps?policy=block"),

  setAppPolicy: (name, policy) =>
    request("POST", `/apps/policy?name=${encodeURIComponent(name)}&policy=${policy}`),

  logs: (since = 0) => request("GET", `/logs?since=${since}`),

  settings: () => request("GET", "/settings"),
  saveSettings: (patch) => request("PATCH", "/settings", patch),

  killConnection: (id) => request("DELETE", `/connections/${id}`),

  usage: (days = 7) => request("GET", `/usage?days=${days}`),

  devices: () => request("GET", "/devices"),
  renameDevice: (mac, name) =>
    request("POST", `/devices?mac=${encodeURIComponent(mac)}&name=${encodeURIComponent(name)}`),

  alerts: () => request("GET", "/alerts"),
  markAlertsRead: () => request("POST", "/alerts/read"),
  clearAlerts: () => request("DELETE", "/alerts"),

  dns: () => request("GET", "/dns"),
  blockDomain: (domain) => request("POST", `/dns/block?domain=${encodeURIComponent(domain)}`),
  unblockDomain: (domain) => request("DELETE", `/dns/block?domain=${encodeURIComponent(domain)}`),
  importDomains: (text) => request("POST", "/dns/import", text, "text/plain"),

  window: {
    minimize: () => windowCall("minimize"),
    toggleMaximize: () => windowCall("maximize"),
    close: () => windowCall("close"),
    moveBy: (dx, dy) => windowCall(`drag?dx=${Math.round(dx)}&dy=${Math.round(dy)}`),
    state: () => windowCall("state"),
  },
};

async function windowCall(action) {
  const res = await fetch(`${BASE}/window/${action}`, {
    method: action === "state" ? "GET" : "POST",
  });
  if (!res.ok) throw new Error(`window/${action}: ${res.status}`);
  return res.json();
}
