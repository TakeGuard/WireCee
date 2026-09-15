import { $, $$, on, toast, num } from "./ui.js";
import { get, subscribe, startPolling, setPosture } from "./store.js";
import { api } from "./api.js";

import dashboard from "./views/dashboard.js";
import connections from "./views/connections.js";
import usage from "./views/usage.js";
import apps from "./views/apps.js";
import rules from "./views/rules.js";
import dns from "./views/dns.js";
import devices from "./views/devices.js";
import alerts from "./views/alerts.js";
import logs from "./views/logs.js";
import settings from "./views/settings.js";

const ROUTES = {
  dashboard: { view: dashboard, title: "Dashboard", sub: "Protection and network overview" },
  connections: { view: connections, title: "Connections", sub: "Live network activity by application" },
  usage: { view: usage, title: "Usage", sub: "Data consumption over time" },
  apps: { view: apps, title: "Applications", sub: "Network access for each application" },
  rules: { view: rules, title: "Rules", sub: "Traffic the firewall allows and blocks" },
  dns: { view: dns, title: "DNS", sub: "Domain filtering and lookups" },
  devices: { view: devices, title: "Devices", sub: "Hardware on your local network" },
  alerts: { view: alerts, title: "Alerts", sub: "Security events that need attention" },
  logs: { view: logs, title: "Logs", sub: "Engine event stream" },
  settings: { view: settings, title: "Settings", sub: "Preferences and protection defaults" },
};

const POSTURE_TEXT = {
  on: "Protected",
  lockdown: "Lockdown",
  off: "Disabled",
};

const host = $("#view");

let unmount = null;

const COUNT_INTERVAL_MS = 5000;
let lastCountWrite = 0;

function routeName() {
  const name = location.hash.replace(/^#\/?/, "").split("/")[0];
  return name in ROUTES ? name : "dashboard";
}

async function navigate() {
  const name = routeName();
  const route = ROUTES[name];

  unmount?.();
  unmount = null;

  for (const link of $$("[data-route]")) {
    if (link.dataset.route === name) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }

  $("[data-topbar-title]").textContent = route.title;
  $("[data-topbar-sub]").textContent = route.sub;

  host.innerHTML = "";
  const el = document.createElement("div");
  el.className = "view-slot";
  host.append(el);
  unmount = route.view(el) ?? null;

  animateIn(el, 8);
  animateIn($("[data-topbar-title]"), 4);
  animateIn($("[data-topbar-sub]"), 4, 50);
  moveIndicator();
}

const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

function animateIn(el, rise = 6, delay = 0) {
  if (!el?.animate || reduceMotion.matches) return;
  el.animate(
    [
      { opacity: 0, transform: `translateY(${rise}px)` },
      { opacity: 1, transform: "none" },
    ],
    { duration: 280, delay, easing: "cubic-bezier(0.2, 0.8, 0.2, 1)", fill: "backwards" }
  );
}

function trackIndicator() {
  const shell = $(".shell");
  const marker = $("[data-rail-indicator]");
  if (!shell || !marker) return;

  document.body.classList.add("rail-anim");
  marker.style.transition = "none";

  const done = () => {
    document.body.classList.remove("rail-anim");
    marker.style.transition = "";
    moveIndicator();
  };

  if (reduceMotion.matches) return done();

  const started = performance.now();
  const step = (now) => {
    moveIndicator();
    if (now - started < 400) requestAnimationFrame(step);
    else done();
  };
  requestAnimationFrame(step);
}

function moveIndicator() {
  const marker = $("[data-rail-indicator]");
  const link = $(".rail__link[aria-current='page']");
  if (!marker || !link) return;
  marker.style.transform = `translateY(${link.offsetTop}px)`;
  marker.style.height = `${link.offsetHeight}px`;
  marker.classList.add("is-ready");
}

function applyPosture(posture) {
  document.body.dataset.posture = posture;
  $("[data-posture-text]").textContent = POSTURE_TEXT[posture] ?? posture;
  const el = $("[data-posture-picker]");
  el.dataset.value = posture;
  $("[data-picker-label]", el).textContent = POSTURE_TEXT[posture] ?? posture;
  for (const option of $$("[role='option']", el)) {
    const match = option.dataset.value === posture;
    option.setAttribute("aria-selected", String(match));
    if (match) {
      const swatch = el.querySelector(".picker__trigger .picker__swatch");
      const tone = option.querySelector(".picker__swatch")?.dataset.tone;
      if (swatch && tone) swatch.dataset.tone = tone;
    }
  }
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  $("[data-theme-icon] use").setAttribute("href", theme === "dark" ? "#i-sun" : "#i-moon");
  try {
    localStorage.setItem("wirecee.theme", theme);
  } catch {
  }
}

on(document, "click", "[data-action='toggle-theme']", () => {
  applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
});

on(document, "click", "[data-action='toggle-rail']", () => {
  const collapsed = document.body.dataset.rail === "collapsed";
  document.body.dataset.rail = collapsed ? "expanded" : "collapsed";
  trackIndicator();
  try {
    localStorage.setItem("wirecee.rail", document.body.dataset.rail);
  } catch {
  }
});

on(document, "picker:change", "[data-posture-picker]", async (event, el) => {
  const value = event.detail.value;
  if (value === get().posture) return;
  try {
    await setPosture(value);
    toast(`Protection set to ${POSTURE_TEXT[value]}`, value === "off" ? "warn" : "ok");
  } catch (err) {
    toast(`Could not change protection: ${err.message}`, "bad");
    applyPosture(get().posture);
  }
});

let hasWindowHost = false;

async function probeWindowHost() {
  try {
    const { state } = await api.window.state();
    hasWindowHost = true;
    $("[data-caption]").hidden = false;
    applyMaximizeIcon(state === "maximized");
  } catch {
    hasWindowHost = false;
    $("[data-caption]").hidden = true;
  }
}

function applyMaximizeIcon(maximized) {
  const svg = $("[data-maximize-icon]");
  const btn = svg.closest("button");
  svg.innerHTML = maximized
    ? '<rect x="0.5" y="2.5" width="7" height="7" fill="none" stroke="currentColor" stroke-width="1"/>' +
      '<path d="M2.5 2.5V0.5h7v7h-2" fill="none" stroke="currentColor" stroke-width="1"/>'
    : '<rect x="0.5" y="0.5" width="9" height="9" fill="none" stroke="currentColor" stroke-width="1"/>';
  btn.title = maximized ? "Restore" : "Maximise";
  btn.setAttribute("aria-label", btn.title);
}

on(document, "click", "[data-window]", async (event, el) => {
  const action = el.dataset.window;
  try {
    if (action === "minimize") await api.window.minimize();
    else if (action === "close") await api.window.close();
    else if (action === "maximize") {
      await api.window.toggleMaximize();
      const { state } = await api.window.state();
      applyMaximizeIcon(state === "maximized");
    }
  } catch (err) {
    toast(`Window control unavailable: ${err.message}`, "bad");
  }
});

let dragging = false;
let dragLast = { x: 0, y: 0 };
let dragPending = null;

function flushDrag() {
  dragPending = null;
  if (!dragging) return;
  const dx = dragNext.x - dragLast.x;
  const dy = dragNext.y - dragLast.y;
  if (!dx && !dy) return;
  dragLast = { ...dragNext };
  api.window.moveBy(dx, dy).catch(() => {
    dragging = false;
  });
}

let dragNext = { x: 0, y: 0 };

on(document, "pointerdown", "[data-drag-region]", (event, el) => {
  if (!hasWindowHost || event.button !== 0) return;
  if (event.target.closest("button, a, select, input, textarea, .segmented, .posture, .picker")) {
    return;
  }
  dragging = true;
  dragLast = { x: event.screenX, y: event.screenY };
  dragNext = { ...dragLast };
  el.setPointerCapture(event.pointerId);
});

on(document, "pointermove", "[data-drag-region]", (event) => {
  if (!dragging) return;
  dragNext = { x: event.screenX, y: event.screenY };
  dragPending ??= requestAnimationFrame(flushDrag);
});

on(document, "pointerup", "[data-drag-region]", (event, el) => {
  if (!dragging) return;
  dragging = false;
  if (el.hasPointerCapture?.(event.pointerId)) el.releasePointerCapture(event.pointerId);
});

on(document, "dblclick", "[data-drag-region]", async (event) => {
  if (!hasWindowHost) return;
  if (event.target.closest("button, a, select, input, textarea, .segmented, .posture")) {
    return;
  }
  try {
    await api.window.toggleMaximize();
    const { state } = await api.window.state();
    applyMaximizeIcon(state === "maximized");
  } catch {
  }
});

const ORDER = Object.keys(ROUTES);
document.addEventListener("keydown", (event) => {
  if (event.ctrlKey || event.altKey || event.metaKey) return;
  const tag = document.activeElement?.tagName;
  if (tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA") return;

  const index = event.key === "0" ? 9 : Number(event.key) - 1;
  if (index >= 0 && index < ORDER.length) {
    location.hash = `#/${ORDER[index]}`;
  }
});

subscribe((state) => {
  applyPosture(state.posture);

  const dot = $("[data-engine-dot]");
  const text = $("[data-engine-text]");
  const online = state.engine === "online";
  dot.dataset.tone = online ? "ok" : "bad";
  dot.classList.toggle("dot--live", online);
  text.textContent = online ? `Engine online · v${state.version}` : "Engine offline";

  const now = Date.now();
  if (now - lastCountWrite > COUNT_INTERVAL_MS) {
    lastCountWrite = now;
    const count = $("[data-count='connections']");
    const next = state.connections.length ? num(state.connections.length) : "";
    if (count.textContent !== next) count.textContent = next;
  }

  const alertBadge = $("[data-count='alerts']");
  const unread = state.metrics?.alertsUnread ? num(state.metrics.alertsUnread) : "";
  if (alertBadge && alertBadge.textContent !== unread) alertBadge.textContent = unread;
});

try {
  const rail = localStorage.getItem("wirecee.rail");
  if (rail) document.body.dataset.rail = rail;
} catch {
}

applyTheme(document.documentElement.dataset.theme ?? "dark");
applyPosture(get().posture);

window.addEventListener("hashchange", navigate);
window.addEventListener("resize", moveIndicator);
if (!location.hash) location.hash = "#/dashboard";

startPolling();
navigate();
probeWindowHost();
