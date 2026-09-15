import { api } from "./api.js";

const state = {
  posture: "on",
  engine: "connecting",
  version: "",
  metrics: null,
  connections: [],
  error: null,
};

const listeners = new Set();

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export const get = () => state;

export function set(patch) {
  Object.assign(state, patch);
  for (const fn of listeners) fn(state);
}

const POLL_MS = 1000;

let timer = null;
let inFlight = false;

async function poll() {
  if (inFlight) return;
  inFlight = true;
  try {
    const [status, metrics, connections] = await Promise.all([
      api.status(),
      api.metrics(),
      api.connections(),
    ]);
    set({
      posture: status.posture,
      engine: status.engine,
      version: status.version,
      metrics,
      connections,
      error: null,
    });
  } catch (err) {
    set({ engine: "offline", error: String(err.message ?? err) });
  } finally {
    inFlight = false;
  }
}

export function startPolling() {
  if (timer) return;
  poll();
  timer = setInterval(() => {
    if (document.hidden) return;
    poll();
  }, POLL_MS);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) poll();
  });
}

export function stopPolling() {
  clearInterval(timer);
  timer = null;
}

export async function setPosture(posture) {
  const previous = state.posture;
  set({ posture });
  try {
    await api.setPosture(posture);
  } catch (err) {
    set({ posture: previous });
    throw err;
  }
}
