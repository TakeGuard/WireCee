import { html, render, on, $, ago, toast, confirmDanger } from "../ui.js";
import { api } from "../api.js";

const KIND = {
  hosts: { icon: "i-logs", tone: "warn", label: "Hosts file" },
  dns: { icon: "i-dns", tone: "warn", label: "DNS" },
  proxy: { icon: "i-conn", tone: "warn", label: "Proxy" },
  remote: { icon: "i-devices", tone: "bad", label: "Remote access" },
  app: { icon: "i-apps", tone: "info", label: "Application" },
  device: { icon: "i-router", tone: "info", label: "Device" },
  data: { icon: "i-usage", tone: "warn", label: "Data usage" },
};

export default function alerts(root) {
  let all = [];
  let filter = "all";
  let last = "";
  let markTimer = null;

  render(
    root,
    html`
      <div class="view" data-view="alerts">
        <div class="panel panel--tight glass">
          <div class="toolbar u-borderless">
            <div class="segmented" role="group" aria-label="Alert filter">
              <button data-filter="all" aria-pressed="true">All</button>
              <button data-filter="unread" aria-pressed="false">Unread</button>
            </div>
            <span class="mono u-dim" data-summary></span>
            <span class="u-row u-push">
              <button class="btn btn--sm" data-action="read">Mark all as read</button>
              <button class="btn btn--sm btn--danger" data-action="clear">Clear all</button>
            </span>
          </div>
        </div>
        <div class="alert-list stagger" data-list>
          <div class="empty"><div class="spinner"></div></div>
        </div>
      </div>
    `
  );

  const view = root.firstElementChild;
  const list = $("[data-list]", view);

  function item(a) {
    const kind = KIND[a.kind] ?? { icon: "i-shield", tone: "info", label: "Security" };
    return html`
      <article class="alert-item glass ${a.unread ? "is-unread" : ""}">
        <span class="alert-item__icon" data-tone="${kind.tone}" aria-hidden="true">
          <svg viewBox="0 0 24 24"><use href="#${kind.icon}" /></svg>
        </span>
        <div class="alert-item__body">
          <div class="alert-item__title">
            ${a.title}
            <span class="chip chip--muted">${kind.label}</span>
          </div>
          <p class="alert-item__detail">${a.detail}</p>
        </div>
        <time class="alert-item__time mono u-faint" title="${new Date(a.ts).toLocaleString()}">${ago(a.ts)}</time>
      </article>
    `;
  }

  function draw(force = false) {
    const unread = all.filter((a) => a.unread).length;
    $("[data-summary]", view).textContent = unread ? `${unread} unread of ${all.length}` : `${all.length} alerts`;

    const rows = filter === "unread" ? all.filter((a) => a.unread) : all;
    const key = JSON.stringify([filter, rows.map((a) => [a.id, a.unread])]);
    if (key === last && !force) return;
    last = key;

    if (!rows.length) {
      render(
        list,
        html`<div class="empty">
          <svg class="empty__icon" viewBox="0 0 24 24" aria-hidden="true"><use href="#i-shield" /></svg>
          <h3>${all.length ? "No unread alerts" : "No alerts"}</h3>
          <p>WireCee raises an alert when it detects a change that affects your security or data usage.</p>
        </div>`
      );
      return;
    }
    render(list, html`${rows.map(item)}`);
    setTimeout(() => list.classList.remove("stagger"), 900);
  }

  async function load() {
    try {
      all = await api.alerts();
      draw();
      if (all.some((a) => a.unread) && !markTimer) {
        markTimer = setTimeout(() => api.markAlertsRead().catch(() => {}), 1500);
      }
    } catch (err) {
      render(list, html`<div class="empty"><h3>Alerts are unavailable</h3><p>${err.message}</p></div>`);
    }
  }

  on(view, "click", "[data-filter]", (event, el) => {
    filter = el.dataset.filter;
    for (const b of view.querySelectorAll("[data-filter]")) b.setAttribute("aria-pressed", String(b === el));
    draw();
  });

  on(view, "click", "[data-action='read']", async () => {
    try {
      await api.markAlertsRead();
      all = all.map((a) => ({ ...a, unread: false }));
      draw();
    } catch (err) {
      toast(`Could not update alerts: ${err.message}`, "bad");
    }
  });

  on(view, "click", "[data-action='clear']", async () => {
    if (!all.length) return;
    const ok = await confirmDanger("Clear all alerts?", "Alerts are removed from this list. Log entries remain.", "Clear");
    if (!ok) return;
    try {
      await api.clearAlerts();
      all = [];
      draw();
      toast("Alerts cleared", "ok");
    } catch (err) {
      toast(`Could not clear alerts: ${err.message}`, "bad");
    }
  });

  const timer = setInterval(load, 5000);
  const clockTimer = setInterval(() => draw(true), 30000);
  load();
  return () => {
    clearInterval(timer);
    clearInterval(clockTimer);
    clearTimeout(markTimer);
  };
}
