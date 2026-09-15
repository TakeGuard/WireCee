import { html, render, on, $, ago, toast, sheet } from "../ui.js";
import { api } from "../api.js";

export default function devices(root) {
  let all = [];
  let filter = "all";
  let last = "";

  render(
    root,
    html`
      <div class="view" data-view="devices">
        <div class="panel panel--tight glass">
          <div class="toolbar u-borderless">
            <div class="segmented" role="group" aria-label="Device filter">
              <button data-filter="all" aria-pressed="true">All</button>
              <button data-filter="online" aria-pressed="false">Online</button>
              <button data-filter="offline" aria-pressed="false">Offline</button>
            </div>
            <span class="mono u-dim u-push" data-summary></span>
          </div>
        </div>

        <div class="device-grid stagger" data-grid>
          <div class="empty u-span"><div class="spinner"></div></div>
        </div>
      </div>
    `
  );

  const view = root.firstElementChild;
  const grid = $("[data-grid]", view);

  const displayName = (d) =>
    d.name || d.hostname || (d.gateway ? "Router" : `Device ${d.mac.slice(-5)}`);

  function card(d) {
    return html`
      <article class="device-card glass hoverable" data-mac="${d.mac}">
        <span class="device-card__icon" data-online="${String(d.online)}" aria-hidden="true">
          <svg viewBox="0 0 24 24"><use href="#${d.gateway ? "i-router" : "i-devices"}" /></svg>
        </span>
        <div class="device-card__body">
          <div class="device-card__name truncate" title="${displayName(d)}">
            ${displayName(d)}${d.gateway ? html`<span class="chip chip--info">gateway</span>` : ""}
          </div>
          <div class="device-card__meta mono truncate">${d.ip || "No address"}</div>
          <div class="device-card__meta mono u-faint">${d.mac}</div>
        </div>
        <div class="device-card__side">
          <span class="chip chip--${d.online ? "allow" : "muted"}">${d.online ? "online" : "offline"}</span>
          <small class="u-faint" title="First seen ${new Date(d.firstSeen).toLocaleString()}">
            ${d.online ? "Connected" : "Seen " + ago(d.lastSeen)}
          </small>
          <button class="btn btn--ghost btn--sm" data-act="rename">Rename</button>
        </div>
      </article>
    `;
  }

  function draw() {
    const online = all.filter((d) => d.online).length;
    $("[data-summary]", view).textContent = `${online} online · ${all.length} known`;

    const rows = all
      .filter((d) => filter === "all" || (filter === "online" ? d.online : !d.online))
      .sort((a, b) => b.gateway - a.gateway || b.online - a.online || displayName(a).localeCompare(displayName(b)));

    const key = JSON.stringify([filter, rows.map((d) => [d.mac, d.ip, d.name, d.hostname, d.online, d.gateway])]);
    if (key === last) return;
    last = key;

    if (!rows.length) {
      render(
        grid,
        html`<div class="empty u-span">
          <h3>${all.length ? "No devices match this filter" : "No devices found yet"}</h3>
          <p>Devices appear once they exchange traffic with this computer on the local network.</p>
        </div>`
      );
      return;
    }
    render(grid, html`${rows.map(card)}`);
    setTimeout(() => grid.classList.remove("stagger"), 900);
  }

  async function load() {
    try {
      all = await api.devices();
      draw();
    } catch (err) {
      render(grid, html`<div class="empty u-span"><h3>Devices are unavailable</h3><p>${err.message}</p></div>`);
    }
  }

  on(view, "click", "[data-filter]", (event, el) => {
    filter = el.dataset.filter;
    for (const b of view.querySelectorAll("[data-filter]")) b.setAttribute("aria-pressed", String(b === el));
    draw();
  });

  on(view, "click", "[data-act='rename']", async (event, el) => {
    const mac = el.closest("[data-mac]").dataset.mac;
    const device = all.find((d) => d.mac === mac);
    if (!device) return;
    const data = await sheet({
      title: "Rename device",
      sub: `${device.mac}${device.ip ? " at " + device.ip : ""}`,
      confirm: "Save",
      body: html`
        <div class="field">
          <label for="device-name">Name</label>
          <input class="input" id="device-name" name="name" maxlength="60"
                 value="${device.name}" placeholder="${device.hostname || "Living room TV"}" />
          <p class="field__hint">Leave empty to use the name reported by the network.</p>
        </div>
      `,
    });
    if (!data) return;
    try {
      await api.renameDevice(mac, data.name.trim());
      toast("Device renamed", "ok");
      last = "";
      load();
    } catch (err) {
      toast(`Could not rename: ${err.message}`, "bad");
    }
  });

  const timer = setInterval(load, 5000);
  load();
  return () => clearInterval(timer);
}
