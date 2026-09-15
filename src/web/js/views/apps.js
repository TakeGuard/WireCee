import { html, render, on, $, bytes, num, monogram, toast, picker } from "../ui.js";
import { api } from "../api.js";

const SORTS = {
  usage: {
    label: "Network usage",
    compare: (a, b) => b.rx + b.tx - (a.rx + a.tx) || b.connections - a.connections,
  },
  connections: { label: "Live connections", compare: (a, b) => b.connections - a.connections },
  name: { label: "Name", compare: (a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }) },
  policy: {
    label: "Policy",
    compare: (a, b) => ({ block: 0, ask: 1, allow: 2 }[a.policy] - { block: 0, ask: 1, allow: 2 }[b.policy]),
  },
};

const POLICIES = [
  ["allow", "Allow"],
  ["ask", "Ask"],
  ["block", "Block"],
];

export default function apps(root) {
  let all = [];
  let query = "";
  let filter = "all";
  let sort = "usage";

  render(
    root,
    html`
      <div class="view" data-view="apps">
        <div class="panel panel--tight glass">
          <div class="toolbar u-borderless">
            <label class="search">
              <svg class="search__icon" viewBox="0 0 24 24"><use href="#i-search" /></svg>
              <input class="input" type="search" placeholder="Search applications…" data-query
                     aria-label="Search applications" />
            </label>
            <div class="segmented" role="group" aria-label="Policy filter">
              <button data-filter="all" aria-pressed="true">All</button>
              <button data-filter="allow" aria-pressed="false">Allowed</button>
              <button data-filter="ask" aria-pressed="false">Ask</button>
              <button data-filter="block" aria-pressed="false">Blocked</button>
            </div>
            <span class="mono u-dim u-push" data-summary></span>
            <div class="apps-sort" data-sort-picker>
              ${picker({
                compact: true,
                value: sort,
                options: Object.entries(SORTS).map(([value, s]) => ({ value, label: `Sort: ${s.label}` })),
              })}
            </div>
          </div>
        </div>

        <p class="notice" data-enforcement-notice hidden></p>

        <div class="app-grid" data-grid>
          <div class="empty"><div class="spinner"></div></div>
        </div>
      </div>
    `
  );

  const view = root.firstElementChild;
  const grid = $("[data-grid]", view);
  const summary = $("[data-summary]", view);

  const cards = new Map();

  function visible() {
    return all
      .filter((a) => {
        if (filter !== "all" && a.policy !== filter) return false;
        if (!query) return true;
        return `${a.name} ${a.path}`.toLowerCase().includes(query);
      })
      .sort((a, b) => SORTS[sort].compare(a, b) || a.name.localeCompare(b.name));
  }

  function createCard(a) {
    const el = document.createElement("article");
    el.className = "app-card glass hoverable";
    el.dataset.id = a.id;
    el.dataset.name = a.name;
    render(
      el,
      html`
        <div class="app-card__icon" aria-hidden="true">
          <span class="app-card__mono">${monogram(a.name)}</span>
          <img class="app-card__img" alt="" width="24" height="24"
               src="/api/apps/icon?name=${encodeURIComponent(a.name)}" data-icon />
        </div>
        <div class="app-card__name truncate" title="${a.name}">${a.name}</div>
        <div class="app-card__path truncate" title="${a.path}">${a.path}</div>
        <div class="app-card__meta">
          <span title="Live connections">
            <span class="dot" data-conn-dot></span>
            <span data-conns></span>
          </span>
          <span class="mono u-faint" data-bytes title="Downloaded and uploaded since WireCee started"></span>
          <div class="segmented" role="group" aria-label="Policy for ${a.name}">
            ${POLICIES.map(
              ([value, label]) => html`<button data-policy="${value}">${label}</button>`
            )}
          </div>
        </div>
      `
    );
    return el;
  }

  function patchCard(el, a) {
    const conns = $("[data-conns]", el);
    if (conns.textContent !== num(a.connections)) conns.textContent = num(a.connections);

    const dot = $("[data-conn-dot]", el);
    const tone = a.connections ? "ok" : "idle";
    if (dot.dataset.tone !== tone) dot.dataset.tone = tone;

    const size = a.rx + a.tx ? `${bytes(a.rx)} · ${bytes(a.tx)}` : "—";
    const bytesEl = $("[data-bytes]", el);
    if (bytesEl.textContent !== size) bytesEl.textContent = size;

    for (const btn of el.querySelectorAll("[data-policy]")) {
      const pressed = String(btn.dataset.policy === a.policy);
      if (btn.getAttribute("aria-pressed") !== pressed) {
        btn.setAttribute("aria-pressed", pressed);
      }
    }
  }

  function draw() {
    const rows = visible();
    summary.textContent = `${rows.length} of ${all.length} applications`;

    if (!rows.length) {
      cards.clear();
      render(
        grid,
        html`<div class="empty u-span">
          <h3>Nothing here</h3>
          <p>${all.length ? "No application matches that filter." : "No application has requested network access yet."}</p>
        </div>`
      );
      return;
    }

    if (!cards.size) grid.textContent = "";

    const wanted = new Set(rows.map((a) => a.id));
    for (const [id, el] of cards) {
      if (!wanted.has(id)) {
        el.remove();
        cards.delete(id);
      }
    }

    let previous = null;
    for (const a of rows) {
      let el = cards.get(a.id);
      if (!el) {
        el = createCard(a);
        cards.set(a.id, el);
        grid.append(el);
      }
      patchCard(el, a);

      const shouldFollow = previous ? previous.nextElementSibling : grid.firstElementChild;
      if (shouldFollow !== el) grid.insertBefore(el, shouldFollow);
      previous = el;
    }
  }

  view.addEventListener(
    "error",
    (event) => {
      const img = event.target;
      if (img instanceof HTMLImageElement && img.dataset.icon !== undefined) {
        img.remove();
      }
    },
    true
  );

  on(view, "picker:change", "[data-sort-picker]", (event) => {
    sort = event.detail.value;
    draw();
  });

  on(view, "input", "[data-query]", (event, el) => {
    query = el.value.trim().toLowerCase();
    draw();
  });

  on(view, "click", "[data-filter]", (event, el) => {
    filter = el.dataset.filter;
    for (const b of view.querySelectorAll("[data-filter]")) {
      b.setAttribute("aria-pressed", String(b === el));
    }
    draw();
  });

  on(view, "click", "[data-policy]", async (event, el) => {
    const id = el.closest(".app-card").dataset.id;
    const app = all.find((a) => a.id === id);
    const policy = el.dataset.policy;
    if (!app || app.policy === policy) return;

    const previous = app.policy;
    app.policy = policy;
    draw();

    try {
      await api.setAppPolicy(app.name, policy);
      toast(`${app.name} set to ${policy}`, policy === "block" ? "warn" : "ok");
    } catch (err) {
      app.policy = previous;
      draw();
      toast(`Could not update ${app.name}: ${err.message}`, "bad");
    }
  });

  async function load() {
    try {
      all = await api.apps();
      draw();
    } catch (err) {
      cards.clear();
      render(grid, html`<div class="empty u-span">
        <h3>Could not load applications</h3><p>${err.message}</p>
      </div>`);
    }
  }

  api
    .status()
    .then((s) => {
      const notice = $("[data-enforcement-notice]", view);
      if (s.enforcement === "active") return;
      notice.hidden = false;
      notice.textContent = `Policies are saved but not enforced. ${String(s.enforcementReason).replace(/\.$/, "")}.`;
    })
    .catch(() => {});

  const timer = setInterval(load, 4000);
  load();
  return () => clearInterval(timer);
}
