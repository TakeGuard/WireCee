import { html, render, on, $, bytes, ago, toast, sheet, confirmDanger, picker } from "../ui.js";
import { get, subscribe } from "../store.js";
import { api } from "../api.js";

const COLUMNS = [
  { key: "process", label: "Process", width: "30%" },
  { key: "remoteHost", label: "Remote", width: "38%" },
  { key: "remotePort", label: "Port", width: "66px" },
  { key: "proto", label: "Proto", width: "82px" },
  { key: "state", label: "State", width: "128px" },
  { key: "rx", label: "In", num: true, width: "72px" },
  { key: "tx", label: "Out", num: true, width: "72px" },
  { key: "since", label: "Age", num: true, width: "56px" },
];

function shortAge(since) {
  const s = Math.max(0, Math.round((Date.now() - since) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86400) return `${Math.round(s / 3600)}h`;
  return `${Math.round(s / 86400)}d`;
}

export default function connections(root) {
  let query = "";
  let filter = "all";
  let sort = { key: "since", dir: "desc" };
  let paused = false;

  let seen = new Set();

  render(
    root,
    html`
      <div class="view view--fill" data-view="connections">
        <div class="panel panel--tight glass u-panel-col">
          <div class="toolbar">
            <label class="search">
              <svg class="search__icon" viewBox="0 0 24 24"><use href="#i-search" /></svg>
              <input class="input" type="search" placeholder="Filter by process, host or port…"
                     data-filter-query aria-label="Filter connections" />
            </label>

            <div class="segmented" role="group" aria-label="Protocol filter">
              <button data-filter="all" aria-pressed="true">All</button>
              <button data-filter="tcp" aria-pressed="false">TCP</button>
              <button data-filter="udp" aria-pressed="false">UDP</button>
            </div>

            <span class="u-row u-push">
              <span class="mono u-dim" data-summary></span>
              <button class="btn btn--sm" data-action="pause" aria-pressed="false">Pause</button>
            </span>
          </div>

          <div class="table-wrap u-fill" data-scroller>
            <table class="data">
              <colgroup>
                ${COLUMNS.map((col) => html`<col width="${col.width}" />`)}
                <col width="100" />
              </colgroup>
              <thead>
                <tr data-head></tr>
              </thead>
              <tbody data-body></tbody>
            </table>
          </div>
        </div>
      </div>
    `
  );

  const view = root.firstElementChild;
  const body = $("[data-body]", view);
  const head = $("[data-head]", view);
  const summary = $("[data-summary]", view);

  function visible() {
    const rows = get().connections.filter((c) => {
      if (filter === "tcp" && !c.proto.startsWith("TCP")) return false;
      if (filter === "udp" && !c.proto.startsWith("UDP")) return false;
      if (!query) return true;
      const hay = `${c.process} ${c.remoteHost} ${c.remoteIp} ${c.remotePort} ${c.proto}`.toLowerCase();
      return hay.includes(query);
    });

    const dir = sort.dir === "asc" ? 1 : -1;
    return rows.sort((a, b) => {
      const x = a[sort.key];
      const y = b[sort.key];
      if (typeof x === "number") return (x - y) * dir;
      return String(x).localeCompare(String(y)) * dir;
    });
  }

  function drawHead() {
    render(
      head,
      html`
        ${COLUMNS.map(
          (col) => html`
            <th class="sortable ${col.num ? "num" : ""}" data-sort="${col.key}"
                ${sort.key === col.key ? html`aria-sort="${sort.dir === "asc" ? "ascending" : "descending"}"` : ""}>
              ${col.label}
            </th>
          `
        )}
        <th><span class="sr-only">Actions</span></th>
      `
    );
  }

  function draw() {
    if (paused) return;

    const rows = visible();
    const total = get().connections.length;
    summary.textContent = `${rows.length} of ${total} shown`;

    if (!rows.length) {
      render(
        body,
        html`<tr>
          <td colspan="${COLUMNS.length + 1}">
            <div class="empty">
              <h3>No matching connections</h3>
              <p>${query || filter !== "all" ? "Nothing matches the current filter." : "There are no active connections."}</p>
            </div>
          </td>
        </tr>`
      );
      return;
    }

    const next = new Set(rows.map((r) => r.id));
    render(body, html`${rows.map((c) => row(c, !seen.has(c.id)))}`);
    seen = next;
    drawHead();
  }

  function row(c, isNew) {
    const host = c.remoteHost || c.remoteIp;
    return html`
      <tr class="${isNew ? "row-enter" : ""}" data-id="${c.id}">
        <td class="truncate" title="${c.path} (pid ${c.pid})">
          <strong class="u-strong">${c.process}</strong>
          <span class="u-faint"> · ${c.pid}</span>
        </td>
        <td class="truncate mono" title="${c.remoteIp}">${host}</td>
        <td class="mono">${c.remotePort}</td>
        <td><span class="chip chip--muted">${c.proto}</span></td>
        <td>
          <span class="chip chip--${/^(ESTABLISHED|ACTIVE)$/.test(c.state) ? "allow" : "muted"}">
            ${c.state.toLowerCase().replace("_", " ")}
          </span>
        </td>
        <td class="num mono">${bytes(c.rx)}</td>
        <td class="num mono">${bytes(c.tx)}</td>
        <td class="num u-tiny" title="First seen ${new Date(c.since).toLocaleTimeString()}">${shortAge(c.since)}</td>
        <td>
          <div class="row-actions">
            <button class="btn btn--ghost btn--sm" data-act="rule" title="Create a rule from this connection">Rule</button>
            <button class="btn btn--ghost btn--sm btn--danger" data-act="kill" title="Terminate this connection">
              <svg class="btn__icon icon-sm" viewBox="0 0 24 24"><use href="#i-block" /></svg>
            </button>
          </div>
        </td>
      </tr>
    `;
  }

  on(view, "input", "[data-filter-query]", (event, el) => {
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

  on(view, "click", "[data-action='pause']", (event, el) => {
    paused = !paused;
    el.setAttribute("aria-pressed", String(paused));
    el.textContent = paused ? "Resume" : "Pause";
    el.classList.toggle("btn--primary", paused);
    if (!paused) draw();
  });

  on(view, "click", "[data-sort]", (event, el) => {
    const key = el.dataset.sort;
    sort = sort.key === key ? { key, dir: sort.dir === "asc" ? "desc" : "asc" } : { key, dir: "desc" };
    draw();
  });

  on(view, "click", "[data-act='kill']", async (event, el) => {
    const id = el.closest("tr").dataset.id;
    const conn = get().connections.find((c) => c.id === id);
    if (!conn) return;

    const ok = await confirmDanger(
      "Terminate connection?",
      `${conn.process} to ${conn.remoteHost || conn.remoteIp}:${conn.remotePort}. The connection closes now, but no rule is created, so the application can reconnect.`,
      "Terminate"
    );
    if (!ok) return;

    try {
      await api.killConnection(id);
      toast("Connection terminated", "ok");
    } catch (err) {
      toast(`Could not terminate: ${err.message}`, "bad");
    }
  });

  on(view, "click", "[data-act='rule']", async (event, el) => {
    const id = el.closest("tr").dataset.id;
    const conn = get().connections.find((c) => c.id === id);
    if (!conn) return;

    const wasPaused = paused;
    paused = true;

    const data = await sheet({
      title: "Create rule from connection",
      sub: `${conn.process} to ${conn.remoteIp}:${conn.remotePort}`,
      confirm: "Create rule",
      body: html`
        <div class="u-stack">
          <div class="field">
            <label for="rn">Name</label>
            <input class="input" id="rn" name="name" required
                   value="Block ${conn.process} to ${conn.remoteHost || conn.remoteIp}" />
          </div>
          <div class="u-2col">
            <div class="field">
              <label>Action</label>
              ${picker({
                name: "action",
                value: "block",
                options: [
                  { value: "block", label: "Block", tone: "bad" },
                  { value: "allow", label: "Allow", tone: "ok" },
                ],
              })}
            </div>
            <div class="field">
              <label>Direction</label>
              ${picker({
                name: "direction",
                value: "out",
                options: [
                  { value: "out", label: "Outbound" },
                  { value: "in", label: "Inbound" },
                  { value: "any", label: "Both" },
                ],
              })}
            </div>
          </div>
          <div class="u-3col">
            <div class="field">
              <label for="rr">Remote</label>
              <input class="input mono" id="rr" name="remote" value="${conn.remoteIp}" />
            </div>
            <div class="field">
              <label for="rp">Port</label>
              <input class="input mono" id="rp" name="port" value="${conn.remotePort}" />
            </div>
            <div class="field">
              <label>Protocol</label>
              ${picker({
                name: "proto",
                value: conn.proto.startsWith("TCP") ? "TCP" : "UDP",
                options: [
                  { value: conn.proto.startsWith("TCP") ? "TCP" : "UDP", label: conn.proto.startsWith("TCP") ? "TCP" : "UDP" },
                  { value: "any", label: "Any" },
                ],
              })}
            </div>
          </div>
        </div>
      `,
    });

    paused = wasPaused;

    if (!data) return;
    try {
      await api.createRule({ ...data, note: `Created from a live connection on ${new Date().toLocaleDateString()}` });
      toast("Rule created", "ok");
    } catch (err) {
      toast(`Could not create rule: ${err.message}`, "bad");
    }
  });

  drawHead();
  const unsubscribe = subscribe(draw);
  draw();
  return unsubscribe;
}
