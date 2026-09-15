import { html, render, on, $, num, toast, sheet, confirmDanger, picker } from "../ui.js";
import { api } from "../api.js";

const remotes = (remote) => (!remote || remote === "any" ? [] : remote.split(",").filter(Boolean));
const remoteList = (remote) => remotes(remote).join("\n");

function remoteSummary(remote) {
  const list = remotes(remote);
  if (!list.length) return "any";
  return list.length === 1 ? list[0] : `${list[0]} +${list.length - 1}`;
}

export default function rules(root) {
  let all = [];
  let query = "";

  render(
    root,
    html`
      <div class="view view--fill" data-view="rules">
        <div class="panel panel--tight glass u-panel-col">
          <div class="toolbar">
            <label class="search">
              <svg class="search__icon" viewBox="0 0 24 24"><use href="#i-search" /></svg>
              <input class="input" type="search" placeholder="Search rules…" data-query aria-label="Search rules" />
            </label>
            <span class="mono u-dim" data-summary></span>
            <button class="btn btn--primary u-push" data-action="new">
              <svg class="btn__icon" viewBox="0 0 24 24"><use href="#i-plus" /></svg>
              New rule
            </button>
          </div>

          <div class="table-wrap u-fill">
            <table class="data">
              <thead>
                <tr>
                  <th class="w-toggle">On</th>
                  <th>Rule</th>
                  <th class="w-action">Action</th>
                  <th class="w-direction">Direction</th>
                  <th class="w-match">Match</th>
                  <th class="num w-hits">Hits</th>
                  <th class="w-actions"><span class="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody data-body>
                <tr><td colspan="7"><div class="empty"><div class="spinner"></div></div></td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `
  );

  const view = root.firstElementChild;
  const body = $("[data-body]", view);
  const summary = $("[data-summary]", view);

  function draw() {
    const matches = (r) =>
      !query || `${r.name} ${r.remote} ${r.port} ${r.proto} ${r.note}`.toLowerCase().includes(query);

    const custom = all.filter((r) => !r.builtin && matches(r));
    const builtin = all.filter((r) => r.builtin && matches(r));

    summary.textContent = `${all.filter((r) => r.enabled).length} of ${all.length} enabled`;

    if (!custom.length && !builtin.length) {
      render(
        body,
        html`<tr>
          <td colspan="7">
            <div class="empty">
              <h3>${all.length ? "No matching rules" : "No rules yet"}</h3>
              <p>
                ${all.length
                  ? "Nothing matches that search."
                  : "WireCee falls back to the default policy in Settings until you add a rule."}
              </p>
            </div>
          </td>
        </tr>`
      );
      return;
    }

    render(
      body,
      html`
        ${groupHeader("Your rules", custom.length, "Rules you created. These are evaluated first.")}
        ${custom.length
          ? custom.map(row)
          : html`<tr class="rules-empty">
              <td colspan="7">
                No custom rules yet. The built in rules below are active.
              </td>
            </tr>`}
        ${builtin.length
          ? html`${groupHeader("Built in rules", builtin.length, "Included with WireCee. You can disable or delete them.")}
              ${builtin.map(row)}`
          : ""}
      `
    );
  }

  function groupHeader(title, count, blurb) {
    return html`
      <tr class="rules-group">
        <td colspan="7">
          <span class="rules-group__title">${title}</span>
          <span class="rules-group__count">${num(count)}</span>
          <small>${blurb}</small>
        </td>
      </tr>
    `;
  }

  function row(r) {
    return html`
      <tr data-id="${r.id}" class="rules-row ${r.enabled ? "" : "u-off"}" tabindex="0"
          role="button" aria-label="Show details for ${r.name}">
        <td>
          <label class="switch">
            <input type="checkbox" data-act="toggle" ${r.enabled ? html`checked` : ""}
                   aria-label="Enable ${r.name}" />
            <span class="switch__track"></span>
          </label>
        </td>
        <td>
          <div class="rule-name__text u-strong" title="${r.name}">${r.name}</div>
          ${r.builtin || r.note
            ? html`<div class="rule-name__meta">
                ${r.builtin ? html`<span class="chip chip--muted rule-name__badge">built in</span>` : ""}
                ${r.note ? html`<small class="rule-name__note u-faint" title="${r.note}">${r.note}</small>` : ""}
              </div>`
            : ""}
        </td>
        <td>
          <span class="chip chip--${r.action === "block" ? "block" : "allow"}">${r.action}</span>
        </td>
        <td class="u-dim">
          ${{ in: "Inbound", out: "Outbound", any: "Both" }[r.direction] ?? r.direction}
        </td>
        <td class="truncate mono u-dim" title="${remotes(r.remote).join(", ")}">
          ${remoteSummary(r.remote)}${r.port && r.port !== "any" ? `:${r.port}` : ""} · ${r.proto}
        </td>
        <td class="num mono">${num(r.hits)}</td>
        <td>
          <div class="row-actions">
            <button class="btn btn--ghost btn--sm" data-act="edit">Edit</button>
            <button class="btn btn--ghost btn--sm btn--danger" data-act="delete" aria-label="Delete ${r.name}">
              <svg class="btn__icon icon-sm" viewBox="0 0 24 24"><use href="#i-trash" /></svg>
            </button>
          </div>
        </td>
      </tr>
    `;
  }

  function form(r = {}) {
    return html`
      <div class="u-stack">
        <div class="field">
          <label for="f-name">Name</label>
          <input class="input" id="f-name" name="name" required value="${r.name ?? ""}"
                 placeholder="Block outbound Telnet" />
        </div>
        <div class="u-2col">
          <div class="field">
            <label>Action</label>
            ${picker({
              name: "action",
              value: r.action ?? "block",
              options: [
                { value: "block", label: "Block", hint: "Refuse matching traffic", tone: "bad" },
                { value: "allow", label: "Allow", hint: "Permit matching traffic", tone: "ok" },
              ],
            })}
          </div>
          <div class="field">
            <label>Direction</label>
            ${picker({
              name: "direction",
              value: r.direction ?? "out",
              options: [
                { value: "out", label: "Outbound", hint: "Connections this machine opens" },
                { value: "in", label: "Inbound", hint: "Connections opened to it" },
                { value: "any", label: "Both", hint: "Either direction" },
              ],
            })}
          </div>
        </div>
        <div class="field">
          <label for="f-remote">Remote addresses</label>
          <textarea class="input textarea mono" id="f-remote" name="remote" rows="4"
                    placeholder="any&#10;91.219.231.0/24&#10;91.219.236.0/24">${remoteList(r.remote)}</textarea>
        </div>
        <div class="u-2col">
          <div class="field">
            <label for="f-port">Port</label>
            <input class="input mono" id="f-port" name="port"
                   value="${r.port && r.port !== "any" ? r.port : ""}"
                   placeholder="any" />
          </div>
          <div class="field">
            <label>Protocol</label>
            ${picker({
              name: "proto",
              value: r.proto ?? "TCP",
              options: [
                { value: "TCP", label: "TCP" },
                { value: "UDP", label: "UDP" },
                { value: "any", label: "Any", hint: "TCP and UDP" },
              ],
            })}
          </div>
        </div>
        <p class="field__hint">
          Leave addresses or port blank to match any. Enter one address or CIDR range
          per line, such as <code>1.2.3.4</code> or <code>10.0.0.0/8</code>. Text after
          <code>#</code> is ignored.
        </p>
        <div class="field">
          <label for="f-note">Note</label>
          <input class="input" id="f-note" name="note" value="${r.note ?? ""}"
                 placeholder="Reason for this rule" />
        </div>
      </div>
    `;
  }

  function normalise(data) {
    return {
      ...data,
      remote: data.remote?.trim() || "any",
      port: data.port?.trim() || "any",
    };
  }

  function detailBody(r) {
    const row = (label, value) => html`
      <div class="detail__row">
        <dt>${label}</dt>
        <dd>${value}</dd>
      </div>
    `;
    return html`
      <dl class="detail">
        ${row("Status", html`<span class="chip chip--${r.enabled ? "allow" : "muted"}">${r.enabled ? "enabled" : "disabled"}</span>`)}
        ${row("Action", html`<span class="chip chip--${r.action === "block" ? "block" : "allow"}">${r.action}</span>`)}
        ${row("Direction", { in: "Inbound", out: "Outbound", any: "Both directions" }[r.direction] ?? r.direction)}
        ${row(
          remotes(r.remote).length > 1 ? `Remote addresses (${remotes(r.remote).length})` : "Remote address",
          r.remote === "any"
            ? html`<span class="mono">any</span><small> Matches every address</small>`
            : html`<span class="mono detail__list">${remoteList(r.remote)}</span>`
        )}
        ${row("Port", html`<span class="mono">${r.port}</span>${r.port === "any" ? html`<small> Matches every port</small>` : ""}`)}
        ${row("Protocol", html`<span class="mono">${r.proto}</span>`)}
        ${row("Times matched", html`<span class="mono">${num(r.hits)}</span>`)}
        ${row("Source", r.builtin ? "Included with WireCee" : "Created by you")}
      </dl>
      ${r.note
        ? html`<p class="detail__note">${r.note}</p>`
        : html`<p class="detail__note detail__note--empty">No note has been added.</p>`}
    `;
  }

  async function showDetail(id) {
    const rule = all.find((r) => r.id === id);
    if (!rule) return;

    const wantsEdit = await sheet({
      title: rule.name,
      sub: rule.builtin ? "Built in rule" : "Your rule",
      body: detailBody(rule),
      confirm: "Edit rule",
      cancel: "Close",
    });
    if (wantsEdit) editRule(id);
  }

  on(view, "input", "[data-query]", (event, el) => {
    query = el.value.trim().toLowerCase();
    draw();
  });

  on(view, "click", "[data-action='new']", async () => {
    const data = await sheet({
      title: "New rule",
      sub: "Rules are evaluated in order. The first match decides.",
      confirm: "Create rule",
      body: form(),
    });
    if (!data) return;
    try {
      const created = await api.createRule(normalise(data));
      all.unshift(created);
      draw();
      toast("Rule created", "ok");
    } catch (err) {
      toast(`Could not create rule: ${err.message}`, "bad");
    }
  });

  async function editRule(id) {
    const rule = all.find((r) => r.id === id);
    if (!rule) return;

    const data = await sheet({ title: "Edit rule", sub: rule.name, confirm: "Save changes", body: form(rule) });
    if (!data) return;
    try {
      Object.assign(rule, await api.updateRule(id, normalise(data)));
      draw();
      toast("Rule updated", "ok");
    } catch (err) {
      toast(`Could not save: ${err.message}`, "bad");
    }
  }

  on(view, "click", "[data-act='edit']", (event, el) => {
    event.stopPropagation();
    editRule(el.closest("tr").dataset.id);
  });

  on(view, "click", "tr.rules-row", (event, el) => {
    if (event.target.closest("button, label, input")) return;
    showDetail(el.dataset.id);
  });

  on(view, "keydown", "tr.rules-row", (event, el) => {
    if (event.key !== "Enter" && event.key !== " ") return;
    if (event.target !== el) return;
    event.preventDefault();
    showDetail(el.dataset.id);
  });

  on(view, "click", "[data-act='toggle']", (event) => event.stopPropagation());

  on(view, "change", "[data-act='toggle']", async (event, el) => {
    const id = el.closest("tr").dataset.id;
    const rule = all.find((r) => r.id === id);
    if (!rule) return;

    const enabled = el.checked;
    rule.enabled = enabled;
    draw();
    try {
      await api.updateRule(id, { enabled });
    } catch (err) {
      rule.enabled = !enabled;
      draw();
      toast(`Could not update rule: ${err.message}`, "bad");
    }
  });

  on(view, "click", "[data-act='delete']", async (event, el) => {
    event.stopPropagation();
    const id = el.closest("tr").dataset.id;
    const rule = all.find((r) => r.id === id);
    if (!rule) return;

    const ok = await confirmDanger(
      "Delete rule?",
      `"${rule.name}" will be removed. Matching traffic falls back to the default policy.`
    );
    if (!ok) return;

    try {
      await api.deleteRule(id);
      all = all.filter((r) => r.id !== id);
      draw();
      toast("Rule deleted", "ok");
    } catch (err) {
      toast(`Could not delete: ${err.message}`, "bad");
    }
  });

  api
    .rules()
    .then((list) => {
      all = list;
      draw();
    })
    .catch((err) => {
      render(
        body,
        html`<tr><td colspan="7"><div class="empty">
          <h3>Could not load rules</h3><p>${err.message}</p>
        </div></td></tr>`
      );
    });

  return () => {};
}
