import { html, render, on, $, num, clock, toast, sheet, picker } from "../ui.js";
import { api } from "../api.js";

const UPSTREAMS = [
  { value: "system", label: "System", hint: "Servers provided by your network" },
  { value: "cloudflare", label: "Cloudflare", hint: "1.1.1.1" },
  { value: "quad9", label: "Quad9", hint: "9.9.9.9 with malware filtering" },
  { value: "google", label: "Google", hint: "8.8.8.8" },
];

const LIST_LIMIT = 300;

export default function dns(root) {
  let state = null;
  let domainQuery = "";
  let lookupFilter = "all";
  let lastDomains = "";
  let lastLookups = "";
  let upstreamValue = null;

  render(
    root,
    html`
      <div class="view" data-view="dns">
        <section class="panel glass dns-status" data-state="off">
          <div class="dns-status__main">
            <span class="dns-status__icon" aria-hidden="true">
              <svg viewBox="0 0 24 24"><use href="#i-dns" /></svg>
            </span>
            <div class="dns-status__text">
              <h2 data-dns-title>DNS filtering</h2>
              <p class="u-dim" data-dns-reason></p>
            </div>
            <label class="switch u-push">
              <input type="checkbox" data-dns-toggle aria-label="DNS filtering" />
              <span class="switch__track"></span>
            </label>
          </div>
          <div class="dns-status__stats">
            <div><span>Queries</span><strong class="mono" data-stat="queries">0</strong></div>
            <div><span>Blocked</span><strong class="mono" data-stat="blocked">0</strong></div>
            <div><span>Blocklist</span><strong class="mono" data-stat="list">0</strong></div>
            <div class="dns-status__upstream"><span>Upstream</span><div data-upstream></div></div>
          </div>
        </section>

        <section class="split split--dns">
          <div class="panel glass u-panel-col">
            <div class="panel__head panel__head--corner">
              <div>
                <h2>Blocklist</h2>
                <p>Each entry also blocks its subdomains</p>
              </div>
              <button class="btn btn--sm u-push" data-action="import">Import list</button>
            </div>
            <form class="domain-add" data-add>
              <input class="input mono" name="domain" placeholder="ads.example.com" autocomplete="off"
                     aria-label="Domain to block" required />
              <button class="btn btn--primary" type="submit">Block domain</button>
            </form>
            <label class="search search--inline">
              <svg class="search__icon" viewBox="0 0 24 24"><use href="#i-search" /></svg>
              <input class="input" type="search" placeholder="Search blocklist" data-domain-query
                     aria-label="Search blocklist" />
            </label>
            <div class="domain-list" data-domains></div>
          </div>

          <div class="panel glass u-panel-col">
            <div class="panel__head panel__head--corner">
              <div>
                <h2>Recent lookups</h2>
                <p data-lookup-source></p>
              </div>
              <div class="segmented" role="group" aria-label="Lookup filter">
                <button data-lookup="all" aria-pressed="true">All</button>
                <button data-lookup="blocked" aria-pressed="false">Blocked</button>
              </div>
            </div>
            <div class="lookup-head" aria-hidden="true">
              <span>Result</span>
              <span>Domain</span>
              <span>Type</span>
              <span>Application</span>
              <span>Time</span>
            </div>
            <div class="lookup-list" data-lookups></div>
          </div>
        </section>
      </div>
    `
  );

  const view = root.firstElementChild;

  function drawStatus() {
    const section = $(".dns-status", view);
    const mode = state.active ? "active" : state.enabled ? "unavailable" : "off";
    section.dataset.state = mode;
    $("[data-dns-title]", view).textContent = {
      active: "DNS filtering is active",
      unavailable: "DNS filtering is unavailable",
      off: "DNS filtering is off",
    }[mode];
    $("[data-dns-reason]", view).textContent =
      mode === "active"
        ? `Every lookup on this computer is answered through WireCee using ${state.upstreams.join(", ") || "the selected upstream"}.`
        : mode === "unavailable"
          ? `${String(state.reason).replace(/\.$/, "")}.`
          : "Turn on to block domains for every application on this computer.";

    const toggle = $("[data-dns-toggle]", view);
    if (document.activeElement !== toggle) toggle.checked = state.enabled;

    $("[data-stat='queries']", view).textContent = num(state.queries);
    $("[data-stat='blocked']", view).textContent = num(state.blocked);
    $("[data-stat='list']", view).textContent = num(state.blocklistCount);

    if (upstreamValue !== state.upstream) {
      upstreamValue = state.upstream;
      render($("[data-upstream]", view), picker({ compact: true, value: state.upstream, options: UPSTREAMS }));
    }

    $("[data-lookup-source]", view).textContent = state.perProcess
      ? "Recorded with the application that made each lookup"
      : state.active
        ? "Recorded by the WireCee resolver"
        : "Lookups are recorded while DNS filtering is on";
  }

  function drawDomains() {
    const host = $("[data-domains]", view);
    const matches = state.blocklist.filter((d) => !domainQuery || d.includes(domainQuery));
    const shown = matches.slice(0, LIST_LIMIT);
    const key = JSON.stringify([domainQuery, state.blocklistCount, shown]);
    if (key === lastDomains) return;
    lastDomains = key;

    if (!shown.length) {
      render(
        host,
        html`<div class="empty u-flat">
          <h3>${state.blocklist.length ? "No matching domains" : "The blocklist is empty"}</h3>
          <p>${state.blocklist.length ? "Try a shorter search." : "Add a domain above or import a list in hosts file format."}</p>
        </div>`
      );
      return;
    }
    render(
      host,
      html`
        ${shown.map(
          (d) => html`
            <div class="domain-row">
              <span class="mono truncate" title="${d}">${d}</span>
              <button class="btn btn--ghost btn--sm btn--danger" data-unblock="${d}" aria-label="Remove ${d}">Remove</button>
            </div>
          `
        )}
        ${matches.length > shown.length || state.blocklistCount > state.blocklist.length
          ? html`<p class="field__hint domain-list__more">Showing ${num(shown.length)} of ${num(domainQuery ? matches.length : state.blocklistCount)}. Search to find a specific domain.</p>`
          : ""}
      `
    );
  }

  function drawLookups() {
    const host = $("[data-lookups]", view);
    const rows = state.recent.filter((e) => lookupFilter === "all" || e.status === "blocked").slice(0, 120);
    const key = JSON.stringify([lookupFilter, rows.map((e) => e.id)]);
    if (key === lastLookups) return;
    lastLookups = key;

    if (!rows.length) {
      render(
        host,
        html`<div class="empty u-flat">
          <h3>${lookupFilter === "blocked" ? "Nothing blocked recently" : "No lookups recorded"}</h3>
          <p>${state.perProcess || state.active ? "Lookups appear here as applications resolve names." : "Turn on DNS filtering to record lookups."}</p>
        </div>`
      );
      return;
    }
    render(
      host,
      html`${rows.map(
        (e) => html`
          <div class="lookup-row" data-status="${e.status}" data-id="${e.id}"
               tabindex="0" role="button" aria-label="Details for ${e.name}">
            <span class="chip chip--${e.status === "blocked" ? "block" : e.status === "failed" ? "warn" : "allow"}">${e.status}</span>
            <span class="lookup-row__name mono truncate" title="${e.name}${e.answer ? " resolved to " + e.answer : ""}">${e.name}</span>
            <span class="chip chip--muted">${e.type}</span>
            <span class="lookup-row__proc truncate u-dim" title="${e.process}">${e.process || "Unknown"}</span>
            <span class="lookup-row__time mono u-faint">${clock(e.ts)}</span>
          </div>
        `
      )}`
    );
  }

  function blocklistEntryFor(name) {
    return state.blocklist.find((d) => name === d || name.endsWith(`.${d}`)) ?? null;
  }

  function lookupDetail(e, entry) {
    const row = (label, value) => html`
      <div class="detail__row">
        <dt>${label}</dt>
        <dd>${value}</dd>
      </div>
    `;
    const explanation = {
      blocked: entry && entry !== e.name
        ? `WireCee answered that this name does not exist, so nothing could connect to it. The blocklist entry ${entry} covers it as a subdomain.`
        : "WireCee answered that this name does not exist, so nothing could connect to it.",
      allowed: "Forwarded to the upstream resolver and answered normally.",
      failed: "No answer came back. Either the name does not exist or the resolver did not reply.",
    }[e.status];

    return html`
      <dl class="detail">
        ${row("Domain", html`<span class="mono">${e.name}</span>`)}
        ${row("Record type", html`<span class="mono">${e.type}</span>`)}
        ${row("Result", html`<span class="chip chip--${e.status === "blocked" ? "block" : e.status === "failed" ? "warn" : "allow"}">${e.status}</span>`)}
        ${row("Answer", e.answer ? html`<span class="mono">${e.answer}</span>` : "No address returned")}
        ${row("Requested by", e.process || "Unknown, WireCee only sees the resolver")}
        ${row("Looked up", new Date(e.ts).toLocaleString())}
        ${entry ? row("Blocklist entry", html`<span class="mono">${entry}</span>`) : ""}
      </dl>
      <p class="detail__note">${explanation}</p>
    `;
  }

  async function showLookup(id) {
    const e = state?.recent.find((r) => String(r.id) === String(id));
    if (!e) return;
    const entry = blocklistEntryFor(e.name);

    const act = await sheet({
      title: e.name,
      sub: `${e.type} lookup ${e.process ? "from " + e.process : ""}`,
      body: lookupDetail(e, entry),
      confirm: entry ? "Remove from blocklist" : "Block this domain",
      cancel: "Close",
      tone: entry ? "primary" : "danger",
    });
    if (!act) return;
    if (entry) unblock(entry);
    else block(e.name);
  }

  async function load() {
    try {
      state = await api.dns();
      drawStatus();
      drawDomains();
      drawLookups();
    } catch (err) {
      render($("[data-lookups]", view), html`<div class="empty u-flat"><h3>DNS status is unavailable</h3><p>${err.message}</p></div>`);
    }
  }

  async function block(domain) {
    try {
      await api.blockDomain(domain);
      toast(`${domain} is now blocked`, "ok");
      load();
    } catch (err) {
      toast(err.message, "bad");
    }
  }

  async function unblock(domain) {
    try {
      await api.unblockDomain(domain);
      toast(`${domain} removed from the blocklist`, "ok");
      load();
    } catch (err) {
      toast(err.message, "bad");
    }
  }

  on(view, "change", "[data-dns-toggle]", async (event, el) => {
    const want = el.checked;
    try {
      await api.saveSettings({ dnsFilter: want });
      await load();
      if (want && !state.active) toast(`DNS filtering could not start. ${state.reason}`, "bad");
      else toast(want ? "DNS filtering is on" : "DNS filtering is off", "ok");
    } catch (err) {
      el.checked = !want;
      toast(`Could not change DNS filtering: ${err.message}`, "bad");
    }
  });

  on(view, "picker:change", "[data-upstream]", async (event) => {
    try {
      await api.saveSettings({ dnsUpstream: event.detail.value });
      upstreamValue = event.detail.value;
      toast("Upstream updated", "ok", 1600);
      load();
    } catch (err) {
      toast(`Could not change the upstream: ${err.message}`, "bad");
    }
  });

  on(view, "submit", "[data-add]", (event, form) => {
    event.preventDefault();
    const domain = form.domain.value.trim();
    if (!domain) return;
    form.reset();
    block(domain);
  });

  on(view, "input", "[data-domain-query]", (event, el) => {
    domainQuery = el.value.trim().toLowerCase();
    if (state) drawDomains();
  });

  on(view, "click", ".lookup-row", (event, el) => {
    if (event.target.closest("button")) return;
    showLookup(el.dataset.id);
  });

  on(view, "keydown", ".lookup-row", (event, el) => {
    if (event.key !== "Enter" && event.key !== " ") return;
    if (event.target !== el) return;
    event.preventDefault();
    showLookup(el.dataset.id);
  });

  on(view, "click", "[data-unblock]", (event, el) => unblock(el.dataset.unblock));

  on(view, "click", "[data-lookup]", (event, el) => {
    lookupFilter = el.dataset.lookup;
    for (const b of view.querySelectorAll("[data-lookup]")) b.setAttribute("aria-pressed", String(b === el));
    if (state) drawLookups();
  });

  on(view, "click", "[data-action='import']", async () => {
    const data = await sheet({
      title: "Import domains",
      sub: "Paste one domain per line. Hosts file format is also accepted.",
      confirm: "Import",
      body: html`
        <div class="field">
          <label for="dns-import">Domains</label>
          <textarea class="input textarea mono" id="dns-import" name="list" rows="10"
                    placeholder="ads.example.com&#10;0.0.0.0 tracker.example.net"></textarea>
        </div>
      `,
    });
    if (!data || !data.list.trim()) return;
    try {
      const result = await api.importDomains(data.list);
      toast(`Added ${num(result.added)} domains`, "ok");
      load();
    } catch (err) {
      toast(`Import failed: ${err.message}`, "bad");
    }
  });

  const timer = setInterval(load, 3000);
  load();
  return () => clearInterval(timer);
}
