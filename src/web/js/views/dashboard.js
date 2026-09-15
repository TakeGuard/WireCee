import { html, render, $, num, bytes, rate, clock, chartGeometry, tween } from "../ui.js";
import { get, subscribe } from "../store.js";
import { api } from "../api.js";

const HEADLINE = {
  on: {
    title: "You are protected",
    body: "WireCee is enforcing your rules, application decisions and default policies.",
  },
  lockdown: {
    title: "Lockdown is active",
    body: "Only traffic matching an explicit allow rule passes, together with DNS and DHCP. Applications without such a rule lose connectivity.",
  },
  off: {
    title: "Protection is off",
    body: "Connections are still monitored and logged, but no filters are installed.",
  },
};

const STATS = [
  { key: "blocked", label: "Blocked", tone: "bad" },
  { key: "allowed", label: "Allowed", tone: "ok" },
  { key: "live", label: "Live connections", tone: "info" },
  { key: "today", label: "Data today", tone: "info" },
];

export default function dashboard(root) {
  let events = [];
  let lastLogTs = 0;
  let mounted = false;

  function mount() {
    render(
      root,
      html`
        <div class="view" data-view="dashboard">
          <section class="hero glass glass--strong glass--ring">
            <div>
              <p class="hero__eyebrow" data-eyebrow></p>
              <h1 data-headline></h1>
              <p data-blurb></p>
              <div class="hero__actions">
                <a class="btn btn--primary" href="#/rules">
                  <svg class="btn__icon" viewBox="0 0 24 24"><use href="#i-rules" /></svg>
                  Manage rules
                </a>
                <a class="btn" href="#/connections">Inspect live traffic</a>
              </div>
            </div>
            <svg class="hero__shield" viewBox="0 0 24 24" aria-hidden="true">
              <circle class="ring" cx="12" cy="12" r="10.6" fill="none"
                      stroke="currentColor" stroke-width="0.6" opacity="0.55" />
              <use href="#i-shield" />
              <path data-shield-mark fill="none" stroke="currentColor" stroke-width="1.8"
                    stroke-linecap="round" stroke-linejoin="round" />
            </svg>
          </section>

          <section class="stat-grid stagger">
            ${STATS.map(
              (s) => html`
                <article class="stat-card glass hoverable">
                  <span class="stat-card__label">
                    <span class="dot" data-tone="${s.tone}"></span>${s.label}
                  </span>
                  <span class="stat-card__value" data-stat="${s.key}">—</span>
                  <span class="stat-card__delta" data-delta="${s.key}"></span>
                </article>
              `
            )}
          </section>

          <section class="split">
            <div class="panel glass">
              <div class="panel__head">
                <div>
                  <h2>Throughput</h2>
                  <p data-window></p>
                </div>
                <div class="u-push u-right">
                  <div class="mono u-lead" data-rx></div>
                  <div class="mono u-dim" data-tx></div>
                </div>
              </div>

              <svg class="chart" viewBox="0 0 600 190" preserveAspectRatio="none"
                   role="img" aria-label="Throughput over the last minute">
                <defs>
                  <linearGradient id="tg-fill-in" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stop-color="rgb(var(--tg-brand-lit))" stop-opacity="0.28" />
                    <stop offset="100%" stop-color="rgb(var(--tg-brand-lit))" stop-opacity="0" />
                  </linearGradient>
                </defs>
                <g data-grid></g>
                <path class="area-in" data-area />
                <path class="series-in" data-series-in />
                <path class="series-out" data-series-out />
              </svg>

              <div class="legend">
                <span class="legend__in"><i></i>Download</span>
                <span class="legend__out"><i></i>Upload</span>
              </div>
            </div>

            <div class="panel glass">
              <div class="panel__head">
                <div>
                  <h2>Recent events</h2>
                  <p>Newest first</p>
                </div>
                <a class="btn btn--ghost btn--sm u-push" href="#/logs">View all</a>
              </div>
              <div class="feed" data-feed></div>
            </div>
          </section>
        </div>
      `
    );
    mounted = true;
  }

  function text(el, value) {
    if (el && el.textContent !== value) el.textContent = value;
  }

  function attr(el, name, value) {
    if (el && el.getAttribute(name) !== value) el.setAttribute(name, value);
  }

  function update() {
    const { posture, metrics, connections } = get();
    if (!mounted) return;

    const copy =
      metrics && metrics.enforcement === false && posture !== "off"
        ? {
            title: "Monitoring only",
            body: `WireCee is monitoring connections but cannot block traffic. ${String(metrics.enforcementReason).replace(/\.$/, "")}.`,
          }
        : HEADLINE[posture] ?? HEADLINE.on;
    text($("[data-eyebrow]", root), `WireCee · ${posture === "on" ? "Home profile" : posture}`);
    text($("[data-headline]", root), copy.title);
    text($("[data-blurb]", root), copy.body);

    attr(
      $("[data-shield-mark]", root),
      "d",
      posture === "off" ? "m8.5 8.5 7 7M15.5 8.5l-7 7" : "m8.6 12.2 2.4 2.4 4.4-4.6"
    );

    if (!metrics) return;

    const total = metrics.blocked24h + metrics.allowed24h;
    const blockRate = total ? metrics.blocked24h / total : 0;
    const processes = new Set(connections.map((c) => c.process)).size;

    tween($("[data-stat='blocked']", root), metrics.blocked24h);
    text(
      $("[data-delta='blocked']", root),
      metrics.enforcement === false ? "Blocking is inactive" : `${(blockRate * 100).toFixed(1)}% of decisions since start`
    );
    tween($("[data-stat='allowed']", root), metrics.allowed24h);
    text($("[data-delta='allowed']", root), "Connections permitted since start");
    tween($("[data-stat='live']", root), connections.length);
    text($("[data-delta='live']", root), `Across ${processes} application${processes === 1 ? "" : "s"}`);
    const todayRx = metrics.todayRx ?? 0;
    const todayTx = metrics.todayTx ?? 0;
    tween($("[data-stat='today']", root), todayRx + todayTx, bytes);
    text($("[data-delta='today']", root), `${bytes(todayRx)} down, ${bytes(todayTx)} up`);

    text($("[data-window]", root), `Last ${metrics.rxSeries.length} seconds`);
    text($("[data-rx]", root), rate(metrics.rxBps));
    text($("[data-tx]", root), `${rate(metrics.txBps)} up`);

    drawChart(metrics.rxSeries, metrics.txSeries);
  }

  function drawChart(rx, tx) {
    const g = chartGeometry(rx, tx, { width: 600, height: 190 });
    attr($("[data-series-in]", root), "d", g.lineIn);
    attr($("[data-series-out]", root), "d", g.lineOut);
    attr($("[data-area]", root), "d", g.area);

    const grid = $("[data-grid]", root);
    if (grid && grid.dataset.peak !== String(g.peak)) {
      grid.dataset.peak = String(g.peak);
      render(
        grid,
        html`${g.gridlines.map(
          (line) => html`
            <line class="grid-line" x1="${line.x1}" y1="${line.y}" x2="${line.x2}" y2="${line.y}" />
            <text class="axis-label" x="${line.labelX}" y="${line.labelY}" text-anchor="end">${bytes(line.value)}</text>
          `
        )}`
      );
    }
  }

  function drawFeed() {
    const feed = $("[data-feed]", root);
    if (!feed) return;

    if (!events.length) {
      if (!feed.dataset.empty) {
        feed.dataset.empty = "1";
        render(
          feed,
          html`<div class="empty u-flat">
            <h3>Nothing yet</h3>
            <p>Events appear here as the engine makes decisions.</p>
          </div>`
        );
      }
      return;
    }
    if (feed.dataset.empty) {
      delete feed.dataset.empty;
      feed.textContent = "";
    }

    const known = new Set([...feed.children].map((el) => el.dataset.id));
    const fresh = events.filter((e) => !known.has(e.id)).reverse();

    for (const entry of fresh) {
      const el = document.createElement("div");
      el.className = "feed__item";
      el.dataset.id = entry.id;
      const tone = { block: "block", allow: "allow", warn: "warn", info: "info" }[entry.level] ?? "muted";
      render(
        el,
        html`
          <span class="chip chip--${tone}">${entry.level}</span>
          <span class="feed__what truncate" title="${entry.message}">${entry.message}</span>
          <span class="feed__when mono">${clock(entry.ts)}</span>
        `
      );
      feed.prepend(el);
    }

    while (feed.children.length > 12) feed.lastElementChild.remove();
  }

  async function pullEvents() {
    try {
      const incoming = await api.logs(lastLogTs);
      if (!incoming.length) return;
      lastLogTs = incoming.at(-1).ts;
      events = [...incoming.reverse(), ...events].slice(0, 40);
      drawFeed();
    } catch {
    }
  }

  mount();
  update();
  const unsubscribe = subscribe(update);
  const timer = setInterval(pullEvents, 2000);
  pullEvents();

  return () => {
    unsubscribe();
    clearInterval(timer);
  };
}
