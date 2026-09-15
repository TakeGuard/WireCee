import { html, render, on, $, $$, bytes } from "../ui.js";
import { api } from "../api.js";

const RANGES = [
  { days: 1, label: "Today" },
  { days: 7, label: "7 days" },
  { days: 30, label: "30 days" },
  { days: 90, label: "90 days" },
];

const W = 720;
const H = 210;
const PAD_T = 10;
const PAD_B = 24;

function dayLabel(day) {
  return new Date(`${day}T00:00:00`).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function card(key, label, tone) {
  return html`
    <article class="stat-card glass hoverable">
      <span class="stat-card__label"><span class="dot" data-tone="${tone}"></span>${label}</span>
      <span class="stat-card__value" data-value="${key}">—</span>
      <span class="stat-card__delta" data-sub="${key}"></span>
      ${key === "plan" ? html`<span class="meter" aria-hidden="true"><span class="meter__fill" data-plan-meter></span></span>` : ""}
    </article>
  `;
}

export default function usage(root) {
  let days = 7;
  let last = "";
  let intro = true;

  render(
    root,
    html`
      <div class="view" data-view="usage">
        <section class="stat-grid stagger">
          ${card("rx", "Downloaded", "info")}
          ${card("tx", "Uploaded", "ok")}
          ${card("total", "Total", "info")}
          ${card("plan", "Data plan", "warn")}
        </section>

        <section class="panel glass">
          <div class="panel__head">
            <div>
              <h2>Daily usage</h2>
              <p data-range-text></p>
            </div>
            <div class="segmented u-push" role="group" aria-label="Range">
              ${RANGES.map(
                (r) => html`<button data-range="${r.days}" aria-pressed="${String(r.days === days)}">${r.label}</button>`
              )}
            </div>
          </div>
          <svg class="bars" viewBox="0 0 ${W} ${H}" role="img" aria-label="Data usage per day" data-bars></svg>
          <div class="legend">
            <span class="legend__in"><i></i>Download</span>
            <span class="legend__out"><i></i>Upload</span>
          </div>
        </section>

        <section class="panel glass">
          <div class="panel__head">
            <div>
              <h2>Top applications</h2>
              <p>Ranked by total data in the selected range</p>
            </div>
          </div>
          <div class="usage-list" data-apps>
            <div class="empty"><div class="spinner"></div></div>
          </div>
        </section>
      </div>
    `
  );

  const view = root.firstElementChild;

  function setText(selector, value) {
    const el = $(selector, view);
    if (el && el.textContent !== value) el.textContent = value;
  }

  function draw(data) {
    const key = JSON.stringify(data);
    if (key === last) return;
    last = key;

    const perDay = (n) => bytes(Math.round(n / Math.max(1, data.range)));
    setText("[data-value='rx']", bytes(data.rx));
    setText("[data-sub='rx']", data.range > 1 ? `${perDay(data.rx)} per day on average` : "Since midnight");
    setText("[data-value='tx']", bytes(data.tx));
    setText("[data-sub='tx']", data.range > 1 ? `${perDay(data.tx)} per day on average` : "Since midnight");
    setText("[data-value='total']", bytes(data.rx + data.tx));
    setText("[data-sub='total']", data.range === 1 ? "Today" : `Last ${data.range} days`);

    const plan = data.period;
    const meter = $("[data-plan-meter]", view);
    if (plan.limitMb > 0) {
      const limit = plan.limitMb * 1024 * 1024;
      const pct = Math.min(100, (plan.used / limit) * 100);
      setText("[data-value='plan']", `${Math.round(pct)}%`);
      setText("[data-sub='plan']", `${bytes(plan.used)} of ${bytes(limit)} since ${dayLabel(plan.start)}`);
      meter.dataset.level = pct >= 100 ? "bad" : pct >= 80 ? "warn" : "ok";
      requestAnimationFrame(() => (meter.style.width = `${pct}%`));
    } else {
      setText("[data-value='plan']", "No limit");
      setText("[data-sub='plan']", "Set a monthly limit in Settings");
      meter.style.width = "0%";
    }

    setText("[data-range-text]", data.range === 1 ? "Today" : `${dayLabel(data.days[0].day)} to ${dayLabel(data.days.at(-1).day)}`);
    drawBars(data.days);
    drawApps(data.apps);
  }

  function drawBars(list) {
    const svg = $("[data-bars]", view);
    svg.classList.toggle("is-intro", intro);
    if (intro) setTimeout(() => svg.classList.remove("is-intro"), 1000);
    intro = false;
    const peak = Math.max(1, ...list.map((d) => d.rx + d.tx));
    const col = W / list.length;
    const bw = Math.max(3, Math.min(34, col * 0.58));
    const usable = H - PAD_T - PAD_B;
    const base = PAD_T + usable;
    const step = Math.ceil(list.length / 8);

    render(
      svg,
      html`
        ${[0.5, 1].map((f) => {
          const y = (PAD_T + usable * (1 - f)).toFixed(1);
          return html`
            <line class="grid-line" x1="0" x2="${W}" y1="${y}" y2="${y}" />
            <text class="axis-label" x="4" y="${(Number(y) - 4).toFixed(1)}">${bytes(peak * f)}</text>
          `;
        })}
        ${list.map((d, i) => {
          const x = (i * col + (col - bw) / 2).toFixed(1);
          const hRx = (d.rx / peak) * usable;
          const hTx = (d.tx / peak) * usable;
          return html`
            <g class="bars__day">
              <title>${dayLabel(d.day)}: ${bytes(d.rx)} down, ${bytes(d.tx)} up</title>
              <rect class="bars__hit" x="${(i * col).toFixed(1)}" y="${PAD_T}" width="${col.toFixed(1)}" height="${usable}" />
              <rect class="bars__rx" x="${x}" y="${(base - hRx).toFixed(1)}" width="${bw.toFixed(1)}" height="${Math.max(0, hRx).toFixed(1)}" rx="3" />
              <rect class="bars__tx" x="${x}" y="${(base - hRx - hTx).toFixed(1)}" width="${bw.toFixed(1)}" height="${Math.max(0, hTx).toFixed(1)}" rx="3" />
              ${i % step === 0 || i === list.length - 1
                ? html`<text class="axis-label" x="${(i * col + col / 2).toFixed(1)}" y="${H - 6}" text-anchor="middle">${dayLabel(d.day)}</text>`
                : ""}
            </g>
          `;
        })}
      `
    );
  }

  function drawApps(list) {
    const host = $("[data-apps]", view);
    if (!list.length) {
      render(
        host,
        html`<div class="empty u-flat">
          <h3>No usage recorded</h3>
          <p>Data is attributed to applications while WireCee is running.</p>
        </div>`
      );
      return;
    }
    const peak = Math.max(1, ...list.map((a) => a.rx + a.tx));
    const previous = new Map($$("[data-share]", host).map((f) => [f.dataset.name, f.style.width]));
    render(
      host,
      html`${list.slice(0, 20).map(
        (a, i) => html`
          <div class="usage-row">
            <span class="usage-row__rank mono">${i + 1}</span>
            <span class="usage-row__name truncate" title="${a.name}">${a.name}</span>
            <span class="meter meter--row" aria-hidden="true">
              <span class="meter__fill" data-name="${a.name}" data-share="${(((a.rx + a.tx) / peak) * 100).toFixed(1)}"></span>
            </span>
            <span class="usage-row__value mono">${bytes(a.rx + a.tx)}</span>
            <span class="usage-row__split mono u-faint">${bytes(a.rx)} down · ${bytes(a.tx)} up</span>
          </div>
        `
      )}`
    );
    const fills = $$("[data-share]", host);
    for (const fill of fills) fill.style.width = previous.get(fill.dataset.name) ?? "0%";
    void host.offsetWidth;
    requestAnimationFrame(() => {
      for (const fill of fills) fill.style.width = `${fill.dataset.share}%`;
    });
  }

  async function load() {
    try {
      draw(await api.usage(days));
    } catch (err) {
      render($("[data-apps]", view), html`<div class="empty u-flat"><h3>Usage is unavailable</h3><p>${err.message}</p></div>`);
    }
  }

  on(view, "click", "[data-range]", (event, el) => {
    days = Number(el.dataset.range);
    for (const b of view.querySelectorAll("[data-range]")) b.setAttribute("aria-pressed", String(b === el));
    last = "";
    intro = true;
    load();
  });

  const timer = setInterval(load, 10000);
  load();
  return () => clearInterval(timer);
}
