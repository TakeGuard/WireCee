import { html, render, on, $, clock, toast } from "../ui.js";
import { api } from "../api.js";

const LEVELS = ["all", "block", "allow", "warn", "info"];

const MAX_LINES = 1500;

export default function logs(root) {
  let buffer = [];
  let since = 0;
  let level = "all";
  let query = "";
  let follow = true;

  render(
    root,
    html`
      <div class="view view--fill" data-view="logs">
        <div class="panel panel--tight glass u-panel-col">
          <div class="toolbar">
            <label class="search">
              <svg class="search__icon" viewBox="0 0 24 24"><use href="#i-search" /></svg>
              <input class="input" type="search" placeholder="Filter log text…" data-query aria-label="Filter log" />
            </label>
            <div class="segmented" role="group" aria-label="Level filter">
              ${LEVELS.map(
                (l) => html`<button data-level="${l}" aria-pressed="${String(l === "all")}">${l}</button>`
              )}
            </div>
            <span class="u-row u-push">
              <span class="mono u-dim" data-summary></span>
              <button class="btn btn--sm btn--primary" data-action="follow" aria-pressed="true">Follow</button>
              <button class="btn btn--sm" data-action="copy">Copy</button>
              <button class="btn btn--sm" data-action="clear">Clear</button>
            </span>
          </div>

          <div class="logstream" data-stream tabindex="0" role="log" aria-label="Engine log"></div>
        </div>
      </div>
    `
  );

  const view = root.firstElementChild;
  const stream = $("[data-stream]", view);
  const summary = $("[data-summary]", view);

  const visible = () =>
    buffer.filter((l) => {
      if (level !== "all" && l.level !== level) return false;
      return !query || l.message.toLowerCase().includes(query);
    });

  function draw() {
    const rows = visible();
    summary.textContent = `${rows.length} line${rows.length === 1 ? "" : "s"}`;

    if (!rows.length) {
      render(stream, html`<div class="empty">
        <h3>No log lines</h3>
        <p>${buffer.length ? "Nothing matches the current filter." : "Waiting for engine events."}</p>
      </div>`);
      return;
    }

    render(
      stream,
      html`${rows.map(
        (l) => html`
          <div class="logline" data-lvl="${l.level}">
            <span class="logline__ts">${clock(l.ts)}</span>
            <span class="logline__lvl">${l.level}</span>
            <span class="logline__msg">${l.message}</span>
          </div>
        `
      )}`
    );

    if (follow) stream.scrollTop = stream.scrollHeight;
  }

  async function tail() {
    try {
      const fresh = await api.logs(since);
      if (!fresh.length) return;
      since = fresh.at(-1).ts;
      buffer.push(...fresh);
      if (buffer.length > MAX_LINES) buffer.splice(0, buffer.length - MAX_LINES);
      draw();
    } catch {
    }
  }

  on(view, "input", "[data-query]", (event, el) => {
    query = el.value.trim().toLowerCase();
    draw();
  });

  on(view, "click", "[data-level]", (event, el) => {
    level = el.dataset.level;
    for (const b of view.querySelectorAll("[data-level]")) {
      b.setAttribute("aria-pressed", String(b === el));
    }
    draw();
  });

  on(view, "click", "[data-action='follow']", (event, el) => {
    follow = !follow;
    el.setAttribute("aria-pressed", String(follow));
    el.classList.toggle("btn--primary", follow);
    if (follow) stream.scrollTop = stream.scrollHeight;
  });

  on(view, "click", "[data-action='clear']", () => {
    buffer = [];
    draw();
  });

  on(view, "click", "[data-action='copy']", async (event, el) => {
    const text = visible().map((l) => `${clock(l.ts)}  ${l.level.padEnd(5)}  ${l.message}`).join("\n");
    try {
      await navigator.clipboard.writeText(text);
      toast(`Copied ${visible().length} lines`, "ok");
    } catch {
      toast("Clipboard unavailable in this window", "warn");
    }
  });

  stream.addEventListener("scroll", () => {
    const atBottom = stream.scrollHeight - stream.scrollTop - stream.clientHeight < 40;
    if (atBottom === follow) return;
    follow = atBottom;
    const btn = $("[data-action='follow']", view);
    btn.setAttribute("aria-pressed", String(follow));
    btn.classList.toggle("btn--primary", follow);
  });

  const timer = setInterval(tail, 1000);
  tail();
  draw();

  return () => clearInterval(timer);
}
