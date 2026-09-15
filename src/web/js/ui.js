export function html(strings, ...values) {
  let out = strings[0];
  for (let i = 0; i < values.length; i++) {
    out += stringify(values[i]) + strings[i + 1];
  }
  return new Raw(out);
}

class Raw {
  constructor(value) {
    this.value = value;
  }
  toString() {
    return this.value;
  }
}

export const raw = (value) => new Raw(String(value));

function stringify(value) {
  if (value == null || value === false) return "";
  if (value instanceof Raw) return value.value;
  if (Array.isArray(value)) return value.map(stringify).join("");
  return escapeHtml(String(value));
}

export function escapeHtml(s) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function render(target, markup) {
  target.innerHTML = String(markup);
  return target;
}

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export function on(root, type, selector, handler) {
  root.addEventListener(type, (event) => {
    const match = event.target.closest(selector);
    if (match && root.contains(match)) handler(event, match);
  });
}

const nf = new Intl.NumberFormat();
const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

export const num = (n) => nf.format(n);

export function bytes(n) {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
  const v = n / 1024 ** i;
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

export const rate = (bytesPerSecond) => `${bytes(bytesPerSecond)}/s`;

export function tween(el, to, format = num, ms = 520) {
  if (!el) return;
  const from = Number(el.dataset.value);
  el.dataset.value = String(to);
  cancelAnimationFrame(el._tween);
  if (!Number.isFinite(from) || from === to || matchMedia("(prefers-reduced-motion: reduce)").matches) {
    el.textContent = format(to);
    return;
  }
  const start = performance.now();
  const step = (now) => {
    const t = Math.min(1, (now - start) / ms);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = format(Math.round(from + (to - from) * eased));
    if (t < 1) el._tween = requestAnimationFrame(step);
  };
  el._tween = requestAnimationFrame(step);
}

export function clock(ts) {
  return new Date(ts).toLocaleTimeString(undefined, {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function ago(ts) {
  const secs = Math.round((ts - Date.now()) / 1000);
  const abs = Math.abs(secs);
  if (abs < 60) return rtf.format(secs, "second");
  if (abs < 3600) return rtf.format(Math.round(secs / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(secs / 3600), "hour");
  return rtf.format(Math.round(secs / 86400), "day");
}

export function monogram(name) {
  const parts = name.replace(/\.exe$/i, "").split(/[\s._-]+/).filter(Boolean);
  return ((parts[0]?.[0] ?? "?") + (parts[1]?.[0] ?? "")).toUpperCase();
}

const toastHost = () => document.querySelector("[data-toasts]");

export function toast(message, tone = "info", ms = 3600) {
  const host = toastHost();
  if (!host) return;

  const el = document.createElement("div");
  el.className = "toast glass glass--strong";
  el.dataset.tone = tone;
  el.setAttribute("role", tone === "bad" ? "alert" : "status");
  el.textContent = message;
  host.append(el);

  setTimeout(() => {
    el.classList.add("leaving");
    el.addEventListener("transitionend", () => el.remove(), { once: true });
    setTimeout(() => el.remove(), 400);
  }, ms);
}

export function sheet({ title, sub, body, confirm = "Save", cancel = "Cancel", tone = "primary" }) {
  return new Promise((resolve) => {
    const dlg = document.createElement("dialog");
    dlg.className = "sheet";
    dlg.innerHTML = String(html`
      <form method="dialog" class="sheet__body glass glass--strong glass--ring">
        <h2 class="sheet__title">${title}</h2>
        ${sub ? html`<p class="sheet__sub">${sub}</p>` : ""}
        <div class="sheet__fields">${body ?? ""}</div>
        <div class="sheet__actions">
          <button class="btn" value="cancel" formnovalidate>${cancel}</button>
          <button class="btn btn--${tone}" value="confirm">${confirm}</button>
        </div>
      </form>
    `);

    const form = dlg.querySelector("form");
    document.body.append(dlg);
    dlg.showModal();

    const cancelOnNavigate = () => dlg.close("cancel");
    window.addEventListener("hashchange", cancelOnNavigate);

    dlg.addEventListener("close", () => {
      window.removeEventListener("hashchange", cancelOnNavigate);
      const ok = dlg.returnValue === "confirm";
      const data = ok ? Object.fromEntries(new FormData(form)) : null;
      dlg.remove();
      resolve(data);
    });

    dlg.addEventListener("click", (e) => {
      if (e.target === dlg) dlg.close("cancel");
    });

    dlg.querySelector("input, select, textarea")?.focus();
  });
}

export async function confirmDanger(title, sub, confirm = "Delete") {
  const result = await sheet({ title, sub, confirm, tone: "danger" });
  return result !== null;
}

export function chartGeometry(seriesIn, seriesOut, { width = 600, height = 190 } = {}) {
  const pad = { t: 10, r: 8, b: 18, l: 44 };
  const w = width - pad.l - pad.r;
  const h = height - pad.t - pad.b;
  const peak = Math.max(1, ...seriesIn, ...seriesOut);

  const x = (i, len) => pad.l + (len < 2 ? w : (i / (len - 1)) * w);
  const y = (v) => pad.t + h - (v / peak) * h;

  const path = (series) =>
    series
      .map((v, i) => `${i ? "L" : "M"}${x(i, series.length).toFixed(1)} ${y(v).toFixed(1)}`)
      .join(" ");

  const lineIn = path(seriesIn);
  const area =
    seriesIn.length > 1
      ? `${lineIn} L${(pad.l + w).toFixed(1)} ${pad.t + h} L${pad.l} ${pad.t + h} Z`
      : "";

  const gridlines = [0, 0.25, 0.5, 0.75, 1].map((f) => {
    const gy = pad.t + h - f * h;
    return {
      y: gy.toFixed(1),
      x1: pad.l,
      x2: width - pad.r,
      labelX: pad.l - 8,
      labelY: (gy + 3.5).toFixed(1),
      value: peak * f,
    };
  });

  return { lineIn, lineOut: path(seriesOut), area, gridlines, peak: Math.round(peak) };
}

export function picker({ name, value, options, compact = false }) {
  const selected = options.find((o) => o.value === value) ?? options[0];
  return html`
    <div class="picker ${compact ? "picker--compact" : "picker--field"}"
         data-picker data-value="${selected.value}">
      <button class="picker__trigger" type="button" data-picker-trigger
              aria-haspopup="listbox" aria-expanded="false">
        ${selected.tone ? html`<span class="picker__swatch" data-tone="${selected.tone}"></span>` : ""}
        <span data-picker-label>${selected.label}</span>
        <svg class="picker__chevron" viewBox="0 0 10 6" aria-hidden="true">
          <path d="M1 1l4 4 4-4" fill="none" stroke="currentColor"
                stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
      </button>
      <ul class="picker__menu glass glass--strong" role="listbox" data-picker-menu hidden>
        ${options.map(
          (o) => html`
            <li class="picker__option" role="option" tabindex="-1"
                data-value="${o.value}"
                aria-selected="${String(o.value === selected.value)}">
              ${o.tone ? html`<span class="picker__swatch" data-tone="${o.tone}"></span>` : ""}
              <span>
                <strong>${o.label}</strong>
                ${o.hint ? html`<small>${o.hint}</small>` : ""}
              </span>
            </li>
          `
        )}
      </ul>
      ${name ? html`<input type="hidden" name="${name}" value="${selected.value}" data-picker-input />` : ""}
    </div>
  `;
}

let openPicker = null;

function setPickerOpen(el, open) {
  const menu = $("[data-picker-menu]", el);
  const trigger = $("[data-picker-trigger]", el);
  if (openPicker && openPicker !== el) setPickerOpen(openPicker, false);
  menu.hidden = !open;
  trigger.setAttribute("aria-expanded", String(open));
  openPicker = open ? el : null;
  if (open) {
    (menu.querySelector("[aria-selected='true']") ?? menu.firstElementChild)?.focus();
  }
}

function choosePickerValue(el, value) {
  const option = el.querySelector(`[role='option'][data-value="${CSS.escape(value)}"]`);
  if (!option) return;

  el.dataset.value = value;
  for (const o of el.querySelectorAll("[role='option']")) {
    o.setAttribute("aria-selected", String(o === option));
  }

  const label = $("[data-picker-label]", el);
  label.textContent = option.querySelector("strong")?.textContent ?? value;

  const swatch = el.querySelector(".picker__trigger .picker__swatch");
  const tone = option.querySelector(".picker__swatch")?.dataset.tone;
  if (swatch && tone) swatch.dataset.tone = tone;

  const input = $("[data-picker-input]", el);
  if (input) input.value = value;

  setPickerOpen(el, false);
  $("[data-picker-trigger]", el).focus();
  el.dispatchEvent(new CustomEvent("picker:change", { detail: { value }, bubbles: true }));
}

function initPickers() {
  document.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-picker-trigger]");
    if (trigger) {
      const el = trigger.closest("[data-picker]");
      setPickerOpen(el, $("[data-picker-menu]", el).hidden);
      return;
    }

    const option = event.target.closest("[data-picker] [role='option']");
    if (option) {
      choosePickerValue(option.closest("[data-picker]"), option.dataset.value);
      return;
    }

    if (openPicker && !openPicker.contains(event.target)) setPickerOpen(openPicker, false);
  });

  document.addEventListener("keydown", (event) => {
    const el = event.target.closest?.("[data-picker]");
    if (!el) return;
    const menu = $("[data-picker-menu]", el);
    const options = [...menu.querySelectorAll("[role='option']")];
    const index = options.indexOf(document.activeElement);

    switch (event.key) {
      case "Escape":
        if (!menu.hidden) {
          event.stopPropagation();
          setPickerOpen(el, false);
          $("[data-picker-trigger]", el).focus();
        }
        break;
      case "ArrowDown":
      case "ArrowUp": {
        event.preventDefault();
        if (menu.hidden) return setPickerOpen(el, true);
        const step = event.key === "ArrowDown" ? 1 : -1;
        options[(index + step + options.length) % options.length].focus();
        break;
      }
      case "Home":
        if (!menu.hidden) { event.preventDefault(); options[0].focus(); }
        break;
      case "End":
        if (!menu.hidden) { event.preventDefault(); options.at(-1).focus(); }
        break;
      case "Enter":
      case " ":
        if (!menu.hidden && index >= 0) {
          event.preventDefault();
          choosePickerValue(el, options[index].dataset.value);
        }
        break;
    }
  });
}

initPickers();
