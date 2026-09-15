import { html, render, on, toast, picker } from "../ui.js";
import { api } from "../api.js";

export default function settings(root) {
  let current = null;
  let status = null;

  render(
    root,
    html`<div class="view" data-view="settings">
      <div class="panel glass"><div class="empty"><div class="spinner"></div></div></div>
    </div>`
  );

  const view = root.firstElementChild;

  function draw() {
    const linux = status?.platform === "linux";
    const elevated = status?.elevated !== false;
    const firewall = linux ? "nftables" : "the Windows Filtering Platform";

    render(
      view,
      html`
        ${elevated
          ? ""
          : html`<p class="notice notice--warn">
              ${linux
                ? "WireCee is not running as root. Blocking, DNS filtering and UDP tracing need sudo."
                : "WireCee is running without administrator rights. Blocking, DNS filtering and byte counts need them. Restart WireCee and approve the prompt."}
            </p>`}

        ${section("Protection", "What happens to traffic that matches no rule", html`
          ${choice("defaultOutbound", "Default outbound policy",
            "Applies to connections this computer starts. Ask refuses new applications until you allow them. DNS and DHCP stay open under Ask and Block.",
            [
              { value: "allow", label: "Allow", tone: "ok" },
              { value: "ask", label: "Ask", tone: "warn" },
              { value: "block", label: "Block", tone: "bad" },
            ])}
          ${choice("defaultInbound", "Default inbound policy",
            `Applies to connections started from outside. Allow defers to ${linux ? "the existing firewall configuration" : "Windows Firewall"}. Block also overrides its exceptions. Replies to your own connections are never affected.`,
            [
              { value: "allow", label: linux ? "Allow" : "Allow, Windows Firewall decides", tone: "ok" },
              { value: "ask", label: "Ask", tone: "warn" },
              { value: "block", label: "Block", tone: "bad" },
            ])}
        `)}

        ${section("DNS filtering", "Block domains for every application on this computer", html`
          ${toggle("dnsFilter", "Filter DNS lookups",
            "Answers every lookup through WireCee and refuses domains on your blocklist, including their subdomains. Applications cannot query other DNS servers directly while this is on.")}
          ${choice("dnsUpstream", "Upstream resolver",
            "Where allowed lookups are forwarded. System uses the servers your network provides.",
            [
              { value: "system", label: "System" },
              { value: "cloudflare", label: "Cloudflare" },
              { value: "quad9", label: "Quad9" },
              { value: "google", label: "Google" },
            ])}
          ${toggle("blockEncryptedDns", "Block encrypted DNS",
            "Blocks DNS over TLS and well known DNS over HTTPS resolvers, so browsers cannot bypass the filter. Websites hosted on those resolver addresses also become unreachable.")}
          <div class="setting">
            <div>
              <div class="setting__label">Blocklist</div>
              <div class="setting__desc">Add, import and remove blocked domains, and review recent lookups.</div>
            </div>
            <div class="setting__control"><a class="btn btn--sm" href="#/dns">Manage blocklist</a></div>
          </div>
        `)}

        ${section("Notifications", "When WireCee interrupts you", html`
          ${toggle("notifyOnNewApp", "New applications", "Notifies you the first time an application connects to the network.")}
          ${toggle("notifyOnBlock", "Blocked traffic", "Notifies you when WireCee refuses a connection, at most once every 15 seconds.")}
          ${toggle("notifyOnNewDevice", "New devices", "Notifies you when an unknown device joins your local network.")}
          ${toggle("quietMode", "Quiet mode", "Suppresses every notification. Events are still recorded in Alerts and Logs.")}
        `)}

        ${section("Security monitoring", "Changes that raise an alert", html`
          ${toggle("alertHostsFile", "Hosts file changes", "The hosts file overrides DNS and is a common target for malware.")}
          ${toggle("alertDnsChange", "DNS server changes", "Detects DNS servers changed by another program or the network.")}
          ${toggle("alertProxyChange", "Proxy changes", "Detects a new system proxy that could intercept web traffic.")}
          ${toggle("alertRemoteAccess", linux ? "SSH sessions" : "Remote Desktop sessions",
            linux ? "Alerts when someone opens an SSH session to this computer." : "Alerts when someone connects to this computer over Remote Desktop.")}
          ${toggle("alertAppChange", "Application changes", "Alerts when the executable of a known application is modified. Updates also trigger this alert.")}
          ${toggle("alertNotify", linux ? "Show desktop notifications" : "Show Windows notifications",
            status?.notifications === false
              ? (linux
                  ? "notify-send was not found, so nothing can be shown on the desktop. Install libnotify-bin. Alerts are always listed in Alerts."
                  : "Notifications are turned off for this Windows account, so nothing will appear on screen. Turn them on in Settings, System, Notifications. Alerts are always listed in Alerts.")
              : (linux
                  ? "Raises a desktop notification for each alert above, using notify-send. Alerts are always listed in Alerts either way."
                  : "Raises a Windows notification in the corner of the screen for each alert above. Alerts are always listed in Alerts either way."))}
        `)}

        ${section("Data usage", "Track consumption against a monthly allowance", html`
          ${number("dataLimitMb", "Monthly limit", "Megabytes per billing period. WireCee alerts at 80 percent and at the limit. Set to 0 to disable.", 0, 10000000, "MB")}
          ${number("dataResetDay", "Billing period starts on", "Day of the month the allowance resets.", 1, 28, "day")}
        `)}

        ${section("Application", "How WireCee runs", html`
          ${linux ? "" : toggle("keepRunningInBackground", "Keep running when the window is closed",
            "Protection and monitoring continue from the tray. When off, closing the window stops the engine and removes every filter.")}
          ${toggle("startWithWindows", linux ? "Start at boot" : "Start with Windows",
            linux
              ? "Enables the systemd service so protection starts before anyone signs in."
              : "Starts WireCee in the tray at sign in, with administrator rights and without a prompt.")}
          ${number("logRetentionDays", "Log retention", "Days of daily log files kept on disk.", 1, 365, "days")}
        `)}

        <section class="panel glass">
          <div class="panel__head">
            <div>
              <h2>About</h2>
              <p>WireCee ${status?.version ?? ""} by TakeGuard</p>
            </div>
          </div>
          <p class="about__body">
            WireCee monitors connections, enforces your rules through ${firewall} and filters DNS on this
            ${linux ? "machine" : "computer"}. Every filter belongs to the running engine and is removed when it stops.
          </p>
        </section>
      `
    );
  }

  function section(title, blurb, body) {
    return html`
      <section class="panel glass">
        <div class="panel__head">
          <div>
            <h2>${title}</h2>
            <p>${blurb}</p>
          </div>
        </div>
        <div class="settings-list">${body}</div>
      </section>
    `;
  }

  function toggle(key, text, desc) {
    return html`
      <div class="setting">
        <div>
          <div class="setting__label">${text}</div>
          <div class="setting__desc">${desc}</div>
        </div>
        <div class="setting__control">
          <label class="switch">
            <input type="checkbox" data-key="${key}" ${current[key] ? html`checked` : ""} aria-label="${text}" />
            <span class="switch__track"></span>
          </label>
        </div>
      </div>
    `;
  }

  function choice(key, text, desc, options) {
    return html`
      <div class="setting">
        <div>
          <div class="setting__label">${text}</div>
          <div class="setting__desc">${desc}</div>
        </div>
        <div class="setting__control" data-choice="${key}">
          ${picker({ value: current[key], options })}
        </div>
      </div>
    `;
  }

  function number(key, text, desc, min, max, unit) {
    return html`
      <div class="setting">
        <div>
          <div class="setting__label">${text}</div>
          <div class="setting__desc">${desc}</div>
        </div>
        <div class="setting__control setting__control--number">
          <input class="input mono" type="number" data-key="${key}" min="${min}" max="${max}"
                 value="${current[key]}" aria-label="${text}" />
          <span class="u-faint">${unit}</span>
        </div>
      </div>
    `;
  }

  async function save(key, value, revert) {
    const previous = current[key];
    current[key] = value;
    try {
      const saved = await api.saveSettings({ [key]: value });
      if (saved && key in saved && saved[key] !== value) {
        current[key] = saved[key];
        revert(saved[key]);
        toast("The system refused that change. Logs has the details.", "bad");
        return;
      }
      toast("Saved", "ok", 1600);
    } catch (err) {
      current[key] = previous;
      revert(previous);
      toast(`Could not save: ${err.message}`, "bad");
    }
  }

  on(view, "change", "[data-key]", (event, el) => {
    const key = el.dataset.key;
    if (el.type !== "checkbox") {
      const min = Number(el.min), max = Number(el.max);
      const n = Math.round(Number(el.value));
      if (!Number.isFinite(n) || n < min || n > max) {
        el.value = current[key];
        toast(`Enter a value between ${min} and ${max}`, "warn");
        return;
      }
    }
    const value = el.type === "checkbox" ? el.checked : Math.round(Number(el.value));
    save(key, value, (next) => {
      if (el.type === "checkbox") el.checked = next;
      else el.value = next;
    });
  });

  on(view, "picker:change", "[data-choice]", (event, el) => {
    save(el.dataset.choice, event.detail.value, () => draw());
  });

  Promise.all([api.settings(), api.status().catch(() => null)])
    .then(([s, st]) => {
      current = s;
      status = st;
      draw();
    })
    .catch((err) => {
      render(view, html`<div class="panel glass"><div class="empty">
        <h3>Settings could not be loaded</h3><p>${err.message}</p>
      </div></div>`);
    });

  return () => {};
}
