/* WireLens dashboard client */
(() => {
  const state = {
    connections: [],
    dns: [],
    rules: [],
    filter: "",
    suspiciousOnly: false,
    selectedKey: null,
    demo: false,
  };

  const $ = (id) => document.getElementById(id);
  const connBody = $("connBody");
  const dnsList = $("dnsList");
  const rulesList = $("rulesList");
  const search = $("search");
  const btnSus = $("btnSuspicious");
  const btnExport = $("btnExport");
  const drawer = $("drawer");
  const drawerBody = $("drawerBody");
  const backdrop = $("backdrop");

  function isSuspicious(row) {
    const flags = row.flags || [];
    for (const f of flags) {
      if (["raw_ip", "many_short", "unusual_port", "blocklist_hit"].includes(f.id)) return true;
      if (f.id === "cgnat_or_public" && f.detail === "cgnat") return true;
    }
    return false;
  }

  function matches(row, q) {
    if (!q) return true;
    const needle = q.toLowerCase();
    const parts = [
      row.proto, row.local_addr, row.local_port, row.remote_addr, row.remote_port,
      row.state, row.pid, row.process_name, row.process_exe, row.remote_hostname,
      row.addr_class,
      ...(row.flags || []).map((f) => `${f.id} ${f.detail}`),
    ];
    return parts.join(" ").toLowerCase().includes(needle);
  }

  function flagBadges(row) {
    const flags = row.flags || [];
    return flags
      .map((f) => {
        let cls = f.id;
        if (f.id === "cgnat_or_public") cls = f.detail || "other";
        const label = f.id === "cgnat_or_public" ? f.detail : f.id;
        return `<span class="badge ${cls}" title="${escapeHtml(f.description)}${f.detail ? " — " + escapeHtml(f.detail) : ""}">${escapeHtml(label)}</span>`;
      })
      .join("");
  }

  function escapeHtml(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function filtered() {
    return state.connections.filter((r) => {
      if (state.suspiciousOnly && !isSuspicious(r)) return false;
      return matches(r, state.filter);
    });
  }

  function renderConnections() {
    const rows = filtered();
    $("shownStat").textContent = `showing ${rows.length}`;
    if (!rows.length) {
      connBody.innerHTML = `<tr><td colspan="8" class="empty">No connections match.</td></tr>`;
      return;
    }
    connBody.innerHTML = rows
      .map((r) => {
        const sus = isSuspicious(r) ? "sus" : "";
        const sel = r.key === state.selectedKey ? "selected" : "";
        const host = r.remote_hostname || "—";
        const proc = r.process_name
          ? `${escapeHtml(r.process_name)}${r.pid != null ? " <span class=\"state\">#" + r.pid + "</span>" : ""}`
          : r.pid != null
            ? `#${r.pid}`
            : "—";
        return `<tr class="${sus} ${sel}" data-key="${escapeHtml(r.key)}">
          <td class="proto">${escapeHtml(r.proto)}</td>
          <td>${escapeHtml(r.local_addr)}:${r.local_port}</td>
          <td>${escapeHtml(r.remote_addr)}:${r.remote_port}</td>
          <td title="${escapeHtml(host)}">${escapeHtml(host)}</td>
          <td class="state ${escapeHtml(r.state)}">${escapeHtml(r.state)}</td>
          <td>${proc}</td>
          <td><span class="badge ${escapeHtml(r.addr_class)}">${escapeHtml(r.addr_class)}</span></td>
          <td>${flagBadges(r)}</td>
        </tr>`;
      })
      .join("");
  }

  function renderDns() {
    if (!state.dns.length) {
      dnsList.innerHTML = `<li class="empty">No DNS cache entries.</li>`;
      return;
    }
    dnsList.innerHTML = state.dns
      .slice(0, 80)
      .map(
        (e) =>
          `<li><span class="ip">${escapeHtml(e.ip)}</span> → <span class="host">${escapeHtml(e.hostname || "(none)")}</span></li>`
      )
      .join("");
  }

  function renderRules() {
    rulesList.innerHTML = state.rules
      .map(
        (r) =>
          `<li><span class="rid">${escapeHtml(r.id)}</span><span class="rdesc">${escapeHtml(r.description)}</span></li>`
      )
      .join("");
  }

  function openDrawer(key) {
    const row = state.connections.find((c) => c.key === key);
    if (!row) return;
    state.selectedKey = key;
    renderConnections();
    const flags = (row.flags || [])
      .map(
        (f) =>
          `<li><div class="fid">${escapeHtml(f.id)}</div><div class="fdesc">${escapeHtml(f.description)}</div>${
            f.detail ? `<div class="fdetail">${escapeHtml(f.detail)}</div>` : ""
          }</li>`
      )
      .join("");
    drawerBody.innerHTML = `
      <div class="kv">
        <div class="k">Key</div><div class="v">${escapeHtml(row.key)}</div>
        <div class="k">Protocol</div><div class="v">${escapeHtml(row.proto)}</div>
        <div class="k">Local</div><div class="v">${escapeHtml(row.local_addr)}:${row.local_port}</div>
        <div class="k">Remote</div><div class="v">${escapeHtml(row.remote_addr)}:${row.remote_port}</div>
        <div class="k">Hostname</div><div class="v">${escapeHtml(row.remote_hostname || "—")}</div>
        <div class="k">State</div><div class="v">${escapeHtml(row.state)}</div>
        <div class="k">Addr class</div><div class="v">${escapeHtml(row.addr_class)}</div>
        <div class="k">PID</div><div class="v">${row.pid ?? "—"}</div>
        <div class="k">Process</div><div class="v">${escapeHtml(row.process_name || "—")}</div>
        <div class="k">Executable</div><div class="v">${escapeHtml(row.process_exe || "—")}</div>
        <div class="k">First seen</div><div class="v">${new Date(row.first_seen * 1000).toLocaleString()}</div>
        <div class="k">Last seen</div><div class="v">${new Date(row.last_seen * 1000).toLocaleString()}</div>
      </div>
      <h4 style="margin:1rem 0 0.4rem;font-size:0.75rem;text-transform:uppercase;letter-spacing:0.08em;color:var(--muted)">Flags</h4>
      <ul class="flag-list">${flags || "<li class='empty'>None</li>"}</ul>
    `;
    drawer.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");
    backdrop.classList.add("show");
  }

  function closeDrawer() {
    drawer.classList.remove("open");
    drawer.setAttribute("aria-hidden", "true");
    backdrop.classList.remove("show");
    state.selectedKey = null;
    renderConnections();
  }

  function applySnapshot(msg) {
    state.connections = msg.connections || [];
    state.dns = msg.dns || [];
    state.demo = !!msg.demo;
    $("connCount").textContent = String(msg.connection_count ?? state.connections.length);
    $("dnsCount").textContent = String(msg.dns_count ?? state.dns.length);
    $("modeLabel").textContent = state.demo ? "demo" : "live";
    renderConnections();
    renderDns();
  }

  connBody.addEventListener("click", (ev) => {
    const tr = ev.target.closest("tr[data-key]");
    if (tr) openDrawer(tr.getAttribute("data-key"));
  });
  $("btnCloseDrawer").addEventListener("click", closeDrawer);
  backdrop.addEventListener("click", closeDrawer);

  search.addEventListener("input", () => {
    state.filter = search.value.trim();
    renderConnections();
  });

  btnSus.addEventListener("click", () => {
    state.suspiciousOnly = !state.suspiciousOnly;
    btnSus.classList.toggle("active", state.suspiciousOnly);
    renderConnections();
  });

  btnExport.addEventListener("click", () => {
    const params = new URLSearchParams();
    if (state.suspiciousOnly) params.set("suspicious_only", "true");
    if (state.filter) params.set("q", state.filter);
    const qs = params.toString();
    window.location.href = "/api/export.csv" + (qs ? "?" + qs : "");
  });

  async function loadRules() {
    try {
      const res = await fetch("/api/rules");
      const data = await res.json();
      state.rules = data.rules || [];
      renderRules();
    } catch (e) {
      rulesList.innerHTML = `<li class="empty">Failed to load rules.</li>`;
    }
  }

  function connectWs() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/ws`);
    const dot = $("wsDot");
    const label = $("wsLabel");

    ws.onopen = () => {
      dot.classList.add("live");
      label.textContent = "live";
    };
    ws.onclose = () => {
      dot.classList.remove("live");
      label.textContent = "reconnecting…";
      setTimeout(connectWs, 2000);
    };
    ws.onerror = () => {
      try { ws.close(); } catch (_) {}
    };
    ws.onmessage = (ev) => {
      try {
        applySnapshot(JSON.parse(ev.data));
      } catch (_) {}
    };
  }

  loadRules();
  connectWs();
})();
