'use strict';

const DEFAULT_MGMT = 'http://127.0.0.1:8081';
const DEFAULT_PROXY_HOST = '127.0.0.1';
const DEFAULT_PROXY_PORT = 8080;

const el = id => document.getElementById(id);

// ── Storage helpers ──────────────────────────────────────────────────────────

async function loadMgmtAddr() {
  const { mgmtAddr } = await chrome.storage.local.get('mgmtAddr');
  return mgmtAddr || DEFAULT_MGMT;
}

async function saveMgmtAddr(addr) {
  await chrome.storage.local.set({ mgmtAddr: addr });
}

// ── Management API ───────────────────────────────────────────────────────────

async function fetchConfig(mgmtAddr) {
  const resp = await fetch(`${mgmtAddr}/api/config`, {
    signal: AbortSignal.timeout(2000),
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

async function postConfig(mgmtAddr, cfg) {
  const resp = await fetch(`${mgmtAddr}/api/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(cfg),
    signal: AbortSignal.timeout(2000),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(text.trim() || `HTTP ${resp.status}`);
  }
  return resp.json();
}

// ── Chrome proxy settings ────────────────────────────────────────────────────

function parseListenAddr(listen) {
  // "127.0.0.1:8080" → { host, port }
  const lastColon = (listen || '').lastIndexOf(':');
  if (lastColon === -1) return { host: DEFAULT_PROXY_HOST, port: DEFAULT_PROXY_PORT };
  return {
    host: listen.slice(0, lastColon) || DEFAULT_PROXY_HOST,
    port: parseInt(listen.slice(lastColon + 1)) || DEFAULT_PROXY_PORT,
  };
}

function getProxyEnabled() {
  return new Promise(resolve => {
    chrome.proxy.settings.get({ incognito: false }, details => {
      resolve(details.value?.mode === 'fixed_servers');
    });
  });
}

function enableProxy(host, port) {
  return new Promise(resolve => {
    chrome.proxy.settings.set({
      value: {
        mode: 'fixed_servers',
        rules: { singleProxy: { scheme: 'http', host, port } },
      },
      scope: 'regular',
    }, resolve);
  });
}

function disableProxy() {
  return new Promise(resolve => {
    chrome.proxy.settings.clear({ scope: 'regular' }, resolve);
  });
}

// ── UI helpers ───────────────────────────────────────────────────────────────

function setStatus(state, text) {
  // state: 'connected' | 'disconnected' | 'unknown'
  el('statusDot').className = `dot dot-${state}`;
  el('statusText').textContent = text;
}

function showApplyMsg(text, type) {
  const div = el('applyMsg');
  div.textContent = text;
  div.className = `apply-msg ${type}`;
  if (text) setTimeout(() => { div.textContent = ''; div.className = 'apply-msg'; }, 2500);
}

// ── Initialisation ───────────────────────────────────────────────────────────

async function init() {
  const mgmtAddr = await loadMgmtAddr();
  el('mgmtAddr').value = mgmtAddr;

  // Proxy toggle: reflect current Chrome proxy state.
  el('proxyToggle').checked = await getProxyEnabled();

  // Fetch live config from management API.
  try {
    const cfg = await fetchConfig(mgmtAddr);
    el('tlsPreset').value = cfg.tls_preset || 'chrome';
    el('clientIP').value  = cfg.client_ip  || '';
    el('userAgent').value = cfg.user_agent || '';
    const { host, port } = parseListenAddr(cfg.listen);
    setStatus('connected', `Connected · ${host}:${port}`);
  } catch {
    setStatus('disconnected', 'Proxy offline');
  }
}

// ── Event listeners ──────────────────────────────────────────────────────────

// Proxy on/off toggle.
el('proxyToggle').addEventListener('change', async e => {
  if (e.target.checked) {
    const mgmtAddr = await loadMgmtAddr();
    let host = DEFAULT_PROXY_HOST;
    let port = DEFAULT_PROXY_PORT;
    try {
      const cfg = await fetchConfig(mgmtAddr);
      ({ host, port } = parseListenAddr(cfg.listen));
    } catch { /* use defaults */ }
    await enableProxy(host, port);
  } else {
    await disableProxy();
  }
});

// Apply button: POST settings to management API.
el('applyBtn').addEventListener('click', async () => {
  const btn = el('applyBtn');
  btn.disabled = true;
  try {
    const mgmtAddr = await loadMgmtAddr();
    await postConfig(mgmtAddr, {
      tls_preset: el('tlsPreset').value,
      client_ip:  el('clientIP').value.trim(),
      user_agent: el('userAgent').value.trim(),
    });
    showApplyMsg('Applied', 'success');
  } catch (err) {
    showApplyMsg(err.message, 'error');
  } finally {
    btn.disabled = false;
  }
});

// Management API address: save on blur and re-init.
el('mgmtAddr').addEventListener('change', async () => {
  const addr = el('mgmtAddr').value.trim();
  await saveMgmtAddr(addr);
  await init();
});

init();
