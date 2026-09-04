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

async function fetchUpstream(mgmtAddr) {
  const resp = await fetch(`${mgmtAddr}/api/upstream`, {
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

// ── Custom TLS ClientHello (JA3/JA4) helpers ────────────────────────────────

// parseIdList turns "0x0a0a, 4865, 4866" into [2570, 4865, 4866].
// Accepts decimal or 0x-prefixed hex, comma/whitespace separated.
function parseIdList(text) {
  return (text || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .map(s => parseInt(s, s.toLowerCase().startsWith('0x') ? 16 : 10));
}

function parseNameList(text) {
  return (text || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
}

function customHelloFromForm() {
  return {
    cipher_suites: parseIdList(el('customCiphers').value),
    curves: parseNameList(el('customCurves').value),
    versions: parseNameList(el('customVersions').value),
    extensions: parseIdList(el('customExtensions').value),
  };
}

function setCustomHelloForm(customHello) {
  const ch = customHello || {};
  el('customCiphers').value = (ch.cipher_suites || []).join(', ');
  el('customCurves').value = (ch.curves || []).join(', ');
  el('customVersions').value = (ch.versions || []).join(', ');
  el('customExtensions').value = (ch.extensions || []).join(', ');
}

function updateCustomHelloVisibility() {
  el('customHelloFields').hidden = el('tlsPreset').value !== 'custom';
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
    setCustomHelloForm(cfg.custom_hello);
    updateCustomHelloVisibility();
    setRandomField('clientIP',  'clientIPRandom',   cfg.client_ip  || '');
    setRandomField('userAgent', 'userAgentRandom',  cfg.user_agent || '');
    const { host, port } = parseListenAddr(cfg.listen);
    setStatus('connected', `Connected · ${host}:${port}`);
  } catch {
    setStatus('disconnected', 'Proxy offline');
  }

  // Fetch live upstream state separately — /api/upstream never returns
  // credentials, only proxy names, but it can still fail independently
  // (e.g. an older proxy binary without this endpoint).
  try {
    const up = await fetchUpstream(mgmtAddr);
    populateUpstreamSelect(up.proxies || [], up.select || '');
    el('upstreamEnabled').checked = !!up.enabled;
    el('upstreamSelect').disabled = (up.proxies || []).length === 0;
  } catch {
    el('upstreamEnabled').checked = false;
    el('upstreamEnabled').disabled = true;
    el('upstreamSelect').disabled = true;
  }
}

// populateUpstreamSelect rebuilds the upstream dropdown from the proxy
// names the management API returns, plus the always-available rotate/random
// modes, and selects whichever is currently active.
function populateUpstreamSelect(names, current) {
  const sel = el('upstreamSelect');
  sel.innerHTML = '';
  if (names.length === 0) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = '(no proxies configured)';
    sel.appendChild(opt);
    return;
  }
  for (const name of names) {
    const opt = document.createElement('option');
    opt.value = name;
    opt.textContent = name;
    sel.appendChild(opt);
  }
  for (const mode of ['rotate', 'random']) {
    const opt = document.createElement('option');
    opt.value = mode;
    opt.textContent = mode === 'rotate' ? 'Rotate' : 'Random';
    sel.appendChild(opt);
  }
  sel.value = current || names[0];
}

// setRandomField syncs a text input + its random checkbox from a config value.
// If value is "random", the checkbox is checked and the input is disabled.
function setRandomField(inputId, checkId, value) {
  const isRandom = value === 'random';
  el(checkId).checked  = isRandom;
  el(inputId).disabled = isRandom;
  el(inputId).value    = isRandom ? '' : value;
}

// randomFieldValue returns "random" when the checkbox is checked,
// otherwise returns the trimmed text input value.
function randomFieldValue(inputId, checkId) {
  return el(checkId).checked ? 'random' : el(inputId).value.trim();
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

// TLS preset select: show/hide the custom ClientHello fields.
el('tlsPreset').addEventListener('change', updateCustomHelloVisibility);

// Random checkboxes: toggle disabled state of the paired text input.
el('clientIPRandom').addEventListener('change', () => {
  el('clientIP').disabled = el('clientIPRandom').checked;
});
el('userAgentRandom').addEventListener('change', () => {
  el('userAgent').disabled = el('userAgentRandom').checked;
});

// Apply button: POST settings to management API.
el('applyBtn').addEventListener('click', async () => {
  const btn = el('applyBtn');
  btn.disabled = true;
  try {
    const mgmtAddr = await loadMgmtAddr();
    await postConfig(mgmtAddr, {
      tls_preset:   el('tlsPreset').value,
      custom_hello: customHelloFromForm(),
      client_ip:    randomFieldValue('clientIP',  'clientIPRandom'),
      user_agent:   randomFieldValue('userAgent', 'userAgentRandom'),
    });
    showApplyMsg('Applied', 'success');
  } catch (err) {
    showApplyMsg(err.message, 'error');
  } finally {
    btn.disabled = false;
  }
});

// Upstream proxy: enabled toggle and select both apply immediately via a
// partial POST (only the changed field is sent — the management API keeps
// every other setting, including TLS preset, untouched).
el('upstreamEnabled').addEventListener('change', async e => {
  const mgmtAddr = await loadMgmtAddr();
  try {
    await postConfig(mgmtAddr, { upstream_enabled: e.target.checked });
    showApplyMsg(e.target.checked ? 'Upstream enabled' : 'Upstream disabled', 'success');
  } catch (err) {
    e.target.checked = !e.target.checked; // revert the toggle on failure
    showApplyMsg(err.message, 'error');
  }
});

el('upstreamSelect').addEventListener('change', async e => {
  const mgmtAddr = await loadMgmtAddr();
  try {
    await postConfig(mgmtAddr, { upstream_select: e.target.value });
    showApplyMsg(`Upstream: ${e.target.value}`, 'success');
  } catch (err) {
    showApplyMsg(err.message, 'error');
  }
});

// Management API address: save on blur and re-init.
el('mgmtAddr').addEventListener('change', async () => {
  const addr = el('mgmtAddr').value.trim();
  await saveMgmtAddr(addr);
  await init();
});

init();
