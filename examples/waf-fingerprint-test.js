// waf-fingerprint-test.js
// A harness for evaluating your own WAF rules.
// Cycles through several fingerprint presets via impersonate-proxy, hits the
// target endpoint through each one, and records whether the WAF allowed or
// blocked the request.
//
// Prerequisites:
//   - impersonate-proxy is running (proxy: 127.0.0.1:8080 / mgmt: 127.0.0.1:8081)
//   - ca.crt is in the same directory as this script
//   - the target is a WAF endpoint you own or are authorized to test
//
// Run:
//   npm i playwright
//   npx playwright install chromium
//   NODE_EXTRA_CA_CERTS=./ca.crt node waf-fingerprint-test.js
//
// Requires Node 18+ (uses the global fetch).

const { chromium } = require('playwright');

const PROXY  = 'http://127.0.0.1:8080';
const MGMT   = 'http://127.0.0.1:8081/api/config';
const TARGET = 'https://your-waf-endpoint.example.com/'; // ← point this at your own WAF endpoint

// Combinations of settings to try.
// An empty string for user_agent / client_ip means "leave it unchanged (passthrough)".
// tls_preset: chrome | firefox | safari | edge | ios | random | golang
const PROFILES = [
  { tls_preset: 'chrome',  user_agent: '', client_ip: '' },
  { tls_preset: 'firefox', user_agent: '', client_ip: '' },
  { tls_preset: 'safari',  user_agent: '', client_ip: '' },
  { tls_preset: 'edge',    user_agent: '', client_ip: '' },
  { tls_preset: 'ios',     user_agent: '', client_ip: '' },
  { tls_preset: 'random',  user_agent: '', client_ip: '' },
  { tls_preset: 'golang',  user_agent: '', client_ip: '' },
  // Example: deliberately mismatch UA and TLS fingerprint, to see whether
  // the WAF catches the inconsistency.
  // { tls_preset: 'firefox', user_agent: 'Mozilla/5.0 ... Chrome/131.0.0.0 Safari/537.36', client_ip: '' },
  // Example: how the WAF reacts to X-Forwarded-For / True-Client-IP spoofing.
  // { tls_preset: 'chrome', user_agent: '', client_ip: '203.0.113.10' },
];

// Decide whether the WAF blocked the request. Adjust this to match how your
// own rules actually respond.
function classify(status, headers, bodyText) {
  if (status === 403 || status === 429) return 'BLOCKED';
  if (/access denied|request blocked|forbidden|blocked by/i.test(bodyText)) return 'BLOCKED';
  // Example: if your WAF reports its verdict via a custom header, check it here.
  // if (headers['x-waf-action'] === 'block') return 'BLOCKED';
  if (status >= 200 && status < 400) return 'ALLOWED';
  return `OTHER(${status})`;
}

async function setProfile(profile) {
  const res = await fetch(MGMT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(profile),
  });
  if (!res.ok) throw new Error(`mgmt POST failed: ${res.status}`);
}

(async () => {
  const results = [];

  for (const profile of PROFILES) {
    await setProfile(profile);

    // Launch a fresh browser/context per preset so the connection is
    // re-established from scratch — otherwise the browser may reuse a
    // pooled connection from the previous fingerprint.
    const browser = await chromium.launch();
    const context = await browser.newContext({
      proxy: { server: PROXY },
      // If you're not trusting the CA via NODE_EXTRA_CA_CERTS, enable this instead:
      // ignoreHTTPSErrors: true,
    });
    const page = await context.newPage();

    let row = {
      preset: profile.tls_preset,
      client_ip: profile.client_ip || '-',
      status: null,
      verdict: 'ERROR',
      note: '',
    };

    try {
      const resp = await page.goto(TARGET, { waitUntil: 'domcontentloaded', timeout: 20000 });
      const status  = resp.status();
      const headers = resp.headers();
      const bodyText = await page.evaluate(
        () => (document.body ? document.body.innerText.slice(0, 500) : '')
      );
      row.status  = status;
      row.verdict = classify(status, headers, bodyText);
      row.note    = bodyText.replace(/\s+/g, ' ').trim().slice(0, 80);
    } catch (e) {
      row.note = String(e.message).slice(0, 80);
    }

    results.push(row);
    await browser.close();
  }

  console.table(results);

  // To also save the results to a file:
  // require('fs').writeFileSync('waf-results.json', JSON.stringify(results, null, 2));
})();
