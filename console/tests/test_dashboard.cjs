// Optional browser regression suite: npm install --no-save playwright
// then node tests/test_dashboard.cjs (or supply NODE_PATH for an existing install).
// Python is required to obtain the real server CSP; override with RDMON_TEST_PYTHON.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { chromium } = require('playwright');

// Use the server's actual CSP, rather than a permissive mock page. Script
// hashes alone do not authorize HTML onclick/ontoggle attributes.
const policyProbe = spawnSync(process.env.RDMON_TEST_PYTHON || (process.platform === 'win32' ? 'python' : 'python3'), ['-c', `
import io, os, pathlib, sys, types
project=pathlib.Path(sys.argv[1])
os.environ['RDMON_CONFIG']=str(project/'config/examples/console.ini.example')
sys.path.insert(0,str(project/'console/app'))
import server
handler=server.Handler.__new__(server.Handler)
headers={}
handler.send_response=lambda *args: None
handler.send_header=lambda name,value: headers.__setitem__(name,value)
handler.end_headers=lambda: None
handler.wfile=io.BytesIO()
handler.server=types.SimpleNamespace(is_tls=True)
handler._send(200,(project/'console/app/static/index.html').read_bytes(),'text/html; charset=utf-8')
print(headers['Content-Security-Policy'])
`, path.resolve(__dirname, '../..')], { encoding:'utf8' });
assert.equal(policyProbe.status, 0, policyProbe.stderr);
const productionPolicy = policyProbe.stdout.trim();

(async () => {
  const browser = await chromium.launch({ headless: true,
    ...(process.env.RDMON_TEST_BROWSER ? { executablePath: process.env.RDMON_TEST_BROWSER } : {}) });
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    const page = await context.newPage();
    await page.addInitScript(() => {
      window.__policyViolations=[];
      window.__testLaunch=null;
      document.addEventListener('securitypolicyviolation', event=>window.__policyViolations.push(event.violatedDirective));
      // Record the handoff without launching a real remote session in tests.
      document.addEventListener('click', event=>{
        const link=event.target.closest('a.connect');
        if(link){window.__testLaunch=link.href;event.preventDefault();}
      });
    });
    await page.clock.install();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const root = path.join(__dirname, '..', 'app', 'static');
    const statuses = ['reported', 'missing report', 'stale report', 'nobody logged on', 'owner mismatch'];
    const peers = statuses.map((status, index) => ({
      id: String(100000001 + index), name: 'TEST-' + index,
      online: index !== 2, ip: '10.0.0.' + (index + 1), port: 21116,
      name_source: 'vault', os: 'Windows 11 26H2',
      users: index === 0 ? ['DOMAIN\\alice'] : index === 2 ? ['DOMAIN\\old'] : index === 3 ? [] : null,
      users_age: index === 2 ? 3600 : 60, age_seconds: index === 2 ? 3600 : 5,
      registered_at: '2026-10-13 10:00:00', report_status: status, report_host: 'TEST-' + index
    }));
    let requests = 0, role = 'admin', vaultEnabled = true;
    await page.route('http://localhost:9876/**', async route => {
      const url = new URL(route.request().url());
      if (url.pathname === '/api/reveal') return route.fulfill({json:{status:'ok',password:'browser-test-secret-sentinel'}});
      if (url.pathname === '/api/clients') {
        requests++;
        return route.fulfill({ json: { csrf:'fixture-csrf', peers: vaultEnabled ? peers : peers.map(p => ({...p, users:null, report_status:'not configured'})), vault_enabled: vaultEnabled, total_count: 5, online_count: 4, online_window: 60,
          user: { username: 'test-user', role }, permissions: role === 'admin' ? ['monitor','connect','reveal','users','audit'] : ['monitor'],
          server_time: Date.now() / 1000, updated: Date.now() / 1000,
          health: { collector_age: 0, vault_status: vaultEnabled ? 'ok' : 'disabled', vault_age: 10,
            report_counts: Object.fromEntries(statuses.map(status => [status, 1])) } } });
      }
      const filename = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
      if (['index.html', 'rdmon.css', 'favicon.svg', 'favicon.ico'].includes(filename)) {
        return route.fulfill({ body: fs.readFileSync(path.join(root, filename)),
          headers: filename.endsWith('html') ? {'Content-Security-Policy':productionPolicy} : {},
          contentType: filename.endsWith('html') ? 'text/html' : filename.endsWith('css') ? 'text/css' : 'image/svg+xml' });
      }
      return route.fulfill({ status: 404, body: 'Not found' });
    });
    await page.goto('http://localhost:9876/');
    await page.waitForSelector('tbody tr');
    assert.equal(await page.locator('tbody tr').count(), 5);
    assert.equal(await page.locator('.pw-btn').count(), 5);
    assert.equal(await page.locator('.connect').count(), 5);
    assert.equal(await page.locator('.connect').first().getAttribute('href'), 'rustdesk://connect/100000001');
    await page.locator('.connect').first().click();
    assert.equal(await page.evaluate(()=>window.__testLaunch), 'rustdesk://connect/100000001');
    await page.locator('[data-act="reveal"]').first().click();
    await page.waitForSelector('.pw-val');
    assert.equal(await page.locator('.pw-val').textContent(), 'browser-test-secret-sentinel');
    await page.locator('.pw-val').evaluate(node=>window.getSelection().selectAllChildren(node));
    await page.clock.fastForward(21000);
    assert.equal(await page.locator('.pw-val').count(), 0, 'password expiry must override active text selection');
    assert(!(await page.locator('body').innerText()).includes('browser-test-secret-sentinel'));
    assert(!(await page.evaluate(()=>JSON.stringify(localStorage))).includes('browser-test-secret-sentinel'));
    await page.evaluate(()=>window.getSelection().removeAllRanges());
    await page.selectOption('#report-filter', 'attention');
    assert.equal(await page.locator('tbody tr').count(), 3);
    await page.click('#seg button[data-mode="online"]');
    assert.equal(await page.locator('tbody tr').count(), 2);
    await page.reload();
    await page.waitForSelector('tbody tr');
    assert.equal(await page.locator('#report-filter').inputValue(), 'attention');
    assert.equal(await page.locator('tbody tr').count(), 2);
    await page.selectOption('#report-filter', 'all');
    await page.click('#seg button[data-mode="all"]');
    await page.fill('#q', '10.0.0.1');
    assert.equal(await page.locator('tbody tr').count(), 1);
    role = 'viewer';
    await page.click('#refresh-now');
    await page.waitForFunction(()=>!document.getElementById('refresh-now').disabled);
    assert.equal(await page.locator('.pw-btn').count(), 0);
    assert.equal(await page.locator('.connect').count(), 0);
    assert(await page.locator('[data-permission=users]').isHidden());
    assert(await page.locator('[data-permission=audit]').isHidden());
    await page.click('#q-clear');
    await page.click('#cols-btn');
    await page.uncheck('input[data-col="report"]');
    await page.click('#cols-btn');
    assert.equal(await page.locator('th button[data-sort="report"]').count(), 0);
    await page.click('#pause');
    const before = requests;
    await page.click('#refresh-now');
    await page.waitForFunction(() => !document.getElementById('refresh-now').disabled);
    assert.equal(requests, before + 1);
    assert.equal(await page.locator('#live-txt').textContent(), 'Paused');
    const theme = await page.locator('html').getAttribute('data-theme');
    await page.click('#theme');
    assert.notEqual(await page.locator('html').getAttribute('data-theme'), theme);
    await page.selectOption('#report-filter', 'missing');
    const downloadPromise = page.waitForEvent('download');
    await page.click('#export');
    const download = await downloadPromise;
    const csv = fs.readFileSync(await download.path(), 'utf8');
    assert(csv.includes('Reporting status') && csv.includes('missing report'));
    assert(!csv.includes('Password'));
    assert.equal(await page.locator('tbody tr').count(), 1);
    role = 'admin';
    vaultEnabled = false;
    await page.selectOption('#report-filter', 'all');
    await page.click('#refresh-now');
    await page.waitForFunction(()=>!document.getElementById('refresh-now').disabled);
    assert.equal(await page.locator('tbody tr').count(), 5);
    assert.equal(await page.locator('.pw-btn').count(), 0);
    assert.equal(await page.locator('td.pw').filter({hasText:'vault disabled'}).count(), 5);
    await page.selectOption('#report-filter', 'attention');
    assert.equal(await page.locator('tbody tr[data-id]').count(), 0);
    assert.deepEqual(errors, []);
    assert.deepEqual(await page.evaluate(()=>window.__policyViolations), [], 'dashboard controls must work under the production CSP');
    console.log('PASS: Connect handoff, reporting/status/search filters, saved preferences, column visibility, manual refresh while paused, theme, CSV, production CSP, no browser errors');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exit(1); });
