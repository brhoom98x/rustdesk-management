const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: true,
    ...(process.env.RDMON_TEST_BROWSER ? { executablePath: process.env.RDMON_TEST_BROWSER } : {}) });
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const root = path.join(__dirname, '..', 'app', 'static');
    const users = [{ username: 'admin', role: 'admin', enabled: 1, last_login: null }];
    let changedPassword = false;
    await page.route('http://localhost:9877/**', async route => {
      const url = new URL(route.request().url());
      if (url.pathname === '/api/me') return route.fulfill({json:{user:{username:'admin',role:'admin'},permissions:['monitor','reveal','audit','users'],csrf:'test-token'}});
      if (url.pathname === '/api/users') {
        if (route.request().method() === 'POST') {
          assert.equal(route.request().headers()['x-csrf-token'], 'test-token');
          const body = route.request().postDataJSON();
          if (body.action === 'create') users.push({username:body.username,role:body.role,enabled:1,last_login:null});
          else {const user=users.find(u=>u.username===body.username); user.role=body.role; user.enabled=Number(body.enabled);}
          return route.fulfill({json:{ok:true}});
        }
        return route.fulfill({json:{users}});
      }
      if (url.pathname === '/api/password') {
        assert.equal(route.request().headers()['x-csrf-token'], 'test-token');
        assert.equal(route.request().postDataJSON().current_password, 'test-current-password');
        changedPassword = true;
        return route.fulfill({json:{ok:true}});
      }
      const filename = url.pathname === '/users' ? 'users.html' : url.pathname === '/account' ? 'account.html' : url.pathname === '/login' ? 'login.html' : url.pathname.slice(1);
      if (['users.html','account.html','login.html','rdmon.css','favicon.svg'].includes(filename)) return route.fulfill({body:fs.readFileSync(path.join(root,filename)),contentType:filename.endsWith('.html')?'text/html':filename.endsWith('.css')?'text/css':'image/svg+xml'});
      return route.fulfill({status:404,body:'Not found'});
    });
    await page.goto('http://localhost:9877/users');
    await page.waitForSelector('#users tr');
    await page.fill('#create-form input[name=username]', 'viewer-test');
    await page.fill('#create-form input[name=password]', 'test-new-password-123');
    await page.click('#create-form button');
    await page.waitForFunction(()=>document.querySelectorAll('#users tr').length===2);
    assert.equal(await page.locator('#create-form input[name=password]').inputValue(), '');
    await page.click('[data-edit="viewer-test"]');
    await page.selectOption('#edit-form select[name=role]', 'operator');
    await page.selectOption('#edit-form select[name=enabled]', 'false');
    await page.click('#edit-form button[type=submit]');
    await page.waitForFunction(()=>document.getElementById('edit-card').hidden);
    assert.equal(users[1].role, 'operator');
    assert.equal(users[1].enabled, 0);
    await page.goto('http://localhost:9877/account');
    await page.waitForFunction(()=>document.getElementById('identity').textContent==='admin');
    await page.fill('[name=current_password]', 'test-current-password');
    await page.fill('[name=password]', 'test-new-password-123');
    await page.fill('[name=confirm]', 'test-new-password-123');
    await page.click('#password-form button');
    await page.waitForURL('**/login?changed=1');
    assert(changedPassword);
    assert.deepEqual(errors, []);
    console.log('PASS: create/edit/disable accounts, password forms cleared, personal password change, CSRF headers, no browser errors');
  } finally { await browser.close(); }
})().catch(error=>{console.error(error);process.exit(1)});
