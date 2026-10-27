'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { createApp } = require('../src/server');

let server;
let baseUrl;
let sessionCookie = '';
let csrfToken = '';

before(async () => {
  const app = createApp({ dbPath: ':memory:' });
  server = app.server;
  await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
});

after(async () => {
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('1. Serves index.html with strict CSP and security headers', async () => {
  const res = await fetch(`${baseUrl}/`);
  assert.equal(res.status, 200);
  const csp = res.headers.get('content-security-policy');
  assert.ok(csp && csp.includes("default-src 'self'"));
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
  const html = await res.text();
  assert.ok(html.includes('PulseFinance'));
  assert.ok(!html.includes('__CSP_NONCE__'));
});

test('2. Rejects disallowed HTTP methods like DELETE or PUT with 405', async () => {
  const res = await fetch(`${baseUrl}/api/accounts`, { method: 'DELETE' });
  assert.equal(res.status, 405);
});

test('3. Registers a new individual user, sets hardened cookie, and masks email PII', async () => {
  const res = await fetch(`${baseUrl}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: 'Jane Doe',
      email: 'jane.doe@example.com',
      password: 'StrongPassword!2026',
      currency: 'USD',
      seedDemo: false,
    }),
  });
  assert.equal(res.status, 201);
  const setCookie = res.headers.get('set-cookie');
  assert.ok(setCookie && setCookie.includes('__Host-pfm_session='));
  assert.ok(setCookie.includes('HttpOnly'));
  assert.ok(setCookie.includes('SameSite=Lax'));
  sessionCookie = setCookie.split(';')[0];

  const body = await res.json();
  assert.equal(body.authenticated, true);
  assert.ok(body.csrfToken);
  csrfToken = body.csrfToken;
  assert.equal(body.user.maskedEmail, 'ja***@example.com');
});

test('4. Enforces CSRF token on state-changing POST requests', async () => {
  const resWithoutCsrf = await fetch(`${baseUrl}/api/accounts/create`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: sessionCookie,
    },
    body: JSON.stringify({ name: 'Savings Account', type: 'savings', balance: 1500 }),
  });
  assert.equal(resWithoutCsrf.status, 403);

  const resWithCsrf = await fetch(`${baseUrl}/api/accounts/create`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: sessionCookie,
      'X-CSRF-Token': csrfToken,
    },
    body: JSON.stringify({ name: 'Savings Account', type: 'savings', balance: 1500, color: '#10b981' }),
  });
  assert.equal(resWithCsrf.status, 201);
  const data = await resWithCsrf.json();
  assert.equal(data.account.name, 'Savings Account');
  assert.equal(data.account.balance, 1500);
});

test('5. Records income & expense transactions and updates account balances & budgets', async () => {
  const acctRes = await fetch(`${baseUrl}/api/accounts`, {
    headers: { Cookie: sessionCookie },
  });
  const { accounts } = await acctRes.json();
  const primaryAccount = accounts[0];

  const currentMonth = new Date().toISOString().slice(0, 7);

  // Create an income transaction
  const incRes = await fetch(`${baseUrl}/api/transactions/create`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: sessionCookie,
      'X-CSRF-Token': csrfToken,
    },
    body: JSON.stringify({
      accountId: primaryAccount.id,
      type: 'income',
      category: 'Salary',
      amount: 4000,
      date: `${currentMonth}-01`,
      description: 'Monthly Salary',
      isRecurring: true,
    }),
  });
  assert.equal(incRes.status, 201);

  // Create an expense transaction
  const expRes = await fetch(`${baseUrl}/api/transactions/create`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: sessionCookie,
      'X-CSRF-Token': csrfToken,
    },
    body: JSON.stringify({
      accountId: primaryAccount.id,
      type: 'expense',
      category: 'Food & Dining',
      amount: 250.75,
      date: `${currentMonth}-05`,
      description: 'Supermarket Groceries',
      isRecurring: false,
    }),
  });
  assert.equal(expRes.status, 201);

  // Upsert a monthly budget for Food & Dining
  const budgetRes = await fetch(`${baseUrl}/api/budgets/upsert`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: sessionCookie,
      'X-CSRF-Token': csrfToken,
    },
    body: JSON.stringify({
      category: 'Food & Dining',
      monthlyLimit: 500,
      month: currentMonth,
    }),
  });
  assert.equal(budgetRes.status, 200);

  // Check dashboard summary calculations
  const dashRes = await fetch(`${baseUrl}/api/dashboard?month=${currentMonth}`, {
    headers: { Cookie: sessionCookie },
  });
  assert.equal(dashRes.status, 200);
  const summary = await dashRes.json();
  assert.equal(summary.monthlyIncome, 4000);
  assert.equal(summary.monthlyExpense, 250.75);
  assert.equal(summary.monthlyNet, 3749.25);
  assert.equal(summary.netWorth, 1500 + 3749.25);
  assert.equal(summary.budgets[0].spent, 250.75);
});

test('6. Creates and updates savings goals and exports CSV safely', async () => {
  const goalRes = await fetch(`${baseUrl}/api/goals/create`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: sessionCookie,
      'X-CSRF-Token': csrfToken,
    },
    body: JSON.stringify({
      name: 'Emergency Fund',
      targetAmount: 10000,
      currentAmount: 2000,
      targetDate: '2027-01-01',
      color: '#10b981',
    }),
  });
  assert.equal(goalRes.status, 201);
  const { goal } = await goalRes.json();

  const contribRes = await fetch(`${baseUrl}/api/goals/contribute`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: sessionCookie,
      'X-CSRF-Token': csrfToken,
    },
    body: JSON.stringify({ id: goal.id, amount: 500 }),
  });
  assert.equal(contribRes.status, 200);
  const updated = await contribRes.json();
  assert.equal(updated.goal.current_amount, 2500);

  const csvRes = await fetch(`${baseUrl}/api/transactions/export`, {
    headers: { Cookie: sessionCookie },
  });
  assert.equal(csvRes.status, 200);
  assert.ok(csvRes.headers.get('content-disposition').includes('attachment'));
  const csvText = await csvRes.text();
  assert.ok(csvText.includes('Supermarket Groceries'));
});
