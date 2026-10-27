'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { URL } = require('node:url');

const { FinanceDatabase } = require('./db');
const {
  validatePasswordStrength,
  hashPassword,
  verifyPassword,
  generateToken,
  signSessionId,
  unsignSessionId,
  maskEmail,
  parseCookies,
  serializeSessionCookie,
  RateLimiter,
} = require('./security');

const PUBLIC_DIR = path.resolve(__dirname, '..', 'public');
const SESSION_COOKIE_NAME = '__Host-pfm_session';
const SESSION_DURATION_MS = 1000 * 60 * 60 * 8; // 8 hours session expiration

const ALLOWED_ACCOUNT_TYPES = new Set(['checking', 'savings', 'credit', 'cash', 'investment']);
const ALLOWED_TX_TYPES = new Set(['income', 'expense']);
const ALLOWED_CATEGORIES = new Set([
  'Salary',
  'Freelance',
  'Investments',
  'Other Income',
  'Housing',
  'Food & Dining',
  'Transportation',
  'Utilities',
  'Healthcare',
  'Entertainment',
  'Shopping',
  'Education',
  'Personal Care',
  'Other Expense',
]);
const ALLOWED_CURRENCIES = new Set(['USD', 'EUR', 'GBP', 'CAD', 'AUD', 'JPY']);
const ALLOWED_COLORS = new Set([
  '#2563eb',
  '#10b981',
  '#8b5cf6',
  '#f59e0b',
  '#ef4444',
  '#06b6d4',
  '#ec4899',
]);

function getCurrentYearMonth() {
  return new Date().toISOString().slice(0, 7);
}

function applySecurityHeaders(res, nonce = null, isApi = true) {
  const scriptSrc = nonce ? `'self' 'nonce-${nonce}'` : `'self'`;
  const csp = [
    "default-src 'self'",
    `script-src ${scriptSrc}`,
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ].join('; ');

  res.setHeader('Content-Security-Policy', csp);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');

  if (isApi) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  }
}

function sendJson(res, statusCode, payload) {
  applySecurityHeaders(res, null, true);
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function readJsonBody(req, maxBytes = 65536) {
  return new Promise((resolve, reject) => {
    let total = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        req.destroy();
        reject(new Error('Payload too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (chunks.length === 0) {
        resolve({});
        return;
      }
      try {
        const raw = Buffer.concat(chunks).toString('utf-8');
        const parsed = JSON.parse(raw);
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
          reject(new Error('Invalid JSON object'));
          return;
        }
        resolve(parsed);
      } catch {
        reject(new Error('Malformed JSON payload'));
      }
    });
    req.on('error', reject);
  });
}

function sanitizeText(input, maxLen = 120) {
  if (typeof input !== 'string') return '';
  return input.replace(/[\u0000-\u001F\u007F]/g, '').trim().slice(0, maxLen);
}

function isValidDateString(dateStr) {
  if (typeof dateStr !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
    return false;
  }
  const time = Date.parse(`${dateStr}T00:00:00Z`);
  return !Number.isNaN(time);
}

function isValidMonthString(monthStr) {
  return typeof monthStr === 'string' && /^\d{4}-\d{2}$/.test(monthStr);
}

function createApp(options = {}) {
  const db = new FinanceDatabase(options.dbPath);
  const rateLimiter = new RateLimiter(60_000, 180);
  const authRateLimiter = new RateLimiter(60_000, 25);

  function getAuthenticatedContext(req) {
    const cookies = parseCookies(req.headers.cookie);
    const rawCookie = cookies[SESSION_COOKIE_NAME];
    if (!rawCookie) return null;
    const sessionId = unsignSessionId(rawCookie);
    if (!sessionId) return null;
    const session = db.getSession(sessionId);
    if (!session) return null;
    const user = db.getUserById(session.user_id);
    if (!user) return null;
    return { user, session };
  }

  function verifyCsrf(req, session) {
    const tokenHeader = req.headers['x-csrf-token'];
    if (typeof tokenHeader !== 'string' || !session || !session.csrf_token) {
      return false;
    }
    const a = Buffer.from(tokenHeader, 'utf-8');
    const b = Buffer.from(session.csrf_token, 'utf-8');
    if (a.length !== b.length) return false;
    return require('node:crypto').timingSafeEqual(a, b);
  }

  function startUserSession(res, userId) {
    const sessionId = generateToken(32);
    const csrfToken = generateToken(24);
    const expiresAt = Date.now() + SESSION_DURATION_MS;
    db.createSession(sessionId, userId, csrfToken, expiresAt);
    const signed = signSessionId(sessionId);
    res.setHeader(
      'Set-Cookie',
      serializeSessionCookie(SESSION_COOKIE_NAME, signed, SESSION_DURATION_MS / 1000, true)
    );
    return csrfToken;
  }

  function clearUserSessionCookie(res) {
    res.setHeader('Set-Cookie', serializeSessionCookie(SESSION_COOKIE_NAME, '', 0, true));
  }

  function serveStaticFile(reqPath, res) {
    const requested = reqPath === '/' ? 'index.html' : path.basename(reqPath);
    const resolvedPath = path.resolve(PUBLIC_DIR, requested);
    if (!resolvedPath.startsWith(PUBLIC_DIR + path.sep)) {
      sendJson(res, 403, { error: 'Forbidden' });
      return;
    }
    if (!fs.existsSync(resolvedPath) || !fs.statSync(resolvedPath).isFile()) {
      sendJson(res, 404, { error: 'Not Found' });
      return;
    }

    const ext = path.extname(resolvedPath).toLowerCase();
    const mimeTypes = {
      '.html': 'text/html; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.js': 'application/javascript; charset=utf-8',
      '.svg': 'image/svg+xml',
      '.json': 'application/json; charset=utf-8',
    };
    const contentType = mimeTypes[ext] || 'application/octet-stream';
    const nonce = generateToken(16);
    applySecurityHeaders(res, nonce, false);

    let content = fs.readFileSync(resolvedPath);
    if (ext === '.html') {
      const htmlStr = content.toString('utf-8').replace(/__CSP_NONCE__/g, nonce);
      content = Buffer.from(htmlStr, 'utf-8');
    }

    res.writeHead(200, {
      'Content-Type': contentType,
      'Content-Length': content.length,
    });
    res.end(content);
  }

  const server = http.createServer(async (req, res) => {
    try {
      // Allow-list strictly GET and POST methods
      if (req.method !== 'GET' && req.method !== 'POST') {
        res.setHeader('Allow', 'GET, POST');
        return sendJson(res, 405, { error: 'Method Not Allowed' });
      }

      // Strict Origin / Host check on state-changing requests
      if (req.method === 'POST' && req.headers.origin) {
        const host = req.headers.host;
        try {
          const originUrl = new URL(req.headers.origin);
          if (host && originUrl.host !== host) {
            return sendJson(res, 403, { error: 'Cross-origin request forbidden' });
          }
        } catch {
          return sendJson(res, 403, { error: 'Invalid Origin header' });
        }
      }

      const clientIp = req.socket.remoteAddress || '127.0.0.1';
      const rateStatus = rateLimiter.check(clientIp);
      if (!rateStatus.allowed) {
        return sendJson(res, 429, { error: 'Too many requests. Please slow down.' });
      }

      const parsedUrl = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1'}`);
      const pathname = parsedUrl.pathname;

      // Serve frontend static files
      if (!pathname.startsWith('/api/')) {
        if (req.method !== 'GET') {
          return sendJson(res, 405, { error: 'Method Not Allowed' });
        }
        return serveStaticFile(pathname, res);
      }

      // --- PUBLIC AUTH ENDPOINTS ---
      if (pathname === '/api/auth/session' && req.method === 'GET') {
        const ctx = getAuthenticatedContext(req);
        if (!ctx) {
          return sendJson(res, 200, { authenticated: false });
        }
        return sendJson(res, 200, {
          authenticated: true,
          csrfToken: ctx.session.csrf_token,
          user: {
            id: ctx.user.id,
            name: ctx.user.name,
            maskedEmail: maskEmail(ctx.user.email),
            currency: ctx.user.currency,
          },
          categories: Array.from(ALLOWED_CATEGORIES),
        });
      }

      if (pathname === '/api/auth/register' && req.method === 'POST') {
        if (!authRateLimiter.check(clientIp).allowed) {
          return sendJson(res, 429, { error: 'Too many authentication attempts.' });
        }
        const body = await readJsonBody(req);
        const name = sanitizeText(body.name, 60);
        const email = sanitizeText(body.email, 120).toLowerCase();
        const password = typeof body.password === 'string' ? body.password : '';
        const currency = ALLOWED_CURRENCIES.has(body.currency) ? body.currency : 'USD';
        const seedDemo = Boolean(body.seedDemo);

        if (!name || name.length < 2) {
          return sendJson(res, 400, { error: 'Name must be at least 2 characters.' });
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return sendJson(res, 400, { error: 'Please provide a valid email address.' });
        }
        const pwCheck = validatePasswordStrength(password);
        if (!pwCheck.valid) {
          return sendJson(res, 400, { error: pwCheck.message });
        }
        if (db.getUserByEmail(email)) {
          return sendJson(res, 409, { error: 'An account with this email already exists.' });
        }

        const passwordHash = await hashPassword(password);
        const user = db.createUser(name, email, passwordHash, currency);
        if (seedDemo) {
          db.seedSampleDataForUser(user.id, getCurrentYearMonth());
        } else {
          db.createAccount(user.id, { name: 'Main Checking', type: 'checking', balance: 0, color: '#2563eb' });
        }

        const csrfToken = startUserSession(res, user.id);
        return sendJson(res, 201, {
          authenticated: true,
          csrfToken,
          user: {
            id: user.id,
            name: user.name,
            maskedEmail: maskEmail(user.email),
            currency: user.currency,
          },
          categories: Array.from(ALLOWED_CATEGORIES),
        });
      }

      if (pathname === '/api/auth/login' && req.method === 'POST') {
        if (!authRateLimiter.check(clientIp).allowed) {
          return sendJson(res, 429, { error: 'Too many login attempts.' });
        }
        const body = await readJsonBody(req);
        const email = sanitizeText(body.email, 120).toLowerCase();
        const password = typeof body.password === 'string' ? body.password : '';

        const userRecord = db.getUserByEmail(email);
        if (!userRecord) {
          return sendJson(res, 401, { error: 'Invalid email or password.' });
        }
        const matches = await verifyPassword(password, userRecord.password_hash);
        if (!matches) {
          return sendJson(res, 401, { error: 'Invalid email or password.' });
        }

        const csrfToken = startUserSession(res, userRecord.id);
        return sendJson(res, 200, {
          authenticated: true,
          csrfToken,
          user: {
            id: userRecord.id,
            name: userRecord.name,
            maskedEmail: maskEmail(userRecord.email),
            currency: userRecord.currency,
          },
          categories: Array.from(ALLOWED_CATEGORIES),
        });
      }

      if (pathname === '/api/auth/demo' && req.method === 'POST') {
        if (!authRateLimiter.check(clientIp).allowed) {
          return sendJson(res, 429, { error: 'Too many demo session requests.' });
        }
        const demoEmail = 'alex.demo@personal.finance';
        let user = db.getUserByEmail(demoEmail);
        if (!user) {
          const randomSecretPw = generateToken(16);
          const pwHash = await hashPassword(randomSecretPw);
          user = db.createUser('Alex Morgan', demoEmail, pwHash, 'USD');
          db.seedSampleDataForUser(user.id, getCurrentYearMonth());
        }
        const csrfToken = startUserSession(res, user.id);
        return sendJson(res, 200, {
          authenticated: true,
          csrfToken,
          user: {
            id: user.id,
            name: user.name,
            maskedEmail: maskEmail(user.email),
            currency: user.currency,
          },
          categories: Array.from(ALLOWED_CATEGORIES),
        });
      }

      // --- AUTHENTICATED ENDPOINTS ---
      const ctx = getAuthenticatedContext(req);
      if (!ctx) {
        return sendJson(res, 401, { error: 'Authentication required.' });
      }

      // Require CSRF token validation on all authenticated POST endpoints
      if (req.method === 'POST' && !verifyCsrf(req, ctx.session)) {
        return sendJson(res, 403, { error: 'Invalid or missing CSRF token.' });
      }

      if (pathname === '/api/auth/logout' && req.method === 'POST') {
        db.deleteAllUserSessions(ctx.user.id);
        clearUserSessionCookie(res);
        return sendJson(res, 200, { ok: true });
      }

      // --- DASHBOARD SUMMARY ---
      if (pathname === '/api/dashboard' && req.method === 'GET') {
        const monthParam = parsedUrl.searchParams.get('month');
        const month = isValidMonthString(monthParam) ? monthParam : getCurrentYearMonth();
        const summary = db.getDashboardSummary(ctx.user.id, month);
        return sendJson(res, 200, summary);
      }

      // --- ACCOUNTS ---
      if (pathname === '/api/accounts' && req.method === 'GET') {
        return sendJson(res, 200, { accounts: db.getAccounts(ctx.user.id) });
      }

      if (pathname === '/api/accounts/create' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const name = sanitizeText(body.name, 50);
        const type = typeof body.type === 'string' ? body.type.trim() : '';
        const balance = Number(body.balance ?? 0);
        const color = ALLOWED_COLORS.has(body.color) ? body.color : '#2563eb';

        if (!name) {
          return sendJson(res, 400, { error: 'Account name is required.' });
        }
        if (!ALLOWED_ACCOUNT_TYPES.has(type)) {
          return sendJson(res, 400, { error: 'Invalid account type.' });
        }
        if (!Number.isFinite(balance) || Math.abs(balance) > 100_000_000) {
          return sendJson(res, 400, { error: 'Invalid starting balance.' });
        }

        const account = db.createAccount(ctx.user.id, { name, type, balance, color });
        return sendJson(res, 201, { account });
      }

      if (pathname === '/api/accounts/delete' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const accountId = Number(body.id);
        if (!Number.isInteger(accountId) || accountId <= 0) {
          return sendJson(res, 400, { error: 'Invalid account ID.' });
        }
        const accounts = db.getAccounts(ctx.user.id);
        if (accounts.length <= 1) {
          return sendJson(res, 400, { error: 'You must keep at least one active account.' });
        }
        const deleted = db.deleteAccount(ctx.user.id, accountId);
        if (!deleted) {
          return sendJson(res, 404, { error: 'Account not found.' });
        }
        return sendJson(res, 200, { ok: true });
      }

      // --- TRANSACTIONS ---
      if (pathname === '/api/transactions' && req.method === 'GET') {
        const filters = {
          month: parsedUrl.searchParams.get('month') || '',
          type: parsedUrl.searchParams.get('type') || '',
          category: parsedUrl.searchParams.get('category') || '',
          accountId: parsedUrl.searchParams.get('accountId') || '',
          search: parsedUrl.searchParams.get('search') || '',
        };
        const transactions = db.getTransactions(ctx.user.id, filters);
        return sendJson(res, 200, { transactions });
      }

      if (pathname === '/api/transactions/create' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const accountId = Number(body.accountId);
        const type = typeof body.type === 'string' ? body.type.trim() : '';
        const category = sanitizeText(body.category, 40);
        const amount = Number(body.amount);
        const date = typeof body.date === 'string' ? body.date.trim() : '';
        const description = sanitizeText(body.description, 140);
        const isRecurring = Boolean(body.isRecurring);

        if (!Number.isInteger(accountId) || accountId <= 0) {
          return sendJson(res, 400, { error: 'Please select a valid account.' });
        }
        if (!ALLOWED_TX_TYPES.has(type)) {
          return sendJson(res, 400, { error: 'Transaction type must be income or expense.' });
        }
        if (!ALLOWED_CATEGORIES.has(category)) {
          return sendJson(res, 400, { error: 'Please select a valid category from the allow-list.' });
        }
        if (!Number.isFinite(amount) || amount <= 0 || amount > 10_000_000) {
          return sendJson(res, 400, { error: 'Amount must be a positive number.' });
        }
        if (!isValidDateString(date)) {
          return sendJson(res, 400, { error: 'Date must be in YYYY-MM-DD format.' });
        }

        const transaction = db.createTransaction(ctx.user.id, {
          accountId,
          type,
          category,
          amount: Math.round(amount * 100) / 100,
          date,
          description,
          isRecurring,
        });
        return sendJson(res, 201, { transaction });
      }

      if (pathname === '/api/transactions/delete' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const txId = Number(body.id);
        if (!Number.isInteger(txId) || txId <= 0) {
          return sendJson(res, 400, { error: 'Invalid transaction ID.' });
        }
        const deleted = db.deleteTransaction(ctx.user.id, txId);
        if (!deleted) {
          return sendJson(res, 404, { error: 'Transaction not found.' });
        }
        return sendJson(res, 200, { ok: true });
      }

      // --- CSV EXPORT ---
      if (pathname === '/api/transactions/export' && req.method === 'GET') {
        const month = parsedUrl.searchParams.get('month') || '';
        const transactions = db.getTransactions(ctx.user.id, { month });
        const escapeCsvCell = (val) => {
          const str = String(val ?? '');
          // Mitigate CSV formula injection
          const safeStr = /^[=+\-@\t\r]/.test(str) ? `'${str}` : str;
          return `"${safeStr.replace(/"/g, '""')}"`;
        };
        const header = ['Date', 'Type', 'Category', 'Account', 'Amount', 'Recurring', 'Description'];
        const rows = transactions.map((t) =>
          [
            escapeCsvCell(t.date),
            escapeCsvCell(t.type),
            escapeCsvCell(t.category),
            escapeCsvCell(t.account_name),
            escapeCsvCell(Number(t.amount).toFixed(2)),
            escapeCsvCell(t.is_recurring ? 'Yes' : 'No'),
            escapeCsvCell(t.description),
          ].join(',')
        );
        const csvContent = [header.join(','), ...rows].join('\r\n');
        applySecurityHeaders(res, null, true);
        res.writeHead(200, {
          'Content-Type': 'text/csv; charset=utf-8',
          'Content-Disposition': 'attachment; filename="transactions-export.csv"',
          'Content-Length': Buffer.byteLength(csvContent),
        });
        res.end(csvContent);
        return;
      }

      // --- BUDGETS ---
      if (pathname === '/api/budgets/upsert' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const category = sanitizeText(body.category, 40);
        const monthlyLimit = Number(body.monthlyLimit);
        const month = isValidMonthString(body.month) ? body.month : getCurrentYearMonth();

        if (!ALLOWED_CATEGORIES.has(category)) {
          return sendJson(res, 400, { error: 'Please choose a valid budget category.' });
        }
        if (!Number.isFinite(monthlyLimit) || monthlyLimit <= 0 || monthlyLimit > 10_000_000) {
          return sendJson(res, 400, { error: 'Monthly limit must be greater than zero.' });
        }

        const budgets = db.upsertBudget(ctx.user.id, {
          category,
          monthlyLimit: Math.round(monthlyLimit * 100) / 100,
          month,
        });
        return sendJson(res, 200, { budgets });
      }

      if (pathname === '/api/budgets/delete' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const budgetId = Number(body.id);
        if (!Number.isInteger(budgetId) || budgetId <= 0) {
          return sendJson(res, 400, { error: 'Invalid budget ID.' });
        }
        const deleted = db.deleteBudget(ctx.user.id, budgetId);
        if (!deleted) {
          return sendJson(res, 404, { error: 'Budget not found.' });
        }
        return sendJson(res, 200, { ok: true });
      }

      // --- SAVINGS GOALS ---
      if (pathname === '/api/goals/create' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const name = sanitizeText(body.name, 60);
        const targetAmount = Number(body.targetAmount);
        const currentAmount = Number(body.currentAmount ?? 0);
        const targetDate = body.targetDate && isValidDateString(body.targetDate) ? body.targetDate : '';
        const color = ALLOWED_COLORS.has(body.color) ? body.color : '#10b981';

        if (!name) {
          return sendJson(res, 400, { error: 'Goal name is required.' });
        }
        if (!Number.isFinite(targetAmount) || targetAmount <= 0 || targetAmount > 100_000_000) {
          return sendJson(res, 400, { error: 'Target amount must be greater than zero.' });
        }
        if (!Number.isFinite(currentAmount) || currentAmount < 0 || currentAmount > 100_000_000) {
          return sendJson(res, 400, { error: 'Current saved amount cannot be negative.' });
        }

        const goal = db.createSavingsGoal(ctx.user.id, {
          name,
          targetAmount: Math.round(targetAmount * 100) / 100,
          currentAmount: Math.round(currentAmount * 100) / 100,
          targetDate,
          color,
        });
        return sendJson(res, 201, { goal });
      }

      if (pathname === '/api/goals/contribute' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const goalId = Number(body.id);
        const amount = Number(body.amount);
        if (!Number.isInteger(goalId) || goalId <= 0) {
          return sendJson(res, 400, { error: 'Invalid goal ID.' });
        }
        if (!Number.isFinite(amount) || amount === 0 || Math.abs(amount) > 10_000_000) {
          return sendJson(res, 400, { error: 'Contribution amount must be non-zero.' });
        }
        const updatedGoal = db.contributeSavingsGoal(ctx.user.id, goalId, amount);
        if (!updatedGoal) {
          return sendJson(res, 404, { error: 'Savings goal not found.' });
        }
        return sendJson(res, 200, { goal: updatedGoal });
      }

      if (pathname === '/api/goals/delete' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const goalId = Number(body.id);
        if (!Number.isInteger(goalId) || goalId <= 0) {
          return sendJson(res, 400, { error: 'Invalid goal ID.' });
        }
        const deleted = db.deleteSavingsGoal(ctx.user.id, goalId);
        if (!deleted) {
          return sendJson(res, 404, { error: 'Savings goal not found.' });
        }
        return sendJson(res, 200, { ok: true });
      }

      return sendJson(res, 404, { error: 'Endpoint not found.' });
    } catch (err) {
      // Never leak SQL or internal stack traces to clients
      if (err && err.message === 'Payload too large') {
        return sendJson(res, 413, { error: 'Request payload is too large.' });
      }
      if (err && (err.message === 'Malformed JSON payload' || err.message === 'Invalid JSON object')) {
        return sendJson(res, 400, { error: err.message });
      }
      if (err && err.message === 'Account not found or access denied.') {
        return sendJson(res, 404, { error: err.message });
      }
      console.error('Internal Server Error occurred while handling request.');
      return sendJson(res, 500, { error: 'An unexpected error occurred. Please try again.' });
    }
  });

  return { server, db };
}

if (require.main === module) {
  const PORT = Number(process.env.PORT) || 3000;
  const HOST = '127.0.0.1'; // Bind strictly to localhost / 127.0.0.1
  const { server } = createApp();
  server.listen(PORT, HOST, () => {
    console.log(`Personal Finance Manager listening on http://${HOST}:${PORT}`);
  });
}

module.exports = { createApp };
