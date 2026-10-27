'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

// TODO(security): SQLite is an embedded local database file, so network mTLS is not applicable;
// ensure host filesystem permissions restrict access to the database file (0600).

const DEFAULT_DB_PATH = path.resolve(__dirname, '..', 'data', 'finance.db');

class FinanceDatabase {
  constructor(dbPath = DEFAULT_DB_PATH) {
    if (dbPath !== ':memory:') {
      const dir = path.dirname(dbPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      }
    }
    this.db = new DatabaseSync(dbPath);
    this.init();
  }

  init() {
    this.db.exec('PRAGMA foreign_keys = ON;');
    this.db.exec('PRAGMA journal_mode = WAL;');

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        currency TEXT NOT NULL DEFAULT 'USD',
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        csrf_token TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        type TEXT NOT NULL CHECK (type IN ('checking', 'savings', 'credit', 'cash', 'investment')),
        balance REAL NOT NULL DEFAULT 0,
        color TEXT NOT NULL DEFAULT '#2563eb',
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        account_id INTEGER NOT NULL,
        type TEXT NOT NULL CHECK (type IN ('income', 'expense')),
        category TEXT NOT NULL,
        amount REAL NOT NULL CHECK (amount > 0),
        date TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        is_recurring INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS budgets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        category TEXT NOT NULL,
        monthly_limit REAL NOT NULL CHECK (monthly_limit > 0),
        month TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE(user_id, category, month),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS savings_goals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        target_amount REAL NOT NULL CHECK (target_amount > 0),
        current_amount REAL NOT NULL DEFAULT 0 CHECK (current_amount >= 0),
        target_date TEXT NOT NULL DEFAULT '',
        color TEXT NOT NULL DEFAULT '#10b981',
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
    `);
  }

  // --- Users ---
  createUser(name, email, passwordHash, currency = 'USD') {
    const stmt = this.db.prepare(
      'INSERT INTO users (name, email, password_hash, currency) VALUES (?, ?, ?, ?)'
    );
    const result = stmt.run(name, email.toLowerCase().trim(), passwordHash, currency);
    return this.getUserById(Number(result.lastInsertRowid));
  }

  getUserByEmail(email) {
    const stmt = this.db.prepare(
      'SELECT id, name, email, password_hash, currency, created_at FROM users WHERE email = ?'
    );
    return stmt.get(email.toLowerCase().trim()) || null;
  }

  getUserById(id) {
    const stmt = this.db.prepare(
      'SELECT id, name, email, currency, created_at FROM users WHERE id = ?'
    );
    return stmt.get(id) || null;
  }

  // --- Sessions ---
  createSession(sessionId, userId, csrfToken, expiresAtMs) {
    const stmt = this.db.prepare(
      'INSERT INTO sessions (id, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)'
    );
    stmt.run(sessionId, userId, csrfToken, expiresAtMs);
  }

  getSession(sessionId) {
    const stmt = this.db.prepare(
      'SELECT id, user_id, csrf_token, expires_at FROM sessions WHERE id = ?'
    );
    const session = stmt.get(sessionId);
    if (!session) return null;
    if (Date.now() > session.expires_at) {
      this.deleteSession(sessionId);
      return null;
    }
    return session;
  }

  deleteSession(sessionId) {
    const stmt = this.db.prepare('DELETE FROM sessions WHERE id = ?');
    stmt.run(sessionId);
  }

  deleteAllUserSessions(userId) {
    const stmt = this.db.prepare('DELETE FROM sessions WHERE user_id = ?');
    stmt.run(userId);
  }

  // --- Accounts ---
  getAccounts(userId) {
    const stmt = this.db.prepare(
      'SELECT id, name, type, balance, color, created_at FROM accounts WHERE user_id = ? ORDER BY id ASC'
    );
    return stmt.all(userId);
  }

  getAccountById(userId, accountId) {
    const stmt = this.db.prepare(
      'SELECT id, user_id, name, type, balance, color, created_at FROM accounts WHERE id = ? AND user_id = ?'
    );
    return stmt.get(accountId, userId) || null;
  }

  createAccount(userId, { name, type, balance = 0, color = '#2563eb' }) {
    const stmt = this.db.prepare(
      'INSERT INTO accounts (user_id, name, type, balance, color) VALUES (?, ?, ?, ?, ?)'
    );
    const res = stmt.run(userId, name, type, Number(balance), color);
    return this.getAccountById(userId, Number(res.lastInsertRowid));
  }

  deleteAccount(userId, accountId) {
    const stmt = this.db.prepare('DELETE FROM accounts WHERE id = ? AND user_id = ?');
    const res = stmt.run(accountId, userId);
    return res.changes > 0;
  }

  // --- Transactions ---
  getTransactions(userId, filters = {}) {
    let sql = `
      SELECT t.id, t.account_id, a.name AS account_name, t.type, t.category,
             t.amount, t.date, t.description, t.is_recurring, t.created_at
      FROM transactions t
      JOIN accounts a ON a.id = t.account_id AND a.user_id = t.user_id
      WHERE t.user_id = ?
    `;
    const params = [userId];

    if (filters.month && /^\d{4}-\d{2}$/.test(filters.month)) {
      sql += ' AND substr(t.date, 1, 7) = ?';
      params.push(filters.month);
    }
    if (filters.type && (filters.type === 'income' || filters.type === 'expense')) {
      sql += ' AND t.type = ?';
      params.push(filters.type);
    }
    if (filters.category && typeof filters.category === 'string' && filters.category !== 'all') {
      sql += ' AND t.category = ?';
      params.push(filters.category);
    }
    if (filters.accountId && Number.isInteger(Number(filters.accountId))) {
      sql += ' AND t.account_id = ?';
      params.push(Number(filters.accountId));
    }
    if (filters.search && typeof filters.search === 'string' && filters.search.trim() !== '') {
      sql += ' AND (LOWER(t.description) LIKE ? OR LOWER(t.category) LIKE ?)';
      const term = `%${filters.search.trim().toLowerCase()}%`;
      params.push(term, term);
    }

    sql += ' ORDER BY t.date DESC, t.id DESC LIMIT 500';
    const stmt = this.db.prepare(sql);
    return stmt.all(...params);
  }

  createTransaction(userId, { accountId, type, category, amount, date, description = '', isRecurring = false }) {
    const account = this.getAccountById(userId, Number(accountId));
    if (!account) {
      throw new Error('Account not found or access denied.');
    }
    const numericAmount = Number(amount);
    const delta = type === 'income' ? numericAmount : -numericAmount;

    this.db.exec('BEGIN');
    try {
      const insertStmt = this.db.prepare(`
        INSERT INTO transactions (user_id, account_id, type, category, amount, date, description, is_recurring)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      const res = insertStmt.run(
        userId,
        account.id,
        type,
        category,
        numericAmount,
        date,
        description,
        isRecurring ? 1 : 0
      );

      const updateAcct = this.db.prepare(
        'UPDATE accounts SET balance = ROUND(balance + ?, 2) WHERE id = ? AND user_id = ?'
      );
      updateAcct.run(delta, account.id, userId);
      this.db.exec('COMMIT');

      const getStmt = this.db.prepare(`
        SELECT t.id, t.account_id, a.name AS account_name, t.type, t.category,
               t.amount, t.date, t.description, t.is_recurring, t.created_at
        FROM transactions t
        JOIN accounts a ON a.id = t.account_id
        WHERE t.id = ? AND t.user_id = ?
      `);
      return getStmt.get(Number(res.lastInsertRowid), userId);
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  deleteTransaction(userId, transactionId) {
    const findStmt = this.db.prepare(
      'SELECT id, account_id, type, amount FROM transactions WHERE id = ? AND user_id = ?'
    );
    const tx = findStmt.get(Number(transactionId), userId);
    if (!tx) return false;

    const reverseDelta = tx.type === 'income' ? -Number(tx.amount) : Number(tx.amount);
    this.db.exec('BEGIN');
    try {
      const delStmt = this.db.prepare('DELETE FROM transactions WHERE id = ? AND user_id = ?');
      delStmt.run(tx.id, userId);

      const updateAcct = this.db.prepare(
        'UPDATE accounts SET balance = ROUND(balance + ?, 2) WHERE id = ? AND user_id = ?'
      );
      updateAcct.run(reverseDelta, tx.account_id, userId);
      this.db.exec('COMMIT');
      return true;
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  // --- Budgets ---
  getBudgetsWithSpending(userId, month) {
    const stmt = this.db.prepare(`
      SELECT b.id, b.category, b.monthly_limit, b.month,
             COALESCE((
               SELECT ROUND(SUM(t.amount), 2)
               FROM transactions t
               WHERE t.user_id = b.user_id
                 AND t.type = 'expense'
                 AND t.category = b.category
                 AND substr(t.date, 1, 7) = b.month
             ), 0) AS spent
      FROM budgets b
      WHERE b.user_id = ? AND b.month = ?
      ORDER BY b.category ASC
    `);
    return stmt.all(userId, month);
  }

  upsertBudget(userId, { category, monthlyLimit, month }) {
    const stmt = this.db.prepare(`
      INSERT INTO budgets (user_id, category, monthly_limit, month)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(user_id, category, month)
      DO UPDATE SET monthly_limit = excluded.monthly_limit
    `);
    stmt.run(userId, category, Number(monthlyLimit), month);
    return this.getBudgetsWithSpending(userId, month);
  }

  deleteBudget(userId, budgetId) {
    const stmt = this.db.prepare('DELETE FROM budgets WHERE id = ? AND user_id = ?');
    return stmt.run(Number(budgetId), userId).changes > 0;
  }

  // --- Savings Goals ---
  getSavingsGoals(userId) {
    const stmt = this.db.prepare(`
      SELECT id, name, target_amount, current_amount, target_date, color, created_at
      FROM savings_goals
      WHERE user_id = ?
      ORDER BY id ASC
    `);
    return stmt.all(userId);
  }

  createSavingsGoal(userId, { name, targetAmount, currentAmount = 0, targetDate = '', color = '#10b981' }) {
    const stmt = this.db.prepare(`
      INSERT INTO savings_goals (user_id, name, target_amount, current_amount, target_date, color)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const res = stmt.run(userId, name, Number(targetAmount), Number(currentAmount), targetDate, color);
    const getStmt = this.db.prepare(
      'SELECT id, name, target_amount, current_amount, target_date, color, created_at FROM savings_goals WHERE id = ? AND user_id = ?'
    );
    return getStmt.get(Number(res.lastInsertRowid), userId);
  }

  contributeSavingsGoal(userId, goalId, deltaAmount) {
    const findStmt = this.db.prepare(
      'SELECT id, current_amount, target_amount FROM savings_goals WHERE id = ? AND user_id = ?'
    );
    const goal = findStmt.get(Number(goalId), userId);
    if (!goal) return null;

    const nextAmount = Math.max(0, Math.round((Number(goal.current_amount) + Number(deltaAmount)) * 100) / 100);
    const updateStmt = this.db.prepare(
      'UPDATE savings_goals SET current_amount = ? WHERE id = ? AND user_id = ?'
    );
    updateStmt.run(nextAmount, goal.id, userId);

    const getStmt = this.db.prepare(
      'SELECT id, name, target_amount, current_amount, target_date, color, created_at FROM savings_goals WHERE id = ? AND user_id = ?'
    );
    return getStmt.get(goal.id, userId);
  }

  deleteSavingsGoal(userId, goalId) {
    const stmt = this.db.prepare('DELETE FROM savings_goals WHERE id = ? AND user_id = ?');
    return stmt.run(Number(goalId), userId).changes > 0;
  }

  // --- Analytics / Dashboard Summary ---
  getDashboardSummary(userId, month) {
    const accounts = this.getAccounts(userId);
    const netWorth = accounts.reduce((acc, a) => acc + Number(a.balance), 0);

    const totalsStmt = this.db.prepare(`
      SELECT
        COALESCE(SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END), 0) AS monthly_income,
        COALESCE(SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END), 0) AS monthly_expense
      FROM transactions
      WHERE user_id = ? AND substr(date, 1, 7) = ?
    `);
    const totals = totalsStmt.get(userId, month) || { monthly_income: 0, monthly_expense: 0 };

    const categoryStmt = this.db.prepare(`
      SELECT category, ROUND(SUM(amount), 2) AS total
      FROM transactions
      WHERE user_id = ? AND type = 'expense' AND substr(date, 1, 7) = ?
      GROUP BY category
      ORDER BY total DESC
    `);
    const expenseByCategory = categoryStmt.all(userId, month);

    const trendStmt = this.db.prepare(`
      SELECT substr(date, 1, 7) AS month,
             ROUND(SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END), 2) AS income,
             ROUND(SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END), 2) AS expense
      FROM transactions
      WHERE user_id = ?
      GROUP BY substr(date, 1, 7)
      ORDER BY month DESC
      LIMIT 6
    `);
    const monthlyTrend = trendStmt.all(userId).reverse();

    const budgets = this.getBudgetsWithSpending(userId, month);
    const goals = this.getSavingsGoals(userId);

    const income = Number(totals.monthly_income || 0);
    const expense = Number(totals.monthly_expense || 0);
    const savingsRate = income > 0 ? Math.round(((income - expense) / income) * 1000) / 10 : 0;

    return {
      month,
      netWorth: Math.round(netWorth * 100) / 100,
      monthlyIncome: Math.round(income * 100) / 100,
      monthlyExpense: Math.round(expense * 100) / 100,
      monthlyNet: Math.round((income - expense) * 100) / 100,
      savingsRate,
      accounts,
      expenseByCategory,
      monthlyTrend,
      budgets,
      goals,
    };
  }

  /**
   * Seed realistic sample personal finance data for a newly created demo or user account.
   */
  seedSampleDataForUser(userId, currentMonth) {
    const checking = this.createAccount(userId, {
      name: 'Main Checking',
      type: 'checking',
      balance: 4250.0,
      color: '#2563eb',
    });
    const savings = this.createAccount(userId, {
      name: 'High-Yield Savings',
      type: 'savings',
      balance: 14800.0,
      color: '#10b981',
    });
    const credit = this.createAccount(userId, {
      name: 'Rewards Credit Card',
      type: 'credit',
      balance: -640.5,
      color: '#8b5cf6',
    });

    // Compute previous 2 months for trend chart
    const [yearStr, monthStr] = currentMonth.split('-');
    const year = Number(yearStr);
    const monthNum = Number(monthStr);
    const prevMonthDate = new Date(Date.UTC(year, monthNum - 2, 15));
    const prev2MonthDate = new Date(Date.UTC(year, monthNum - 3, 15));
    const m1 = prev2MonthDate.toISOString().slice(0, 7);
    const m2 = prevMonthDate.toISOString().slice(0, 7);

    const sampleTxs = [
      { accountId: checking.id, type: 'income', category: 'Salary', amount: 5200, date: `${m1}-01`, description: 'Monthly Payroll Deposit', isRecurring: true },
      { accountId: checking.id, type: 'expense', category: 'Housing', amount: 1650, date: `${m1}-02`, description: 'Apartment Rent', isRecurring: true },
      { accountId: credit.id, type: 'expense', category: 'Food & Dining', amount: 490, date: `${m1}-12`, description: 'Groceries & Supermarket', isRecurring: false },
      { accountId: checking.id, type: 'expense', category: 'Utilities', amount: 185, date: `${m1}-18`, description: 'Electricity & Fiber Internet', isRecurring: true },

      { accountId: checking.id, type: 'income', category: 'Salary', amount: 5200, date: `${m2}-01`, description: 'Monthly Payroll Deposit', isRecurring: true },
      { accountId: savings.id, type: 'income', category: 'Freelance', amount: 650, date: `${m2}-10`, description: 'UI Design Consultation', isRecurring: false },
      { accountId: checking.id, type: 'expense', category: 'Housing', amount: 1650, date: `${m2}-02`, description: 'Apartment Rent', isRecurring: true },
      { accountId: credit.id, type: 'expense', category: 'Food & Dining', amount: 540, date: `${m2}-14`, description: 'Groceries & Restaurants', isRecurring: false },
      { accountId: credit.id, type: 'expense', category: 'Transportation', amount: 210, date: `${m2}-19`, description: 'Transit Pass & Fuel', isRecurring: false },

      { accountId: checking.id, type: 'income', category: 'Salary', amount: 5200, date: `${currentMonth}-01`, description: 'Monthly Payroll Deposit', isRecurring: true },
      { accountId: savings.id, type: 'income', category: 'Investments', amount: 310, date: `${currentMonth}-05`, description: 'Index Fund Dividend & Interest', isRecurring: false },
      { accountId: checking.id, type: 'expense', category: 'Housing', amount: 1650, date: `${currentMonth}-02`, description: 'Apartment Rent', isRecurring: true },
      { accountId: credit.id, type: 'expense', category: 'Food & Dining', amount: 425.5, date: `${currentMonth}-07`, description: 'Weekly Groceries & Coffee', isRecurring: false },
      { accountId: checking.id, type: 'expense', category: 'Utilities', amount: 192.0, date: `${currentMonth}-09`, description: 'Power, Water & Fiber Internet', isRecurring: true },
      { accountId: credit.id, type: 'expense', category: 'Transportation', amount: 145.0, date: `${currentMonth}-11`, description: 'Metro Pass & Fuel', isRecurring: false },
      { accountId: credit.id, type: 'expense', category: 'Entertainment', amount: 89.99, date: `${currentMonth}-14`, description: 'Streaming & Concert Ticket', isRecurring: false },
      { accountId: checking.id, type: 'expense', category: 'Healthcare', amount: 120.0, date: `${currentMonth}-15`, description: 'Dental Checkup & Pharmacy', isRecurring: false },
    ];

    // Insert transactions without re-adjusting initial balances so seeded balances remain exact
    const insertTxStmt = this.db.prepare(`
      INSERT INTO transactions (user_id, account_id, type, category, amount, date, description, is_recurring)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const tx of sampleTxs) {
      insertTxStmt.run(
        userId,
        tx.accountId,
        tx.type,
        tx.category,
        tx.amount,
        tx.date,
        tx.description,
        tx.isRecurring ? 1 : 0
      );
    }

    this.upsertBudget(userId, { category: 'Housing', monthlyLimit: 1700, month: currentMonth });
    this.upsertBudget(userId, { category: 'Food & Dining', monthlyLimit: 600, month: currentMonth });
    this.upsertBudget(userId, { category: 'Transportation', monthlyLimit: 250, month: currentMonth });
    this.upsertBudget(userId, { category: 'Utilities', monthlyLimit: 220, month: currentMonth });
    this.upsertBudget(userId, { category: 'Entertainment', monthlyLimit: 150, month: currentMonth });

    this.createSavingsGoal(userId, {
      name: '6-Month Emergency Fund',
      targetAmount: 18000,
      currentAmount: 14800,
      targetDate: `${year + 1}-06-30`,
      color: '#10b981',
    });
    this.createSavingsGoal(userId, {
      name: 'Summer Trip to Japan',
      targetAmount: 4500,
      currentAmount: 2150,
      targetDate: `${year + 1}-08-15`,
      color: '#3b82f6',
    });
    this.createSavingsGoal(userId, {
      name: 'Home Office Upgrade',
      targetAmount: 1800,
      currentAmount: 1350,
      targetDate: `${year}-12-31`,
      color: '#f59e0b',
    });
  }
}

module.exports = { FinanceDatabase };
