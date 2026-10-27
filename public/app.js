'use strict';

(function () {
  const state = {
    csrfToken: null,
    user: null,
    categories: [],
    activeMonth: new Date().toISOString().slice(0, 7),
    dashboard: null,
    transactions: [],
  };

  const CHART_COLORS = [
    '#3b82f6',
    '#10b981',
    '#f59e0b',
    '#8b5cf6',
    '#ec4899',
    '#06b6d4',
    '#ef4444',
    '#84cc16',
  ];

  // --- Safe UI Toast Notification (avoids native alert/confirm) ---
  function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = String(message);
    container.appendChild(toast);
    setTimeout(() => {
      toast.remove();
    }, 3600);
  }

  function formatCurrency(amount) {
    const currency = (state.user && state.user.currency) || 'USD';
    const num = Number(amount) || 0;
    try {
      return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency,
        minimumFractionDigits: 2,
        maximumFractionDigits: 2,
      }).format(num);
    } catch {
      return `$${num.toFixed(2)}`;
    }
  }

  // --- API Client with Automatic CSRF Header ---
  async function apiRequest(path, options = {}) {
    const headers = Object.assign({ 'Content-Type': 'application/json' }, options.headers || {});
    if (options.method === 'POST' && state.csrfToken) {
      headers['X-CSRF-Token'] = state.csrfToken;
    }
    const response = await fetch(path, {
      method: options.method || 'GET',
      headers,
      credentials: 'same-origin',
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.error || 'Request failed');
    }
    return data;
  }

  // --- Populate Category & Account Selects Safely ---
  function populateCategorySelects() {
    const filterCat = document.getElementById('filter-category');
    const txCat = document.getElementById('tx-category');
    const budgetCat = document.getElementById('budget-category');

    if (filterCat) {
      filterCat.replaceChildren();
      const allOpt = document.createElement('option');
      allOpt.value = 'all';
      allOpt.textContent = 'All Categories';
      filterCat.appendChild(allOpt);
      for (const cat of state.categories) {
        const opt = document.createElement('option');
        opt.value = cat;
        opt.textContent = cat;
        filterCat.appendChild(opt);
      }
    }

    if (txCat) {
      txCat.replaceChildren();
      for (const cat of state.categories) {
        const opt = document.createElement('option');
        opt.value = cat;
        opt.textContent = cat;
        txCat.appendChild(opt);
      }
    }

    if (budgetCat) {
      budgetCat.replaceChildren();
      const expenseCategories = state.categories.filter(
        (c) => !['Salary', 'Freelance', 'Investments', 'Other Income'].includes(c)
      );
      for (const cat of expenseCategories) {
        const opt = document.createElement('option');
        opt.value = cat;
        opt.textContent = cat;
        budgetCat.appendChild(opt);
      }
    }
  }

  function populateAccountSelects(accounts) {
    const filterAcct = document.getElementById('filter-account');
    const txAcct = document.getElementById('tx-account');

    if (filterAcct) {
      const currentVal = filterAcct.value;
      filterAcct.replaceChildren();
      const allOpt = document.createElement('option');
      allOpt.value = '';
      allOpt.textContent = 'All Accounts';
      filterAcct.appendChild(allOpt);
      for (const acct of accounts) {
        const opt = document.createElement('option');
        opt.value = String(acct.id);
        opt.textContent = acct.name;
        filterAcct.appendChild(opt);
      }
      filterAcct.value = currentVal;
    }

    if (txAcct) {
      txAcct.replaceChildren();
      for (const acct of accounts) {
        const opt = document.createElement('option');
        opt.value = String(acct.id);
        opt.textContent = `${acct.name} (${formatCurrency(acct.balance)})`;
        txAcct.appendChild(opt);
      }
    }
  }

  // --- Render KPI Cards ---
  function renderKpis(summary) {
    const netWorthEl = document.getElementById('kpi-net-worth');
    const acctCountEl = document.getElementById('kpi-accounts-count');
    const incomeEl = document.getElementById('kpi-income');
    const expenseEl = document.getElementById('kpi-expense');
    const netMonthlyEl = document.getElementById('kpi-net-monthly');
    const savingsRateEl = document.getElementById('kpi-savings-rate');

    netWorthEl.textContent = formatCurrency(summary.netWorth);
    acctCountEl.textContent = `Across ${summary.accounts.length} account${summary.accounts.length === 1 ? '' : 's'}`;
    incomeEl.textContent = formatCurrency(summary.monthlyIncome);
    expenseEl.textContent = formatCurrency(summary.monthlyExpense);
    netMonthlyEl.textContent = formatCurrency(summary.monthlyNet);
    netMonthlyEl.className = `kpi-value ${summary.monthlyNet >= 0 ? 'positive' : 'negative'}`;
    savingsRateEl.textContent = `${summary.savingsRate}% monthly savings rate`;
  }

  // --- Render Accounts List ---
  function renderAccounts(accounts) {
    const container = document.getElementById('accounts-list');
    container.replaceChildren();

    if (!accounts.length) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.textContent = 'No accounts added yet.';
      container.appendChild(empty);
      return;
    }

    for (const acct of accounts) {
      const card = document.createElement('div');
      card.className = 'list-item-card';

      const row = document.createElement('div');
      row.className = 'list-item-row';

      const left = document.createElement('div');
      const dot = document.createElement('span');
      dot.className = 'acct-badge';
      dot.style.backgroundColor = acct.color || '#3b82f6';

      const title = document.createElement('span');
      title.className = 'item-title';
      title.textContent = acct.name;

      const sub = document.createElement('div');
      sub.className = 'item-sub';
      sub.textContent = acct.type;

      left.appendChild(dot);
      left.appendChild(title);
      left.appendChild(sub);

      const right = document.createElement('div');
      right.className = 'list-item-row';

      const bal = document.createElement('strong');
      bal.className = acct.balance < 0 ? 'negative' : '';
      bal.textContent = formatCurrency(acct.balance);
      right.appendChild(bal);

      if (accounts.length > 1) {
        const delBtn = document.createElement('button');
        delBtn.type = 'button';
        delBtn.className = 'btn-danger-icon';
        delBtn.textContent = 'Remove';
        delBtn.addEventListener('click', async () => {
          try {
            await apiRequest('/api/accounts/delete', {
              method: 'POST',
              body: { id: acct.id },
            });
            showToast(`Removed account "${acct.name}"`, 'success');
            await refreshAllData();
          } catch (err) {
            showToast(err.message, 'error');
          }
        });
        right.appendChild(delBtn);
      }

      row.appendChild(left);
      row.appendChild(right);
      card.appendChild(row);
      container.appendChild(card);
    }
  }

  // --- Render Monthly Budgets ---
  function renderBudgets(budgets) {
    const container = document.getElementById('budgets-list');
    container.replaceChildren();

    if (!budgets.length) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.textContent = 'No budgets configured for this month.';
      container.appendChild(empty);
      return;
    }

    for (const b of budgets) {
      const card = document.createElement('div');
      card.className = 'list-item-card';

      const topRow = document.createElement('div');
      topRow.className = 'list-item-row';

      const catTitle = document.createElement('span');
      catTitle.className = 'item-title';
      catTitle.textContent = b.category;

      const rightWrap = document.createElement('div');
      rightWrap.className = 'list-item-row';

      const ratio = b.monthly_limit > 0 ? (b.spent / b.monthly_limit) * 100 : 0;
      const pctLabel = document.createElement('span');
      pctLabel.className = 'item-sub';
      pctLabel.textContent = `${formatCurrency(b.spent)} / ${formatCurrency(b.monthly_limit)} (${Math.round(ratio)}%)`;

      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.className = 'btn-danger-icon';
      delBtn.textContent = '×';
      delBtn.title = 'Remove budget';
      delBtn.addEventListener('click', async () => {
        try {
          await apiRequest('/api/budgets/delete', {
            method: 'POST',
            body: { id: b.id },
          });
          showToast(`Removed ${b.category} budget`, 'success');
          await refreshAllData();
        } catch (err) {
          showToast(err.message, 'error');
        }
      });

      rightWrap.appendChild(pctLabel);
      rightWrap.appendChild(delBtn);
      topRow.appendChild(catTitle);
      topRow.appendChild(rightWrap);

      const track = document.createElement('div');
      track.className = 'progress-track';
      const fill = document.createElement('div');
      fill.className = 'progress-fill';
      fill.style.width = `${Math.min(100, Math.round(ratio))}%`;
      if (ratio >= 100) {
        fill.style.backgroundColor = '#ef4444';
      } else if (ratio >= 80) {
        fill.style.backgroundColor = '#f59e0b';
      } else {
        fill.style.backgroundColor = '#10b981';
      }
      track.appendChild(fill);

      card.appendChild(topRow);
      card.appendChild(track);
      container.appendChild(card);
    }
  }

  // --- Render Savings Goals ---
  function renderGoals(goals) {
    const container = document.getElementById('goals-list');
    container.replaceChildren();

    if (!goals.length) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.textContent = 'No savings goals yet. Set a target to start saving!';
      container.appendChild(empty);
      return;
    }

    for (const g of goals) {
      const card = document.createElement('div');
      card.className = 'list-item-card';

      const topRow = document.createElement('div');
      topRow.className = 'list-item-row';

      const left = document.createElement('div');
      const nameEl = document.createElement('div');
      nameEl.className = 'item-title';
      nameEl.textContent = g.name;

      const subEl = document.createElement('div');
      subEl.className = 'item-sub';
      const pct = g.target_amount > 0 ? Math.min(100, Math.round((g.current_amount / g.target_amount) * 100)) : 0;
      subEl.textContent = `${formatCurrency(g.current_amount)} of ${formatCurrency(g.target_amount)} (${pct}%)${
        g.target_date ? ` • Due ${g.target_date}` : ''
      }`;

      left.appendChild(nameEl);
      left.appendChild(subEl);

      const actions = document.createElement('div');
      actions.className = 'list-item-row';

      const addFundsBtn = document.createElement('button');
      addFundsBtn.type = 'button';
      addFundsBtn.className = 'btn btn-sm btn-outline';
      addFundsBtn.textContent = '+/- Funds';
      addFundsBtn.addEventListener('click', () => {
        document.getElementById('contribute-goal-id').value = String(g.id);
        document.getElementById('contribute-modal-title').textContent = `Update "${g.name}"`;
        document.getElementById('contribute-amount').value = '';
        document.getElementById('modal-goal-contribute').showModal();
      });

      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.className = 'btn-danger-icon';
      delBtn.textContent = '×';
      delBtn.addEventListener('click', async () => {
        try {
          await apiRequest('/api/goals/delete', {
            method: 'POST',
            body: { id: g.id },
          });
          showToast(`Deleted goal "${g.name}"`, 'success');
          await refreshAllData();
        } catch (err) {
          showToast(err.message, 'error');
        }
      });

      actions.appendChild(addFundsBtn);
      actions.appendChild(delBtn);

      topRow.appendChild(left);
      topRow.appendChild(actions);

      const track = document.createElement('div');
      track.className = 'progress-track';
      const fill = document.createElement('div');
      fill.className = 'progress-fill';
      fill.style.width = `${pct}%`;
      fill.style.backgroundColor = g.color || '#10b981';
      track.appendChild(fill);

      card.appendChild(topRow);
      card.appendChild(track);
      container.appendChild(card);
    }
  }

  // --- Render Transactions Ledger Table ---
  function renderTransactions(transactions) {
    const tbody = document.getElementById('transactions-tbody');
    tbody.replaceChildren();

    if (!transactions.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.className = 'empty-state';
      td.textContent = 'No transactions match the current filter criteria.';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    for (const tx of transactions) {
      const tr = document.createElement('tr');

      const tdDate = document.createElement('td');
      tdDate.textContent = tx.date;

      const tdDesc = document.createElement('td');
      const descSpan = document.createElement('span');
      descSpan.textContent = tx.description || tx.category;
      tdDesc.appendChild(descSpan);
      if (tx.is_recurring) {
        const recBadge = document.createElement('span');
        recBadge.className = 'recurring-tag';
        recBadge.textContent = '↻ Recurring';
        tdDesc.appendChild(recBadge);
      }

      const tdCat = document.createElement('td');
      const pill = document.createElement('span');
      pill.className = 'category-pill';
      pill.textContent = tx.category;
      tdCat.appendChild(pill);

      const tdAcct = document.createElement('td');
      tdAcct.textContent = tx.account_name;

      const tdAmount = document.createElement('td');
      tdAmount.className = `text-right ${tx.type === 'income' ? 'positive' : 'negative'}`;
      const sign = tx.type === 'income' ? '+' : '-';
      tdAmount.textContent = `${sign}${formatCurrency(tx.amount)}`;

      const tdAction = document.createElement('td');
      tdAction.className = 'text-right';
      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.className = 'btn-danger-icon';
      delBtn.textContent = 'Delete';
      delBtn.addEventListener('click', async () => {
        try {
          await apiRequest('/api/transactions/delete', {
            method: 'POST',
            body: { id: tx.id },
          });
          showToast('Transaction deleted', 'success');
          await refreshAllData();
        } catch (err) {
          showToast(err.message, 'error');
        }
      });
      tdAction.appendChild(delBtn);

      tr.appendChild(tdDate);
      tr.appendChild(tdDesc);
      tr.appendChild(tdCat);
      tr.appendChild(tdAcct);
      tr.appendChild(tdAmount);
      tr.appendChild(tdAction);
      tbody.appendChild(tr);
    }
  }

  // --- HTML5 Canvas Cash Flow Bar Chart ---
  function drawCashFlowChart(monthlyTrend) {
    const canvas = document.getElementById('cashflow-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    if (!monthlyTrend || !monthlyTrend.length) {
      ctx.fillStyle = '#64748b';
      ctx.font = '14px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('No monthly trend data yet', w / 2, h / 2);
      return;
    }

    const padLeft = 64;
    const padRight = 24;
    const padTop = 24;
    const padBottom = 38;
    const plotW = w - padLeft - padRight;
    const plotH = h - padTop - padBottom;

    let maxVal = 100;
    for (const item of monthlyTrend) {
      maxVal = Math.max(maxVal, Number(item.income) || 0, Number(item.expense) || 0);
    }
    maxVal = Math.ceil(maxVal * 1.15);

    // Horizontal grid lines
    ctx.strokeStyle = '#1e293b';
    ctx.lineWidth = 1;
    ctx.fillStyle = '#94a3b8';
    ctx.font = '11px sans-serif';
    ctx.textAlign = 'right';

    const steps = 4;
    for (let i = 0; i <= steps; i++) {
      const y = padTop + plotH - (i / steps) * plotH;
      ctx.beginPath();
      ctx.moveTo(padLeft, y);
      ctx.lineTo(w - padRight, y);
      ctx.stroke();

      const labelVal = Math.round((maxVal * i) / steps);
      ctx.fillText(`${labelVal}`, padLeft - 8, y + 4);
    }

    const groupW = plotW / monthlyTrend.length;
    const barW = Math.min(26, groupW * 0.32);

    monthlyTrend.forEach((item, idx) => {
      const centerX = padLeft + idx * groupW + groupW / 2;
      const incH = ((Number(item.income) || 0) / maxVal) * plotH;
      const expH = ((Number(item.expense) || 0) / maxVal) * plotH;

      // Income bar
      ctx.fillStyle = '#10b981';
      ctx.fillRect(centerX - barW - 3, padTop + plotH - incH, barW, incH);

      // Expense bar
      ctx.fillStyle = '#ef4444';
      ctx.fillRect(centerX + 3, padTop + plotH - expH, barW, expH);

      // Month label
      ctx.fillStyle = '#94a3b8';
      ctx.textAlign = 'center';
      ctx.fillText(item.month, centerX, h - 12);
    });
  }

  // --- HTML5 Canvas Category Doughnut Chart ---
  function drawCategoryChart(expenseByCategory) {
    const canvas = document.getElementById('category-canvas');
    const legend = document.getElementById('category-legend');
    if (!canvas || !legend) return;

    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    ctx.clearRect(0, 0, w, h);
    legend.replaceChildren();

    const total = (expenseByCategory || []).reduce((acc, c) => acc + Number(c.total), 0);
    if (total <= 0) {
      ctx.beginPath();
      ctx.arc(w / 2, h / 2, 75, 0, Math.PI * 2);
      ctx.strokeStyle = '#1e293b';
      ctx.lineWidth = 24;
      ctx.stroke();

      const li = document.createElement('li');
      li.className = 'empty-state';
      li.textContent = 'No expenses recorded in this month.';
      legend.appendChild(li);
      return;
    }

    let startAngle = -Math.PI / 2;
    expenseByCategory.forEach((item, idx) => {
      const color = CHART_COLORS[idx % CHART_COLORS.length];
      const sliceAngle = (Number(item.total) / total) * Math.PI * 2;

      ctx.beginPath();
      ctx.arc(w / 2, h / 2, 76, startAngle, startAngle + sliceAngle);
      ctx.strokeStyle = color;
      ctx.lineWidth = 28;
      ctx.stroke();
      startAngle += sliceAngle;

      const li = document.createElement('li');
      li.className = 'legend-item';

      const leftWrap = document.createElement('div');
      leftWrap.className = 'legend-label-wrap';

      const dot = document.createElement('span');
      dot.className = 'legend-dot';
      dot.style.backgroundColor = color;

      const nameSpan = document.createElement('span');
      nameSpan.textContent = item.category;

      leftWrap.appendChild(dot);
      leftWrap.appendChild(nameSpan);

      const valSpan = document.createElement('strong');
      const pct = Math.round((Number(item.total) / total) * 100);
      valSpan.textContent = `${formatCurrency(item.total)} (${pct}%)`;

      li.appendChild(leftWrap);
      li.appendChild(valSpan);
      legend.appendChild(li);
    });
  }

  // --- Data Fetching & Refresh ---
  async function loadTransactionsOnly() {
    const search = document.getElementById('filter-search').value.trim();
    const type = document.getElementById('filter-type').value;
    const category = document.getElementById('filter-category').value;
    const accountId = document.getElementById('filter-account').value;

    const params = new URLSearchParams({
      month: state.activeMonth,
      type,
      category,
      accountId,
      search,
    });
    const res = await apiRequest(`/api/transactions?${params.toString()}`);
    state.transactions = res.transactions || [];
    renderTransactions(state.transactions);
  }

  async function refreshAllData() {
    const summary = await apiRequest(`/api/dashboard?month=${encodeURIComponent(state.activeMonth)}`);
    state.dashboard = summary;
    renderKpis(summary);
    populateAccountSelects(summary.accounts || []);
    renderAccounts(summary.accounts || []);
    renderBudgets(summary.budgets || []);
    renderGoals(summary.goals || []);
    drawCashFlowChart(summary.monthlyTrend || []);
    drawCategoryChart(summary.expenseByCategory || []);
    await loadTransactionsOnly();
  }

  function enterAuthenticatedApp(sessionPayload) {
    state.csrfToken = sessionPayload.csrfToken;
    state.user = sessionPayload.user;
    state.categories = sessionPayload.categories || [];

    document.getElementById('auth-view').classList.add('hidden');
    document.getElementById('app-view').classList.remove('hidden');

    const badge = document.getElementById('user-badge');
    badge.textContent = `${state.user.name} (${state.user.maskedEmail})`;

    const monthInput = document.getElementById('active-month');
    monthInput.value = state.activeMonth;

    populateCategorySelects();
    refreshAllData().catch((err) => showToast(err.message, 'error'));
  }

  function showAuthScreen() {
    state.csrfToken = null;
    state.user = null;
    document.getElementById('app-view').classList.add('hidden');
    document.getElementById('auth-view').classList.remove('hidden');
  }

  // --- Event Listeners Setup ---
  function initEventListeners() {
    // Auth Tabs
    const tabLogin = document.getElementById('tab-login');
    const tabRegister = document.getElementById('tab-register');
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');

    tabLogin.addEventListener('click', () => {
      tabLogin.classList.add('active');
      tabRegister.classList.remove('active');
      loginForm.classList.remove('hidden');
      registerForm.classList.add('hidden');
    });

    tabRegister.addEventListener('click', () => {
      tabRegister.classList.add('active');
      tabLogin.classList.remove('active');
      registerForm.classList.remove('hidden');
      loginForm.classList.add('hidden');
    });

    // Sign In
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        const email = document.getElementById('login-email').value;
        const password = document.getElementById('login-password').value;
        const payload = await apiRequest('/api/auth/login', {
          method: 'POST',
          body: { email, password },
        });
        showToast('Signed in successfully!', 'success');
        enterAuthenticatedApp(payload);
      } catch (err) {
        showToast(err.message, 'error');
      }
    });

    // Register
    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        const name = document.getElementById('reg-name').value;
        const email = document.getElementById('reg-email').value;
        const password = document.getElementById('reg-password').value;
        const currency = document.getElementById('reg-currency').value;
        const seedDemo = document.getElementById('reg-seed-demo').checked;

        const payload = await apiRequest('/api/auth/register', {
          method: 'POST',
          body: { name, email, password, currency, seedDemo },
        });
        showToast('Personal account created!', 'success');
        enterAuthenticatedApp(payload);
      } catch (err) {
        showToast(err.message, 'error');
      }
    });

    // Instant Demo Workspace
    document.getElementById('btn-demo-login').addEventListener('click', async () => {
      try {
        const payload = await apiRequest('/api/auth/demo', { method: 'POST', body: {} });
        showToast('Demo workspace loaded!', 'success');
        enterAuthenticatedApp(payload);
      } catch (err) {
        showToast(err.message, 'error');
      }
    });

    // Logout (clears state and reloads page cleanly)
    document.getElementById('btn-logout').addEventListener('click', async () => {
      try {
        await apiRequest('/api/auth/logout', { method: 'POST', body: {} });
      } catch {
        // Proceed with client state cleanup even if request errors
      }
      state.csrfToken = null;
      state.user = null;
      window.location.href = '/';
    });

    // Month Selector
    document.getElementById('active-month').addEventListener('change', (e) => {
      if (e.target.value) {
        state.activeMonth = e.target.value;
        refreshAllData().catch((err) => showToast(err.message, 'error'));
      }
    });

    // CSV Export
    document.getElementById('btn-export-csv').addEventListener('click', () => {
      const url = `/api/transactions/export?month=${encodeURIComponent(state.activeMonth)}`;
      window.location.href = url;
    });

    // Open Modals
    document.getElementById('btn-open-tx-modal').addEventListener('click', () => {
      document.getElementById('tx-date').value = new Date().toISOString().slice(0, 10);
      document.getElementById('tx-amount').value = '';
      document.getElementById('tx-description').value = '';
      document.getElementById('tx-recurring').checked = false;
      document.getElementById('modal-transaction').showModal();
    });

    document.getElementById('btn-open-account-modal').addEventListener('click', () => {
      document.getElementById('acct-name').value = '';
      document.getElementById('acct-balance').value = '0.00';
      document.getElementById('modal-account').showModal();
    });

    document.getElementById('btn-open-budget-modal').addEventListener('click', () => {
      document.getElementById('budget-limit').value = '';
      document.getElementById('modal-budget').showModal();
    });

    document.getElementById('btn-open-goal-modal').addEventListener('click', () => {
      document.getElementById('goal-name').value = '';
      document.getElementById('goal-target').value = '';
      document.getElementById('goal-current').value = '0';
      document.getElementById('modal-goal').showModal();
    });

    // Close Modal Buttons
    document.querySelectorAll('[data-close-modal]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const modalId = btn.getAttribute('data-close-modal');
        const dialog = document.getElementById(modalId);
        if (dialog) dialog.close();
      });
    });

    // Submit New Transaction
    document.getElementById('form-transaction').addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        const type = document.getElementById('tx-type').value;
        const amount = Number(document.getElementById('tx-amount').value);
        const accountId = Number(document.getElementById('tx-account').value);
        const category = document.getElementById('tx-category').value;
        const date = document.getElementById('tx-date').value;
        const description = document.getElementById('tx-description').value;
        const isRecurring = document.getElementById('tx-recurring').checked;

        await apiRequest('/api/transactions/create', {
          method: 'POST',
          body: { type, amount, accountId, category, date, description, isRecurring },
        });
        document.getElementById('modal-transaction').close();
        showToast('Transaction saved!', 'success');
        await refreshAllData();
      } catch (err) {
        showToast(err.message, 'error');
      }
    });

    // Submit New Account
    document.getElementById('form-account').addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        const name = document.getElementById('acct-name').value;
        const type = document.getElementById('acct-type').value;
        const balance = Number(document.getElementById('acct-balance').value);
        const color = document.getElementById('acct-color').value;

        await apiRequest('/api/accounts/create', {
          method: 'POST',
          body: { name, type, balance, color },
        });
        document.getElementById('modal-account').close();
        showToast('Account created!', 'success');
        await refreshAllData();
      } catch (err) {
        showToast(err.message, 'error');
      }
    });

    // Submit Monthly Budget
    document.getElementById('form-budget').addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        const category = document.getElementById('budget-category').value;
        const monthlyLimit = Number(document.getElementById('budget-limit').value);
        await apiRequest('/api/budgets/upsert', {
          method: 'POST',
          body: { category, monthlyLimit, month: state.activeMonth },
        });
        document.getElementById('modal-budget').close();
        showToast(`Budget updated for ${category}`, 'success');
        await refreshAllData();
      } catch (err) {
        showToast(err.message, 'error');
      }
    });

    // Submit New Goal
    document.getElementById('form-goal').addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        const name = document.getElementById('goal-name').value;
        const targetAmount = Number(document.getElementById('goal-target').value);
        const currentAmount = Number(document.getElementById('goal-current').value);
        const targetDate = document.getElementById('goal-date').value;
        const color = document.getElementById('goal-color').value;

        await apiRequest('/api/goals/create', {
          method: 'POST',
          body: { name, targetAmount, currentAmount, targetDate, color },
        });
        document.getElementById('modal-goal').close();
        showToast('Savings goal created!', 'success');
        await refreshAllData();
      } catch (err) {
        showToast(err.message, 'error');
      }
    });

    // Submit Goal Contribution
    document.getElementById('form-goal-contribute').addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        const id = Number(document.getElementById('contribute-goal-id').value);
        const amount = Number(document.getElementById('contribute-amount').value);
        await apiRequest('/api/goals/contribute', {
          method: 'POST',
          body: { id, amount },
        });
        document.getElementById('modal-goal-contribute').close();
        showToast('Savings goal balance updated!', 'success');
        await refreshAllData();
      } catch (err) {
        showToast(err.message, 'error');
      }
    });

    // Ledger Filters
    ['filter-search', 'filter-type', 'filter-category', 'filter-account'].forEach((id) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.addEventListener('input', () => {
        loadTransactionsOnly().catch((err) => showToast(err.message, 'error'));
      });
    });
  }

  // Bootstrap App
  document.addEventListener('DOMContentLoaded', async () => {
    initEventListeners();
    try {
      const sessionData = await apiRequest('/api/auth/session');
      if (sessionData.authenticated) {
        enterAuthenticatedApp(sessionData);
      } else {
        showAuthScreen();
      }
    } catch {
      showAuthScreen();
    }
  });
})();
