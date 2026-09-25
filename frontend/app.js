/* =============================================================================
   SentinelAPI — single frontend application (the ONLY active implementation).
   Loaded by frontend/index.html. Every displayed value comes from the FastAPI
   backend; there is no demo dataset in this file. Demo mode only runs the real
   scanner against the explicitly authorized vulnerable sandbox API and is
   clearly labeled — it never invents findings or metrics.
   ========================================================================== */
(function () {
  'use strict';

  // ------------------------------------------------------------------ helpers
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (ch) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
  ));

  const TOKEN_KEY = 'sentinel_token';
  const SCAN_KEY = 'sentinel_scan';
  const MODE_KEY = 'sentinelapi-mode';
  const DEMO_KEY = 'sentinel_demo';
  const SANDBOX_DEFAULT_URL = 'http://127.0.0.1:9000';
  const FINDING_STATUSES = ['open', 'in_review', 'mitigated', 'resolved', 'false_positive'];
  const SEVERITIES_UPPER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

  function toast(message, isError) {
    const el = $('#toast');
    if (!el) return;
    el.textContent = message;
    el.classList.toggle('error', !!isError);
    el.classList.add('show');
    clearTimeout(toast._t);
    toast._t = setTimeout(() => el.classList.remove('show'), 2600);
  }

  function timeAgo(iso) {
    const t = Date.parse(iso);
    if (!Number.isFinite(t)) return '—';
    const s = Math.max(0, (Date.now() - t) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  }

  function fmtDate(iso) {
    const t = Date.parse(iso);
    return Number.isFinite(t) ? new Date(t).toLocaleString() : '—';
  }

  function initialsOf(text) {
    const out = String(text || '').replace(/[._-]+/g, ' ').trim().split(/\s+/)
      .map((p) => p[0]).join('').slice(0, 2).toUpperCase();
    return out || '?';
  }

  function displayName(user) {
    if (!user || !user.email) return 'Not signed in';
    return user.email.split('@')[0].replace(/[._-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
  }

  function statusClass(status) {
    return { completed: 'good', running: 'high', queued: 'medium', failed: 'critical', cancelled: 'low' }[String(status || '').toLowerCase()] || 'medium';
  }

  function setText(id, text) { const el = document.getElementById(id); if (el) el.textContent = text; }

  // ------------------------------------------------------------------- state
  const state = {
    token: localStorage.getItem(TOKEN_KEY) || '',
    user: null,
    projects: [],
    project: null,
    scans: [],
    scan: localStorage.getItem(SCAN_KEY) || null,
    findings: [],
    findingsTotal: 0,
    finding: null,
    dashboard: null,
    report: null,
    status: null,
    socket: null,
    poller: 0,
    filters: { severity: '', status: '', query: '' },
    demo: localStorage.getItem(DEMO_KEY) === '1',
    authDestination: 'overview',
    authMode: 'signin',
  };

  const views = {};
  let currentView = '';

  // -------------------------------------------------------------- API client
  const API_BASE = (() => {
    if (window.SENTINEL_API_BASE) return String(window.SENTINEL_API_BASE).replace(/\/+$/, '');
    if (location.protocol === 'http:' || location.protocol === 'https:') return location.origin;
    return 'http://127.0.0.1:8000';
  })();

  class ApiError extends Error {
    constructor(message, status) { super(message); this.name = 'ApiError'; this.status = status || 0; }
  }

  async function apiRequest(path, options) {
    const config = options || {};
    const headers = new Headers(config.headers || {});
    if (state.token) headers.set('Authorization', 'Bearer ' + state.token);
    let response;
    try {
      response = await fetch(API_BASE + path, Object.assign({}, config, { headers }));
    } catch (networkErr) {
      throw new ApiError('Cannot reach the SentinelAPI backend at ' + API_BASE + '. Is it running?', 0);
    }
    if (response.status === 204) return null;
    const text = await response.text();
    let body = {};
    if (text) { try { body = JSON.parse(text); } catch (_) { body = { detail: text }; } }
    if (!response.ok) {
      const detail = typeof body.detail === 'string' ? body.detail
        : body.detail ? JSON.stringify(body.detail) : '';
      throw new ApiError(detail || 'Request failed (' + response.status + ')', response.status);
    }
    return body;
  }

  function handleApiError(error, fallbackMessage) {
    if (error && error.status === 401 && state.token) {
      signOutLocal();
      toast('Session expired — please sign in again', true);
      go('login');
      return;
    }
    toast((error && error.message) || fallbackMessage || 'Request failed', true);
  }

  function signOutLocal() {
    state.token = ''; state.user = null; state.projects = []; state.project = null;
    state.scans = []; state.scan = null; state.findings = []; state.findingsTotal = 0;
    state.finding = null; state.dashboard = null; state.report = null; state.status = null;
    state.demo = false;
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(SCAN_KEY);
    localStorage.removeItem(DEMO_KEY);
    stopLiveUpdates();
    syncIdentity();
  }

  // ------------------------------------------------------- workspace bootstrap
  async function ensureProjects() {
    if (state.projects.length) return state.projects;
    const list = await apiRequest('/api/projects');
    state.projects = list.items || [];
    state.project = state.projects.length ? state.projects[0].id : null;
    return state.projects;
  }

  async function ensureScan() {
    if (state.scan) {
      try {
        return await apiRequest('/api/scans/' + encodeURIComponent(state.scan));
      } catch (e) {
        if (e.status === 404) { state.scan = null; localStorage.removeItem(SCAN_KEY); }
        else throw e;
      }
    }
    await ensureProjects();
    const list = await apiRequest('/api/scans');
    state.scans = list.items || [];
    if (state.scans.length) {
      state.scan = state.scans[0].id;
      localStorage.setItem(SCAN_KEY, state.scan);
      return state.scans[0];
    }
    return null;
  }

  // ------------------------------------------------------------ theme / drawer
  function applyTheme(mode) {
    if (['light', 'dark', 'system'].indexOf(mode) < 0) mode = 'dark';
    localStorage.setItem(MODE_KEY, mode);
    const actual = mode === 'system'
      ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
      : mode;
    document.documentElement.dataset.theme = actual;
    $$('.modes button[data-mode]').forEach((b) => b.classList.toggle('active', b.dataset.mode === mode));
  }
  window.setTheme = (mode) => applyTheme(mode);

  function toggleDrawer(force) {
    const open = typeof force === 'boolean' ? force : !document.body.classList.contains('nav-open');
    document.body.classList.toggle('nav-open', open);
    const btn = $('#nav-toggle');
    if (btn) btn.setAttribute('aria-expanded', String(open));
  }
  function closeDrawer() { toggleDrawer(false); }

  function buildNav() {
    const items = [
      ['overview', '◉', 'Security Overview'],
      ['config', '⌁', 'Scan Configuration'],
      ['live', '◌', 'Live Testing'],
      ['network', '⌘', 'Network Graph'],
      ['findings', '◇', 'Finding Explorer'],
      ['investigation', '⌕', 'Investigation'],
      ['poc', '△', 'Proof of Concept'],
      ['ai', '✦', 'AI Explanation'],
      ['report', '▤', 'Security Report'],
      ['profile', '◎', 'Profile'],
      ['settings', '⚙', 'Settings'],
    ];
    const nav = $('#nav');
    if (!nav) return;
    nav.innerHTML = items.map(([key, ico, label]) => (
      '<button data-page="' + key + '" type="button"><span class="ico">' + ico + '</span><span>' + label + '</span></button>'
    )).join('');
    $$('#nav button').forEach((b) => b.addEventListener('click', () => go(b.dataset.page)));
  }

  function highlightNav(key) {
    $$('#nav button').forEach((b) => b.classList.toggle('active', b.dataset.page === key));
  }

  function syncIdentity() {
    const name = state.user ? displayName(state.user) : 'Not signed in';
    const email = state.user ? state.user.email : '';
    $$('.user-btn .avatar').forEach((el) => { el.textContent = initialsOf(name); });
    $$('.user-btn b').forEach((el) => { el.textContent = name; });
    $$('.user-btn small').forEach((el) => { el.textContent = email; });
  }

  // ---------------------------------------------------------- render helpers
  function head(title, sub, actions) {
    return '<div class="head"><div><div class="eyebrow">SentinelAPI workspace</div>' +
      '<h1>' + esc(title) + '</h1><p>' + esc(sub) + '</p></div>' +
      '<div class="actions">' + (actions || '') + '</div></div>';
  }
  function card(title, body, extra) {
    return '<div class="card">' + (title
      ? '<div class="section-title"><h3>' + esc(title) + '</h3>' + (extra || '') + '</div>'
      : '') + body + '</div>';
  }
  function stat(icon, label, value, trend) {
    return '<div class="card stat"><div class="stat-icon">' + icon + '</div>' +
      '<div class="value">' + esc(value) + '</div><div class="label">' + esc(label) + '</div>' +
      (trend ? '<div class="trend">' + esc(trend) + '</div>' : '') + '</div>';
  }
  function pill(cls, text) { return '<span class="pill ' + esc(cls) + '">' + esc(text) + '</span>'; }
  function severityPill(sev) { return pill(String(sev || '').toLowerCase() || 'low', String(sev || '—')); }
  function stateBlock(kind, title, message, actionsHtml) {
    const glyph = kind === 'loading' ? '<span class="spinner"></span>' : kind === 'error' ? '!' : '◌';
    return '<div class="state ' + kind + '"><div class="big">' + glyph + '</div>' +
      '<b>' + esc(title) + '</b><p>' + esc(message) + '</p>' +
      (actionsHtml ? '<div class="state-actions">' + actionsHtml + '</div>' : '') + '</div>';
  }
  function emptyNoScan() {
    return stateBlock('empty', 'No scan data available',
      'Create a project, upload an OpenAPI 3.x specification and start a scan against the authorized sandbox.',
      '<button class="btn primary" onclick="go(\'config\')">Configure a scan</button>');
  }
  function demoBanner() {
    if (!state.demo) return '';
    return '<div class="demo-banner"><b>DEMO / SANDBOX DATA</b><span>This workspace is running the real scanner against the intentionally vulnerable sandbox API — not a production system.</span></div>';
  }

  // ------------------------------------------------------------ landing page
  function renderLanding() {
    return '<div class="landing-shell"><div class="landing-grid"></div>' +      '<nav class="landing-nav">' +
        '<div class="landing-brand"><div class="landing-logo">✦</div><span>SentinelAPI</span></div>' +
        '<div class="landing-links"><a href="#product-anchor" onclick="landingScroll(event,\'product-anchor\')">Product</a>' +
        '<a href="#features-anchor" onclick="landingScroll(event,\'features-anchor\')">Features</a></div>' +
        '<button class="landing-cta" onclick="openLogin(\'overview\')">Get Started</button>' +
      '</nav>' +
      '<main class="landing-hero" id="product-anchor">' +
        '<section class="landing-copy">' +
          '<div class="landing-kicker"><i></i> AI-assisted API security</div>' +
          '<h1 class="landing-title">Secure Your<br/>APIs Before<br/><span class="glow">Attackers Do.</span></h1>' +
          '<p class="landing-sub">AI-assisted, evidence-driven API security testing with real proof, not just warnings.</p>' +
          '<div class="landing-actions">' +
            '<button class="landing-primary" onclick="openLogin(\'config\')">Start Security Scan&nbsp; →</button>' +
            '<button class="landing-secondary" type="button" onclick="go(\'demo\')">View Demo</button>' +
          '</div>' +
          '<div class="landing-features" id="features-anchor">' +
            '<div class="landing-feature"><div class="fi">◈</div><b>BOLA / IDOR Detection</b><small>Discover broken object-level authorization paths.</small></div>' +
            '<div class="landing-feature"><div class="fi">▤</div><b>Excessive Data Exposure</b><small>Identify sensitive data returned by APIs.</small></div>' +
            '<div class="landing-feature"><div class="fi">♙</div><b>Authentication Testing</b><small>Validate authentication and access boundaries.</small></div>' +
            '<div class="landing-feature"><div class="fi">✦</div><b>Reproducible Proof of Concept</b><small>Turn findings into controlled evidence.</small></div>' +
          '</div>' +
        '</section>' +
        '<section class="hero-visual" aria-label="Animated API security visualization">' +
          '<div class="orbit o1"></div><div class="orbit o2"></div><div class="orbit o3"></div>' +
          '<div class="platform"></div>' +
          '<div class="shield-wrap"><div class="shield-glow"></div><div class="shield"><div class="shield-mark">✦</div></div></div>' +
          '<div class="bubble b1"><span class="dot"></span>/users</div><div class="bubble b2"><span class="dot"></span>/orders</div>' +
          '<div class="bubble b3"><span class="dot"></span>/payments</div><div class="bubble b4"><span class="dot"></span>/auth</div>' +
          '<div class="bubble b5"><span class="dot"></span>/api/v1</div>' +
          '<div class="scan-line"></div><div class="visual-caption">continuous endpoint protection · live evidence</div>' +
        '</section>' +
      '</main>' +
      '<div class="landing-trust">Trusted by developers, security teams and organizations building safer APIs.</div>' +
    '</div>';
  }
  window.landingScroll = function (event, id) {
    event.preventDefault();
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  views.landing = { public: true, render: renderLanding };

  // ------------------------------------------------------------- auth views
  function renderLogin() {
    const create = state.authMode === 'signup';
    const destLabel = state.authDestination === 'config' ? 'Scan Configuration' : 'Security Overview';
    return '<div class="login-shell"><div class="login-grid"></div><div class="login-card">' +
      '<div class="login-brand"><div class="login-logo">✦</div><span>SentinelAPI</span></div>' +
      '<div class="login-dest"><i></i> Continue to ' + esc(destLabel) + '</div>' +
      '<h1>' + (create ? 'Create your account' : 'Welcome back') + '</h1>' +
      '<p>' + (create
        ? 'Create your SentinelAPI account to start securing your APIs.'
        : 'Sign in to access your SentinelAPI security workspace and continue where you left off.') + '</p>' +
      (create
        ? '<div class="auth-benefits">' +
          '<div class="auth-benefit"><b>API Security Workspace</b>Scan, investigate and track findings.</div>' +
          '<div class="auth-benefit"><b>Evidence &amp; PoC</b>Turn findings into reproducible proof.</div></div>'
        : '') +
      '<form onsubmit="submitAuth(event)">' +
        '<div class="login-field"><label for="auth-email">Email address</label>' +
        '<input id="auth-email" type="email" autocomplete="email" placeholder="you@company.com" required></div>' +
        '<div class="login-field"><label for="auth-password">Password</label>' +
        '<input id="auth-password" type="password" minlength="8" autocomplete="' + (create ? 'new-password' : 'current-password') + '" placeholder="' + (create ? 'At least 8 characters' : 'Enter your password') + '" required></div>' +
        (create
          ? '<div class="login-field"><label for="signup-confirm">Confirm password</label>' +
            '<input id="signup-confirm" type="password" minlength="8" autocomplete="new-password" placeholder="Repeat your password" required></div>'
          : '') +
        '<button id="auth-submit" class="login-submit" type="submit">' + (create ? 'Create SentinelAPI account' : 'Sign in to SentinelAPI') + '&nbsp; →</button>' +
        '<p id="auth-error" class="form-error" role="alert"></p>' +
      '</form>' +
      (create ? '<div class="auth-terms">By creating an account, you agree to the SentinelAPI terms and privacy policy.</div>' : '') +
      '<div class="auth-switch">' + (create ? 'Already have an account?' : 'First time here?') +
      ' <button type="button" onclick="toggleAuthMode()">' + (create ? 'Sign in' : 'Create an account') + '</button></div>' +
      '<button class="login-back" onclick="go(\'landing\')">← Back to landing page</button>' +
      '<div class="login-note">Secure workspace access · authenticated by the SentinelAPI backend</div>' +
    '</div></div>';
  }
  views.login = { public: true, render: renderLogin };

  window.toggleAuthMode = function () {
    state.authMode = state.authMode === 'signin' ? 'signup' : 'signin';
    go('login');
  };
  window.openLogin = function (destination) {
    state.authDestination = destination || 'overview';
    state.authMode = 'signin';
    go('login');
  };

  function friendlyAuthError(error) {
    if (!error.status) return error.message || 'Cannot reach the backend.';
    if (error.status === 401) return 'Incorrect email or password.';
    if (error.status === 409) return 'An account with this email already exists.';
    return error.message || 'Authentication failed.';
  }

  window.submitAuth = async function (event) {
    event.preventDefault();
    const errEl = $('#auth-error');
    const btn = $('#auth-submit');
    const email = (($('#auth-email') || {}).value || '').trim();
    const password = ($('#auth-password') || {}).value || '';
    const confirmEl = $('#signup-confirm');
    const create = state.authMode === 'signup';
    errEl.textContent = '';
    if (!email || !password) { errEl.textContent = 'Email and password are required.'; return; }
    if (create) {
      if (password !== (confirmEl ? confirmEl.value : '')) { errEl.textContent = 'Passwords do not match.'; return; }
      if (password.length < 8) { errEl.textContent = 'Password must be at least 8 characters.'; return; }
    }
    const originalLabel = btn.textContent;
    btn.disabled = true;
    btn.textContent = create ? 'Creating account…' : 'Signing in…';
    try {
      const data = await apiRequest('/api/auth/' + (create ? 'register' : 'login'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email, password: password }),
      });
      state.token = data.access_token;
      localStorage.setItem(TOKEN_KEY, state.token);
      state.user = await apiRequest('/api/auth/me');
      syncIdentity();
      toast(create ? 'Account created' : 'Signed in successfully');
      state.demo = false;
      go(state.authDestination || 'overview');
    } catch (error) {
      errEl.textContent = friendlyAuthError(error);
    } finally {
      btn.disabled = false;
      btn.textContent = originalLabel;
    }
  };

  // ------------------------------------------------- scan form (config + demo)
  function scanFormHtml(prefix) {
    return '' +
      '<div class="field"><label for="' + prefix + '-file">OpenAPI 3.x specification (JSON or YAML)</label>' +
      '<input id="' + prefix + '-file" type="file" accept=".json,.yaml,.yml,application/json,application/yaml"></div>' +
      '<div class="field"><label for="' + prefix + '-target">Authorized sandbox target URL</label>' +
      '<input id="' + prefix + '-target" value="' + esc(SANDBOX_DEFAULT_URL) + '"></div>' +
      '<p class="muted" style="font-size:13px">Sandbox identities (DEMO / SANDBOX DATA — dummy accounts inside the vulnerable sandbox, not real credentials):</p>' +
      '<div class="grid two"><div class="field"><label for="' + prefix + '-identity-a">User A (demo)</label>' +
      '<input id="' + prefix + '-identity-a" value="alice:password123"></div>' +
      '<div class="field"><label for="' + prefix + '-identity-b">User B (demo)</label>' +
      '<input id="' + prefix + '-identity-b" value="bob:password456"></div></div>' +
      '<button class="landing-primary" style="width:100%" onclick="submitScanForm(\'' + prefix + '\')">Start Security Scan →</button>' +
      '<p id="' + prefix + '-msg" class="muted" style="margin-top:12px">Select an OpenAPI file to begin.</p>';
  }

  window.submitScanForm = async function (prefix) {
    const msgEl = $('#' + prefix + '-msg');
    const fileInput = $('#' + prefix + '-file');
    const target = (($('#' + prefix + '-target') || {}).value || '').trim() || SANDBOX_DEFAULT_URL;
    const file = fileInput && fileInput.files && fileInput.files[0];
    if (msgEl) msgEl.textContent = '';
    if (!file) { toast('Select an OpenAPI 3.x file first', true); return; }
    try {
      if (msgEl) msgEl.textContent = 'Preparing project…';
      await ensureProjects();
      if (!state.project) {
        const project = await apiRequest('/api/projects', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: 'Workspace API', description: 'Created by SentinelAPI workspace', base_url: target }),
        });
        state.projects = [project];
        state.project = project.id;
      }
      if (msgEl) msgEl.textContent = 'Uploading specification…';
      const form = new FormData();
      form.append('project_id', state.project);
      form.append('file', file, file.name);
      const scan = await apiRequest('/api/scans', { method: 'POST', body: form });
      state.scan = scan.id;
      localStorage.setItem(SCAN_KEY, state.scan);
      if (msgEl) msgEl.textContent = 'Starting scan…';
      const identities = {};
      const a = (($('#' + prefix + '-identity-a') || {}).value || '').trim();
      const b = (($('#' + prefix + '-identity-b') || {}).value || '').trim();
      if (a) identities.user_a = a;
      if (b) identities.user_b = b;
      await apiRequest('/api/scans/' + encodeURIComponent(state.scan) + '/start', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_url: target, identities: identities }),
      });
      state.demo = prefix === 'demo';
      if (state.demo) localStorage.setItem(DEMO_KEY, '1');
      else localStorage.removeItem(DEMO_KEY);
      state.scans = state.scans.filter((item) => item.id !== scan.id);
      state.scans.unshift(scan);
      state.findings = []; state.dashboard = null; state.report = null; state.finding = null;
      toast('Scan started');
      go('live');
    } catch (error) {
      if (msgEl) msgEl.textContent = error.message;
      handleApiError(error, 'Could not start the scan');
    }
  };

  // -------------------------------------------------------------- demo view
  function renderDemo() {
    const signedIn = !!state.token;
    return '<div class="landing-shell"><div class="landing-grid"></div>' +
      '<nav class="landing-nav">' +
        '<div class="landing-brand"><div class="landing-logo">✦</div><span>SentinelAPI</span></div>' +
        '<button class="landing-cta" onclick="go(\'landing\')">← Back</button>' +
      '</nav>' +
      '<main class="landing-hero" style="grid-template-columns:1fr;max-width:780px">' +
        '<div class="demo-banner" style="width:100%"><b>Demo Workspace</b><span>Demo data — not a real security scan. The real scan engine runs against an intentionally vulnerable sandbox API.</span></div>' +
        '<div class="login-card" style="width:100%">' +
          '<h1 style="margin-top:0">Try the scanner on the sandbox</h1>' +
          '<p>Upload any OpenAPI 3.x document and scan the authorized sandbox target (' + esc(SANDBOX_DEFAULT_URL) + '). Findings, evidence and PoC requests are produced by the real scan engine against deliberately vulnerable demo endpoints.</p>' +
          (signedIn
            ? scanFormHtml('demo')
            : '<p class="muted">Sign in to run the demo scan — results are stored in your own workspace.</p>' +
              '<button class="landing-primary" style="width:100%" onclick="openLogin(\'config\')">Sign in to continue →</button>') +
        '</div>' +
      '</main>' +
    '</div>';
  }
  views.demo = { public: true, render: renderDemo };

  // ----------------------------------------------------------------- router
  function go(key) {
    if (!views[key]) key = 'landing';
    const view = views[key];
    const appEl = document.querySelector('.app');
    currentView = key;
    if (view.public) {
      toggleDrawer(false);
      appEl.style.display = 'none';
      let lp = document.getElementById('landing-root');
      if (!lp) { lp = document.createElement('div'); lp.id = 'landing-root'; document.body.appendChild(lp); }
      lp.innerHTML = view.render();
      window.scrollTo(0, 0);
    } else {
      document.getElementById('landing-root') && document.getElementById('landing-root').remove();
      appEl.style.display = 'flex';
      $('#page').innerHTML = demoBanner() + view.render();
      highlightNav(key);
      $('.content').scrollTo({ top: 0 });
    }
    if (history.replaceState) history.replaceState(null, '', '#' + key);
    if (typeof view.after === 'function') view.after();
  }
  window.go = go;

  function requireScanView(renderFn, loadFn) {
    if (!state.scan) return { html: head('No scan', '', '') + emptyNoScan(), after: null };
    return { html: renderFn(), after: loadFn };
  }

  // ------------------------------------------------------ findings data access
  async function loadFindings() {
    if (!state.scan) return [];
    const base = '/api/scans/' + encodeURIComponent(state.scan) + '/findings';
    const first = await apiRequest(base + '?page=1&limit=100');
    const total = Number(first.total || (first.items || []).length);
    const items = Array.isArray(first.items) ? first.items.slice() : [];
    const pages = Math.ceil(total / 100);
    for (let page = 2; page <= pages; page += 1) {
      const result = await apiRequest(base + '?page=' + page + '&limit=100');
      if (Array.isArray(result.items)) items.push(...result.items);
    }
    state.findings = items;
    state.findingsTotal = total;
    return state.findings;
  }

  function findingMatches(f, q) {
    if (!q) return true;
    const hay = [f.title, f.type, f.status, f.severity,
      f.endpoint && f.endpoint.method, f.endpoint && f.endpoint.path]
      .join(' ').toLowerCase();
    return hay.indexOf(q) >= 0;
  }

  // --------------------------------------------------------------- overview
  function ringHtml(pct, label) {
    const p = Math.max(0, Math.min(100, Number(pct) || 0));
    return '<div class="ring" style="background:conic-gradient(var(--accent) 0 ' + p + '%,rgba(130,160,170,.18) ' + p + '% 100%)">' +
      '<div><strong>' + Math.round(p) + '%</strong>' + (label ? '<small>' + esc(label) + '</small>' : '') + '</div></div>';
  }

  function donutHtml(sev, total) {
    const parts = [
      ['var(--danger)', sev.critical], ['#df7a00', sev.high],
      ['#bb8700', sev.medium], ['var(--accent2)', sev.low],
    ];
    const sum = parts.reduce((a, p) => a + Number(p[1] || 0), 0);
    let acc = 0, stops = [];
    parts.forEach(([color, n]) => {
      const from = sum ? (acc / sum) * 100 : 0;
      acc += Number(n || 0);
      const to = sum ? (acc / sum) * 100 : 0;
      stops.push(color + ' ' + from + '% ' + to + '%');
    });
    stops.push('rgba(130,160,170,.25) 0 100%');
    return '<div class="donut" style="background:conic-gradient(' + stops.join(',') + ')">' +
      '<div>' + esc(total) + '</div></div>';
  }

  function renderOverview() {
    return head('Security Overview', 'Live metrics from your selected API scan',
      '<button class="btn primary" onclick="go(\'config\')">New Scan →</button>') +
      '<div class="grid four" style="margin-bottom:12px" id="ov-stats">' +
      stateBlock('loading', 'Loading dashboard…', 'Fetching metrics from the backend.') + '</div>' +
      '<div class="grid overview-grid" id="ov-body"></div>';
  }

  async function loadOverview() {
    let dash;
    try {
      await ensureScan();
      if (!state.scan) { const el = $('#ov-stats'); if (el) el.innerHTML = emptyNoScan(); return; }
      dash = await apiRequest('/api/scans/' + encodeURIComponent(state.scan) + '/dashboard');
      state.dashboard = dash;
      await loadFindings();
    } catch (error) {
      const el = $('#ov-stats');
      if (el) el.innerHTML = stateBlock('error', 'Unable to load dashboard', error.message,
        '<button class="btn" onclick="go(\'overview\')">Retry</button>');
      return;
    }
    const sev = dash.severity || { critical: 0, high: 0, medium: 0, low: 0 };
    const statsEl = $('#ov-stats');
    if (!statsEl) return;
    statsEl.innerHTML =
      stat('✦', 'Security Score', dash.security_score, 'Based on verified findings') +
      stat('△', 'Findings', dash.findings, dash.scan_status) +
      stat('✓', 'Tests Completed', dash.tests_completed, 'of ' + dash.tests_run + ' run') +
      stat('◉', 'Endpoints', dash.endpoints, 'discovered from spec');
    const bodyEl = $('#ov-body');
    if (!bodyEl) return;
    const statusPillHtml = pill(statusClass(dash.scan_status), dash.scan_status);
    bodyEl.innerHTML =
      card('Latest Scan Status',
        ringHtml(dash.security_score, 'security score') +
        '<div class="current-list"><div>◉ Status ' + statusPillHtml + '</div>' +
        '<div>◉ Scan ID <b style="font-size:12px">' + esc(dash.scan_id) + '</b></div>' +
        '<div>◉ Duration ' + (dash.scan_duration != null ? esc(dash.scan_duration + 's') : 'Calculating…') + '</div></div>',
        statusPillHtml) +
      card('Issue Distribution',
        '<div style="display:flex;gap:18px;align-items:center;justify-content:center;padding:10px 0 18px;flex-wrap:wrap">' +
        donutHtml(sev, dash.findings) +
        '<div style="display:flex;flex-direction:column;gap:9px;font-size:14px">' +
        '<div>' + severityPill('critical') + ' <span>' + sev.critical + '</span></div>' +
        '<div>' + severityPill('high') + ' <span>' + sev.high + '</span></div>' +
        '<div>' + severityPill('medium') + ' <span>' + sev.medium + '</span></div>' +
        '<div>' + severityPill('low') + ' <span>' + sev.low + '</span></div>' +
        '</div></div>' +
        '<div class="grid three"><div><div class="label">Open</div><b>' +
        state.findings.filter((f) => (f.status || '') !== 'resolved').length + '</b></div>' +
        '<div><div class="label">Resolved</div><b>' +
        state.findings.filter((f) => (f.status || '') === 'resolved').length + '</b></div>' +
        '<div><div class="label">Total</div><b>' + state.findingsTotal + '</b></div></div>');
  }
  views.overview = { render: renderOverview, after: loadOverview };

  // ----------------------------------------------------------- scan config
  function renderConfig() {
    return head('Scan Configuration', 'Upload an OpenAPI document and scan the authorized sandbox API.',
      '<button class="btn" onclick="go(\'overview\')">Overview</button>') +
      '<div class="scan-config"><div class="card">' +
      '<div class="section-title"><h3>Authorized API</h3><span class="pill good">Sandbox only</span></div>' +
      '<p class="muted" style="font-size:13px">Zero-Trust policy: only explicitly allow-listed sandbox targets (localhost, private ranges) can be scanned.</p>' +
      scanFormHtml('config') + '</div>' +
      '<div class="card profile"><div class="section-title"><h3>Security Tests</h3><span class="muted">Deterministic engine</span></div>' +
      '<div class="checks"><label class="check"><input checked disabled type="checkbox"> BOLA / IDOR</label>' +
      '<label class="check"><input checked disabled type="checkbox"> BOPLA / data exposure</label>' +
      '<label class="check"><input checked disabled type="checkbox"> Evidence capture</label>' +
      '<label class="check"><input checked disabled type="checkbox"> Reproducible PoC</label></div>' +
      '<div class="profile-art" style="margin-top:14px"><div><div class="cube"><span>▦</span></div>' +
      '<b style="display:block">Ready to scan</b><small class="muted">Configure a target and upload a specification.</small></div></div></div></div>' +
      (state.scans.length ? '' : '');
  }
  views.config = { render: renderConfig };

  // ------------------------------------------------------------- live view
  function renderLive() {
    const s = state.status;
    const controls = [];
    if (s && (s.status === 'queued' || s.status === 'running')) {
      controls.push('<button class="btn danger" onclick="cancelScan()">Cancel scan</button>');
    }
    return head('Live Security Scan', 'Live progress from the SentinelAPI scan manager.',
      '<button class="btn" onclick="go(\'findings\')">View Findings →</button>') +
      '<div class="scan-live"><div class="card" id="live-card">' +
      stateBlock('loading', 'Loading scan status…', 'Connecting to the backend scan manager.') + '</div>' +
      '<div class="card"><div class="section-title"><h3>Scan Details</h3><span class="muted">polled every second</span></div>' +
      '<div id="live-details" class="log">Loading…</div>' +
      '<p class="muted" style="font-size:12px">Pause/Resume is not supported by the backend scan engine — only queued, running, completed, failed and cancelled states exist.</p>' +
      '</div></div>';
  }

  async function loadLive() {
    await renderLiveStatus();
    startLiveUpdates();
  }

  async function renderLiveStatus() {
    let s;
    try {
      if (!state.scan) { const c = $('#live-card'); if (c) c.innerHTML = emptyNoScan(); return; }
      s = await apiRequest('/api/scans/' + encodeURIComponent(state.scan) + '/status');
      state.status = s;
    } catch (error) {
      const c = $('#live-card');
      if (c) c.innerHTML = stateBlock('error', 'Unable to load scan status', error.message,
        '<button class="btn" onclick="go(\'live\')">Retry</button>');
      return;
    }
    const cardEl = $('#live-card');
    if (!cardEl) return;
    const status = String(s.status || 'unknown');
    const finished = status === 'completed' || status === 'failed' || status === 'cancelled';
    const progress = Math.max(0, Math.min(100, Number(s.progress) || 0));
    const controls = (!finished && (status === 'queued' || status === 'running'))
      ? '<button class="btn danger" onclick="cancelScan()">Cancel scan</button>' : '';
    const targetRow = s.target_url ? '<div>◉ Target <b style="font-size:12px">' + esc(s.target_url) + '</b></div>' : '';
    cardEl.innerHTML =
      '<div class="section-title"><h3>Live Security Scan</h3>' + pill(statusClass(status), status) + '</div>' +
      ringHtml(status === 'completed' ? 100 : progress, finished ? status : 'running') +
      '<div class="progress"><span style="width:' + progress + '%"></span></div>' +
      '<div class="live-list" style="margin-top:15px">' +
      '<div class="live-row"><span class="dot ' + (status !== 'unknown' ? '' : 'off') + '"></span>Status: ' + esc(status) + '</div>' +
      '<div class="live-row"><span class="dot"></span>Endpoints discovered: ' + esc(s.endpoints_discovered) + '</div>' +
      '<div class="live-row"><span class="dot"></span>Tests: ' + esc(s.tests_completed) + ' / ' + esc(s.tests_generated) + ' generated</div>' +
      '<div class="live-row"><span class="dot"></span>Findings so far: ' + esc(s.findings) + '</div>' +
      targetRow +
      '</div><div style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap">' + controls +
      (finished ? '<button class="btn primary" onclick="go(\'overview\')">Open dashboard →</button>' : '') +
      '</div>';
    const details = $('#live-details');
    if (details) details.textContent = JSON.stringify(s, null, 2);
  }

  window.cancelScan = async function () {
    if (!state.scan) return;
    if (!window.confirm('Cancel the running scan? Findings gathered so far are kept.')) return;
    try {
      await apiRequest('/api/scans/' + encodeURIComponent(state.scan) + '/cancel', { method: 'POST' });
      toast('Scan cancelled');
      await renderLiveStatus();
    } catch (error) {
      handleApiError(error, 'Could not cancel the scan');
    }
  };

  function startLiveUpdates() {
    stopLiveUpdates();
    state.poller = window.setInterval(renderLiveStatus, 1000);
    if (state.scan && window.WebSocket) {
      try {
        const wsBase = API_BASE.replace(/^http/, 'ws');
        // Auth: token rides the sub-protocol (browser WS cannot set headers).
        // The server closes with 1008/4404 when auth/ownership fails; the
        // 1s status poll remains authoritative either way.
        state.socket = new WebSocket(
          wsBase + '/ws/scans/' + encodeURIComponent(state.scan),
          ['bearer', state.token]
        );
        state.socket.onmessage = () => renderLiveStatus();
        state.socket.onerror = () => { try { state.socket.close(); } catch (_) { /* polling remains */ } };
      } catch (_) { /* polling remains authoritative */ }
    }
  }

  function stopLiveUpdates() {
    if (state.poller) { clearInterval(state.poller); state.poller = 0; }
    if (state.socket) { try { state.socket.close(); } catch (_) { /* ignore */ } state.socket = null; }
  }
  views.live = { render: renderLive, after: loadLive };

  // ---------------------------------------------------------- network graph
  function renderNetwork() {
    return head('Attack Surface', 'Endpoints discovered from your specification, with live risk levels.', '') +
      '<div class="network"><div class="card"><div class="section-title"><h3>Endpoint Graph</h3>' +
      '<span class="muted" id="net-count">Loading…</span></div>' +
      '<div class="graph"><svg viewBox="0 0 800 500" preserveAspectRatio="xMidYMid meet" id="net-svg"></svg></div></div>' +
      '<div>' + card('Endpoint Risk', '<div id="net-list">' +
      stateBlock('loading', 'Loading endpoints…', 'Fetching attack surface from the backend.') + '</div>') + '</div></div>';
  }

  async function loadNetwork() {
    let data;
    try {
      if (!state.scan) { const l = $('#net-list'); if (l) l.innerHTML = emptyNoScan(); const c = $('#net-count'); if (c) c.textContent = ''; return; }
      data = await apiRequest('/api/scans/' + encodeURIComponent(state.scan) + '/endpoints?page=1&limit=100');
    } catch (error) {
      const l = $('#net-list');
      if (l) l.innerHTML = stateBlock('error', 'Unable to load endpoints', error.message,
        '<button class="btn" onclick="go(\'network\')">Retry</button>');
      return;
    }
    const items = data.items || [];
    const count = $('#net-count');
    if (count) count.textContent = items.length + ' of ' + data.total + ' endpoints';
    const listEl = $('#net-list');
    if (listEl) {
      listEl.innerHTML = items.length ? items.map((ep) =>
        '<div class="finding">' + pill(String(ep.risk_level || 'SAFE').toLowerCase(), ep.risk_level || 'SAFE') +
        '<div><b>' + esc(ep.method) + ' ' + esc(ep.path) + '</b>' +
        '<small>' + (ep.authentication_required ? 'auth required' : 'no auth declared') +
        ' · ' + ep.related_findings + ' findings</small></div></div>').join('')
        : stateBlock('empty', 'No endpoints found', 'This scan has no stored endpoints yet.');
    }
    const svg = $('#net-svg');
    if (!svg) return;
    if (!items.length) {
      svg.innerHTML = '<text x="400" y="250" text-anchor="middle" class="node-label">No endpoints to display</text>';
      return;
    }
    const n = items.length, cx = 400, cy = 250, r = Math.min(190, 120 + n * 8);
    let edges = '', nodes = '';
    items.slice(0, 14).forEach((ep, i) => {
      const angle = (i / Math.min(n, 14)) * Math.PI * 2 - Math.PI / 2;
      const x = cx + r * Math.cos(angle), y = cy + r * 0.62 * Math.sin(angle);
      const color = { CRITICAL: 'var(--danger)', HIGH: 'var(--warn)', MEDIUM: '#bb8700', LOW: 'var(--accent2)', SAFE: 'var(--accent)' }[ep.risk_level] || 'var(--accent)';
      edges += '<path d="M' + cx + ' ' + cy + ' L' + x + ' ' + y + '" stroke="var(--line)" opacity=".7"/>';
      nodes += '<circle cx="' + x + '" cy="' + y + '" r="14" fill="var(--panel)" stroke="' + color + '" stroke-width="3"/>' +
        '<text x="' + x + '" y="' + (y - 20) + '" text-anchor="middle" class="node-sub">' + esc(ep.method) + '</text>' +
        '<text x="' + x + '" y="' + (y + 30) + '" text-anchor="middle" class="node-sub">' + esc(ep.path.length > 22 ? ep.path.slice(0, 21) + '…' : ep.path) + '</text>';
    });
    svg.innerHTML = edges + nodes +
      '<circle cx="' + cx + '" cy="' + cy + '" r="30" fill="var(--panel)" stroke="var(--accent)" stroke-width="3"/>' +
      '<text x="' + cx + '" y="' + (cy + 4) + '" text-anchor="middle" class="node-label">API</text>';
  }
  views.network = { render: renderNetwork, after: loadNetwork };

  // --------------------------------------------------------- findings view
  function filteredFindings() {
    return state.findings.filter((f) => {
      if (state.filters.severity && String(f.severity || '').toLowerCase() !== state.filters.severity) return false;
      if (state.filters.status && String(f.status || '').toLowerCase() !== state.filters.status) return false;
      return findingMatches(f, state.filters.query);
    });
  }

  function renderFindings() {
    return head('Findings', 'Verified findings from the selected scan, generated by the scan engine.',
      '<button class="btn" onclick="go(\'report\')">Report →</button>') +
      '<div class="card"><div class="section-title"><h3>Finding Explorer</h3>' +
      '<span class="muted" id="f-count"></span></div>' +
      '<div style="display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap">' +
      '<select id="f-severity" class="btn" aria-label="Filter by severity">' +
      '<option value="">All severities</option>' + SEVERITIES_UPPER.map((s) => '<option value="' + s + '">' + s.charAt(0) + s.slice(1).toLowerCase() + '</option>').join('') +
      '</select>' +
      '<select id="f-status" class="btn" aria-label="Filter by status">' +
      '<option value="">All statuses</option>' + FINDING_STATUSES.map((s) => '<option value="' + s + '">' + esc(s) + '</option>').join('') +
      '</select>' +
      '<input id="f-query" class="btn" style="flex:1;min-width:160px" placeholder="Filter by title, type, endpoint…" aria-label="Filter findings"></div>' +
      '<div id="f-table">' + stateBlock('loading', 'Loading findings…', 'Fetching findings from the backend.') + '</div></div>';
  }

  function findingsTableHtml(rows) {
    const cols = '<tr><th>Severity</th><th>Title</th><th>Endpoint</th><th>Status</th><th>Age</th><th></th></tr>';
    if (!rows.length) {
      const filtered = state.filters.severity || state.filters.status || state.filters.query;
      return '<div class="table-wrapper"><table class="table">' + cols + '</table></div>' +
        stateBlock('empty', filtered ? 'No matching findings' : 'No findings found',
          filtered ? 'No findings match the current filters.' : 'This scan has not produced any findings yet.');
    }
    return '<div class="table-wrapper"><table class="table">' + cols +
      rows.map((f) => '<tr>' +
        '<td>' + severityPill(f.severity) + '</td>' +
        '<td><b>' + esc(f.title) + '</b><br><small class="muted">' + esc(f.type || '') + '</small></td>' +
        '<td>' + esc(f.endpoint ? (f.endpoint.method + ' ' + f.endpoint.path) : '—') + '</td>' +
        '<td>' + pill(String(f.status || 'open').toLowerCase(), f.status || 'open') + '</td>' +
        '<td>' + esc(timeAgo(f.created_at)) + '</td>' +
        '<td><button class="btn" onclick="openFinding(\'' + esc(f.id) + '\')">View</button></td></tr>').join('') +
      '</table></div>';
  }

  function bindFindingFilters() {
    const sev = $('#f-severity'), st = $('#f-status'), q = $('#f-query');
    if (sev) { sev.value = state.filters.severity; sev.onchange = () => { state.filters.severity = sev.value; paintFindings(); }; }
    if (st) { st.value = state.filters.status; st.onchange = () => { state.filters.status = st.value; paintFindings(); }; }
    if (q) { q.value = state.filters.query; q.oninput = () => { state.filters.query = q.value; paintFindings(); }; }
  }

  async function paintFindings() {
    const wrap = $('#f-table');
    if (!wrap) return;
    const rows = filteredFindings();
    wrap.innerHTML = findingsTableHtml(rows);
    const c = $('#f-count');
    if (c) c.textContent = rows.length + ' shown · ' + state.findingsTotal + ' total';
    bindFindingFilters();
  }

  async function loadFindingsView() {
    try {
      await ensureScan();
      if (!state.scan) { const w = $('#f-table'); if (w) w.innerHTML = emptyNoScan(); return; }
      await loadFindings();
    } catch (error) {
      const w = $('#f-table');
      if (w) {
        w.innerHTML = stateBlock('error', 'Unable to load findings', error.message,
          '<button class="btn" onclick="go(\'findings\')">Retry</button>');
      }
      return;
    }
    await paintFindings();
  }
  views.findings = { render: renderFindings, after: loadFindingsView };

  window.openFinding = async function (id) {
    try {
      state.finding = await apiRequest('/api/findings/' + encodeURIComponent(id));
      go('investigation');
    } catch (error) {
      handleApiError(error, 'Could not open the finding');
    }
  };

  // ---------------------------------------------------- investigation view
  function renderInvestigation() {
    if (!state.finding) {
      return head('Finding Investigation', 'Select a finding from the explorer.',
        '<button class="btn" onclick="go(\'findings\')">← Back</button>') +
        stateBlock('empty', 'No finding selected', 'Open the Finding Explorer and choose a finding to investigate.',
          '<button class="btn primary" onclick="go(\'findings\')">Open Finding Explorer</button>');
    }
    const f = state.finding;
    return head('Finding Investigation', f.title || '',
      '<button class="btn" onclick="go(\'findings\')">← Back</button>') +
      '<div class="investigate"><div class="card">' +
      '<div class="section-title">' + severityPill(f.severity) + pill(String(f.status || 'open').toLowerCase(), f.status || 'open') + '</div>' +
      '<h2 style="margin:0 0 6px">' + esc(f.title) + '</h2>' +
      '<div class="muted">' + esc(f.type || '') + ' · ' + esc(f.endpoint ? (f.endpoint.method + ' ' + f.endpoint.path) : 'no endpoint') +
      ' · confidence ' + Math.round((Number(f.confidence) || 0) * 100) + '% · discovered ' + esc(timeAgo(f.created_at)) + '</div>' +
      '<div class="impact" style="margin-top:14px"><b>Description</b><br>' + esc(f.description || 'No description recorded for this finding.') + '</div>' +
      '<div class="impact" style="margin-top:10px"><b>Impact</b><br>' + esc(f.impact || 'No impact statement recorded.') + '</div>' +
      '<div class="recommend" style="margin-top:10px"><b>Remediation</b><br>' + esc(f.remediation || 'No remediation recorded.') + '</div>' +
      '<div style="margin-top:14px"><label class="label" for="f-status-update">Update status</label>' +
      '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:6px">' +
      '<select id="f-status-update" class="btn">' + FINDING_STATUSES.map((s) => '<option value="' + s + '"' + (s === String(f.status || 'open').toLowerCase() ? ' selected' : '') + '>' + esc(s) + '</option>').join('') + '</select>' +
      '<button class="btn primary" onclick="updateFindingStatus()">Save status</button></div></div>' +
      '</div><div>' +
      card('Evidence', '<div class="code">' + esc(f.evidence ? JSON.stringify(f.evidence, null, 2) : 'No evidence stored for this finding.') + '</div>') +
      card('PoC request', '<div class="code">' + esc(f.poc_request || (f.evidence && f.evidence.poc_request) || 'No PoC request stored for this finding.') + '</div>') +
      '</div></div>';
  }

  window.updateFindingStatus = async function () {
    if (!state.finding) return;
    const sel = $('#f-status-update');
    if (!sel) return;
    try {
      state.finding = await apiRequest('/api/findings/' + encodeURIComponent(state.finding.id), {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: sel.value }),
      });
      const updated = state.finding;
      state.findings = state.findings.map((f) => (f.id === updated.id ? Object.assign({}, f, { status: updated.status }) : f));
      toast('Finding status updated to "' + updated.status + '"');
      go('investigation');
    } catch (error) {
      handleApiError(error, 'Could not update the finding status');
    }
  };
  views.investigation = { render: renderInvestigation };

  // -------------------------------------------------------------- PoC view
  function renderPoc() {
    const f = state.finding;
    if (!f) {
      return head('Proof of Concept', 'Reproduce a verified finding in the controlled sandbox.',
        '<button class="btn" onclick="go(\'findings\')">← Back</button>') +
        stateBlock('empty', 'No finding selected', 'Choose a finding first to see its stored PoC request.',
          '<button class="btn primary" onclick="go(\'findings\')">Open Finding Explorer</button>');
    }
    const poc = f.poc_request || (f.evidence && f.evidence.poc_request) || '';
    return head('Proof of Concept', 'Controlled reproduction from verified sandbox evidence.',
      '<button class="btn" onclick="go(\'findings\')">← Back</button>') +
      '<div class="card">' +
      '<div class="section-title"><h3>' + esc(f.title) + '</h3>' + severityPill(f.severity) + '</div>' +
      (poc
        ? '<p class="muted" style="font-size:13px">Reproduce this finding against the authorized sandbox target only. Replace <code>$TOKEN</code> with an identity from your own sandbox.</p>' +
          '<div class="code">' + esc(poc) + '</div>'
        : '<p class="muted">No PoC request was stored for this finding by the scan engine.</p>') +
      '<div class="impact" style="margin-top:12px"><b>Impact</b><br>' + esc(f.impact || 'No impact statement recorded.') + '</div></div>';
  }
  views.poc = { render: renderPoc };

  // --------------------------------------------------------------- AI view
  function renderAi() {
    const f = state.finding;
    if (!f) {
      return head('Finding Explanation', 'Understand the selected issue, its impact and remediation.', '') +
        stateBlock('empty', 'No finding selected', 'Open a finding to see its structured explanation.',
          '<button class="btn primary" onclick="go(\'findings\')">Open Finding Explorer</button>');
    }
    const steps = [
      ['What happened?', f.description || 'No description recorded for this finding.'],
      ['Why is this a problem?', f.impact || 'No impact statement recorded.'],
      ['How to fix it?', f.remediation || 'No remediation recorded.'],
    ];
    return head('Finding Explanation', 'Structured explanation generated from the finding record.',
      '<button class="btn" onclick="go(\'poc\')">PoC →</button>') +
      '<div class="ai-grid"><div class="card"><div class="section-title"><h3>' + esc(f.title) + '</h3>' + severityPill(f.severity) + '</div>' +
      '<div class="steps">' + steps.map((s, i) =>
        '<div class="step"><div class="step-num">' + (i + 1) + '</div><div><b>' + esc(s[0]) + '</b><p>' + esc(s[1]) + '</p></div></div>').join('') +
      '</div></div><div>' +
      card('Next steps',
        '<div class="checkrow"><div class="checkmark">✓</div>Review the evidence and PoC request</div>' +
        '<div class="checkrow"><div class="checkmark">✓</div>Apply the remediation in your API</div>' +
        '<div class="checkrow"><div class="checkmark">✓</div>Update the finding status when resolved</div>' +
        '<button class="btn" style="margin-top:12px" onclick="go(\'investigation\')">Open investigation →</button>') +
      '</div></div>';
  }
  views.ai = { render: renderAi };

  // ------------------------------------------------------------ report view
  function renderReport() {
    return head('Security Report', 'Executive report generated from the selected scan.',
      '<button class="btn" id="share-btn" onclick="shareReport()" title="Copies the API report URL for this scan">Share Report</button>' +
      '<button class="btn primary" onclick="downloadReport()">↓ Download PDF</button>') +
      '<div class="report"><div class="card report-preview" id="report-preview">' +
      stateBlock('loading', 'Loading report…', 'Generating from the backend scan data.') + '</div>' +
      '<div><div class="card" id="report-recommendations">' +
      stateBlock('loading', 'Loading…', '') + '</div>' +
      '<div class="card" style="margin-top:12px" id="report-contents"></div></div></div>';
  }

  async function loadReport() {
    let r;
    try {
      if (!state.scan) { const p = $('#report-preview'); if (p) p.innerHTML = emptyNoScan(); return; }
      r = await apiRequest('/api/scans/' + encodeURIComponent(state.scan) + '/report');
      state.report = r;
    } catch (error) {
      const p = $('#report-preview');
      if (p) p.innerHTML = stateBlock('error', 'Unable to load report', error.message,
        '<button class="btn" onclick="go(\'report\')">Retry</button>');
      return;
    }
    const preview = $('#report-preview');
    if (!preview) return;
    const sev = r.vulnerability_summary || { critical: 0, high: 0, medium: 0, low: 0 };
    const meta = r.scan_metadata || {};
    preview.innerHTML =
      '<div class="section-title"><h3>' + esc(r.title || 'API Vulnerability Report') + '</h3>' + pill(statusClass(r.scan_status), r.scan_status || '') + '</div>' +
      '<div class="current-list"><div>' + severityPill(r.security_score >= 80 ? 'LOW' : r.security_score >= 50 ? 'MEDIUM' : 'HIGH') + ' Security score <b>' + esc(r.security_score) + ' / 100</b></div>' +
      '<div>◉ OpenAPI version: ' + esc(meta.openapi_version || r.openapi_version || '—') + '</div>' +
      '<div>◉ Target: ' + esc(meta.target_url || 'not recorded') + '</div>' +
      '<div>◉ Endpoints discovered: ' + esc(meta.endpoints_discovered != null ? meta.endpoints_discovered : '—') + ' · Tests completed: ' + esc(meta.tests_completed != null ? meta.tests_completed : '—') + '</div>' +
      (r.scan_duration != null ? '<div>◉ Duration: ' + esc(r.scan_duration + 's') + '</div>' : '') + '</div>' +
      '<div class="impact" style="margin-top:14px"><b>Executive summary</b><br>' + esc(r.executive_summary || '') + '</div>';
    const recEl = $('#report-recommendations');
    if (recEl) {
      recEl.innerHTML = '<div class="section-title"><h3>Recommendations</h3></div>' +
        (Array.isArray(r.recommendations) && r.recommendations.length
          ? r.recommendations.map((rec) => '<div class="checkrow"><div class="checkmark">→</div>' + esc(rec) + '</div>').join('')
          : '<p class="muted">No recommendations recorded.</p>');
    }
    const contentsEl = $('#report-contents');
    if (contentsEl) {
      const rows = Array.isArray(r.findings) ? r.findings : [];
      contentsEl.innerHTML = '<div class="section-title"><h3>Findings (' + esc(r.severity_counts ? Object.values(r.severity_counts).reduce((a, b) => a + Number(b || 0), 0) : rows.length) + ')</h3></div>' +
        '<div class="current-list">' +
        '<div>' + severityPill('CRITICAL') + ' <span>' + (r.severity_counts ? r.severity_counts.critical : sev.critical) + '</span></div>' +
        '<div>' + severityPill('HIGH') + ' <span>' + (r.severity_counts ? r.severity_counts.high : sev.high) + '</span></div>' +
        '<div>' + severityPill('MEDIUM') + ' <span>' + (r.severity_counts ? r.severity_counts.medium : sev.medium) + '</span></div>' +
        '<div>' + severityPill('LOW') + ' <span>' + (r.severity_counts ? r.severity_counts.low : sev.low) + '</span></div>' +
        '</div>' +
        (rows.length
          ? '<div style="margin-top:12px;display:flex;flex-direction:column;gap:6px">' + rows.map((f) =>
              '<div class="finding">' + severityPill(f.severity) + '<div><b>' + esc(f.title) + '</b><small class="muted">' +
              esc(f.endpoint ? (f.endpoint.method + ' ' + f.endpoint.path) : (f.type || '')) + '</small></div></div>').join('') + '</div>'
          : '');
    }
  }
  views.report = { render: renderReport, after: loadReport };

  // Minimal client-side PDF generator: builds a real application/pdf from the
  // report data (no server-side PDF endpoint exists — documented limitation).
  function pdfEscape(text) {
    return String(text == null ? '' : text).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
  }

  function buildPdf(lines) {
    const pageW = 595, pageH = 842, margin = 56, lineH = 14, maxLines = Math.floor((pageH - 2 * margin) / lineH);
    const pages = [];
    for (let i = 0; i < lines.length; i += maxLines) pages.push(lines.slice(i, i + maxLines));
    if (!pages.length) pages.push(['(empty report)']);
    const objects = [];
    const pageObjNums = [];
    const contentNums = [];
    const firstPageObj = 4;
    pages.forEach((_, idx) => {
      pageObjNums.push(firstPageObj + idx * 2);
      contentNums.push(firstPageObj + idx * 2 + 1);
    });
    objects[1] = '<< /Type /Catalog /Pages 2 0 R >>';
    objects[2] = '<< /Type /Pages /Kids [' + pageObjNums.map((n) => n + ' 0 R').join(' ') + '] /Count ' + pages.length + ' >>';
    objects[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';
    pages.forEach((pageLines, idx) => {
      let stream = 'BT /F1 11 Tf ' + margin + ' ' + (pageH - margin) + ' Td ' + (lineH + 2) + ' TL\n';
      pageLines.forEach((line) => { stream += '(' + pdfEscape(line) + ') Tj T*\n'; });
      stream += 'ET';
      objects[pageObjNums[idx]] = '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ' + pageW + ' ' + pageH + '] /Resources << /Font << /F1 3 0 R >> >> /Contents ' + contentNums[idx] + ' 0 R >>';
      objects[contentNums[idx]] = { stream: stream };
    });
    let pdf = '%PDF-1.4\n';
    const offsets = [];
    for (let i = 1; i < objects.length; i += 1) {
      offsets[i] = pdf.length;
      const obj = objects[i];
      if (typeof obj === 'string') {
        pdf += i + ' 0 obj\n' + obj + '\nendobj\n';
      } else {
        const bytes = new TextEncoder().encode(obj.stream);
        pdf += i + ' 0 obj\n<< /Length ' + bytes.length + ' >>\nstream\n' + obj.stream + '\nendstream\nendobj\n';
      }
    }
    const xrefPos = pdf.length;
    pdf += 'xref\n0 ' + objects.length + '\n0000000000 65535 f \n';
    for (let i = 1; i < objects.length; i += 1) {
      pdf += String(offsets[i]).padStart(10, '0') + ' 00000 n \n';
    }
    pdf += 'trailer\n<< /Size ' + objects.length + ' /Root 1 0 R >>\nstartxref\n' + xrefPos + '\n%%EOF';
    return new Blob([pdf], { type: 'application/pdf' });
  }

  window.downloadReport = function () {
    const r = state.report;
    if (!r) { toast('Load the report first', true); return; }
    const lines = [
      'SentinelAPI - API Vulnerability Report',
      'Title: ' + (r.title || ''),
      'Scan status: ' + (r.scan_status || '') + '   Security score: ' + (r.security_score != null ? r.security_score + '/100' : 'n/a'),
      'Scan ID: ' + String(r.scan_id || ''),
      '',
      'Executive summary:',
      r.executive_summary || '',
      '',
      'Findings severity: critical=' + (r.severity_counts ? r.severity_counts.critical : '') +
        '  high=' + (r.severity_counts ? r.severity_counts.high : '') +
        '  medium=' + (r.severity_counts ? r.severity_counts.medium : '') +
        '  low=' + (r.severity_counts ? r.severity_counts.low : ''),
      '',
      'Recommendations:',
    ];
    (r.recommendations || []).forEach((rec, i) => lines.push((i + 1) + '. ' + rec));
    lines.push('', 'Findings:');
    (r.findings || []).forEach((f) => {
      lines.push('- [' + (f.severity || '') + '] ' + (f.title || '') + (f.endpoint ? ' (' + f.endpoint.method + ' ' + f.endpoint.path + ')' : ''));
    });
    const blob = buildPdf(lines);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sentinelapi-report-' + String(r.scan_id || 'scan').slice(0, 8) + '.pdf';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
    toast('Report PDF downloaded');
  };

  window.shareReport = async function () {
    if (!state.scan) { toast('No scan selected', true); return; }
    const url = API_BASE + '/api/scans/' + encodeURIComponent(state.scan) + '/report';
    try {
      if (navigator.share) { await navigator.share({ title: 'SentinelAPI Report', url: url }); return; }
      await navigator.clipboard.writeText(url);
      toast('Report API URL copied to clipboard');
    } catch (_) {
      toast(url, true);
    }
  };

  // ------------------------------------------------------------- profile view
  function renderProfile() {
    const u = state.user;
    return head('Profile', 'Your SentinelAPI account identity.',
      '<button class="btn" onclick="go(\'overview\')">Overview</button>') +
      '<div class="scan-config"><div class="card">' +
      '<div class="section-title"><h3>Account</h3><span class="pill good">read-only</span></div>' +
      '<div class="current-list">' +
      '<div>◉ Email <b>' + esc(u ? u.email : '—') + '</b></div>' +
      '<div>◉ User ID <b style="font-size:12px">' + esc(u ? u.id : '—') + '</b></div>' +
      '<div>◉ Status <b>' + (u && u.is_active ? 'active' : 'inactive') + '</b></div>' +
      (u && u.created_at ? '<div>◉ Member since ' + esc(fmtDate(u.created_at)) + '</div>' : '') +
      '</div>' +
      '<p class="muted" style="margin-top:12px;font-size:13px">The backend exposes no profile-update endpoint, so this view is read-only by design.</p>' +
      '</div>' +
      '<div class="card profile"><div class="section-title"><h3>Session</h3></div>' +
      '<button class="btn danger" onclick="signOut()">Sign out</button>' +
      '<p class="muted" style="margin-top:10px;font-size:13px">Signing out clears the local token and returns you to the landing page.</p>' +
      '</div></div>';
  }
  views.profile = { render: renderProfile };

  // ------------------------------------------------------------ settings view
  function renderSettings() {
    return head('Settings', 'Workspace appearance and session controls.', '') +
      '<div class="scan-config"><div class="card">' +
      '<div class="section-title"><h3>Appearance</h3></div>' +
      '<div class="modes" style="gap:8px">' +
      '<button type="button" data-mode="light">☀ Light</button>' +
      '<button type="button" data-mode="dark">◐ Dark</button>' +
      '<button type="button" data-mode="system">Auto</button>' +
      '</div>' +
      '<p class="muted" style="margin-top:10px;font-size:13px">Theme preference is stored locally; Auto follows your operating system.</p>' +
      '</div>' +
      '<div class="card profile"><div class="section-title"><h3>Connection</h3><span class="muted">backend API</span></div>' +
      '<div class="code">' + esc(API_BASE) + '</div>' +
      '<p class="muted" style="margin-top:10px;font-size:13px">The frontend talks to its own origin by default. Set <code>window.SENTINEL_API_BASE</code> before app.js loads to override.</p>' +
      '<div style="margin-top:14px"><button class="btn danger" onclick="signOut()">Sign out</button></div>' +
      '</div></div>';
  }
  views.settings = { render: renderSettings };

  window.signOut = function () {
    signOutLocal();
    toast('Signed out');
    go('landing');
  };

  // ------------------------------------------------------------- global search
  window.performSearch = function (rawQuery) {
    const q = String(rawQuery || '').trim().toLowerCase();
    if (!q) return;
    const finding = state.findings.find((f) => findingMatches(f, q))
      || (state.finding && findingMatches(state.finding, q) ? state.finding : null);
    if (finding) { state.finding = finding; go('investigation'); return; }
    const scan = state.scans.find((s) => String(s.id).toLowerCase().indexOf(q) >= 0 || String(s.title || '').toLowerCase().indexOf(q) >= 0);
    if (scan) { state.scan = scan.id; localStorage.setItem(SCAN_KEY, state.scan); go('live'); return; }
    const project = state.projects.find((p) => String(p.name || '').toLowerCase().indexOf(q) >= 0);
    if (project) { state.project = project.id; go('config'); return; }
    toast('No match for "' + rawQuery + '" in loaded workspace data', true);
  };

  // ------------------------------------------------------------------ boot
  function boot() {
    applyTheme(localStorage.getItem(MODE_KEY) || 'dark');
    buildNav();
    toggleDrawer(false);

    $('#nav-toggle').addEventListener('click', () => toggleDrawer());
    $('#sidebar-overlay').addEventListener('click', closeDrawer);
    $('#profile-btn').addEventListener('click', () => go('profile'));

    const searchEl = $('#search');
    if (searchEl) {
      searchEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); performSearch(searchEl.value); }
      });
    }

    // Delegated: theme buttons also exist inside re-rendered views (settings).
    document.addEventListener('click', (e) => {
      const btn = e.target && e.target.closest ? e.target.closest('.modes button[data-mode]') : null;
      if (btn) applyTheme(btn.dataset.mode);
    });
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
      if ((localStorage.getItem(MODE_KEY) || 'dark') === 'system') applyTheme('system');
    });

    const initial = (location.hash || '').replace('#', '');
    go(views[initial] ? initial : (state.token ? 'overview' : 'landing'));
    if (state.token) {
      apiRequest('/api/auth/me')
        .then((user) => { state.user = user; syncIdentity(); })
        .catch(() => { if (state.token) { signOutLocal(); } });
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();