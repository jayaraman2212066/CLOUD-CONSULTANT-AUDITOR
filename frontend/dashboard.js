// ═══════════════════════════════════════════════════════════════════════
//  CLOUDCONSULTANT AUDITOR — dashboard.js
//  Vanilla JS · All original function signatures preserved
//  API_BASE is relative so it works on Vercel and localhost alike
// ═══════════════════════════════════════════════════════════════════════

const API_BASE = '';

// ── Global State (exact original names) ──────────────────────────────
let rawFindings      = [];
let filteredFindings = [];
let exceptions       = new Set();
let currentTheme     = 'corporate';
let charts           = {};
let iacData          = {};

// ── Paywall / license state ───────────────────────────────────────────
const CB_STATE = {
  licenseKey:        localStorage.getItem('cca_license_key') || '',
  isProActive:       false,
  freeUsesRemaining: parseInt(localStorage.getItem('cca_free_uses') ?? '3', 10),
};

// ── Pagination state ──────────────────────────────────────────────────
let _currentPage  = 1;
const PAGE_SIZE   = 25;

// ── Sort state ────────────────────────────────────────────────────────
let _sortCol = null;
let _sortDir = 'asc';

// ── Active IaC finding ────────────────────────────────────────────────
let _activeIacCheckId = null;
let _activeIacFmt     = 'cli';

// ── Pending action blocked by paywall ────────────────────────────────
let _pendingAction = null;

// ═════════════════════════════════════════════════════════════════════
// SESSION / AUTH HELPERS (unchanged)
// ═════════════════════════════════════════════════════════════════════

function getSessionToken() {
  return localStorage.getItem('session_token') || '';
}

function authHeaders() {
  const t = getSessionToken();
  return t ? { 'X-Session-Token': t } : {};
}

function authFetch(url, opts = {}) {
  opts.headers = Object.assign({}, opts.headers || {}, authHeaders());
  return fetch(url, opts);
}

// ═════════════════════════════════════════════════════════════════════
// INITIALIZATION
// ═════════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  initThemeSwitcher();
  initSidebar();
  initFileUpload();
  loadLicenseStatus();
  loadHistory();
  restoreBranding();
  updateFreeBanner();
  initAgent();
  initLandingMotion();
  loadAccountStatus();
});

let authMode = 'login';

async function loadAccountStatus() {
  try {
    const response = await fetch(`${API_BASE}/account/me`);
    const data = await response.json();
    const button = document.getElementById('cca-account-button');
    if (!button) return;
    if (data.authenticated) {
      button.textContent = data.email;
      button.onclick = () => logoutAccount();
      button.setAttribute('aria-label', 'Sign out account');
      loadAccountHistory();
    }
  } catch (_) { /* account controls are optional */ }
}

async function loadAccountHistory() {
  const list = document.getElementById('cca-history-list');
  if (!list) return;
  try {
    const response = await fetch(`${API_BASE}/account/history`, { credentials: 'same-origin' });
    const data = await response.json();
    if (!response.ok) { list.textContent = data.detail || 'Sign in to view saved history.'; return; }
    list.replaceChildren();
    if (!data.history.length) { list.textContent = 'No saved reports yet.'; return; }
    data.history.forEach(item => {
      const row = document.createElement('div');
      row.className = 'cca-history-item';
      const company = document.createElement('strong');
      company.textContent = item.company_name;
      const summary = document.createElement('span');
      summary.textContent = `${item.score}/100 · ${item.grade} · ${item.date.slice(0, 10)}`;
      row.append(company, summary);
      list.appendChild(row);
    });
  } catch (_) { list.textContent = 'History is temporarily unavailable.'; }
}

function openAuthModal(mode = 'login') {
  authMode = mode;
  toggleAgentPanel(false);
  updateAuthModal();
  const modal = document.getElementById('cca-auth-modal');
  if (modal) { 
    modal.classList.add('is-open'); 
    modal.setAttribute('aria-hidden', 'false'); 
    document.getElementById('cca-auth-email')?.focus(); 
    
    // Dynamically render Google Sign-In button now that the modal is visible
    if (window.google && window.google.accounts) {
      window.google.accounts.id.initialize({
        client_id: "74114039394-q7i7u46a91b6fmrumi8fejbh1ssu7go2.apps.googleusercontent.com",
        callback: handleGoogleCredential,
        context: "signin",
        auto_prompt: false
      });
      window.google.accounts.id.renderButton(
        document.getElementById("google-btn-container"),
        { theme: "outline", size: "large", type: "standard", text: "signin_with", shape: "rectangular" }
      );
    }
  }
}

function closeAuthModal() {
  const modal = document.getElementById('cca-auth-modal');
  if (modal) { modal.classList.remove('is-open'); modal.setAttribute('aria-hidden', 'true'); }
}

function switchAuthMode() { authMode = authMode === 'login' ? 'signup' : 'login'; updateAuthModal(); }

function updateAuthModal() {
  const signup = authMode === 'signup';
  const title = document.getElementById('cca-auth-title');
  const copy = document.getElementById('cca-auth-copy');
  const submit = document.getElementById('cca-auth-submit');
  const switchButton = document.getElementById('cca-auth-switch');
  const password = document.getElementById('cca-auth-password');
  if (title) title.textContent = signup ? 'Keep your audit history close.' : 'Welcome back to your audits.';
  if (copy) copy.textContent = signup ? 'Create an account to save reports and continue across devices.' : 'Sign in to keep your workspace and report history together.';
  if (submit) submit.textContent = signup ? 'Create account' : 'Log in';
  if (switchButton) switchButton.textContent = signup ? 'Already have an account? Log in' : 'Need an account? Sign up';
  if (password) password.autocomplete = signup ? 'new-password' : 'current-password';
}

async function submitAuth(event) {
  event.preventDefault();
  const email = document.getElementById('cca-auth-email')?.value.trim();
  const password = document.getElementById('cca-auth-password')?.value || '';
  const message = document.getElementById('cca-auth-message');
  try {
    const response = await fetch(`${API_BASE}/account/${authMode}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin', body: JSON.stringify({ email, password }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'Account request failed.');
    closeAuthModal();
    await loadAccountStatus();
    showToast(authMode === 'signup' ? 'Account created.' : 'Signed in.', 'success');
  } catch (error) { if (message) message.textContent = error.message; }
}

async function handleGoogleCredential(response) {
  const message = document.getElementById('cca-auth-message');
  try {
    const res = await fetch(`${API_BASE}/account/google`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ credential: response.credential }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Google sign-in failed.');
    closeAuthModal();
    await loadAccountStatus();
    showToast('Signed in with Google.', 'success');
  } catch (error) {
    if (message) message.textContent = error.message;
  }
}

function handleGoogleSignIn() {
  const message = document.getElementById('cca-auth-message');
  if (message) {
    message.textContent = 'Google Sign-in is not configured on this environment. Please use email and password, or configure GOOGLE_CLIENT_ID in the backend.';
  }
}

async function logoutAccount() {
  await fetch(`${API_BASE}/account/logout`, { method: 'POST', credentials: 'same-origin' });
  const button = document.getElementById('cca-account-button');
  if (button) { button.textContent = 'Log in'; button.onclick = () => openAuthModal('login'); button.setAttribute('aria-label', 'Log in'); }
  showToast('Signed out.', 'info');
}

function initLandingMotion() {
  const sections = document.querySelectorAll('.cca-proof-strip, .cca-workflow');
  if (!('IntersectionObserver' in window)) {
    sections.forEach(section => section.classList.add('is-visible'));
    return;
  }
  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) { entry.target.classList.add('is-visible'); observer.unobserve(entry.target); }
    });
  }, { threshold: 0.12 });
  sections.forEach(section => observer.observe(section));
}

// ── Embedded Gemini agent ────────────────────────────────────────────
const agentMessages = [];
let agentRecognition = null;
let agentVoiceEnabled = localStorage.getItem('cca_agent_voice') === '1';

function initAgent() {
  const send = document.getElementById('cca-agent-send');
  const input = document.getElementById('cca-agent-input');
  const mic = document.getElementById('cca-agent-mic');
  const voice = document.getElementById('cca-agent-voice');
  if (!send || !input) return;
  toggleAgentPanel(false);
  updateAgentVoiceButton();
  send.addEventListener('click', () => sendAgentMessage());
  input.addEventListener('keydown', event => {
    if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); sendAgentMessage(); }
  });
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SpeechRecognition || !mic) { if (mic) mic.disabled = true; return; }
  agentRecognition = new SpeechRecognition();
  agentRecognition.lang = document.documentElement.lang || 'en-US';
  agentRecognition.interimResults = false;
  agentRecognition.onstart = () => { mic.classList.add('active'); setAgentStatus('Listening...'); };
  agentRecognition.onend = () => { mic.classList.remove('active'); setAgentStatus('Ready'); };
  agentRecognition.onerror = () => { mic.classList.remove('active'); setAgentStatus('Voice unavailable'); };
  agentRecognition.onresult = event => {
    input.value = event.results[0][0].transcript;
    sendAgentMessage();
  };
  mic.addEventListener('click', () => {
    toggleAgentPanel(true);
    try { agentRecognition.start(); } catch (_) { /* recognition already active */ }
  });
}

function toggleAgentPanel(forceOpen) {
  const panel = document.getElementById('cca-agent');
  const launcher = document.getElementById('cca-agent-launcher');
  if (!panel || !launcher) return;
  const open = typeof forceOpen === 'boolean' ? forceOpen : !panel.classList.contains('is-open');
  panel.classList.toggle('is-open', open);
  panel.setAttribute('aria-hidden', String(!open));
  launcher.setAttribute('aria-expanded', String(open));
  launcher.style.display = open ? 'none' : 'inline-flex';
  if (open) document.getElementById('cca-agent-input')?.focus();
}

function updateAgentVoiceButton() {
  const voice = document.getElementById('cca-agent-voice');
  if (!voice) return;
  voice.classList.toggle('active', agentVoiceEnabled);
  voice.setAttribute('aria-pressed', String(agentVoiceEnabled));
  voice.setAttribute('aria-label', agentVoiceEnabled ? 'Disable AI voice' : 'Enable AI voice');
  voice.textContent = `AI voice: ${agentVoiceEnabled ? 'On' : 'Off'}`;
}

function toggleAgentVoice() {
  agentVoiceEnabled = !agentVoiceEnabled;
  localStorage.setItem('cca_agent_voice', agentVoiceEnabled ? '1' : '0');
  if (!agentVoiceEnabled && window.speechSynthesis) window.speechSynthesis.cancel();
  updateAgentVoiceButton();
}

function setAgentStatus(value) { const el = document.getElementById('cca-agent-status'); if (el) el.textContent = value; }

function agentContext() {
  return {
    company: document.getElementById('companyName')?.value || 'AWS Account',
    loaded: rawFindings.length > 0,
    finding_count: rawFindings.length,
    visible_count: filteredFindings.length,
    exceptions: exceptions.size,
    score: document.getElementById('metricScore')?.textContent || null,
    critical: document.getElementById('metricCritical')?.textContent || null,
    high: document.getElementById('metricHigh')?.textContent || null,
    current_panel: document.querySelector('.cb-panel.active')?.id?.replace('panel-', '') || 'upload',
  };
}

function addAgentMessage(text, role) {
  const list = document.getElementById('cca-agent-messages');
  if (!list) return;
  const item = document.createElement('div');
  item.className = `cca-agent-message ${role}`;
  item.textContent = text;
  list.appendChild(item);
  list.scrollTop = list.scrollHeight;
}

function runAgentAction(action) {
  const actions = {
    upload: () => navigateTo('upload'), dashboard: () => navigateTo('dashboard'),
    findings: () => navigateTo('findings'), iac: () => navigateTo('iac'),
    analyse: () => previewFindings(), generate_report: () => generateReport(),
    generate_ultimate: () => generateUltimateReport(), export_csv: () => exportCSV(),
    export_bundle: () => exportBundle(),
  };
  if (actions[action]) actions[action]();
}

async function sendAgentMessage() {
  const input = document.getElementById('cca-agent-input');
  const send = document.getElementById('cca-agent-send');
  const text = input?.value.trim();
  if (!text || !send) return;
  input.value = '';
  agentMessages.push({ role: 'user', text });
  addAgentMessage(text, 'user');
  send.disabled = true;
  setAgentStatus('Thinking...');
  try {
    const response = await authFetch(`${API_BASE}/agent/chat`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages: agentMessages.slice(-12), context: agentContext() }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'Agent unavailable');
    agentMessages.push({ role: 'assistant', text: data.message });
    addAgentMessage(data.message, 'agent');
    if (data.action) runAgentAction(data.action);
    if (agentVoiceEnabled && window.speechSynthesis && data.message) {
      window.speechSynthesis.cancel();
      window.speechSynthesis.speak(new SpeechSynthesisUtterance(data.message));
    }
  } catch (error) { addAgentMessage(error.message, 'agent'); }
  finally { send.disabled = false; setAgentStatus('Ready'); }
}

// ── Restore branding from localStorage ───────────────────────────────
function restoreBranding() {
  const company = localStorage.getItem('cca_company') || '';
  const color   = localStorage.getItem('cca_color')   || '#1e3a5f';
  if (company) {
    const cn = document.getElementById('companyName');
    const sc = document.getElementById('settingsCompany');
    if (cn) cn.value = company;
    if (sc) sc.value = company;
  }
  updateColorSwatch(color);
  const pc = document.getElementById('primaryColor');
  const sc2 = document.getElementById('settingsColor');
  if (pc)  pc.value  = color;
  if (sc2) sc2.value = color;
}

// ── Sync branding fields ──────────────────────────────────────────────
function syncBrandingField(fieldId, value) {
  const el = document.getElementById(fieldId);
  if (el) el.value = value;
  if (fieldId === 'companyName') localStorage.setItem('cca_company', value);
  if (fieldId === 'primaryColor') {
    localStorage.setItem('cca_color', value);
    updateColorSwatch(value);
    const sw = document.getElementById('settingsColorSwatch');
    if (sw && /^#[0-9a-fA-F]{6}$/.test(value)) sw.style.background = value;
  }
}

function syncLogoField(input) {
  const logoInput = document.getElementById('logoInput');
  if (logoInput && input.files[0]) {
    const dt = new DataTransfer();
    dt.items.add(input.files[0]);
    logoInput.files = dt.files;
  }
}

function updateColorSwatch(hex) {
  const sw = document.getElementById('colorSwatch');
  if (sw && /^#[0-9a-fA-F]{6}$/.test(hex)) sw.style.background = hex;
}

function setPdfTheme(theme) {
  document.querySelectorAll('[data-pdf-theme]').forEach(b => {
    b.classList.toggle('active', b.dataset.pdfTheme === theme);
  });
  const sel = document.getElementById('pdfTheme');
  if (sel) sel.value = theme;
}

// ═════════════════════════════════════════════════════════════════════
// THEME MANAGEMENT
// ═════════════════════════════════════════════════════════════════════

function initThemeSwitcher() {
  // Header theme buttons
  document.querySelectorAll('.cb-theme-btn').forEach(btn => {
    btn.addEventListener('click', () => setTheme(btn.dataset.theme));
  });
  // Restore saved theme
  const saved = localStorage.getItem('cca_theme') || 'dark';
  setTheme(saved);
}

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  document.body.setAttribute('data-theme', theme);
  currentTheme = theme;
  localStorage.setItem('cca_theme', theme);

  // Header buttons
  document.querySelectorAll('.cb-theme-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.theme === theme);
  });

  // Settings swatches
  document.querySelectorAll('.cb-theme-swatch').forEach(s => {
    const isActive = s.dataset.theme === theme;
    s.classList.toggle('active', isActive);
    s.setAttribute('aria-pressed', String(isActive));
  });

  // Sync PDF theme selector
  setPdfTheme(theme);

  // Refresh charts if loaded
  if (Object.keys(charts).length > 0) refreshCharts();
}

// ═════════════════════════════════════════════════════════════════════
// SIDEBAR MANAGEMENT
// ═════════════════════════════════════════════════════════════════════

function initSidebar() {
  // Hamburger toggle (mobile)
  const hamburger = document.getElementById('cb-hamburger');
  const overlay   = document.getElementById('cb-sidebar-overlay');
  const sidebar   = document.getElementById('cb-sidebar');

  if (hamburger) {
    hamburger.addEventListener('click', () => {
      const open = sidebar.classList.toggle('mobile-open');
      overlay.classList.toggle('show', open);
      hamburger.setAttribute('aria-expanded', String(open));
    });
  }

  if (overlay) {
    overlay.addEventListener('click', () => {
      sidebar.classList.remove('mobile-open');
      overlay.classList.remove('show');
      if (hamburger) hamburger.setAttribute('aria-expanded', 'false');
    });
  }

  // Restore collapsed state
  if (localStorage.getItem('cca_sidebar_collapsed') === '1') {
    sidebar.classList.add('collapsed');
  }
}

function toggleSidebar() {
  const sidebar = document.getElementById('cb-sidebar');
  const collapsed = sidebar.classList.toggle('collapsed');
  localStorage.setItem('cca_sidebar_collapsed', collapsed ? '1' : '0');
}

function toggleExportMenu() {
  const toggle  = document.getElementById('cb-export-toggle');
  const submenu = document.getElementById('cb-export-submenu');
  const open    = submenu.classList.toggle('open');
  toggle.classList.toggle('open', open);
  toggle.setAttribute('aria-expanded', String(open));
}

// ═════════════════════════════════════════════════════════════════════
// NAVIGATION
// ═════════════════════════════════════════════════════════════════════

function navigateTo(panelId) {
  // Hide all panels
  document.querySelectorAll('.cb-panel').forEach(p => p.classList.remove('active'));

  // Show target panel
  const target = document.getElementById(`panel-${panelId}`);
  if (target) target.classList.add('active');

  // Update sidebar active state
  document.querySelectorAll('.cb-nav-link').forEach(l => {
    l.classList.toggle('active', l.dataset.panel === panelId);
    l.setAttribute('aria-current', l.dataset.panel === panelId ? 'page' : 'false');
  });

  // Close mobile sidebar
  const sidebar = document.getElementById('cb-sidebar');
  const overlay = document.getElementById('cb-sidebar-overlay');
  if (sidebar.classList.contains('mobile-open')) {
    sidebar.classList.remove('mobile-open');
    overlay.classList.remove('show');
    const hamburger = document.getElementById('cb-hamburger');
    if (hamburger) hamburger.setAttribute('aria-expanded', 'false');
  }

  // Panel-specific actions
  if (panelId === 'findings' && filteredFindings.length > 0) {
    showFindingsContent();
  }
  if (panelId === 'iac' && filteredFindings.length > 0) {
    renderIacList();
  }
}

// ═════════════════════════════════════════════════════════════════════
// FILE UPLOAD
// ═════════════════════════════════════════════════════════════════════

function initFileUpload() {
  const zone  = document.getElementById('uploadZone');
  const input = document.getElementById('fileInput');
  if (!zone || !input) return;

  zone.addEventListener('click', () => input.click());
  zone.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
  });

  zone.addEventListener('dragover', e => {
    e.preventDefault();
    zone.classList.add('drag-over');
  });

  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));

  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file && file.name.endsWith('.json')) handleFileSelect(file);
  });

  input.addEventListener('change', e => {
    if (e.target.files[0]) handleFileSelect(e.target.files[0]);
  });
}

function handleFileSelect(file) {
  const limitMB = CB_STATE.isProActive ? 500 : 50;
  if (file.size > limitMB * 1024 * 1024) {
    showToast(`File exceeds ${limitMB} MB limit. ${CB_STATE.isProActive ? '' : 'Upgrade to a paid plan for up to 500 MB.'}`, 'error');
    return;
  }
  const sizeKB = (file.size / 1024).toFixed(1);
  const label  = `${file.name} (${sizeKB} KB) — Ready to analyse`;
  const nameEl = document.getElementById('fileName');
  const infoEl = document.getElementById('fileInfo');
  const prevBtn = document.getElementById('previewBtn');

  if (nameEl) nameEl.textContent = label;
  if (infoEl) infoEl.classList.add('show');
  if (prevBtn) { prevBtn.disabled = false; prevBtn.setAttribute('aria-disabled', 'false'); }
}

function clearFile() {
  const input   = document.getElementById('fileInput');
  const infoEl  = document.getElementById('fileInfo');
  const prevBtn = document.getElementById('previewBtn');
  const genBtn  = document.getElementById('generateBtn');
  const ultBtn  = document.getElementById('generateUltimateBtn');

  if (input)   input.value = '';
  if (infoEl)  infoEl.classList.remove('show');
  if (prevBtn) { prevBtn.disabled = true; prevBtn.setAttribute('aria-disabled', 'true'); }
  if (genBtn)  { genBtn.disabled  = true; genBtn.setAttribute('aria-disabled', 'true'); }
  if (ultBtn)  { ultBtn.disabled  = true; ultBtn.setAttribute('aria-disabled', 'true'); }

  rawFindings      = [];
  filteredFindings = [];
  exceptions.clear();
  updateExceptionBadge();
  const ctx = document.getElementById('cb-header-context');
  if (ctx) ctx.textContent = '';
}


// ═════════════════════════════════════════════════════════════════════
// LICENSE STATUS
// ═════════════════════════════════════════════════════════════════════

async function loadLicenseStatus() {
  try {
    const resp = await authFetch(`${API_BASE}/license/status`);
    const data = await resp.json();
    const pill = document.getElementById('cb-license-pill');
    const text = document.getElementById('cb-license-pill-text');
    const detail = document.getElementById('licenseStatusDetail');

    if (data.authenticated) {
      CB_STATE.isProActive = true;
      const tier = data.tier.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
      if (pill) { pill.className = 'cb-license-pill pro'; }
      if (text) text.textContent = `${tier} ACTIVE`;
      const rem = data.reports_remaining != null ? `${data.reports_remaining} reports remaining · ` : '';
      if (detail) detail.textContent = `${rem}Expires ${data.expires_at?.slice(0,10) || 'N/A'}`;
      // Update upload limit badge
      const badge = document.getElementById('cb-upload-limit-badge');
      if (badge) badge.innerHTML = `<svg width="12" height="12" aria-hidden="true"><use href="#ic-info"/></svg> 500 MB max`;
    } else {
      CB_STATE.isProActive = false;
      if (pill) { pill.className = 'cb-license-pill free'; }
      if (text) text.textContent = `FREE — ${CB_STATE.freeUsesRemaining} left`;
    }
    updateFreeBanner();
  } catch (_) { /* non-critical */ }
}

function updateFreeBanner() {
  const banner = document.getElementById('cb-free-banner');
  const bannerText = document.getElementById('cb-free-banner-text');
  if (!banner) return;
  if (!CB_STATE.isProActive) {
    banner.style.display = 'flex';
    if (bannerText) {
      bannerText.innerHTML = `You have <strong>${CB_STATE.freeUsesRemaining}</strong> use${CB_STATE.freeUsesRemaining !== 1 ? 's' : ''} remaining on the free tier.`;
    }
  } else {
    banner.style.display = 'none';
  }
}

// ── Activate license ──────────────────────────────────────────────────
async function activateLicense() {
  const input = document.getElementById('licenseKeyInput');
  const msg   = document.getElementById('licenseStatusMsg');
  if (!input || !input.value.trim()) return;

  const key = input.value.trim();
  try {
    const resp = await fetch(`${API_BASE}/license/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license_key: key }),
    });
    const data = await resp.json();

    if (resp.ok && data.session_token) {
      localStorage.setItem('session_token', data.session_token);
      localStorage.setItem('cca_license_key', key);
      CB_STATE.licenseKey   = key;
      CB_STATE.isProActive  = true;
      if (msg) { msg.className = 'cb-license-status-msg show success'; msg.textContent = '✓ PRO ACTIVE — Unlimited reports unlocked.'; }
      await loadLicenseStatus();
      showToast('License activated! PRO features unlocked.', 'success');
    } else {
      if (msg) { msg.className = 'cb-license-status-msg show error'; msg.textContent = data.detail || 'Invalid license key.'; }
      input.classList.add('cb-shake');
      setTimeout(() => input.classList.remove('cb-shake'), 500);
    }
  } catch (_) {
    if (msg) { msg.className = 'cb-license-status-msg show error'; msg.textContent = 'Network error. Please try again.'; }
  }
}

async function activateLicenseFromPricing() {
  const input = document.getElementById('pricingLicenseInput');
  const msg   = document.getElementById('pricingLicenseMsg');
  if (!input || !input.value.trim()) return;

  const key = input.value.trim();
  try {
    const resp = await fetch(`${API_BASE}/license/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license_key: key }),
    });
    const data = await resp.json();

    if (resp.ok && data.session_token) {
      localStorage.setItem('session_token', data.session_token);
      localStorage.setItem('cca_license_key', key);
      CB_STATE.isProActive = true;
      if (msg) { msg.className = 'cb-license-status-msg show success'; msg.textContent = '✓ License activated! PRO features unlocked.'; }
      await loadLicenseStatus();
      showToast('License activated! PRO features unlocked.', 'success');
      setTimeout(() => navigateTo('upload'), 1500);
    } else {
      if (msg) { msg.className = 'cb-license-status-msg show error'; msg.textContent = data.detail || 'Invalid license key.'; }
    }
  } catch (_) {
    if (msg) { msg.className = 'cb-license-status-msg show error'; msg.textContent = 'Network error. Please try again.'; }
  }
}

async function activateLicenseFromPaywall() {
  const input = document.getElementById('paywallLicenseInput');
  const msg   = document.getElementById('paywallLicenseMsg');
  if (!input || !input.value.trim()) return;

  const key = input.value.trim();
  try {
    const resp = await fetch(`${API_BASE}/license/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license_key: key }),
    });
    const data = await resp.json();

    if (resp.ok && data.session_token) {
      localStorage.setItem('session_token', data.session_token);
      localStorage.setItem('cca_license_key', key);
      CB_STATE.isProActive = true;
      closePaywall();
      await loadLicenseStatus();
      showToast('License activated! Proceeding…', 'success');
      if (_pendingAction) { _pendingAction(); _pendingAction = null; }
    } else {
      if (msg) { msg.className = 'cb-license-status-msg show error'; msg.textContent = data.detail || 'Invalid key.'; }
      input.classList.add('cb-shake');
      setTimeout(() => input.classList.remove('cb-shake'), 500);
    }
  } catch (_) {
    if (msg) { msg.className = 'cb-license-status-msg show error'; msg.textContent = 'Network error.'; }
  }
}

function closePaywall() {
  document.getElementById('cb-paywall-modal').classList.remove('show');
}

function showPaywall(pendingFn) {
  _pendingAction = pendingFn || null;
  document.getElementById('cb-paywall-modal').classList.add('show');
}

// ── Paywall gate ──────────────────────────────────────────────────────
function checkPaywall(action) {
  if (CB_STATE.isProActive) return true;
  if (CB_STATE.freeUsesRemaining > 0) {
    // Don't decrement here — server tracks usage; decrement only on success
    return true;
  }
  showPaywall(action);
  return false;
}

// Call after a successful free-tier report generation
function _consumeLocalFreeTier() {
  if (!CB_STATE.isProActive && CB_STATE.freeUsesRemaining > 0) {
    CB_STATE.freeUsesRemaining--;
    localStorage.setItem('cca_free_uses', CB_STATE.freeUsesRemaining);
    updateFreeBanner();
    const pill = document.getElementById('cb-license-pill-text');
    if (pill && !CB_STATE.isProActive) pill.textContent = `FREE — ${CB_STATE.freeUsesRemaining} left`;
  }
}

// ═════════════════════════════════════════════════════════════════════
// PREVIEW FINDINGS  (original signature preserved)
// ═════════════════════════════════════════════════════════════════════

async function previewFindings() {
  const fileInput   = document.getElementById('fileInput');
  const companyName = document.getElementById('companyName').value;

  if (!fileInput.files[0]) { showToast('Please select a JSON file first.', 'error'); return; }

  if (!checkPaywall(() => previewFindings())) return;

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  formData.append('company_name', companyName);

  const steps = [
    'Parsing Prowler JSON…',
    'Deduplicating findings…',
    'Calculating risk score…',
    'Generating MITRE mappings…',
    'Building dashboard…',
  ];
  showCommandProgress(steps, 'Analysing Findings');

  try {
    const response = await authFetch(`${API_BASE}/preview-findings`, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || 'Failed to preview findings');
    }

    const data = await response.json();
    rawFindings      = data.findings;
    filteredFindings = [...rawFindings];

    populateFilters(data);
    renderDashboard(data);
    renderFindingsTable();
    renderExceptionTable();
    populateIacDropdown();

    // Enable generate buttons
    ['generateBtn','generateUltimateBtn','generateBtn2','generateUltimateBtn2'].forEach(id => {
      const el = document.getElementById(id);
      if (el) { el.disabled = false; el.setAttribute('aria-disabled','false'); }
    });

    // Update header context
    const ctx = document.getElementById('cb-header-context');
    if (ctx) ctx.textContent = `${companyName} · ${data.total} findings · Score ${data.score}/100`;

    const gradeDisplay = data.grade_label || data.grade;
    hideCommandProgress(true, `✓ ${data.total} findings loaded — Score ${data.score}/100 (${gradeDisplay})`);
    _consumeLocalFreeTier();
    navigateTo('dashboard');

  } catch (error) {
    hideCommandProgress(false, error.message);
  }
}

// ═════════════════════════════════════════════════════════════════════
// POPULATE FILTER DROPDOWNS  (original logic preserved)
// ═════════════════════════════════════════════════════════════════════

function populateFilters(data) {
  const regions  = new Set();
  const services = Object.keys(data.by_service || {});
  const accounts = new Set();

  rawFindings.forEach(f => { regions.add(f.region); accounts.add(f.account); });

  _populateSelect('filterRegion',  [...regions].sort());
  _populateSelect('filterService', services);
  _populateSelect('filterAccount', [...accounts].sort());
}

function _populateSelect(id, values) {
  const sel = document.getElementById(id);
  if (!sel) return;
  sel.innerHTML = '';
  values.forEach(v => {
    const opt = document.createElement('option');
    opt.value = v; opt.textContent = v; opt.selected = true;
    sel.appendChild(opt);
  });
}

// ═════════════════════════════════════════════════════════════════════
// DASHBOARD RENDERING
// ═════════════════════════════════════════════════════════════════════

function renderDashboard(data) {
  const empty   = document.getElementById('dashboard-empty');
  const content = document.getElementById('dashboardContent');
  if (empty)   empty.style.display   = 'none';
  if (content) content.style.display = 'block';

  // KPI values
  _setText('metricTotal',    data.total);
  _setText('metricCritical', data.severity.critical || 0);
  _setText('metricHigh',     data.severity.high     || 0);
  _setText('metricScore',    `${data.score}/100`);
  // Show full grade label in score delta
  _setText('kpiDeltaScore', data.grade_label || data.grade || 'First scan');

  // KPI deltas
  if (data.trend) {
    const d = data.trend.delta;
    _setDelta('kpiDeltaScore',    d,    `${d >= 0 ? '+' : ''}${d} from last scan`);
    const dc = (data.severity.critical||0) - (data.trend.prev_critical||0);
    _setDelta('kpiDeltaCritical', -dc,  `${dc >= 0 ? '+' : ''}${dc} from last scan`);
    _setText('kpiDeltaTotal',  'Updated');
    _setText('kpiDeltaHigh',   'Updated');
  }

  // Security arc
  renderSecurityArc(data.score, data.grade);

  // Charts
  renderSeverityChart(data.severity);
  renderServiceChart(data.by_service);
  renderTrendChart(data.trend);
}

function _setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function _setDelta(id, positiveIsGood, text) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text;
  el.className = 'cb-kpi-delta ' + (positiveIsGood > 0 ? 'positive' : positiveIsGood < 0 ? 'negative' : '');
}

// ═════════════════════════════════════════════════════════════════════
// SECURITY POSTURE ARC
// ═════════════════════════════════════════════════════════════════════

function renderSecurityArc(score, grade) {
  const fill      = document.getElementById('arcFill');
  const scoreEl   = document.getElementById('arcScore');
  const gradeEl   = document.getElementById('arcGrade');
  const riskLabel = document.getElementById('arcRiskLabel');
  if (!fill) return;

  // Arc path total length for 240° arc on r=80 circle
  // circumference of full circle = 2π×80 ≈ 502.65
  // 240/360 × 502.65 ≈ 335.1
  const arcLen   = 335.1;
  const dashLen  = (score / 100) * arcLen;

  // Grade → color class
  const gradeClass = { A:'a', B:'b', C:'c', D:'d', F:'f' }[grade] || 'f';
  const riskLabels = { A:'LOW RISK', B:'MODERATE RISK', C:'ELEVATED RISK', D:'HIGH RISK', F:'CRITICAL RISK' };
  const riskColors = { A:'var(--cb-low)', B:'#3BAD72', C:'var(--cb-medium)', D:'var(--cb-high)', F:'var(--cb-critical)' };

  // Remove old grade classes
  fill.className = `cb-arc-fill arc-grade-${gradeClass}`;
  fill.style.strokeDasharray = `${dashLen} ${arcLen}`;

  if (scoreEl) {
    scoreEl.textContent = score;
    scoreEl.className   = `cb-arc-score text-grade-${gradeClass}`;
  }
  if (gradeEl) gradeEl.textContent = grade;  // single letter e.g. "F"
  if (riskLabel) {
    riskLabel.textContent = riskLabels[grade] || 'UNKNOWN';
    riskLabel.style.color = riskColors[grade] || 'var(--cb-text-muted)';
  }
}


// ═════════════════════════════════════════════════════════════════════
// CHART RENDERING
// ═════════════════════════════════════════════════════════════════════

function renderSeverityChart(severity) {
  const ctx = document.getElementById('severityChart');
  if (!ctx) return;
  if (charts.severity) charts.severity.destroy();

  const labels = ['Critical','High','Medium','Low','Info'];
  const values = [
    severity.critical      || 0,
    severity.high          || 0,
    severity.medium        || 0,
    severity.low           || 0,
    severity.informational || 0,
  ];
  const colors = [
    getVar('--cb-critical'),
    getVar('--cb-high'),
    getVar('--cb-medium'),
    getVar('--cb-low'),
    getVar('--cb-info'),
  ];
  const total = values.reduce((a,b) => a+b, 0);

  charts.severity = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{ data: values, backgroundColor: colors, borderWidth: 2,
                   borderColor: getVar('--cb-surface') }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      cutout: '65%',
      plugins: {
        legend: {
          position: 'right',
          labels: {
            color: getVar('--cb-text-secondary'),
            font: { size: 12, family: "'Inter', sans-serif" },
            generateLabels(chart) {
              return chart.data.labels.map((label, i) => ({
                text: `${label}  ${values[i]}  (${total ? Math.round(values[i]/total*100) : 0}%)`,
                fillStyle: colors[i],
                strokeStyle: colors[i],
                lineWidth: 0,
                index: i,
              }));
            },
          },
        },
        tooltip: {
          callbacks: {
            label: ctx => ` ${ctx.label}: ${ctx.raw} (${total ? Math.round(ctx.raw/total*100) : 0}%)`,
          },
        },
      },
    },
    plugins: [{
      id: 'centerText',
      afterDraw(chart) {
        const { ctx: c, chartArea: { left, top, right, bottom } } = chart;
        const cx = (left + right) / 2;
        const cy = (top + bottom) / 2;
        c.save();
        c.font = `700 22px 'Inter', sans-serif`;
        c.fillStyle = getVar('--cb-text-primary');
        c.textAlign = 'center';
        c.textBaseline = 'middle';
        c.fillText(total, cx, cy);
        c.restore();
      },
    }],
  });
}

function renderServiceChart(services) {
  const ctx = document.getElementById('serviceChart');
  if (!ctx) return;
  if (charts.service) charts.service.destroy();

  const top10  = Object.entries(services || {}).slice(0, 10);
  const labels = top10.map(([n]) => n);
  const values = top10.map(([,v]) => v);
  const accent = getVar('--cb-accent');

  charts.service = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Findings',
        data: values,
        backgroundColor: accent + 'B3',
        borderColor: accent,
        borderWidth: 1,
        borderRadius: 4,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: c => ` ${c.raw} findings` } },
      },
      scales: {
        x: {
          beginAtZero: true,
          ticks: { color: getVar('--cb-text-muted'), font: { size: 11 } },
          grid:  { color: getVar('--cb-border') },
        },
        y: {
          ticks: { color: getVar('--cb-text-secondary'), font: { size: 11 } },
          grid:  { display: false },
        },
      },
    },
  });
}

function renderTrendChart(trend) {
  const wrap = document.getElementById('trendChartWrap');
  if (!wrap) return;
  if (charts.trend) { charts.trend.destroy(); charts.trend = null; }

  if (!trend) {
    wrap.innerHTML = `
      <div class="cb-empty" style="padding:24px 12px;">
        <svg class="cb-empty-icon" style="width:40px;height:40px;" aria-hidden="true">
          <use href="#ic-trend"/>
        </svg>
        <p class="cb-empty-sub" style="margin:0;font-size:0.8rem;">
          Run a second scan to see your security trend.
        </p>
      </div>`;
    return;
  }

  // Ensure canvas exists (may have been replaced by empty-state innerHTML)
  let ctx = wrap.querySelector('canvas#trendChart');
  if (!ctx) {
    ctx = document.createElement('canvas');
    ctx.id = 'trendChart';
    ctx.setAttribute('aria-label', 'Security score trend chart');
    wrap.innerHTML = '';
    wrap.appendChild(ctx);
  }

  const prevScore = trend.prev_score;
  const currScore = prevScore + trend.delta;
  const improved  = trend.delta >= 0;
  const lineColor = improved ? getVar('--cb-low') : getVar('--cb-critical');

  charts.trend = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [trend.prev_date, 'Current'],
      datasets: [{
        label: 'Security Score',
        data: [prevScore, currScore],
        borderColor: lineColor,
        backgroundColor: lineColor + '1A',
        tension: 0.3,
        fill: true,
        pointRadius: 5,
        pointBackgroundColor: lineColor,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: { legend: { display: false } },
      scales: {
        y: {
          min: 0, max: 100,
          ticks: { color: getVar('--cb-text-muted'), font: { size: 11 } },
          grid:  { color: getVar('--cb-border') },
        },
        x: {
          ticks: { color: getVar('--cb-text-secondary'), font: { size: 11 } },
          grid:  { display: false },
        },
      },
    },
  });
}

function refreshCharts() {
  const accent = getVar('--cb-accent');
  if (charts.service) {
    charts.service.data.datasets[0].backgroundColor = accent + 'B3';
    charts.service.data.datasets[0].borderColor      = accent;
    charts.service.update();
  }
  if (charts.severity) charts.severity.update();
  if (charts.trend)    charts.trend.update();
}

function getVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

// ═════════════════════════════════════════════════════════════════════
// FINDINGS TABLE  (renderFindingsTable — original name preserved)
// ═════════════════════════════════════════════════════════════════════

function renderFindingsTable() {
  showFindingsContent();
  _currentPage = 1;
  _renderPage();
}

function showFindingsContent() {
  const empty   = document.getElementById('findings-empty');
  const content = document.getElementById('findings-content');
  if (empty)   empty.style.display   = filteredFindings.length === 0 ? 'flex' : 'none';
  if (content) content.style.display = filteredFindings.length === 0 ? 'none' : 'block';
}

function _renderPage() {
  const tbody = document.getElementById('findingsTableBody');
  if (!tbody) return;

  // Sort
  let rows = [...filteredFindings];
  if (_sortCol) {
    const sevOrder = { critical:0, high:1, medium:2, low:3, informational:4 };
    rows.sort((a, b) => {
      let av = a[_sortCol] ?? '', bv = b[_sortCol] ?? '';
      if (_sortCol === 'severity') { av = sevOrder[av] ?? 9; bv = sevOrder[bv] ?? 9; }
      if (_sortCol === 'affected') { av = a.affected_count || 1; bv = b.affected_count || 1; }
      if (av < bv) return _sortDir === 'asc' ? -1 : 1;
      if (av > bv) return _sortDir === 'asc' ?  1 : -1;
      return 0;
    });
  }

  const total  = rows.length;
  const pages  = Math.ceil(total / PAGE_SIZE) || 1;
  _currentPage = Math.min(_currentPage, pages);
  const start  = (_currentPage - 1) * PAGE_SIZE;
  const slice  = rows.slice(start, start + PAGE_SIZE);

  tbody.innerHTML = '';
  slice.forEach((f, i) => {
    const globalIdx = start + i + 1;
    const tr = document.createElement('tr');
    tr.setAttribute('data-check-id', f.check_id);
    tr.innerHTML = `
      <td class="cb-td-check">
        <input type="checkbox" class="exception-check" value="${f.check_id}"
               aria-label="Select ${f.check_id}">
      </td>
      <td class="cb-td-muted">${globalIdx}</td>
      <td>${severityBadge(f.severity)}</td>
      <td class="cb-td-mono">${f.check_id}</td>
      <td>${f.title}</td>
      <td>${f.service}</td>
      <td class="col-region cb-td-muted">${f.region}</td>
      <td class="cb-td-muted">${f.affected_count > 0 ? f.affected_count : 1}</td>
    `;
    tr.addEventListener('click', e => {
      if (e.target.type === 'checkbox') return;
      toggleRowDetail(tr, f);
    });
    tbody.appendChild(tr);
  });

  // Pagination info
  const info = document.getElementById('cb-page-info');
  if (info) info.textContent = `Showing ${start+1}–${Math.min(start+PAGE_SIZE, total)} of ${total} findings`;

  renderPaginationBtns(pages);
}

function renderPaginationBtns(pages) {
  const container = document.getElementById('cb-page-btns');
  if (!container) return;
  container.innerHTML = '';

  const prev = document.createElement('button');
  prev.className = 'cb-page-btn';
  prev.textContent = '← Prev';
  prev.disabled = _currentPage === 1;
  prev.addEventListener('click', () => { _currentPage--; _renderPage(); });
  container.appendChild(prev);

  // Page number buttons (max 5 shown)
  const start = Math.max(1, _currentPage - 2);
  const end   = Math.min(pages, start + 4);
  for (let p = start; p <= end; p++) {
    const btn = document.createElement('button');
    btn.className = 'cb-page-btn' + (p === _currentPage ? ' active' : '');
    btn.textContent = p;
    btn.addEventListener('click', (pp => () => { _currentPage = pp; _renderPage(); })(p));
    container.appendChild(btn);
  }

  const next = document.createElement('button');
  next.className = 'cb-page-btn';
  next.textContent = 'Next →';
  next.disabled = _currentPage === pages;
  next.addEventListener('click', () => { _currentPage++; _renderPage(); });
  container.appendChild(next);
}

function sortTable(col) {
  if (_sortCol === col) {
    _sortDir = _sortDir === 'asc' ? 'desc' : 'asc';
  } else {
    _sortCol = col;
    _sortDir = 'asc';
  }
  // Update header indicators
  document.querySelectorAll('.cb-table thead th').forEach(th => {
    th.classList.remove('sort-asc','sort-desc');
    if (th.dataset.col === col) th.classList.add(`sort-${_sortDir}`);
  });
  _renderPage();
}

// Inline row detail expand
function toggleRowDetail(tr, f) {
  const existingDetail = tr.nextElementSibling;
  if (existingDetail && existingDetail.classList.contains('cb-row-detail')) {
    existingDetail.classList.toggle('open');
    return;
  }
  const detailTr = document.createElement('tr');
  detailTr.className = 'cb-row-detail open';
  const colCount = tr.cells.length;
  detailTr.innerHTML = `
    <td colspan="${colCount}">
      <div class="cb-row-detail-inner">
        <div>
          <div class="cb-detail-block-label">Technical Risk</div>
          <div class="cb-detail-block-value">${f.technical_risk || '—'}</div>
        </div>
        <div>
          <div class="cb-detail-block-label">MITRE ATT&CK</div>
          <div class="cb-detail-block-value">${f.mitre_attack || '—'}</div>
        </div>
        <div>
          <div class="cb-detail-block-label">Compliance</div>
          <div class="cb-detail-block-value">${_renderCompliance(f.compliance)}</div>
        </div>
        <div>
          <div class="cb-detail-block-label">Affected Resources</div>
          <div class="cb-detail-block-value cb-td-mono" style="font-size:0.75rem;">
            ${(f.affected_resources || []).slice(0,5).join('<br>') || '—'}
          </div>
        </div>
      </div>
    </td>`;
  tr.after(detailTr);
}

function _renderCompliance(compliance) {
  if (!compliance || !Object.keys(compliance).length) return '—';
  return Object.entries(compliance)
    .map(([k,v]) => `<span class="cb-compliance-badge">${k}: ${v}</span>`)
    .join(' ');
}

// ═════════════════════════════════════════════════════════════════════
// FILTER MANAGEMENT  (original function signatures preserved)
// ═════════════════════════════════════════════════════════════════════

function applyFilters() {
  const severities = Array.from(document.getElementById('filterSeverity').selectedOptions).map(o => o.value);
  const regions    = Array.from(document.getElementById('filterRegion').selectedOptions).map(o => o.value);
  const services   = Array.from(document.getElementById('filterService').selectedOptions).map(o => o.value);
  const accounts   = Array.from(document.getElementById('filterAccount').selectedOptions).map(o => o.value);

  filteredFindings = rawFindings.filter(f =>
    severities.includes(f.severity) &&
    regions.includes(f.region)      &&
    services.includes(f.service)    &&
    accounts.includes(f.account)
  );

  renderFilterChips({ severities, regions, services, accounts });
  updateFilteredCount();
  renderFindingsTable();
  renderExceptionTable();
}

function resetFilters() {
  ['filterSeverity','filterRegion','filterService','filterAccount'].forEach(id => {
    const sel = document.getElementById(id);
    if (sel) Array.from(sel.options).forEach(o => o.selected = true);
  });

  // Reset severity pills
  document.querySelectorAll('.cb-sev-pill').forEach(p => {
    p.className = 'cb-sev-pill' + (p.dataset.sev === 'all' ? ' active-all' : '');
  });

  filteredFindings = [...rawFindings];
  const chips = document.getElementById('filterChips');
  if (chips) chips.innerHTML = '';
  updateFilteredCount();
  renderFindingsTable();
  renderExceptionTable();
  showToast('Filters reset.', 'info');
}

function renderFilterChips(filters) {
  const container = document.getElementById('filterChips');
  if (!container) return;
  container.innerHTML = '';

  const addChips = (label, values, allValues) => {
    if (values.length === allValues) return;
    values.forEach(v => {
      const chip = document.createElement('span');
      chip.className = 'cb-chip';
      chip.innerHTML = `${label}: ${v}
        <button class="cb-chip-remove" onclick="removeFilter('${label}','${v}')"
                aria-label="Remove filter ${label}: ${v}">×</button>`;
      container.appendChild(chip);
    });
  };

  const totalSev = document.getElementById('filterSeverity')?.options.length || 5;
  const totalReg = document.getElementById('filterRegion')?.options.length   || 0;
  const totalSvc = document.getElementById('filterService')?.options.length  || 0;
  const totalAcc = document.getElementById('filterAccount')?.options.length  || 0;

  addChips('Severity', filters.severities, totalSev);
  addChips('Region',   filters.regions,    totalReg);
  addChips('Service',  filters.services,   totalSvc);
  addChips('Account',  filters.accounts,   totalAcc);
}

function updateFilteredCount() {
  const el = document.getElementById('filteredCount');
  if (el) el.textContent = `${filteredFindings.length} of ${rawFindings.length} findings`;
}

function removeFilter(label, value) {
  const map = { Severity:'filterSeverity', Region:'filterRegion', Service:'filterService', Account:'filterAccount' };
  const sel = document.getElementById(map[label]);
  if (sel) {
    Array.from(sel.options).forEach(o => { if (o.value === value) o.selected = false; });
  }
  applyFilters();
}

// Severity pill toggle
function toggleSevPill(btn, sev) {
  const allPills = document.querySelectorAll('.cb-sev-pill');
  const sevSel   = document.getElementById('filterSeverity');

  if (sev === 'all') {
    allPills.forEach(p => {
      p.className = 'cb-sev-pill' + (p.dataset.sev === 'all' ? ' active-all' : '');
    });
    if (sevSel) Array.from(sevSel.options).forEach(o => o.selected = true);
  } else {
    // Deactivate "all" pill
    allPills.forEach(p => { if (p.dataset.sev === 'all') p.className = 'cb-sev-pill'; });
    const isActive = btn.className.includes(`active-${sev}`);
    btn.className  = isActive ? 'cb-sev-pill' : `cb-sev-pill active-${sev}`;
    if (sevSel) {
      Array.from(sevSel.options).forEach(o => {
        if (o.value === sev) o.selected = !isActive;
      });
    }
    // If none active, reset to all
    const anyActive = [...allPills].some(p => p.className.includes('active-') && p.dataset.sev !== 'all');
    if (!anyActive) { toggleSevPill(document.querySelector('[data-sev="all"]'), 'all'); return; }
  }
  applyFilters();
}


// ═════════════════════════════════════════════════════════════════════
// EXCEPTION MANAGEMENT  (original signatures preserved)
// ═════════════════════════════════════════════════════════════════════

function renderExceptionTable() {
  const tbody = document.querySelector('#exceptionTable tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  filteredFindings.filter(f => !exceptions.has(f.check_id)).forEach(f => {
    const row = tbody.insertRow();
    row.innerHTML = `
      <td class="cb-td-check">
        <input type="checkbox" class="exception-check" value="${f.check_id}"
               aria-label="Select ${f.check_id}">
      </td>
      <td class="cb-td-mono">${f.check_id}</td>
      <td>${f.title}</td>
      <td>${severityBadge(f.severity)}</td>
      <td>${f.service}</td>
    `;
  });
}

function toggleSelectAll() {
  // selectAll is in findings panel, selectAll2 is in exceptions panel — check both
  const sa  = document.getElementById('selectAll');
  const sa2 = document.getElementById('selectAll2');
  const checked = (sa && sa.checked) || (sa2 && sa2.checked);
  document.querySelectorAll('.exception-check').forEach(cb => cb.checked = checked);
}

function markAsExceptions() {
  const selected = Array.from(document.querySelectorAll('.exception-check:checked')).map(cb => cb.value);
  if (selected.length === 0) { showToast('Select at least one finding.', 'error'); return; }

  selected.forEach(id => exceptions.add(id));
  renderExceptionsList();
  renderExceptionTable();
  updateExceptionBadge();

  const sa  = document.getElementById('selectAll');
  const sa2 = document.getElementById('selectAll2');
  if (sa)  sa.checked  = false;
  if (sa2) sa2.checked = false;

  showToast(`${selected.length} finding(s) marked as exceptions.`, 'success');
}

function renderExceptionsList() {
  const container = document.getElementById('exceptionsList');
  const countEl   = document.getElementById('exceptionCount');
  if (!container) return;
  if (countEl) countEl.textContent = exceptions.size;

  if (exceptions.size === 0) {
    container.innerHTML = `
      <div class="cb-empty" style="padding:32px 16px;">
        <svg class="cb-empty-icon" style="width:40px;height:40px;" aria-hidden="true">
          <use href="#ic-check"/>
        </svg>
        <p class="cb-empty-sub" style="margin:0;">No false positives marked.</p>
      </div>`;
    return;
  }

  container.innerHTML = '';
  exceptions.forEach(checkId => {
    const finding = rawFindings.find(f => f.check_id === checkId);
    if (!finding) return;
    const item = document.createElement('div');
    item.className = 'cb-exception-item';
    item.innerHTML = `
      <div class="cb-exception-info">
        <div class="cb-exception-id">${finding.check_id}</div>
        <div class="cb-exception-title">${finding.title}</div>
      </div>
      ${severityBadge(finding.severity)}
      <button class="cb-exception-remove" onclick="removeException('${checkId}')"
              aria-label="Remove exception ${checkId}">
        <svg aria-hidden="true"><use href="#ic-x"/></svg>
      </button>
    `;
    container.appendChild(item);
  });
}

function removeException(checkId) {
  exceptions.delete(checkId);
  renderExceptionsList();
  renderExceptionTable();
  updateExceptionBadge();
  showToast('Exception removed.', 'info');
}

function updateExceptionBadge() {
  const badge = document.getElementById('cb-exc-badge');
  if (!badge) return;
  if (exceptions.size > 0) {
    badge.textContent    = exceptions.size;
    badge.style.display  = 'inline-flex';
  } else {
    badge.style.display  = 'none';
  }
}

// ═════════════════════════════════════════════════════════════════════
// IAC SNIPPETS  (original signatures preserved)
// ═════════════════════════════════════════════════════════════════════

function populateIacDropdown() {
  // Legacy hidden select (kept for loadIacSnippet compat)
  const select = document.getElementById('iacFinding');
  if (select) {
    select.innerHTML = '<option value="">-- Select a finding --</option>';
    filteredFindings.forEach(f => {
      const opt = document.createElement('option');
      opt.value = f.check_id;
      opt.textContent = `${f.check_id} - ${f.title}`;
      select.appendChild(opt);
    });
  }
  renderIacList();
}

function renderIacList() {
  const list  = document.getElementById('iacFindingList');
  const empty = document.getElementById('iac-list-empty');
  if (!list) return;

  if (filteredFindings.length === 0) {
    if (empty) empty.style.display = 'flex';
    return;
  }
  if (empty) empty.style.display = 'none';

  // Remove old items (keep empty state div)
  Array.from(list.children).forEach(c => {
    if (!c.id) list.removeChild(c);
  });

  filteredFindings.filter(f => !exceptions.has(f.check_id)).forEach(f => {
    const item = document.createElement('div');
    item.className = 'cb-iac-list-item';
    item.setAttribute('role', 'option');
    item.setAttribute('aria-selected', 'false');
    item.dataset.checkId = f.check_id;
    item.innerHTML = `
      <div class="cb-iac-list-id">${f.check_id}</div>
      <div class="cb-iac-list-title">${f.title}</div>
      ${severityBadge(f.severity)}
    `;
    item.addEventListener('click', () => {
      document.querySelectorAll('.cb-iac-list-item').forEach(i => {
        i.classList.remove('active');
        i.setAttribute('aria-selected','false');
      });
      item.classList.add('active');
      item.setAttribute('aria-selected','true');
      _activeIacCheckId = f.check_id;
      // Sync legacy select
      const sel = document.getElementById('iacFinding');
      if (sel) sel.value = f.check_id;
      loadIacSnippet();
    });
    list.appendChild(item);
  });
}

async function loadIacSnippet() {
  const checkId = document.getElementById('iacFinding')?.value || _activeIacCheckId;
  if (!checkId) return;
  _activeIacCheckId = checkId;
  _showIacSkeleton();

  try {
    const response = await authFetch(
      `${API_BASE}/iac-snippet?check_id=${encodeURIComponent(checkId)}&fmt=${_activeIacFmt}`
    );
    const data = await response.json();
    iacData[checkId] = iacData[checkId] || {};
    iacData[checkId][_activeIacFmt] = data.snippet;
    _showIacCode(data.snippet, _activeIacFmt);
  } catch (_) {
    _showIacCode('# Failed to load snippet. Please try again.', 'bash');
  }
}

async function switchIacTab(fmt) {
  _activeIacFmt = fmt;

  // Update tab active state
  document.querySelectorAll('.cb-iac-tab').forEach(t => {
    const isActive = t.id === `iac-tab-${fmt}`;
    t.classList.toggle('active', isActive);
    t.setAttribute('aria-selected', String(isActive));
  });

  // Legacy iac-tab class support
  document.querySelectorAll('.iac-tab').forEach(t => {
    t.classList.toggle('active', t.getAttribute('onclick')?.includes(`'${fmt}'`));
  });

  if (!_activeIacCheckId) return;

  // Use cached data if available
  if (iacData[_activeIacCheckId]?.[fmt]) {
    _showIacCode(iacData[_activeIacCheckId][fmt], fmt);
    return;
  }

  _showIacSkeleton();
  try {
    const response = await authFetch(
      `${API_BASE}/iac-snippet?check_id=${encodeURIComponent(_activeIacCheckId)}&fmt=${fmt}`
    );
    const data = await response.json();
    iacData[_activeIacCheckId] = iacData[_activeIacCheckId] || {};
    iacData[_activeIacCheckId][fmt] = data.snippet;
    _showIacCode(data.snippet, fmt);
  } catch (_) {
    _showIacCode('# Failed to load snippet.', 'bash');
  }
}

function _showIacSkeleton() {
  const empty    = document.getElementById('iac-code-empty');
  const skeleton = document.getElementById('iac-skeleton');
  const snippet  = document.getElementById('iacSnippet');
  if (empty)    empty.style.display    = 'none';
  if (skeleton) skeleton.style.display = 'block';
  if (snippet)  snippet.style.display  = 'none';
}

function _showIacCode(code, fmt) {
  const skeleton = document.getElementById('iac-skeleton');
  const snippet  = document.getElementById('iacSnippet');
  const codeEl   = document.getElementById('iacCode');
  if (skeleton) skeleton.style.display = 'none';
  if (!snippet || !codeEl) return;

  const langMap = { cli:'bash', terraform:'hcl', cloudformation:'yaml' };
  const lang    = langMap[fmt] || 'bash';

  codeEl.className   = `language-${lang}`;
  codeEl.textContent = code;
  snippet.style.display = 'block';

  // Prism highlight
  if (window.Prism) Prism.highlightElement(codeEl);
}

function copyIacCode() {
  const code = document.getElementById('iacCode')?.textContent || '';
  if (!code) return;
  navigator.clipboard.writeText(code).then(() => {
    const btn = document.getElementById('copyIacBtn');
    if (btn) {
      const orig = btn.innerHTML;
      btn.innerHTML = `<svg aria-hidden="true"><use href="#ic-check"/></svg> Copied ✓`;
      btn.style.color = 'var(--cb-success)';
      setTimeout(() => { btn.innerHTML = orig; btn.style.color = ''; }, 2000);
    }
  });
}

// ═════════════════════════════════════════════════════════════════════
// REPORT GENERATION  (original signatures preserved)
// ═════════════════════════════════════════════════════════════════════

async function generateReport() {
  const fileInput   = document.getElementById('fileInput');
  const companyName = document.getElementById('companyName').value;
  const primaryColor= document.getElementById('primaryColor').value;
  const theme       = document.getElementById('pdfTheme').value;
  const logoInput   = document.getElementById('logoInput');

  if (!fileInput?.files[0]) { showToast('Please upload a JSON file first.', 'error'); return; }

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  formData.append('company_name', companyName);
  formData.append('primary_color', primaryColor);
  formData.append('theme', theme);
  formData.append('exceptions_json', JSON.stringify([...exceptions]));
  if (logoInput?.files[0]) formData.append('logo', logoInput.files[0]);

  const steps = [
    'Parsing Prowler JSON…',
    'Applying exceptions…',
    'Calculating risk score…',
    'Building executive summary…',
    'Generating compliance badges…',
    'Rendering PDF…',
  ];
  showCommandProgress(steps, 'Generating Elite PDF Report');
  showProgress('Generating PDF report...');

  try {
    const response = await authFetch(`${API_BASE}/generate-report`, {
      method: 'POST', body: formData,
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || 'Failed to generate report');
    }

    const blob = await response.blob();
    _downloadBlob(blob, `security_report_${_safeName(companyName)}.pdf`);
    hideCommandProgress(true, '✓ Report ready — Downloading…');
    hideProgress();
    _consumeLocalFreeTier();
    showSuccess('Report generated successfully!');

  } catch (error) {
    hideCommandProgress(false, error.message);
    hideProgress();
    if (error.message?.includes('free_used') || error.message?.includes('limit_reached')) {
      showPaywall(() => generateReport());
    } else {
      showError(error.message);
    }
  }
}

async function generateUltimateReport() {
  const fileInput    = document.getElementById('fileInput');
  const companyName  = document.getElementById('companyName').value;
  const primaryColor = document.getElementById('primaryColor').value;
  const logoInput    = document.getElementById('logoInput');

  if (!fileInput?.files[0]) { showToast('Please upload a JSON file first.', 'error'); return; }

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  formData.append('company_name', companyName);
  formData.append('primary_color', primaryColor);
  if (logoInput?.files[0]) formData.append('logo', logoInput.files[0]);

  const steps = [
    'Parsing Prowler JSON…',
    'Deduplicating findings…',
    'Generating MITRE ATT&CK mappings…',
    'Building CLI + Terraform code blocks…',
    'Rendering risk heatmap…',
    'Compiling 3-phase roadmap…',
    'Generating Ultimate PDF…',
  ];
  showCommandProgress(steps, 'Generating Ultimate Report');
  showProgress('Generating ULTIMATE report...');

  try {
    const response = await authFetch(`${API_BASE}/generate-ultimate-report`, {
      method: 'POST', body: formData,
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || 'Failed to generate ultimate report');
    }

    const blob = await response.blob();
    _downloadBlob(blob, `ultimate_report_${_safeName(companyName)}.pdf`);
    hideCommandProgress(true, '✓ Ultimate Report ready — Downloading…');
    hideProgress();
    showSuccess('ULTIMATE Report generated successfully!');

  } catch (error) {
    hideCommandProgress(false, error.message);
    hideProgress();
    showError(error.message);
  }
}

async function exportCSV() {
  const fileInput = document.getElementById('fileInput');
  if (!fileInput?.files[0]) { showToast('Please upload a JSON file first.', 'error'); return; }

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);

  try {
    const response = await authFetch(`${API_BASE}/export-csv`, { method:'POST', body:formData });
    if (!response.ok) throw new Error('Failed to export CSV');
    const blob = await response.blob();
    _downloadBlob(blob, 'findings.csv');
    showToast('CSV exported successfully!', 'success');
  } catch (error) {
    showToast(error.message, 'error');
  }
}

async function exportBundle() {
  const fileInput    = document.getElementById('fileInput');
  const companyName  = document.getElementById('companyName').value;
  const primaryColor = document.getElementById('primaryColor').value;
  const logoInput    = document.getElementById('logoInput');

  if (!fileInput?.files[0]) { showToast('Please upload a JSON file first.', 'error'); return; }

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  formData.append('company_name', companyName);
  formData.append('primary_color', primaryColor);
  if (logoInput?.files[0]) formData.append('logo', logoInput.files[0]);

  showProgress('Generating evidence bundle...');
  try {
    const response = await authFetch(`${API_BASE}/export-bundle`, { method:'POST', body:formData });
    if (!response.ok) throw new Error('Failed to export bundle');
    const blob = await response.blob();
    _downloadBlob(blob, `evidence_bundle_${_safeName(companyName)}.zip`);
    hideProgress();
    showToast('Evidence bundle downloaded!', 'success');
  } catch (error) {
    hideProgress();
    showToast(error.message, 'error');
  }
}

async function downloadScript(fmt) {
  if (filteredFindings.length === 0) { showToast('No findings to include.', 'error'); return; }

  const findings = filteredFindings
    .filter(f => !exceptions.has(f.check_id))
    .map(f => ({ check_id: f.check_id, title: f.title, severity: f.severity }));

  try {
    const response = await authFetch(`${API_BASE}/download-script?fmt=${fmt}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ findings }),
    });
    if (!response.ok) throw new Error('Failed to generate script');
    const blob = await response.blob();
    _downloadBlob(blob, `remediation_script.${fmt}`);
    showToast('Script downloaded!', 'success');
  } catch (error) {
    showToast(error.message, 'error');
  }
}

async function loadHistory() {
  const companyName = document.getElementById('companyName')?.value || 'AWS Account';
  try {
    const response = await authFetch(
      `${API_BASE}/trend-history?company_name=${encodeURIComponent(companyName)}`
    );
    const data = await response.json();
    if (data.history?.length > 0) console.log('History loaded:', data.history.length, 'entries');
  } catch (_) { /* non-critical */ }
}

// ── Download helper ───────────────────────────────────────────────────
function _downloadBlob(blob, filename) {
  const url = window.URL.createObjectURL(blob);
  const a   = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => window.URL.revokeObjectURL(url), 1000);
}

function _safeName(name) {
  return name.replace(/\s/g, '_').replace(/[^a-zA-Z0-9_]/g, '');
}

// ═════════════════════════════════════════════════════════════════════
// COMMAND PROGRESS PANEL  (replaces showProgress/hideProgress)
// ═════════════════════════════════════════════════════════════════════

let _progressStepTimers = [];

function showCommandProgress(steps, title) {
  const overlay  = document.getElementById('cb-progress-overlay');
  const titleEl  = document.getElementById('cb-progress-title');
  const body     = document.getElementById('cb-progress-body');
  const fill     = document.getElementById('cb-progress-fill');
  const pct      = document.getElementById('cb-progress-pct');
  const footer   = document.getElementById('cb-progress-footer');
  const header   = document.getElementById('cb-progress-header');
  const closeBtn = document.getElementById('cb-progress-close');

  if (!overlay) return;

  // Reset
  _progressStepTimers.forEach(clearTimeout);
  _progressStepTimers = [];
  body.innerHTML = '';
  fill.style.width = '0%';
  pct.textContent  = '0%';
  footer.className = 'cb-progress-footer';
  footer.style.display = 'none';
  header.className = 'cb-progress-header';
  if (closeBtn) closeBtn.style.display = 'none';
  if (titleEl)  titleEl.textContent = title || 'Processing…';

  // Build step elements
  const stepEls = steps.map((text, i) => {
    const div = document.createElement('div');
    div.className = 'cb-progress-step';
    div.innerHTML = `<span class="cb-step-icon">○</span><span class="cb-step-text">${text}</span>`;
    body.appendChild(div);
    return div;
  });

  overlay.classList.add('show');

  // Animate steps sequentially
  const interval = Math.min(800, 4000 / steps.length);
  steps.forEach((_, i) => {
    const t = setTimeout(() => {
      // Mark previous as done
      if (i > 0) {
        stepEls[i-1].className = 'cb-progress-step visible done';
        stepEls[i-1].querySelector('.cb-step-icon').innerHTML = '✓';
      }
      // Mark current as active
      stepEls[i].className = 'cb-progress-step visible active';
      stepEls[i].querySelector('.cb-step-icon').innerHTML = '<span class="cb-step-spinner"></span>';

      // Update progress bar
      const pctVal = Math.round(((i + 1) / steps.length) * 85);
      fill.style.width = `${pctVal}%`;
      pct.textContent  = `${pctVal}%`;
    }, i * interval);
    _progressStepTimers.push(t);
  });
}

function hideCommandProgress(success = true, message = '') {
  const overlay  = document.getElementById('cb-progress-overlay');
  const fill     = document.getElementById('cb-progress-fill');
  const pct      = document.getElementById('cb-progress-pct');
  const footer   = document.getElementById('cb-progress-footer');
  const closeBtn = document.getElementById('cb-progress-close');
  const msgEl    = document.getElementById('cb-progress-footer-msg');
  const header   = document.getElementById('cb-progress-header');
  const body     = document.getElementById('cb-progress-body');

  if (!overlay) return;

  _progressStepTimers.forEach(clearTimeout);
  _progressStepTimers = [];

  // Complete all steps
  body.querySelectorAll('.cb-progress-step').forEach(s => {
    s.className = 'cb-progress-step visible ' + (success ? 'done' : 'active');
    s.querySelector('.cb-step-icon').innerHTML = success ? '✓' : '✗';
  });

  fill.style.width = success ? '100%' : fill.style.width;
  pct.textContent  = success ? '100%' : pct.textContent;

  if (msgEl)  msgEl.textContent = message;
  footer.className = `cb-progress-footer show ${success ? 'success' : 'error'}`;
  if (!success && closeBtn) closeBtn.style.display = 'inline-flex';
  if (!success && header)   header.className = 'cb-progress-header error';

  if (success) {
    setTimeout(() => {
      overlay.classList.remove('show');
    }, 2000);
  }
}

// ── Legacy progress helpers (kept for backward compat) ────────────────
function showProgress(text) {
  const sec  = document.getElementById('progressSection');
  const txt  = document.getElementById('progressText');
  const fill = document.getElementById('progressFill');
  if (sec)  sec.style.display  = 'block';
  if (txt)  txt.textContent    = text;
  if (fill) fill.style.width   = '70%';
}

function hideProgress() {
  const sec  = document.getElementById('progressSection');
  const fill = document.getElementById('progressFill');
  if (sec)  sec.style.display = 'none';
  if (fill) fill.style.width  = '0%';
}

function showSuccess(message) {
  const alert = document.getElementById('successAlert');
  if (!alert) return;
  alert.querySelector('span').textContent = message;
  alert.classList.add('show');
  setTimeout(() => alert.classList.remove('show'), 5000);
}

function showError(message) {
  const alert = document.getElementById('errorAlert');
  if (!alert) return;
  const msgEl = alert.querySelector('#errorMessage') || alert.querySelector('span');
  if (msgEl) msgEl.textContent = message;
  alert.classList.add('show');
  setTimeout(() => alert.classList.remove('show'), 5000);
}

// ═════════════════════════════════════════════════════════════════════
// TOAST SYSTEM
// ═════════════════════════════════════════════════════════════════════

function showToast(message, type = 'info') {
  const container = document.getElementById('cb-toasts');
  if (!container) return;

  const iconMap = {
    success: '#ic-check',
    error:   '#ic-alert',
    info:    '#ic-info',
  };

  const toast = document.createElement('div');
  toast.className = `cb-toast cb-toast-${type}`;
  toast.innerHTML = `
    <svg width="16" height="16" aria-hidden="true"><use href="${iconMap[type] || '#ic-info'}"/></svg>
    <span class="cb-toast-msg">${message}</span>
    <button class="cb-toast-close" aria-label="Dismiss notification">
      <svg aria-hidden="true"><use href="#ic-x"/></svg>
    </button>
  `;

  toast.querySelector('.cb-toast-close').addEventListener('click', () => {
    toast.classList.add('cb-fade-out');
    setTimeout(() => toast.remove(), 200);
  });

  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add('cb-fade-out');
    setTimeout(() => toast.remove(), 200);
  }, 4000);
}

// ═════════════════════════════════════════════════════════════════════
// COMPONENT HELPERS
// ═════════════════════════════════════════════════════════════════════

function severityBadge(severity) {
  const sev  = (severity || 'info').toLowerCase();
  const icons = {
    critical: '⛔', high: '⚠', medium: '▲', low: '▼', informational: 'ℹ', info: 'ℹ',
  };
  const icon  = icons[sev] || 'ℹ';
  const label = sev === 'informational' ? 'INFO' : sev.toUpperCase();
  return `<span class="cb-badge cb-badge--${sev}" aria-label="Severity: ${label}">${icon} ${label}</span>`;
}

function kpiCard({ icon, label, value, delta, deltaLabel, valueColor }) {
  return `
    <div class="cb-kpi-card">
      <div class="cb-kpi-top">
        <svg class="cb-kpi-icon" aria-hidden="true"><use href="${icon}"/></svg>
        <span class="cb-kpi-label">${label}</span>
      </div>
      <div class="cb-kpi-value" style="${valueColor ? `color:${valueColor}` : ''}">${value}</div>
      <div class="cb-kpi-delta ${delta >= 0 ? 'positive' : 'negative'}">${deltaLabel || 'First scan'}</div>
    </div>`;
}

function complianceBadge(framework, control) {
  return `<span class="cb-compliance-badge">${framework}: ${control}</span>`;
}

function codeBlock(code, language) {
  return `<div class="cb-code-block"><pre><code class="language-${language}">${code}</code></pre></div>`;
}

function skeleton(height, width = '100%') {
  return `<div class="cb-skeleton cb-skeleton-block" style="height:${height};width:${width};"></div>`;
}

/* ══════════════════════════════════════════════════════════════════
   GITGUARDIAN DESIGN SYSTEM LOGIC
   ══════════════════════════════════════════════════════════════════ */

// 1. Mouse Glow Tracking
document.addEventListener('mousemove', e => {
  const glowTargets = document.querySelectorAll('[data-mouse-glow]');
  for (const el of glowTargets) {
    const rect = el.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    el.style.setProperty('--mouse-x', `${x}px`);
    el.style.setProperty('--mouse-y', `${y}px`);
  }
});

// 2. Scroll-aware Header
const mainScrollArea = document.getElementById('cb-main');
const header = document.getElementById('cb-header');
if (mainScrollArea && header) {
  mainScrollArea.addEventListener('scroll', () => {
    if (mainScrollArea.scrollTop > 10) {
      header.classList.add('is--scrolling');
    } else {
      header.classList.remove('is--scrolling');
    }
  });
}

// 3. Command Palette Logic
const cmdBackdrop = document.getElementById('cb-command-palette-backdrop');
const cmdInput = document.getElementById('cb-cmd-input');

function toggleCommandPalette() {
  if (!cmdBackdrop) return;
  const isOpen = cmdBackdrop.classList.contains('open');
  if (isOpen) {
    cmdBackdrop.classList.remove('open');
  } else {
    cmdBackdrop.classList.add('open');
    if (cmdInput) {
      cmdInput.value = '';
      setTimeout(() => cmdInput.focus(), 50);
    }
  }
}

// Command palette backdrop click to close
if (cmdBackdrop) {
  cmdBackdrop.addEventListener('click', (e) => {
    if (e.target === cmdBackdrop) toggleCommandPalette();
  });
}

// Keyboard shortcuts
document.addEventListener('keydown', e => {
  // Command palette: Ctrl+K or Cmd+K
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    toggleCommandPalette();
  }

  // Export report: Ctrl+E
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'e') {
    e.preventDefault();
    if (typeof generateReport === 'function') generateReport();
  }

  // Close command palette on Escape
  if (e.key === 'Escape') {
    if (cmdBackdrop && cmdBackdrop.classList.contains('open')) {
      toggleCommandPalette();
    }
  }

  // Open Agent: Ctrl + /
  if ((e.ctrlKey || e.metaKey) && e.key === '/') {
    e.preventDefault();
    if (typeof toggleAgentPanel === 'function') toggleAgentPanel(true);
  }
});

// 4. Agent Helper function for suggested prompts
window.sendAgentPrompt = function(promptText) {
  const agentInput = document.getElementById('cca-agent-input');
  const agentSend = document.getElementById('cca-agent-send');
  if (agentInput && agentSend) {
    // Ensure agent is open
    if (typeof toggleAgentPanel === 'function') toggleAgentPanel(true);
    agentInput.value = promptText;
    agentSend.click();
  }
};
