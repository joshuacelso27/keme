/* ═══════════════════════════════════════════════════════════════════
   WatchMeWhip — login.js
   All login/logout calls go to Flask API. Logs fetched from DB.
═══════════════════════════════════════════════════════════════════ */

// ── Element refs ────────────────────────────────────────────────────────────
const form           = document.getElementById('loginForm');
const emailInput     = document.getElementById('emailInput');
const passwordInput  = document.getElementById('passwordInput');
const emailError     = document.getElementById('emailError');
const passwordError  = document.getElementById('passwordError');
const loginBtn       = document.getElementById('loginBtn');
const togglePw       = document.getElementById('togglePw');
const dashboard      = document.getElementById('dashboard');
const loginCard      = document.getElementById('loginCard');

// nav
const navDash      = document.getElementById('navDash');
const navLogs      = document.getElementById('navLogs');
const navIntrusion = document.getElementById('navIntrusion');

// pages
const pageDashboard  = document.getElementById('pageDashboard');
const pageLogs       = document.getElementById('pageLogs');
const pageIntrusion  = document.getElementById('pageIntrusion');

// logout buttons
document.getElementById('logoutBtn')          .addEventListener('click', doLogout);
document.getElementById('logoutBtnLogs')      .addEventListener('click', doLogout);
document.getElementById('logoutBtnIntrusion') .addEventListener('click', doLogout);

// ── Eye icon SVGs ────────────────────────────────────────────────────────────
const eyeOpen = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
const eyeClosed = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`;

togglePw.addEventListener('click', () => {
  const isPw = passwordInput.type === 'password';
  passwordInput.type = isPw ? 'text' : 'password';
  togglePw.innerHTML = isPw ? eyeClosed : eyeOpen;
});

// ── Input error clear ────────────────────────────────────────────────────────
emailInput.addEventListener('input', () => {
  emailInput.classList.remove('error-field');
  emailError.classList.remove('show');
});
passwordInput.addEventListener('input', () => {
  passwordInput.classList.remove('error-field');
  passwordError.classList.remove('show');
});

// ── Helpers ──────────────────────────────────────────────────────────────────
function isValidEmail(val) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test((val || '').trim());
}

function showError(inputEl, errorEl, msg) {
  inputEl.classList.add('error-field');
  errorEl.textContent = msg;
  errorEl.classList.add('show');
}

// ── LOGIN ────────────────────────────────────────────────────────────────────
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  let valid = true;

  if (!isValidEmail(emailInput.value)) {
    showError(emailInput, emailError, 'Please enter a valid email address.');
    valid = false;
  }
  if (passwordInput.value.length < 6) {
    showError(passwordInput, passwordError, 'Password must be at least 6 characters.');
    valid = false;
  }
  if (!valid) return;

  loginBtn.classList.add('loading');
  loginBtn.disabled = true;

  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: emailInput.value.trim(), password: passwordInput.value })
    });
    const data = await res.json();

    if (!data.success) {
      if (data.field === 'email') showError(emailInput, emailError, data.message);
      else if (data.field === 'password') showError(passwordInput, passwordError, data.message);
      else showError(emailInput, emailError, data.message || 'Login failed.');
      loginBtn.classList.remove('loading');
      loginBtn.disabled = false;
      return;
    }

    // Success — enter dashboard
    loginCard.style.display = 'none';
    dashboard.classList.add('show');
    initDashboard(data);

  } catch (err) {
    showError(emailInput, emailError, 'Network error. Please try again.');
    loginBtn.classList.remove('loading');
    loginBtn.disabled = false;
  }
});

// ── INIT DASHBOARD ────────────────────────────────────────────────────────────
function initDashboard(data) {
  document.getElementById('sessionStarted').textContent = data.timeIn + ' — ' + data.date;
  document.getElementById('loggedInAs').textContent = data.user;
  document.getElementById('sidebarUser').innerHTML = `<b>Logged in:</b><br>${data.user}<br><br><b>Role:</b> ${data.role || 'admin'}`;
  showPage('dashboard');
  startClock();
  loadLogs();
}

// ── LOGOUT ────────────────────────────────────────────────────────────────────
async function doLogout() {
  try {
    await fetch('/api/logout', { method: 'POST' });
  } catch (_) {}
  dashboard.classList.remove('show');
  loginCard.style.display = '';
  loginBtn.classList.remove('loading');
  loginBtn.disabled = false;
  emailInput.value = '';
  passwordInput.value = '';
  stopClock();
}

// ── PAGE ROUTING ──────────────────────────────────────────────────────────────
function showPage(page) {
  pageDashboard.style.display  = page === 'dashboard'  ? 'block' : 'none';
  pageLogs.style.display       = page === 'logs'       ? 'block' : 'none';
  pageIntrusion.style.display  = page === 'intrusion'  ? 'block' : 'none';

  [navDash, navLogs, navIntrusion].forEach(el => el && el.classList.remove('active'));
  if (page === 'dashboard' && navDash) navDash.classList.add('active');
  if (page === 'logs'      && navLogs) navLogs.classList.add('active');
  if (page === 'intrusion' && navIntrusion) navIntrusion.classList.add('active');

  if (page === 'logs' || page === 'intrusion') loadLogs();
}

// ── LOAD LOGS FROM API ────────────────────────────────────────────────────────
async function loadLogs() {
  try {
    const res = await fetch('/api/logs');
    if (!res.ok) return;
    const data = await res.json();
    if (!data.success) return;

    // Session logs
    const logsBody = document.getElementById('logsTableBody');
    if (data.sessions.length === 0) {
      logsBody.innerHTML = '<tr><td colspan="6">No session logs yet</td></tr>';
    } else {
      logsBody.innerHTML = data.sessions.map(s => `
        <tr>
          <td>${s.user_email}</td>
          <td>${s.ip_address || '—'}</td>
          <td>${s.time_in || '—'}</td>
          <td>${s.time_out || '—'}</td>
          <td>${s.date_label || '—'}</td>
          <td class="${s.status === 'active' ? 'status-active' : 'status-closed'}">
            ${s.status === 'active' ? '● Active' : '○ Closed'}
          </td>
        </tr>
      `).join('');
    }

    // Intrusion logs
    const intrusionBody = document.getElementById('intrusionTableBody');
    const countEl = document.getElementById('intrusionCount');
    if (data.intrusions.length === 0) {
      intrusionBody.innerHTML = '<tr><td colspan="5">No intrusion attempts detected</td></tr>';
      if (countEl) { countEl.textContent = '0 Attempts'; countEl.style.color = '#00aa44'; }
    } else {
      if (countEl) countEl.textContent = data.intrusions.length + ' Detected';
      intrusionBody.innerHTML = data.intrusions.map(i => `
        <tr class="intrusion-row">
          <td>${i.attempted_email || '—'}</td>
          <td>${i.ip_address || '—'}</td>
          <td>${i.reason || '—'}</td>
          <td>${i.time || '—'}</td>
          <td>${i.date || '—'}</td>
        </tr>
      `).join('');
    }

  } catch (err) {
    console.error('loadLogs error:', err);
  }
}

// ── CLOCK ─────────────────────────────────────────────────────────────────────
let clockInterval = null;
function startClock() {
  const el = document.getElementById('clockDisplay');
  function tick() {
    const now = new Date();
    if (el) el.textContent = now.toTimeString().slice(0, 8);
    // also update camera timestamp
    const ts = document.getElementById('camTimestamp');
    if (ts) ts.textContent = now.toLocaleDateString('en-US',{month:'short',day:'2-digit',year:'numeric'}) + ' ' + now.toTimeString().slice(0,8);
  }
  tick();
  clockInterval = setInterval(tick, 1000);
}
function stopClock() {
  clearInterval(clockInterval);
  const el = document.getElementById('clockDisplay');
  if (el) el.textContent = '';
}

// ── CAMERA CONTROLS ────────────────────────────────────────────────────────────
let motionOn = false;
let feedPaused = false;

function toggleMotion() {
  motionOn = !motionOn;
  document.getElementById('motionAlert').classList.toggle('show', motionOn);
  if (motionOn) addActivity('⚠ Motion Detected — Camera 01');
}

function toggleFeed() {
  feedPaused = !feedPaused;
  const status = document.getElementById('feedStatus');
  const btn = document.getElementById('pauseBtn');
  const liveBadge = document.querySelector('.live-badge');
  status.textContent = feedPaused ? '● Paused' : '● Live';
  status.style.color = feedPaused ? '#cc2222' : '#00aa44';
  btn.textContent = feedPaused ? '▶ Resume Feed' : '⏸ Pause Feed';
  if (liveBadge) liveBadge.style.background = feedPaused ? '#555' : '#cc0000';
  addActivity(feedPaused ? '⏸ Feed paused — Camera 01' : '▶ Feed resumed — Camera 01');
}

function addActivity(msg) {
  const log = document.getElementById('activityLog');
  if (!log) return;
  const now = new Date();
  const time = now.toTimeString().slice(0, 8);
  if (log.querySelector('div') && log.firstChild.textContent === 'No activity yet') {
    log.innerHTML = '';
  }
  const entry = document.createElement('div');
  entry.textContent = time + ' — ' + msg;
  log.prepend(entry);
  // Keep max 5 items
  while (log.children.length > 5) log.removeChild(log.lastChild);
}
