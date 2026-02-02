/**
 * AI Chat RAG - Frontend JavaScript
 * Med JWT Authentication, Azure AD SSO og CSRF protection
 */

// ============================================================
// Helper Functions
// ============================================================
const el = (id) => document.getElementById(id);

function sanitizeHTML(html) {
  if (typeof DOMPurify !== 'undefined') {
    return DOMPurify.sanitize(html, {
      ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'code', 'pre', 'h1', 'h2', 'h3', 'ul', 'ol', 'li', 'blockquote', 'a', 'span'],
      ALLOWED_ATTR: ['href', 'target', 'class'],
    });
  }
  const div = document.createElement('div');
  div.textContent = html;
  return div.innerHTML;
}

function sanitizeInput(text) {
  return text.trim().replace(/\0/g, '');
}

/**
 * Henter CSRF token fra cookie.
 * 
 * CSRF token er gemt i en cookie der KAN læses af JavaScript (httponly=false).
 * Dette er sikkert fordi:
 * 1. En angriber fra et andet domæne kan IKKE læse vores cookies (Same-Origin Policy)
 * 2. Angriberen kan derfor ikke sætte den korrekte X-CSRF-Token header
 * 3. Backend verificerer at cookie og header matcher (Double Submit Cookie pattern)
 */
function getCsrfToken() {
  const name = 'csrf_token=';
  const decodedCookie = decodeURIComponent(document.cookie);
  const cookies = decodedCookie.split(';');
  
  for (let cookie of cookies) {
    cookie = cookie.trim();
    if (cookie.indexOf(name) === 0) {
      return cookie.substring(name.length);
    }
  }
  return null;
}

// ============================================================
// Auth State Management (HttpOnly Cookie-baseret)
// ============================================================
/**
 * SIKKERHEDSFORBEDRING: Tokens gemmes nu i HttpOnly cookies
 * 
 * Fordele:
 * - JavaScript kan IKKE læse tokens (forhindrer XSS token-tyveri)
 * - Cookies sendes automatisk med alle requests (credentials: 'include')
 * - Ingen tokens eksponeret i localStorage, sessionStorage eller URL
 * 
 * Ulemper:
 * - Vi kan ikke tjekke token-udløb client-side (håndteres via /auth/me)
 * - Kræver credentials: 'include' på alle fetch requests
 */
const auth = {
  user: null,
  jwtEnabled: false,
  azureAdEnabled: false,
  isAuthenticated: false,  // Tracks om vi har en valid session
  
  init() {
    this.handleOAuthCallback();
    // Prøv at hente cached user info (kun for UI, ikke til auth)
    const userStr = localStorage.getItem('user_info');
    if (userStr) {
      try { this.user = JSON.parse(userStr); } catch (e) {}
    }
    this.checkAuthStatus();
  },
  
  handleOAuthCallback() {
    // Check for OAuth success/error i URL params
    const urlParams = new URLSearchParams(window.location.search);
    
    // Azure AD success - cookies er allerede sat af backend
    if (urlParams.get('login') === 'success') {
      window.history.replaceState({}, document.title, window.location.pathname);
      this.fetchUserInfo(); // Hent bruger info nu da cookies er sat
    }
    
    // Fejl håndtering
    const error = urlParams.get('error');
    if (error) {
      showError('leftError', `Login fejl: ${urlParams.get('message') || error}`);
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  },
  
  async checkAuthStatus() {
    try {
      const { baseUrl } = getConfig();
      if (!baseUrl) return;
      
      const response = await fetch(`${baseUrl}/api/auth/status`, {
        credentials: 'include'  // VIGTIGT: Send cookies med
      });
      const data = await response.json();
      this.jwtEnabled = data.jwt_enabled;
      this.azureAdEnabled = data.azure_ad_enabled;
      
      // Tjek om vi har en valid session ved at kalde /auth/me
      if (this.jwtEnabled) {
        await this.fetchUserInfo();
      }
      
      this.updateAuthUI();
    } catch (e) {
      console.error('Auth status check failed:', e);
    }
  },
  
  async fetchUserInfo() {
    try {
      const { baseUrl } = getConfig();
      const response = await fetch(`${baseUrl}/api/auth/me`, {
        credentials: 'include'  // VIGTIGT: Send cookies med
      });
      
      if (response.ok) {
        this.user = await response.json();
        this.isAuthenticated = true;
        // Cache user info for UI (IKKE tokens!)
        localStorage.setItem('user_info', JSON.stringify(this.user));
        this.updateAuthUI();
      } else if (response.status === 401) {
        // Prøv at refreshe token
        const refreshed = await this.refreshAccessToken();
        if (!refreshed) {
          this.handleLogoutState();
        }
      }
    } catch (e) {
      console.error('Fetch user info failed:', e);
    }
  },
  
  async refreshAccessToken() {
    try {
      const { baseUrl } = getConfig();
      const response = await fetch(`${baseUrl}/api/auth/refresh`, {
        method: 'POST',
        credentials: 'include'  // VIGTIGT: Send cookies med
      });
      
      if (response.ok) {
        // Nye cookies er sat automatisk af backend
        await this.fetchUserInfo();
        return true;
      }
    } catch (e) {
      console.error('Token refresh failed:', e);
    }
    return false;
  },
  
  handleLogoutState() {
    // Ryd lokal state (IKKE tokens - de er i HttpOnly cookies)
    this.user = null;
    this.isAuthenticated = false;
    localStorage.removeItem('user_info');
    this.updateAuthUI();
  },
  
  async logout() {
    const wasAzure = this.user?.auth_provider === 'azure_ad';
    const { baseUrl } = getConfig();
    
    try {
      // Kald logout endpoint for at rydde cookies på serveren
      // Inkluder CSRF token for beskyttelse
      const csrfToken = getCsrfToken();
      const headers = {};
      if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
      
      await fetch(`${baseUrl}/api/auth/logout`, {
        method: 'POST',
        headers,
        credentials: 'include'
      });
    } catch (e) {
      console.error('Logout request failed:', e);
    }
    
    this.handleLogoutState();
    
    // Azure AD logout kræver redirect til Microsoft
    if (wasAzure && this.azureAdEnabled) {
      window.location.href = `${baseUrl}/api/auth/azure/logout?post_logout_redirect_uri=${encodeURIComponent(window.location.origin)}`;
    }
  },
  
  isLoggedIn() { 
    return this.isAuthenticated && !!this.user; 
  },
  
  requiresAuth() { 
    return this.jwtEnabled; 
  },
  
  // BEMÆRK: Ingen Authorization header nødvendig - cookies sendes automatisk
  getAuthHeaders() { 
    return {}; 
  },
  
  updateAuthUI() {
    const authNotLoggedIn = el('authNotLoggedIn');
    const authLoggedIn = el('authLoggedIn');
    const azureLoginSection = el('azureLoginSection');
    const loginModal = el('loginModal');
    
    if (azureLoginSection) azureLoginSection.style.display = this.azureAdEnabled ? 'block' : 'none';
    
    if (this.isLoggedIn()) {
      if (authNotLoggedIn) authNotLoggedIn.style.display = 'none';
      if (authLoggedIn) authLoggedIn.style.display = 'block';
      if (loginModal) loginModal.classList.remove('active');
      
      const userAvatar = el('userAvatar');
      const userName = el('userName');
      const userProvider = el('userProvider');
      
      if (userAvatar) userAvatar.textContent = (this.user?.full_name || this.user?.username || '?')[0].toUpperCase();
      if (userName) userName.textContent = this.user?.full_name || this.user?.username;
      if (userProvider) userProvider.textContent = this.user?.auth_provider === 'azure_ad' ? 'Microsoft' : 'Lokal';
    } else {
      if (authNotLoggedIn) authNotLoggedIn.style.display = 'block';
      if (authLoggedIn) authLoggedIn.style.display = 'none';
      if (this.requiresAuth() && loginModal) loginModal.classList.add('active');
    }
  }
};

// ============================================================
// State Management
// ============================================================
const state = { sessionId: null, prompts: null, connected: false };

// ============================================================
// Markdown
// ============================================================
marked.setOptions({ breaks: true, gfm: true });

// ============================================================
// UI Functions
// ============================================================
function showError(elementId, message) {
  const errorEl = el(elementId);
  if (!errorEl) return;
  if (!message) { errorEl.classList.remove('show'); errorEl.textContent = ''; return; }
  errorEl.textContent = message;
  errorEl.classList.add('show');
  setTimeout(() => { if (errorEl.textContent === message) errorEl.classList.remove('show'); }, 10000);
}

function updateUI() {
  const sessionBadge = el("sessionBadge");
  if (sessionBadge) {
    const indicator = sessionBadge.querySelector('.status-indicator');
    if (state.sessionId) {
      sessionBadge.querySelector('span:last-child').textContent = `Session: ${state.sessionId.substring(0, 8)}...`;
      indicator?.classList.add('active');
    } else {
      sessionBadge.querySelector('span:last-child').textContent = 'Ingen session';
      indicator?.classList.remove('active');
    }
  }
  
  const connBadge = el("connectionBadge");
  if (connBadge) {
    const indicator = connBadge.querySelector('.status-indicator');
    connBadge.querySelector('span:last-child').textContent = state.connected ? 'Forbundet' : 'Ikke forbundet';
    if (state.connected) { indicator?.classList.add('active'); connBadge.classList.add('badge-success'); }
    else { indicator?.classList.remove('active'); connBadge.classList.remove('badge-success'); }
  }
  
  const promptSelect = el("promptSelect");
  const promptBadge = el("promptBadge");
  if (promptSelect && promptBadge) {
    const key = promptSelect.value;
    promptBadge.textContent = (key && state.prompts?.[key]) ? `📝 ${state.prompts[key].name || key}` : '📝 Ingen prompt valgt';
  }
}

function addMessage(role, text, meta = null, sources = null) {
  const chatLog = el("chatLog");
  if (!chatLog) return;
  
  const messageEl = document.createElement("div");
  messageEl.className = `message ${role}`;
  
  if (meta) {
    const metaEl = document.createElement("div");
    metaEl.className = "message-meta";
    metaEl.textContent = meta;
    messageEl.appendChild(metaEl);
  }
  
  const contentEl = document.createElement("div");
  contentEl.className = "message-content";
  
  if (role === 'ai') {
    contentEl.innerHTML = sanitizeHTML(marked.parse(text));
    contentEl.querySelectorAll('pre code').forEach((block) => hljs.highlightElement(block));
  } else {
    contentEl.textContent = text;
  }
  
  messageEl.appendChild(contentEl);
  
  // Kilder med klikbare links
  if (sources?.length) {
    const sourcesEl = document.createElement("div");
    sourcesEl.className = "sources";
    sourcesEl.innerHTML = `<div class="sources-header">📚 Kilder (${sources.length})</div>`;
    sources.forEach(s => {
      const docName = s.document || 'N/A';
      const page = s.page || 'N/A';
      const sourceUrl = s.sourceUrl;
      
      // Hvis sourceUrl findes, lav et klikbart link
      let docHtml;
      if (sourceUrl) {
        docHtml = `<a href="${sourceUrl}" target="_blank" class="source-link">📄 ${docName}</a>`;
      } else {
        docHtml = `📄 ${docName}`;
      }
      
      sourcesEl.innerHTML += `<div class="source-item"><div class="source-row">${docHtml} | Side: ${page}</div></div>`;
    });
    messageEl.appendChild(sourcesEl);
  }
  
  chatLog.appendChild(messageEl);
  chatLog.scrollTop = chatLog.scrollHeight;
}

// ============================================================
// API Functions
// ============================================================
function getConfig() {
  const baseUrlEl = el("baseUrl");
  return { baseUrl: baseUrlEl ? baseUrlEl.value.trim().replace(/\/+$/, "") : "" };
}

async function apiFetch(path, { method = "GET", body = null, timeout = 30000 } = {}) {
  const { baseUrl } = getConfig();
  if (!baseUrl) throw new Error("Base URL mangler.");
  
  const headers = {};
  if (body) headers["Content-Type"] = "application/json";
  
  // Tilføj CSRF token til alle modifying requests (POST, PUT, DELETE, PATCH)
  if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
    const csrfToken = getCsrfToken();
    if (csrfToken) {
      headers['X-CSRF-Token'] = csrfToken;
    }
  }
  
  const apiPath = path.startsWith('/api/') ? path : '/api' + path;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  
  try {
    let res = await fetch(baseUrl + apiPath, {
      method, 
      headers,
      body: body ? JSON.stringify(body) : null,
      signal: controller.signal,
      credentials: 'include',  // VIGTIGT: Send HttpOnly cookies med
    });
    clearTimeout(timeoutId);
    
    // Ved 401: prøv at refreshe token og gentag request
    if (res.status === 401) {
      const refreshed = await auth.refreshAccessToken();
      if (refreshed) {
        // Opdater CSRF token efter refresh (ny cookie kan være sat)
        const newCsrfToken = getCsrfToken();
        if (newCsrfToken && method !== 'GET') {
          headers['X-CSRF-Token'] = newCsrfToken;
        }
        // Gentag original request - cookies er opdateret
        res = await fetch(baseUrl + apiPath, { 
          method, 
          headers, 
          body: body ? JSON.stringify(body) : null,
          credentials: 'include',
        });
      } else {
        auth.handleLogoutState();
        throw new Error("Session udløbet");
      }
    }
    
    // Ved 403 med CSRF fejl: informer brugeren
    if (res.status === 403) {
      const errorData = await res.json().catch(() => ({}));
      if (errorData.detail && errorData.detail.includes('CSRF')) {
        console.error('CSRF validation failed - session may need refresh');
        // Prøv at refreshe for at få ny CSRF token
        const refreshed = await auth.refreshAccessToken();
        if (refreshed) {
          headers['X-CSRF-Token'] = getCsrfToken();
          res = await fetch(baseUrl + apiPath, { 
            method, headers, 
            body: body ? JSON.stringify(body) : null,
            credentials: 'include',
          });
        }
      }
      if (!res.ok) throw new Error(errorData.detail || `HTTP ${res.status}`);
    }
    
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  } catch (err) {
    clearTimeout(timeoutId);
    throw err.name === 'AbortError' ? new Error('Timeout') : err;
  }
}

// ============================================================
// Login Functions
// ============================================================
async function handleLogin(username, password) {
  const { baseUrl } = getConfig();
  if (!baseUrl) { showLoginError("Base URL mangler"); return false; }
  
  try {
    const response = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
      credentials: 'include',  // VIGTIGT: Modtag og gem HttpOnly cookies
    });
    const data = await response.json();
    
    if (!response.ok) { showLoginError(data.detail || 'Login fejlede'); return false; }
    
    // Cookies er automatisk sat af browseren (HttpOnly)
    // Vi gemmer kun user info lokalt til UI formål
    if (data.user) { 
      auth.user = data.user; 
      auth.isAuthenticated = true;
      localStorage.setItem('user_info', JSON.stringify(data.user)); 
    } else { 
      await auth.fetchUserInfo(); 
    }
    
    auth.updateAuthUI();
    el('loginModal')?.classList.remove('active');
    addMessage('system', `✅ Logget ind som ${auth.user?.full_name || auth.user?.username}`, 'System');
    return true;
  } catch (err) {
    showLoginError(err.message);
    return false;
  }
}

function showLoginError(msg) {
  const e = el('loginError');
  if (e) { e.textContent = msg; e.classList.add('show'); }
}

function hideLoginError() {
  const e = el('loginError');
  if (e) e.classList.remove('show');
}

function startAzureLogin() {
  const { baseUrl } = getConfig();
  if (!baseUrl) { showLoginError("Base URL mangler"); return; }
  window.location.href = `${baseUrl}/api/auth/azure/login?redirect_url=${encodeURIComponent(window.location.href)}`;
}

// ============================================================
// Chat Functions
// ============================================================
async function loadPrompts() {
  showError("leftError", "");
  const statusEl = el("promptStatus");
  const loadBtn = el("loadPromptsBtn");
  
  if (statusEl) { statusEl.style.display = 'block'; statusEl.innerHTML = '⏳ Henter...'; }
  if (loadBtn) { loadBtn.disabled = true; loadBtn.innerHTML = '⏳ Henter...'; }
  
  try {
    const data = await apiFetch("/prompts");
    state.prompts = data?.prompts || {};
    const select = el("promptSelect");
    if (select) {
      select.innerHTML = '<option value="">— Vælg en prompt —</option>';
      Object.entries(state.prompts).forEach(([key, val]) => {
        select.appendChild(new Option(val.name || key, key));
      });
    }
    if (statusEl) statusEl.innerHTML = `✅ ${Object.keys(state.prompts).length} prompts`;
    state.connected = true;
  } catch (err) {
    showError("leftError", `❌ ${err.message}`);
    if (statusEl) statusEl.innerHTML = '❌ Fejl';
  } finally {
    if (loadBtn) { loadBtn.disabled = false; loadBtn.textContent = "📥 Hent Prompts"; }
    updateUI();
  }
}

async function sendMessage() {
  if (auth.requiresAuth() && !auth.isLoggedIn()) {
    el('loginModal')?.classList.add('active');
    return;
  }
  
  const messageInput = el("messageInput");
  const text = sanitizeInput(messageInput?.value || '');
  if (!text) return;
  
  const promptKey = el("promptSelect")?.value;
  if (!state.sessionId && !promptKey) {
    showError("leftError", "❌ Vælg en prompt først.");
    return;
  }
  
  addMessage("user", text, auth.user?.full_name || "Du");
  messageInput.value = "";
  
  const sendBtn = el("sendBtn");
  if (sendBtn) { sendBtn.disabled = true; sendBtn.innerHTML = '⏳...'; }
  
  try {
    const body = { message: text };
    if (!state.sessionId && promptKey) body.prompt_key = promptKey;
    else if (state.sessionId) body.session_id = state.sessionId;
    
    const data = await apiFetch("/chat", { method: "POST", body, timeout: 60000 });
    
    if (data?.session_id) state.sessionId = data.session_id;
    state.connected = true;
    
    addMessage("ai", data?.response || "(tomt svar)", "AI Assistant", data?.sources_metadata);
    
    const costBadge = el("costBadge");
    if (data?.tokens && costBadge) {
      costBadge.textContent = `💰 ${data.tokens.input}/${data.tokens.output} tokens | $${data.tokens.total_cost}`;
    }
  } catch (err) {
    addMessage("ai", `**Fejl:** ${err.message}`, "System");
  } finally {
    if (sendBtn) { sendBtn.disabled = false; sendBtn.textContent = "📤 Send"; }
    updateUI();
    messageInput?.focus();
  }
}

function resetSession() {
  state.sessionId = null;
  el("costBadge").textContent = "💰 Tokens: – | Cost: –";
  updateUI();
  addMessage("system", "🔄 Session nulstillet.", "System");
}

async function clearChat() {
  const chatLog = el("chatLog");
  if (chatLog) chatLog.innerHTML = '<div class="message system">👋 Velkommen!</div>';
  state.sessionId = null;
  updateUI();
  await loadPrompts(); // Automatisk hent prompts ved ryd chat
}

async function saveToPDF() {
  const { jsPDF } = window.jspdf;
  const chatLog = el("chatLog");
  if (!chatLog) return;
  
  const messages = chatLog.querySelectorAll('.message');
  if (messages.length === 0) { alert('Ingen beskeder!'); return; }
  
  const filename = prompt('Filnavn?', `chat-${new Date().toISOString().split('T')[0]}.pdf`) || 'chat.pdf';
  
  const pdf = new jsPDF();
  let y = 20;
  
  pdf.setFontSize(16);
  pdf.text('AI Chat Eksport', 20, y); y += 10;
  pdf.setFontSize(10);
  pdf.text(`Dato: ${new Date().toLocaleString('da-DK')}`, 20, y); y += 10;
  
  messages.forEach(msg => {
    const role = msg.classList.contains('user') ? 'Bruger' : msg.classList.contains('ai') ? 'AI' : 'System';
    const content = msg.querySelector('.message-content')?.textContent || msg.textContent;
    
    if (y > 270) { pdf.addPage(); y = 20; }
    
    pdf.setFontSize(11);
    pdf.setFont(undefined, 'bold');
    pdf.text(role + ':', 20, y); y += 5;
    
    pdf.setFont(undefined, 'normal');
    pdf.setFontSize(10);
    const lines = pdf.splitTextToSize(content.trim(), 170);
    lines.forEach(line => {
      if (y > 280) { pdf.addPage(); y = 20; }
      pdf.text(line, 20, y); y += 5;
    });
    y += 5;
  });
  
  pdf.save(filename.endsWith('.pdf') ? filename : filename + '.pdf');
}

// ============================================================
// Event Listeners
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  auth.init();
  
  // Login form
  el('loginForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideLoginError();
    const btn = el('loginSubmitBtn');
    if (btn) { btn.disabled = true; btn.textContent = 'Logger ind...'; }
    await handleLogin(el('loginUsername')?.value, el('loginPassword')?.value);
    if (btn) { btn.disabled = false; btn.textContent = 'Log ind'; }
  });
  
  el('showLoginBtn')?.addEventListener('click', () => el('loginModal')?.classList.add('active'));
  el('azureLoginBtn')?.addEventListener('click', startAzureLogin);
  
  // User menu
  el('userBadge')?.addEventListener('click', () => el('userMenu')?.classList.toggle('show'));
  document.addEventListener('click', (e) => {
    if (!el('userBadge')?.contains(e.target)) el('userMenu')?.classList.remove('show');
  });
  
  el('logoutBtn')?.addEventListener('click', async () => {
    await auth.logout();
    addMessage('system', '👋 Logget ud.', 'System');
    el('userMenu')?.classList.remove('show');
  });
  
  // Modal close
  el('loginModal')?.addEventListener('click', (e) => {
    if (e.target.id === 'loginModal' && !auth.requiresAuth()) el('loginModal').classList.remove('active');
  });
  
  // Chat controls
  el("loadPromptsBtn")?.addEventListener("click", loadPrompts);
  el("sendBtn")?.addEventListener("click", sendMessage);
  el("resetBtn")?.addEventListener("click", resetSession);
  el("clearChatBtn")?.addEventListener("click", clearChat);
  el("savePdfBtn")?.addEventListener("click", saveToPDF);
  
  el("promptSelect")?.addEventListener("change", updateUI);
  
  el("messageInput")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });
  
  updateUI();
  el("promptStatus").style.display = 'block';
  
  // Automatisk hent prompts ved side-load
  loadPrompts();
});