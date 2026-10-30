/**
 * AuthGuard-X Authentication Manager
 * Handles login, logout, session lifecycle, and view toggling.
 * Sprint 1
 */

(function (window) {
  'use strict';

  let currentUser = null;
  let cachedDemoCreds = null;
  const authListeners = [];

  function onAuthChange(fn) {
    if (typeof fn === 'function') {
      authListeners.push(fn);
    }
  }

  function notifyAuthChange(user) {
    authListeners.forEach((fn) => {
      try {
        fn(user);
      } catch (err) {
        console.error('[Auth] Error in auth change listener:', err);
      }
    });
  }

  async function checkSession() {
    try {
      const data = await window.API.auth.getSession();
      const envBadge = document.getElementById('env-badge');
      if (envBadge) {
        envBadge.textContent = (data.environment === 'development' ? 'DEV' : (data.environment || 'DEV')).toUpperCase();
      }

      if (data.authenticated && data.user) {
        currentUser = data.user;
        showDashboardView(data.user);
        notifyAuthChange(data.user);
      } else {
        currentUser = null;
        showLoginView(data);
        notifyAuthChange(null);
      }
    } catch (err) {
      console.warn('[Auth] Session check failed:', err);
      showLoginView(null);
      notifyAuthChange(null);
    }
  }

  function showLoginView(sessionData) {
    const loginPage = document.getElementById('login-page');
    const appShell = document.getElementById('app-shell');
    if (loginPage) loginPage.style.display = 'flex';
    if (appShell) appShell.style.display = 'none';

    // Show development demo credentials helper if available
    const demoBox = document.getElementById('demo-credentials-box');
    if (sessionData && sessionData.demo_credentials) {
      cachedDemoCreds = sessionData.demo_credentials;
      const userEl = document.getElementById('demo-user-val');
      const passEl = document.getElementById('demo-pass-val');
      if (userEl) userEl.textContent = sessionData.demo_credentials.username;
      if (passEl) passEl.textContent = sessionData.demo_credentials.password;
      if (demoBox) demoBox.style.display = 'block';
    } else if (demoBox) {
      demoBox.style.display = 'none';
    }
  }

  function showDashboardView(user) {
    const loginPage = document.getElementById('login-page');
    const appShell = document.getElementById('app-shell');
    if (loginPage) loginPage.style.display = 'none';
    if (appShell) appShell.style.display = 'flex';

    // Update user info in topbar and sidebar
    const usernameEls = document.querySelectorAll('.user-display-name');
    usernameEls.forEach((el) => {
      el.textContent = user.username || 'Analyst';
    });

    const roleBadges = document.querySelectorAll('.user-role-badge');
    roleBadges.forEach((el) => {
      el.textContent = (user.role || 'analyst').toUpperCase();
    });

    // Clear password input
    const passInput = document.getElementById('login-password');
    if (passInput) passInput.value = '';
  }

  function fillDemoCredentials() {
    if (cachedDemoCreds) {
      const userIn = document.getElementById('login-username');
      const passIn = document.getElementById('login-password');
      if (userIn) userIn.value = cachedDemoCreds.username;
      if (passIn) passIn.value = cachedDemoCreds.password;
    }
  }

  async function handleLogin(e) {
    if (e) e.preventDefault();
    const userIn = document.getElementById('login-username');
    const passIn = document.getElementById('login-password');
    const submitBtn = document.getElementById('login-submit-btn');
    const errorEl = document.getElementById('login-error-msg');

    if (!userIn || !passIn) return;

    const username = userIn.value.trim();
    const password = passIn.value;

    if (!username || !password) {
      if (errorEl) errorEl.textContent = 'Please enter both username and password.';
      return;
    }

    if (errorEl) errorEl.textContent = '';
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = 'Authenticating...';
    }

    try {
      const res = await window.API.auth.login(username, password);
      if (res && res.status === 'success') {
        window.UI.showToast(`Authenticated as ${res.user.username}`, 'success');
        await checkSession();
      } else {
        if (errorEl) errorEl.textContent = res.error || 'Invalid credentials.';
      }
    } catch (err) {
      if (err.status === 429) {
        if (errorEl) errorEl.textContent = 'Rate limit reached. Please wait a moment.';
      } else {
        if (errorEl) errorEl.textContent = err.message || 'Authentication failed.';
      }
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Authenticate Session';
      }
    }
  }

  async function handleLogout() {
    const confirmed = await window.UI.showConfirmDialog({
      title: 'Sign Out',
      message: 'End your current SOC analyst session?',
      confirmText: 'Sign Out',
      cancelText: 'Stay Signed In'
    });

    if (!confirmed) return;

    try {
      await window.API.auth.logout();
      window.UI.showToast('Session ended successfully', 'info');
    } catch (err) {
      console.warn('[Auth] Logout warning:', err);
    }
    await checkSession();
  }

  function init() {
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
      loginForm.addEventListener('submit', handleLogin);
    }

    const demoFiller = document.getElementById('demo-credentials-box');
    if (demoFiller) {
      demoFiller.addEventListener('click', fillDemoCredentials);
    }

    const logoutBtns = document.querySelectorAll('.logout-trigger');
    logoutBtns.forEach((btn) => {
      btn.addEventListener('click', handleLogout);
    });

    // Check initial session
    checkSession();
  }

  window.Auth = {
    init,
    checkSession,
    onAuthChange,
    getCurrentUser: () => currentUser,
    fillDemoCredentials,
    handleLogout
  };
})(window);

