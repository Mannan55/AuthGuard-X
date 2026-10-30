/**
 * AuthGuard-X UI Utilities
 * Reusable helper functions, notifications, modals, and formatting.
 * Sprint 1
 */

(function (window) {
  'use strict';

  // ── XSS Sanitization ───────────────────────────────────────────────
  function escapeHTML(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // ── Toast Notifications ─────────────────────────────────────────────
  function showToast(message, type = 'info', duration = 4000) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.setAttribute('role', 'status');
    toast.setAttribute('aria-live', 'polite');

    const icons = {
      success: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>',
      error: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
      warning: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
      info: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
    };

    toast.innerHTML = `
      <div class="toast-icon">${icons[type] || icons.info}</div>
      <div class="toast-body">${escapeHTML(message)}</div>
      <button class="toast-close" aria-label="Close notification">&times;</button>
    `;

    toast.querySelector('.toast-close').addEventListener('click', () => {
      toast.classList.add('fade-out');
      setTimeout(() => toast.remove(), 200);
    });

    container.appendChild(toast);

    if (duration > 0) {
      setTimeout(() => {
        if (toast.parentElement) {
          toast.classList.add('fade-out');
          setTimeout(() => toast.remove(), 200);
        }
      }, duration);
    }
  }

  // ── Modal Dialogs ───────────────────────────────────────────────────
  function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) return;
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
    document.body.classList.add('modal-open');

    // Focus first actionable element
    const focusable = modal.querySelector('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
    if (focusable) focusable.focus();
  }

  function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) return;
    modal.classList.remove('open');
    modal.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('modal-open');

    // Trigger confirmation hook if active
    if (modalId === 'confirm-modal' && typeof modal._settleConfirm === 'function') {
      const fn = modal._settleConfirm;
      modal._settleConfirm = null;
      fn(false);
    }
  }

  function initModals() {
    document.querySelectorAll('.modal').forEach((modal) => {
      modal.addEventListener('click', (e) => {
        if (e.target === modal || e.target.classList.contains('modal-backdrop')) {
          closeModal(modal.id);
        }
      });

      modal.querySelectorAll('[data-dismiss="modal"]').forEach((btn) => {
        btn.addEventListener('click', () => closeModal(modal.id));
      });
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        const activeModal = document.querySelector('.modal.open');
        if (activeModal) closeModal(activeModal.id);
      }
    });
  }

  // ── Confirmation Dialog ─────────────────────────────────────────────
  function showConfirmDialog({
    title = 'Confirm Action',
    message = 'Are you sure you want to proceed?',
    confirmText = 'Confirm',
    cancelText = 'Cancel',
    isDanger = false
  }) {
    return new Promise((resolve) => {
      const modal = document.getElementById('confirm-modal');
      if (!modal) {
        resolve(window.confirm(message));
        return;
      }

      const previousFocused = document.activeElement;
      let settled = false;

      const titleEl = modal.querySelector('.confirm-title');
      const msgEl = modal.querySelector('.confirm-message');
      const confirmBtn = modal.querySelector('.confirm-btn');
      const cancelBtn = modal.querySelector('.cancel-btn');
      const closeBtn = modal.querySelector('.modal-close-btn');

      if (titleEl) titleEl.textContent = title;
      if (msgEl) msgEl.textContent = message;
      if (confirmBtn) {
        confirmBtn.textContent = confirmText;
        confirmBtn.className = `btn ${isDanger ? 'btn-danger' : 'btn-primary'} confirm-btn`;
      }
      if (cancelBtn) cancelBtn.textContent = cancelText;

      function settle(val) {
        if (settled) return;
        settled = true;
        modal._settleConfirm = null;
        cleanup();
        closeModal('confirm-modal');
        if (previousFocused && typeof previousFocused.focus === 'function') {
          try { previousFocused.focus(); } catch (err) {}
        }
        resolve(Boolean(val));
      }

      function onConfirm(e) {
        e.preventDefault();
        settle(true);
      }

      function onCancel(e) {
        e.preventDefault();
        settle(false);
      }

      function onKeydown(e) {
        if (e.key === 'Escape') {
          e.preventDefault();
          settle(false);
        }
      }

      function cleanup() {
        if (confirmBtn) confirmBtn.removeEventListener('click', onConfirm);
        if (cancelBtn) cancelBtn.removeEventListener('click', onCancel);
        if (closeBtn) closeBtn.removeEventListener('click', onCancel);
        document.removeEventListener('keydown', onKeydown, true);
      }

      // Register hook for backdrop clicks & generic dismiss
      modal._settleConfirm = settle;

      if (confirmBtn) confirmBtn.addEventListener('click', onConfirm);
      if (cancelBtn) cancelBtn.addEventListener('click', onCancel);
      if (closeBtn) closeBtn.addEventListener('click', onCancel);
      document.addEventListener('keydown', onKeydown, true);

      openModal('confirm-modal');
      if (cancelBtn) cancelBtn.focus();
    });
  }

  // ── Responsive Sidebar ──────────────────────────────────────────────
  function initSidebar() {
    const sidebar = document.getElementById('sidebar');
    const toggleBtn = document.getElementById('sidebar-toggle');
    const mobileToggle = document.getElementById('mobile-sidebar-toggle');

    if (!sidebar) return;

    // Restore state from localStorage
    const savedState = localStorage.getItem('authguard_sidebar_collapsed');
    if (savedState === 'true' && window.innerWidth >= 1024) {
      sidebar.classList.add('collapsed');
      document.body.classList.add('sidebar-collapsed');
    }

    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        sidebar.classList.toggle('collapsed');
        document.body.classList.toggle('sidebar-collapsed');
        const isCollapsed = sidebar.classList.contains('collapsed');
        localStorage.setItem('authguard_sidebar_collapsed', isCollapsed);
      });
    }

    if (mobileToggle) {
      mobileToggle.addEventListener('click', () => {
        sidebar.classList.toggle('mobile-open');
      });
    }

    // Auto-close on small screens when navigation link is clicked
    sidebar.querySelectorAll('.nav-link').forEach((link) => {
      link.addEventListener('click', () => {
        if (window.innerWidth < 1024) {
          sidebar.classList.remove('mobile-open');
        }
      });
    });
  }

  // ── Severity & Badge Helpers ────────────────────────────────────────
  function getSeverityLabel(risk) {
    const r = Number(risk) || 0;
    if (r >= 80) return 'Critical';
    if (r >= 60) return 'High';
    if (r >= 40) return 'Medium';
    return 'Low';
  }

  function getSeverityClass(risk) {
    const r = Number(risk) || 0;
    if (r >= 80) return 'badge-critical';
    if (r >= 60) return 'badge-high';
    if (r >= 40) return 'badge-medium';
    return 'badge-low';
  }

  function renderSeverityBadge(risk) {
    const label = getSeverityLabel(risk);
    const cls = getSeverityClass(risk);
    return `<span class="badge ${cls}">${label} (${escapeHTML(risk)})</span>`;
  }

  function renderStatusBadge(resolved) {
    if (resolved) {
      return `<span class="badge badge-resolved">Resolved</span>`;
    }
    return `<span class="badge badge-open">Open</span>`;
  }

  function renderSourceBadge(isSimulated) {
    if (isSimulated) {
      return `<span class="badge badge-simulated" title="Simulated training telemetry (is_simulated = 1)">Simulated</span>`;
    }
    return `<span class="badge badge-telemetry" title="Internal system / audit log event (is_simulated = 0)">System Event</span>`;
  }

  // ── Date Formatting ─────────────────────────────────────────────────
  function formatDate(dateStr) {
    if (!dateStr) return '—';
    try {
      const d = new Date(dateStr.replace(' ', 'T'));
      if (isNaN(d.getTime())) return escapeHTML(dateStr);
      return d.toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      });
    } catch {
      return escapeHTML(dateStr);
    }
  }

  function formatRelativeTime(dateStr) {
    if (!dateStr) return '—';
    try {
      const d = new Date(dateStr.replace(' ', 'T'));
      if (isNaN(d.getTime())) return escapeHTML(dateStr);
      const diffSec = Math.floor((Date.now() - d.getTime()) / 1000);
      if (diffSec < 60) return 'Just now';
      if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
      if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
      return `${Math.floor(diffSec / 86400)}d ago`;
    } catch {
      return escapeHTML(dateStr);
    }
  }

  // ── Smooth Animated Number Tick ─────────────────────────────────────
  function numberTick(element, targetValue, duration = 600) {
    if (!element) return;
    const startValue = parseInt(element.textContent, 10) || 0;
    const target = parseInt(targetValue, 10) || 0;
    if (startValue === target) return;

    // Respect user's motion preferences
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      element.textContent = target;
      return;
    }

    const startTime = performance.now();
    function update(now) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // easeOutCubic
      const ease = 1 - Math.pow(1 - progress, 3);
      const current = Math.round(startValue + (target - startValue) * ease);
      element.textContent = current;
      if (progress < 1) {
        requestAnimationFrame(update);
      } else {
        element.textContent = target;
      }
    }
    requestAnimationFrame(update);
  }

  // ── Debounce ────────────────────────────────────────────────────────
  function debounce(fn, wait = 300) {
    let timeout;
    return function (...args) {
      clearTimeout(timeout);
      timeout = setTimeout(() => fn.apply(this, args), wait);
    };
  }

  // Expose UI namespace
  window.UI = {
    escapeHTML,
    showToast,
    openModal,
    closeModal,
    initModals,
    showConfirmDialog,
    initSidebar,
    getSeverityLabel,
    getSeverityClass,
    renderSeverityBadge,
    renderStatusBadge,
    renderSourceBadge,
    formatDate,
    formatRelativeTime,
    numberTick,
    debounce
  };
})(window);

