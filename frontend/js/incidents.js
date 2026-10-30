/**
 * AuthGuard-X Incident Management
 * Search, filter, sort, backend pagination, details dialog, and resolution.
 * Sprint 1
 */

(function (window) {
  'use strict';

  let state = {
    page: 1,
    per_page: 15,
    search: '',
    severity: 'all',
    status: 'all',
    source: 'all',
    sort_by: 'id',
    sort_dir: 'desc',
    pagination: {
      total: 0,
      total_pages: 1,
      has_next: false,
      has_prev: false
    }
  };

  async function loadIncidents() {
    const tbody = document.getElementById('incidents-tbody');
    const loadingEl = document.getElementById('incidents-loading');
    const emptyEl = document.getElementById('incidents-empty');

    if (loadingEl) loadingEl.style.display = 'block';
    if (emptyEl) emptyEl.style.display = 'none';

    try {
      const params = {
        page: state.page,
        per_page: state.per_page,
        search: state.search,
        severity: state.severity,
        status: state.status,
        source: state.source,
        sort_by: state.sort_by,
        sort_dir: state.sort_dir
      };

      const res = await window.API.incidents.list(params);
      let incidents = [];

      if (res && res.incidents && res.pagination) {
        incidents = res.incidents;
        state.pagination = res.pagination;
      } else if (Array.isArray(res)) {
        incidents = res;
        state.pagination = {
          page: 1,
          per_page: incidents.length,
          total: incidents.length,
          total_pages: 1,
          has_next: false,
          has_prev: false
        };
      }

      renderTable(incidents);
      renderPagination();

      // Update timeline with current list if on overview
      if (window.Dashboard && typeof window.Dashboard.updateTimeline === 'function') {
        window.Dashboard.updateTimeline(incidents);
      }
    } catch (err) {
      console.error('[Incidents] Failed to fetch incidents:', err);
      if (tbody) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;color:var(--color-critical);padding:24px;">Failed to load incidents: ${window.UI.escapeHTML(err.message)}</td></tr>`;
      }
    } finally {
      if (loadingEl) loadingEl.style.display = 'none';
    }
  }

  function renderTable(incidents) {
    const tbody = document.getElementById('incidents-tbody');
    const emptyEl = document.getElementById('incidents-empty');
    if (!tbody) return;

    tbody.innerHTML = '';

    if (!incidents || incidents.length === 0) {
      if (emptyEl) emptyEl.style.display = 'block';
      return;
    }

    if (emptyEl) emptyEl.style.display = 'none';

    incidents.forEach((inc) => {
      const tr = document.createElement('tr');
      tr.setAttribute('data-id', inc.id);

      const sevBadge = window.UI.renderSeverityBadge(inc.risk);
      const statusBadge = window.UI.renderStatusBadge(inc.resolved);
      const sourceBadge = window.UI.renderSourceBadge(inc.is_simulated);
      const timeStr = window.UI.formatDate(inc.time);

      const actionBtn = inc.resolved
        ? `<span class="text-muted" style="font-size:var(--text-xs);">Closed</span>`
        : `<button class="btn btn-sm btn-secondary resolve-trigger" data-id="${inc.id}">Resolve</button>`;

      tr.innerHTML = `
        <td class="cell-id">#${window.UI.escapeHTML(inc.id)}</td>
        <td>${sourceBadge}</td>
        <td><strong class="user-cell">${window.UI.escapeHTML(inc.username)}</strong></td>
        <td class="attack-cell">${window.UI.escapeHTML(inc.attack)}</td>
        <td class="location-cell text-muted">${window.UI.escapeHTML(inc.location || 'Internal')}</td>
        <td>${sevBadge}</td>
        <td>${statusBadge}</td>
        <td class="time-cell text-muted">${timeStr}</td>
        <td class="actions-cell">
          <div style="display:inline-flex;gap:4px;">
            <button class="btn btn-sm btn-ghost view-detail-trigger" data-id="${inc.id}" title="View Details">Details</button>
            ${actionBtn}
          </div>
        </td>
      `;

      tbody.appendChild(tr);
    });

    // Wire action triggers
    tbody.querySelectorAll('.resolve-trigger').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const id = btn.dataset.id;
        handleResolve(id);
      });
    });

    tbody.querySelectorAll('.view-detail-trigger').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const id = btn.dataset.id;
        openIncidentDetail(id);
      });
    });
  }

  function renderPagination() {
    const p = state.pagination;
    const pageDisplay = document.getElementById('pagination-info');
    const prevBtn = document.getElementById('prev-page-btn');
    const nextBtn = document.getElementById('next-page-btn');

    if (pageDisplay) {
      pageDisplay.textContent = `Page ${p.page} of ${p.total_pages || 1} (${p.total} total)`;
    }

    if (prevBtn) {
      prevBtn.disabled = !p.has_prev;
    }
    if (nextBtn) {
      nextBtn.disabled = !p.has_next;
    }
  }

  async function openIncidentDetail(id) {
    try {
      const inc = await window.API.incidents.getById(id);
      if (!inc) return;

      const modal = document.getElementById('incident-modal');
      if (!modal) return;

      const setField = (sel, val) => {
        const el = modal.querySelector(sel);
        if (el) el.innerHTML = val;
      };

      setField('.detail-id', `#${window.UI.escapeHTML(inc.id)}`);
      setField('.detail-attack', window.UI.escapeHTML(inc.attack));
      setField('.detail-username', window.UI.escapeHTML(inc.username));
      setField('.detail-behavior', window.UI.escapeHTML(inc.behavior || 'None'));
      setField('.detail-risk', window.UI.renderSeverityBadge(inc.risk));
      setField('.detail-location', window.UI.escapeHTML(inc.location || 'Internal'));
      setField('.detail-ip', window.UI.escapeHTML(inc.ip || '127.0.0.1'));
      setField('.detail-time', window.UI.formatDate(inc.time));
      setField('.detail-status', window.UI.renderStatusBadge(inc.resolved));
      setField('.detail-source', window.UI.renderSourceBadge(inc.is_simulated));

      const resolveBtn = modal.querySelector('.modal-resolve-btn');
      if (resolveBtn) {
        if (inc.resolved) {
          resolveBtn.style.display = 'none';
        } else {
          resolveBtn.style.display = 'inline-flex';
          resolveBtn.onclick = async () => {
            await handleResolve(inc.id);
            window.UI.closeModal('incident-modal');
          };
        }
      }

      window.UI.openModal('incident-modal');
    } catch (err) {
      window.UI.showToast(`Failed to load incident detail: ${err.message}`, 'error');
    }
  }

  async function handleResolve(id) {
    const confirmed = await window.UI.showConfirmDialog({
      title: 'Resolve Incident',
      message: `Mark Incident #${id} as resolved and apply remediation status?`,
      confirmText: 'Resolve Incident',
      isDanger: false
    });

    if (!confirmed) return;

    try {
      await window.API.incidents.resolve(id);
      window.UI.showToast(`Incident #${id} resolved successfully`, 'success');
      await loadIncidents();
      if (window.Dashboard && typeof window.Dashboard.loadMetrics === 'function') {
        window.Dashboard.loadMetrics();
      }
    } catch (err) {
      window.UI.showToast(`Resolution failed: ${err.message}`, 'error');
    }
  }

  function initControls() {
    // Search input (debounced)
    const searchInput = document.getElementById('incidents-search-input');
    if (searchInput) {
      searchInput.addEventListener(
        'input',
        window.UI.debounce((e) => {
          state.search = e.target.value.trim();
          state.page = 1;
          loadIncidents();
        }, 300)
      );
    }

    // Filter pills / selects
    const severityFilter = document.getElementById('filter-severity');
    if (severityFilter) {
      severityFilter.addEventListener('change', (e) => {
        state.severity = e.target.value;
        state.page = 1;
        loadIncidents();
      });
    }

    const statusFilter = document.getElementById('filter-status');
    if (statusFilter) {
      statusFilter.addEventListener('change', (e) => {
        state.status = e.target.value;
        state.page = 1;
        loadIncidents();
      });
    }

    const sourceFilter = document.getElementById('filter-source');
    if (sourceFilter) {
      sourceFilter.addEventListener('change', (e) => {
        state.source = e.target.value;
        state.page = 1;
        loadIncidents();
      });
    }

    // Pagination buttons
    const prevBtn = document.getElementById('prev-page-btn');
    if (prevBtn) {
      prevBtn.addEventListener('click', () => {
        if (state.pagination.has_prev) {
          state.page--;
          loadIncidents();
        }
      });
    }

    const nextBtn = document.getElementById('next-page-btn');
    if (nextBtn) {
      nextBtn.addEventListener('click', () => {
        if (state.pagination.has_next) {
          state.page++;
          loadIncidents();
        }
      });
    }

    // Column sorting headers
    document.querySelectorAll('[data-sort]').forEach((th) => {
      th.addEventListener('click', () => {
        const col = th.dataset.sort;
        if (state.sort_by === col) {
          state.sort_dir = state.sort_dir === 'asc' ? 'desc' : 'asc';
        } else {
          state.sort_by = col;
          state.sort_dir = 'desc';
        }

        // Update indicator icons/classes
        document.querySelectorAll('[data-sort]').forEach((other) => {
          other.classList.remove('sort-asc', 'sort-desc');
        });
        th.classList.add(state.sort_dir === 'asc' ? 'sort-asc' : 'sort-desc');

        loadIncidents();
      });
    });

    // Refresh button
    const refreshBtn = document.getElementById('refresh-incidents-btn');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => {
        loadIncidents();
        if (window.Dashboard) window.Dashboard.loadMetrics();
      });
    }
  }

  function init() {
    initControls();
    loadIncidents();
  }

  window.Incidents = {
    init,
    refresh: loadIncidents,
    openDetail: openIncidentDetail,
    resolve: handleResolve
  };
})(window);
