/**
 * AuthGuard-X Detection Engineering & Threat Correlation Engine
 * Rule management, correlation analysis, alert feed, and MITRE ATT&CK integration.
 * Sprint 3
 */

(function (window) {
  'use strict';

  let rulesState = [];
  let alertsState = [];
  let metricsState = null;
  let currentEditingRuleId = null;
  let currentEditingRuleVersion = null;
  let selectedAlertDetail = null;

  // Filter & Search states
  const rulesFilter = {
    search: '',
    severity: 'all',
    status: 'all'
  };

  const alertsFilter = {
    search: '',
    severity: 'all',
    status: 'all',
    page: 1,
    limit: 25,
    totalPages: 1
  };

  // ── Metrics Loader ─────────────────────────────────────────────────
  async function loadMetrics() {
    try {
      const data = await window.API.detection.getMetrics();
      metricsState = data;
      renderMetrics(data);
    } catch (err) {
      console.warn('[Detection] Failed to load detection metrics:', err);
    }
  }

  function renderMetrics(metrics) {
    if (!metrics) return;

    // Rules KPI
    const activeRulesEl = document.getElementById('metric-active-rules');
    const totalRulesEl = document.getElementById('metric-total-rules');
    const evalEventsEl = document.getElementById('metric-eval-events');
    const totalAlertsEl = document.getElementById('metric-total-alerts');
    const openAlertsEl = document.getElementById('metric-open-alerts');
    const critAlertsEl = document.getElementById('metric-critical-alerts');
    const escalatedAlertsEl = document.getElementById('metric-escalated-alerts');

    if (activeRulesEl) activeRulesEl.textContent = metrics.active_rules ?? 0;
    if (totalRulesEl) totalRulesEl.textContent = metrics.total_rules ?? 0;
    if (evalEventsEl) evalEventsEl.textContent = metrics.evaluated_events ?? 0;
    if (totalAlertsEl) totalAlertsEl.textContent = metrics.total_alerts ?? 0;
    if (openAlertsEl) openAlertsEl.textContent = metrics.open_alerts ?? 0;
    if (critAlertsEl) critAlertsEl.textContent = metrics.critical_alerts ?? 0;
    if (escalatedAlertsEl) escalatedAlertsEl.textContent = metrics.escalated_alerts ?? 0;

    // Update sidebar alert badge
    const navAlertsBadge = document.getElementById('nav-alerts-count');
    if (navAlertsBadge) {
      const openCount = metrics.open_alerts ?? 0;
      navAlertsBadge.textContent = openCount;
      navAlertsBadge.style.display = openCount > 0 ? 'inline-flex' : 'none';
    }
  }

  // ── Rules Management ────────────────────────────────────────────────
  async function loadRules() {
    const tableBody = document.getElementById('detection-rules-table-body');
    if (tableBody) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="7" class="table-empty">
            <span class="spinner-inline" style="margin-right: var(--space-2);"></span>
            Loading detection rules...
          </td>
        </tr>
      `;
    }

    try {
      const res = await window.API.detection.getRules({
        search: rulesFilter.search,
        severity: rulesFilter.severity,
        status: rulesFilter.status
      });

      rulesState = res.rules || [];
      renderRulesTable(rulesState);
      loadMetrics();
    } catch (err) {
      console.error('[Detection] Error loading rules:', err);
      if (tableBody) {
        tableBody.innerHTML = `
          <tr>
            <td colspan="7" class="table-empty text-danger">
              Failed to load detection rules. ${window.UI.escapeHTML(err.message)}
            </td>
          </tr>
        `;
      }
    }
  }

  function renderRulesTable(rules) {
    const tableBody = document.getElementById('detection-rules-table-body');
    if (!tableBody) return;

    if (!rules || rules.length === 0) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="7" class="table-empty">
            <div class="empty-state-card" style="padding: var(--space-6);">
              <p class="text-secondary" style="margin-bottom: var(--space-2);">No detection rules match the current filters.</p>
              <button class="btn btn-secondary btn-sm" id="btn-reset-rules-filters">Reset Filters</button>
            </div>
          </td>
        </tr>
      `;
      const resetBtn = document.getElementById('btn-reset-rules-filters');
      if (resetBtn) {
        resetBtn.addEventListener('click', () => {
          rulesFilter.search = '';
          rulesFilter.severity = 'all';
          rulesFilter.status = 'all';
          const searchInput = document.getElementById('rules-search-input');
          const sevSelect = document.getElementById('rules-filter-severity');
          const statSelect = document.getElementById('rules-filter-status');
          if (searchInput) searchInput.value = '';
          if (sevSelect) sevSelect.value = 'all';
          if (statSelect) statSelect.value = 'all';
          loadRules();
        });
      }
      return;
    }

    const currentUser = window.Auth ? window.Auth.getCurrentUser() : null;
    const isAdmin = currentUser && currentUser.role === 'admin';

    tableBody.innerHTML = rules.map(rule => {
      const isEnabled = rule.status === 'enabled';
      const isArchived = rule.status === 'archived';
      const statusBadge = isEnabled
        ? `<span class="badge badge-success">Enabled</span>`
        : (isArchived
            ? `<span class="badge badge-secondary" style="opacity: 0.85;">Archived</span>`
            : `<span class="badge badge-resolved">Disabled</span>`);

      const sevClass = getSeverityBadgeClass(rule.severity);
      const sevLabel = (rule.severity || 'medium').toUpperCase();

      const mitreCell = rule.mitre_technique_id
        ? `<a href="${window.UI.escapeHTML(rule.mitre_url || `https://attack.mitre.org/techniques/${rule.mitre_technique_id.replace('.', '/')}/`)}" 
              target="_blank" rel="noopener noreferrer" 
              class="mitre-badge" 
              title="${window.UI.escapeHTML(rule.mitre_technique_name || '')} (${window.UI.escapeHTML(rule.mitre_tactic || '')})">
              <code>${window.UI.escapeHTML(rule.mitre_technique_id)}</code>
              <span class="mitre-name">${window.UI.escapeHTML(rule.mitre_technique_name || '')}</span>
           </a>`
        : `<span class="text-muted">—</span>`;

      const conditionsCount = Array.isArray(rule.conditions) ? rule.conditions.length : 0;
      const correlationSummary = `&ge; ${rule.threshold} ev / ${rule.time_window_seconds}s (${rule.group_by_field || 'none'})`;

      const adminControls = isAdmin ? `
        <button class="btn btn-ghost btn-sm btn-rule-toggle" data-rule-id="${window.UI.escapeHTML(rule.rule_id)}" title="${isEnabled ? 'Disable rule' : (isArchived ? 'Re-enable archived rule' : 'Enable rule')}">
          ${isEnabled ? 'Disable' : (isArchived ? 'Unarchive' : 'Enable')}
        </button>
        <button class="btn btn-secondary btn-sm btn-rule-edit" data-rule-id="${window.UI.escapeHTML(rule.rule_id)}" title="Edit rule configuration">
          Edit
        </button>
        ${!isArchived ? `
        <button class="btn btn-ghost btn-sm text-danger btn-rule-delete" data-rule-id="${window.UI.escapeHTML(rule.rule_id)}" title="Archive rule (preserves history)">
          Archive
        </button>` : ''}
      ` : `
        <span class="text-muted text-xs">Read-only</span>
      `;

      return `
        <tr data-rule-id="${window.UI.escapeHTML(rule.rule_id)}">
          <td>
            <div style="font-family: var(--font-mono); font-size: var(--text-xs); font-weight: var(--font-semibold); color: var(--color-accent);">
              ${window.UI.escapeHTML(rule.rule_id)}
            </div>
            <div style="font-weight: var(--font-medium); color: var(--color-text-primary); margin-top: 2px;">
              ${window.UI.escapeHTML(rule.name)}
            </div>
          </td>
          <td>
            <span class="badge ${sevClass}">${sevLabel}</span>
          </td>
          <td>${mitreCell}</td>
          <td>
            <div style="font-size: var(--text-xs); font-family: var(--font-mono); color: var(--color-text-secondary);">
              ${correlationSummary}
            </div>
            <small class="text-muted">${conditionsCount} condition${conditionsCount !== 1 ? 's' : ''}</small>
          </td>
          <td>${statusBadge}</td>
          <td>
            <div style="font-size: var(--text-xs); color: var(--color-text-secondary);">
              ${rule.stats ? `${rule.stats.alert_count} alert(s)` : '0 alerts'}
            </div>
            <small class="text-muted">${rule.stats && rule.stats.last_execution ? window.UI.formatRelativeTime(rule.stats.last_execution) : 'Never fired'}</small>
          </td>
          <td class="table-actions">
            <div style="display: flex; gap: var(--space-1); align-items: center; justify-content: flex-end;">
              <button class="btn btn-secondary btn-sm btn-rule-inspect" data-rule-id="${window.UI.escapeHTML(rule.rule_id)}" title="Inspect rule definition">
                Inspect
              </button>
              ${adminControls}
            </div>
          </td>
        </tr>
      `;
    }).join('');

    // Attach row event listeners
    tableBody.querySelectorAll('.btn-rule-inspect').forEach(btn => {
      btn.addEventListener('click', () => openRuleDetail(btn.dataset.ruleId));
    });

    if (isAdmin) {
      tableBody.querySelectorAll('.btn-rule-toggle').forEach(btn => {
        btn.addEventListener('click', () => handleToggleRule(btn.dataset.ruleId));
      });
      tableBody.querySelectorAll('.btn-rule-edit').forEach(btn => {
        btn.addEventListener('click', () => openRuleEditor(btn.dataset.ruleId));
      });
      tableBody.querySelectorAll('.btn-rule-delete').forEach(btn => {
        btn.addEventListener('click', () => handleDeleteRule(btn.dataset.ruleId));
      });
    }
  }

  async function handleToggleRule(ruleId) {
    try {
      const res = await window.API.detection.toggleRule(ruleId);
      window.UI.showToast(res.message || `Rule status updated to ${res.status}.`, 'success');
      loadRules();
    } catch (err) {
      window.UI.showToast(`Failed to toggle rule: ${err.message}`, 'error');
    }
  }

  async function handleDeleteRule(ruleId) {
    const confirmed = await window.UI.showConfirmDialog({
      title: 'Archive Detection Rule',
      message: `Are you sure you want to archive detection rule "${ruleId}"? Archived rules stop evaluating, but all historical alerts, audit logs, and investigation references are safely preserved.`,
      confirmText: 'Archive Rule',
      isDanger: true
    });
    if (!confirmed) return;

    try {
      await window.API.detection.deleteRule(ruleId);
      window.UI.showToast(`Rule ${ruleId} successfully archived.`, 'success');
      loadRules();
    } catch (err) {
      window.UI.showToast(`Failed to archive rule: ${err.message}`, 'error');
    }
  }

  // ── Rule Inspection Modal ──────────────────────────────────────────
  async function openRuleDetail(ruleId) {
    try {
      const res = await window.API.detection.getRule(ruleId);
      const rule = res.rule;
      if (!rule) throw new Error('Rule details not returned');

      const modal = document.getElementById('modal-rule-detail');
      if (!modal) return;

      document.getElementById('rule-detail-id').textContent = rule.rule_id;
      document.getElementById('rule-detail-name').textContent = rule.name;
      document.getElementById('rule-detail-desc').textContent = rule.description || 'No description provided.';
      
      const sevBadge = document.getElementById('rule-detail-severity');
      sevBadge.className = `badge ${getSeverityBadgeClass(rule.severity)}`;
      sevBadge.textContent = (rule.severity || 'medium').toUpperCase();

      const statBadge = document.getElementById('rule-detail-status');
      statBadge.className = `badge ${rule.status === 'enabled' ? 'badge-success' : 'badge-resolved'}`;
      statBadge.textContent = rule.status.toUpperCase();

      document.getElementById('rule-detail-threshold').textContent = rule.threshold;
      document.getElementById('rule-detail-window').textContent = `${rule.time_window_seconds}s`;
      document.getElementById('rule-detail-groupby').textContent = rule.group_by_field || 'none';
      document.getElementById('rule-detail-version').textContent = `v${rule.version || 1}`;

      // MITRE
      const mitreContainer = document.getElementById('rule-detail-mitre');
      if (rule.mitre_technique_id) {
        mitreContainer.innerHTML = `
          <div class="mitre-detail-card">
            <div>
              <strong>${window.UI.escapeHTML(rule.mitre_technique_id)}</strong> — 
              <span>${window.UI.escapeHTML(rule.mitre_technique_name || '')}</span>
            </div>
            <div class="text-secondary text-xs" style="margin-top: 4px;">
              Tactic: <strong>${window.UI.escapeHTML(rule.mitre_tactic || 'Execution')}</strong>
            </div>
            <a href="${window.UI.escapeHTML(rule.mitre_url || `https://attack.mitre.org/techniques/${rule.mitre_technique_id.replace('.', '/')}/`)}" 
               target="_blank" rel="noopener noreferrer" 
               class="btn btn-secondary btn-sm" style="margin-top: var(--space-2); display: inline-flex;">
              View in MITRE ATT&CK Matrix &nearr;
            </a>
          </div>
        `;
      } else {
        mitreContainer.innerHTML = `<span class="text-muted">No MITRE ATT&CK technique mapped.</span>`;
      }

      // Conditions Table
      const conditionsList = document.getElementById('rule-detail-conditions');
      const conditions = Array.isArray(rule.conditions) ? rule.conditions : [];
      if (conditions.length === 0) {
        conditionsList.innerHTML = `<p class="text-muted">No conditions configured (matches all telemetry).</p>`;
      } else {
        conditionsList.innerHTML = conditions.map((cond, idx) => `
          <div class="condition-token">
            <span class="cond-field">${window.UI.escapeHTML(cond.field)}</span>
            <span class="cond-op">${window.UI.escapeHTML(cond.operator)}</span>
            <span class="cond-val">${window.UI.escapeHTML(Array.isArray(cond.value) ? cond.value.join(', ') : String(cond.value))}</span>
          </div>
        `).join('');
      }

      // Audit Log
      const auditContainer = document.getElementById('rule-detail-audit-log');
      const audits = res.audit_log || [];
      if (audits.length === 0) {
        auditContainer.innerHTML = `<p class="text-muted text-xs">No audit history found.</p>`;
      } else {
        auditContainer.innerHTML = audits.map(entry => `
          <div class="audit-history-row">
            <div>
              <span class="badge badge-subtle text-xs">${window.UI.escapeHTML(entry.action.toUpperCase())}</span>
              <span style="font-weight: var(--font-medium); margin-left: var(--space-2);">${window.UI.escapeHTML(entry.actor_name || 'System')}</span>
            </div>
            <div class="text-muted text-xs">${window.UI.formatDate(entry.timestamp)}</div>
          </div>
        `).join('');
      }

      window.UI.openModal('modal-rule-detail');
    } catch (err) {
      window.UI.showToast(`Failed to load rule details: ${err.message}`, 'error');
    }
  }

  // ── Rule Editor / Builder Modal ─────────────────────────────────────
  function openRuleEditor(ruleId = null) {
    currentEditingRuleId = ruleId;
    currentEditingRuleVersion = null;

    const modalTitle = document.getElementById('modal-rule-editor-title');
    const form = document.getElementById('form-rule-editor');
    if (!form) return;
    form.reset();

    const conditionsContainer = document.getElementById('rule-conditions-builder');
    if (conditionsContainer) conditionsContainer.innerHTML = '';

    if (!ruleId) {
      if (modalTitle) modalTitle.textContent = 'Create Custom Detection Rule';
      document.getElementById('rule-editor-id').value = '';
      document.getElementById('rule-editor-id').readOnly = false;
      document.getElementById('rule-editor-name').value = '';
      document.getElementById('rule-editor-desc').value = '';
      document.getElementById('rule-editor-severity').value = 'medium';
      document.getElementById('rule-editor-threshold').value = '1';
      document.getElementById('rule-editor-window').value = '300';
      document.getElementById('rule-editor-groupby').value = 'none';
      document.getElementById('rule-editor-mitre-id').value = '';
      document.getElementById('rule-editor-mitre-name').value = '';
      document.getElementById('rule-editor-mitre-tactic').value = '';
      document.getElementById('rule-editor-mitre-url').value = '';

      // Add one default condition row
      addConditionRow('attack', 'contains', '');
      window.UI.openModal('modal-rule-editor');
    } else {
      if (modalTitle) modalTitle.textContent = `Edit Detection Rule (${ruleId})`;
      document.getElementById('rule-editor-id').value = ruleId;
      document.getElementById('rule-editor-id').readOnly = true;

      window.API.detection.getRule(ruleId).then(res => {
        const r = res.rule;
        if (!r) throw new Error('Rule not found');
        currentEditingRuleVersion = r.version || 1;

        document.getElementById('rule-editor-name').value = r.name || '';
        document.getElementById('rule-editor-desc').value = r.description || '';
        document.getElementById('rule-editor-severity').value = r.severity || 'medium';
        document.getElementById('rule-editor-threshold').value = r.threshold || 1;
        document.getElementById('rule-editor-window').value = r.time_window_seconds || 300;
        document.getElementById('rule-editor-groupby').value = r.group_by_field || 'none';
        document.getElementById('rule-editor-mitre-id').value = r.mitre_technique_id || '';
        document.getElementById('rule-editor-mitre-name').value = r.mitre_technique_name || '';
        document.getElementById('rule-editor-mitre-tactic').value = r.mitre_tactic || '';
        document.getElementById('rule-editor-mitre-url').value = r.mitre_url || '';

        const conds = Array.isArray(r.conditions) ? r.conditions : [];
        if (conds.length === 0) {
          addConditionRow('attack', 'contains', '');
        } else {
          conds.forEach(c => addConditionRow(c.field, c.operator, c.value));
        }

        window.UI.openModal('modal-rule-editor');
      }).catch(err => {
        window.UI.showToast(`Failed to load rule for editing: ${err.message}`, 'error');
      });
    }
  }

  function addConditionRow(field = 'attack', operator = 'contains', value = '') {
    const container = document.getElementById('rule-conditions-builder');
    if (!container) return;

    const row = document.createElement('div');
    row.className = 'condition-row';
    row.innerHTML = `
      <select class="form-input cond-field-select" style="max-width: 130px;">
        <option value="attack" ${field === 'attack' ? 'selected' : ''}>attack</option>
        <option value="behavior" ${field === 'behavior' ? 'selected' : ''}>behavior</option>
        <option value="risk" ${field === 'risk' ? 'selected' : ''}>risk</option>
        <option value="ip" ${field === 'ip' ? 'selected' : ''}>ip</option>
        <option value="location" ${field === 'location' ? 'selected' : ''}>location</option>
        <option value="username" ${field === 'username' ? 'selected' : ''}>username</option>
        <option value="is_simulated" ${field === 'is_simulated' ? 'selected' : ''}>is_simulated</option>
      </select>
      <select class="form-input cond-op-select" style="max-width: 140px;">
        <option value="eq" ${operator === 'eq' ? 'selected' : ''}>equals (=)</option>
        <option value="neq" ${operator === 'neq' ? 'selected' : ''}>not equals (!=)</option>
        <option value="contains" ${operator === 'contains' ? 'selected' : ''}>contains</option>
        <option value="not_contains" ${operator === 'not_contains' ? 'selected' : ''}>not contains</option>
        <option value="gte" ${operator === 'gte' ? 'selected' : ''}>&ge; (greater/eq)</option>
        <option value="lte" ${operator === 'lte' ? 'selected' : ''}>&le; (less/eq)</option>
        <option value="gt" ${operator === 'gt' ? 'selected' : ''}>&gt; (greater)</option>
        <option value="lt" ${operator === 'lt' ? 'selected' : ''}>&lt; (less)</option>
        <option value="in" ${operator === 'in' ? 'selected' : ''}>in list (CSV)</option>
        <option value="not_empty" ${operator === 'not_empty' ? 'selected' : ''}>not empty</option>
      </select>
      <input type="text" class="form-input cond-val-input" placeholder="value" value="${window.UI.escapeHTML(Array.isArray(value) ? value.join(', ') : String(value ?? ''))}" style="flex: 1;">
      <button type="button" class="btn btn-ghost btn-sm text-danger btn-remove-cond" title="Remove condition">
        &times;
      </button>
    `;

    row.querySelector('.btn-remove-cond').addEventListener('click', () => {
      row.remove();
    });

    container.appendChild(row);
  }

  async function handleSaveRule(e) {
    e.preventDefault();

    const ruleIdInput = document.getElementById('rule-editor-id');
    const nameInput = document.getElementById('rule-editor-name');
    const descInput = document.getElementById('rule-editor-desc');
    const severityInput = document.getElementById('rule-editor-severity');
    const thresholdInput = document.getElementById('rule-editor-threshold');
    const windowInput = document.getElementById('rule-editor-window');
    const groupbyInput = document.getElementById('rule-editor-groupby');
    const mitreIdInput = document.getElementById('rule-editor-mitre-id');
    const mitreNameInput = document.getElementById('rule-editor-mitre-name');
    const mitreTacticInput = document.getElementById('rule-editor-mitre-tactic');
    const mitreUrlInput = document.getElementById('rule-editor-mitre-url');

    const ruleId = ruleIdInput.value.trim().toUpperCase();
    const name = nameInput.value.trim();
    const description = descInput.value.trim();
    const severity = severityInput.value;
    const threshold = parseInt(thresholdInput.value, 10);
    const time_window_seconds = parseInt(windowInput.value, 10);
    const group_by_field = groupbyInput.value;

    if (!name) {
      window.UI.showToast('Rule name is required.', 'error');
      return;
    }

    if (isNaN(threshold) || threshold < 1) {
      window.UI.showToast('Threshold must be an integer greater than or equal to 1.', 'error');
      return;
    }

    if (isNaN(time_window_seconds) || time_window_seconds < 10) {
      window.UI.showToast('Time window must be at least 10 seconds.', 'error');
      return;
    }

    // Build conditions from DOM rows
    const conditionRows = document.querySelectorAll('#rule-conditions-builder .condition-row');
    const conditions = [];
    for (const row of conditionRows) {
      const field = row.querySelector('.cond-field-select').value;
      const operator = row.querySelector('.cond-op-select').value;
      const valStr = row.querySelector('.cond-val-input').value.trim();

      if (operator === 'not_empty') {
        conditions.push({ field, operator, value: null });
      } else if (operator === 'in') {
        const items = valStr.split(',').map(s => s.trim()).filter(Boolean);
        conditions.push({ field, operator, value: items });
      } else if (field === 'risk' || ['gte', 'lte', 'gt', 'lt'].includes(operator)) {
        const numVal = Number(valStr);
        if (isNaN(numVal)) {
          window.UI.showToast(`Numeric value required for operator ${operator}.`, 'error');
          return;
        }
        conditions.push({ field, operator, value: numVal });
      } else {
        conditions.push({ field, operator, value: valStr });
      }
    }

    const payload = {
      name,
      description,
      severity,
      conditions,
      threshold,
      time_window_seconds,
      group_by_field,
      mitre_technique_id: mitreIdInput.value.trim() || null,
      mitre_technique_name: mitreNameInput.value.trim() || null,
      mitre_tactic: mitreTacticInput.value.trim() || null,
      mitre_url: mitreUrlInput.value.trim() || null
    };

    try {
      if (!currentEditingRuleId) {
        if (!ruleId) {
          window.UI.showToast('Rule ID is required (e.g. RULE-CUSTOM-001).', 'error');
          return;
        }
        payload.rule_id = ruleId;
        await window.API.detection.createRule(payload);
        window.UI.showToast(`Detection rule "${ruleId}" successfully created.`, 'success');
      } else {
        payload.version = currentEditingRuleVersion;
        await window.API.detection.updateRule(currentEditingRuleId, payload);
        window.UI.showToast(`Detection rule "${currentEditingRuleId}" successfully updated.`, 'success');
      }

      window.UI.closeModal('modal-rule-editor');
      loadRules();
    } catch (err) {
      window.UI.showToast(`Failed to save detection rule: ${err.message}`, 'error');
    }
  }

  // ── Alerts Workspace ────────────────────────────────────────────────
  async function loadAlerts() {
    const tableBody = document.getElementById('detection-alerts-table-body');
    if (tableBody) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="7" class="table-empty">
            <span class="spinner-inline" style="margin-right: var(--space-2);"></span>
            Loading detection alerts...
          </td>
        </tr>
      `;
    }

    try {
      const res = await window.API.detection.getAlerts({
        page: alertsFilter.page,
        limit: alertsFilter.limit,
        severity: alertsFilter.severity,
        status: alertsFilter.status,
        search: alertsFilter.search
      });

      alertsState = res.alerts || [];
      alertsFilter.totalPages = res.total_pages || 1;
      renderAlertsTable(alertsState, res);
      loadMetrics();
    } catch (err) {
      console.error('[Detection] Error loading alerts:', err);
      if (tableBody) {
        tableBody.innerHTML = `
          <tr>
            <td colspan="7" class="table-empty text-danger">
              Failed to load detection alerts: ${window.UI.escapeHTML(err.message)}
            </td>
          </tr>
        `;
      }
    }
  }

  function renderAlertsTable(alerts, meta = {}) {
    const tableBody = document.getElementById('detection-alerts-table-body');
    if (!tableBody) return;

    if (!alerts || alerts.length === 0) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="7" class="table-empty">
            <div class="empty-state-card" style="padding: var(--space-6);">
              <p class="text-secondary" style="margin-bottom: var(--space-2);">No detection alerts match the selected criteria.</p>
              <button class="btn btn-secondary btn-sm" id="btn-reset-alerts-filters">Reset Filters</button>
            </div>
          </td>
        </tr>
      `;
      const resetBtn = document.getElementById('btn-reset-alerts-filters');
      if (resetBtn) {
        resetBtn.addEventListener('click', () => {
          alertsFilter.search = '';
          alertsFilter.severity = 'all';
          alertsFilter.status = 'all';
          alertsFilter.page = 1;
          const searchInput = document.getElementById('alerts-search-input');
          const sevSelect = document.getElementById('alerts-filter-severity');
          const statSelect = document.getElementById('alerts-filter-status');
          if (searchInput) searchInput.value = '';
          if (sevSelect) sevSelect.value = 'all';
          if (statSelect) statSelect.value = 'all';
          loadAlerts();
        });
      }
      return;
    }

    tableBody.innerHTML = alerts.map(alert => {
      const sevClass = getSeverityBadgeClass(alert.severity);
      const sevLabel = (alert.severity || 'medium').toUpperCase();

      let statBadge = `<span class="badge badge-warning">Open</span>`;
      if (alert.status === 'escalated') {
        statBadge = `<span class="badge badge-info" title="Escalated to Case #${alert.case_id}">Escalated (Case #${alert.case_id})</span>`;
      } else if (alert.status === 'closed') {
        statBadge = `<span class="badge badge-resolved">Closed</span>`;
      }

      const mitreCell = alert.mitre_technique_id
        ? `<span class="mitre-badge" title="${window.UI.escapeHTML(alert.mitre_technique_name || '')}">
             <code>${window.UI.escapeHTML(alert.mitre_technique_id)}</code>
           </span>`
        : `<span class="text-muted">—</span>`;

      const groupKeyDisplay = alert.group_key && alert.group_key !== 'all'
        ? `<code style="font-size: var(--text-xs); color: var(--color-accent);">${window.UI.escapeHTML(alert.group_key)}</code>`
        : `<span class="text-muted">global</span>`;

      return `
        <tr data-alert-id="${window.UI.escapeHTML(alert.alert_id)}">
          <td>
            <div style="font-family: var(--font-mono); font-size: var(--text-xs); font-weight: var(--font-semibold); color: var(--color-accent);">
              ${window.UI.escapeHTML(alert.alert_id)}
            </div>
            <div class="text-muted text-xs" style="margin-top: 2px;">
              ${window.UI.formatDate(alert.created_at)}
            </div>
          </td>
          <td>
            <div style="font-weight: var(--font-medium); color: var(--color-text-primary);">
              ${window.UI.escapeHTML(alert.rule_name || alert.rule_id)}
            </div>
            <small class="text-muted font-mono">${window.UI.escapeHTML(alert.rule_id)}</small>
          </td>
          <td><span class="badge ${sevClass}">${sevLabel}</span></td>
          <td>${mitreCell}</td>
          <td>
            <div>${groupKeyDisplay}</div>
            <small class="text-muted">${alert.incident_count ?? 1} correlated event${alert.incident_count === 1 ? '' : 's'}</small>
          </td>
          <td>${statBadge}</td>
          <td class="table-actions">
            <button class="btn btn-secondary btn-sm btn-inspect-alert" data-alert-id="${window.UI.escapeHTML(alert.alert_id)}">
              Inspect
            </button>
          </td>
        </tr>
      `;
    }).join('');

    tableBody.querySelectorAll('.btn-inspect-alert').forEach(btn => {
      btn.addEventListener('click', () => openAlertDetail(btn.dataset.alertId));
    });

    // Pagination info
    const pageInfo = document.getElementById('alerts-pagination-info');
    if (pageInfo) {
      pageInfo.textContent = `Page ${meta.page || 1} of ${meta.total_pages || 1} (${meta.total || alerts.length} alerts)`;
    }

    const prevBtn = document.getElementById('btn-alerts-page-prev');
    const nextBtn = document.getElementById('btn-alerts-page-next');
    if (prevBtn) prevBtn.disabled = (meta.page || 1) <= 1;
    if (nextBtn) nextBtn.disabled = (meta.page || 1) >= (meta.total_pages || 1);
  }

  // ── Alert Inspection Modal ──────────────────────────────────────────
  async function openAlertDetail(alertId) {
    try {
      const res = await window.API.detection.getAlert(alertId);
      const alert = res.alert;
      if (!alert) throw new Error('Alert not found');

      selectedAlertDetail = alert;
      const modal = document.getElementById('modal-alert-detail');
      if (!modal) return;

      document.getElementById('alert-detail-id').textContent = alert.alert_id;
      document.getElementById('alert-detail-rule-name').textContent = alert.rule_name || alert.rule_id;
      document.getElementById('alert-detail-rule-id').textContent = alert.rule_id;
      document.getElementById('alert-detail-timestamp').textContent = window.UI.formatDate(alert.created_at);

      const sevBadge = document.getElementById('alert-detail-severity');
      sevBadge.className = `badge ${getSeverityBadgeClass(alert.severity)}`;
      sevBadge.textContent = (alert.severity || 'medium').toUpperCase();

      const statBadge = document.getElementById('alert-detail-status');
      statBadge.className = `badge ${alert.status === 'escalated' ? 'badge-info' : (alert.status === 'closed' ? 'badge-resolved' : 'badge-warning')}`;
      statBadge.textContent = alert.status.toUpperCase();

      // Explainability Narrative
      const explainCard = document.getElementById('alert-detail-explanation');
      if (explainCard) {
        explainCard.innerHTML = `
          <div class="correlation-explain-box">
            <div class="correlation-explain-title">Detection Rationale & Threat Correlation Breakdown</div>
            <p style="margin-bottom: var(--space-2); line-height: var(--leading-relaxed);">
              ${window.UI.escapeHTML(alert.explanation || 'Correlated telemetry matched detection rule threshold.')}
            </p>
            <div class="correlation-meta-grid">
              <div><strong>Group Key:</strong> <code>${window.UI.escapeHTML(alert.group_key || 'all')}</code></div>
              <div><strong>Window Lookback:</strong> <span>${window.UI.escapeHTML(alert.time_window_start || '—')} &rarr; ${window.UI.escapeHTML(alert.time_window_end || '—')}</span></div>
              <div><strong>Correlated Events:</strong> <span>${alert.incident_count ?? 1} events</span></div>
              <div><strong>Correlation Hash:</strong> <code style="font-size: 11px;">${alert.idempotency_hash ? alert.idempotency_hash.substring(0, 16) + '...' : '—'}</code></div>
            </div>
          </div>
        `;
      }

      // MITRE ATT&CK Info
      const mitreCard = document.getElementById('alert-detail-mitre');
      if (mitreCard) {
        if (alert.mitre_technique_id) {
          mitreCard.innerHTML = `
            <div class="mitre-detail-card">
              <div>
                <strong>${window.UI.escapeHTML(alert.mitre_technique_id)}</strong> &mdash; 
                <span>${window.UI.escapeHTML(alert.mitre_technique_name || '')}</span>
              </div>
              <div class="text-secondary text-xs" style="margin-top: 4px;">
                Tactic: <strong>${window.UI.escapeHTML(alert.mitre_tactic || 'Execution')}</strong>
              </div>
              <a href="${window.UI.escapeHTML(alert.mitre_url || `https://attack.mitre.org/techniques/${alert.mitre_technique_id.replace('.', '/')}/`)}" 
                 target="_blank" rel="noopener noreferrer" 
                 class="btn btn-secondary btn-sm" style="margin-top: var(--space-2); display: inline-flex;">
                View MITRE Technique &nearr;
              </a>
            </div>
          `;
        } else {
          mitreCard.innerHTML = `<span class="text-muted">No MITRE ATT&CK mapping attached.</span>`;
        }
      }

      // Correlated Incidents Table
      const incidentsTableBody = document.getElementById('alert-correlated-incidents-body');
      const incidents = alert.incidents || [];
      if (incidentsTableBody) {
        if (incidents.length === 0) {
          incidentsTableBody.innerHTML = `<tr><td colspan="6" class="text-muted text-center py-3">No incident records linked.</td></tr>`;
        } else {
          incidentsTableBody.innerHTML = incidents.map(inc => `
            <tr>
              <td><code>#${inc.id}</code></td>
              <td>${window.UI.formatDate(inc.timestamp)}</td>
              <td><strong>${window.UI.escapeHTML(inc.attack || '—')}</strong></td>
              <td>${window.UI.escapeHTML(inc.behavior || '—')}</td>
              <td>${window.UI.renderSeverityBadge(inc.risk || 0)}</td>
              <td><code>${window.UI.escapeHTML(inc.ip || '—')}</code></td>
            </tr>
          `).join('');
        }
      }

      // Case Escalation Action Controls
      const escalationBanner = document.getElementById('alert-escalation-action-container');
      if (escalationBanner) {
        if (alert.status === 'escalated' && alert.case_id) {
          escalationBanner.innerHTML = `
            <div class="escalated-state-box">
              <span class="badge badge-info" style="margin-right: var(--space-2);">Escalated</span>
              <span>Linked to Investigation <strong>Case #${alert.case_id}</strong></span>
              <button class="btn btn-primary btn-sm ml-auto" id="btn-jump-to-case" data-case-id="${alert.case_id}">
                Open Case in Workspace &rarr;
              </button>
            </div>
          `;
          document.getElementById('btn-jump-to-case').addEventListener('click', () => {
            window.UI.closeModal('modal-alert-detail');
            if (window.Investigation && typeof window.Investigation.openCase === 'function') {
              window.Investigation.openCase(alert.case_id);
            }
          });
        } else if (alert.status === 'closed') {
          escalationBanner.innerHTML = `
            <div class="escalated-state-box text-muted">
              <span>This alert is closed. No further escalation actions permitted.</span>
            </div>
          `;
        } else {
          escalationBanner.innerHTML = `
            <div style="display: flex; gap: var(--space-2); justify-content: flex-end; align-items: center; width: 100%;">
              <button class="btn btn-secondary btn-sm" id="btn-alert-close-action">
                Close Alert
              </button>
              <button class="btn btn-primary btn-sm" id="btn-alert-escalate-action">
                Escalate to SOC Investigation Case &rarr;
              </button>
            </div>
          `;
          document.getElementById('btn-alert-escalate-action').addEventListener('click', () => handleEscalateAlert(alert.alert_id));
          document.getElementById('btn-alert-close-action').addEventListener('click', () => handleCloseAlert(alert.alert_id));
        }
      }

      window.UI.openModal('modal-alert-detail');
    } catch (err) {
      window.UI.showToast(`Failed to load alert details: ${err.message}`, 'error');
    }
  }

  async function handleEscalateAlert(alertId) {
    try {
      const res = await window.API.detection.escalateAlert(alertId);
      window.UI.showToast(`Alert escalated to Case #${res.case_id}.`, 'success');
      window.UI.closeModal('modal-alert-detail');
      loadAlerts();

      // Offer to transition directly into workspace
      if (window.Investigation && typeof window.Investigation.openCase === 'function') {
        window.Investigation.openCase(res.case_id);
      }
    } catch (err) {
      window.UI.showToast(`Escalation failed: ${err.message}`, 'error');
    }
  }

  async function handleCloseAlert(alertId) {
    const confirmed = await window.UI.showConfirmDialog({
      title: 'Close Detection Alert',
      message: `Are you sure you want to close alert "${alertId}" without escalating to an investigation?`,
      confirmText: 'Close Alert',
      cancelText: 'Cancel'
    });
    if (!confirmed) return;

    try {
      await window.API.detection.closeAlert(alertId);
      window.UI.showToast(`Alert ${alertId} closed.`, 'success');
      window.UI.closeModal('modal-alert-detail');
      loadAlerts();
    } catch (err) {
      window.UI.showToast(`Failed to close alert: ${err.message}`, 'error');
    }
  }

  // ── Synthetic Replay Scenarios ──────────────────────────────────────
  async function triggerReplay(preset = 'all') {
    const btn = document.getElementById(`btn-replay-${preset}`) || document.getElementById('btn-trigger-replay');
    if (btn) btn.disabled = true;

    try {
      window.UI.showToast(`Replaying synthetic telemetry scenario (${preset})...`, 'info');
      const res = await window.API.detection.replay(preset);
      window.UI.showToast(
        `Replay finished! ${res.alerts_generated} alert(s) triggered from ${res.incidents_created} synthetic incidents.`,
        'success'
      );

      // Refresh views
      loadMetrics();
      loadAlerts();
      if (window.Incidents && typeof window.Incidents.refresh === 'function') {
        window.Incidents.refresh();
      }
      if (window.Dashboard && typeof window.Dashboard.loadMetrics === 'function') {
        window.Dashboard.loadMetrics();
      }
    } catch (err) {
      window.UI.showToast(`Replay execution failed: ${err.message}`, 'error');
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  // ── Helper: Severity Badge Class ────────────────────────────────────
  function getSeverityBadgeClass(sev) {
    switch (String(sev).toLowerCase()) {
      case 'critical': return 'badge-critical';
      case 'high': return 'badge-high';
      case 'medium': return 'badge-medium';
      case 'low': return 'badge-low';
      default: return 'badge-subtle';
    }
  }

  // ── Event Handlers & Initialization ─────────────────────────────────
  function init() {
    // Rules Filters
    const rulesSearch = document.getElementById('rules-search-input');
    if (rulesSearch) {
      rulesSearch.addEventListener('input', window.UI.debounce((e) => {
        rulesFilter.search = e.target.value.trim();
        loadRules();
      }, 300));
    }

    const rulesSevFilter = document.getElementById('rules-filter-severity');
    if (rulesSevFilter) {
      rulesSevFilter.addEventListener('change', (e) => {
        rulesFilter.severity = e.target.value;
        loadRules();
      });
    }

    const rulesStatFilter = document.getElementById('rules-filter-status');
    if (rulesStatFilter) {
      rulesStatFilter.addEventListener('change', (e) => {
        rulesFilter.status = e.target.value;
        loadRules();
      });
    }

    const btnNewRule = document.getElementById('btn-create-rule');
    if (btnNewRule) {
      btnNewRule.addEventListener('click', () => openRuleEditor(null));
    }

    const btnAddCondition = document.getElementById('btn-add-rule-condition');
    if (btnAddCondition) {
      btnAddCondition.addEventListener('click', () => addConditionRow());
    }

    const formRuleEditor = document.getElementById('form-rule-editor');
    if (formRuleEditor) {
      formRuleEditor.addEventListener('submit', handleSaveRule);
    }

    // Alerts Filters
    const alertsSearch = document.getElementById('alerts-search-input');
    if (alertsSearch) {
      alertsSearch.addEventListener('input', window.UI.debounce((e) => {
        alertsFilter.search = e.target.value.trim();
        alertsFilter.page = 1;
        loadAlerts();
      }, 300));
    }

    const alertsSevFilter = document.getElementById('alerts-filter-severity');
    if (alertsSevFilter) {
      alertsSevFilter.addEventListener('change', (e) => {
        alertsFilter.severity = e.target.value;
        alertsFilter.page = 1;
        loadAlerts();
      });
    }

    const alertsStatFilter = document.getElementById('alerts-filter-status');
    if (alertsStatFilter) {
      alertsStatFilter.addEventListener('change', (e) => {
        alertsFilter.status = e.target.value;
        alertsFilter.page = 1;
        loadAlerts();
      });
    }

    const prevPageBtn = document.getElementById('btn-alerts-page-prev');
    if (prevPageBtn) {
      prevPageBtn.addEventListener('click', () => {
        if (alertsFilter.page > 1) {
          alertsFilter.page--;
          loadAlerts();
        }
      });
    }

    const nextPageBtn = document.getElementById('btn-alerts-page-next');
    if (nextPageBtn) {
      nextPageBtn.addEventListener('click', () => {
        if (alertsFilter.page < alertsFilter.totalPages) {
          alertsFilter.page++;
          loadAlerts();
        }
      });
    }

    // Replay Buttons
    const replayAllBtn = document.getElementById('btn-replay-all');
    if (replayAllBtn) {
      replayAllBtn.addEventListener('click', () => triggerReplay('all'));
    }
    const replayCredBtn = document.getElementById('btn-replay-cred');
    if (replayCredBtn) {
      replayCredBtn.addEventListener('click', () => triggerReplay('credential_spray'));
    }
    const replayReconBtn = document.getElementById('btn-replay-recon');
    if (replayReconBtn) {
      replayReconBtn.addEventListener('click', () => triggerReplay('recon_burst'));
    }
    const replayExploitBtn = document.getElementById('btn-replay-exploit');
    if (replayExploitBtn) {
      replayExploitBtn.addEventListener('click', () => triggerReplay('lateral_exploit'));
    }
    const replayKerbBtn = document.getElementById('btn-replay-kerb');
    if (replayKerbBtn) {
      replayKerbBtn.addEventListener('click', () => triggerReplay('kerberoast'));
    }

    // Initial load of metrics
    loadMetrics();
  }

  window.Detection = {
    init,
    loadRules,
    loadAlerts,
    loadMetrics,
    openRuleDetail,
    openRuleEditor,
    openAlertDetail,
    triggerReplay
  };

})(window);
