/**
 * AuthGuard-X SOC Incident Investigation & Case Management Module
 * Sprint 2
 */

(function (window) {
  'use strict';

  let currentCaseId = null;
  let currentCaseData = null;
  let cachedAnalysts = [];
  let queueFilter = 'active'; // 'all', 'active', 'contained', 'resolved'

  // Helper: Format ISO / SQLite timestamps
  function formatTime(str) {
    if (!str) return '—';
    try {
      const d = new Date(str.replace(' ', 'T'));
      if (isNaN(d.getTime())) return str;
      return d.toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      });
    } catch (e) {
      return str;
    }
  }

  // Helper: Severity CSS classes
  function getSeverityClass(risk) {
    if (risk >= 80) return 'badge-critical';
    if (risk >= 60) return 'badge-high';
    if (risk >= 40) return 'badge-medium';
    return 'badge-low';
  }

  function getSeverityLabel(risk) {
    if (risk >= 80) return 'Critical';
    if (risk >= 60) return 'High';
    if (risk >= 40) return 'Medium';
    return 'Low';
  }

  // Helper: Status badge HTML
  function getStatusBadge(status) {
    const s = (status || 'new').toLowerCase();
    const badges = {
      new: '<span class="badge badge-status-new">New</span>',
      investigating: '<span class="badge badge-status-investigating">Investigating</span>',
      contained: '<span class="badge badge-status-contained">Contained</span>',
      resolved: '<span class="badge badge-status-resolved">Resolved</span>'
    };
    return badges[s] || `<span class="badge badge-subtle">${window.UI.escapeHTML(s)}</span>`;
  }

  // ── 1. Analyst Work Queue View ──────────────────────────────────────────

  async function loadWorkQueue() {
    const container = document.getElementById('queue-table-body');
    const emptyState = document.getElementById('queue-empty-state');
    const tableWrapper = document.getElementById('queue-table-wrapper');
    if (!container) return;

    try {
      // Fetch queue items and investigation metrics in parallel
      const [queueData, metricsData] = await Promise.all([
        window.API.cases.myQueue({ status: queueFilter === 'active' ? 'open' : queueFilter }),
        window.API.cases.metrics()
      ]);

      // Update KPI widgets
      const myCountEl = document.getElementById('kpi-my-cases');
      const unassignedCountEl = document.getElementById('kpi-unassigned-cases');
      const critCountEl = document.getElementById('kpi-crit-unresolved');
      const avgResEl = document.getElementById('kpi-avg-resolution');
      const navBadge = document.getElementById('nav-my-queue-count');

      if (myCountEl) myCountEl.textContent = metricsData.my_queue ?? 0;
      if (unassignedCountEl) unassignedCountEl.textContent = metricsData.unassigned ?? 0;
      if (critCountEl) critCountEl.textContent = metricsData.critical_unresolved ?? 0;
      if (avgResEl) avgResEl.textContent = metricsData.avg_resolution_human || 'N/A';

      if (navBadge) {
        const count = metricsData.my_queue ?? 0;
        navBadge.textContent = count;
        navBadge.style.display = count > 0 ? 'inline-flex' : 'none';
      }

      const cases = Array.isArray(queueData) ? queueData : (queueData.cases || []);

      if (cases.length === 0) {
        if (tableWrapper) tableWrapper.style.display = 'none';
        if (emptyState) emptyState.style.display = 'block';
        return;
      }

      if (emptyState) emptyState.style.display = 'none';
      if (tableWrapper) tableWrapper.style.display = 'block';

      container.innerHTML = cases.map(item => {
        const sevClass = getSeverityClass(item.risk);
        const sevLabel = getSeverityLabel(item.risk);
        const statusBadge = getStatusBadge(item.status);
        const sourceBadge = item.is_simulated
          ? '<span class="badge badge-simulated">Simulated</span>'
          : '<span class="badge badge-telemetry">System Event</span>';

        return `
          <tr data-case-id="${item.id}" class="clickable-row">
            <td class="font-mono text-primary font-bold">#${item.id}</td>
            <td>
              <div class="table-attack-title">${window.UI.escapeHTML(item.attack)}</div>
              <div class="text-muted" style="font-size: var(--text-xs);">${window.UI.escapeHTML(item.username)} &bull; ${window.UI.escapeHTML(item.location || 'Local')}</div>
            </td>
            <td>
              <span class="badge ${sevClass}">${sevLabel} (${item.risk})</span>
            </td>
            <td>${statusBadge}</td>
            <td>${sourceBadge}</td>
            <td class="text-muted font-mono" style="font-size: var(--text-xs);">${formatTime(item.time)}</td>
            <td>
              <button class="btn btn-secondary btn-sm open-case-btn" data-id="${item.id}">
                Investigate
              </button>
            </td>
          </tr>
        `;
      }).join('');

      // Attach row / button listeners
      container.querySelectorAll('.open-case-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          const id = btn.getAttribute('data-id');
          openCase(id);
        });
      });

      container.querySelectorAll('tr[data-case-id]').forEach(row => {
        row.addEventListener('click', () => {
          const id = row.getAttribute('data-case-id');
          openCase(id);
        });
      });

    } catch (err) {
      console.error('[Investigation] Failed to load work queue:', err);
      window.UI.showToast(`Error loading work queue: ${err.message}`, 'error');
    }
  }

  // ── 2. Investigation Detail Workspace View ──────────────────────────────

  async function openCase(incidentId) {
    currentCaseId = incidentId;
    window.location.hash = `investigation?id=${incidentId}`;
    if (typeof window.switchView === 'function') {
      window.switchView('investigation');
    }

    const titleEl = document.getElementById('page-title');
    if (titleEl) titleEl.textContent = `Incident Investigation #${incidentId}`;

    await refreshCaseData();
  }

  async function refreshCaseData() {
    if (!currentCaseId) return;

    try {
      const data = await window.API.cases.getCase(currentCaseId);
      currentCaseData = data;
      renderInvestigationWorkspace(data);
    } catch (err) {
      console.error('[Investigation] Failed to load case details:', err);
      window.UI.showToast(`Failed to load case #${currentCaseId}: ${err.message}`, 'error');
    }
  }

  function renderInvestigationWorkspace(data) {
    const { incident, case: cData, notes, evidence, activity } = data;

    // 1. Header Elements
    const idEl = document.getElementById('case-view-id');
    const attackEl = document.getElementById('case-view-attack');
    const statusPillEl = document.getElementById('case-view-status-badge');
    const sevPillEl = document.getElementById('case-view-severity-badge');
    const provPillEl = document.getElementById('case-view-prov-badge');
    const assigneeNameEl = document.getElementById('case-view-assignee-name');

    if (idEl) idEl.textContent = `#${incident.id}`;
    if (attackEl) attackEl.textContent = incident.attack;
    if (statusPillEl) {
      let badgeHtml = getStatusBadge(cData.status);
      if (cData.reopen_count && cData.reopen_count > 0) {
        badgeHtml += ` <span class="badge badge-warning" style="font-size: 11px; margin-left: 6px;" title="Case reopened ${cData.reopen_count} time(s)">Reopened (${cData.reopen_count})</span>`;
      }
      statusPillEl.innerHTML = badgeHtml;
    }
    if (sevPillEl) {
      const sevClass = getSeverityClass(incident.risk);
      const sevLabel = getSeverityLabel(incident.risk);
      sevPillEl.className = `badge ${sevClass}`;
      sevPillEl.textContent = `${sevLabel} (${incident.risk})`;
    }
    if (provPillEl) {
      provPillEl.className = incident.is_simulated ? 'badge badge-simulated' : 'badge badge-telemetry';
      provPillEl.textContent = incident.is_simulated ? 'Simulated Incident' : 'Internal System Event';
    }
    if (assigneeNameEl) {
      assigneeNameEl.textContent = cData.assigned_username ? `@${cData.assigned_username}` : 'Unassigned';
    }

    // 2. Incident Event Information Card
    const targetUserEl = document.getElementById('case-target-user');
    const behaviorEl = document.getElementById('case-behavior-profile');
    const ipEl = document.getElementById('case-client-ip');
    const locEl = document.getElementById('case-geo-location');
    const timeEl = document.getElementById('case-detection-time');
    const riskBarEl = document.getElementById('case-risk-bar-fill');
    const riskScoreValEl = document.getElementById('case-risk-score-value');

    if (targetUserEl) targetUserEl.textContent = incident.username;
    if (behaviorEl) behaviorEl.textContent = incident.behavior || 'standard_detection';
    if (ipEl) ipEl.textContent = incident.ip;
    if (locEl) locEl.textContent = incident.location;
    if (timeEl) timeEl.textContent = formatTime(incident.time);
    if (riskScoreValEl) riskScoreValEl.textContent = incident.risk;
    if (riskBarEl) {
      riskBarEl.style.width = `${Math.min(100, Math.max(0, incident.risk))}%`;
      if (incident.risk >= 80) riskBarEl.style.backgroundColor = 'var(--color-critical)';
      else if (incident.risk >= 60) riskBarEl.style.backgroundColor = 'var(--color-warning)';
      else if (incident.risk >= 40) riskBarEl.style.backgroundColor = 'var(--color-accent)';
      else riskBarEl.style.backgroundColor = 'var(--color-success)';
    }

    // 3. Lifecycle Stepper Progress Indicator
    renderLifecycleStepper(cData);

    // 4. Action Buttons State
    updateActionButtons(cData);

    // 5. Ownership & Assignment Card
    renderOwnershipCard(cData);

    // 6. Notes Findings List
    renderNotesList(notes);

    // 7. Evidence References List
    renderEvidenceList(evidence);

    // 8. Chronological Activity Audit Timeline
    renderActivityTimeline(activity);
  }

  function renderLifecycleStepper(cData) {
    const steps = ['new', 'investigating', 'contained', 'resolved'];
    const current = (cData.status || 'new').toLowerCase();
    const curIdx = steps.indexOf(current);

    steps.forEach((step, idx) => {
      const stepEl = document.getElementById(`step-node-${step}`);
      const lineEl = document.getElementById(`step-line-${step}`);
      const timeEl = document.getElementById(`step-time-${step}`);

      if (stepEl) {
        stepEl.classList.remove('completed', 'active', 'pending');
        if (idx < curIdx) stepEl.classList.add('completed');
        else if (idx === curIdx) stepEl.classList.add('active');
        else stepEl.classList.add('pending');
      }

      if (lineEl) {
        lineEl.classList.remove('active');
        if (idx < curIdx) lineEl.classList.add('active');
      }

      if (timeEl) {
        if (step === 'new') timeEl.textContent = formatTime(cData.created_at);
        else if (step === 'investigating') timeEl.textContent = formatTime(cData.investigation_started_at);
        else if (step === 'contained') timeEl.textContent = formatTime(cData.contained_at);
        else if (step === 'resolved') timeEl.textContent = formatTime(cData.resolved_at);
      }
    });

    // Resolution Summary Card (if resolved)
    const resSummaryCard = document.getElementById('case-resolution-summary-banner');
    const resSummaryText = document.getElementById('case-resolution-summary-text');
    if (resSummaryCard && resSummaryText) {
      if (cData.status === 'resolved' && cData.resolution_summary) {
        resSummaryCard.style.display = 'block';
        resSummaryText.textContent = cData.resolution_summary;
      } else {
        resSummaryCard.style.display = 'none';
      }
    }
  }

  function updateActionButtons(cData) {
    const claimBtn = document.getElementById('case-claim-btn');
    const startBtn = document.getElementById('case-start-btn');
    const containBtn = document.getElementById('case-contain-btn');
    const resolveBtn = document.getElementById('case-resolve-btn');
    const reopenBtn = document.getElementById('case-reopen-btn');

    const status = (cData.status || 'new').toLowerCase();
    const user = window.Auth ? window.Auth.getUser() : null;
    const isAssignedToMe = user && cData.assigned_to === user.id;
    const isUnassigned = !cData.assigned_to;
    const isAdmin = user && user.role === 'admin';

    // Claim button: visible if unassigned and not resolved
    if (claimBtn) {
      claimBtn.style.display = (isUnassigned && status !== 'resolved') ? 'inline-flex' : 'none';
    }

    // Start Investigation: from 'new'
    if (startBtn) {
      startBtn.style.display = (status === 'new') ? 'inline-flex' : 'none';
    }

    // Mark Contained: from 'investigating'
    if (containBtn) {
      containBtn.style.display = (status === 'investigating') ? 'inline-flex' : 'none';
    }

    // Resolve: from 'investigating' or 'contained'
    if (resolveBtn) {
      resolveBtn.style.display = (status === 'investigating' || status === 'contained') ? 'inline-flex' : 'none';
    }

    // Reopen: from 'resolved'
    if (reopenBtn) {
      reopenBtn.style.display = (status === 'resolved') ? 'inline-flex' : 'none';
    }
  }

  function renderOwnershipCard(cData) {
    const ownerNameEl = document.getElementById('owner-display-name');
    const ownerTimeEl = document.getElementById('owner-assigned-time');
    const reassignSelect = document.getElementById('case-reassign-select');
    const reassignBtn = document.getElementById('case-reassign-btn');
    const unassignBtn = document.getElementById('case-unassign-btn');

    if (ownerNameEl) {
      ownerNameEl.textContent = cData.assigned_username ? `@${cData.assigned_username}` : 'Unassigned';
    }
    if (ownerTimeEl) {
      ownerTimeEl.textContent = cData.assigned_at ? `Assigned: ${formatTime(cData.assigned_at)}` : 'Awaiting assignment';
    }

    const user = window.Auth ? window.Auth.getUser() : null;
    const isAdmin = user && user.role === 'admin';
    const isOwner = user && cData.assigned_to === user.id;

    if (reassignSelect) {
      reassignSelect.style.display = isAdmin ? 'inline-block' : 'none';
      if (reassignBtn) reassignBtn.style.display = isAdmin ? 'inline-flex' : 'none';
      if (isAdmin && cachedAnalysts.length > 0) {
        reassignSelect.innerHTML = '<option value="">-- Reassign Analyst --</option>' +
          cachedAnalysts.map(a => `
            <option value="${a.id}" ${a.id === cData.assigned_to ? 'selected' : ''}>
              ${window.UI.escapeHTML(a.username)} (${a.role})
            </option>
          `).join('');
      }
    }

    if (unassignBtn) {
      unassignBtn.style.display = (cData.assigned_to && (isAdmin || isOwner)) ? 'inline-flex' : 'none';
    }
  }

  function renderNotesList(notes) {
    const container = document.getElementById('case-notes-list');
    const countEl = document.getElementById('case-notes-count');
    if (!container) return;

    if (countEl) countEl.textContent = notes ? notes.length : 0;

    if (!notes || notes.length === 0) {
      container.innerHTML = `
        <div class="empty-state-sm">
          <svg class="icon-sm text-muted" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
          </svg>
          <span class="text-muted" style="font-size: var(--text-xs);">No investigation notes documented yet. Add initial triage findings below.</span>
        </div>
      `;
      return;
    }

    container.innerHTML = notes.map(n => `
      <div class="note-card">
        <div class="note-header">
          <div class="note-author">
            <span class="user-avatar-sm">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
              </svg>
            </span>
            <strong style="color: var(--color-text-primary); font-size: var(--text-xs);">@${window.UI.escapeHTML(n.author_username)}</strong>
          </div>
          <span class="text-muted font-mono" style="font-size: var(--text-xs);">${formatTime(n.created_at)}</span>
        </div>
        <div class="note-content">${window.UI.escapeHTML(n.content)}</div>
      </div>
    `).join('');
  }

  function renderEvidenceList(evidence) {
    const container = document.getElementById('case-evidence-list');
    const countEl = document.getElementById('case-evidence-count');
    if (!container) return;

    if (countEl) countEl.textContent = evidence ? evidence.length : 0;

    if (!evidence || evidence.length === 0) {
      container.innerHTML = `
        <div class="empty-state-sm">
          <svg class="icon-sm text-muted" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          <span class="text-muted" style="font-size: var(--text-xs);">No evidence metadata linked. Attach log excerpts, pcap references, or indicator hashes below.</span>
        </div>
      `;
      return;
    }

    container.innerHTML = evidence.map(e => {
      const typeLabels = {
        log_excerpt: 'Log Excerpt',
        network_pcap: 'Network PCAP',
        external_report: 'External Report',
        ip_reputation: 'IP Reputation',
        hash_indicator: 'Hash / IOC',
        screenshot_ref: 'Screenshot Ref',
        other: 'Evidence Metadata'
      };
      const label = typeLabels[e.evidence_type] || e.evidence_type;

      let sourceDisplay = '';
      if (e.source_ref) {
        const safeRef = window.UI.escapeHTML(e.source_ref);
        if (e.source_ref.startsWith('http://') || e.source_ref.startsWith('https://')) {
          sourceDisplay = `<a href="${safeRef}" target="_blank" rel="noopener noreferrer" class="evidence-link font-mono" style="font-size: var(--text-xs);">${safeRef} &#8599;</a>`;
        } else {
          sourceDisplay = `<span class="font-mono text-muted" style="font-size: var(--text-xs);">${safeRef}</span>`;
        }
      }

      return `
        <div class="evidence-card">
          <div class="evidence-header">
            <div>
              <span class="badge badge-subtle" style="font-size: 10px; margin-bottom: 2px;">${window.UI.escapeHTML(label)}</span>
              <strong style="color: var(--color-text-primary); font-size: var(--text-sm); display: block;">${window.UI.escapeHTML(e.title)}</strong>
            </div>
            <span class="text-muted font-mono" style="font-size: var(--text-xs);">${formatTime(e.created_at)}</span>
          </div>
          ${sourceDisplay ? `<div style="margin: 4px 0;">${sourceDisplay}</div>` : ''}
          ${e.description ? `<p class="evidence-desc text-muted">${window.UI.escapeHTML(e.description)}</p>` : ''}
          <div class="evidence-meta">
            Added by <span style="color: var(--color-text-secondary);">@${window.UI.escapeHTML(e.added_by_username)}</span>
          </div>
        </div>
      `;
    }).join('');
  }

  function renderActivityTimeline(activity) {
    const container = document.getElementById('case-activity-timeline');
    if (!container) return;

    if (!activity || activity.length === 0) {
      container.innerHTML = '<div class="text-muted" style="font-size: var(--text-xs); padding: var(--space-3);">No audit records registered.</div>';
      return;
    }

    const actionIcons = {
      incident_created: '<circle cx="12" cy="12" r="4"/>',
      status_change: '<polyline points="9 18 15 12 9 6"/>',
      investigation_started: '<polygon points="5 3 19 12 5 21 5 3"/>',
      incident_contained: '<rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>',
      incident_resolved: '<polyline points="20 6 9 17 4 12"/>',
      incident_reopened: '<path d="M1 4v6h6"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>',
      assignment_change: '<path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/>',
      note_added: '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
      evidence_added: '<path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/>'
    };

    container.innerHTML = activity.map(act => {
      const iconSvg = actionIcons[act.action] || '<circle cx="12" cy="12" r="3"/>';
      return `
        <div class="timeline-item">
          <div class="timeline-icon">
            <svg class="icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              ${iconSvg}
            </svg>
          </div>
          <div class="timeline-content">
            <div class="timeline-header">
              <strong style="color: var(--color-text-primary); font-size: var(--text-xs);">@${window.UI.escapeHTML(act.actor_username)}</strong>
              <span class="timeline-time font-mono">${formatTime(act.created_at)}</span>
            </div>
            <div class="timeline-desc text-muted">${window.UI.escapeHTML(act.description || act.action)}</div>
          </div>
        </div>
      `;
    }).join('');
  }

  // ── 3. Lifecycle Transitions & Mutations ────────────────────────────────

  async function executeStatusTransition(targetStatus, resolutionSummary = null, reopenReason = null) {
    if (!currentCaseId) return;

    try {
      const payload = { status: targetStatus };
      if (currentCaseData && currentCaseData.case && currentCaseData.case.version) {
        payload.version = currentCaseData.case.version;
      }
      if (resolutionSummary) payload.resolution_summary = resolutionSummary;
      if (reopenReason) payload.reopen_reason = reopenReason;

      await window.API.cases.updateStatus(currentCaseId, payload);
      window.UI.showToast(`Case #${currentCaseId} transitioned to ${targetStatus}`, 'success');

      await refreshCaseData();
      if (typeof window.Dashboard !== 'undefined' && window.Dashboard.loadMetrics) {
        window.Dashboard.loadMetrics();
      }
    } catch (err) {
      console.error('[Investigation] Status transition failed:', err);
      if (err.status === 409) {
        window.UI.showToast('Concurrent update conflict: this case was modified by another operation. Reloading latest state...', 'warning');
        await refreshCaseData();
        return;
      }
      window.UI.showToast(err.message || 'Status transition failed', 'error');
    }
  }

  async function executeAssignment(targetUserId) {
    if (!currentCaseId) return;

    try {
      const payload = targetUserId ? { assigned_to: parseInt(targetUserId, 10) } : { unassign: true };
      if (currentCaseData && currentCaseData.case && currentCaseData.case.version) {
        payload.version = currentCaseData.case.version;
      }
      await window.API.cases.assign(currentCaseId, payload);
      if (targetUserId) {
        window.UI.showToast(`Case #${currentCaseId} assigned successfully`, 'success');
      } else {
        window.UI.showToast(`Case #${currentCaseId} unassigned`, 'info');
      }

      await refreshCaseData();
    } catch (err) {
      console.error('[Investigation] Assignment failed:', err);
      if (err.status === 409) {
        window.UI.showToast('Concurrent update conflict: assignment was modified by another user. Reloading latest state...', 'warning');
        await refreshCaseData();
        return;
      }
      window.UI.showToast(err.message || 'Assignment failed', 'error');
    }
  }

  // ── 4. Event Listeners & Module Setup ───────────────────────────────────

  function initListeners() {
    // Back button in investigation view
    const backBtn = document.getElementById('investigation-back-btn');
    if (backBtn) {
      backBtn.addEventListener('click', () => {
        window.location.hash = 'my-queue';
        if (typeof window.switchView === 'function') {
          window.switchView('my-queue');
        }
      });
    }

    // Work Queue filter buttons
    document.querySelectorAll('[data-queue-filter]').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('[data-queue-filter]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        queueFilter = btn.getAttribute('data-queue-filter');
        loadWorkQueue();
      });
    });

    // Claim Case button
    const claimBtn = document.getElementById('case-claim-btn');
    if (claimBtn) {
      claimBtn.addEventListener('click', async () => {
        const user = window.Auth ? window.Auth.getUser() : null;
        if (!user) return;
        await executeAssignment(user.id);
      });
    }

    // Start Investigation button (new -> investigating)
    const startBtn = document.getElementById('case-start-btn');
    if (startBtn) {
      startBtn.addEventListener('click', async () => {
        await executeStatusTransition('investigating');
      });
    }

    // Mark Contained button (investigating -> contained)
    const containBtn = document.getElementById('case-contain-btn');
    if (containBtn) {
      containBtn.addEventListener('click', async () => {
        await executeStatusTransition('contained');
      });
    }

    // Resolve Case button: opens resolution summary modal
    const resolveBtn = document.getElementById('case-resolve-btn');
    if (resolveBtn) {
      resolveBtn.addEventListener('click', () => {
        const modal = document.getElementById('modal-resolve-case');
        const summaryInput = document.getElementById('resolve-summary-input');
        if (summaryInput) summaryInput.value = '';
        if (modal && window.UI.openModal) {
          window.UI.openModal('modal-resolve-case');
        }
      });
    }

    // Confirm Resolution button in modal
    const confirmResolveBtn = document.getElementById('confirm-resolve-btn');
    if (confirmResolveBtn) {
      confirmResolveBtn.addEventListener('click', async () => {
        const summaryInput = document.getElementById('resolve-summary-input');
        const summary = summaryInput ? summaryInput.value.trim() : '';
        if (summary.length < 5) {
          window.UI.showToast('Please provide a resolution summary of at least 5 characters.', 'warning');
          return;
        }

        window.UI.closeModal('modal-resolve-case');
        await executeStatusTransition('resolved', summary);
      });
    }

    // Reopen Case button: opens reopen reason modal
    const reopenBtn = document.getElementById('case-reopen-btn');
    if (reopenBtn) {
      reopenBtn.addEventListener('click', () => {
        const modal = document.getElementById('modal-reopen-case');
        const reasonInput = document.getElementById('reopen-reason-input');
        if (reasonInput) reasonInput.value = '';
        if (modal && window.UI.openModal) {
          window.UI.openModal('modal-reopen-case');
        }
      });
    }

    // Confirm Reopen button in modal
    const confirmReopenBtn = document.getElementById('confirm-reopen-btn');
    if (confirmReopenBtn) {
      confirmReopenBtn.addEventListener('click', async () => {
        const reasonInput = document.getElementById('reopen-reason-input');
        const reason = reasonInput ? reasonInput.value.trim() : '';
        if (reason.length < 5) {
          window.UI.showToast('Please provide a reopen justification of at least 5 characters.', 'warning');
          return;
        }

        window.UI.closeModal('modal-reopen-case');
        await executeStatusTransition('investigating', null, reason);
      });
    }

    // Reassign Analyst button
    const reassignBtn = document.getElementById('case-reassign-btn');
    if (reassignBtn) {
      reassignBtn.addEventListener('click', async () => {
        const select = document.getElementById('case-reassign-select');
        if (!select) return;
        const targetId = select.value;
        if (!targetId) {
          window.UI.showToast('Please select an analyst to assign.', 'warning');
          return;
        }
        await executeAssignment(targetId);
      });
    }

    // Unassign button
    const unassignBtn = document.getElementById('case-unassign-btn');
    if (unassignBtn) {
      unassignBtn.addEventListener('click', async () => {
        await executeAssignment(null);
      });
    }

    // Add Note form submission
    const noteSubmitBtn = document.getElementById('note-submit-btn');
    const noteInput = document.getElementById('note-content-input');
    if (noteSubmitBtn && noteInput) {
      noteSubmitBtn.addEventListener('click', async () => {
        const content = noteInput.value.trim();
        if (!content) {
          window.UI.showToast('Please enter note content before submitting.', 'warning');
          return;
        }

        try {
          noteSubmitBtn.disabled = true;
          const caseVer = currentCaseData && currentCaseData.case ? currentCaseData.case.version : 1;
          await window.API.cases.addNote(currentCaseId, { content, version: caseVer });
          noteInput.value = '';
          window.UI.showToast('Investigation note saved', 'success');
          await refreshCaseData();
        } catch (err) {
          if (err.status === 409) {
            window.UI.showToast('Concurrent update conflict: this case was modified by another operation. Reloading latest state...', 'warning');
            await refreshCaseData();
            return;
          }
          window.UI.showToast(err.message || 'Failed to save note', 'error');
        } finally {
          noteSubmitBtn.disabled = false;
        }
      });
    }

    // Add Evidence form submission
    const evSubmitBtn = document.getElementById('evidence-submit-btn');
    if (evSubmitBtn) {
      evSubmitBtn.addEventListener('click', async () => {
        const titleEl = document.getElementById('evidence-title-input');
        const typeEl = document.getElementById('evidence-type-select');
        const refEl = document.getElementById('evidence-ref-input');
        const descEl = document.getElementById('evidence-desc-input');

        const title = titleEl ? titleEl.value.trim() : '';
        const evidence_type = typeEl ? typeEl.value : 'log_excerpt';
        const source_ref = refEl ? refEl.value.trim() : '';
        const description = descEl ? descEl.value.trim() : '';

        if (!title) {
          window.UI.showToast('Evidence title is required.', 'warning');
          return;
        }

        try {
          evSubmitBtn.disabled = true;
          const caseVer = currentCaseData && currentCaseData.case ? currentCaseData.case.version : 1;
          await window.API.cases.addEvidence(currentCaseId, {
            title,
            evidence_type,
            source_ref,
            description,
            version: caseVer
          });

          if (titleEl) titleEl.value = '';
          if (refEl) refEl.value = '';
          if (descEl) descEl.value = '';

          window.UI.showToast('Evidence metadata attached', 'success');
          await refreshCaseData();
        } catch (err) {
          if (err.status === 409) {
            window.UI.showToast('Concurrent update conflict: this case was modified by another operation. Reloading latest state...', 'warning');
            await refreshCaseData();
            return;
          }
          window.UI.showToast(err.message || 'Failed to attach evidence', 'error');
        } finally {
          evSubmitBtn.disabled = false;
        }
      });
    }
  }

  async function loadAnalystsList() {
    try {
      cachedAnalysts = await window.API.cases.getAnalysts();
    } catch (e) {
      console.warn('[Investigation] Failed to load analysts list:', e);
    }
  }

  function getCurrentCaseVersion(id) {
    if (currentCaseData && currentCaseData.case) {
      if (!id || currentCaseData.case.incident_id === parseInt(id, 10)) {
        return currentCaseData.case.version || 1;
      }
    }
    return 1;
  }

  // ── 5. Public API ───────────────────────────────────────────────────────

  const Investigation = {
    async init() {
      initListeners();
      await loadAnalystsList();

      // Check URL parameters for direct incident investigation opening
      const hash = window.location.hash || '';
      if (hash.startsWith('#investigation')) {
        const match = hash.match(/id=(\d+)/);
        if (match) {
          openCase(parseInt(match[1], 10));
        }
      }
    },
    loadWorkQueue,
    openCase,
    refreshCaseData,
    getCurrentCaseVersion,
    executeStatusTransition,
    executeAssignment
  };

  window.Investigation = Investigation;

})(window);
