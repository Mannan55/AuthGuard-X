/**
 * AuthGuard-X Case Reports Workspace Module
 * Evidence-Grounded SOC Investigation Reporting
 * Sprint 5
 */

(function (window) {
  'use strict';

  let currentReportId = null;
  let currentReportData = null;
  let activeTab = 'tab-rep-summary';

  function escapeHTML(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // ── Reports List View ──────────────────────────────────────────────
  async function loadReports() {
    const tbody = document.getElementById('reports-table-body');
    if (!tbody) return;

    tbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted py-4">Loading reports...</td></tr>';

    try {
      const statusFilter = document.getElementById('report-status-filter')?.value || 'all';
      const searchVal = document.getElementById('report-search-input')?.value || '';

      const res = await window.API.reports.list({
        status: statusFilter,
        search: searchVal
      });

      const reports = res.reports || [];
      if (reports.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted py-4">No investigation reports found. Click "New Case Report" to create one.</td></tr>';
        return;
      }

      tbody.innerHTML = reports.map(r => {
        const statusBadge = r.status === 'finalized'
          ? '<span class="badge badge-pass">FINALIZED</span>'
          : (r.status === 'in_review'
            ? '<span class="badge badge-warn">IN REVIEW</span>'
            : '<span class="badge badge-subtle">DRAFT</span>');

        const sevBadge = `<span class="badge badge-${r.severity || 'low'}">${(r.severity || 'low').toUpperCase()}</span>`;

        return `
          <tr>
            <td class="font-mono text-cyan"><strong>${escapeHTML(r.report_id)}</strong></td>
            <td><a href="#investigation" class="text-primary font-mono case-nav-link" data-case-id="${r.case_id}">Case #${r.case_id}</a></td>
            <td><strong>${escapeHTML(r.title)}</strong></td>
            <td>${sevBadge}</td>
            <td>${statusBadge}</td>
            <td><span class="badge badge-subtle">v${r.version}</span></td>
            <td><small>@${escapeHTML(r.author_username)}${r.reviewer_username ? ` &bull; @${escapeHTML(r.reviewer_username)}` : ''}</small></td>
            <td class="text-xs text-muted">${escapeHTML(r.updated_at || r.created_at)}</td>
            <td>
              <div style="display: flex; gap: 4px;">
                <button class="btn btn-secondary btn-sm btn-open-report" data-report-id="${escapeHTML(r.report_id)}">Open</button>
                <a href="${window.API.reports.getExportHtmlUrl(r.report_id)}" target="_blank" class="btn btn-secondary btn-sm" title="Printable HTML">HTML</a>
                <a href="${window.API.reports.getExportJsonUrl(r.report_id)}" target="_blank" class="btn btn-secondary btn-sm" title="JSON Export">JSON</a>
              </div>
            </td>
          </tr>
        `;
      }).join('');

      // Attach event listeners
      tbody.querySelectorAll('.btn-open-report').forEach(btn => {
        btn.addEventListener('click', () => {
          openReport(btn.dataset.reportId);
        });
      });

      tbody.querySelectorAll('.case-nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
          e.preventDefault();
          const cid = link.dataset.caseId;
          if (window.Investigation && window.Investigation.openCase) {
            window.Investigation.openCase(cid);
          }
        });
      });
    } catch (err) {
      console.error('[Reports] Failed to load reports:', err);
      tbody.innerHTML = `<tr><td colspan="9" class="text-center text-danger py-4">Failed to load reports: ${escapeHTML(err.message)}</td></tr>`;
    }
  }

  // ── Open Single Report Detail ──────────────────────────────────────
  async function openReport(reportId) {
    currentReportId = reportId;

    const listContainer = document.getElementById('reports-list-container');
    const detailContainer = document.getElementById('report-detail-container');
    if (listContainer) listContainer.style.display = 'none';
    if (detailContainer) detailContainer.style.display = 'block';

    try {
      const res = await window.API.reports.get(reportId);
      currentReportData = res;
      renderReportDetail(res);
    } catch (err) {
      console.error('[Reports] Failed to open report:', err);
      if (window.UI && window.UI.showToast) {
        window.UI.showToast(`Failed to open report ${reportId}: ${err.message}`, 'error');
      }
    }
  }

  function closeReportDetail() {
    currentReportId = null;
    currentReportData = null;
    const listContainer = document.getElementById('reports-list-container');
    const detailContainer = document.getElementById('report-detail-container');
    if (listContainer) listContainer.style.display = 'block';
    if (detailContainer) detailContainer.style.display = 'none';
    loadReports();
  }

  // ── Render Report Workspace ────────────────────────────────────────
  function renderReportDetail(data) {
    const rep = data.report;
    const caseData = data.case;
    const qc = rep.quality_checks || [];
    const isFinalized = Boolean(rep.is_finalized);

    // Breadcrumb & Header
    const bc = document.getElementById('active-report-breadcrumb');
    if (bc) bc.textContent = rep.report_id;

    const idEl = document.getElementById('rep-detail-id');
    if (idEl) idEl.textContent = rep.report_id;

    const vEl = document.getElementById('rep-detail-version');
    if (vEl) vEl.textContent = `v${rep.version}`;

    const stEl = document.getElementById('rep-detail-status');
    if (stEl) {
      stEl.textContent = rep.status.toUpperCase();
      stEl.className = 'badge ' + (rep.status === 'finalized' ? 'badge-pass' : (rep.status === 'in_review' ? 'badge-warn' : 'badge-subtle'));
    }

    const cbEl = document.getElementById('rep-detail-case-badge');
    if (cbEl) cbEl.textContent = `Case #${rep.case_id} (${escapeHTML(rep.incident_classification || 'Incident')})`;

    const titleEl = document.getElementById('rep-detail-title-display');
    if (titleEl) titleEl.textContent = rep.title;

    const authorEl = document.getElementById('rep-detail-author');
    if (authorEl) authorEl.textContent = `@${rep.author_username}`;

    const crEl = document.getElementById('rep-detail-created');
    if (crEl) crEl.textContent = rep.created_at;

    const upEl = document.getElementById('rep-detail-updated');
    if (upEl) upEl.textContent = rep.updated_at;

    // Export buttons
    const btnExpHtml = document.getElementById('btn-export-html');
    if (btnExpHtml) {
      btnExpHtml.onclick = () => {
        window.open(window.API.reports.getExportHtmlUrl(rep.report_id), '_blank');
      };
    }
    const btnExpJson = document.getElementById('btn-export-json');
    if (btnExpJson) {
      btnExpJson.onclick = () => {
        window.open(window.API.reports.getExportJsonUrl(rep.report_id), '_blank');
      };
    }

    // Action Buttons for Lifecycle
    renderLifecycleButtons(rep);

    // Render Quality Checklist
    renderQualityChecklist(qc);

    // Summary & Facts fields
    const sumInput = document.getElementById('rep-edit-summary');
    if (sumInput) {
      sumInput.value = rep.executive_summary || '';
      sumInput.disabled = isFinalized;
    }

    const remInput = document.getElementById('rep-edit-remediation');
    if (remInput) {
      remInput.value = rep.containment_remediation_history || '';
      remInput.disabled = isFinalized;
    }

    const recInput = document.getElementById('rep-edit-recommendations');
    if (recInput) {
      recInput.value = rep.recommendations || '';
      recInput.disabled = isFinalized;
    }

    // Grounded accounts & assets
    const accContainer = document.getElementById('rep-grounded-accounts');
    if (accContainer) {
      const accs = rep.affected_accounts || [];
      accContainer.innerHTML = accs.length ? accs.map(a => `<code class="badge badge-subtle">${escapeHTML(a)}</code>`).join(' ') : '<em class="text-muted text-xs">None observed / Unknown</em>';
    }

    const astContainer = document.getElementById('rep-grounded-assets');
    if (astContainer) {
      const asts = rep.affected_assets || [];
      astContainer.innerHTML = asts.length ? asts.map(a => `<code class="badge badge-subtle">${escapeHTML(a)}</code>`).join(' ') : '<em class="text-muted text-xs">None observed / Unknown</em>';
    }

    // Detection Context & MITRE ATT&CK
    const detEl = document.getElementById('rep-detection-context');
    if (detEl) detEl.textContent = rep.detection_context || 'No automated detection alert context recorded.';

    const mitreEl = document.getElementById('rep-mitre-mapping');
    if (mitreEl) {
      const mitres = rep.mitre_attack || [];
      if (mitres.length) {
        mitreEl.innerHTML = mitres.map(m => `
          <div class="card" style="padding: var(--space-2); margin-top: 4px; font-size: var(--text-xs);">
            <strong>${escapeHTML(m.technique_id)} &mdash; ${escapeHTML(m.technique_name)}</strong>
            <div class="text-muted" style="margin-top: 2px;">Rule: ${escapeHTML(m.rule_name)}</div>
            <div class="text-muted text-xs" style="margin-top: 2px; font-style: italic;">${escapeHTML(m.classification_limitation || 'Automated rule mapping; not exhaustive attribution.')}</div>
          </div>
        `).join('');
      } else {
        mitreEl.innerHTML = '<span class="text-muted text-xs">No MITRE ATT&CK techniques mapped to correlated alerts.</span>';
      }
    }

    // Render Sub-Tabs
    let findings = rep.analyst_findings;
    if (!findings && rep.analyst_findings_json) {
      try { findings = JSON.parse(rep.analyst_findings_json); } catch(e) { findings = []; }
    }
    renderFindings(findings || [], isFinalized);
    renderEvidence(rep.evidence_links || [], isFinalized);
    loadTimeline(rep.report_id);
    renderVersionHistory(rep.version_history || []);

    // Save Draft button bar visibility
    const saveBar = document.getElementById('rep-save-bar');
    if (saveBar) saveBar.style.display = isFinalized ? 'none' : 'flex';
  }

  // ── Render Lifecycle Action Buttons ────────────────────────────────
  function renderLifecycleButtons(rep) {
    const container = document.getElementById('report-action-buttons');
    if (!container) return;

    container.innerHTML = '';
    const status = rep.status;

    if (status === 'draft') {
      const btnReview = document.createElement('button');
      btnReview.className = 'btn btn-secondary btn-sm';
      btnReview.textContent = 'Submit for Review';
      btnReview.onclick = async () => {
        try {
          await window.API.reports.setStatus(rep.report_id, {
            status: 'in_review',
            expected_version: rep.version
          });
          if (window.UI && window.UI.showToast) window.UI.showToast('Report submitted for peer review.', 'success');
          openReport(rep.report_id);
        } catch (err) {
          if (window.UI && window.UI.showToast) window.UI.showToast(`Failed: ${err.message}`, 'error');
        }
      };
      container.appendChild(btnReview);
    } else if (status === 'in_review') {
      const btnBackDraft = document.createElement('button');
      btnBackDraft.className = 'btn btn-secondary btn-sm';
      btnBackDraft.textContent = 'Request Changes (Draft)';
      btnBackDraft.onclick = async () => {
        try {
          await window.API.reports.setStatus(rep.report_id, {
            status: 'draft',
            expected_version: rep.version
          });
          if (window.UI && window.UI.showToast) window.UI.showToast('Report moved back to draft.', 'info');
          openReport(rep.report_id);
        } catch (err) {
          if (window.UI && window.UI.showToast) window.UI.showToast(`Failed: ${err.message}`, 'error');
        }
      };
      container.appendChild(btnBackDraft);

      const btnFinalize = document.createElement('button');
      btnFinalize.className = 'btn btn-primary btn-sm';
      btnFinalize.textContent = 'Approve & Finalize';
      btnFinalize.onclick = () => {
        openFinalizeModal(rep);
      };
      container.appendChild(btnFinalize);
    } else if (status === 'finalized') {
      const btnRevise = document.createElement('button');
      btnRevise.className = 'btn btn-secondary btn-sm';
      btnRevise.textContent = 'Create Revision (New Version)';
      btnRevise.onclick = () => {
        openReviseModal(rep);
      };
      container.appendChild(btnRevise);
    }
  }

  // ── Quality Checklist Banner ───────────────────────────────────────
  function renderQualityChecklist(qcList) {
    const container = document.getElementById('report-qc-container');
    if (!container) return;

    if (!qcList || !qcList.length) {
      container.innerHTML = '<span class="text-muted text-xs">No quality checks evaluated.</span>';
      return;
    }

    container.innerHTML = qcList.map(c => {
      const badgeCls = c.status === 'pass' ? 'badge-pass' : (c.status === 'warn' ? 'badge-warn' : 'badge-fail');
      const icon = c.status === 'pass' ? 'CHECK' : (c.status === 'warn' ? 'WARN' : 'FAIL');
      return `
        <div class="card" style="padding: var(--space-2); border-left: 3px solid var(--color-${c.status === 'pass' ? 'success' : (c.status === 'warn' ? 'warning' : 'danger')});">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2px;">
            <strong style="font-size: var(--text-xs); color: var(--color-text-primary);">${escapeHTML(c.name)}</strong>
            <span class="badge ${badgeCls}" style="font-size: 9px; padding: 1px 4px;">${icon}</span>
          </div>
          <div class="text-muted text-xs" style="line-height: 1.3;">${escapeHTML(c.description)}</div>
        </div>
      `;
    }).join('');
  }

  // ── Analyst Findings Tab ───────────────────────────────────────────
  function renderFindings(findings, isFinalized) {
    const list = document.getElementById('rep-findings-list');
    if (!list) return;

    if (!findings.length) {
      list.innerHTML = '<div class="text-muted text-xs py-3">No analyst findings documented yet. Click "+ Add Finding" above.</div>';
      return;
    }

    list.innerHTML = findings.map((f, idx) => {
      const confBadge = f.confidence === 'high' ? 'badge-pass' : (f.confidence === 'medium' ? 'badge-warn' : 'badge-subtle');
      const refs = (f.evidence_refs || []).map(r => `<span class="badge badge-subtle font-mono">${escapeHTML(String(r))}</span>`).join(' ') || '<em class="text-muted">None cited</em>';

      return `
        <div class="card" style="padding: var(--space-3); margin-bottom: var(--space-2); background: var(--color-surface);">
          <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 4px;">
            <div>
              <strong style="font-size: var(--text-sm); color: var(--color-text-primary);">Finding #${idx + 1}: ${escapeHTML(f.claim || '')}</strong>
            </div>
            <div style="display: flex; gap: 4px; align-items: center;">
              <span class="badge ${confBadge}">${escapeHTML((f.confidence || 'medium').toUpperCase())} CONFIDENCE</span>
              ${!isFinalized ? `<button class="btn btn-ghost btn-sm btn-del-finding" data-index="${idx}" style="color: var(--color-danger); padding: 2px 6px;">&times;</button>` : ''}
            </div>
          </div>
          <div style="font-size: var(--text-xs); margin-top: 4px;">
            <strong>Cited Evidence:</strong> ${refs}
          </div>
          ${f.rationale ? `<div class="text-muted text-xs" style="margin-top: 4px;"><strong>Analyst Rationale:</strong> ${escapeHTML(f.rationale)}</div>` : ''}
        </div>
      `;
    }).join('');

    if (!isFinalized) {
      list.querySelectorAll('.btn-del-finding').forEach(btn => {
        btn.addEventListener('click', async () => {
          const idx = parseInt(btn.dataset.index, 10);
          const newFindings = [...(currentReportData.report.analyst_findings || [])];
          newFindings.splice(idx, 1);
          await saveReportPartial({ analyst_findings: newFindings });
        });
      });
    }
  }

  // ── Verified Evidence Tab ──────────────────────────────────────────
  function renderEvidence(evidenceLinks, isFinalized) {
    const tbody = document.getElementById('rep-evidence-body');
    if (!tbody) return;

    if (!evidenceLinks.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-3">No evidence linked yet.</td></tr>';
      return;
    }

    tbody.innerHTML = evidenceLinks.map(lk => {
      const provCls = lk.provenance_status === 'observed' ? 'badge-pass' : (lk.provenance_status === 'unavailable' ? 'badge-fail' : 'badge-warn');
      return `
        <tr>
          <td><code class="font-mono text-xs">${escapeHTML(lk.reference_type)}</code></td>
          <td class="font-mono text-cyan"><strong>${escapeHTML(String(lk.reference_id))}</strong></td>
          <td>${escapeHTML(lk.label)}</td>
          <td><span class="badge ${provCls}">${escapeHTML(lk.provenance_status)}</span></td>
          <td class="text-xs">${escapeHTML(lk.snapshot_summary)}</td>
          <td class="text-xs text-muted">${escapeHTML(lk.limitations_note || 'None')}</td>
          <td>
            ${!isFinalized ? `<button class="btn btn-ghost btn-sm text-danger btn-unlink-evidence" data-link-id="${lk.id}">&times; Remove</button>` : '<span class="text-muted text-xs">Locked</span>'}
          </td>
        </tr>
      `;
    }).join('');

    if (!isFinalized) {
      tbody.querySelectorAll('.btn-unlink-evidence').forEach(btn => {
        btn.addEventListener('click', async () => {
          const linkId = btn.dataset.linkId;
          try {
            await window.API.reports.unlinkEvidence(currentReportId, linkId);
            if (window.UI && window.UI.showToast) window.UI.showToast('Evidence unlinked.', 'info');
            openReport(currentReportId);
          } catch (err) {
            if (window.UI && window.UI.showToast) window.UI.showToast(`Failed to unlink: ${err.message}`, 'error');
          }
        });
      });
    }
  }

  // ── Investigation Timeline Tab ─────────────────────────────────────
  async function loadTimeline(reportId) {
    const tbody = document.getElementById('rep-timeline-body');
    if (!tbody) return;

    tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-3">Loading timeline...</td></tr>';
    const filter = document.getElementById('rep-timeline-filter')?.value || 'all';

    try {
      const res = await window.API.reports.getTimeline(reportId, { category: filter });
      const items = res.timeline || [];

      if (!items.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-3">No activity recorded for this category.</td></tr>';
        return;
      }

      tbody.innerHTML = items.map(ev => {
        const catBadge = `<span class="badge badge-${ev.category}">${escapeHTML(ev.category)}</span>`;
        const tzInfo = (ev.original_timezone && ev.original_timezone !== 'UTC') ? ` <small class="text-muted">(${escapeHTML(ev.original_timezone)})</small>` : '';
        return `
          <tr>
            <td class="font-mono text-xs">${escapeHTML(ev.occurrence_time)}${tzInfo}</td>
            <td class="font-mono text-xs text-muted">${escapeHTML(ev.recorded_time)}</td>
            <td>${catBadge}</td>
            <td><strong>${escapeHTML(ev.event_type)}</strong></td>
            <td class="font-mono text-xs">${escapeHTML(ev.actor || '-')}</td>
            <td class="text-xs">${escapeHTML(ev.details || '')}</td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      console.error('[Reports] Failed to load timeline:', err);
      tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger py-3">Failed: ${escapeHTML(err.message)}</td></tr>`;
    }
  }

  // ── Version History Tab ────────────────────────────────────────────
  function renderVersionHistory(versions) {
    const tbody = document.getElementById('rep-versions-body');
    if (!tbody) return;

    if (!versions.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-3">Current draft working copy. No immutable snapshots finalized yet.</td></tr>';
      return;
    }

    tbody.innerHTML = versions.map(v => `
      <tr>
        <td><strong>v${v.version}</strong></td>
        <td><span class="badge badge-pass">${escapeHTML((v.status || 'finalized').toUpperCase())}</span></td>
        <td><small>@${escapeHTML(v.finalized_by_username || v.author_username || '-')}</small></td>
        <td class="text-xs text-muted">${escapeHTML(v.finalized_at || v.created_at || '-')}</td>
        <td class="text-xs">${escapeHTML(v.change_summary || 'Preserved version snapshot.')}</td>
        <td>
          <div style="display: flex; gap: var(--space-1);">
            <a href="${window.API.reports.getExportHtmlUrl(currentReportId, v.version)}" target="_blank" class="btn btn-secondary btn-xs" title="Export HTML for v${v.version}">HTML</a>
            <a href="${window.API.reports.getExportJsonUrl(currentReportId, v.version)}" download class="btn btn-secondary btn-xs" title="Export JSON for v${v.version}">JSON</a>
          </div>
        </td>
      </tr>
    `).join('');
  }

  // ── Save Report Draft ──────────────────────────────────────────────
  async function saveReportDraft() {
    if (!currentReportId || !currentReportData) return;

    const rep = currentReportData.report;
    const summary = document.getElementById('rep-edit-summary')?.value || '';
    const remediation = document.getElementById('rep-edit-remediation')?.value || '';
    const recommendations = document.getElementById('rep-edit-recommendations')?.value || '';

    try {
      await window.API.reports.update(currentReportId, {
        expected_version: rep.version,
        executive_summary: summary,
        containment_remediation_history: remediation,
        recommendations: recommendations
      });
      if (window.UI && window.UI.showToast) window.UI.showToast('Report draft saved.', 'success');
      openReport(currentReportId);
    } catch (err) {
      console.error('[Reports] Save failed:', err);
      if (window.UI && window.UI.showToast) window.UI.showToast(`Save failed: ${err.message}`, 'error');
    }
  }

  async function saveReportPartial(payload) {
    if (!currentReportId || !currentReportData) return;
    const rep = currentReportData.report;

    try {
      await window.API.reports.update(currentReportId, {
        expected_version: rep.version,
        ...payload
      });
      openReport(currentReportId);
    } catch (err) {
      console.error('[Reports] Partial save failed:', err);
      if (window.UI && window.UI.showToast) window.UI.showToast(`Update failed: ${err.message}`, 'error');
    }
  }

  // ── Modal Actions ──────────────────────────────────────────────────
  function openCreateModal(defaultCaseId = null) {
    const modal = document.getElementById('modal-create-report');
    if (!modal) return;

    const caseInput = document.getElementById('create-rep-case-id');
    const titleInput = document.getElementById('create-rep-title');
    const sumInput = document.getElementById('create-rep-summary');

    if (caseInput && defaultCaseId) {
      caseInput.value = defaultCaseId;
      caseInput.disabled = true;
    } else if (caseInput) {
      caseInput.value = '';
      caseInput.disabled = false;
    }

    if (titleInput) titleInput.value = '';
    if (sumInput) sumInput.value = '';

    modal.classList.add('active');
  }

  async function submitCreateReport(e) {
    if (e) e.preventDefault();
    const caseId = document.getElementById('create-rep-case-id')?.value;
    const title = document.getElementById('create-rep-title')?.value;
    const summary = document.getElementById('create-rep-summary')?.value;

    if (!caseId) {
      if (window.UI && window.UI.showToast) window.UI.showToast('Case ID is required.', 'error');
      return;
    }

    try {
      const res = await window.API.reports.create({
        case_id: parseInt(caseId, 10),
        title: title || undefined,
        executive_summary: summary || undefined
      });

      const modal = document.getElementById('modal-create-report');
      if (modal) modal.classList.remove('active');

      if (window.UI && window.UI.showToast) window.UI.showToast(`Report ${res.report_id} initialized.`, 'success');
      openReport(res.report_id);
    } catch (err) {
      if (window.UI && window.UI.showToast) window.UI.showToast(`Failed: ${err.message}`, 'error');
    }
  }

  function openFinalizeModal(rep) {
    const modal = document.getElementById('modal-finalize-report');
    if (!modal) return;
    const chgInput = document.getElementById('finalize-rep-change-summary');
    const chk = document.getElementById('finalize-rep-signoff-chk');
    if (chgInput) chgInput.value = `Formal signoff and finalization of investigation report v${rep.version}`;
    if (chk) chk.checked = false;
    modal.classList.add('active');
  }

  async function submitFinalizeReport() {
    const chk = document.getElementById('finalize-rep-signoff-chk');
    if (!chk || !chk.checked) {
      if (window.UI && window.UI.showToast) window.UI.showToast('Please confirm analyst signoff.', 'warning');
      return;
    }

    const summary = document.getElementById('finalize-rep-change-summary')?.value;
    try {
      await window.API.reports.setStatus(currentReportId, {
        status: 'finalized',
        expected_version: currentReportData.report.version,
        change_summary: summary
      });

      const modal = document.getElementById('modal-finalize-report');
      if (modal) modal.classList.remove('active');

      if (window.UI && window.UI.showToast) window.UI.showToast('Report successfully finalized and snapshot frozen.', 'success');
      openReport(currentReportId);
    } catch (err) {
      if (window.UI && window.UI.showToast) window.UI.showToast(`Finalize failed: ${err.message}`, 'error');
    }
  }

  function openReviseModal(rep) {
    const modal = document.getElementById('modal-revise-report');
    if (!modal) return;
    const chgInput = document.getElementById('revise-rep-change-summary');
    if (chgInput) chgInput.value = `Revision v${rep.version + 1} initiated for new evidence analysis.`;
    modal.classList.add('active');
  }

  async function submitReviseReport() {
    const summary = document.getElementById('revise-rep-change-summary')?.value;
    try {
      const res = await window.API.reports.revise(currentReportId, {
        change_summary: summary
      });

      const modal = document.getElementById('modal-revise-report');
      if (modal) modal.classList.remove('active');

      if (window.UI && window.UI.showToast) window.UI.showToast(`Revision v${res.version} created.`, 'success');
      openReport(currentReportId);
    } catch (err) {
      if (window.UI && window.UI.showToast) window.UI.showToast(`Revision failed: ${err.message}`, 'error');
    }
  }

  function openLinkEvidenceModal() {
    const modal = document.getElementById('modal-link-evidence');
    if (!modal) return;
    const refType = document.getElementById('link-ev-type');
    const refId = document.getElementById('link-ev-id');
    const label = document.getElementById('link-ev-label');
    const note = document.getElementById('link-ev-note');
    if (refType) refType.value = 'security_event';
    if (refId) refId.value = '';
    if (label) label.value = '';
    if (note) note.value = '';
    modal.classList.add('active');
  }

  async function submitLinkEvidence() {
    const refType = document.getElementById('link-ev-type')?.value;
    const refId = document.getElementById('link-ev-id')?.value;
    const label = document.getElementById('link-ev-label')?.value;
    const note = document.getElementById('link-ev-note')?.value;

    if (!refType || !refId) {
      if (window.UI && window.UI.showToast) window.UI.showToast('Reference type and ID are required.', 'error');
      return;
    }

    try {
      await window.API.reports.linkEvidence(currentReportId, {
        reference_type: refType,
        reference_id: refId,
        label: label || undefined,
        limitations_note: note || undefined
      });

      const modal = document.getElementById('modal-link-evidence');
      if (modal) modal.classList.remove('active');

      if (window.UI && window.UI.showToast) window.UI.showToast('Evidence record linked.', 'success');
      openReport(currentReportId);
    } catch (err) {
      if (window.UI && window.UI.showToast) window.UI.showToast(`Link failed: ${err.message}`, 'error');
    }
  }

  function openAddFindingModal() {
    const modal = document.getElementById('modal-add-finding');
    if (!modal) return;
    const claim = document.getElementById('finding-claim-input');
    const conf = document.getElementById('finding-conf-select');
    const refs = document.getElementById('finding-refs-input');
    const rat = document.getElementById('finding-rat-input');
    if (claim) claim.value = '';
    if (conf) conf.value = 'medium';
    if (refs) refs.value = '';
    if (rat) rat.value = '';
    modal.classList.add('active');
  }

  async function submitAddFinding() {
    const claim = document.getElementById('finding-claim-input')?.value.trim();
    const conf = document.getElementById('finding-conf-select')?.value;
    const refsRaw = document.getElementById('finding-refs-input')?.value.trim();
    const rationale = document.getElementById('finding-rat-input')?.value.trim();

    if (!claim) {
      if (window.UI && window.UI.showToast) window.UI.showToast('Finding claim is required.', 'error');
      return;
    }

    const refs = refsRaw ? refsRaw.split(',').map(s => s.trim()).filter(Boolean) : [];
    const findings = [...(currentReportData.report.analyst_findings || [])];
    findings.push({
      claim,
      confidence: conf,
      evidence_refs: refs,
      rationale
    });

    try {
      await saveReportPartial({ analyst_findings: findings });
      const modal = document.getElementById('modal-add-finding');
      if (modal) modal.classList.remove('active');
      if (window.UI && window.UI.showToast) window.UI.showToast('Analyst finding added.', 'success');
    } catch (err) {
      if (window.UI && window.UI.showToast) window.UI.showToast(`Failed: ${err.message}`, 'error');
    }
  }

  // ── Tab Switching ──────────────────────────────────────────────────
  function setupTabs() {
    document.querySelectorAll('#report-detail-container .tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const targetTab = btn.dataset.tab;
        document.querySelectorAll('#report-detail-container .tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('#report-detail-container .tab-panel').forEach(p => p.style.display = 'none');

        btn.classList.add('active');
        const panel = document.getElementById(targetTab);
        if (panel) panel.style.display = 'block';
        activeTab = targetTab;

        if (targetTab === 'tab-rep-timeline' && currentReportId) {
          loadTimeline(currentReportId);
        }
      });
    });
  }

  // ── Init ───────────────────────────────────────────────────────────
  function init() {
    // List view buttons
    const btnCreate = document.getElementById('btn-create-report');
    if (btnCreate) btnCreate.addEventListener('click', () => openCreateModal());

    const btnRefresh = document.getElementById('btn-refresh-reports');
    if (btnRefresh) btnRefresh.addEventListener('click', () => loadReports());

    const statusFilter = document.getElementById('report-status-filter');
    if (statusFilter) statusFilter.addEventListener('change', () => loadReports());

    const searchInput = document.getElementById('report-search-input');
    if (searchInput) {
      let timeout = null;
      searchInput.addEventListener('input', () => {
        clearTimeout(timeout);
        timeout = setTimeout(loadReports, 300);
      });
    }

    // Detail view buttons
    const btnBack = document.getElementById('btn-back-to-reports');
    if (btnBack) btnBack.addEventListener('click', () => closeReportDetail());

    const btnSaveDraft = document.getElementById('btn-save-draft');
    if (btnSaveDraft) btnSaveDraft.addEventListener('click', () => saveReportDraft());

    const btnAddFinding = document.getElementById('btn-add-finding');
    if (btnAddFinding) btnAddFinding.addEventListener('click', () => openAddFindingModal());

    const btnLinkEvidence = document.getElementById('btn-link-evidence');
    if (btnLinkEvidence) btnLinkEvidence.addEventListener('click', () => openLinkEvidenceModal());

    const tlFilter = document.getElementById('rep-timeline-filter');
    if (tlFilter) tlFilter.addEventListener('change', () => {
      if (currentReportId) loadTimeline(currentReportId);
    });

    // Modals confirm buttons
    const formCreate = document.getElementById('form-create-report');
    if (formCreate) formCreate.addEventListener('submit', submitCreateReport);

    const btnConfirmFinalize = document.getElementById('confirm-finalize-report-btn');
    if (btnConfirmFinalize) btnConfirmFinalize.addEventListener('click', submitFinalizeReport);

    const btnConfirmRevise = document.getElementById('confirm-revise-report-btn');
    if (btnConfirmRevise) btnConfirmRevise.addEventListener('click', submitReviseReport);

    const btnConfirmLinkEv = document.getElementById('confirm-link-evidence-btn');
    if (btnConfirmLinkEv) btnConfirmLinkEv.addEventListener('click', submitLinkEvidence);

    const btnConfirmAddFind = document.getElementById('confirm-add-finding-btn');
    if (btnConfirmAddFind) btnConfirmAddFind.addEventListener('click', submitAddFinding);

    setupTabs();
  }

  function switchSubView(subView) {
    if (subView === 'list') {
      closeReportDetail();
    }
  }

  window.Reports = {
    init,
    loadReports,
    openReport,
    openCreateModal,
    closeReportDetail,
    switchSubView
  };

})(window);
