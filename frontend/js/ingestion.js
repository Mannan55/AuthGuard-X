/**
 * AuthGuard-X — Security Event Ingestion & Normalization Workspace (Sprint 4)
 * Handles multi-format log upload, training datasets loading, event explorer filtering,
 * pagination, normalized telemetry inspection, and investigation workspace linking.
 */

(function (window) {
  'use strict';

  const Ingestion = {
    state: {
      currentPage: 1,
      perPage: 20,
      totalPages: 1,
      totalEvents: 0,
      filters: {
        source_type: 'all',
        category: 'all',
        outcome: 'all',
        severity: 'all',
        search: ''
      },
      selectedFile: null
    },

    init() {
      this.bindEvents();
    },

    bindEvents() {
      // Search input with debounce
      const searchInput = document.getElementById('event-search-input');
      if (searchInput) {
        let debounceTimer;
        searchInput.addEventListener('input', (e) => {
          clearTimeout(debounceTimer);
          debounceTimer = setTimeout(() => {
            this.state.filters.search = e.target.value.trim();
            this.state.currentPage = 1;
            this.loadEvents();
          }, 300);
        });
      }

      // Filter dropdowns
      const srcFilter = document.getElementById('event-source-filter');
      if (srcFilter) {
        srcFilter.addEventListener('change', (e) => {
          this.state.filters.source_type = e.target.value;
          this.state.currentPage = 1;
          this.loadEvents();
        });
      }

      const catFilter = document.getElementById('event-category-filter');
      if (catFilter) {
        catFilter.addEventListener('change', (e) => {
          this.state.filters.category = e.target.value;
          this.state.currentPage = 1;
          this.loadEvents();
        });
      }

      const outcomeFilter = document.getElementById('event-outcome-filter');
      if (outcomeFilter) {
        outcomeFilter.addEventListener('change', (e) => {
          this.state.filters.outcome = e.target.value;
          this.state.currentPage = 1;
          this.loadEvents();
        });
      }

      const sevFilter = document.getElementById('event-severity-filter');
      if (sevFilter) {
        sevFilter.addEventListener('change', (e) => {
          this.state.filters.severity = e.target.value;
          this.state.currentPage = 1;
          this.loadEvents();
        });
      }

      // Reset filters button
      const resetBtn = document.getElementById('btn-reset-event-filters');
      if (resetBtn) {
        resetBtn.addEventListener('click', () => {
          this.state.filters = {
            source_type: 'all',
            category: 'all',
            outcome: 'all',
            severity: 'all',
            search: ''
          };
          if (searchInput) searchInput.value = '';
          if (srcFilter) srcFilter.value = 'all';
          if (catFilter) catFilter.value = 'all';
          if (outcomeFilter) outcomeFilter.value = 'all';
          if (sevFilter) sevFilter.value = 'all';
          this.state.currentPage = 1;
          this.loadEvents();
        });
      }

      // Pagination controls
      const prevBtn = document.getElementById('event-prev-page');
      if (prevBtn) {
        prevBtn.addEventListener('click', () => {
          if (this.state.currentPage > 1) {
            this.state.currentPage--;
            this.loadEvents();
          }
        });
      }

      const nextBtn = document.getElementById('event-next-page');
      if (nextBtn) {
        nextBtn.addEventListener('click', () => {
          if (this.state.currentPage < this.state.totalPages) {
            this.state.currentPage++;
            this.loadEvents();
          }
        });
      }

      const perPageSelect = document.getElementById('event-per-page');
      if (perPageSelect) {
        perPageSelect.addEventListener('change', (e) => {
          this.state.perPage = parseInt(e.target.value, 10) || 20;
          this.state.currentPage = 1;
          this.loadEvents();
        });
      }

      // Action Buttons
      const openImportBtn = document.getElementById('btn-open-import-modal');
      if (openImportBtn) {
        openImportBtn.addEventListener('click', () => this.openImportModal());
      }

      const openSamplesBtn = document.getElementById('btn-open-samples-modal');
      if (openSamplesBtn) {
        openSamplesBtn.addEventListener('click', () => this.openSamplesModal());
      }

      const exportBtn = document.getElementById('btn-export-events-csv');
      if (exportBtn) {
        exportBtn.addEventListener('click', () => {
          const exportUrl = window.API.ingestion.getExportUrl(this.state.filters);
          window.location.href = exportUrl;
        });
      }

      // File Drag & Drop Setup
      const dropZone = document.getElementById('import-drop-zone');
      const fileInput = document.getElementById('import-file-input');
      const filenameLabel = document.getElementById('import-selected-filename');

      if (dropZone && fileInput) {
        dropZone.addEventListener('click', () => fileInput.click());

        fileInput.addEventListener('change', (e) => {
          if (e.target.files && e.target.files[0]) {
            this.state.selectedFile = e.target.files[0];
            if (filenameLabel) {
              filenameLabel.textContent = `Selected: ${this.state.selectedFile.name} (${Math.round(this.state.selectedFile.size / 1024)} KB)`;
              filenameLabel.style.display = 'block';
            }
          }
        });

        ['dragenter', 'dragover'].forEach(eventName => {
          dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.style.borderColor = 'var(--color-primary)';
          });
        });

        ['dragleave', 'drop'].forEach(eventName => {
          dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.style.borderColor = 'var(--color-border)';
          });
        });

        dropZone.addEventListener('drop', (e) => {
          if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
            this.state.selectedFile = e.dataTransfer.files[0];
            if (filenameLabel) {
              filenameLabel.textContent = `Selected: ${this.state.selectedFile.name} (${Math.round(this.state.selectedFile.size / 1024)} KB)`;
              filenameLabel.style.display = 'block';
            }
          }
        });
      }

      // Import execute button
      const execImportBtn = document.getElementById('btn-execute-import');
      if (execImportBtn) {
        execImportBtn.addEventListener('click', () => this.executeImport());
      }
    },

    refresh() {
      this.loadEvents();
    },

    async loadEvents() {
      const tbody = document.getElementById('security-events-tbody');
      const countLabel = document.getElementById('events-count-label');

      if (tbody) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center text-muted" style="padding: var(--space-6);">Loading security events...</td></tr>`;
      }

      try {
        const params = {
          page: this.state.currentPage,
          per_page: this.state.perPage,
          source_type: this.state.filters.source_type,
          category: this.state.filters.category,
          outcome: this.state.filters.outcome,
          severity: this.state.filters.severity,
          search: this.state.filters.search
        };

        const res = await window.API.ingestion.getEvents(params);
        this.state.totalEvents = res.total;
        this.state.totalPages = res.total_pages;

        // Update pagination UI
        const pageInfo = document.getElementById('event-page-info');
        if (pageInfo) {
          pageInfo.textContent = `Page ${res.page} of ${res.total_pages || 1} (${res.total} total)`;
        }
        if (countLabel) {
          countLabel.textContent = `Showing ${res.events.length} of ${res.total} records`;
        }

        const prevBtn = document.getElementById('event-prev-page');
        if (prevBtn) prevBtn.disabled = res.page <= 1;

        const nextBtn = document.getElementById('event-next-page');
        if (nextBtn) nextBtn.disabled = res.page >= res.total_pages;

        // Update stats
        this.updateStatsCards(res);

        // Render Table Rows
        if (!res.events || res.events.length === 0) {
          if (tbody) {
            tbody.innerHTML = `<tr><td colspan="9" class="text-center text-muted" style="padding: var(--space-6);">No normalized security events found matching current criteria.</td></tr>`;
          }
          return;
        }

        if (tbody) {
          tbody.innerHTML = res.events.map(evt => this.renderEventRow(evt)).join('');
          // Bind click listeners for inspect buttons
          tbody.querySelectorAll('.btn-inspect-event').forEach(btn => {
            btn.addEventListener('click', (e) => {
              const eventId = e.currentTarget.dataset.id;
              this.openEventDetail(eventId);
            });
          });
        }
      } catch (err) {
        if (tbody) {
          tbody.innerHTML = `<tr><td colspan="9" class="text-center text-danger" style="padding: var(--space-4);">Failed to load security events: ${this.escapeHtml(err.message)}</td></tr>`;
        }
        if (window.UI && window.UI.showToast) {
          window.UI.showToast(`Error loading events: ${err.message}`, 'error');
        }
      }
    },

    renderEventRow(evt) {
      const outcomeBadge = this.getOutcomeBadge(evt.outcome);
      const severityBadge = this.getSeverityBadge(evt.severity);
      const sourceBadge = `<span class="badge badge-subtle font-mono text-xs">${this.escapeHtml(evt.source_type)}</span>`;
      const provenanceBadge = evt.provenance === 'synthetic' 
        ? `<span class="badge badge-subtle" title="Synthetic Simulation Provenance">SIM</span>`
        : `<span class="badge badge-subtle text-cyan" title="Imported Real-World Telemetry">IMPORTED</span>`;

      return `
        <tr data-event-id="${evt.id}">
          <td class="font-mono text-xs" style="white-space: nowrap;">${this.escapeHtml(evt.event_time)}</td>
          <td>${sourceBadge} ${provenanceBadge}</td>
          <td>
            <strong style="color: var(--color-text-primary);">${this.escapeHtml(evt.attack_type)}</strong>
            <div class="text-muted text-xs">${this.escapeHtml(evt.category)}</div>
          </td>
          <td class="font-mono text-xs">${this.escapeHtml(evt.username || 'unknown')}</td>
          <td class="font-mono text-xs text-primary">${this.escapeHtml(evt.source_ip)}</td>
          <td class="font-mono text-xs text-muted">${this.escapeHtml(evt.dest_ip || '—')}</td>
          <td>${outcomeBadge}</td>
          <td>${severityBadge} <span class="font-mono text-xs text-muted">(${evt.risk_score})</span></td>
          <td>
            <button class="btn btn-secondary btn-sm btn-inspect-event" data-id="${evt.id}">
              Inspect
            </button>
          </td>
        </tr>
      `;
    },

    async updateStatsCards(eventsRes) {
      const statTotal = document.getElementById('stat-total-events');
      if (statTotal) statTotal.textContent = eventsRes.total.toLocaleString();

      try {
        const batchesRes = await window.API.ingestion.getBatches({ per_page: 1 });
        const statBatches = document.getElementById('stat-total-batches');
        if (statBatches) statBatches.textContent = batchesRes.total.toLocaleString();
      } catch (e) {
        // Soft fail
      }

      // Count failures and distinct threat IPs in current slice
      if (eventsRes.events) {
        const failCount = eventsRes.events.filter(e => e.outcome === 'failure' || e.outcome === 'blocked').length;
        const statFailed = document.getElementById('stat-failed-outcomes');
        if (statFailed) statFailed.textContent = failCount.toString();

        const threatIps = new Set(eventsRes.events.map(e => e.source_ip)).size;
        const statIps = document.getElementById('stat-threat-ips');
        if (statIps) statIps.textContent = threatIps.toString();
      }
    },

    async openEventDetail(eventId) {
      const modal = document.getElementById('modal-event-detail');
      if (!modal) return;

      try {
        const evt = await window.API.ingestion.getEvent(eventId);

        document.getElementById('event-detail-id').textContent = `#${evt.id}`;
        document.getElementById('event-detail-time').textContent = evt.event_time;
        document.getElementById('event-detail-attack').textContent = evt.attack_type;
        document.getElementById('event-detail-category').textContent = evt.category;
        document.getElementById('event-detail-source-type').textContent = evt.source_type;
        document.getElementById('event-detail-provenance').textContent = evt.provenance;
        document.getElementById('event-detail-user').textContent = evt.username || 'unknown';
        document.getElementById('event-detail-ip').textContent = evt.source_ip;
        document.getElementById('event-detail-dest-ip').textContent = evt.dest_ip || '—';
        document.getElementById('event-detail-host').textContent = evt.hostname || '—';

        const origTimeEl = document.getElementById('event-detail-original-time');
        if (origTimeEl) origTimeEl.textContent = evt.original_timestamp || evt.event_time || '—';

        const origTzEl = document.getElementById('event-detail-original-tz');
        if (origTzEl) origTzEl.textContent = evt.original_timezone || 'UTC';

        const rawHashEl = document.getElementById('event-detail-raw-hash');
        if (rawHashEl) rawHashEl.textContent = evt.raw_hash || '—';

        const provEl = document.getElementById('event-detail-field-provenance');
        if (provEl) {
          const p = evt.field_provenance || {};
          provEl.innerHTML = Object.entries(p).map(([k, v]) => {
            const badgeClass = v === 'observed' ? 'text-success' : (v === 'inferred' || v === 'inferred_year' ? 'text-amber' : 'text-muted');
            return `<span style="margin-right: 8px;"><strong>${k}:</strong> <span class="${badgeClass}">${v}</span></span>`;
          }).join('') || '—';
        }

        const rawPayloadPre = document.getElementById('event-detail-raw-payload');
        if (rawPayloadPre) {
          rawPayloadPre.textContent = evt.raw_payload || '—';
        }

        const outcomeEl = document.getElementById('event-detail-outcome');
        outcomeEl.innerHTML = this.getOutcomeBadge(evt.outcome);

        const sevEl = document.getElementById('event-detail-severity');
        sevEl.innerHTML = this.getSeverityBadge(evt.severity);

        document.getElementById('event-detail-risk').textContent = evt.risk_score;
        document.getElementById('event-detail-behavior').textContent = evt.metadata && evt.metadata.behavior ? evt.metadata.behavior : (evt.source_record_ref || 'Standard event telemetry');
        document.getElementById('event-detail-fingerprint').textContent = evt.fingerprint || '—';

        const rawPre = document.getElementById('event-detail-raw-metadata');
        if (rawPre) {
          rawPre.textContent = JSON.stringify(evt.metadata || {}, null, 2);
        }

        // Action button
        const actionContainer = document.getElementById('event-investigation-action');
        if (actionContainer) {
          if (evt.incident_id) {
            actionContainer.innerHTML = `
              <button class="btn btn-primary btn-sm" id="btn-jump-investigate">
                Open Investigation Case #${evt.incident_id} &rarr;
              </button>
            `;
            const jumpBtn = document.getElementById('btn-jump-investigate');
            if (jumpBtn) {
              jumpBtn.addEventListener('click', () => {
                if (window.UI && window.UI.closeModal) window.UI.closeModal(modal);
                window.location.hash = `#investigation?id=${evt.incident_id}`;
                if (window.Investigation && window.Investigation.openCase) {
                  window.Investigation.openCase(evt.incident_id);
                }
              });
            }
          } else {
            actionContainer.innerHTML = '';
          }
        }

        if (window.UI && window.UI.openModal) {
          window.UI.openModal(modal);
        } else {
          modal.classList.add('show');
          modal.setAttribute('aria-hidden', 'false');
        }
      } catch (err) {
        if (window.UI && window.UI.showToast) {
          window.UI.showToast(`Error retrieving event detail: ${err.message}`, 'error');
        }
      }
    },

    openImportModal() {
      const modal = document.getElementById('modal-log-import');
      if (!modal) return;

      const banner = document.getElementById('import-result-banner');
      if (banner) banner.style.display = 'none';

      const fileLabel = document.getElementById('import-selected-filename');
      if (fileLabel) fileLabel.style.display = 'none';

      const fileInput = document.getElementById('import-file-input');
      if (fileInput) fileInput.value = '';

      const textInput = document.getElementById('import-text-content');
      if (textInput) textInput.value = '';

      this.state.selectedFile = null;

      if (window.UI && window.UI.openModal) {
        window.UI.openModal(modal);
      } else {
        modal.classList.add('show');
        modal.setAttribute('aria-hidden', 'false');
      }
    },

    async executeImport() {
      const btn = document.getElementById('btn-execute-import');
      const banner = document.getElementById('import-result-banner');
      const formatSelect = document.getElementById('import-format-select');
      const textInput = document.getElementById('import-text-content');
      const dryRunCheckbox = document.getElementById('import-dry-run-checkbox');

      const format = formatSelect ? formatSelect.value : 'auto';
      const textContent = textInput ? textInput.value.trim() : '';
      const dryRun = dryRunCheckbox ? dryRunCheckbox.checked : false;

      if (!this.state.selectedFile && !textContent) {
        if (banner) {
          banner.style.display = 'block';
          banner.style.background = 'rgba(239, 68, 68, 0.15)';
          banner.style.color = 'var(--color-danger)';
          banner.textContent = 'Please choose a log file to upload or paste log telemetry data.';
        }
        return;
      }

      if (btn) btn.disabled = true;

      try {
        let result;
        if (this.state.selectedFile) {
          const formData = new FormData();
          formData.append('file', this.state.selectedFile);
          formData.append('format', format);
          if (dryRun) formData.append('dry_run', 'true');
          result = await window.API.ingestion.importLogs(formData, true);
        } else {
          result = await window.API.ingestion.importLogs({
            content: textContent,
            format: format,
            filename: 'pasted_telemetry.txt',
            dry_run: dryRun
          }, false);
        }

        if (banner) {
          banner.style.display = 'block';
          if (result.status === 'dry_run') {
            banner.style.background = 'rgba(56, 189, 248, 0.15)';
            banner.style.color = 'var(--color-cyan)';
            banner.innerHTML = `<strong>Dry Run Succeeded:</strong> Parsed ${result.total_records_found} valid records (${result.parse_errors_count} parse errors). No changes written to database.`;
          } else if (result.detection_status === 'failed') {
            banner.style.background = 'rgba(245, 158, 11, 0.15)';
            banner.style.color = 'var(--color-amber)';
            banner.innerHTML = `
              <strong>Import Saved (Batch ${result.batch_id}), Detection Failed:</strong> ${this.escapeHtml(result.summary)}
              <div style="margin-top: 8px;">
                <button class="btn btn-sm btn-secondary" id="btn-retry-batch-detection">Retry Detection Pipeline &rarr;</button>
              </div>
            `;
            const retryBtn = document.getElementById('btn-retry-batch-detection');
            if (retryBtn) {
              retryBtn.addEventListener('click', async () => {
                retryBtn.disabled = true;
                retryBtn.textContent = 'Retrying...';
                try {
                  const retryRes = await window.API.ingestion.retryDetection(result.batch_id);
                  banner.style.background = 'rgba(16, 185, 129, 0.15)';
                  banner.style.color = 'var(--color-success)';
                  banner.innerHTML = `<strong>Detection Complete:</strong> ${this.escapeHtml(retryRes.message)}`;
                  this.loadEvents();
                  if (window.UI && window.UI.showToast) {
                    window.UI.showToast(retryRes.message, 'success');
                  }
                } catch (e) {
                  banner.style.background = 'rgba(239, 68, 68, 0.15)';
                  banner.style.color = 'var(--color-danger)';
                  banner.textContent = `Retry failed: ${e.message}`;
                }
              });
            }
            this.loadEvents();
          } else {
            banner.style.background = 'rgba(16, 185, 129, 0.15)';
            banner.style.color = 'var(--color-success)';
            banner.innerHTML = `<strong>Import Complete (Batch ${result.batch_id}):</strong> ${this.escapeHtml(result.summary)}`;
            
            // Reload feed
            this.loadEvents();
            if (window.UI && window.UI.showToast) {
              window.UI.showToast(`Imported ${result.accepted_records} event(s) successfully!`, 'success');
            }
          }
        }
      } catch (err) {
        if (banner) {
          banner.style.display = 'block';
          banner.style.background = 'rgba(239, 68, 68, 0.15)';
          banner.style.color = 'var(--color-danger)';
          banner.textContent = `Import Failed: ${err.message}`;
        }
        if (window.UI && window.UI.showToast) {
          window.UI.showToast(`Import error: ${err.message}`, 'error');
        }
      } finally {
        if (btn) btn.disabled = false;
      }
    },

    async openSamplesModal() {
      const modal = document.getElementById('modal-load-sample');
      if (!modal) return;

      const listContainer = document.getElementById('samples-dataset-list');
      const statusBanner = document.getElementById('sample-load-status-banner');
      if (statusBanner) statusBanner.style.display = 'none';

      if (listContainer) {
        listContainer.innerHTML = '<div class="text-center text-muted py-4">Loading training datasets catalog...</div>';
      }

      if (window.UI && window.UI.openModal) {
        window.UI.openModal(modal);
      } else {
        modal.classList.add('show');
        modal.setAttribute('aria-hidden', 'false');
      }

      try {
        const res = await window.API.ingestion.getSamples();
        if (listContainer) {
          listContainer.innerHTML = res.samples.map(s => `
            <div class="card" style="padding: var(--space-3); display: flex; justify-content: space-between; align-items: center; gap: var(--space-3);">
              <div style="flex: 1;">
                <div style="display: flex; align-items: center; gap: var(--space-2); margin-bottom: 4px;">
                  <strong style="color: var(--color-text-primary); font-size: var(--text-sm);">${this.escapeHtml(s.name)}</strong>
                  <span class="badge badge-subtle font-mono text-xs">${this.escapeHtml(s.format)}</span>
                  <span class="badge badge-subtle text-xs" style="color: var(--color-cyan);">${this.escapeHtml(s.mitre_technique)}</span>
                </div>
                <div class="text-muted text-xs">${this.escapeHtml(s.description)}</div>
                <div class="text-muted font-mono" style="font-size: 11px; margin-top: 4px;">${this.escapeHtml(s.filename)}</div>
              </div>
              <div>
                <button class="btn btn-primary btn-sm btn-load-sample" data-id="${s.id}">
                  Load Dataset
                </button>
              </div>
            </div>
          `).join('');

          listContainer.querySelectorAll('.btn-load-sample').forEach(btn => {
            btn.addEventListener('click', (e) => {
              const sampleId = e.currentTarget.dataset.id;
              this.executeLoadSample(sampleId, e.currentTarget);
            });
          });
        }
      } catch (err) {
        if (listContainer) {
          listContainer.innerHTML = `<div class="text-danger text-center py-4">Failed to load sample catalog: ${this.escapeHtml(err.message)}</div>`;
        }
      }
    },

    async executeLoadSample(sampleId, btnElement) {
      const statusBanner = document.getElementById('sample-load-status-banner');
      if (btnElement) {
        btnElement.disabled = true;
        btnElement.textContent = 'Loading...';
      }

      try {
        const res = await window.API.ingestion.loadSample(sampleId);
        if (statusBanner) {
          statusBanner.style.display = 'block';
          statusBanner.style.background = 'rgba(16, 185, 129, 0.15)';
          statusBanner.style.color = 'var(--color-success)';
          statusBanner.textContent = res.message;
        }
        if (window.UI && window.UI.showToast) {
          window.UI.showToast(res.message, 'success');
        }
        this.loadEvents();
      } catch (err) {
        if (statusBanner) {
          statusBanner.style.display = 'block';
          statusBanner.style.background = 'rgba(239, 68, 68, 0.15)';
          statusBanner.style.color = 'var(--color-danger)';
          statusBanner.textContent = `Error loading dataset: ${err.message}`;
        }
      } finally {
        if (btnElement) {
          btnElement.disabled = false;
          btnElement.textContent = 'Load Dataset';
        }
      }
    },

    getOutcomeBadge(outcome) {
      const oc = (outcome || 'unknown').toLowerCase();
      if (oc === 'success') {
        return `<span class="badge" style="background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.4);">SUCCESS</span>`;
      }
      if (oc === 'failure') {
        return `<span class="badge" style="background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4);">FAILURE</span>`;
      }
      if (oc === 'blocked') {
        return `<span class="badge" style="background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.4);">BLOCKED</span>`;
      }
      return `<span class="badge badge-subtle">UNKNOWN</span>`;
    },

    getSeverityBadge(sev) {
      const s = (sev || 'info').toLowerCase();
      if (s === 'critical') return `<span class="badge badge-critical">CRITICAL</span>`;
      if (s === 'high') return `<span class="badge badge-high">HIGH</span>`;
      if (s === 'medium') return `<span class="badge badge-medium">MEDIUM</span>`;
      if (s === 'low') return `<span class="badge badge-low">LOW</span>`;
      return `<span class="badge badge-subtle">INFO</span>`;
    },

    escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }
  };

  window.Ingestion = Ingestion;

  // Auto-init on DOMContentLoaded
  document.addEventListener('DOMContentLoaded', () => {
    Ingestion.init();
  });

})(window);

