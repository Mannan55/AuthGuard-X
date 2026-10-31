/**
 * AuthGuard-X Global Threat Map & Live Simulation Engine
 * Handles real-time geospatial attack vector projections, trajectory rendering,
 * and synthetic adversary telemetry streams.
 */

(function (window) {
  'use strict';

  // ── Coordinates and Geolocation Nodes ───────────────────────────────
  const ORIGIN_NODES = [
    { city: 'Frankfurt, Germany', country: 'DE', x: 52.5, y: 28.5, ipPrefix: '194.12.44' },
    { city: 'London, UK', country: 'GB', x: 48.0, y: 26.5, ipPrefix: '185.86.151' },
    { city: 'Tokyo, Japan', country: 'JP', x: 86.5, y: 36.5, ipPrefix: '133.242.18' },
    { city: 'Singapore', country: 'SG', x: 77.5, y: 55.0, ipPrefix: '103.253.25' },
    { city: 'Sydney, Australia', country: 'AU', x: 89.5, y: 78.5, ipPrefix: '139.130.4' },
    { city: 'Sao Paulo, Brazil', country: 'BR', x: 34.0, y: 72.0, ipPrefix: '177.18.204' },
    { city: 'San Jose, USA', country: 'US', x: 17.5, y: 35.5, ipPrefix: '198.51.100' },
    { city: 'Amsterdam, Netherlands', country: 'NL', x: 50.5, y: 26.0, ipPrefix: '188.166.42' },
    { city: 'Seoul, South Korea', country: 'KR', x: 83.5, y: 35.0, ipPrefix: '211.234.118' },
    { city: 'Mumbai, India', country: 'IN', x: 68.5, y: 45.0, ipPrefix: '103.7.128' },
    { city: 'Stockholm, Sweden', country: 'SE', x: 53.5, y: 20.0, ipPrefix: '193.180.251' },
    { city: 'Toronto, Canada', country: 'CA', x: 25.0, y: 30.5, ipPrefix: '142.1.96' },
    { city: 'Johannesburg, South Africa', country: 'ZA', x: 56.5, y: 75.0, ipPrefix: '196.25.1' },
    { city: 'Dubai, UAE', country: 'AE', x: 62.5, y: 41.0, ipPrefix: '94.200.12' },
    { city: 'Hong Kong', country: 'HK', x: 80.0, y: 44.5, ipPrefix: '203.80.240' },
    { city: 'Paris, France', country: 'FR', x: 49.0, y: 29.0, ipPrefix: '195.154.122' },
    { city: 'Warsaw, Poland', country: 'PL', x: 54.5, y: 25.5, ipPrefix: '193.0.96' }
  ];

  const TARGET_GATEWAY = {
    name: 'US-East Auth Gateway',
    x: 26.5,
    y: 33.5,
    svgX: 265,
    svgY: 167
  };

  const SCENARIOS = [
    {
      category: 'credential',
      attack: 'Brute Force Credential Spray',
      risk: 85,
      severity: 'critical',
      behavior: 'high_velocity_login',
      target: 'admin@corp.internal',
      technique: 'T1110.001'
    },
    {
      category: 'credential',
      attack: 'Credential Stuffing Botnet',
      risk: 70,
      severity: 'high',
      behavior: 'automated_stuffing',
      target: 'finance_triage@corp.internal',
      technique: 'T1110.004'
    },
    {
      category: 'credential',
      attack: 'Distributed Password Spraying',
      risk: 80,
      severity: 'high',
      behavior: 'multi_target_spray',
      target: 'sales_execs@corp.internal',
      technique: 'T1110.003'
    },
    {
      category: 'credential',
      attack: 'Impossible Geolocation Velocity',
      risk: 45,
      severity: 'medium',
      behavior: 'geographic_velocity',
      target: 'cloud_architect@corp.internal',
      technique: 'T1078'
    },
    {
      category: 'critical',
      attack: 'Active Directory Kerberoasting',
      risk: 92,
      severity: 'critical',
      behavior: 'spn_ticket_extract',
      target: 'krbtgt@corp.internal',
      technique: 'T1558.003'
    },
    {
      category: 'recon',
      attack: 'Network Service Discovery Recon',
      risk: 50,
      severity: 'medium',
      behavior: 'port_scan_syn',
      target: 'edge_ingress_proxy',
      technique: 'T1046'
    },
    {
      category: 'critical',
      attack: 'Lateral SMB Named Pipe Impersonation',
      risk: 95,
      severity: 'critical',
      behavior: 'named_pipe_impersonate',
      target: 'dc_backup_srv',
      technique: 'T1021.002'
    },
    {
      category: 'recon',
      attack: 'SQL Injection Exploit Probe',
      risk: 65,
      severity: 'high',
      behavior: 'sql_injection_probe',
      target: 'api_login_endpoint',
      technique: 'T1190'
    }
  ];

  // ── State ───────────────────────────────────────────────────────────
  let isRunning = false;
  let timerId = null;
  let intervalMs = 2500;
  let interceptCounter = 0;
  const originFrequencies = {};
  const recentIntercepts = [];

  // ── Color and Severity Helpers ──────────────────────────────────────
  function getSeverityColor(risk) {
    if (risk >= 80) return '#ef4444'; // critical red
    if (risk >= 60) return '#f97316'; // high orange
    if (risk >= 40) return '#eab308'; // medium yellow
    return '#3b82f6';                // low blue
  }

  function getSeverityBadge(risk) {
    if (risk >= 80) return '<span class="badge badge-critical">Critical</span>';
    if (risk >= 60) return '<span class="badge badge-high">High</span>';
    if (risk >= 40) return '<span class="badge badge-medium">Medium</span>';
    return '<span class="badge badge-low">Low</span>';
  }

  // ── Threat Vector Generation ────────────────────────────────────────
  function pickScenario() {
    const filterEl = document.getElementById('threat-scenario-select');
    const filter = filterEl ? filterEl.value : 'all';

    let candidates = SCENARIOS;
    if (filter === 'credential') {
      candidates = SCENARIOS.filter(s => s.category === 'credential');
    } else if (filter === 'recon') {
      candidates = SCENARIOS.filter(s => s.category === 'recon');
    } else if (filter === 'critical') {
      candidates = SCENARIOS.filter(s => s.severity === 'critical');
    }
    return candidates[Math.floor(Math.random() * candidates.length)] || SCENARIOS[0];
  }

  function pickOrigin() {
    return ORIGIN_NODES[Math.floor(Math.random() * ORIGIN_NODES.length)];
  }

  function generateSimulatedIP(prefix) {
    const host1 = Math.floor(Math.random() * 250) + 2;
    return `${prefix}.${host1}`;
  }

  // ── Map Canvas Trajectory & Marker Rendering ────────────────────────
  function renderTrajectory(originNode, scenario, color) {
    const svgLayer = document.getElementById('threat-map-svg-layer');
    const markersContainer = document.getElementById('threat-markers-container');
    if (!svgLayer || !markersContainer) return;

    // ViewBox is 1000 x 500
    const startX = originNode.x * 10;
    const startY = originNode.y * 5;
    const targetX = TARGET_GATEWAY.svgX;
    const targetY = TARGET_GATEWAY.svgY;

    // Calculate arc control point (curve upward or downward based on distance)
    const midX = (startX + targetX) / 2;
    const midY = (startY + targetY) / 2;
    const dist = Math.hypot(targetX - startX, targetY - startY);
    const curveOffset = Math.min(dist * 0.35, 120);
    const ctrlY = Math.max(20, midY - curveOffset);

    // Draw SVG arc path
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    const d = `M ${startX} ${startY} Q ${midX} ${ctrlY} ${targetX} ${targetY}`;
    path.setAttribute('d', d);
    path.setAttribute('class', 'threat-arc-path');
    path.setAttribute('stroke', color);
    path.setAttribute('stroke-width', '2');
    svgLayer.appendChild(path);

    // Origin Pulse Marker
    const dot = document.createElement('div');
    dot.className = 'threat-origin-dot';
    dot.style.left = `${originNode.x}%`;
    dot.style.top = `${originNode.y}%`;
    dot.style.color = color;
    dot.style.backgroundColor = color;
    dot.style.boxShadow = `0 0 10px ${color}`;

    // Origin Label
    const label = document.createElement('div');
    label.className = 'threat-origin-label';
    label.textContent = `${originNode.city} (${scenario.attack.split(' ')[0]})`;
    dot.appendChild(label);

    markersContainer.appendChild(dot);

    // Cleanup elements after animation completes
    setTimeout(() => {
      if (path.parentElement) path.remove();
    }, 1800);

    setTimeout(() => {
      if (dot.parentElement) dot.remove();
    }, 2600);
  }

  // ── Feed and HUD Updates ────────────────────────────────────────────
  function updateHUD(originNode) {
    interceptCounter++;
    originFrequencies[originNode.city] = (originFrequencies[originNode.city] || 0) + 1;

    const countEl = document.getElementById('hud-intercepts-count');
    if (countEl) countEl.textContent = interceptCounter.toLocaleString();

    const originsCountEl = document.getElementById('hud-origins-count');
    if (originsCountEl) originsCountEl.textContent = Object.keys(originFrequencies).length.toString();

    const lastOriginEl = document.getElementById('hud-last-origin');
    if (lastOriginEl) lastOriginEl.textContent = `${originNode.city} (${new Date().toLocaleTimeString()})`;

    renderOriginsDistribution();
  }

  function appendFeedRow(originNode, scenario, ip, timeStr) {
    const tbody = document.getElementById('threat-feed-tbody');
    if (!tbody) return;

    // Remove empty-state placeholder row
    const emptyRow = tbody.querySelector('.text-muted');
    if (emptyRow && emptyRow.closest('tr')) {
      emptyRow.closest('tr').remove();
    }

    const tr = document.createElement('tr');
    tr.className = 'threat-row-new';
    tr.innerHTML = `
      <td style="font-family: var(--font-mono); color: var(--color-text-muted);">${timeStr}</td>
      <td><strong>${originNode.city}</strong></td>
      <td style="font-family: var(--font-mono);">${ip}</td>
      <td>
        <div>${scenario.attack}</div>
        <div class="text-muted" style="font-size: 10px;">${scenario.technique} &bull; ${scenario.behavior}</div>
      </td>
      <td style="font-family: var(--font-mono); font-size: 11px;">${scenario.target}</td>
      <td style="text-align: right;">${getSeverityBadge(scenario.risk)}</td>
    `;

    tbody.insertBefore(tr, tbody.firstChild);

    // Keep feed trimmed to 20 rows
    while (tbody.children.length > 20) {
      tbody.removeChild(tbody.lastChild);
    }
  }

  function renderOriginsDistribution() {
    const container = document.getElementById('threat-origins-distribution');
    if (!container) return;

    const sorted = Object.entries(originFrequencies)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    if (sorted.length === 0) return;

    const maxCount = sorted[0][1] || 1;
    container.innerHTML = sorted.map(([city, count]) => {
      const pct = Math.round((count / maxCount) * 100);
      return `
        <div>
          <div style="display: flex; justify-content: space-between; font-size: var(--text-xs); margin-bottom: 2px;">
            <span>${city}</span>
            <strong style="font-family: var(--font-mono);">${count} hits</strong>
          </div>
          <div style="height: 6px; background: rgba(255,255,255,0.08); border-radius: 3px; overflow: hidden;">
            <div style="height: 100%; width: ${pct}%; background: var(--color-danger); border-radius: 3px; transition: width 0.3s ease;"></div>
          </div>
        </div>
      `;
    }).join('');
  }

  // ── Core Simulation Dispatcher ──────────────────────────────────────
  async function dispatchThreatVector(customOrigin = null, customScenario = null, syncToBackend = null) {
    const origin = customOrigin || pickOrigin();
    const scenario = customScenario || pickScenario();
    const ip = generateSimulatedIP(origin.ipPrefix);
    const timeStr = new Date().toTimeString().split(' ')[0];
    const color = getSeverityColor(scenario.risk);

    // Render visual elements
    renderTrajectory(origin, scenario, color);
    updateHUD(origin);
    appendFeedRow(origin, scenario, ip, timeStr);

    // Optionally sync with backend incidents table
    const persistChk = document.getElementById('threat-persist-chk');
    const shouldPersist = (syncToBackend !== null) ? syncToBackend : (persistChk ? persistChk.checked : true);

    if (shouldPersist && window.API && window.API.incidents && typeof window.API.incidents.simulate === 'function') {
      try {
        await window.API.incidents.simulate({
          attack: scenario.attack,
          risk: scenario.risk,
          behavior: scenario.behavior,
          username: scenario.target.split('@')[0],
          is_simulated: true,
          simulated_location: origin.city
        });

        // Soft refresh metrics on dashboard if available
        if (window.Dashboard && typeof window.Dashboard.loadMetrics === 'function') {
          window.Dashboard.loadMetrics();
        }
      } catch (err) {
        // Visual simulation continues seamlessly even if backend call is rejected (e.g. rate limit)
      }
    }
  }

  // ── Public Simulation Controls ──────────────────────────────────────
  function startSimulation() {
    if (isRunning) return;
    isRunning = true;
    updateStatusUI();

    // Trigger first vector immediately
    dispatchThreatVector();

    // Start interval
    timerId = setInterval(() => {
      dispatchThreatVector();
    }, intervalMs);
  }

  function pauseSimulation() {
    isRunning = false;
    if (timerId) {
      clearInterval(timerId);
      timerId = null;
    }
    updateStatusUI();
  }

  function toggleSimulation() {
    if (isRunning) {
      pauseSimulation();
    } else {
      startSimulation();
    }
  }

  function updateStatusUI() {
    const pill = document.getElementById('threat-map-status-pill');
    const textEl = document.getElementById('threat-status-text');
    const toggleBtn = document.getElementById('threat-toggle-btn');
    const toggleLabel = document.getElementById('threat-toggle-label');

    if (isRunning) {
      if (pill) pill.classList.remove('threat-status-paused');
      if (textEl) textEl.textContent = 'LIVE SIMULATION ACTIVE';
      if (toggleLabel) toggleLabel.textContent = 'Pause Stream';
      if (toggleBtn) {
        toggleBtn.classList.remove('btn-primary');
        toggleBtn.classList.add('btn-secondary');
      }
    } else {
      if (pill) pill.classList.add('threat-status-paused');
      if (textEl) textEl.textContent = 'STREAM PAUSED';
      if (toggleLabel) toggleLabel.textContent = 'Resume Stream';
      if (toggleBtn) {
        toggleBtn.classList.remove('btn-secondary');
        toggleBtn.classList.add('btn-primary');
      }
    }
  }

  function setSpeed(ms) {
    intervalMs = Number(ms) || 2500;
    if (isRunning) {
      clearInterval(timerId);
      timerId = setInterval(() => {
        dispatchThreatVector();
      }, intervalMs);
    }
  }

  function clearFeed() {
    const tbody = document.getElementById('threat-feed-tbody');
    if (tbody) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" class="text-center text-muted" style="padding: var(--space-4);">
            Feed cleared. Waiting for simulated telemetry vectors...
          </td>
        </tr>
      `;
    }
  }

  // ── Navigation Lifecycle ────────────────────────────────────────────
  function activate() {
    // When user visits the Threat Map view, ensure live simulation is running
    if (!isRunning) {
      startSimulation();
    }
  }

  // ── Initialization ──────────────────────────────────────────────────
  function init() {
    const toggleBtn = document.getElementById('threat-toggle-btn');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', toggleSimulation);
    }

    const injectBtn = document.getElementById('threat-inject-btn');
    if (injectBtn) {
      injectBtn.addEventListener('click', () => {
        dispatchThreatVector();
      });
    }

    const speedSelect = document.getElementById('threat-speed-select');
    if (speedSelect) {
      speedSelect.addEventListener('change', (e) => {
        setSpeed(e.target.value);
      });
    }

    const clearBtn = document.getElementById('threat-clear-feed-btn');
    if (clearBtn) {
      clearBtn.addEventListener('click', clearFeed);
    }
  }

  // ── Global Interface ────────────────────────────────────────────────
  window.ThreatMap = {
    init,
    activate,
    start: startSimulation,
    pause: pauseSimulation,
    toggle: toggleSimulation,
    injectThreat: dispatchThreatVector,
    addMarker: (xPercent, yPercent) => {
      // Compatibility bridge for dashboard simulation buttons
      const matchedNode = ORIGIN_NODES.reduce((closest, node) => {
        const d = Math.hypot(node.x - xPercent, node.y - yPercent);
        return d < closest.d ? { node, d } : closest;
      }, { node: ORIGIN_NODES[0], d: Infinity }).node;

      dispatchThreatVector(matchedNode, null, false);
    }
  };

})(window);

