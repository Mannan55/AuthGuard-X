/**
 * AuthGuard-X Dashboard & Analytics
 * KPI metrics, Chart.js timeline, severity breakdown, and attack map.
 * Sprint 1
 */

(function (window) {
  'use strict';

  let chartInstance = null;
  let fullTimelineScores = [];

  async function loadMetrics() {
    try {
      const data = await window.API.metrics.get();
      renderKPIs(data);
      renderSeverityBreakdown(data);
    } catch (err) {
      console.warn('[Dashboard] Failed to load metrics:', err);
    }
  }

  function renderKPIs(metrics) {
    const totalEl = document.getElementById('metric-total');
    const openEl = document.getElementById('metric-open');
    const criticalEl = document.getElementById('metric-critical');
    const healthEl = document.getElementById('metric-health');

    if (totalEl) window.UI.numberTick(totalEl, metrics.total_incidents || 0);
    if (openEl) window.UI.numberTick(openEl, metrics.open_incidents || 0);
    if (criticalEl) window.UI.numberTick(criticalEl, metrics.critical_count || 0);
    if (healthEl) {
      const score = typeof metrics.health_score === 'number' ? metrics.health_score : (metrics.health_score ?? 100);
      window.UI.numberTick(healthEl, score);
      healthEl.classList.remove('health-success', 'health-warning', 'health-critical', 'highlight-success', 'highlight-warning', 'highlight-danger');
      if (score >= 80) {
        healthEl.classList.add('health-success');
        healthEl.style.setProperty('color', 'var(--color-success)', 'important');
      } else if (score >= 50) {
        healthEl.classList.add('health-warning');
        healthEl.style.setProperty('color', 'var(--color-warning)', 'important');
      } else {
        healthEl.classList.add('health-critical');
        healthEl.style.setProperty('color', 'var(--color-critical)', 'important');
      }
    }

    // Mini counters
    const simCountEl = document.getElementById('metric-sim-count');
    const teleCountEl = document.getElementById('metric-tele-count');
    if (simCountEl) simCountEl.textContent = metrics.simulated_count || 0;
    if (teleCountEl) teleCountEl.textContent = metrics.telemetry_count || 0;
  }

  function renderSeverityBreakdown(metrics) {
    const total = metrics.total_incidents || 1;
    const critPercent = Math.round(((metrics.critical_count || 0) / total) * 100);
    const highPercent = Math.round(((metrics.high_count || 0) / total) * 100);
    const medPercent = Math.round(((metrics.medium_count || 0) / total) * 100);
    const lowPercent = Math.round(((metrics.low_count || 0) / total) * 100);

    const barCrit = document.getElementById('bar-crit');
    const barHigh = document.getElementById('bar-high');
    const barMed = document.getElementById('bar-med');
    const barLow = document.getElementById('bar-low');

    if (barCrit) barCrit.style.width = `${critPercent}%`;
    if (barHigh) barHigh.style.width = `${highPercent}%`;
    if (barMed) barMed.style.width = `${medPercent}%`;
    if (barLow) barLow.style.width = `${lowPercent}%`;

    const lblCrit = document.getElementById('lbl-crit-count');
    const lblHigh = document.getElementById('lbl-high-count');
    const lblMed = document.getElementById('lbl-med-count');
    const lblLow = document.getElementById('lbl-low-count');

    if (lblCrit) lblCrit.textContent = metrics.critical_count || 0;
    if (lblHigh) lblHigh.textContent = metrics.high_count || 0;
    if (lblMed) lblMed.textContent = metrics.medium_count || 0;
    if (lblLow) lblLow.textContent = metrics.low_count || 0;
  }

  // ── Chart.js Timeline ───────────────────────────────────────────────
  function initChart() {
    const ctx = document.getElementById('timeline-chart');
    if (!ctx || typeof Chart === 'undefined') return;

    if (chartInstance) {
      chartInstance.destroy();
    }

    chartInstance = new Chart(ctx, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          {
            label: 'Incident Risk Severity',
            data: [],
            borderColor: '#38bdf8',
            backgroundColor: 'rgba(56, 189, 248, 0.08)',
            borderWidth: 2,
            tension: 0.35,
            fill: true,
            pointRadius: 3,
            pointHoverRadius: 6,
            pointBackgroundColor: '#38bdf8'
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: {
          duration: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 400
        },
        scales: {
          y: {
            beginAtZero: true,
            max: 100,
            grid: { color: 'rgba(255, 255, 255, 0.04)' },
            ticks: { color: '#64748b', font: { family: 'Inter', size: 11 } }
          },
          x: {
            grid: { display: false },
            ticks: { color: '#64748b', font: { family: 'Inter', size: 11 } }
          }
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#0f1629',
            titleColor: '#e2e8f0',
            bodyColor: '#94a3b8',
            borderColor: '#1e2a45',
            borderWidth: 1,
            padding: 10,
            displayColors: false
          }
        }
      }
    });
  }

  function updateTimeline(incidents) {
    if (!chartInstance) initChart();
    if (!chartInstance) return;

    const dataPoints = (incidents || []).slice(0, 30).map((i) => i.risk).reverse();
    fullTimelineScores = [...dataPoints];

    const labels = dataPoints.map((_, idx) => `T-${dataPoints.length - idx}`);
    chartInstance.data.labels = labels;
    chartInstance.data.datasets[0].data = dataPoints;
    chartInstance.update();
  }

  function replayTimeline() {
    if (!chartInstance || fullTimelineScores.length === 0) return;
    let idx = 0;
    const buffer = [];
    const timer = setInterval(() => {
      buffer.push(fullTimelineScores[idx]);
      chartInstance.data.labels = buffer.map((_, i) => `T-${fullTimelineScores.length - i}`);
      chartInstance.data.datasets[0].data = [...buffer];
      chartInstance.update();
      idx++;
      if (idx >= fullTimelineScores.length) clearInterval(timer);
    }, 200);
  }

  // ── Attack Map Simulation Dots ──────────────────────────────────────
  function addAttackMarker(xPercent, yPercent) {
    const map = document.getElementById('attack-map-canvas');
    if (!map) return;

    const dot = document.createElement('div');
    dot.className = 'attack-dot';
    dot.style.left = `${xPercent}%`;
    dot.style.top = `${yPercent}%`;
    map.appendChild(dot);

    setTimeout(() => {
      if (dot.parentElement) dot.remove();
    }, 2200);
  }

  // ── Attack Simulation Trigger ───────────────────────────────────────
  const SIM_CITIES = [
    'Frankfurt, Germany',
    'Singapore',
    'Tokyo, Japan',
    'London, UK',
    'Sao Paulo, Brazil',
    'Sydney, Australia',
    'San Jose, USA'
  ];

  function parseRiskScore(val, defaultVal = 50) {
    if (val === null || val === undefined || val === '') return defaultVal;
    const parsed = Number(val);
    if (!Number.isFinite(parsed) || isNaN(parsed)) return defaultVal;
    const clamped = Math.round(parsed);
    if (clamped < 0) return 0;
    if (clamped > 100) return 100;
    return clamped;
  }

  async function triggerSimulation(attackName, risk, behavior, customCity = null) {
    const selectedCity = (typeof customCity === 'string' && customCity.trim().length > 0)
      ? customCity.trim()
      : SIM_CITIES[Math.floor(Math.random() * SIM_CITIES.length)];
    const validatedRisk = parseRiskScore(risk, 50);

    try {
      const res = await window.API.incidents.simulate({
        attack: attackName,
        risk: validatedRisk,
        behavior: behavior,
        username: 'sim_agent',
        is_simulated: true,
        simulated_location: selectedCity
      });

      window.UI.showToast(`Simulated: ${attackName} (Risk: ${validatedRisk})`, 'info');

      // Random map dot coordinates
      const randX = Math.random() * 80 + 10;
      const randY = Math.random() * 50 + 20;
      addAttackMarker(randX, randY);

      // Refresh metrics and incidents
      await loadMetrics();
      if (window.Incidents && typeof window.Incidents.refresh === 'function') {
        window.Incidents.refresh();
      }
    } catch (err) {
      window.UI.showToast(`Simulation failed: ${err.message}`, 'error');
    }
  }

  function init() {
    initChart();
    loadMetrics();

    const replayBtn = document.getElementById('replay-timeline-btn');
    if (replayBtn) {
      replayBtn.addEventListener('click', replayTimeline);
    }

    const simButtons = document.querySelectorAll('[data-simulate]');
    simButtons.forEach((btn) => {
      btn.addEventListener('click', () => {
        const attack = (btn.dataset.attack || 'Brute Force Spray').trim();
        const risk = parseRiskScore(btn.dataset.risk, 75);
        const behavior = btn.dataset.behavior || 'automated';
        triggerSimulation(attack, risk, behavior);
      });
    });

    const customSubmitBtn = document.getElementById('custom-sim-submit-btn');
    if (customSubmitBtn) {
      customSubmitBtn.addEventListener('click', (e) => {
        e.preventDefault();
        const attackEl = document.getElementById('custom-sim-attack');
        const riskEl = document.getElementById('custom-sim-risk');
        const behaviorEl = document.getElementById('custom-sim-behavior');
        const cityEl = document.getElementById('custom-sim-city');

        const attack = (attackEl && attackEl.value.trim()) || 'Custom Adversary Simulation';
        const rawRisk = riskEl ? riskEl.value : '';
        const risk = parseRiskScore(rawRisk, 75);
        const behavior = behaviorEl ? behaviorEl.value : 'custom_vector';
        const city = cityEl && cityEl.value ? cityEl.value.trim() : null;
        triggerSimulation(attack, risk, behavior, city);
      });
    }
  }

  window.Dashboard = {
    init,
    loadMetrics,
    renderKPIs,
    updateTimeline,
    replayTimeline,
    triggerSimulation
  };
})(window);

