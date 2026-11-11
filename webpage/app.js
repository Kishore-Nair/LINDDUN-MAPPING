/**
 * MPSS — Application Controller
 * 
 * Handles UI interactions, metric selection, score display updates,
 * tab navigation, vector string copy, and section toggling.
 */

(() => {
  'use strict';

  // ============================================================
  // State
  // ============================================================

  const state = {
    metrics: {
      // Base metrics (initially empty — user must select)
      AV: null, AC: null, PR: null, UI: null,
      S: null, C: null, I: null, A: null,
      // Temporal metrics (default: Not Defined)
      E: 'X', RL: 'X', RC: 'X',
      // Environmental metrics (default: Not Defined)
      CR: 'X', IR: 'X', AR: 'X',
      MAV: 'X', MAC: 'X', MPR: 'X', MUI: 'X', MS: 'X',
      MC: 'X', MI: 'X', MA: 'X'
    }
  };

  // ============================================================
  // DOM References
  // ============================================================

  const dom = {
    // Score displays
    baseScoreDisplay: document.getElementById('base-score-display'),
    temporalScoreDisplay: document.getElementById('temporal-score-display'),
    envScoreDisplay: document.getElementById('env-score-display'),
    baseSeverityDisplay: document.getElementById('base-severity-display'),
    temporalSeverityDisplay: document.getElementById('temporal-severity-display'),
    envSeverityDisplay: document.getElementById('env-severity-display'),

    // Score rings
    baseRing: document.getElementById('base-ring'),
    temporalRing: document.getElementById('temporal-ring'),
    envRing: document.getElementById('env-ring'),

    // Score cards
    baseCard: document.getElementById('score-card-base'),
    temporalCard: document.getElementById('score-card-temporal'),
    envCard: document.getElementById('score-card-env'),

    // Vector
    vectorString: document.getElementById('vector-string'),
    btnCopyVector: document.getElementById('btn-copy-vector'),

    // Toast
    toast: document.getElementById('toast'),
    toastMessage: document.getElementById('toast-message'),

    // Navigation
    navBtns: document.querySelectorAll('.nav-btn'),

    // Reset
    btnReset: document.getElementById('btn-reset'),

    // Metric group headers (for toggling)
    headerBase: document.getElementById('header-base'),
    headerTemporal: document.getElementById('header-temporal'),
    headerEnv: document.getElementById('header-env')
  };

  // ============================================================
  // Ring Animation Constants
  // ============================================================

  const RING_CIRCUMFERENCE = 2 * Math.PI * 52; // ~326.73

  // ============================================================
  // Initialize
  // ============================================================

  function init() {
    bindMetricButtons();
    bindNavigation();
    bindGroupToggles();
    bindCopyButton();
    bindReset();
    loadFromURL();
    updateDisplay();
  }

  // ============================================================
  // Metric Button Bindings
  // ============================================================

  function bindMetricButtons() {
    document.querySelectorAll('.metric-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const metric = btn.dataset.metric;
        const value = btn.dataset.value;

        // Update state
        state.metrics[metric] = value;

        // Update button selection UI
        const parent = btn.closest('.metric-row') || btn.closest('.metric-options');
        const siblings = parent.querySelectorAll(`.metric-btn[data-metric="${metric}"]`);
        siblings.forEach(s => s.classList.remove('selected'));
        btn.classList.add('selected');

        // Pulse animation
        btn.classList.remove('pulse');
        void btn.offsetWidth; // trigger reflow
        btn.classList.add('pulse');

        // Remove incomplete highlight
        const row = btn.closest('.metric-row');
        if (row) row.classList.remove('incomplete');

        // Recalculate and update
        updateDisplay();
        updateURL();
      });
    });
  }

  // ============================================================
  // Score Display Update
  // ============================================================

  function updateDisplay() {
    const result = CVSS31.calculate(state.metrics);

    // Animate score values
    animateScore(dom.baseScoreDisplay, result.baseScore);
    animateScore(dom.temporalScoreDisplay, result.temporalScore);
    animateScore(dom.envScoreDisplay, result.environmentalScore);

    // Update severity labels
    dom.baseSeverityDisplay.textContent = result.baseSeverity;
    dom.temporalSeverityDisplay.textContent = result.temporalSeverity;
    dom.envSeverityDisplay.textContent = result.environmentalSeverity;

    // Update severity colors
    updateSeverityColors(dom.baseScoreDisplay, dom.baseSeverityDisplay, dom.baseCard, result.baseSeverityClass);
    updateSeverityColors(dom.temporalScoreDisplay, dom.temporalSeverityDisplay, dom.temporalCard, result.temporalSeverityClass);
    updateSeverityColors(dom.envScoreDisplay, dom.envSeverityDisplay, dom.envCard, result.environmentalSeverityClass);

    // Update rings
    updateRing(dom.baseRing, result.baseScore, result.baseSeverityClass);
    updateRing(dom.temporalRing, result.temporalScore, result.temporalSeverityClass);
    updateRing(dom.envRing, result.environmentalScore, result.environmentalSeverityClass);

    // Update vector string
    dom.vectorString.textContent = result.vectorString;

    // Highlight incomplete base metrics
    highlightIncomplete();
  }

  function animateScore(element, targetValue) {
    const currentValue = parseFloat(element.textContent) || 0;
    const diff = targetValue - currentValue;

    if (Math.abs(diff) < 0.05) {
      element.textContent = targetValue.toFixed(1);
      return;
    }

    const duration = 400;
    const startTime = performance.now();

    function step(timestamp) {
      const elapsed = timestamp - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = currentValue + diff * eased;
      element.textContent = current.toFixed(1);

      if (progress < 1) {
        requestAnimationFrame(step);
      } else {
        element.textContent = targetValue.toFixed(1);
      }
    }

    requestAnimationFrame(step);
  }

  function updateSeverityColors(scoreEl, severityEl, cardEl, severityClass) {
    const classes = ['severity-color-none', 'severity-color-low', 'severity-color-medium', 'severity-color-high', 'severity-color-critical'];
    classes.forEach(cls => {
      scoreEl.classList.remove(cls);
      severityEl.classList.remove(cls);
    });
    scoreEl.classList.add(`severity-color-${severityClass}`);
    severityEl.classList.add(`severity-color-${severityClass}`);
  }

  function updateRing(ringEl, score, severityClass) {
    const fraction = score / 10;
    const offset = RING_CIRCUMFERENCE * (1 - fraction);
    ringEl.style.strokeDashoffset = offset;

    // Update ring color to match severity
    const colorMap = {
      none: 'var(--severity-none)',
      low: 'var(--severity-low)',
      medium: 'var(--severity-medium)',
      high: 'var(--severity-high)',
      critical: 'var(--severity-critical)'
    };
    ringEl.style.stroke = colorMap[severityClass] || colorMap.none;
  }

  function highlightIncomplete() {
    const baseMetrics = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
    baseMetrics.forEach(m => {
      const row = document.getElementById(`metric-${m}`);
      if (row) {
        if (!state.metrics[m]) {
          row.classList.add('incomplete');
        } else {
          row.classList.remove('incomplete');
        }
      }
    });
  }

  // ============================================================
  // Navigation
  // ============================================================

  function bindNavigation() {
    dom.navBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;

        // Update nav buttons
        dom.navBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        const targetTab = document.getElementById(`tab-${tab}`);
        if (targetTab) targetTab.classList.add('active');
      });
    });
  }

  // ============================================================
  // Group Toggles
  // ============================================================

  function bindGroupToggles() {
    const headers = [dom.headerBase, dom.headerTemporal, dom.headerEnv];
    headers.forEach(header => {
      if (!header) return;
      header.addEventListener('click', () => {
        const body = header.nextElementSibling;
        if (body && body.classList.contains('metric-group-body')) {
          body.classList.toggle('open');
        }
      });
    });
  }

  // ============================================================
  // Copy Vector String
  // ============================================================

  function bindCopyButton() {
    dom.btnCopyVector.addEventListener('click', async () => {
      const text = dom.vectorString.textContent;
      try {
        await navigator.clipboard.writeText(text);
        showToast('Vector string copied!');
      } catch {
        // Fallback
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        showToast('Vector string copied!');
      }
    });
  }

  // ============================================================
  // Toast Notification
  // ============================================================

  let toastTimeout = null;

  function showToast(message) {
    dom.toastMessage.textContent = message;
    dom.toast.classList.add('show');

    if (toastTimeout) clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => {
      dom.toast.classList.remove('show');
    }, 2500);
  }

  // ============================================================
  // Reset
  // ============================================================

  function bindReset() {
    dom.btnReset.addEventListener('click', () => {
      // Reset base metrics
      ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'].forEach(m => {
        state.metrics[m] = null;
      });

      // Reset temporal & environmental to defaults
      ['E', 'RL', 'RC', 'CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA'].forEach(m => {
        state.metrics[m] = 'X';
      });

      // Reset all button selections
      document.querySelectorAll('.metric-btn').forEach(btn => {
        btn.classList.remove('selected');
      });

      // Re-select "Not Defined" for temporal & environmental
      ['E', 'RL', 'RC', 'CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA'].forEach(m => {
        const btn = document.getElementById(`${m}-X`);
        if (btn) btn.classList.add('selected');
      });

      // Clear URL
      window.history.replaceState(null, '', window.location.pathname);

      updateDisplay();
      showToast('All metrics reset');
    });
  }

  // ============================================================
  // URL State (Hash-based)
  // ============================================================

  function updateURL() {
    const vector = CVSS31.generateVectorString(state.metrics);
    if (state.metrics.AV && state.metrics.AC) {
      window.history.replaceState(null, '', `#${vector}`);
    }
  }

  function loadFromURL() {
    const hash = window.location.hash;
    if (!hash || hash.length < 2) return;

    const vectorString = decodeURIComponent(hash.substring(1));
    const parsed = CVSS31.parseVectorString(vectorString);
    if (!parsed) return;

    // Apply parsed metrics to state
    Object.keys(parsed).forEach(key => {
      if (key in state.metrics) {
        state.metrics[key] = parsed[key];
      }
    });

    // Update button selections
    Object.entries(state.metrics).forEach(([metric, value]) => {
      if (value) {
        const btn = document.getElementById(`${metric}-${value}`);
        if (btn) {
          // Deselect siblings
          const parent = btn.closest('.metric-row') || btn.closest('.metric-options');
          if (parent) {
            parent.querySelectorAll(`.metric-btn[data-metric="${metric}"]`).forEach(s => s.classList.remove('selected'));
          }
          btn.classList.add('selected');
        }
      }
    });
  }

  // ============================================================
  // Listen for hash changes
  // ============================================================

  window.addEventListener('hashchange', () => {
    loadFromURL();
    updateDisplay();
  });

  // ============================================================
  // Boot
  // ============================================================

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
