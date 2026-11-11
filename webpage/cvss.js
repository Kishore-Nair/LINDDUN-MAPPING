/**
 * MPSS — CVSS v3.1 Scoring Engine
 * 
 * Implements the exact CVSS v3.1 specification formulas from FIRST.Org.
 * Reference: https://www.first.org/cvss/v3.1/specification-document
 * 
 * All metric values, equations, and the Roundup function are implemented
 * precisely as specified in the CVSS v3.1 standard.
 */

const CVSS31 = (() => {
  'use strict';

  // ============================================================
  // Metric Value Mappings (from CVSS v3.1 Specification §7.4)
  // ============================================================

  const Weight = {
    // Attack Vector
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.20 },

    // Attack Complexity
    AC: { L: 0.77, H: 0.44 },

    // Privileges Required — Scope Unchanged
    PR: {
      U: { N: 0.85, L: 0.62, H: 0.27 },
      C: { N: 0.85, L: 0.68, H: 0.50 }
    },

    // User Interaction
    UI: { N: 0.85, R: 0.62 },

    // Impact values (Confidentiality, Integrity, Availability)
    CIA: { N: 0.00, L: 0.22, H: 0.56 },

    // Exploit Code Maturity
    E: { X: 1.00, U: 0.91, P: 0.94, F: 0.97, H: 1.00 },

    // Remediation Level
    RL: { X: 1.00, O: 0.95, T: 0.96, W: 0.97, U: 1.00 },

    // Report Confidence
    RC: { X: 1.00, U: 0.92, R: 0.96, C: 1.00 },

    // Security Requirements (CR, IR, AR)
    CIAR: { X: 1.00, L: 0.50, M: 1.00, H: 1.50 }
  };

  // ============================================================
  // Roundup Function (CVSS v3.1 Specification §7.5)
  // ============================================================
  // "Roundup returns the smallest number, specified to one
  //  decimal place, that is equal to or higher than its input."
  // e.g. Roundup(4.02) = 4.1, Roundup(4.00) = 4.0

  function roundUp(value) {
    return Math.ceil(value * 10) / 10;
  }

  // ============================================================
  // Base Score Calculation (CVSS v3.1 Specification §7.1)
  // ============================================================

  function calculateBaseScore(metrics) {
    const { AV, AC, PR, UI, S, C, I, A } = metrics;

    // Check all required base metrics are present
    if (!AV || !AC || !PR || !UI || !S || !C || !I || !A) {
      return { baseScore: 0, impactScore: 0, exploitabilityScore: 0, complete: false };
    }

    // Get privileges required weight based on scope
    const prWeight = Weight.PR[S][PR];

    // Exploitability Sub Score
    const exploitabilityScore = 8.22 * Weight.AV[AV] * Weight.AC[AC] * prWeight * Weight.UI[UI];

    // Impact Sub Score Base (ISCBase)
    const iscBase = 1 - ((1 - Weight.CIA[C]) * (1 - Weight.CIA[I]) * (1 - Weight.CIA[A]));

    // Impact Sub Score
    let impactScore;
    if (S === 'U') {
      impactScore = 6.42 * iscBase;
    } else {
      // Scope Changed
      impactScore = 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
    }

    // Base Score
    let baseScore;
    if (impactScore <= 0) {
      baseScore = 0;
    } else if (S === 'U') {
      baseScore = roundUp(Math.min(impactScore + exploitabilityScore, 10));
    } else {
      baseScore = roundUp(Math.min(1.08 * (impactScore + exploitabilityScore), 10));
    }

    return {
      baseScore,
      impactScore: Math.round(impactScore * 10) / 10,
      exploitabilityScore: Math.round(exploitabilityScore * 10) / 10,
      complete: true
    };
  }

  // ============================================================
  // Temporal Score Calculation (CVSS v3.1 Specification §7.2)
  // ============================================================

  function calculateTemporalScore(baseScore, metrics) {
    const E = metrics.E || 'X';
    const RL = metrics.RL || 'X';
    const RC = metrics.RC || 'X';

    return roundUp(baseScore * Weight.E[E] * Weight.RL[RL] * Weight.RC[RC]);
  }

  // ============================================================
  // Environmental Score Calculation (CVSS v3.1 Specification §7.3)
  // ============================================================

  function calculateEnvironmentalScore(metrics) {
    // Determine modified values (fall back to base values if "Not Defined")
    const mAV = (metrics.MAV && metrics.MAV !== 'X') ? metrics.MAV : metrics.AV;
    const mAC = (metrics.MAC && metrics.MAC !== 'X') ? metrics.MAC : metrics.AC;
    const mPR = (metrics.MPR && metrics.MPR !== 'X') ? metrics.MPR : metrics.PR;
    const mUI = (metrics.MUI && metrics.MUI !== 'X') ? metrics.MUI : metrics.UI;
    const mS  = (metrics.MS  && metrics.MS  !== 'X') ? metrics.MS  : metrics.S;
    const mC  = (metrics.MC  && metrics.MC  !== 'X') ? metrics.MC  : metrics.C;
    const mI  = (metrics.MI  && metrics.MI  !== 'X') ? metrics.MI  : metrics.I;
    const mA  = (metrics.MA  && metrics.MA  !== 'X') ? metrics.MA  : metrics.A;

    // Check that we have all required base values
    if (!mAV || !mAC || !mPR || !mUI || !mS || !mC || !mI || !mA) {
      return 0;
    }

    const cr = Weight.CIAR[metrics.CR || 'X'];
    const ir = Weight.CIAR[metrics.IR || 'X'];
    const ar = Weight.CIAR[metrics.AR || 'X'];

    const E  = Weight.E[metrics.E || 'X'];
    const RL = Weight.RL[metrics.RL || 'X'];
    const RC = Weight.RC[metrics.RC || 'X'];

    // Modified Privileges Required (depends on Modified Scope)
    const mPRWeight = Weight.PR[mS][mPR];

    // Modified Exploitability Sub Score
    const mExploitability = 8.22 * Weight.AV[mAV] * Weight.AC[mAC] * mPRWeight * Weight.UI[mUI];

    // Modified Impact Sub Score Base (MISS)
    // MISS = Minimum(1 - [(1 - M.IConf × CR) × (1 - M.IInteg × IR) × (1 - M.IAvail × AR)], 0.915)
    const missBase = Math.min(
      1 - (
        (1 - Weight.CIA[mC] * cr) *
        (1 - Weight.CIA[mI] * ir) *
        (1 - Weight.CIA[mA] * ar)
      ),
      0.915
    );

    // Modified Impact Sub Score
    let mImpact;
    if (mS === 'U') {
      mImpact = 6.42 * missBase;
    } else {
      // Modified Scope Changed
      mImpact = 7.52 * (missBase - 0.029) - 3.25 * Math.pow(missBase * 0.9731 - 0.02, 13);
    }

    // Environmental Score
    let envScore;
    if (mImpact <= 0) {
      envScore = 0;
    } else if (mS === 'U') {
      envScore = roundUp(roundUp(Math.min(mImpact + mExploitability, 10)) * E * RL * RC);
    } else {
      envScore = roundUp(roundUp(Math.min(1.08 * (mImpact + mExploitability), 10)) * E * RL * RC);
    }

    return Math.max(0, envScore);
  }

  // ============================================================
  // Vector String Generation
  // ============================================================

  function generateVectorString(metrics) {
    const parts = ['CVSS:3.1'];

    // Base metrics (required)
    const baseMetrics = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
    for (const m of baseMetrics) {
      parts.push(`${m}:${metrics[m] || '_'}`);
    }

    // Temporal metrics (only include if not "X" / Not Defined)
    const temporalMetrics = ['E', 'RL', 'RC'];
    for (const m of temporalMetrics) {
      if (metrics[m] && metrics[m] !== 'X') {
        parts.push(`${m}:${metrics[m]}`);
      }
    }

    // Environmental metrics (only include if not "X" / Not Defined)
    const envMetrics = ['CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA'];
    for (const m of envMetrics) {
      if (metrics[m] && metrics[m] !== 'X') {
        parts.push(`${m}:${metrics[m]}`);
      }
    }

    return parts.join('/');
  }

  // ============================================================
  // Vector String Parsing
  // ============================================================

  function parseVectorString(vectorString) {
    if (!vectorString || !vectorString.startsWith('CVSS:3.1/')) {
      return null;
    }

    const metrics = {};
    const parts = vectorString.substring(9).split('/');

    for (const part of parts) {
      const [key, value] = part.split(':');
      if (key && value) {
        metrics[key] = value;
      }
    }

    return metrics;
  }

  // ============================================================
  // Severity Rating (CVSS v3.1 Specification §5)
  // ============================================================

  function getSeverityRating(score) {
    if (score === 0.0) return 'None';
    if (score <= 3.9) return 'Low';
    if (score <= 6.9) return 'Medium';
    if (score <= 8.9) return 'High';
    return 'Critical';
  }

  function getSeverityClass(score) {
    if (score === 0.0) return 'none';
    if (score <= 3.9) return 'low';
    if (score <= 6.9) return 'medium';
    if (score <= 8.9) return 'high';
    return 'critical';
  }

  // ============================================================
  // Full Calculation
  // ============================================================

  function calculate(metrics) {
    const baseResult = calculateBaseScore(metrics);
    const baseScore = baseResult.baseScore;

    const temporalScore = baseResult.complete
      ? calculateTemporalScore(baseScore, metrics)
      : 0;

    const envScore = baseResult.complete
      ? calculateEnvironmentalScore(metrics)
      : 0;

    const vectorString = generateVectorString(metrics);

    return {
      baseScore,
      temporalScore,
      environmentalScore: envScore,
      impactScore: baseResult.impactScore,
      exploitabilityScore: baseResult.exploitabilityScore,
      baseSeverity: getSeverityRating(baseScore),
      temporalSeverity: getSeverityRating(temporalScore),
      environmentalSeverity: getSeverityRating(envScore),
      baseSeverityClass: getSeverityClass(baseScore),
      temporalSeverityClass: getSeverityClass(temporalScore),
      environmentalSeverityClass: getSeverityClass(envScore),
      vectorString,
      complete: baseResult.complete
    };
  }

  // Public API
  return {
    calculate,
    calculateBaseScore,
    calculateTemporalScore,
    calculateEnvironmentalScore,
    generateVectorString,
    parseVectorString,
    getSeverityRating,
    getSeverityClass,
    roundUp,
    Weight
  };
})();

// Export for use in app.js
if (typeof window !== 'undefined') {
  window.CVSS31 = CVSS31;
}
