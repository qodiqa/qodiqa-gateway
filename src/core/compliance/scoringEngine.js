'use strict';

/**
 * QODIQA Compliance Scoring Engine
 *
 * Transforms per-control validation results into:
 *   - Control-level status (PASS / PARTIAL / FAIL / NOT_APPLICABLE)
 *   - Framework-level weighted score (0–100)
 *   - Overall compliance verdict (COMPLIANT / PARTIALLY_COMPLIANT / NON_COMPLIANT)
 *
 * Scoring algorithm:
 *   Each control has a weight (default 1.0; critical controls weight 2.0).
 *   Control score (0–100) × weight = weighted contribution.
 *   Framework score = sum(weighted scores) / sum(weights).
 *
 *   PASS     = score >= PASS_THRESHOLD    (default 80)
 *   PARTIAL  = score >= PARTIAL_THRESHOLD (default 50)
 *   FAIL     = score <  PARTIAL_THRESHOLD
 *   NOT_APPLICABLE = control's validation result carries evidenceCount 0 for every
 *                    rule (see evidenceValidator.validateControl) — excluded from
 *                    both the weighted score and the PASS/PARTIAL/FAIL tallies, since
 *                    zero evidence is proof of neither compliance nor non-compliance.
 *
 *   COMPLIANT         = framework score >= COMPLIANT_THRESHOLD (default 80)
 *                       AND zero critical control FAILs
 *   PARTIALLY_COMPLIANT = framework score >= PARTIAL_THRESHOLD (default 60)
 *                         OR at most one critical FAIL
 *   NON_COMPLIANT     = otherwise
 */

const PASS_THRESHOLD      = 80;
const PARTIAL_THRESHOLD   = 50;
const COMPLIANT_THRESHOLD = 80;
const PARTIAL_VERDICT_THRESHOLD = 60;

// ── Control status determination ──────────────────────────────────────────────

function controlStatus(score) {
  if (score >= PASS_THRESHOLD)    return 'PASS';
  if (score >= PARTIAL_THRESHOLD) return 'PARTIAL';
  return 'FAIL';
}

// ── Framework scoring ─────────────────────────────────────────────────────────

/**
 * Score a single framework from its per-control validation results.
 *
 * @param {object[]} controls        — from controlRegistry.getControlsForFramework()
 * @param {Map<string, object>} validationResults — from evidenceValidator.validateAll()
 * @returns {FrameworkScore}
 */
function scoreFramework(controls, validationResults) {
  if (!controls || controls.length === 0) {
    return {
      frameworkScore:    0,
      verdict:           'NON_COMPLIANT',
      controlsTotal:     0,
      controlsPass:      0,
      controlsPartial:   0,
      controlsFail:      0,
      controlsNotApplicable: 0,
      criticalFailCount: 0,
      controlScores:     [],
      weightedSum:       0,
      totalWeight:       0,
    };
  }

  const controlScores  = [];
  let   weightedSum    = 0;
  let   totalWeight    = 0;
  let   pass           = 0;
  let   partial        = 0;
  let   fail           = 0;
  let   notApplicable  = 0;
  let   criticalFails  = 0;

  for (const ctrl of controls) {
    // none of the 37 registry controls defines `enabled`, so `!ctrl.enabled` skipped ALL of them and every report
    // scored 0/100 NON_COMPLIANT with zero controls assessed. A control is skipped only when explicitly disabled.
    if (ctrl.enabled === false) continue;

    const vr     = validationResults.get(ctrl.id);
    const weight = ctrl.weight ?? 1.0;

    // A control with zero supporting evidence is unfalsifiable — it must never be
    // counted as PASS or FAIL, and must not participate in the weighted average.
    if (vr?.notApplicable) {
      notApplicable++;
      controlScores.push({
        controlId:   ctrl.id,
        controlRef:  ctrl.controlRef,
        title:       ctrl.title,
        category:    ctrl.category,
        status:      'NOT_APPLICABLE',
        score:       vr.score ?? 0,
        weight,
        isCritical:  ctrl.isCritical,
        findings:    vr?.findings ?? [],
        evidenceCount: vr?.evidenceCount ?? 0,
      });
      continue;
    }

    const score  = vr ? (vr.score ?? 0) : 0;
    const status = controlStatus(score);

    weightedSum += score * weight;
    totalWeight += weight;

    if (status === 'PASS')    pass++;
    else if (status === 'PARTIAL') partial++;
    else {
      fail++;
      if (ctrl.isCritical) criticalFails++;
    }

    controlScores.push({
      controlId:   ctrl.id,
      controlRef:  ctrl.controlRef,
      title:       ctrl.title,
      category:    ctrl.category,
      status,
      score,
      weight,
      isCritical:  ctrl.isCritical,
      findings:    vr?.findings ?? [],
      evidenceCount: vr?.evidenceCount ?? 0,
    });
  }

  const frameworkScore = totalWeight > 0
    ? Math.round(weightedSum / totalWeight)
    : 0;

  const verdict = _determineVerdict(frameworkScore, criticalFails);

  return {
    frameworkScore,
    verdict,
    controlsTotal:     controls.length,
    controlsPass:      pass,
    controlsPartial:   partial,
    controlsFail:      fail,
    controlsNotApplicable: notApplicable,
    criticalFailCount: criticalFails,
    controlScores,
    weightedSum,
    totalWeight,
  };
}

function _determineVerdict(score, criticalFails) {
  if (criticalFails > 0) {
    return score >= PARTIAL_VERDICT_THRESHOLD
      ? 'PARTIALLY_COMPLIANT'
      : 'NON_COMPLIANT';
  }
  if (score >= COMPLIANT_THRESHOLD)       return 'COMPLIANT';
  if (score >= PARTIAL_VERDICT_THRESHOLD) return 'PARTIALLY_COMPLIANT';
  return 'NON_COMPLIANT';
}

// ── Overall score (multi-framework) ──────────────────────────────────────────

/**
 * Compute an overall score across multiple framework results.
 * Used when generating a consolidated report.
 * @param {FrameworkScore[]} frameworkScores
 * @returns {{ overallScore: number, overallVerdict: string }}
 */
function scoreOverall(frameworkScores) {
  if (!frameworkScores || frameworkScores.length === 0) {
    return { overallScore: 0, overallVerdict: 'NON_COMPLIANT' };
  }
  const avg = Math.round(
    frameworkScores.reduce((sum, fs) => sum + fs.frameworkScore, 0) / frameworkScores.length,
  );
  const anyNonCompliant = frameworkScores.some(fs => fs.verdict === 'NON_COMPLIANT');
  const verdict = anyNonCompliant
    ? (avg >= PARTIAL_VERDICT_THRESHOLD ? 'PARTIALLY_COMPLIANT' : 'NON_COMPLIANT')
    : (avg >= COMPLIANT_THRESHOLD ? 'COMPLIANT' : 'PARTIALLY_COMPLIANT');
  return { overallScore: avg, overallVerdict: verdict };
}

// ── Executive summary generation ──────────────────────────────────────────────

function buildExecutiveSummary(frameworkId, frameworkName, fs, period) {
  const { frameworkScore, verdict, controlsTotal, controlsPass, controlsFail,
    criticalFailCount } = fs;

  const verdictText = {
    COMPLIANT:            'COMPLIANT',
    PARTIALLY_COMPLIANT:  'PARTIALLY COMPLIANT',
    NON_COMPLIANT:        'NON-COMPLIANT',
  }[verdict] ?? verdict;

  const lines = [
    `${frameworkName} Compliance Assessment`,
    `Assessment Period: ${period.start} to ${period.end}`,
    ``,
    `Overall Status: ${verdictText} (Score: ${frameworkScore}/100)`,
    ``,
    `Controls assessed: ${controlsTotal}`,
    `  Passing: ${controlsPass}`,
    `  Partial: ${fs.controlsPartial}`,
    `  Failing: ${controlsFail}`,
  ];

  if (criticalFailCount > 0) {
    lines.push(`  CRITICAL failures: ${criticalFailCount} — immediate remediation required`);
  }

  if (verdict === 'COMPLIANT') {
    lines.push(``, `The QODIQA platform demonstrates ${frameworkName} compliance based on available evidence.`);
  } else if (verdict === 'PARTIALLY_COMPLIANT') {
    lines.push(``, `Partial compliance achieved. See findings for areas requiring remediation.`);
  } else {
    lines.push(``, `Compliance cannot be confirmed. Multiple critical controls require remediation before certification.`);
  }

  return lines.join('\n');
}

// ── Aggregated findings ───────────────────────────────────────────────────────

function aggregateFindings(controlScores) {
  const findings = [];
  for (const cs of controlScores) {
    for (const f of (cs.findings ?? [])) {
      findings.push({
        controlId:   cs.controlId,
        controlRef:  cs.controlRef,
        severity:    f.severity,
        rule:        f.rule,
        description: f.description,
        detail:      f.detail,
        remediation: f.remediation,
      });
    }
  }
  // Critical findings first, then by controlId
  findings.sort((a, b) => {
    if (a.severity === 'CRITICAL' && b.severity !== 'CRITICAL') return -1;
    if (b.severity === 'CRITICAL' && a.severity !== 'CRITICAL') return  1;
    return a.controlId.localeCompare(b.controlId);
  });
  return findings;
}

module.exports = {
  controlStatus,
  scoreFramework,
  scoreOverall,
  buildExecutiveSummary,
  aggregateFindings,
  PASS_THRESHOLD,
  PARTIAL_THRESHOLD,
  COMPLIANT_THRESHOLD,
};
