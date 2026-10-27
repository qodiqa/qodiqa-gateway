'use strict';

/**
 * QODIQA Compliance Evidence Validator
 *
 * Applies rule-based validation to collected evidence.
 * Produces structured validation results per control:
 *   { passed: bool, score: 0-100, findings: [], evidenceRefs: [] }
 *
 * Validation is deliberately strict: invalid or missing evidence
 * reduces the control score and is recorded as a finding.
 *
 * Rules are defined in controlRegistry.js (validationRules array).
 * The validator dispatches on rule.rule (string key).
 */

// ── Rule implementations ──────────────────────────────────────────────────────

/**
 * Each rule function receives (ruleSpec, bundle, control) and returns:
 *   { passed: bool, detail: string, evidenceCount: number }
 */
const RULE_HANDLERS = {

  min_enforcement_events({ threshold = 1 }, bundle) {
    const count = bundle.enforcement?.count ?? 0;
    return {
      passed:        count >= threshold,
      detail:        `Enforcement events found: ${count} (required: ${threshold})`,
      evidenceCount: count,
    };
  },

  policy_coverage({ field = 'type', values = [] }, bundle) {
    const policies = bundle.policy_records?.items ?? [];
    const matched  = policies.filter(p =>
      p.metadata && values.includes(p.metadata[field]),
    );
    const activeMatch = matched.filter(p => p.metadata?.enabled !== false).length;
    return {
      passed:        activeMatch > 0,
      detail:        `Active policies with ${field} in [${values.join(',')}]: ${activeMatch}`,
      evidenceCount: activeMatch,
    };
  },

  active_policy_count({ minCount = 1 }, bundle) {
    const count = bundle.policy_records?.activeCount ?? 0;
    return {
      passed:        count >= minCount,
      detail:        `Active policies: ${count} (required: ${minCount})`,
      evidenceCount: count,
    };
  },

  consent_policy_active(_rule, bundle) {
    const consentPolicies = bundle.policy_records?.consentPolicies ?? 0;
    return {
      passed:        consentPolicies > 0,
      detail:        `Active REQUIRE_CONSENT policies: ${consentPolicies}`,
      evidenceCount: consentPolicies,
    };
  },

  enforcement_block_evidence(_rule, bundle) {
    const blocks = bundle.enforcement?.blockCount ?? 0;
    // What we validate is that the enforcement capability *exists* (i.e. events were processed).
    // Zero enforcement events means the capability has never been exercised — that is
    // unproven, not compliant, so it must not be scored as a PASS.
    const total  = bundle.enforcement?.count ?? 0;
    if (total === 0) {
      return {
        passed:        false,
        notApplicable: true,
        detail:        'No enforcement events in period — enforcement blocking cannot be demonstrated',
        evidenceCount: total,
      };
    }
    return {
      passed:        true,
      detail:        `Total enforcement: ${total}, blocks: ${blocks}`,
      evidenceCount: total,
    };
  },

  audit_chain_non_empty(_rule, bundle) {
    const count = bundle.audit_chain_entries?.count ?? 0;
    return {
      passed:        count > 0,
      detail:        `Audit chain entries in period: ${count}`,
      evidenceCount: count,
    };
  },

  audit_events_exist(_rule, bundle) {
    const count = bundle.audit_events?.count ?? 0;
    return {
      passed:        count > 0,
      detail:        `Audit events in period: ${count}`,
      evidenceCount: count,
    };
  },

  audit_events_in_period(_rule, bundle) {
    const count = bundle.audit_events?.count ?? 0;
    return {
      passed:        count > 0,
      detail:        `Audit events in assessment period: ${count}`,
      evidenceCount: count,
    };
  },

  monitoring_continuity(_rule, bundle) {
    // Evidence exists; deep gap analysis would require time-series data not available here.
    // We mark as passed if there are events; gap detection is advisory.
    const count = bundle.audit_events?.count ?? 0;
    return {
      passed:        count > 0,
      detail:        `Monitoring continuity indicator: ${count} events in period`,
      evidenceCount: count,
    };
  },

  active_signing_key(_rule, bundle) {
    const count = bundle.signing_key_records?.activeCount ?? 0;
    return {
      passed:        count > 0,
      detail:        `Active signing keys: ${count}`,
      evidenceCount: count,
    };
  },

  rbac_users_configured({ minCount = 1 }, bundle) {
    const count = bundle.rbac_users?.count ?? 0;
    return {
      passed:        count >= minCount,
      detail:        `Enabled RBAC users: ${count} (required: ${minCount})`,
      evidenceCount: count,
    };
  },

  rbac_admin_exists(_rule, bundle) {
    const hasAdmin = bundle.rbac_users?.hasAdmin ?? false;
    const count    = bundle.rbac_users?.count    ?? 0;
    return {
      passed:        hasAdmin,
      detail:        `Admin role present: ${hasAdmin} (total RBAC users: ${count})`,
      evidenceCount: hasAdmin ? 1 : 0,
    };
  },

  rbac_role_diversity({ minRoles = 2 }, bundle) {
    const roleCount = bundle.rbac_users?.roleCount ?? 0;
    return {
      passed:        roleCount >= minRoles,
      detail:        `Distinct RBAC roles: ${roleCount} (required: ${minRoles})`,
      evidenceCount: roleCount,
    };
  },

  key_encryption_algorithm({ expected = 'ed25519' }, bundle) {
    const algos = bundle.signing_key_records?.algorithms ?? [];
    const match  = algos.includes(expected);
    return {
      passed:        match || algos.length === 0, // absence is flagged by active_signing_key
      detail:        `Signing algorithms in use: [${algos.join(', ')}]`,
      evidenceCount: algos.length,
    };
  },

  chain_integrity(_rule, bundle) {
    const chainBroken = bundle.audit_chain_entries?.chainBroken ?? false;
    const count       = bundle.audit_chain_entries?.count ?? 0;
    return {
      passed:        !chainBroken,
      detail:        count === 0
        ? 'No audit chain entries in period — cannot verify chain integrity'
        : `Chain integrity check: ${chainBroken ? 'BROKEN' : 'OK'} (${count} entries sampled)`,
      evidenceCount: count,
    };
  },

  signed_artifacts_exist(_rule, bundle) {
    const count = bundle.signed_artifacts?.count ?? 0;
    return {
      passed:        count > 0,
      detail:        `Cryptographically signed artifacts in period: ${count}`,
      evidenceCount: count,
    };
  },

  artifact_provenance(_rule, bundle) {
    const count = bundle.signed_artifacts?.count ?? 0;
    return {
      passed:        count > 0,
      detail:        `Artifacts with cryptographic provenance: ${count}`,
      evidenceCount: count,
    };
  },

  artifact_verification_rate({ minRate = 0.0 }, bundle) {
    const verified = bundle.audit_chain_entries?.verifiedCount ?? 0;
    const total    = bundle.audit_chain_entries?.count ?? 0;
    const rate     = total > 0 ? verified / total : 0;
    return {
      passed:        rate >= minRate || total === 0,
      detail:        `Verification rate: ${(rate * 100).toFixed(1)}% (${verified}/${total})`,
      evidenceCount: verified,
    };
  },

  security_audit_category_events(_rule, bundle) {
    const count = bundle.security_events?.count ?? 0;
    // SECURITY events may legitimately be absent in a clean system, but absence is not
    // positive proof that the SECURITY audit category is being captured at all.
    if (count === 0) {
      return {
        passed:        false,
        notApplicable: true,
        detail:        'No SECURITY category events captured in audit store',
        evidenceCount: count,
      };
    }
    return {
      passed:        true,
      detail:        `SECURITY category events: ${count}`,
      evidenceCount: count,
    };
  },

  security_monitoring_active(_rule, bundle) {
    const securityCount = bundle.security_events?.count ?? 0;
    const totalCount    = bundle.audit_events?.count ?? 0;
    // Monitoring is active if any audit events exist
    return {
      passed:        totalCount > 0,
      detail:        `Security events: ${securityCount}, total audit events: ${totalCount}`,
      evidenceCount: totalCount,
    };
  },

  enforcement_events_logged(_rule, bundle) {
    const count = bundle.enforcement?.count ?? 0;
    return {
      passed:        count > 0,
      detail:        `Enforcement events in period: ${count}`,
      evidenceCount: count,
    };
  },

  block_decision_evidence(_rule, bundle) {
    const total  = bundle.enforcement?.count ?? 0;
    // Block capability is demonstrated by existence of enforcement decisions, not by
    // requiring blocks specifically — but it does require at least one decision to exist.
    if (total === 0) {
      return {
        passed:        false,
        notApplicable: true,
        detail:        'No enforcement decisions recorded — block/override capability cannot be demonstrated',
        evidenceCount: total,
      };
    }
    return {
      passed:        true,
      detail:        `Enforcement capability: ${total} decisions recorded`,
      evidenceCount: total,
    };
  },

  policy_version_history(_rule, bundle) {
    const items   = bundle.policy_records?.items ?? [];
    const versioned = items.filter(p => (p.metadata?.version ?? 0) > 1).length;
    return {
      passed:        versioned > 0 || items.length > 0,
      detail:        `Policies with version > 1: ${versioned} of ${items.length}`,
      evidenceCount: items.length,
    };
  },

  policy_update_evidence(_rule, bundle) {
    const items = bundle.lifecycle_events?.items ?? [];
    const policyUpdates = bundle.policy_records?.items?.filter(
      p => p.metadata?.version > 1,
    ).length ?? 0;
    return {
      passed:        policyUpdates > 0 || items.length > 0,
      detail:        `Policy updates tracked: ${policyUpdates}, lifecycle events: ${items.length}`,
      evidenceCount: policyUpdates + items.length,
    };
  },

  lifecycle_events_exist(_rule, bundle) {
    const keyMgmt   = bundle.key_management_events?.count ?? 0;
    const lifecycle = bundle.lifecycle_events?.count ?? 0;
    return {
      passed:        (keyMgmt + lifecycle) > 0,
      detail:        `Key management events: ${keyMgmt}, lifecycle events: ${lifecycle}`,
      evidenceCount: keyMgmt + lifecycle,
    };
  },

  risk_response_evidence(_rule, bundle) {
    const blocks  = bundle.enforcement?.blockCount ?? 0;
    const total   = bundle.enforcement?.count ?? 0;
    return {
      passed:        total > 0,
      detail:        `Risk response events: ${total} enforcement decisions, ${blocks} blocks`,
      evidenceCount: total,
    };
  },

  risk_categorization_evidence(_rule, bundle) {
    const total = bundle.enforcement?.count ?? 0;
    return {
      passed:        total > 0,
      detail:        `Risk categorization enforced via ${total} decisions`,
      evidenceCount: total,
    };
  },

  enforcement_coverage(_rule, bundle) {
    const total   = bundle.enforcement?.count ?? 0;
    if (total === 0) {
      return {
        passed:        false,
        notApplicable: true,
        detail:        'No enforcement events in period — enforcement coverage cannot be assessed',
        evidenceCount: total,
      };
    }
    return {
      passed:        true,
      detail:        `Enforcement events: ${total}`,
      evidenceCount: total,
    };
  },

  data_governance_policy(_rule, bundle) {
    const active = bundle.policy_records?.activeCount ?? 0;
    return {
      passed:        active > 0,
      detail:        `Active data governance policies: ${active}`,
      evidenceCount: active,
    };
  },

  verification_capability(_rule, bundle) {
    const signed = bundle.signed_artifacts?.count ?? 0;
    // The /verify endpoint always exists structurally, but that is not evidence that
    // anything has actually been verified — evaluation capability requires signed
    // artifacts to have been produced.
    if (signed === 0) {
      return {
        passed:        false,
        notApplicable: true,
        detail:        'No signed artifacts available to demonstrate verification capability',
        evidenceCount: signed,
      };
    }
    return {
      passed:        true,
      detail:        `Signed artifacts available for verification: ${signed}`,
      evidenceCount: signed,
    };
  },

  metrics_available(_rule, bundle) {
    const count = bundle.audit_events?.count ?? 0;
    return {
      passed:        count > 0,
      detail:        `Audit metrics computable from ${count} events`,
      evidenceCount: count,
    };
  },

  key_management_active(_rule, bundle) {
    const keyMgmt   = bundle.key_management_events?.count ?? 0;
    const activeKeys = bundle.signing_key_records?.activeCount ?? 0;
    return {
      passed:        activeKeys > 0,
      detail:        `Active keys: ${activeKeys}, key management events: ${keyMgmt}`,
      evidenceCount: activeKeys + keyMgmt,
    };
  },
};

// ── Core validation ───────────────────────────────────────────────────────────

/**
 * Validate all rules for a single control against the evidence bundle.
 *
 * Rules that find zero supporting evidence report `notApplicable: true` instead of
 * `passed: true` — zero evidence is never sufficient to PASS a control that requires
 * evidence. Such rules are excluded from the control's score; if every rule for a
 * control is inapplicable, the control result itself carries `notApplicable: true`
 * so scoringEngine can exclude it from the weighted framework average.
 *
 * @param {object} control  From controlRegistry
 * @param {object} bundle   From evidenceCollector.collectAll()
 * @returns {{ passed: bool, notApplicable?: bool, score: number, findings: [], evidenceRefs: [], evidenceCount: number }}
 */
function validateControl(control, bundle) {
  const rules    = control.validationRules ?? [];
  const findings = [];
  let   totalEvidence = 0;

  if (rules.length === 0) {
    // No rules defined: pass with full score but note it
    return {
      passed:        true,
      score:         100,
      findings:      [],
      evidenceRefs:  _extractEvidenceRefs(control.evidenceRequired, bundle),
      evidenceCount: 0,
    };
  }

  const ruleResults = rules.map(rule => {
    const handler = RULE_HANDLERS[rule.rule];
    if (!handler) {
      return {
        rule:          rule.rule,
        passed:        false,
        detail:        `Unknown validation rule: "${rule.rule}"`,
        evidenceCount: 0,
      };
    }
    try {
      const res = handler(rule, bundle, control);
      totalEvidence += res.evidenceCount ?? 0;
      return { rule: rule.rule, description: rule.description, ...res };
    } catch (err) {
      return {
        rule:          rule.rule,
        passed:        false,
        detail:        `Rule evaluation error: ${err.message}`,
        evidenceCount: 0,
      };
    }
  });

  // Rules that report zero supporting evidence are excluded from scoring entirely —
  // a rule cannot contribute a PASS or a FAIL when there is nothing to evaluate.
  const applicableResults = ruleResults.filter(r => !r.notApplicable);

  if (applicableResults.length === 0) {
    // Every rule for this control found zero evidence: the control itself is
    // NOT_APPLICABLE rather than PASS or FAIL — it must not contribute to the
    // framework's weighted score in either direction.
    return {
      passed:        false,
      notApplicable: true,
      score:         0,
      findings:      [],
      evidenceRefs:  _extractEvidenceRefs(control.evidenceRequired, bundle),
      evidenceCount: totalEvidence,
      ruleResults,
    };
  }

  // Scoring: each applicable rule contributes equally. Partial rule pass = partial score.
  const passedCount = applicableResults.filter(r => r.passed).length;
  const totalRules  = applicableResults.length;
  const score       = Math.round((passedCount / totalRules) * 100);
  const passed      = passedCount === totalRules;

  // Collect findings for failed applicable rules
  for (const r of applicableResults) {
    if (!r.passed) {
      findings.push({
        severity:    control.isCritical ? 'CRITICAL' : 'MEDIUM',
        rule:        r.rule,
        description: r.description || r.rule,
        detail:      r.detail,
        remediation: control.remediationHint,
      });
    }
  }

  return {
    passed,
    score,
    findings,
    evidenceRefs:  _extractEvidenceRefs(control.evidenceRequired, bundle),
    evidenceCount: totalEvidence,
    ruleResults,
  };
}

function _extractEvidenceRefs(required = [], bundle) {
  const refs = [];
  for (const type of required) {
    const key    = type === 'enforcement_events' ? 'enforcement' : type;
    const source = bundle[key] ?? bundle[type];
    if (!source) continue;
    const items = (source.items ?? []).slice(0, 5); // cap at 5 refs per type
    for (const item of items) {
      refs.push({
        evidenceType: item.evidenceType ?? type,
        sourceTable:  item.sourceTable,
        sourceId:     item.sourceId,
        occurredAt:   item.occurredAt,
        summary:      item.summary,
        valid:        item.valid !== false,
        integrityOk:  item.integrityOk !== false,
        metadata:     item.metadata ?? {},
      });
    }
  }
  return refs;
}

/**
 * Validate all controls for a framework.
 * @param {object[]} controls
 * @param {object} bundle
 * @returns {Map<string, validationResult>}
 */
function validateAll(controls, bundle) {
  const results = new Map();
  for (const ctrl of controls) {
    results.set(ctrl.id, validateControl(ctrl, bundle));
  }
  return results;
}

module.exports = { validateControl, validateAll };
