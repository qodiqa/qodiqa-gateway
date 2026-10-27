'use strict';

/**
 * QODIQA Compliance Control Registry
 *
 * Defines the complete set of compliance controls for:
 *   - GDPR (2016/679)
 *   - EU AI Act (2024/1689)
 *   - ISO/IEC 42001:2023
 *   - NIST AI Risk Management Framework 1.0
 *
 * Each control specifies:
 *   id                — unique control identifier
 *   frameworkId       — parent framework
 *   controlRef        — official reference number (Article, Section, Function)
 *   title             — short control title
 *   description       — full description
 *   category          — control category within the framework
 *   weight            — scoring weight (1.0 = normal, 2.0 = double for critical)
 *   isCritical        — fatal to compliance if failed
 *   evidenceRequired  — array of evidence type strings that must be present
 *   validationRules   — array of rule descriptors used by evidenceValidator.js
 *   remediationHint   — operator guidance when control fails
 */

// ── GDPR Controls ─────────────────────────────────────────────────────────────

const GDPR_CONTROLS = [
  {
    id:              'GDPR-L1',
    frameworkId:     'GDPR',
    controlRef:      'Art. 5(1)(a)',
    title:           'Lawfulness, Fairness and Transparency',
    description:     'Personal data must be processed lawfully, fairly, and in a transparent manner. ' +
                     'AI decisions affecting data subjects must have a legal basis documented and enforced.',
    category:        'Lawfulness',
    weight:          2.0,
    isCritical:      true,
    evidenceRequired: ['enforcement_events', 'policy_records', 'consent_events'],
    validationRules: [
      { rule: 'min_enforcement_events', threshold: 1, description: 'At least one enforcement record must exist' },
      { rule: 'policy_coverage', field: 'type', values: ['REQUIRE_CONSENT'], description: 'Consent policy must be active' },
    ],
    remediationHint: 'Ensure at least one REQUIRE_CONSENT policy is active and enforcement events confirm it is applied.',
  },
  {
    id:              'GDPR-A5',
    frameworkId:     'GDPR',
    controlRef:      'Art. 5(1)(b)',
    title:           'Purpose Limitation',
    description:     'Data collected for one purpose must not be reused for incompatible purposes. ' +
                     'Policy engine must reflect purpose constraints at runtime.',
    category:        'Lawfulness',
    weight:          1.5,
    isCritical:      false,
    evidenceRequired: ['policy_records', 'enforcement_events'],
    validationRules: [
      { rule: 'active_policy_count', minCount: 1, description: 'At least one active policy governing data use' },
    ],
    remediationHint: 'Define and activate purpose-specific policies in the QODIQA policy engine.',
  },
  {
    id:              'GDPR-C1',
    frameworkId:     'GDPR',
    controlRef:      'Art. 6 / Art. 7',
    title:           'Consent Management',
    description:     'Where consent is the legal basis, it must be freely given, specific, informed, and unambiguous. ' +
                     'QODIQA must record and enforce consent before processing.',
    category:        'Consent',
    weight:          2.0,
    isCritical:      true,
    evidenceRequired: ['consent_events', 'enforcement_events', 'policy_records'],
    validationRules: [
      { rule: 'consent_policy_active', description: 'REQUIRE_CONSENT policy must be enabled and have no validation errors' },
      { rule: 'enforcement_block_evidence', description: 'Blocked enforcement events demonstrate consent enforcement' },
    ],
    remediationHint: 'Activate REQUIRE_CONSENT policy. Verify GATEWAY_BLOCK events exist for missing-consent cases.',
  },
  {
    id:              'GDPR-A30',
    frameworkId:     'GDPR',
    controlRef:      'Art. 30',
    title:           'Records of Processing Activities',
    description:     'Controllers must maintain records of all processing activities. ' +
                     'The QODIQA audit chain and audit log serve as the processing record.',
    category:        'Accountability',
    weight:          1.5,
    isCritical:      false,
    evidenceRequired: ['audit_chain_entries', 'audit_events'],
    validationRules: [
      { rule: 'audit_chain_non_empty', description: 'Audit chain must have at least one entry' },
      { rule: 'audit_events_exist', description: 'platform_audit_events must contain records in the period' },
    ],
    remediationHint: 'Ensure audit chain persistence is enabled and events are flowing to the audit store.',
  },
  {
    id:              'GDPR-A32',
    frameworkId:     'GDPR',
    controlRef:      'Art. 32',
    title:           'Security of Processing',
    description:     'Appropriate technical measures must be implemented including encryption at rest. ' +
                     'QODIQA must demonstrate encrypted key storage and access control.',
    category:        'Security',
    weight:          2.0,
    isCritical:      true,
    evidenceRequired: ['key_management_events', 'rbac_users', 'signing_key_records'],
    validationRules: [
      { rule: 'active_signing_key', description: 'At least one active Ed25519 signing key must exist' },
      { rule: 'rbac_users_configured', minCount: 1, description: 'RBAC must be configured with defined roles' },
      { rule: 'key_encryption_algorithm', expected: 'ed25519', description: 'Keys must use approved algorithm' },
    ],
    remediationHint: 'Verify QODIQA_KEY_ENCRYPTION_KEY is set, signing keys are active, and RBAC users are configured.',
  },
  {
    id:              'GDPR-A33',
    frameworkId:     'GDPR',
    controlRef:      'Art. 33',
    title:           'Breach Notification Capability',
    description:     'Controller must be able to detect and notify supervisory authority of breaches within 72 hours. ' +
                     'QODIQA security event logging enables breach detection.',
    category:        'Security',
    weight:          1.5,
    isCritical:      false,
    evidenceRequired: ['security_events', 'audit_events'],
    validationRules: [
      { rule: 'security_audit_category_events', description: 'SECURITY category events must be captured in audit store' },
    ],
    remediationHint: 'Ensure QODIQA_PG_ENABLED=true and centralStore receives SECURITY category events.',
  },
  {
    id:              'GDPR-A35',
    frameworkId:     'GDPR',
    controlRef:      'Art. 35',
    title:           'Data Protection Impact Assessment',
    description:     'High-risk processing requires a DPIA. AI systems using personal data are high-risk. ' +
                     'Evidence of systematic monitoring and risk evaluation must be demonstrable.',
    category:        'Risk Management',
    weight:          1.0,
    isCritical:      false,
    evidenceRequired: ['enforcement_events', 'policy_records'],
    validationRules: [
      { rule: 'policy_version_history', description: 'Policy changes must be tracked (version history exists)' },
    ],
    remediationHint: 'Use QODIQA policy versioning to document evaluation history. Retain policy change audit trail.',
  },
  {
    id:              'GDPR-AU1',
    frameworkId:     'GDPR',
    controlRef:      'Art. 5(2) / Recital 74',
    title:           'Accountability and Audit Trail',
    description:     'Controller must be able to demonstrate compliance. ' +
                     'Immutable audit chain and cryptographic signatures provide accountability evidence.',
    category:        'Accountability',
    weight:          2.0,
    isCritical:      true,
    evidenceRequired: ['audit_chain_entries', 'signed_artifacts', 'audit_events'],
    validationRules: [
      { rule: 'chain_integrity', description: 'Audit chain hash chain must be unbroken' },
      { rule: 'signed_artifacts_exist', description: 'At least one cryptographically signed artifact must exist' },
    ],
    remediationHint: 'Verify audit chain is persisted. Enable artifact signing via /sign endpoint.',
  },
];

// ── EU AI Act Controls ─────────────────────────────────────────────────────────

const EU_AI_ACT_CONTROLS = [
  {
    id:              'EUAIA-G1',
    frameworkId:     'EU_AI_ACT',
    controlRef:      'Art. 9',
    title:           'Risk Management System',
    description:     'High-risk AI systems must implement a continuous risk management system throughout the lifecycle. ' +
                     'QODIQA policy enforcement, anomaly detection, and audit logging satisfy this requirement.',
    category:        'Risk Management',
    weight:          2.0,
    isCritical:      true,
    evidenceRequired: ['enforcement_events', 'policy_records', 'anomaly_events'],
    validationRules: [
      { rule: 'enforcement_coverage', minEnforcedRatio: 0.0, description: 'Enforcement must be operational' },
      { rule: 'active_policy_count', minCount: 1, description: 'At least one active risk policy' },
    ],
    remediationHint: 'Ensure policies cover all AI interactions. Enable runtime enforcement with anomaly detection.',
  },
  {
    id:              'EUAIA-DG1',
    frameworkId:     'EU_AI_ACT',
    controlRef:      'Art. 10',
    title:           'Data and Data Governance',
    description:     'Training, validation, and testing datasets must be governed with documented practices. ' +
                     'Data quality and lineage must be traceable.',
    category:        'Data Governance',
    weight:          1.5,
    isCritical:      false,
    evidenceRequired: ['policy_records', 'enforcement_events'],
    validationRules: [
      { rule: 'data_governance_policy', description: 'Policy governing data handling must exist' },
    ],
    remediationHint: 'Create QODIQA policies that enforce data quality gates. Document dataset provenance.',
  },
  {
    id:              'EUAIA-TD1',
    frameworkId:     'EU_AI_ACT',
    controlRef:      'Art. 11',
    title:           'Technical Documentation',
    description:     'High-risk AI systems must have technical documentation created before market placement ' +
                     'and kept up to date. Signed QODIQA artifacts serve as tamper-evident technical records.',
    category:        'Traceability',
    weight:          1.5,
    isCritical:      false,
    evidenceRequired: ['signed_artifacts', 'audit_chain_entries'],
    validationRules: [
      { rule: 'signed_artifacts_exist', description: 'Cryptographically signed artifacts demonstrate documentation integrity' },
      { rule: 'artifact_verification_rate', minRate: 0.0, description: 'Verification capability must be operational' },
    ],
    remediationHint: 'Enable QODIQA artifact signing for all AI model outputs. Retain signed records.',
  },
  {
    id:              'EUAIA-RK1',
    frameworkId:     'EU_AI_ACT',
    controlRef:      'Art. 12',
    title:           'Record Keeping and Logging',
    description:     'High-risk AI systems must automatically log events throughout operation, ' +
                     'capturing decisions, inputs, and sufficient data to identify anomalies.',
    category:        'Traceability',
    weight:          2.0,
    isCritical:      true,
    evidenceRequired: ['audit_chain_entries', 'audit_events', 'enforcement_events'],
    validationRules: [
      { rule: 'audit_chain_non_empty', description: 'Audit chain logging is operational' },
      { rule: 'enforcement_events_logged', description: 'Every enforcement decision is logged' },
    ],
    remediationHint: 'Ensure audit chain is persisted to PostgreSQL. Every /sign and /verify call must generate audit events.',
  },
  {
    id:              'EUAIA-TR1',
    frameworkId:     'EU_AI_ACT',
    controlRef:      'Art. 13',
    title:           'Transparency and Provision of Information',
    description:     'High-risk AI systems must be transparent. Users must receive information allowing them to ' +
                     'interpret the system\'s output. Cryptographic provenance supports this requirement.',
    category:        'Transparency',
    weight:          1.5,
    isCritical:      false,
    evidenceRequired: ['signed_artifacts', 'audit_events'],
    validationRules: [
      { rule: 'artifact_provenance', description: 'Signed artifacts carry verifiable provenance (keyId, timestamp)' },
    ],
    remediationHint: 'Ensure signed QODIQA envelopes include model ID, timestamp, and policy state. Expose /verify endpoint.',
  },
  {
    id:              'EUAIA-HO1',
    frameworkId:     'EU_AI_ACT',
    controlRef:      'Art. 14',
    title:           'Human Oversight',
    description:     'High-risk AI systems must be designed to enable effective human oversight. ' +
                     'Operators must be able to intervene, stop, and override AI outputs.',
    category:        'Human Oversight',
    weight:          2.0,
    isCritical:      true,
    evidenceRequired: ['enforcement_events', 'rbac_users', 'audit_events'],
    validationRules: [
      { rule: 'block_decision_evidence', description: 'Enforcement blocks demonstrate human-configurable override capability' },
      { rule: 'rbac_admin_exists', description: 'Admin role must exist to enable human policy control' },
    ],
    remediationHint: 'Configure RBAC admin accounts. Test that BLOCK policies can be applied in real time.',
  },
  {
    id:              'EUAIA-AC1',
    frameworkId:     'EU_AI_ACT',
    controlRef:      'Art. 15',
    title:           'Accuracy, Robustness and Cybersecurity',
    description:     'High-risk AI systems must achieve appropriate levels of accuracy and be resilient ' +
                     'against adversarial manipulation, including replay attacks.',
    category:        'Cybersecurity',
    weight:          1.5,
    isCritical:      false,
    evidenceRequired: ['security_events', 'key_management_events', 'audit_events'],
    validationRules: [
      { rule: 'active_signing_key', description: 'Cryptographic signing demonstrates anti-tampering' },
      { rule: 'security_monitoring_active', description: 'SECURITY category events captured' },
    ],
    remediationHint: 'Enable replay protection (STRICT_REPLAY_PROTECTION=true). Ensure nonce store is Redis-backed.',
  },
  {
    id:              'EUAIA-CONF1',
    frameworkId:     'EU_AI_ACT',
    controlRef:      'Art. 16 / Art. 17',
    title:           'Quality Management and Conformity',
    description:     'Providers must implement a quality management system covering all aspects of the AI lifecycle.',
    category:        'Governance',
    weight:          1.0,
    isCritical:      false,
    evidenceRequired: ['policy_records', 'lifecycle_events', 'audit_events'],
    validationRules: [
      { rule: 'lifecycle_events_exist', description: 'Key lifecycle events (KEY_CREATED, KEY_ROTATED) must be logged' },
    ],
    remediationHint: 'Ensure key rotation events are logged. Document and track policy lifecycle changes.',
  },
];

// ── ISO/IEC 42001 Controls ─────────────────────────────────────────────────────

const ISO_42001_CONTROLS = [
  {
    id:              'ISO42001-4-1',
    frameworkId:     'ISO_42001',
    controlRef:      'Clause 4.1',
    title:           'Understanding the Organization and its Context',
    description:     'The organization must determine internal and external issues relevant to its purpose ' +
                     'and their effect on its ability to achieve intended AI management outcomes.',
    category:        'Context',
    weight:          1.0,
    isCritical:      false,
    evidenceRequired: ['policy_records', 'audit_events'],
    validationRules: [
      { rule: 'active_policy_count', minCount: 1, description: 'Policy framework must be established' },
    ],
    remediationHint: 'Establish policies that reflect organizational AI context and risk appetite.',
  },
  {
    id:              'ISO42001-5-1',
    frameworkId:     'ISO_42001',
    controlRef:      'Clause 5.1',
    title:           'Leadership and Commitment',
    description:     'Top management must demonstrate leadership and commitment to the AI management system ' +
                     'by ensuring policies, resources, and accountabilities are defined.',
    category:        'Leadership',
    weight:          1.5,
    isCritical:      false,
    evidenceRequired: ['rbac_users', 'policy_records', 'audit_events'],
    validationRules: [
      { rule: 'rbac_admin_exists', description: 'Management role (admin) must exist in RBAC' },
      { rule: 'active_policy_count', minCount: 1, description: 'At least one policy must be approved and active' },
    ],
    remediationHint: 'Assign admin RBAC roles. Ensure compliance officers are registered in the system.',
  },
  {
    id:              'ISO42001-6-1',
    frameworkId:     'ISO_42001',
    controlRef:      'Clause 6.1',
    title:           'Actions to Address Risks and Opportunities',
    description:     'The organization must plan actions to address risks and opportunities, ' +
                     'integrating these into AI management system processes.',
    category:        'Risk',
    weight:          1.5,
    isCritical:      false,
    evidenceRequired: ['enforcement_events', 'policy_records', 'security_events'],
    validationRules: [
      { rule: 'risk_response_evidence', description: 'Enforcement blocks demonstrate risk response capability' },
    ],
    remediationHint: 'Document risk treatment in policies. Review BLOCK enforcement events for risk patterns.',
  },
  {
    id:              'ISO42001-8-1',
    frameworkId:     'ISO_42001',
    controlRef:      'Clause 8.1',
    title:           'Operational Planning and Control',
    description:     'Processes needed to meet AI management requirements must be planned, implemented, ' +
                     'controlled, and maintained.',
    category:        'Operations',
    weight:          1.5,
    isCritical:      false,
    evidenceRequired: ['enforcement_events', 'audit_events', 'audit_chain_entries'],
    validationRules: [
      { rule: 'enforcement_events_logged', description: 'Operational enforcement events must be captured' },
      { rule: 'audit_chain_non_empty', description: 'Operational audit trail must exist' },
    ],
    remediationHint: 'Ensure runtime enforcement is active and all AI interactions generate audit events.',
  },
  {
    id:              'ISO42001-9-1',
    frameworkId:     'ISO_42001',
    controlRef:      'Clause 9.1',
    title:           'Monitoring, Measurement, Analysis and Evaluation',
    description:     'The organization must evaluate AI management system performance. ' +
                     'Methods, criteria, and timing for monitoring must be determined.',
    category:        'Monitoring',
    weight:          2.0,
    isCritical:      true,
    evidenceRequired: ['audit_events', 'enforcement_events', 'security_events'],
    validationRules: [
      { rule: 'audit_events_in_period', description: 'Audit events must exist within the assessment period' },
      { rule: 'monitoring_continuity', description: 'No gaps longer than 24 hours in audit event stream' },
    ],
    remediationHint: 'Configure continuous audit event streaming. Set up health monitoring on the audit store.',
  },
  {
    id:              'ISO42001-9-3',
    frameworkId:     'ISO_42001',
    controlRef:      'Clause 9.3',
    title:           'Management Review',
    description:     'Top management must review the AI management system at planned intervals ' +
                     'to ensure its continuing suitability, adequacy, and effectiveness.',
    category:        'Governance',
    weight:          1.0,
    isCritical:      false,
    evidenceRequired: ['audit_events', 'policy_records'],
    validationRules: [
      { rule: 'policy_update_evidence', description: 'Policy updates demonstrate management review cycle' },
    ],
    remediationHint: 'Schedule regular policy reviews. Use QODIQA policy versioning to track review decisions.',
  },
  {
    id:              'ISO42001-10-1',
    frameworkId:     'ISO_42001',
    controlRef:      'Clause 10.1',
    title:           'Continual Improvement',
    description:     'The organization must continually improve the suitability, adequacy, and effectiveness ' +
                     'of the AI management system.',
    category:        'Improvement',
    weight:          1.0,
    isCritical:      false,
    evidenceRequired: ['policy_records', 'lifecycle_events'],
    validationRules: [
      { rule: 'policy_version_history', description: 'Policy version increments demonstrate continual improvement' },
    ],
    remediationHint: 'Track policy changes via version history. Document rationale for each policy update.',
  },
  {
    id:              'ISO42001-A-4',
    frameworkId:     'ISO_42001',
    controlRef:      'Annex A — 4',
    title:           'AI System Impact Assessment',
    description:     'Before deployment, the organization must conduct and document an AI impact assessment ' +
                     'addressing risks to individuals and society.',
    category:        'Risk',
    weight:          1.5,
    isCritical:      false,
    evidenceRequired: ['enforcement_events', 'signed_artifacts'],
    validationRules: [
      { rule: 'signed_artifacts_exist', description: 'Signed artifacts demonstrate pre-deployment assessment artifacts' },
    ],
    remediationHint: 'Use QODIQA artifact signing to notarize impact assessment documents before deployment.',
  },
  {
    id:              'ISO42001-A-6',
    frameworkId:     'ISO_42001',
    controlRef:      'Annex A — 6',
    title:           'AI System Lifecycle Management',
    description:     'The organization must establish processes for the entire lifecycle of AI systems ' +
                     'including development, deployment, monitoring, and decommissioning.',
    category:        'Lifecycle',
    weight:          1.5,
    isCritical:      false,
    evidenceRequired: ['lifecycle_events', 'key_management_events', 'audit_events'],
    validationRules: [
      { rule: 'lifecycle_events_exist', description: 'Lifecycle events (KEY_CREATED, KEY_ROTATED, KEY_REVOKED) demonstrate lifecycle management' },
    ],
    remediationHint: 'Ensure key rotation and revocation events are captured. Use policy versioning to track AI system changes.',
  },
];

// ── NIST AI RMF Controls ───────────────────────────────────────────────────────

const NIST_AI_RMF_CONTROLS = [
  {
    id:              'NIST-GOV-1-1',
    frameworkId:     'NIST_AI_RMF',
    controlRef:      'GOVERN 1.1',
    title:           'Policies, Processes and Procedures',
    description:     'Policies, processes, and procedures are in place and documented so that the risks ' +
                     'of AI systems are addressed in alignment with organizational risk strategy.',
    category:        'GOVERN',
    weight:          2.0,
    isCritical:      true,
    evidenceRequired: ['policy_records', 'enforcement_events', 'audit_events'],
    validationRules: [
      { rule: 'active_policy_count', minCount: 1, description: 'At least one active policy must govern AI behavior' },
      { rule: 'enforcement_events_logged', description: 'Policies must generate enforcement evidence' },
    ],
    remediationHint: 'Define AI risk policies in the QODIQA policy engine. Verify enforcement generates audit records.',
  },
  {
    id:              'NIST-GOV-1-2',
    frameworkId:     'NIST_AI_RMF',
    controlRef:      'GOVERN 1.2',
    title:           'Accountability',
    description:     'The characteristics of trustworthy AI are integrated into organizational policies, ' +
                     'processes, procedures, and practices.',
    category:        'GOVERN',
    weight:          1.5,
    isCritical:      false,
    evidenceRequired: ['rbac_users', 'audit_events', 'signing_key_records'],
    validationRules: [
      { rule: 'rbac_users_configured', minCount: 1, description: 'Role-based access control demonstrates accountability structure' },
      { rule: 'active_signing_key', description: 'Cryptographic accountability via signing must be operational' },
    ],
    remediationHint: 'Assign named RBAC users. Enable artifact signing to establish cryptographic accountability.',
  },
  {
    id:              'NIST-GOV-4-1',
    frameworkId:     'NIST_AI_RMF',
    controlRef:      'GOVERN 4.1',
    title:           'Organizational Teams and Roles',
    description:     'Organizational teams are committed to a culture that supports AI risk management. ' +
                     'Roles and responsibilities for AI risk management are documented.',
    category:        'GOVERN',
    weight:          1.0,
    isCritical:      false,
    evidenceRequired: ['rbac_users'],
    validationRules: [
      { rule: 'rbac_role_diversity', minRoles: 2, description: 'Multiple RBAC roles demonstrate documented responsibilities' },
    ],
    remediationHint: 'Configure distinct RBAC roles (admin, auditor, compliance, operator) in the system.',
  },
  {
    id:              'NIST-MAP-1-1',
    frameworkId:     'NIST_AI_RMF',
    controlRef:      'MAP 1.1',
    title:           'Context Establishment',
    description:     'The context in which AI systems operate is understood and documented. ' +
                     'Intended purpose, goals, risk appetite, and operational environment are mapped.',
    category:        'MAP',
    weight:          1.5,
    isCritical:      false,
    evidenceRequired: ['policy_records', 'enforcement_events'],
    validationRules: [
      { rule: 'active_policy_count', minCount: 1, description: 'Policy framework establishes operational context' },
    ],
    remediationHint: 'Create policies that reflect the intended use context of each AI system.',
  },
  {
    id:              'NIST-MAP-2-1',
    frameworkId:     'NIST_AI_RMF',
    controlRef:      'MAP 2.1',
    title:           'Scientific Groundedness and Risk Categorization',
    description:     'AI risk and benefits are identified and categorized. Risk sources are enumerated ' +
                     'including harms to individuals, groups, organizations, and society.',
    category:        'MAP',
    weight:          1.5,
    isCritical:      false,
    evidenceRequired: ['enforcement_events', 'security_events', 'policy_records'],
    validationRules: [
      { rule: 'risk_categorization_evidence', description: 'Blocked enforcement events indicate risk categorization is applied' },
    ],
    remediationHint: 'Configure risk-tiered policies. Use BLOCK policies for high-risk scenarios.',
  },
  {
    id:              'NIST-MAP-5-1',
    frameworkId:     'NIST_AI_RMF',
    controlRef:      'MAP 5.1',
    title:           'Likelihood and Impact Assessment',
    description:     'Likelihood and impact of each identified risk is evaluated and documented. ' +
                     'Risk prioritization informs resource allocation and treatment decisions.',
    category:        'MAP',
    weight:          1.0,
    isCritical:      false,
    evidenceRequired: ['enforcement_events', 'audit_events'],
    validationRules: [
      { rule: 'enforcement_events_logged', description: 'Enforcement records provide impact measurement baseline' },
    ],
    remediationHint: 'Review BLOCK decision rationale in audit records to assess impact evidence.',
  },
  {
    id:              'NIST-MEA-1-1',
    frameworkId:     'NIST_AI_RMF',
    controlRef:      'MEASURE 1.1',
    title:           'AI Risk Metrics',
    description:     'AI risk measurement approaches are identified and applied following applicable standards. ' +
                     'Key performance indicators for AI risk are tracked.',
    category:        'MEASURE',
    weight:          1.5,
    isCritical:      false,
    evidenceRequired: ['audit_events', 'enforcement_events'],
    validationRules: [
      { rule: 'metrics_available', description: 'Enforcement and audit metrics must be computable from audit store' },
    ],
    remediationHint: 'Enable audit store (QODIQA_PG_ENABLED=true). Expose /compliance/metrics endpoint.',
  },
  {
    id:              'NIST-MEA-2-1',
    frameworkId:     'NIST_AI_RMF',
    controlRef:      'MEASURE 2.1',
    title:           'Evaluation Methods',
    description:     'Test sets, metrics, and methodologies are in place to evaluate AI systems against ' +
                     'intended use and known risks.',
    category:        'MEASURE',
    weight:          1.5,
    isCritical:      false,
    evidenceRequired: ['signed_artifacts', 'audit_chain_entries', 'enforcement_events'],
    validationRules: [
      { rule: 'verification_capability', description: 'QODIQA /verify endpoint demonstrates evaluation capability' },
      { rule: 'signed_artifacts_exist', description: 'Signed artifacts demonstrate evaluation artifacts exist' },
    ],
    remediationHint: 'Ensure /verify endpoint is operational. Sign and retain test evaluation artifacts.',
  },
  {
    id:              'NIST-MEA-4-1',
    frameworkId:     'NIST_AI_RMF',
    controlRef:      'MEASURE 4.1',
    title:           'Risk Measurement Feedback',
    description:     'Measurement results inform risk management decisions. Identified AI risks are tracked ' +
                     'and reviewed to ensure treatment is effective.',
    category:        'MEASURE',
    weight:          1.0,
    isCritical:      false,
    evidenceRequired: ['audit_events', 'lifecycle_events'],
    validationRules: [
      { rule: 'policy_update_evidence', description: 'Policy updates in response to audit findings demonstrate feedback loop' },
    ],
    remediationHint: 'Document policy changes triggered by audit findings. Use policy versioning to track feedback cycles.',
  },
  {
    id:              'NIST-MAN-1-1',
    frameworkId:     'NIST_AI_RMF',
    controlRef:      'MANAGE 1.1',
    title:           'Risk Response Planning',
    description:     'Plans to respond to identified risks are developed. Risk response mechanisms are ' +
                     'tested and documented.',
    category:        'MANAGE',
    weight:          1.5,
    isCritical:      false,
    evidenceRequired: ['enforcement_events', 'policy_records', 'audit_events'],
    validationRules: [
      { rule: 'block_decision_evidence', description: 'BLOCK enforcement events demonstrate risk response execution' },
    ],
    remediationHint: 'Define and test BLOCK policies for identified risk scenarios. Retain enforcement audit records.',
  },
  {
    id:              'NIST-MAN-2-1',
    frameworkId:     'NIST_AI_RMF',
    controlRef:      'MANAGE 2.1',
    title:           'Treatment of Risks',
    description:     'AI risk treatments are documented, implemented, and tracked. Actions are taken to ' +
                     'reduce, transfer, avoid, or accept identified risks.',
    category:        'MANAGE',
    weight:          1.5,
    isCritical:      false,
    evidenceRequired: ['enforcement_events', 'lifecycle_events', 'key_management_events'],
    validationRules: [
      { rule: 'key_management_active', description: 'Key rotation events demonstrate proactive risk treatment' },
      { rule: 'enforcement_events_logged', description: 'Policy enforcement demonstrates risk treatment application' },
    ],
    remediationHint: 'Perform regular key rotations. Enforce risk-treatment policies at runtime.',
  },
  {
    id:              'NIST-MAN-4-1',
    frameworkId:     'NIST_AI_RMF',
    controlRef:      'MANAGE 4.1',
    title:           'Incident Response',
    description:     'Processes for detecting, reporting, and responding to AI incidents are established ' +
                     'and tested.',
    category:        'MANAGE',
    weight:          1.5,
    isCritical:      false,
    evidenceRequired: ['security_events', 'audit_events', 'key_management_events'],
    validationRules: [
      { rule: 'security_audit_category_events', description: 'SECURITY events in audit store demonstrate incident detection' },
    ],
    remediationHint: 'Configure alert thresholds on SECURITY category events. Test incident response runbook.',
  },
];

// ── Registry ──────────────────────────────────────────────────────────────────

const ALL_CONTROLS = [
  ...GDPR_CONTROLS,
  ...EU_AI_ACT_CONTROLS,
  ...ISO_42001_CONTROLS,
  ...NIST_AI_RMF_CONTROLS,
];

const _byId       = new Map(ALL_CONTROLS.map(c => [c.id, c]));
const _byFramework = new Map();

for (const ctrl of ALL_CONTROLS) {
  if (!_byFramework.has(ctrl.frameworkId)) _byFramework.set(ctrl.frameworkId, []);
  _byFramework.get(ctrl.frameworkId).push(ctrl);
}

const FRAMEWORK_IDS = ['GDPR', 'EU_AI_ACT', 'ISO_42001', 'NIST_AI_RMF'];

function getControl(id) {
  return _byId.get(id) ?? null;
}

function getControlsForFramework(frameworkId) {
  return _byFramework.get(frameworkId) ?? [];
}

function getAllControls() {
  return [...ALL_CONTROLS];
}

function isValidFramework(id) {
  return FRAMEWORK_IDS.includes(id);
}

module.exports = {
  getAllControls,
  getControl,
  getControlsForFramework,
  isValidFramework,
  FRAMEWORK_IDS,
  GDPR_CONTROLS,
  EU_AI_ACT_CONTROLS,
  ISO_42001_CONTROLS,
  NIST_AI_RMF_CONTROLS,
};
