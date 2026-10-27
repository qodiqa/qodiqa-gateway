# Target privilege policy (role x object x operation)

Status: **IMPLEMENTED** (migration 099). The policy plus the table created after it.

## 1. Changes from the policy

| object | change |
|---|---|
| external_anchors | new table (migrations 099 / 100): qodiqa_app: SELECT, INSERT, UPDATE; qodiqa_read: SELECT; qodiqa_backup: SELECT; RLS on (forced) |
| agent_identities | new table (migrations 099 / 100): qodiqa_app: SELECT, INSERT; qodiqa_read: SELECT; qodiqa_backup: SELECT; RLS on (forced) |
| agent_sessions | new table (migrations 099 / 100): qodiqa_app: SELECT, INSERT; qodiqa_read: SELECT; qodiqa_backup: SELECT; RLS on (forced) |
| tool_registry | new table (migrations 099 / 100): qodiqa_app: SELECT, INSERT; qodiqa_read: SELECT; qodiqa_backup: SELECT; RLS on (forced) |
| action_executions | new table (migrations 099 / 100): qodiqa_app: SELECT, INSERT; qodiqa_read: SELECT; qodiqa_backup: SELECT; RLS on (forced) |
| action_plans | new table (migrations 099 / 100): qodiqa_app: SELECT, INSERT; qodiqa_read: SELECT; qodiqa_backup: SELECT; RLS on (forced) |
| agent_delegations | new table (migrations 099 / 100): qodiqa_app: SELECT, INSERT; qodiqa_read: SELECT; qodiqa_backup: SELECT; RLS on (forced) |
| delegation_uses | new table (migrations 099 / 100): qodiqa_app: SELECT, INSERT; qodiqa_read: SELECT; qodiqa_backup: SELECT; RLS on (forced) |
| mcp_servers | new table (migrations 099 / 100): qodiqa_app: SELECT, INSERT; qodiqa_read: SELECT; qodiqa_backup: SELECT; RLS on (forced) |
| approval_requests | new table (migrations 099 / 100): qodiqa_app: SELECT, INSERT; qodiqa_read: SELECT; qodiqa_backup: SELECT; RLS on (forced) |

## 2. Canonical policy (JSON)

```json
{
 "source": "privilege matrix of the disposable database",
 "status": "IMPLEMENTED",
 "roles": {
  "qodiqa_app": {
   "super": false,
   "inherit": true,
   "createrole": false,
   "createdb": false,
   "login": true,
   "bypassrls": false,
   "member_of": []
  },
  "qodiqa_mig": {
   "super": false,
   "inherit": true,
   "createrole": false,
   "createdb": false,
   "login": true,
   "bypassrls": true,
   "member_of": []
  },
  "qodiqa_read": {
   "super": false,
   "inherit": true,
   "createrole": false,
   "createdb": false,
   "login": true,
   "bypassrls": false,
   "member_of": []
  },
  "qodiqa_retention": {
   "super": false,
   "inherit": true,
   "createrole": false,
   "createdb": false,
   "login": true,
   "bypassrls": false,
   "member_of": []
  },
  "qodiqa_test": {
   "super": false,
   "inherit": true,
   "createrole": true,
   "createdb": true,
   "login": true,
   "bypassrls": true,
   "member_of": [
    "pg_signal_backend",
    "qodiqa_app",
    "qodiqa_mig",
    "qodiqa_mig",
    "qodiqa_read",
    "qodiqa_retention"
   ]
  },
  "qodiqa_system": {
   "super": false,
   "inherit": true,
   "createrole": false,
   "createdb": false,
   "login": true,
   "bypassrls": false,
   "member_of": []
  },
  "qodiqa_reporting": {
   "super": false,
   "inherit": true,
   "createrole": false,
   "createdb": false,
   "login": true,
   "bypassrls": false,
   "member_of": []
  },
  "qodiqa_control": {
   "super": false,
   "inherit": true,
   "createrole": false,
   "createdb": false,
   "login": true,
   "bypassrls": false,
   "member_of": []
  },
  "qodiqa_backup": {
   "super": false,
   "inherit": true,
   "createrole": false,
   "createdb": false,
   "login": true,
   "bypassrls": true,
   "member_of": []
  },
  "qodiqa_definer": {
   "super": false,
   "inherit": true,
   "createrole": false,
   "createdb": false,
   "login": false,
   "bypassrls": true,
   "member_of": []
  },
  "qodiqa_owner": {
   "super": false,
   "inherit": true,
   "createrole": false,
   "createdb": false,
   "login": false,
   "bypassrls": false,
   "member_of": []
  }
 },
 "tables": {
  "approval_events": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "attestations": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "audit_chain": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT",
     "UPDATE"
    ]
   },
   "columnOnlyUpdate": [],
   "triggers": [
    "audit_chain_append_only_guard",
    "audit_chain_maintenance_log",
    "audit_chain_mirror_count_delete",
    "audit_chain_mirror_count_insert",
    "audit_chain_mirror_count_truncate",
    "audit_chain_no_truncate"
   ]
  },
  "audit_chain_checkpoints": {
   "kind": "r",
   "rls": false,
   "forceRls": false,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "audit_chain_head": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "audit_chain_mirror_count": {
   "kind": "r",
   "rls": false,
   "forceRls": false,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [],
    "qodiqa_read": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_reporting": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT",
     "INSERT"
    ]
   },
   "columnOnlyUpdate": [
    "qodiqa_definer"
   ],
   "triggers": [
    "audit_chain_mirror_count_guard",
    "audit_chain_mirror_count_no_truncate"
   ]
  },
  "audit_chain_prunes": {
   "kind": "r",
   "rls": false,
   "forceRls": false,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_reporting": [
     "SELECT"
    ],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": [
    "audit_chain_prunes_append_only_guard",
    "audit_chain_prunes_no_truncate"
   ]
  },
  "audit_chain_verification_progress": {
   "kind": "r",
   "rls": false,
   "forceRls": false,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_reporting": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "audit_chain_verifier_state": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "audit_checksum_anchor": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": [
    "audit_checksum_anchor_monotonic_guard"
   ]
  },
  "audit_legal_holds": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT"
    ]
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "audit_retention_policies": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE",
     "DELETE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [
     "SELECT"
    ],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT"
    ]
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "audit_retention_runs": {
   "kind": "r",
   "rls": false,
   "forceRls": false,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "audit_signed_checkpoints": {
   "kind": "r",
   "rls": false,
   "forceRls": false,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_reporting": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": [
    "audit_signed_checkpoints_append_only_guard",
    "audit_signed_checkpoints_no_truncate"
   ]
  },
  "certificate_artifacts": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "certifications": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "compliance_control_assessments": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "compliance_controls": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "compliance_evidence_refs": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "compliance_frameworks": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "compliance_report_exports": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "compliance_report_signatures": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "compliance_reports": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT"
    ]
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "consent_audit_log": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT"
    ]
   },
   "columnOnlyUpdate": [
    "qodiqa_definer"
   ],
   "triggers": []
  },
  "consent_records": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT"
    ]
   },
   "columnOnlyUpdate": [],
   "triggers": [
    "consent_records_updated_at"
   ]
  },
  "consent_scopes": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "control_plane_records": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [],
    "qodiqa_read": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_reporting": [],
    "qodiqa_control": [
     "SELECT",
     "INSERT",
     "UPDATE"
    ],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": [
    "control_plane_records_guard"
   ]
  },
  "dsr_erasure_ledger": {
   "kind": "r",
   "rls": false,
   "forceRls": false,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [],
    "qodiqa_read": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_reporting": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT",
     "INSERT"
    ]
   },
   "columnOnlyUpdate": [],
   "triggers": [
    "dsr_erasure_ledger_append_only_guard",
    "dsr_erasure_ledger_no_truncate"
   ]
  },
  "dsr_exports": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT"
    ]
   },
   "columnOnlyUpdate": [
    "qodiqa_definer"
   ],
   "triggers": []
  },
  "dsr_rectifications": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT"
    ]
   },
   "columnOnlyUpdate": [
    "qodiqa_definer"
   ],
   "triggers": []
  },
  "dsr_request_events": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "INSERT"
    ]
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "dsr_requests": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT"
    ]
   },
   "columnOnlyUpdate": [
    "qodiqa_definer"
   ],
   "triggers": [
    "dsr_requests_updated_at"
   ]
  },
  "evidence_chain_head": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "UPDATE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "evidence_chain_records": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT"
    ]
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "evidence_chain_verifications": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "evidence_packages": {
   "kind": "r",
   "rls": false,
   "forceRls": false,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "gap_scanner_state": {
   "kind": "r",
   "rls": false,
   "forceRls": false,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "investigation_artifacts": {
   "kind": "r",
   "rls": false,
   "forceRls": false,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE",
     "DELETE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "investigation_audit_events": {
   "kind": "r",
   "rls": false,
   "forceRls": false,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": [
    "investigation_audit_events_append_only_guard",
    "investigation_audit_events_maintenance_log",
    "investigation_audit_events_no_truncate"
   ]
  },
  "investigations": {
   "kind": "r",
   "rls": false,
   "forceRls": false,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE",
     "DELETE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "kms_encrypted_data_keys": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "kms_provider_events": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "kms_wrapping_key_rotations": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "organizations": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [],
    "qodiqa_read": [],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": [
    "set_organizations_updated_at"
   ]
  },
  "persistence_recovery_queue": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE",
     "DELETE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "platform_audit_events": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [
     "SELECT",
     "UPDATE",
     "DELETE"
    ],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT"
    ]
   },
   "columnOnlyUpdate": [
    "qodiqa_app",
    "qodiqa_definer"
   ],
   "triggers": [
    "platform_audit_events_append_only_guard"
   ]
  },
  "policies": {
   "kind": "r",
   "rls": false,
   "forceRls": false,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE",
     "DELETE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "policy_approvals": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "policy_change_requests": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT"
    ]
   },
   "columnOnlyUpdate": [],
   "triggers": [
    "policy_change_requests_updated_at"
   ]
  },
  "policy_emergency_activations": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT"
    ]
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "policy_history": {
   "kind": "r",
   "rls": false,
   "forceRls": false,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": [
    "policy_history_append_only_guard",
    "policy_history_maintenance_log",
    "policy_history_no_truncate"
   ]
  },
  "policy_provenance_integrity_runs": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "policy_provenance_versions": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "policy_publications": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "policy_reviews": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "policy_rollbacks": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "policy_versions": {
   "kind": "r",
   "rls": false,
   "forceRls": false,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE",
     "DELETE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "portal_verifications": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "qodiqa_alert_history": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT"
    ]
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "qodiqa_alert_stats": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [],
    "qodiqa_read": [],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "qodiqa_alerts": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE"
    ],
    "qodiqa_read": [],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT"
    ]
   },
   "columnOnlyUpdate": [
    "qodiqa_definer"
   ],
   "triggers": []
  },
  "qodiqa_anomaly_baselines": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [],
    "qodiqa_read": [],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "qodiqa_escalation_records": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "INSERT"
    ],
    "qodiqa_read": [],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "qodiqa_incidents": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "INSERT"
    ],
    "qodiqa_read": [],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "qodiqa_migrations": {
   "kind": "r",
   "rls": false,
   "forceRls": false,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "qodiqa_notification_deliveries": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "INSERT"
    ],
    "qodiqa_read": [],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "qodiqa_suppression_rules": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "UPDATE"
    ],
    "qodiqa_read": [],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "rbac_users": {
   "kind": "r",
   "rls": false,
   "forceRls": false,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE",
     "DELETE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "request_trails": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "INSERT"
    ],
    "qodiqa_read": [],
    "qodiqa_retention": [
     "SELECT",
     "UPDATE",
     "DELETE"
    ],
    "qodiqa_system": [],
    "qodiqa_reporting": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT"
    ]
   },
   "columnOnlyUpdate": [
    "qodiqa_definer"
   ],
   "triggers": []
  },
  "revocation_events": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [],
    "qodiqa_read": [],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT"
    ]
   },
   "columnOnlyUpdate": [
    "qodiqa_definer"
   ],
   "triggers": []
  },
  "signing_key_legacy_map": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "signing_keys": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "subject_pseudonym_keys": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_reporting": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT",
     "DELETE"
    ]
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "tenant_policy_sets": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT"
    ]
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "tenant_semantic_configs": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT"
    ]
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "tenants": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [],
    "qodiqa_read": [],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": [
    "set_tenants_updated_at"
   ]
  },
  "transparency_log_entries": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [
     "SELECT"
    ]
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "transparency_log_head": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "UPDATE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "transparency_merkle_checkpoints": {
   "kind": "r",
   "rls": false,
   "forceRls": false,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "transparency_roots": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "transparency_roots_head": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "UPDATE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "transparency_verifications": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "webhook_delivery_log": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "webhook_endpoints": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_reporting": [],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "external_anchors": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT",
     "UPDATE"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_reporting": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [],
    "qodiqa_owner": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "agent_identities": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_reporting": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [],
    "qodiqa_owner": []
   },
   "columnOnlyUpdate": [
    "qodiqa_app"
   ],
   "triggers": []
  },
  "agent_sessions": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_reporting": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [],
    "qodiqa_owner": []
   },
   "columnOnlyUpdate": [
    "qodiqa_app"
   ],
   "triggers": []
  },
  "tool_registry": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_reporting": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [],
    "qodiqa_owner": []
   },
   "columnOnlyUpdate": [
    "qodiqa_app"
   ],
   "triggers": []
  },
  "action_executions": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_reporting": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [],
    "qodiqa_owner": []
   },
   "columnOnlyUpdate": [
    "qodiqa_app"
   ],
   "triggers": []
  },
  "action_plans": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_reporting": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [],
    "qodiqa_owner": []
   },
   "columnOnlyUpdate": [
    "qodiqa_app"
   ],
   "triggers": []
  },
  "agent_delegations": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_reporting": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [],
    "qodiqa_owner": []
   },
   "columnOnlyUpdate": [
    "qodiqa_app"
   ],
   "triggers": []
  },
  "delegation_uses": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_reporting": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [],
    "qodiqa_owner": []
   },
   "columnOnlyUpdate": [],
   "triggers": []
  },
  "mcp_servers": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_reporting": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [],
    "qodiqa_owner": []
   },
   "columnOnlyUpdate": [
    "qodiqa_app"
   ],
   "triggers": []
  },
  "approval_requests": {
   "kind": "r",
   "rls": true,
   "forceRls": true,
   "publicPrivs": [],
   "privs": {
    "qodiqa_app": [
     "SELECT",
     "INSERT"
    ],
    "qodiqa_read": [
     "SELECT"
    ],
    "qodiqa_retention": [],
    "qodiqa_system": [],
    "qodiqa_reporting": [],
    "qodiqa_control": [],
    "qodiqa_backup": [
     "SELECT"
    ],
    "qodiqa_definer": [],
    "qodiqa_owner": []
   },
   "columnOnlyUpdate": [
    "qodiqa_app"
   ],
   "triggers": []
  }
 },
 "functions": {
  "qodiqa_audit_chain_detect_sequence_gaps(from_seq bigint, batch_size integer)": {
   "executableBy": [
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_audit_chain_fetch_batch(from_seq bigint, batch_size integer)": {
   "executableBy": [
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_audit_chain_fetch_by_artifact_id(target_artifact_id character varying)": {
   "executableBy": [
    "qodiqa_reporting"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_audit_chain_fetch_replay_lineage(target_artifact_id character varying)": {
   "executableBy": [
    "qodiqa_reporting"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_audit_chain_fetch_row_by_seq(target_seq bigint)": {
   "executableBy": [
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_audit_chain_full_read()": {
   "executableBy": [
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_audit_chain_hash_exists(target_hash character)": {
   "executableBy": [
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_audit_chain_max_seq()": {
   "executableBy": [
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_audit_chain_true_tail()": {
   "executableBy": [
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_audit_legal_holds_full_read()": {
   "executableBy": [
    "qodiqa_reporting"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_audit_retention_policies_full_read()": {
   "executableBy": [
    "qodiqa_reporting"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_compliance_reports_full_read()": {
   "executableBy": [
    "qodiqa_reporting"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_consent_audit_log_full_read()": {
   "executableBy": [
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_evidence_chain_records_full_read()": {
   "executableBy": [
    "qodiqa_reporting"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_platform_audit_events_full_read()": {
   "executableBy": [
    "qodiqa_reporting"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_policy_change_request_by_id(p_id uuid)": {
   "executableBy": [
    "qodiqa_reporting"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_policy_emergency_activations_full_read()": {
   "executableBy": [
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_qodiqa_alert_history_full_read()": {
   "executableBy": [
    "qodiqa_reporting"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_qodiqa_alerts_full_read()": {
   "executableBy": [
    "qodiqa_reporting"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_tenant_policy_sets_full_read()": {
   "executableBy": [
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_tenant_semantic_configs_full_read()": {
   "executableBy": [
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_transparency_log_fetch_batch(from_id bigint, batch_size integer)": {
   "executableBy": [
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_transparency_log_fetch_boundary(before_id bigint)": {
   "executableBy": [
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_transparency_log_fetch_by_artifact_id(target_artifact_id character varying)": {
   "executableBy": [
    "qodiqa_reporting"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_transparency_log_fetch_by_entry_hash(target_hash character)": {
   "executableBy": [],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_transparency_log_fetch_by_transparency_id(target_id uuid)": {
   "executableBy": [
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_transparency_log_fetch_hashes_in_range(seq_from bigint, seq_to bigint)": {
   "executableBy": [
    "qodiqa_app",
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_transparency_log_fetch_range_full(from_id bigint, to_id bigint)": {
   "executableBy": [
    "qodiqa_reporting"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_transparency_log_latest_entry()": {
   "executableBy": [
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_transparency_log_read_all()": {
   "executableBy": [
    "qodiqa_reporting"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "ownerSuper": false
  },
  "qodiqa_transparency_public_entry(target_id uuid)": {
   "executableBy": [
    "qodiqa_app"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "new": true,
   "ownerSuper": false
  },
  "qodiqa_transparency_public_entry_by_hash(target_hash character)": {
   "executableBy": [
    "qodiqa_app"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "new": true,
   "ownerSuper": false
  },
  "qodiqa_transparency_public_list(p_entry_type text, p_artifact_id text, p_signer_key_id text, p_start timestamp with time zone, p_end timestamp with time zone, p_limit integer, p_offset integer, p_desc boolean)": {
   "executableBy": [
    "qodiqa_app"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "new": true,
   "ownerSuper": false
  },
  "qodiqa_transparency_public_hashes_from_id(from_id bigint, max_rows integer)": {
   "executableBy": [
    "qodiqa_app"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "new": true,
   "ownerSuper": false
  },
  "qodiqa_evidence_public_lookup(target_artifact_id character varying, claimed_tenant_id text)": {
   "executableBy": [
    "qodiqa_app"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "new": true,
   "ownerSuper": false
  },
  "qodiqa_erase_subject(p_tenant_id text, p_actor_id text, p_pseudonym text, p_batch integer)": {
   "executableBy": [
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "new": true,
   "ownerSuper": false
  },
  "qodiqa_erase_subject_finalize(p_request_id uuid, p_tenant_id text, p_actor_id text, p_pseudonym text, p_subject_ref text, p_run_id uuid, p_result jsonb, p_event_actor text, p_event_detail text, p_event_checksum text)": {
   "executableBy": [
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "new": true,
   "ownerSuper": false
  },
  "qodiqa_erasure_subject_candidates()": {
   "executableBy": [
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "new": true,
   "ownerSuper": false
  },
  "qodiqa_erasure_ledger_list(p_after_id bigint, p_limit integer)": {
   "executableBy": [
    "qodiqa_reporting",
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "new": true,
   "ownerSuper": false
  },
  "qodiqa_request_trails_by_ids(p_request_id uuid, p_artifact_id text)": {
   "executableBy": [
    "qodiqa_reporting"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "new": true,
   "ownerSuper": false
  },
  "qodiqa_audit_chain_decisions(p_artifact_ids text[])": {
   "executableBy": [
    "qodiqa_reporting"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "new": true,
   "ownerSuper": false
  },
  "qodiqa_audit_chain_mirror_count()": {
   "executableBy": [
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "new": true,
   "ownerSuper": false
  },
  "qodiqa_audit_chain_mirror_count_check()": {
   "executableBy": [
    "qodiqa_system"
   ],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "new": true,
   "ownerSuper": false
  },
  "qodiqa_audit_chain_mirror_count_rebuild()": {
   "executableBy": [],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "new": true,
   "ownerSuper": false
  },
  "qodiqa_audit_chain_mirror_count_on_insert()": {
   "executableBy": [],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "new": true,
   "ownerSuper": false
  },
  "qodiqa_audit_chain_mirror_count_on_delete()": {
   "executableBy": [],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "new": true,
   "ownerSuper": false
  },
  "qodiqa_audit_chain_mirror_count_on_truncate()": {
   "executableBy": [],
   "ownerBypassRls": true,
   "publicExecute": false,
   "searchPathSet": true,
   "new": true,
   "ownerSuper": false
  }
 },
 "policies": [
  {
   "table": "tenants",
   "name": "tenants_isolation",
   "cmd": "SELECT",
   "rule": "tenant_id = current_setting('qodiqa.tenant_id', true) — zero rows without context"
  },
  {
   "table": "organizations",
   "name": "orgs_admin_select",
   "cmd": "SELECT",
   "rule": "organization_id = (tenant's organization under current_setting('qodiqa.tenant_id', true)) — zero rows without context"
  },
  {
   "table": "tenants",
   "name": "tenants_admin_write",
   "cmd": "ALL",
   "rule": "false (writes only by the owner/migrator, which bypasses RLS) — replaces the dead-role predicate"
  },
  {
   "table": "organizations",
   "name": "orgs_admin_write",
   "cmd": "ALL",
   "rule": "false (as above)"
  },
  {
   "table": "control_plane_records",
   "name": "control_plane_records_control",
   "cmd": "ALL"
  }
 ]
}
```
