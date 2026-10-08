# knowledge/

Data-only knowledge base for VIGIX's SOC processes — no executable logic,
consumed by `apps/backend/src/application/playbook/` and
`.../recommendation/` at runtime (parse + read, never eval).

```
knowledge/
└── playbooks/
    └── PB-STC-001/
        ├── manifest.yaml     # playbook identity + 7 phases + procedure index
        ├── playbook.md       # human-readable doc (read this first)
        └── procedures/
            ├── BRUTE_FORCE/                   ✅ MVP            (TC-01)
            ├── MALWARE/                       ✅ MVP            (TC-02)
            ├── RANSOMWARE/                    ✅ MVP
            ├── PHISHING/                      ✅                (TC-03)
            ├── ACCOUNT_COMPROMISE/            ✅                (TC-04)
            ├── POWERSHELL/                    ✅                (TC-05)
            ├── SQL_INJECTION/                 ✅                (TC-06)
            ├── COMMAND_AND_CONTROL/           ✅                (TC-07)
            ├── SUSPICIOUS_PROCESS_EXECUTION/  ✅                (TC-08)
            ├── DATA_EXFILTRATION/             ✅                (TC-09)
            ├── PRIVILEGE_ESCALATION/          ✅                (TC-10)
            ├── WEB_ATTACK/                    ⏳ not yet written
            └── LATERAL_MOVEMENT/              ⏳ not yet written
```

`knowledge/policies/` (assignment/approval/severity) from the fuller tree
you sketched isn't included here — that content already exists as
executable TypeScript (`policy/seeds/policy.seed.ts`), not YAML, so there's
nothing to duplicate into a parallel knowledge/ copy unless you want a
human-readable mirror of the same rules. Say the word and I'll generate one
from the seed file so the two never drift apart.

## Containment procedure → Recommendation

Each procedure is the attack-specific containment strategy the Recommendation
is built from (backend `ContainmentProcedureLoader` → RecommendationContext →
prompt → `RecommendationValidator`):

| File | Holds |
|---|---|
| `procedure.yaml` | `objective`, `strategy` |
| `steps.yaml` | ordered steps; each `recommendedAction` item is **ACTION** `(see containment.yaml: ACT-…)`, **MANUAL** `(manual - outside the VIGIX Action Catalog[; requires <who> approval])` or **CHECK** (anything else) |
| `containment.yaml` | candidate Actions (= the DB playbook's `allowedActions`) with the `condition` IR must confirm |
| `decisions.yaml` | human decision points (`stepRef` = the step carrying the `decisionRef`) |
| `verification.yaml` | re-hunt template + `successCriteria` |

The DB playbook stays the authority for identity and `allowedActions`; the
YAML procedure is the authority for strategy, order, conditions and
verification. CHECK and MANUAL steps are never executable Actions and never
become Response Tickets. Checks (identify, check login, monitor) are never
added to the Action Catalog.

## Adding the next procedure (e.g. ACCOUNT_COMPROMISE)

1. `mkdir procedures/ACCOUNT_COMPROMISE`
2. Copy the 5-file shape from `BRUTE_FORCE/` (closest analog — both center
   on login/credential evidence) and rewrite each field's content.
3. Flip its `manifest.yaml` entry from `status: PLANNED` to `status: ACTIVE`.
4. No code changes needed — the Playbook Resolver reads `manifest.yaml`'s
   `procedures[]` list at runtime, so a new ACTIVE entry is picked up
   automatically once the files exist.

## Subtype-level knowledge (v2.0.0) — `subtype-playbooks/`

Layer ใหม่ (แยกจาก `playbooks/PB-STC-001`, ไม่แตะ runtime เดิม) ที่แตก 10 attack families เป็น **50 subtypes** พร้อม Playbook → Policy (predicate ตรวจได้) → Runbook (ขั้นตอนลงมือ) → Recommendation contract
เอกสารเริ่มต้น: [subtype-playbooks/README.md](subtype-playbooks/README.md) · ตรวจ: `node apps/knowledge/subtype-playbooks/tools/validate.mjs`
