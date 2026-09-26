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
            ├── BRUTE_FORCE/      ✅ MVP
            ├── MALWARE/          ✅ MVP
            ├── RANSOMWARE/       ✅ MVP
            ├── ACCOUNT_COMPROMISE/  ⏳ not yet written
            ├── PHISHING/             ⏳ not yet written
            ├── WEB_ATTACK/           ⏳ not yet written
            └── LATERAL_MOVEMENT/     ⏳ not yet written
```

`knowledge/policies/` (assignment/approval/severity) from the fuller tree
you sketched isn't included here — that content already exists as
executable TypeScript (`policy/seeds/policy.seed.ts`), not YAML, so there's
nothing to duplicate into a parallel knowledge/ copy unless you want a
human-readable mirror of the same rules. Say the word and I'll generate one
from the seed file so the two never drift apart.

## Adding the next procedure (e.g. ACCOUNT_COMPROMISE)

1. `mkdir procedures/ACCOUNT_COMPROMISE`
2. Copy the 5-file shape from `BRUTE_FORCE/` (closest analog — both center
   on login/credential evidence) and rewrite each field's content.
3. Flip its `manifest.yaml` entry from `status: PLANNED` to `status: ACTIVE`.
4. No code changes needed — the Playbook Resolver reads `manifest.yaml`'s
   `procedures[]` list at runtime, so a new ACTIVE entry is picked up
   automatically once the files exist.
