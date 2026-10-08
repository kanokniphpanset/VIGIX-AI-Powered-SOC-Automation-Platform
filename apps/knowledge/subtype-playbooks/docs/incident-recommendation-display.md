# Incident recommendation display

The incident AI/recommendation tab now displays the subtype draft automatically from linked incident alerts. It refreshes read-only every 30 seconds while mounted and when incident evidence changes. Fixture and yellow preview panels are removed from the incident page. Existing stored recommendations and tickets remain under History; historical rows are not deleted.

The current-case endpoint recomputes instead of reusing a shadow result without an evidence fingerprint. The generation service also adapts stored raw alerts into Evidence Contract v2 in memory.

The default requested generation mode is now enforce. Explicit off/shadow environment settings continue to select the existing behavior. Enforce refuses to generate legacy output if review, mapping, knowledge or catalog prerequisites fail; no review bypass is introduced. Failure remains INSUFFICIENT_EVIDENCE in the existing API contract, with the actual readiness reason in audit.

This does not apply migrations/seed, change the running process environment, create tickets, execute containment or introduce an ingestion-triggered persisted recommendation job. New linked alerts are reflected in the current-case draft when viewed. Persisted approved recommendations still require the existing generation and review workflow and deployable knowledge.

Implementation changes have not been tested, typechecked or evaluated, per user instruction.
