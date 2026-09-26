# Wazuh Re-hunt integration — implementation and verification

## Timestamp acceptance follow-up (2026-09-24)

The authentication blockage described in the original report below has been resolved.
Live inspection found four indices with both `timestamp` and `@timestamp` date mappings:
189 documents populate both, while the existing IOC test alert populates only `@timestamp`.
The previous wildcard field-capability check verified that `timestamp` was mapped, but
did not prove that each document populated it. Filtering only on that field silently
excluded the known IOC.

Default timestamp selection now uses the Wazuh `timestamp` event time when populated,
and falls back to `@timestamp` only when `timestamp` is absent. A document with both
fields is not counted twice and its secondary timestamp cannot pull it into a window
outside its primary event time. Each branch uses the caller's exact inclusive bounds.
Returned evidence uses the same priority. The adapter validates date mappings for each
concrete index, not just the merged wildcard field capabilities. Conflicting types or
indices without a supported time field fail with QUERY_FAILED.

An IOC-matching document missing every supported time field is included only to detect
incomplete timestamp coverage: the missing_timestamp aggregation then makes the query
fail, even if that document is outside the returned sample. It never becomes MATCH or
NO_MATCH evidence. No lookback or artificial timestamp is introduced.

Leave `WAZUH_REHUNT_TIMESTAMP_FIELD` unset for automatic fallback; the backend example
now leaves it blank. An explicitly supplied field remains a deliberate single-field
restriction, with the same coverage checks. No real environment file or provider setting
was changed. ISiemRehuntPort, MockRehuntAdapter and business workflows are unchanged.

Validation after the fix:

- Backend tests: 301 tests passed in 15 suites. The full command still exits 1 only
  because the pre-existing Approval.integration.test.ts file is empty. Typecheck passed.
- Live MATCH without any timestamp override: data.srcip `10.10.10.50`, 1 event,
  source WAZUH_INDEXER, matchedIocValues contains that IP, normalized time
  `2026-09-22T08:31:02.6065047Z`.
- Live NO_MATCH without any timestamp override: `203.0.113.254`, 0 events,
  source WAZUH_INDEXER, empty matched IOC values, with the same original rule supplied.
- Both tests used exact bounds `2026-09-22T07:31:02.606Z` through
  `2026-09-22T09:31:02.606Z`, against existing data in wazuh-alerts-4.x-*.
  The positive event is the pre-existing indexed test alert mock-not-resolved-001,
  not a claim of a production threat. No events were inserted or changed.
- An initial live attempt returned TIMEOUT during concurrent local checks; the retry
  passed without timeout or timestamp configuration changes. Errors remained errors.
- Timestamp coverage is sufficient for the four inspected indices and these acceptance
  cases. Switching the provider is the next separate step; REHUNT_PROVIDER remains mock.

The original inspection/acceptance report follows for historical context.

Verified 2026-09-24 (Asia/Bangkok). **Implementation delivered; live acceptance is blocked by authentication.**
No claim of completed real Wazuh Re-hunt: the configured account receives HTTP 401, so live mappings and MATCH/NO_MATCH have not been verified.

## Inspection and environment

The repository already contained ISiemRehuntPort, MockRehuntAdapter, WazuhIndexerAdapter,
RunRehuntVerificationUseCase, CreateVerificationUseCase, an authenticated re-hunt endpoint,
and a re-hunt health endpoint. The original real adapter used broad multi_match clauses,
allowed rule-only matching, lost transport timeout classification, did not identify individual
matching IOCs, and could normalize incomplete responses into zero matches. Its health check
did not execute a search. The mock imports its legacy DSL builder; that builder remains intact.

Docker inspection confirmed running single-node Wazuh manager, indexer, and dashboard images
at version **4.14.7**, with Indexer port **9200 published to Windows**. No backend container
appeared in the running Docker list. The host backend health endpoint at
`http://localhost:4000/api/v1/health` returned `status: ok`.

The backend's existing configuration specifies:

- HTTPS origin `https://localhost:9200`, HTTP Basic authentication.
- CA file `D:/soar-platform/wazuh-docker/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem`.
- TLS server name `wazuh.indexer`; certificate verification enabled.
- Configured index pattern `wazuh-alerts-4.x-*`; existence not authenticated/verified.
- Current application provider remains `mock`; no real `.env` was edited.

For a future backend container, localhost would refer to that container. Use the verified
compose service name `wazuh.indexer:9200` only after placing that backend on the same Docker
network and mounting the CA. No Docker networking was changed. The OpenSearch engine version
could not be read through the authenticated API.

## A. Files created

- `apps/backend/src/infrastructure/external-services/siem/WazuhRehuntAdapter.ts`
- `apps/backend/src/infrastructure/external-services/siem/createRehuntProvider.ts`
- `apps/backend/test/WazuhRehuntAdapter.test.ts`
- `apps/backend/scripts/check-wazuh-rehunt.ts`
- `docs/architecture/wazuh-rehunt-integration.md` (this report)

## B. Files modified for this request

- `apps/backend/src/infrastructure/external-services/siem/WazuhIndexerAdapter.ts`: reuse transport,
  validate complete responses, authenticate health searches, preserve request deadlines,
  normalize per-IOC named matches, support the configured event timestamp field.
- `apps/backend/src/infrastructure/config/container.ts`: use the provider factory at the existing injection point.
- `apps/backend/src/application/verification/ports/ISiemRehuntPort.ts`: correct the matchedIocValues comment only; no contract changes.
- `.env.example` and `apps/backend/.env.example`: documented configuration placeholders.

MockRehuntAdapter, verification use cases, controllers/routes, frontend, Policy, Approval,
Recommendation, ResponsePlan and Incident behavior were not edited for this request.
Existing unrelated workspace changes were retained. No database or Wazuh data was modified.

## C. Dependencies

None added. The project had no OpenSearch client dependency. The existing injectable Node
HTTPS transport is sufficient for read-only REST requests and avoids an additional client package.

## D. Environment

| Variable | Behavior |
|---|---|
| `REHUNT_PROVIDER` | `mock` or `wazuh`; examples select mock; unset retains existing real-provider default |
| `WAZUH_INDEXER_URL` | HTTPS origin, no embedded credentials |
| `WAZUH_INDEXER_USERNAME`, `WAZUH_INDEXER_PASSWORD` | Existing Basic credentials, never logged or sent to frontend |
| `WAZUH_INDEXER_CA_PATH` | Existing PEM trust anchor |
| `WAZUH_INDEXER_TLS_SERVERNAME` | Existing certificate hostname override |
| `WAZUH_INDEXER_INSECURE_TLS` | Existing dev option; not enabled in the verified environment |
| `WAZUH_INDEXER_INDEX_PATTERN` | New preferred index variable; existing `WAZUH_INDEX_PATTERN` remains fallback, then legacy `wazuh-alerts-4.x-*` default |
| `WAZUH_REHUNT_TIMEOUT_MS` | New positive per-request deadline; default 15000 ms |
| `WAZUH_REHUNT_IOC_FIELDS` | New optional JSON mapping from ip/domain/url/hash to exact searchable field arrays |
| `WAZUH_REHUNT_TIMESTAMP_FIELD` | New event-time field, default `timestamp`; override only according to actual mapping |

Example mapping override: `{"ip":["data.srcip","data.dstip"],"domain":["data.dns.question.name"]}`.
Omitted types keep adapter defaults. Field paths may not contain query syntax or wildcards.
No lookback variable was added: the existing use case already supplies response completion/update
time through the current time. Those bounds are used verbatim; no whole-database fallback.

## E. Provider selection

`createRehuntProvider(process.env)` returns MockRehuntAdapter for `mock`, otherwise
WazuhRehuntAdapter for `wazuh`/unset. Unknown names fail configuration rather than silently
choosing a provider. Mock selection does not require or parse live Wazuh settings.
RunRehuntVerificationUseCase continues to depend on ISiemRehuntPort.

## F. Query construction

1. Reject empty/unsupported IOC criteria and invalid or non-increasing time bounds.
2. Read `_field_caps` for configured IOC fields and the event-time field. Require searchable
   keyword/IP IOC mappings and a searchable date mapping; missing/incompatible mappings fail.
3. POST a structured bool/term search to the configured index pattern with exact date bounds,
   exact hit counts, named `ioc_N` clauses, a 20-event sample, host aggregation and IOC count.
4. Require complete shards, a non-timeout response, exact totals, valid hits and aggregations.
   Missing indices and partial search results are explicitly disallowed.
5. Normalize existing RehuntResult/RehuntEvent values, including matchedIocValues and source
   WAZUH_INDEXER. investigationNumber remains on the request and never selects real fixtures.

The real adapter requires an IOC match; it does not count an unrelated recurrence of the same
rule as an IOC MATCH. Legacy mock DSL/rule behavior is preserved. Input values are literal
terms, never query_string syntax. Exact matching is intentionally case-sensitive and does not
parse concatenated hash text (for example `MD5=...,SHA256=...`) as standalone hash values;
configure extracted hash keyword fields for that deployment.

Named query identifiers returned in matched_queries are documented by
[OpenSearch](https://docs.opensearch.org/latest/query-dsl/named-queries/). Mapping checks use the
[Field capabilities API](https://docs.opensearch.org/latest/api-reference/search-apis/field-caps/).
The default event-time field follows the Wazuh alert index convention documented under
[Wazuh indexer indices](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html).
Live mappings still require verification after authentication is repaired.

## G. Supported IOC types

- IP: source/destination decoder fields, including Windows network source/destination fields.
- Domain: DNS question, domain, and Windows DNS query name fields.
- URL: data.url and data.http.url.
- Hash: MD5/SHA1/SHA256/hash decoder fields and syscheck after-change hashes.

These are configurable candidate fields, not a claim that every decoder in this deployment
populates them. Live field-capability validation prevents entirely missing/incompatible mappings
from silently producing NO_MATCH. Full-log free text is not searched.

## H. Result and failure semantics

| Outcome | Existing contract |
|---|---|
| MATCH | matchingEvents > 0; IOC recurrence true; containment false; event/host evidence returned |
| NO_MATCH | Only a complete successful authenticated query with exact zero hits; containment evidence true |
| TIMEOUT | RehuntError TIMEOUT for deadline/socket timeout or server timed_out |
| ERROR | NOT_CONFIGURED, INSUFFICIENT_CRITERIA, UNREACHABLE or QUERY_FAILED as appropriate |

No new verification status model was introduced. Errors never return empty evidence. Existing
use cases still control verification persistence, new investigation/recommendation, escalation
and incident resolution. The adapter never approves, closes, isolates, blocks or executes endpoints.

## I. Tests

Command: `npm test --workspace=@soar-platform/backend -- --runInBand --silent`.

**288 tests passed: 252 existing tests plus 36 new tests. 15 suites passed.** MockRehuntAdapter,
RunRehuntVerification, CreateVerification, ResponseVerificationLoop and policy tests passed.

The full command exits 1 because the pre-existing `apps/backend/test/Approval.integration.test.ts`
is a zero-byte file: Jest reports “Your test suite must contain at least one test.” It was not
deleted, skipped, weakened or modified. Therefore this report does not label the overall suite green.

New coverage includes all four IOC types, multiple IOCs, named matches, literal injection strings,
empty/invalid types, provider selection, exact time bounds, field mappings, HTTP failures,
network/search/server timeouts, incomplete responses/shards and authenticated health searches.
The injected mock is the HTTP/OpenSearch transport boundary, not live Wazuh data.

## J. Typecheck

`npx tsc --noEmit -p apps/backend/tsconfig.json`: **passed**.

## K. Real connectivity

Executed `npx ts-node scripts/check-wazuh-rehunt.ts` from `apps/backend`, using the same dotenv
location and Node host environment as the backend. The probe uses a process-local real-provider
selection without changing `.env`.

Actual output: configured true, reachable false, indexPattern wazuh-alerts-4.x-*,
error **Indexer responded 401**. HTTPS transport and CA/hostname validation succeeded; Basic
authentication did not. The authenticated health search was not reached.

## L. Real MATCH / NO_MATCH

**Not verified.** Authentication prevents inspecting mappings, locating a known existing IOC,
or running an authenticated search. No events were fabricated, inserted or deleted.

After valid read-only Indexer access is configured, run the health probe, then from apps/backend:

```powershell
npx ts-node scripts/check-wazuh-rehunt.ts <type> <known-existing-ioc> <start-ISO> <end-ISO>
```

Use an IOC and time window from an existing event for MATCH. Verify NO_MATCH with an absent
IOC in the same explicit scope. The script prints actual outcome/count/event IDs without
credentials and never invokes the verification workflow or writes data.

## M. Remaining gaps

1. Valid read-only Indexer authentication is required; real `.env` remains untouched as requested.
2. Verify actual index existence, engine version and IOC/time mappings after auth succeeds.
3. Run genuine read-only MATCH and NO_MATCH acceptance checks against existing data.
4. Resolve the pre-existing empty Approval test suite before claiming the entire test command passes.
5. Production remains on the existing mock setting until the environment owner deliberately selects
   `REHUNT_PROVIDER=wazuh` after acceptance. No provider setting was silently activated.
