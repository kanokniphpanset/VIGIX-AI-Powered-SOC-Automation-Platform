# Results (draft for the paper)

Labels: **MEASURED RESULT** = a value read from the recorded data; **INTERPRETATION** = what the value supports; **LIMITATION** = what it does not support.

## 1. Evaluation setup

**MEASURED RESULT.** Ten predefined test cases (TC-01…TC-10) were evaluated on a Real Wazuh pipeline: a Wazuh 4.9.2 manager/indexer with an agent on an isolated Ubuntu endpoint produced the alerts; VIGIX ingested each alert, investigated it, generated an AI recommendation (self-hosted vLLM model vllm-spark-01/gemma4-26b-uncensored) that was validated deterministically, sent through a scripted SOC/IR decision, followed by a simulated manual response and a real re-hunt of the Wazuh Indexer. Nine cases were evaluable; TC-05 (PowerShell) needs a Windows endpoint that does not exist and was not simulated. A Clean Run (no corrections allowed) and an Intervention Run (analyst IOC correction when a recommendation was blocked) were executed. Three additional conditions were measured on a cloned database: a controlled procedural baseline, recommendation consistency and negative validation.

**LIMITATION.** Only TC-01, TC-04 and TC-06 use stock Wazuh rules; TC-02, TC-07, TC-09 and TC-10 depend on custom rules written for the evaluation, and TC-03, TC-07, TC-08 and TC-09 use harness-generated telemetry. SOC and IR steps are scripted API calls. The evaluation was conducted on 10 predefined test cases and does not represent all SOC situations.

## 2. Main results

**MEASURED RESULT.** In the Clean Run, 7 of 7 validated recommendations satisfied all six deterministic compliance criteria (Recommendation Compliance = 100% among evaluated recommendations; 77.78% = 7/9 among attempted cases, because TC-03 and TC-08 produced no valid recommendation). Playbook Alignment and Policy Compliance were 7/7, Evidence Coverage was 7/9 attempted cases (77.78%), and Workflow Completion was 5/9 (55.56%). Investigation Time had a mean of 40.27 s (median 33.79, SD 26.61, min 22.32, max 98.12; n = 7), Detection-to-Response measured from VIGIX ingest had a mean of 40.39 s (n = 7). The Intervention Rate was 0% and 2 of 9 cases needed at least one retry (total retry count 10). In the Intervention Run, Recommendation Compliance was 9/9, Workflow Completion 7/9 (77.78%), Investigation Time mean 72.23 s (n = 9), and 2 of 9 cases required an analyst correction.

**INTERPRETATION.** Whenever the pipeline produced a recommendation that passed validation, that recommendation met the deterministic criteria; the failures of the pipeline were cases in which no recommendation could be validated (an e-mail and a process/command indicator that were not actionable evidence) or in which the follow-up re-hunt could not run. The validator blocked rather than guessed.

**LIMITATION.** Recommendation Compliance is a conformance score against a fixed ground truth, not accuracy. The 100% figure excludes the two blocked cases and the Intervention result includes analyst corrections; the playbook-alignment figure was obtained after a selector tie-break defect (TC-09) had been found and fixed in the first real run. One run per condition; no confidence intervals are computed.

## 3. Baseline comparison

**MEASURED RESULT.** A controlled procedural baseline (evidence collection from the same Wazuh alert with the same deterministic indicator extractor, playbook lookup from the alert-declared MITRE techniques, and a static plan of every applicable playbook action) produced a proposed response for 9 of 9 cases, all aligned with the expected playbook (9/9) and inside the allowed action set (9/9), with a mean of 2.78 actions per plan. Its procedure latency was 0.013 s on average (median 0.01, SD 0.009, n = 9) compared with 40.27 s (n = 7) for VIGIX in the Clean Run and 72.23 s (n = 9) in the Intervention Run. Baseline decision latency was not measured (NULL).

**INTERPRETATION.** On the criteria that both conditions can be scored on, a static playbook lookup reaches the same conformance as VIGIX and is far faster as a machine procedure, and it produced a plan in the two cases where VIGIX's validator produced none. What the baseline does not provide is the AI analysis and instruction text, or the deterministic gates that VIGIX applies before a recommendation is trusted (evidence-linked or analyst-confirmed targets); the baseline treats every extracted indicator as confirmed.

**LIMITATION.** The baseline is not a human study and says nothing about analyst performance or real-world response time; its latency excludes any human reaction time and any LLM stage, so it must not be read as a speed-up or as evidence for or against VIGIX. Evidence and indicator counts, policy compliance, approval correctness and verification are not compared because the procedures are not comparable.

## 4. Recommendation consistency

**MEASURED RESULT.** With the same evidence snapshot (identical context hash in every repetition) and 5 repetitions per case, pooled Recommendation Consistency was 96.67% (29/30 runs; per-case mean 96.67%, SD 8.16 percentage points across 6 cases). Per case: TC-01 5/5, TC-02 5/5, TC-04 5/5, TC-06 5/5, TC-07 4/5, TC-09 5/5. Agreement on the complete set of validated steps (not only the primary one) was 86.67% pooled (TC-01 100%, TC-02 100%, TC-04 40%, TC-06 100%, TC-07 100%, TC-09 80%). All 30 runs produced a validated recommendation. 10 calls failed because the LLM endpoint was unreachable (a 120 s timeout followed by connection errors) and were excluded from the denominator, listed in consistency.json and repeated after the endpoint returned. Of 26 IP-blocking steps in the repeated runs, 1 (TC-09#2 ACT-BLOCK-DESTINATION-IP) was aimed at the endpoint's own address, which the six criteria cannot detect.

**INTERPRETATION.** The values show how stable the validated primary recommendation is when only the AI stage varies; because the validator constrains actions and targets to recorded evidence, variation is confined to which allowed action or target the model ranks first.

**LIMITATION.** One model, one provider, one day, representative cases only; earlier recommendations were hidden from the context to reproduce first-round generation; consistency is not correctness and says nothing about other models or attack types.

## 5. Negative validation

**MEASURED RESULT.** 10 of 10 controlled invalid recommendations were rejected (Unsupported Recommendation Rejection Rate = 100%; Policy-derived rules rejected 2 scenarios (NEG-03, NEG-04: responsible role, approval waiver) and validator knowledge/grounding rules rejected 8; NEG-02 was expected at the Policy layer but the required evidence (COMMAND_LINE for ACT-KILL-PROCESS) comes from the Action's own knowledge, not from an ACTION_COMPLIANCE policy, so it was rejected at the validator layer — the layer expectation was mis-specified, the rejection itself occurred), each with the expected violation code and each after a positive control showed the unmodified candidate was accepted. In the human-decision checks, an IR rejection moved the ticket to PENDING_MANUAL_DECISION without any execution and without closing the incident; approvals by the SOC role, an AI role or an administrator were denied; starting a response before approval, re-hunting before completion and marking an incident RESOLVED manually were blocked (17/17 checks passed).

**INTERPRETATION.** The deterministic validation and human-decision gates behave as specified for the injected faults: the AI cannot approve, execute or resolve, and an unsupported recommendation does not become a response ticket.

**LIMITATION.** The scenarios were written by the evaluator, contain one fault each and test rule coverage; a 10/10 rejection rate is expected of a deterministic rule set and is not an estimate of how often the AI proposes unsupported actions (in the Clean Run the validator rejected the AI's own output in 10 generation calls). Only one incident and one reject path were exercised.

## 6. Verification results

**MEASURED RESULT.** Real re-hunt outcomes for completed (simulated) responses were 5 RESOLVED and 2 ERROR in the Clean Run and 7 RESOLVED and 2 ERROR in the Intervention Run; the ERROR cases (TC-02, TC-10) had no searchable IOC. Verification/Re-hunt Time had a mean of 0.03 s (n = 5) and 0.03 s (n = 7). In the recurrence control, repeating the TC-01 attack after the response produced 29 matching events, iocRecurrence = true, result NOT_RESOLVED; the incident stayed investigating and Investigation #2 was opened.

**INTERPRETATION.** RESOLVED means the verification procedure did not detect the specified recurrence condition within the tested verification window. The control shows that the procedure is able to detect a recurring indicator.

**LIMITATION.** RESOLVED is not proof of eradication or containment: responses were simulated, each attack ran once, and only IP, domain, URL and hash indicators can be searched (the TC-08 verification searched only the command-line's domain). The sensitivity control is a single case with a single indicator type.

## 7. Observed failure and intervention cases

**MEASURED RESULT.** TC-03 (phishing): the sender e-mail was extracted but not actionable, so `ACT-QUARANTINE-EMAIL` was rejected on every attempt (5 failed generation calls in the Clean Run); an analyst confirmation of the indicators produced a compliant recommendation. TC-08 (suspicious process): the process and command line were not extracted from the auditd-style fields, so `ACT-KILL-PROCESS` (which requires COMMAND_LINE evidence) was blocked; analyst-added indicators unblocked it. TC-02 and TC-10 produced compliant recommendations but could not be verified (no hash/file or host-searchable indicator). TC-07: one step targeted the endpoint's own address and was still counted as evidence-supported.

**INTERPRETATION.** The observed failures concern evidence extraction and verification scope, not the validator's gating, which prevented recommendations without recorded evidence.

**LIMITATION.** These are properties of the tested extractor and rules; they were recorded, not repaired, during the Clean Run.

## 8. Limitations

The evaluation uses 10 predefined cases (9 evaluable), one run per condition for the Real Wazuh results, one LLM (vllm-spark-01/gemma4-26b-uncensored on a self-hosted vLLM server; an earlier internal note naming OpenRouter was wrong and is corrected in CORRECTIONS.md), scripted SOC/IR actors, simulated responses, harness-generated telemetry for four cases and custom rules for four cases. Time-to-Decision (≈0.06 s) is the latency of a scripted approval and is not a human decision time; no baseline decision latency exists. Timing values include third-party LLM latency. The ML risk score table was empty and was not evaluated. No claim of statistical significance or generalisation beyond the tested cases is made.
