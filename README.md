# Agentic Synthetic Attack Log Workflow

An agentic detection-engineering workflow for generating, reviewing, and refining synthetic Google SecOps UDM JSON events.

This project adapts the workflow described in Microsoft Defender Security Research's [AI-assisted synthetic attack log generation](https://www.microsoft.com/en-us/security/blog/2026/05/12/accelerating-detection-engineering-using-ai-assisted-synthetic-attack-logs-generation/) article to Google SecOps, YARA-L detections, and UDM-shaped telemetry.

The purpose is not to recreate real logs byte-for-byte. The purpose is to produce semantically correct synthetic telemetry that helps detection engineers test whether a rule, query, or analytic idea behaves as expected before deeper environment-specific validation.

## What This Solves

High-quality malicious telemetry is hard to collect safely and repeatedly. Real attack logs can be rare, sensitive, incomplete, expensive to reproduce, or tied to lab environments that take time to maintain.

Synthetic UDM events help with early detection-engineering work by making it faster to:

- Convert attacker behavior, TTPs, and detection ideas into structured telemetry.
- Build positive test cases for YARA-L detections.
- Build negative and edge-case test cases.
- Exercise joins, thresholds, match windows, regex predicates, and field constraints.
- Review telemetry assumptions before attempting tenant-specific validation.

Synthetic logs are not evidence of compromise and are not a replacement for lab validation. They are controlled test inputs for detection design, tuning, and coverage exploration.

## Research Pattern

The Microsoft article describes three approaches to synthetic attack log generation:

- Prompt-engineered generation: structured prompting, iterative generation, and independent LLM-as-judge evaluation.
- Agentic workflow-based generation: specialized generator, evaluator, and improver agents collaborate in a generate, evaluate, and improve loop.
- Reinforcement learning with verifiable rewards: reward-guided refinement against labeled ground-truth logs.

This project implements the agentic workflow pattern in a smaller two-agent form:

- The **Log Generator Agent** creates draft synthetic UDM JSON events.
- The **Log Review Agent** combines evaluator and improver responsibilities by reviewing, correcting, and preparing events for validation.

## Agentic Workflow

<img width="1672" height="941" alt="image" src="https://github.com/user-attachments/assets/c6677c71-f1fc-4ad2-b523-4f18a64a9cd1" />


## Log Generator Agent

The Log Generator Agent converts either:

- A Google SecOps YARA-L detection query.
- A natural-language attack pattern, TTP, or attacker action.

into synthetic Google SecOps UDM JSON.

Responsibilities:

- Classify the input as a YARA-L query or natural-language attack pattern.
- Parse event variables, field constraints, joins, timestamp ordering, match windows, thresholds, regexes, and reference-list assumptions.
- Identify likely log sources, UDM event types, entities, and relevant ATT&CK behavior.
- Generate the minimum positive event set that should satisfy the detection.
- Generate negative or edge-case scenarios when useful.
- Preserve ordering, parent-child relationships, correlation keys, and threshold counts.
- Output UDM-shaped JSON, not raw vendor logs.

Default generator output shape:

```json
{
  "format": "google_secops_udm_json",
  "generated_for": {
    "input_type": "yaral_detection_query",
    "purpose": "positive_detection_test"
  },
  "assumptions": [],
  "scenarios": [
    {
      "name": "positive_trigger",
      "expected_result": "alert",
      "events": []
    }
  ]
}
```

## Log Review Agent

The Log Review Agent treats generated logs as draft telemetry, not trusted truth.

Responsibilities:

- Identify invalid JSON, raw-log leakage, non-UDM structures, and events encoded as strings.
- Verify that detection field paths exist in the generated events.
- Check timestamp ordering and match-window constraints.
- Check equality joins, inequality joins, aggregation thresholds, and distinct counts.
- Confirm regex predicates match the generated values.
- Review semantic realism for users, hosts, processes, SaaS audit events, cloud audit events, network activity, and security results.
- Correct UDM JSON while preserving the generator's intent.
- Distinguish scenario-wrapper readiness from ingestion API payload readiness.
- Call out parser, log type, reference-list, and tenant-specific validation assumptions.

Default review output shape:

```json
{
  "format": "google_secops_udm_json",
  "review_status": "corrected",
  "generated_for": {
    "input_type": "log_generator_agent_output",
    "purpose": "detection_validation"
  },
  "assumptions": [],
  "scenarios": [
    {
      "name": "positive_trigger",
      "expected_result": "alert",
      "events": []
    }
  ]
}
```

If an ingestion payload is explicitly requested, the review agent can produce:

```json
{
  "customer_id": "<CUSTOMER_ID>",
  "events": []
}
```

## Usage

### Starting From A YARA-L Rule

```text
Use the Log Generator Agent for this YARA-L detection.

Generate:
- one positive trigger scenario
- one negative control scenario
- compact Google SecOps UDM JSON only

<paste YARA-L rule here>
```

Then send the generator output and the original rule to the review agent:

```text
Use the Log Review Agent.

Review and correct this synthetic UDM output against the original YARA-L rule.
Call out detection satisfaction, UDM shape issues, and ingestion readiness.

<paste original YARA-L rule>
<paste generator output>
```

### Starting From An Attack Behavior

```text
Use the Log Generator Agent.

Generate synthetic Google SecOps UDM JSON for this attacker behavior:

<describe the TTP or attacker action>

Include schema assumptions and a validation checklist.
```

Then review:

```text
Use the Log Review Agent.

Check semantic fidelity, UDM realism, timestamp ordering, correlation keys,
and whether the corrected output is ready as a scenario wrapper or ingestion payload.

<paste generator output>
```

## Validation Checklist

Before using generated events for detection validation, confirm:

- The JSON parses successfully.
- Every event is UDM-shaped.
- Every event has `metadata.event_timestamp`.
- Every event has a plausible `metadata.event_type`.
- Known products include `metadata.vendor_name` and `metadata.product_name`.
- YARA-L field paths referenced by the rule exist in the events.
- Equality joins use consistent values.
- Inequality joins intentionally use different values.
- Timestamp ordering matches the detection logic.
- Events fall inside the match window.
- `count > N` and `count_distinct > N` conditions have at least `N + 1` matching events.
- Regex predicates actually match the generated values.
- Reference-list assumptions are explicitly documented.
- Positive tests avoid allowlist and exclusion conditions.
- Negative tests change one control variable at a time.
- No real employee names, corporate domains, public infrastructure, secrets, tokens, passwords, or private keys are introduced.
- The output is clearly labeled as either scenario-wrapper documentation or an ingestion API payload.

## UDM Requirements

Generated and corrected events must be Google SecOps UDM JSON.

Use UDM sections such as:

- `metadata`
- `principal`
- `target`
- `src`
- `observer`
- `intermediary`
- `about`
- `network`
- `security_result`
- `additional.fields`
- `extracted.fields`

Do not use final outputs made of:

- Raw Windows Event XML
- Raw Sysmon XML
- Raw SaaS audit-log JSON
- Raw Git provider audit-log JSON
- Syslog strings
- CSV rows
- Prose-only examples
- Event objects encoded as strings

Vendor-specific values may appear inside UDM-compatible fields when needed for detection fidelity.

## Safety Scope

This workflow is for authorized defensive work:

- Detection engineering
- SOC validation
- Purple-team coverage testing
- Rule regression testing
- Telemetry gap analysis

Do not use this workflow to provide instructions for unauthorized compromise, credential theft, malware deployment, control bypass, or real-world exploitation. Potentially dangerous behavior should be represented only as synthetic telemetry values when needed to test a detection.

## Limitations

Synthetic telemetry is useful, but it is not ground truth.

Known limitations:

- Synthetic UDM may not match tenant-specific parser output exactly.
- Google SecOps ingestion paths may assign or normalize fields differently than expected.
- Rules that depend on raw-parser `metadata.log_type` values may not behave the same when events are sent through a UDM ingestion path.
- Reference lists, allowlists, baselines, parser extensions, and environment-specific fields must be validated in the target tenant.
- Passing a synthetic test does not prove that a detection will catch every real-world variant.

