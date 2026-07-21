# TODO

## Outstanding

- [ ] Prevent URL linkification inside the hidden `json_string` cell from altering the JSON used by the record modal.

## Completed

- [x] Collapse findings link cells containing more than 10 links while retaining access to every link.

### Remove content redaction

- [x] Preserve collection-manifest context, options, parameters, command templates, limitations, and error content without credential or token replacement.
- [x] Retain only the 1,000-character collection-manifest endpoint error limit.
- [x] Preserve all report-ready engagement, finding, observation, reference-link, narrative, and analyst content without redaction or truncation.
- [x] Remove report-ready redaction metadata, warnings, blockers, and validation rules, with an explicit schema-version boundary.
- [x] Replace redaction tests with exact content-preservation and retained error-limit regression tests.
- [x] Update documentation to state that generated artefacts may contain sensitive content.
- [x] Run focused and full validation, search for residual redaction functionality, and complete a full changed-file review.

### Offline finding correlations

- [x] Add exact logical dataset contracts and conservative completeness handling for offline correlations.
- [x] Surface critical resources without effective deletion locks, and emit absence findings only when lock collection supports negative conclusions.
- [x] Surface Azure Policy non-compliance and complete-inventory assignment gaps; independently propagate policy-state and policy-event completeness into evaluation-failure conclusions.
- [x] Correlate security Advisor recommendations with Defender assessments.
- [x] Correlate public access with approved private endpoints across service datasets.
- [x] Surface privileged non-human identities and application credential-expiry concerns.
- [x] Build end-to-end public-IP, frontend, backend, route, and effective-NSG attack paths with destination-aware, source-set first-match processing, attached-NSG default-deny semantics, and no reachability finding for unknown decisions.

### Report-ready findings

- [x] Persist a versioned collection-run manifest containing endpoint completeness and dataset integrity metadata.
- [x] Reconcile stable finding IDs and add report definition metadata.
- [x] Normalise finding assets, observations, and provenance.
- [x] Add assessment coverage denominators.
- [x] Add analyst review disposition and confidence data.
- [x] Add family-specific Azure and engagement context.
- [x] Add grouping, contextual severity, deduplication, and retesting.
- [x] Generate report-ready JSON containing candidates by default.
- [x] Populate collection scope from the active Azure account when no subscription or tenant was supplied.
- [x] Attribute derived role datasets to their input collection endpoints.
- [x] Treat findings against incomplete baselines as inconclusive rather than new.
