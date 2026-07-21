# TODO

## Outstanding

- [ ] Prevent URL linkification inside the hidden `json_string` cell from altering the JSON used by the record modal.

## Completed

- [x] Collapse findings link cells containing more than 10 links while retaining access to every link.

### Offline finding correlations

- [x] Add exact logical dataset contracts and conservative completeness handling for offline correlations.
- [x] Surface critical resources without effective deletion locks, gating absence conclusions on complete lock data.
- [x] Surface Azure Policy non-compliance, complete-inventory assignment gaps, and state/event evaluation failures.
- [x] Correlate security Advisor recommendations with Defender assessments.
- [x] Correlate public access with approved private endpoints across service datasets.
- [x] Surface privileged non-human identities and application credential-expiry concerns.
- [x] Build end-to-end public-IP, frontend, backend, route, and effective-NSG attack paths with source/destination-aware first-match and default-deny semantics.

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
