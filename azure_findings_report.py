# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generate a compact report-ready findings export."""

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


REPORT_READY_SCHEMA_VERSION = "2.0"
INCLUDED_DISPOSITIONS = [
    "candidate",
    "confirmed",
    "accepted_risk",
    "informational",
]
SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
    "Unknown": 5,
}


def utc_timestamp() -> str:
    """Return a timezone-aware UTC timestamp for the export envelope."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00",
        "Z",
    )


def canonical_observations(finding: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Emit one canonical observation from every exact duplicate set."""
    duplicate_ids = {
        observation_id
        for duplicate_set in finding.get("triage", {})
        .get("deduplication", {})
        .get("duplicate_sets", [])
        for observation_id in duplicate_set.get("duplicate_observation_ids", [])
    }
    observations = []
    for observation in finding.get("reporting", {}).get("observations", []):
        if observation.get("observation_id") in duplicate_ids:
            continue
        observations.append(
            {
                "observation_id": observation.get("observation_id"),
                "summary": observation.get("summary"),
                "asset_ids": list(observation.get("asset_ids", [])),
                # Report records must preserve evidence exactly, including values
                # which resemble credentials or signed resource URLs.
                "data": deepcopy(observation.get("data", {})),
                "source_files": list(observation.get("source_files", [])),
                "reference_links": deepcopy(
                    observation.get("reference_links", [])
                ),
            }
        )
    return observations


def publication_readiness(finding: Mapping[str, Any]) -> Dict[str, Any]:
    """Separate workflow selection from readiness to publish a report finding."""
    blockers = []
    warnings = []
    review = finding.get("review", {})
    report = finding.get("definition", {}).get("report", {})
    if finding.get("status") != "found":
        blockers.append("positive_finding_not_detected")
    if review.get("review_state") != "reviewed":
        blockers.append("analyst_review_required")
    required_narrative_fields = ("description", "impact", "recommendation")
    if report.get("narrative_status") != "authored" or any(
        not report.get(key) for key in required_narrative_fields
    ):
        blockers.append("report_narrative_not_authored")
    confidence = review.get("confidence", {}).get("level")
    if confidence in {"low", "not_assessed", None}:
        blockers.append("evidence_confidence_insufficient")
    if finding.get("coverage", {}).get("status") != "proxy":
        blockers.append("assessment_coverage_unavailable")
    provenance = finding.get("reporting", {}).get("provenance", {})
    if provenance.get("limitations"):
        warnings.append("evidence_provenance_has_limitations")
    retest = finding.get("triage", {}).get("retest", {})
    if retest.get("comparison_status") == "compared" and retest.get("outcome") in {
        "inconclusive",
        "scope_changed",
        "same_run",
    }:
        warnings.append("retest_requires_attention")
    if review.get("disposition") == "candidate":
        warnings.append("candidate_included_by_default")
    return {
        "ready_for_publication": not blockers,
        "blockers": sorted(set(blockers)),
        "warnings": sorted(set(warnings)),
    }


def finding_limitations(finding: Mapping[str, Any]) -> List[Dict[str, str]]:
    """Retain subsystem attribution for limitations used during report drafting."""
    limitations = []
    sources = {
        "provenance": finding.get("reporting", {})
        .get("provenance", {})
        .get("limitations", []),
        "context": finding.get("context", {}).get("limitations", []),
        "coverage": finding.get("coverage", {}).get("limitations", []),
    }
    for source, values in sources.items():
        for value in values:
            if value:
                limitations.append({"source": source, "detail": str(value)})
    return sorted(
        limitations,
        key=lambda item: (item["source"], item["detail"].casefold()),
    )


def report_finding(finding: Mapping[str, Any]) -> Dict[str, Any]:
    """Build one selected report-facing finding without legacy raw evidence."""
    definition = finding.get("definition", {})
    review = finding.get("review", {})
    triage = finding.get("triage", {})
    deduplication = triage.get("deduplication", {})
    observations = canonical_observations(finding)
    record = {
        "finding_id": finding.get("finding_id"),
        "definition": {
            "definition_version": definition.get("definition_version"),
            "title": definition.get("report_title"),
            "category": definition.get("category"),
            "check_ids": list(definition.get("check_ids", [])),
        },
        "report": deepcopy(definition.get("report", {})),
        "evaluation": {
            "status": finding.get("status"),
            "reason": finding.get("reason"),
        },
        "workflow": {
            "selection": deepcopy(review.get("report_ready", {})),
            "review_state": review.get("review_state"),
            "disposition": review.get("disposition"),
            "confidence": deepcopy(review.get("confidence", {})),
            "analyst": deepcopy(review.get("analyst", {})),
            "publication": publication_readiness(finding),
        },
        "severity": deepcopy(triage.get("severity", {})),
        "context": deepcopy(finding.get("context", {})),
        "coverage": deepcopy(finding.get("coverage", {})),
        "affected_assets": deepcopy(
            finding.get("reporting", {}).get("assets", [])
        ),
        "evidence": {
            "original_observation_count": deduplication.get(
                "original_observation_count"
            ),
            "emitted_observation_count": len(observations),
            "duplicate_observation_count": deduplication.get(
                "duplicate_observation_count"
            ),
            "observations": observations,
            "duplicate_sets": deepcopy(deduplication.get("duplicate_sets", [])),
        },
        "provenance": deepcopy(
            finding.get("reporting", {}).get("provenance", {})
        ),
        "grouping": deepcopy(triage.get("grouping", {})),
        "fingerprint": deepcopy(triage.get("fingerprint", {})),
        "retest": deepcopy(triage.get("retest", {})),
        "limitations": finding_limitations(finding),
    }
    return record


def report_sort_key(finding: Mapping[str, Any]) -> Tuple[Any, ...]:
    """Sort selected findings into stable report sections and severity order."""
    record = finding.get("triage", {})
    severity = record.get("severity", {}).get("contextual", "Unknown")
    return (
        record.get("grouping", {}).get("report_group_id", ""),
        SEVERITY_ORDER.get(severity, 99),
        str(finding.get("title") or "").casefold(),
        str(finding.get("finding_id") or ""),
    )


def count_by(values: Iterable[Any]) -> Dict[str, int]:
    """Return deterministic string-keyed counts for report summaries."""
    counts = {}
    for value in values:
        key = str(value or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: item[0].casefold()))


def report_groups(findings: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Aggregate selected findings under their stable report group identities."""
    groups = {}
    for finding in findings:
        grouping = finding.get("triage", {}).get("grouping", {})
        group_id = grouping.get("report_group_id")
        group = groups.setdefault(
            group_id,
            {
                "report_group_id": group_id,
                "dimensions": deepcopy(grouping.get("dimensions", {})),
                "finding_ids": [],
            },
        )
        if group["dimensions"] != grouping.get("dimensions", {}):
            raise ValueError("Report group ID has conflicting dimensions")
        group["finding_ids"].append(finding.get("finding_id"))
    for group in groups.values():
        group["finding_ids"] = sorted(group["finding_ids"])
    return sorted(groups.values(), key=lambda item: item["report_group_id"])


def shared_engagement(findings: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    """Require one coherent engagement context across evaluated definitions."""
    engagements = [
        finding.get("context", {}).get("engagement", {})
        for finding in findings
    ]
    if not engagements:
        return {}
    first = engagements[0]
    if any(engagement != first for engagement in engagements[1:]):
        raise ValueError("Findings contain conflicting engagement contexts")
    return deepcopy(first)


def report_summary(
    all_findings: List[Mapping[str, Any]],
    selected: List[Mapping[str, Any]],
    records: List[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Build selection and publication counts without conflating the two states."""
    selected_ids = {finding.get("finding_id") for finding in selected}
    excluded = [
        finding
        for finding in all_findings
        if finding.get("finding_id") not in selected_ids
    ]
    return {
        "checks_evaluated": len(all_findings),
        "findings_selected": len(selected),
        "findings_excluded": len(excluded),
        "candidates_selected": sum(
            finding.get("review", {}).get("disposition") == "candidate"
            for finding in selected
        ),
        "ready_for_publication": sum(
            record.get("workflow", {})
            .get("publication", {})
            .get("ready_for_publication")
            is True
            for record in records
        ),
        "requiring_work": sum(
            record.get("workflow", {})
            .get("publication", {})
            .get("ready_for_publication")
            is False
            for record in records
        ),
        "selected_by_contextual_severity": count_by(
            finding.get("triage", {}).get("severity", {}).get("contextual")
            for finding in selected
        ),
        "selected_by_disposition": count_by(
            finding.get("review", {}).get("disposition")
            for finding in selected
        ),
        "selected_by_family": count_by(
            finding.get("context", {}).get("family", {}).get("id")
            for finding in selected
        ),
        "excluded_by_disposition": count_by(
            finding.get("review", {}).get("disposition")
            for finding in excluded
        ),
    }


def build_report_ready_output(
    input_dir: Any,
    findings: Iterable[Mapping[str, Any]],
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Build and validate a versioned report-ready export."""
    findings = list(findings)
    selected = [
        finding
        for finding in findings
        if finding.get("review", {}).get("report_ready", {}).get("include") is True
    ]
    selected.sort(key=report_sort_key)
    records = [report_finding(finding) for finding in selected]
    selected_ids = {finding.get("finding_id") for finding in selected}
    excluded = [
        {
            "finding_id": finding.get("finding_id"),
            "title": finding.get("definition", {}).get("report_title"),
            "status": finding.get("status"),
            "disposition": finding.get("review", {}).get("disposition"),
            "selection_basis": finding.get("review", {})
            .get("report_ready", {})
            .get("basis"),
            "evaluation_reason": finding.get("reason"),
        }
        for finding in findings
        if finding.get("finding_id") not in selected_ids
    ]
    excluded.sort(key=lambda item: str(item["finding_id"]))
    engagement = deepcopy(shared_engagement(findings))
    output = {
        "schema_version": REPORT_READY_SCHEMA_VERSION,
        "generated_at": generated_at or utc_timestamp(),
        "generator": {
            "name": "azure-findings",
            "output_kind": "report_ready_findings",
        },
        "assessment": {
            "input_dir": str(input_dir),
            "engagement": engagement,
        },
        "selection_policy": {
            "include_candidates_by_default": True,
            "included_dispositions": list(INCLUDED_DISPOSITIONS),
            "selection_source": "finding.review.report_ready.include",
            "publication_readiness_is_separate": True,
        },
        "summary": report_summary(findings, selected, records),
        "report_groups": report_groups(selected),
        "findings": records,
        "excluded_findings": excluded,
    }
    validate_report_ready_output(output, source_findings=findings)
    return output


def parse_timestamp(value: Any) -> datetime:
    """Parse a timezone-aware report envelope timestamp."""
    if not isinstance(value, str):
        raise ValueError("Report-ready generated_at must be a timestamp string")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("Report-ready generated_at must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("Report-ready generated_at must include a timezone")
    return parsed


def validate_report_ready_output(
    output: Mapping[str, Any],
    source_findings: Optional[Iterable[Mapping[str, Any]]] = None,
) -> None:
    """Reject malformed selection, summary, grouping, or evidence metadata."""
    if output.get("schema_version") != REPORT_READY_SCHEMA_VERSION:
        raise ValueError("Unsupported report-ready schema")
    parse_timestamp(output.get("generated_at"))
    policy = output.get("selection_policy")
    summary = output.get("summary")
    groups = output.get("report_groups")
    records = output.get("findings")
    excluded = output.get("excluded_findings")
    if not isinstance(policy, Mapping) or policy.get("include_candidates_by_default") is not True:
        raise ValueError("Report-ready policy must include candidates by default")
    if policy.get("included_dispositions") != INCLUDED_DISPOSITIONS:
        raise ValueError("Report-ready included dispositions are invalid")
    if policy.get("selection_source") != "finding.review.report_ready.include":
        raise ValueError("Report-ready selection source is invalid")
    if policy.get("publication_readiness_is_separate") is not True:
        raise ValueError("Report-ready publication state must remain separate")
    if not isinstance(summary, Mapping):
        raise ValueError("Report-ready summary must be an object")
    assessment = output.get("assessment")
    if not isinstance(assessment, Mapping) or not isinstance(
        assessment.get("engagement"), Mapping
    ):
        raise ValueError("Report-ready assessment engagement must be an object")
    if not all(isinstance(value, list) for value in (groups, records, excluded)):
        raise ValueError("Report-ready findings, groups, and exclusions must be lists")

    selected_ids = [record.get("finding_id") for record in records]
    excluded_ids = [record.get("finding_id") for record in excluded]
    if any(not isinstance(item, str) or not item for item in selected_ids + excluded_ids):
        raise ValueError("Report-ready records require canonical finding IDs")
    if len(selected_ids) != len(set(selected_ids)):
        raise ValueError("Report-ready output contains duplicate selected finding IDs")
    if len(excluded_ids) != len(set(excluded_ids)):
        raise ValueError("Report-ready output contains duplicate excluded finding IDs")
    if set(selected_ids).intersection(excluded_ids):
        raise ValueError("Report-ready selected and excluded findings overlap")
    if summary.get("findings_selected") != len(records):
        raise ValueError("Report-ready selected count is inconsistent")
    if summary.get("findings_excluded") != len(excluded):
        raise ValueError("Report-ready excluded count is inconsistent")
    if summary.get("checks_evaluated") != len(records) + len(excluded):
        raise ValueError("Report-ready evaluated count is inconsistent")

    grouped_ids = []
    group_ids = []
    for group in groups:
        if not isinstance(group, Mapping) or not isinstance(group.get("finding_ids"), list):
            raise ValueError("Report-ready groups must contain finding ID lists")
        if not isinstance(group.get("report_group_id"), str):
            raise ValueError("Report-ready groups require report group IDs")
        group_ids.append(group["report_group_id"])
        grouped_ids.extend(group["finding_ids"])
    if len(group_ids) != len(set(group_ids)):
        raise ValueError("Report-ready output contains duplicate report groups")
    if sorted(grouped_ids) != sorted(selected_ids):
        raise ValueError("Report-ready groups do not partition selected findings")

    for record in records:
        workflow = record.get("workflow")
        evidence = record.get("evidence")
        if not isinstance(workflow, Mapping) or not isinstance(evidence, Mapping):
            raise ValueError("Report-ready workflow and evidence must be objects")
        if workflow.get("selection", {}).get("include") is not True:
            raise ValueError("Report-ready selected finding is not marked for inclusion")
        publication = workflow.get("publication")
        if not isinstance(publication, Mapping):
            raise ValueError("Report-ready publication readiness must be an object")
        if not isinstance(publication.get("blockers"), list) or not isinstance(
            publication.get("warnings"), list
        ):
            raise ValueError("Report-ready publication reasons must be lists")
        if publication.get("ready_for_publication") is not (
            not publication["blockers"]
        ):
            raise ValueError("Report-ready publication readiness is inconsistent")
        observations = evidence.get("observations")
        if not isinstance(observations, list):
            raise ValueError("Report-ready observations must be a list")
        if evidence.get("emitted_observation_count") != len(observations):
            raise ValueError("Report-ready emitted observation count is inconsistent")
        counts = (
            evidence.get("original_observation_count"),
            evidence.get("emitted_observation_count"),
            evidence.get("duplicate_observation_count"),
        )
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in counts
        ):
            raise ValueError("Report-ready observation counts are invalid")
        if counts[0] - counts[2] != counts[1]:
            raise ValueError("Report-ready observation counts are inconsistent")
        observation_ids = [
            observation.get("observation_id")
            for observation in observations
            if isinstance(observation, Mapping)
        ]
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("Report-ready output contains duplicate observations")
        duplicate_sets = evidence.get("duplicate_sets")
        if not isinstance(duplicate_sets, list):
            raise ValueError("Report-ready duplicate sets must be a list")
        duplicate_ids = []
        for duplicate_set in duplicate_sets:
            if not isinstance(duplicate_set, Mapping):
                raise ValueError("Report-ready duplicate sets must be objects")
            if duplicate_set.get("canonical_observation_id") not in observation_ids:
                raise ValueError("Report-ready duplicate canonical observation is absent")
            item_ids = duplicate_set.get("duplicate_observation_ids")
            if not isinstance(item_ids, list):
                raise ValueError("Report-ready duplicate observation IDs must be a list")
            duplicate_ids.extend(item_ids)
        if len(duplicate_ids) != counts[2] or len(duplicate_ids) != len(
            set(duplicate_ids)
        ):
            raise ValueError("Report-ready duplicate observation accounting is inconsistent")
        if set(duplicate_ids).intersection(observation_ids):
            raise ValueError("Report-ready duplicate observations were emitted as canonical")
        for observation in observations:
            if not isinstance(observation, Mapping):
                raise ValueError("Report-ready observations must be objects")
            if not isinstance(observation.get("data"), Mapping):
                raise ValueError("Report-ready observation data must be an object")
            if not isinstance(observation.get("reference_links"), list):
                raise ValueError("Report-ready observation reference links must be a list")

    expected_summary = {
        "checks_evaluated": len(records) + len(excluded),
        "findings_selected": len(records),
        "findings_excluded": len(excluded),
        "candidates_selected": sum(
            record.get("workflow", {}).get("disposition") == "candidate"
            for record in records
        ),
        "ready_for_publication": sum(
            record.get("workflow", {})
            .get("publication", {})
            .get("ready_for_publication")
            is True
            for record in records
        ),
        "requiring_work": sum(
            record.get("workflow", {})
            .get("publication", {})
            .get("ready_for_publication")
            is False
            for record in records
        ),
        "selected_by_contextual_severity": count_by(
            record.get("severity", {}).get("contextual")
            for record in records
        ),
        "selected_by_disposition": count_by(
            record.get("workflow", {}).get("disposition")
            for record in records
        ),
        "selected_by_family": count_by(
            record.get("context", {}).get("family", {}).get("id")
            for record in records
        ),
        "excluded_by_disposition": count_by(
            record.get("disposition") for record in excluded
        ),
    }
    if summary != expected_summary:
        raise ValueError("Report-ready summary is inconsistent")

    if source_findings is not None:
        source_findings = list(source_findings)
        source_ids = {finding.get("finding_id") for finding in source_findings}
        if source_ids != set(selected_ids).union(excluded_ids):
            raise ValueError("Report-ready output does not partition source findings")
        expected_selected_ids = {
            finding.get("finding_id")
            for finding in source_findings
            if finding.get("review", {}).get("report_ready", {}).get("include") is True
        }
        if expected_selected_ids != set(selected_ids):
            raise ValueError("Report-ready selection conflicts with finding review metadata")
        candidate_ids = {
            finding.get("finding_id")
            for finding in source_findings
            if finding.get("review", {}).get("disposition") == "candidate"
        }
        if not candidate_ids.issubset(selected_ids):
            raise ValueError("Report-ready output excluded candidate findings")
