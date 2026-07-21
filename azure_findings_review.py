# SPDX-License-Identifier: AGPL-3.0-or-later
"""Analyst review dispositions and evidence-confidence metadata."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional


REVIEW_SCHEMA_VERSION = "1.0"
REVIEW_STATES = {"unreviewed", "reviewed", "not_required"}
REVIEW_DISPOSITIONS = {
    "candidate",
    "confirmed",
    "false_positive",
    "accepted_risk",
    "duplicate",
    "informational",
    "not_detected",
    "not_applicable",
    "inconclusive",
    "not_implemented",
}
CONFIDENCE_LEVELS = {"high", "medium", "low", "not_assessed"}
REPORT_INCLUDED_DISPOSITIONS = {
    "candidate",
    "confirmed",
    "accepted_risk",
    "informational",
}
MAX_REVIEW_TEXT_LENGTH = 10_000


def finding_default_disposition(finding: Mapping[str, Any]) -> str:
    """Map evaluation status to its initial review disposition."""
    return {
        "found": "candidate",
        "not_found": "not_detected",
        "no_data_to_assess": "inconclusive",
        "not_implemented": "not_implemented",
    }.get(finding.get("status"), "inconclusive")


def automated_confidence(finding: Mapping[str, Any]) -> Dict[str, Any]:
    """Derive evidence confidence without pretending it is analyst judgement."""
    if finding.get("status") != "found":
        return {
            "level": "not_assessed",
            "source": "automated",
            "rationale": [
                f"Finding status is {finding.get('status') or 'unknown'}; no positive evidence confidence was assigned"
            ],
        }

    reporting = finding.get("reporting", {})
    provenance = reporting.get("provenance", {})
    collection_run = provenance.get("collection_run") or {}
    source_datasets = provenance.get("source_datasets", [])
    observations = reporting.get("observations", [])
    run_status = collection_run.get("status")
    integrity_statuses = {
        item.get("integrity_status")
        for item in source_datasets
        if item.get("integrity_status")
    }
    collection_statuses = {
        status
        for item in source_datasets
        for status in item.get("collection_statuses", [])
    }

    severe_integrity = integrity_statuses.intersection(
        {"mismatch", "source_unavailable", "not_recorded"}
    )
    severe_collection = collection_statuses.intersection(
        {"failed", "unauthorised", "not_attempted"}
    )
    if not observations:
        return {
            "level": "low",
            "source": "automated",
            "rationale": ["The finding is positive but has no normalized observations"],
        }
    if severe_integrity or severe_collection or run_status == "failed":
        reasons = []
        if severe_integrity:
            reasons.append(
                "Source dataset integrity is incomplete: "
                + ", ".join(sorted(severe_integrity))
            )
        if severe_collection:
            reasons.append(
                "Relevant collection endpoints are incomplete: "
                + ", ".join(sorted(severe_collection))
            )
        if run_status == "failed":
            reasons.append("The collection run failed")
        return {
            "level": "low",
            "source": "automated",
            "rationale": reasons,
        }

    if (
        source_datasets
        and integrity_statuses == {"verified"}
        and collection_statuses
        and collection_statuses.issubset({"success", "empty"})
        and run_status == "success"
    ):
        return {
            "level": "high",
            "source": "automated",
            "rationale": [
                "Positive observations are backed by hash-verified datasets from a successful collection run"
            ],
        }

    reasons = []
    if not collection_run:
        reasons.append("No collection-run manifest was available")
    elif run_status == "partial":
        reasons.append("The overall collection run was partial")
    if not source_datasets:
        reasons.append("No source dataset was attributable to the positive observations")
    elif integrity_statuses != {"verified"}:
        reasons.append(
            "Source datasets were not all hash-verified: "
            + ", ".join(sorted(integrity_statuses or {"unknown"}))
        )
    if source_datasets and not collection_statuses:
        reasons.append("No collection endpoint status was attributable to the source datasets")
    if not reasons:
        reasons.append("Positive observations are present but provenance is incomplete")
    return {
        "level": "medium",
        "source": "automated",
        "rationale": reasons,
    }


def report_inclusion(disposition: str) -> Dict[str, Any]:
    """Express report-ready inclusion without silently dropping candidates."""
    included = disposition in REPORT_INCLUDED_DISPOSITIONS
    return {
        "include": included,
        "basis": (
            "candidate_included_by_default"
            if disposition == "candidate"
            else f"disposition_{disposition}"
        ),
    }


def default_finding_review(finding: Mapping[str, Any]) -> Dict[str, Any]:
    """Build the initial review state for an evaluated finding."""
    disposition = finding_default_disposition(finding)
    return {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "review_state": "unreviewed" if disposition == "candidate" else "not_required",
        "disposition": disposition,
        "confidence": automated_confidence(finding),
        "analyst": {
            "reviewer": None,
            "reviewed_at": None,
            "notes": None,
        },
        "report_ready": report_inclusion(disposition),
    }


def validate_review_text(value: Any, field_name: str) -> None:
    """Validate optional analyst-authored text without altering it."""
    if value is None:
        return
    if not isinstance(value, str):
        raise ValueError(f"Review {field_name} must be a string or null")
    if len(value) > MAX_REVIEW_TEXT_LENGTH:
        raise ValueError(f"Review {field_name} exceeds {MAX_REVIEW_TEXT_LENGTH} characters")


def validate_reviewed_at(value: Any) -> None:
    """Require an ISO-8601 timestamp when a review time is supplied."""
    if value is None:
        return
    if not isinstance(value, str):
        raise ValueError("Review reviewed_at must be an ISO-8601 string or null")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("Review reviewed_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("Review reviewed_at must include a timezone")


def validate_review_override(review: Mapping[str, Any]) -> None:
    """Validate one analyst review override."""
    finding_id = review.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id:
        raise ValueError("Review finding_id must be a non-empty string")
    if review.get("disposition") not in REVIEW_DISPOSITIONS:
        raise ValueError(f"Invalid review disposition for {finding_id}")
    confidence = review.get("confidence")
    if confidence is not None:
        if not isinstance(confidence, Mapping):
            raise ValueError(f"Review confidence must be an object for {finding_id}")
        if confidence.get("level") not in CONFIDENCE_LEVELS:
            raise ValueError(f"Invalid review confidence level for {finding_id}")
        validate_review_text(confidence.get("rationale"), "confidence rationale")
    validate_review_text(review.get("reviewer"), "reviewer")
    validate_review_text(review.get("notes"), "notes")
    validate_reviewed_at(review.get("reviewed_at"))
    if not review.get("reviewer"):
        raise ValueError(f"Review reviewer is required for {finding_id}")
    if not review.get("reviewed_at"):
        raise ValueError(f"Review reviewed_at is required for {finding_id}")


def load_review_overrides(path: Path) -> Dict[str, Dict[str, Any]]:
    """Load a versioned analyst review file keyed by canonical finding ID."""
    review_path = Path(path)
    with review_path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, Mapping):
        raise ValueError("Review file must contain a JSON object")
    if payload.get("schema_version") != REVIEW_SCHEMA_VERSION:
        raise ValueError("Unsupported review file schema version")
    reviews = payload.get("reviews")
    if not isinstance(reviews, list):
        raise ValueError("Review file reviews must be a list")
    overrides = {}
    for review in reviews:
        if not isinstance(review, Mapping):
            raise ValueError("Each review override must be an object")
        validate_review_override(review)
        finding_id = review["finding_id"]
        if finding_id in overrides:
            raise ValueError(f"Duplicate review override for {finding_id}")
        overrides[finding_id] = dict(review)
    return overrides


def apply_review_override(
    finding: Dict[str, Any],
    override: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Attach defaults or a validated analyst decision to one finding."""
    review = default_finding_review(finding)
    if override is not None:
        validate_review_override(override)
        if override["finding_id"] != finding.get("finding_id"):
            raise ValueError("Review override finding_id does not match the finding")
        disposition = override["disposition"]
        review["review_state"] = "reviewed"
        review["disposition"] = disposition
        review["analyst"] = {
            "reviewer": override.get("reviewer"),
            "reviewed_at": override.get("reviewed_at"),
            "notes": override.get("notes"),
        }
        if override.get("confidence") is not None:
            review["confidence"] = {
                "level": override["confidence"]["level"],
                "source": "analyst",
                "rationale": [override["confidence"].get("rationale")]
                if override["confidence"].get("rationale")
                else [],
            }
        review["report_ready"] = report_inclusion(disposition)
    finding["review"] = review
    validate_finding_review(finding)
    return finding


def apply_review_overrides(
    findings: Iterable[Dict[str, Any]],
    overrides: Optional[Mapping[str, Mapping[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Apply review defaults and reject stale or unknown override IDs."""
    findings = list(findings)
    overrides = dict(overrides or {})
    finding_ids = {finding.get("finding_id") for finding in findings}
    unknown_ids = sorted(set(overrides) - finding_ids)
    if unknown_ids:
        raise ValueError(
            "Review file contains unknown finding IDs: " + ", ".join(unknown_ids)
        )
    for finding in findings:
        apply_review_override(finding, overrides.get(finding.get("finding_id")))
    return findings


def validate_finding_review(finding: Mapping[str, Any]) -> None:
    """Reject malformed or inconsistent finding review metadata."""
    review = finding.get("review") or {}
    if review.get("schema_version") != REVIEW_SCHEMA_VERSION:
        raise ValueError("Unsupported finding review schema")
    if review.get("review_state") not in REVIEW_STATES:
        raise ValueError("Invalid finding review state")
    disposition = review.get("disposition")
    if disposition not in REVIEW_DISPOSITIONS:
        raise ValueError("Invalid finding review disposition")
    confidence = review.get("confidence")
    if not isinstance(confidence, Mapping):
        raise ValueError("Finding review confidence must be an object")
    if confidence.get("level") not in CONFIDENCE_LEVELS:
        raise ValueError("Invalid finding review confidence level")
    if confidence.get("source") not in {"automated", "analyst"}:
        raise ValueError("Invalid finding review confidence source")
    rationale = confidence.get("rationale")
    if not isinstance(rationale, list):
        raise ValueError("Finding review confidence rationale must be a list")
    for item in rationale:
        if not isinstance(item, str):
            raise ValueError("Finding review confidence rationale items must be strings")
        validate_review_text(item, "confidence rationale item")
    analyst = review.get("analyst")
    if not isinstance(analyst, Mapping):
        raise ValueError("Finding review analyst metadata must be an object")
    validate_review_text(analyst.get("reviewer"), "reviewer")
    validate_review_text(analyst.get("notes"), "notes")
    validate_reviewed_at(analyst.get("reviewed_at"))
    if review.get("review_state") == "reviewed":
        if not analyst.get("reviewer") or not analyst.get("reviewed_at"):
            raise ValueError("Reviewed findings require a reviewer and reviewed_at")
    report_ready = review.get("report_ready")
    if not isinstance(report_ready, Mapping) or not isinstance(
        report_ready.get("include"), bool
    ):
        raise ValueError("Finding review report_ready metadata is invalid")
    if report_ready.get("include") != (disposition in REPORT_INCLUDED_DISPOSITIONS):
        raise ValueError("Finding review report-ready inclusion conflicts with disposition")
    expected_basis = report_inclusion(disposition)["basis"]
    if report_ready.get("basis") != expected_basis:
        raise ValueError("Finding review report-ready basis conflicts with disposition")
