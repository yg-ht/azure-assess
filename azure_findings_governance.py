#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Offline Azure governance correlations for locks and Azure Policy."""

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from azure_findings_correlation import (
    CorrelationResult,
    arm_parent_scopes,
    canonical_arm_id,
    canonical_role_definition_id,
    normalise_identifier,
    parse_timestamp,
)
from azure_findings_profiles import CRITICAL_RESOURCE_PROFILE, EXPECTED_POLICY_PROFILE
from azure_findings_shared import assessment_resource_id, assessment_status, assessment_title


LOCK_PROVIDER_SEGMENT = "/providers/microsoft.authorization/locks/"
LOCK_STRENGTH = {"cannotdelete": 1, "readonly": 2}
NON_COMPLIANT_STATES = {"noncompliant", "non-compliant"}
EXCLUDED_POLICY_STATES = {"compliant", "exempt", "notapplicable", "not-applicable"}


def nested_value(record: Mapping[str, Any], *paths: Any) -> Any:
    """Return the first present value from simple keys or tuple paths."""
    for path in paths:
        parts = (path,) if isinstance(path, str) else tuple(path)
        current: Any = record
        for part in parts:
            if not isinstance(current, Mapping) or part not in current:
                current = None
                break
            current = current[part]
        if current is not None:
            return current
    return None


def resource_type(record: Mapping[str, Any]) -> str:
    explicit = normalise_identifier(nested_value(record, "type", ("properties", "type")))
    if explicit:
        return explicit
    resource_id = canonical_arm_id(record.get("id"))
    marker = "/providers/"
    if marker not in resource_id:
        return ""
    provider_path = resource_id.split(marker, 1)[1].split("/")
    if len(provider_path) < 2:
        return ""
    return "/".join(provider_path[:2])


def lock_scope(lock: Mapping[str, Any]) -> str:
    """Return the resource scope protected by an Azure management lock."""
    lock_id = canonical_arm_id(lock.get("id"))
    if LOCK_PROVIDER_SEGMENT not in lock_id:
        return ""
    return lock_id.split(LOCK_PROVIDER_SEGMENT, 1)[0]


def lock_level(lock: Mapping[str, Any]) -> str:
    return normalise_identifier(nested_value(lock, "level", ("properties", "level")))


def effective_lock(resource_id: Any, locks_by_scope: Mapping[str, Sequence[Mapping[str, Any]]]):
    """Return the strongest resource or inherited lock for one ARM resource."""
    candidates = []
    for scope in arm_parent_scopes(resource_id):
        for lock in locks_by_scope.get(scope, []):
            level = lock_level(lock)
            if level in LOCK_STRENGTH:
                candidates.append((LOCK_STRENGTH[level], scope, lock))
    if not candidates:
        return None
    return sorted(candidates, key=lambda item: (-item[0], item[1]))[0]


def analyse_critical_resource_locks(
    resources: Iterable[Mapping[str, Any]],
    locks: Iterable[Mapping[str, Any]],
    conclusion_support: str,
    source_files: Iterable[str] = (),
    profile: Mapping[str, Any] = CRITICAL_RESOURCE_PROFILE,
) -> CorrelationResult:
    """Identify profiled critical resources without an effective deletion lock."""
    critical_types = profile.get("resource_types", {})
    locks_by_scope: Dict[str, List[Mapping[str, Any]]] = {}
    malformed_locks = 0
    for lock in locks:
        scope = lock_scope(lock)
        if not scope:
            malformed_locks += 1
            continue
        locks_by_scope.setdefault(scope, []).append(lock)

    eligible_assets = []
    observations = []
    for resource in resources:
        current_type = resource_type(resource)
        if current_type not in critical_types:
            continue
        resource_id = canonical_arm_id(resource.get("id"))
        if not resource_id:
            continue
        eligible_assets.append(
            {"id": resource.get("id"), "name": resource.get("name"), "type": current_type}
        )
        protected = effective_lock(resource_id, locks_by_scope)
        if protected is not None or conclusion_support != "positive_and_negative":
            continue
        observations.append(
            {
                "id": resource.get("id"),
                "name": resource.get("name"),
                "resourceType": current_type,
                "resourceGroup": resource.get("resourceGroup"),
                "requiredLockLevel": profile.get("minimum_lock_level"),
                "effectiveLockLevel": None,
                "evaluatedScopes": arm_parent_scopes(resource_id),
                "criticalityReason": critical_types[current_type],
                "profileVersion": profile.get("profile_version"),
            }
        )

    limitations = []
    if malformed_locks:
        limitations.append(f"Ignored {malformed_locks} lock records without a valid ARM lock scope")
    return CorrelationResult(
        observations=observations,
        eligible_assets=eligible_assets,
        source_files=sorted(set(source_files)),
        limitations=limitations,
        conclusion_support=conclusion_support,
    )


def policy_assignment_definition_id(assignment: Mapping[str, Any]) -> str:
    return canonical_role_definition_id(
        nested_value(
            assignment,
            "policyDefinitionId",
            ("properties", "policyDefinitionId"),
        )
    )


def policy_assignment_scope(assignment: Mapping[str, Any]) -> str:
    explicit = nested_value(assignment, "scope", ("properties", "scope"))
    if explicit:
        return canonical_arm_id(explicit)
    assignment_id = canonical_arm_id(assignment.get("id"))
    marker = "/providers/microsoft.authorization/policyassignments/"
    return assignment_id.split(marker, 1)[0] if marker in assignment_id else ""


def assignment_is_enforced(assignment: Mapping[str, Any]) -> bool:
    mode = normalise_identifier(
        nested_value(assignment, "enforcementMode", ("properties", "enforcementMode"))
    )
    return mode not in {"donotenforce", "disabled"}


def assignment_applies_to_subscription(
    assignment: Mapping[str, Any], subscription_scope: str
) -> bool:
    """Match direct or collector-returned inherited management-group assignments."""
    assignment_scope = policy_assignment_scope(assignment)
    if assignment_scope == subscription_scope:
        return True
    inherited_scope = (
        assignment_scope.startswith("/providers/microsoft.management/managementgroups/")
        or assignment_scope in {"", "/"}
    )
    if not inherited_scope:
        return False
    excluded = nested_value(assignment, "notScopes", ("properties", "notScopes")) or []
    excluded_scopes = [canonical_arm_id(item) for item in excluded]
    return not any(
        subscription_scope == excluded_scope
        or subscription_scope.startswith(excluded_scope.rstrip("/") + "/")
        for excluded_scope in excluded_scopes
        if excluded_scope
    )


def analyse_expected_policy_assignments(
    assignments: Iterable[Mapping[str, Any]],
    subscription_ids: Iterable[str],
    conclusion_support: str,
    source_files: Iterable[str] = (),
    profile: Mapping[str, Any] = EXPECTED_POLICY_PROFILE,
) -> CorrelationResult:
    """Compare enforced assignments with an explicit, versioned security baseline."""
    assignments = list(assignments)
    subscription_ids = sorted(
        {normalise_identifier(item) for item in subscription_ids if item}
    )
    eligible_assets = []
    observations = []
    for subscription_id in subscription_ids:
        scope = canonical_arm_id(f"/subscriptions/{subscription_id}")
        eligible_assets.append({"id": scope, "kind": "azure_subscription"})
        for requirement in profile.get("requirements", []):
            wanted = {
                normalise_identifier(item)
                for item in requirement.get("definition_ids", [])
            }
            satisfied = any(
                policy_assignment_definition_id(assignment) in wanted
                and assignment_is_enforced(assignment)
                and assignment_applies_to_subscription(assignment, scope)
                for assignment in assignments
            )
            if satisfied:
                continue
            if conclusion_support != "positive_and_negative":
                # A partial assignment inventory cannot prove that another
                # applicable enforced assignment is absent.
                continue
            non_enforced = [
                assignment.get("id")
                for assignment in assignments
                if policy_assignment_definition_id(assignment) in wanted
                and assignment_applies_to_subscription(assignment, scope)
                and not assignment_is_enforced(assignment)
            ]
            observations.append(
                {
                    "id": scope,
                    "subscriptionId": subscription_id,
                    "requirementId": requirement.get("requirement_id"),
                    "expectedDefinitionIds": sorted(wanted),
                    "expectedDisplayName": requirement.get("display_name"),
                    "rationale": requirement.get("rationale"),
                    "nonEnforcedAssignmentIds": sorted(
                        item for item in non_enforced if item
                    ),
                    "profileVersion": profile.get("profile_version"),
                }
            )
    limitations = []
    if not subscription_ids:
        # A complete assignment list cannot prove a baseline for an unknown
        # engagement scope.  Preserve this as not assessed, not a clean result.
        limitations.append("No selected subscription ID was available for policy baseline analysis")
        conclusion_support = "inconclusive"
    return CorrelationResult(
        observations=observations,
        eligible_assets=eligible_assets,
        source_files=sorted(set(source_files)),
        limitations=limitations,
        conclusion_support=conclusion_support,
    )


def policy_state_key(state: Mapping[str, Any]) -> Tuple[str, str, str, str]:
    return (
        canonical_arm_id(nested_value(state, "resourceId", ("properties", "resourceId"))),
        canonical_arm_id(
            nested_value(state, "policyAssignmentId", ("properties", "policyAssignmentId"))
        ),
        canonical_arm_id(
            nested_value(state, "policyDefinitionId", ("properties", "policyDefinitionId"))
        ),
        normalise_identifier(
            nested_value(
                state,
                "policyDefinitionReferenceId",
                ("properties", "policyDefinitionReferenceId"),
            )
        ),
    )


def policy_state_timestamp(state: Mapping[str, Any]) -> datetime:
    parsed = parse_timestamp(
        nested_value(state, "timestamp", ("properties", "timestamp"))
    )
    return parsed or datetime.min.replace(tzinfo=timezone.utc)


def current_policy_states(states: Iterable[Mapping[str, Any]]) -> List[Mapping[str, Any]]:
    """Select the latest deterministic record for each policy/resource state key."""
    selected: Dict[Tuple[str, str, str, str], Tuple[datetime, int, Mapping[str, Any]]] = {}
    for index, state in enumerate(states):
        key = policy_state_key(state)
        candidate = (policy_state_timestamp(state), index, state)
        if key not in selected or candidate[:2] > selected[key][:2]:
            selected[key] = candidate
    return [selected[key][2] for key in sorted(selected)]


def policy_evaluation_error(state: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """Return explicit engine error evidence without conflating non-compliance."""
    error = nested_value(
        state,
        "error",
        "errorCode",
        ("properties", "error"),
        ("properties", "errorCode"),
        ("policyEvaluationDetails", "error"),
        ("properties", "policyEvaluationDetails", "error"),
    )
    if not error:
        return None
    return {
        "resourceId": nested_value(state, "resourceId", ("properties", "resourceId")),
        "policyAssignmentId": nested_value(
            state, "policyAssignmentId", ("properties", "policyAssignmentId")
        ),
        "policyDefinitionId": nested_value(
            state, "policyDefinitionId", ("properties", "policyDefinitionId")
        ),
        "evaluationError": error,
        "timestamp": nested_value(state, "timestamp", ("properties", "timestamp")),
    }


def analyse_policy_states(
    states: Iterable[Mapping[str, Any]],
    conclusion_support: str,
    source_files: Iterable[str] = (),
    events: Iterable[Mapping[str, Any]] = (),
    error_conclusion_support: Optional[str] = None,
) -> Tuple[CorrelationResult, CorrelationResult]:
    """Return separate current non-compliance and explicit evaluation-error results."""
    current = current_policy_states(states)
    eligible_assets = []
    non_compliant = []
    errors = []
    unknown_states = 0
    for state in current:
        resource_id = nested_value(state, "resourceId", ("properties", "resourceId"))
        assignment_id = nested_value(
            state, "policyAssignmentId", ("properties", "policyAssignmentId")
        )
        definition_id = nested_value(
            state, "policyDefinitionId", ("properties", "policyDefinitionId")
        )
        eligible_assets.append(
            {
                "id": resource_id,
                "policyAssignmentId": assignment_id,
                "policyDefinitionId": definition_id,
            }
        )
        error = policy_evaluation_error(state)
        if error:
            errors.append(error)
            continue
        compliance = normalise_identifier(
            nested_value(state, "complianceState", ("properties", "complianceState"))
        )
        if compliance in NON_COMPLIANT_STATES:
            non_compliant.append(
                {
                    "id": resource_id,
                    "resourceId": resource_id,
                    "policyAssignmentId": assignment_id,
                    "policyDefinitionId": definition_id,
                    "policyDefinitionReferenceId": nested_value(
                        state,
                        "policyDefinitionReferenceId",
                        ("properties", "policyDefinitionReferenceId"),
                    ),
                    "complianceState": nested_value(
                        state, "complianceState", ("properties", "complianceState")
                    ),
                    "timestamp": nested_value(state, "timestamp", ("properties", "timestamp")),
                }
            )
        elif compliance not in EXCLUDED_POLICY_STATES:
            unknown_states += 1
    seen_errors = {
        (
            canonical_arm_id(item.get("resourceId")),
            canonical_arm_id(item.get("policyAssignmentId")),
            str(item.get("evaluationError")),
        )
        for item in errors
    }
    for event in events:
        error = policy_evaluation_error(event)
        if not error:
            continue
        key = (
            canonical_arm_id(error.get("resourceId")),
            canonical_arm_id(error.get("policyAssignmentId")),
            str(error.get("evaluationError")),
        )
        if key not in seen_errors:
            seen_errors.add(key)
            errors.append(error)
    limitations = []
    if unknown_states:
        limitations.append(
            f"{unknown_states} current policy states had unsupported or missing compliance values"
        )
    common = {
        "eligible_assets": eligible_assets,
        "source_files": sorted(set(source_files)),
        "limitations": limitations,
    }
    return (
        CorrelationResult(
            observations=non_compliant,
            conclusion_support=conclusion_support,
            **common,
        ),
        CorrelationResult(
            observations=errors,
            conclusion_support=error_conclusion_support or conclusion_support,
            **common,
        ),
    )


def advisor_recommendation(record: Mapping[str, Any]) -> Dict[str, Any]:
    """Normalise the security-relevant fields of one Advisor recommendation."""
    description = nested_value(record, "shortDescription", ("properties", "shortDescription"))
    if not isinstance(description, Mapping):
        description = {}
    metadata = nested_value(record, "resourceMetadata", ("properties", "resourceMetadata"))
    if not isinstance(metadata, Mapping):
        metadata = {}
    return {
        "recommendation_id": nested_value(
            record, "recommendationTypeId", ("properties", "recommendationTypeId"), "id"
        ),
        "resource_id": metadata.get("resourceId") or nested_value(record, "resourceId"),
        "category": nested_value(record, "category", ("properties", "category")),
        "impact": nested_value(record, "impact", ("properties", "impact")),
        "title": description.get("problem") or nested_value(record, "name"),
        "solution": description.get("solution"),
        "suppressed": bool(
            nested_value(record, "suppressionIds", ("properties", "suppressionIds"))
        )
        or normalise_identifier(
            nested_value(record, "state", ("properties", "state"))
        )
        in {"suppressed", "dismissed"},
    }


def title_tokens(value: Any) -> set:
    return {
        token
        for token in normalise_identifier(value).replace("-", " ").replace("_", " ").split()
        if len(token) > 2
    }


def title_similarity(left: Any, right: Any) -> float:
    left_tokens = title_tokens(left)
    right_tokens = title_tokens(right)
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens.intersection(right_tokens)) / len(left_tokens.union(right_tokens))


def analyse_advisor_defender(
    recommendations: Iterable[Mapping[str, Any]],
    assessments: Iterable[Mapping[str, Any]],
    conclusion_support: str,
    source_files: Iterable[str] = (),
    explicit_mappings: Optional[Mapping[str, Sequence[str]]] = None,
) -> CorrelationResult:
    """Surface active security recommendations with exact-first Defender context."""
    explicit_mappings = {
        normalise_identifier(key): {normalise_identifier(item) for item in values}
        for key, values in (explicit_mappings or {}).items()
    }
    defender = []
    for assessment in assessments:
        defender.append(
            {
                "assessment_id": assessment.get("name") or assessment.get("id"),
                "resource_id": assessment_resource_id(assessment),
                "title": assessment_title(assessment),
                "status": assessment_status(assessment),
            }
        )
    defender_by_resource: Dict[str, List[Dict[str, Any]]] = {}
    for assessment in defender:
        resource_id = canonical_arm_id(assessment.get("resource_id"))
        if resource_id:
            defender_by_resource.setdefault(resource_id, []).append(assessment)

    observations = []
    eligible_assets = []
    for raw_recommendation in recommendations:
        recommendation = advisor_recommendation(raw_recommendation)
        if normalise_identifier(recommendation.get("category")) != "security":
            continue
        if recommendation.get("suppressed"):
            continue
        resource_id = canonical_arm_id(recommendation.get("resource_id"))
        eligible_assets.append(
            {
                "id": recommendation.get("resource_id")
                or recommendation.get("recommendation_id"),
                "kind": "advisor_recommendation",
            }
        )
        candidates = defender_by_resource.get(resource_id, [])
        mapping_ids = explicit_mappings.get(
            normalise_identifier(recommendation.get("recommendation_id")), set()
        )
        ranked = []
        for assessment in candidates:
            assessment_id = normalise_identifier(assessment.get("assessment_id"))
            exact_title = normalise_identifier(recommendation.get("title")) == normalise_identifier(
                assessment.get("title")
            )
            similarity = title_similarity(recommendation.get("title"), assessment.get("title"))
            if assessment_id == normalise_identifier(
                recommendation.get("recommendation_id")
            ):
                ranked.append((4, 1.0, "exact_resource_and_control_id", assessment))
            elif assessment_id in mapping_ids:
                ranked.append((3, 1.0, "explicit_mapping", assessment))
            elif exact_title and assessment.get("title"):
                ranked.append((2, 1.0, "exact_resource_and_title", assessment))
            elif similarity >= 0.75:
                ranked.append((1, similarity, "inferred_resource_and_title", assessment))
        match = sorted(
            ranked,
            key=lambda item: (-item[0], -item[1], str(item[3].get("assessment_id"))),
        )[0] if ranked else None
        observation = {
            "id": recommendation.get("resource_id") or recommendation.get("recommendation_id"),
            "resourceId": recommendation.get("resource_id"),
            "advisorRecommendationId": recommendation.get("recommendation_id"),
            "advisorTitle": recommendation.get("title"),
            "advisorImpact": recommendation.get("impact"),
            "advisorSolution": recommendation.get("solution"),
            "defenderAssessmentId": match[3].get("assessment_id") if match else None,
            "defenderTitle": match[3].get("title") if match else None,
            "defenderStatus": match[3].get("status") if match else None,
            "correlationMethod": match[2] if match else "unmatched",
        }
        observations.append(observation)

    return CorrelationResult(
        observations=observations,
        eligible_assets=eligible_assets,
        source_files=sorted(set(source_files)),
        conclusion_support=conclusion_support,
    )
