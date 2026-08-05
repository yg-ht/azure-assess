"""Describe which collection plane can satisfy a finding's evidence needs."""

from itertools import product
from typing import Iterable, FrozenSet, Tuple


BASE = "Base"
GRAPH = "Graph"
EITHER = "Either"
BASE_AND_GRAPH = "BaseAndGraph"
ENDPOINT_SOURCE_TYPES = {BASE, GRAPH, EITHER, BASE_AND_GRAPH}

SourceOption = FrozenSet[str]
SourceOptions = Tuple[SourceOption, ...]


def endpoint_plane(identifier: object) -> str:
    """Classify a dataset, URL fragment, or stable endpoint ID by collection plane."""
    value = str(identifier or "").casefold()
    if value.startswith("graph_") or "graph.microsoft.com" in value:
        return GRAPH
    return BASE


def minimise_source_options(options: Iterable[Iterable[str]]) -> SourceOptions:
    """Remove duplicate and needlessly broader ways of satisfying a requirement."""
    unique = {frozenset(option) for option in options if option}
    minimal = {
        option
        for option in unique
        if not any(other < option for other in unique)
    }
    return tuple(sorted(minimal, key=lambda item: (len(item), sorted(item))))


def required_source_options(*option_sets: SourceOptions) -> SourceOptions:
    """Combine independently required inputs into their possible collection planes."""
    populated = [options for options in option_sets if options]
    if not populated:
        return ()
    return minimise_source_options(
        frozenset().union(*combination)
        for combination in product(*populated)
    )


def alternative_source_options(*option_sets: SourceOptions) -> SourceOptions:
    """Combine interchangeable inputs into alternative collection-plane choices."""
    return minimise_source_options(
        option
        for options in option_sets
        for option in options
    )


def source_options_for_identifiers(identifiers: Iterable[object]) -> SourceOptions:
    """Treat each identifier as an independently required collection input."""
    return required_source_options(
        *((frozenset({endpoint_plane(identifier)}),) for identifier in identifiers)
    )


def source_options_for_patterns(patterns: Iterable[Iterable[object]]) -> SourceOptions:
    """Classify each endpoint-matching pattern as one required input."""
    return required_source_options(
        *(
            (
                frozenset(
                    {
                        GRAPH
                        if any(endpoint_plane(fragment) == GRAPH for fragment in pattern)
                        else BASE
                    }
                ),
            )
            for pattern in patterns
        )
    )


def source_type_for_options(options: SourceOptions) -> str | None:
    """Return the public requirement label for normalised plane choices."""
    normalised = minimise_source_options(options)
    if normalised == (frozenset({BASE}),):
        return BASE
    if normalised == (frozenset({GRAPH}),):
        return GRAPH
    if set(normalised) == {frozenset({BASE}), frozenset({GRAPH})}:
        return EITHER
    if normalised == (frozenset({BASE, GRAPH}),):
        return BASE_AND_GRAPH
    return None


def source_options_for_type(source_type: str | None) -> SourceOptions:
    """Expand a public requirement label into its normalised plane choices."""
    mapping = {
        BASE: (frozenset({BASE}),),
        GRAPH: (frozenset({GRAPH}),),
        EITHER: (frozenset({BASE}), frozenset({GRAPH})),
        BASE_AND_GRAPH: (frozenset({BASE, GRAPH}),),
    }
    return mapping.get(str(source_type), ())
