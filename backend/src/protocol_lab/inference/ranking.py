"""Explainable lexicographic ordering; no probability claims."""

from fractions import Fraction

VERSION = "lexicographic-1"


def ranking_key(candidate):
    r = candidate.ranking
    return (
        candidate.family,
        -r.supporting_sessions,
        -Fraction(r.matched, r.checked or 1),
        -r.explained_bytes,
        r.contradictions,
        r.free_parameters,
        candidate.rule_sha256,
        candidate.scope.direction,
    )
