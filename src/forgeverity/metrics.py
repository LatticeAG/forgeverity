"""Exact metrics for suite tickets-lexical-1 (spec sections 6.4-6.6).

All arithmetic uses exact rationals (fractions.Fraction) and integer square
root; no float32/float64, eigensolver, GPU, or random projection is used.
"""

from __future__ import annotations

from fractions import Fraction
from math import isqrt

from .canonical import B
from .errors import EvaluationError
from .filter import content_key, token_set, tokenize

SAMPLE_MAX = 128
SAMPLE_MIN_PRODUCTION = 32


def record_hash(record: dict) -> str:
    """B({title,body,category}) — the RecordLink.content_hash."""
    return B(content_object(record))


def content_object(record: dict) -> dict:
    return {"title": record["title"], "body": record["body"], "category": record["category"]}


def select_sample(records: list[dict], m: int) -> list[dict]:
    """The m lowest B({title,body,category}) values, ties broken by record ID.
    Deterministic: IDs, arrival time, worker count, clock, and seed do not
    affect membership."""
    keyed = sorted(records, key=lambda r: (record_hash(r), r["id"]))
    return keyed[:m]


def _jaccard(us_x: set, us_y: set) -> Fraction:
    inter = len(us_x & us_y)
    union = len(us_x) + len(us_y) - inter
    if union == 0:
        return Fraction(1)
    return Fraction(inter, union)


def vendi(token_arrays: list[list[str]]) -> Fraction:
    """Order-2 generalized Vendi effective rank V2(K) = m^2 / sum_ij K_ij^2
    over the set-Jaccard kernel. Exact rational result in [1, m]."""
    m = len(token_arrays)
    if m == 0:
        raise EvaluationError("INSUFFICIENT_SAMPLE", "Vendi requires at least one record.")
    sets = [token_set(t) for t in token_arrays]
    total = Fraction(0)
    for i in range(m):
        for j in range(m):
            if i == j:
                total += 1
            else:
                k = _jaccard(sets[i], sets[j])
                total += k * k
    return Fraction(m * m, 1) / total


def _ngrams(tokens: list[str], n: int) -> dict[tuple, int]:
    counts: dict[tuple, int] = {}
    for i in range(len(tokens) - n + 1):
        gram = tuple(tokens[i : i + n])
        counts[gram] = counts.get(gram, 0) + 1
    return counts


def self_bleu(token_arrays: list[list[str]]) -> int:
    """Precision-only self-BLEU-2 in basis points.

    Each sampled record is a hypothesis over all other sampled records as its
    reference set; n-gram counts are clipped to the maximum count in any one
    reference with no smoothing; brevity penalty is 1. Per-record score is
    isqrt(10**8 * p1*p2); the result is the integer floor of the mean.
    """
    m = len(token_arrays)
    if m < 2:
        raise EvaluationError("INSUFFICIENT_SAMPLE", "Self-BLEU requires at least two records.")
    ngrams = [[_ngrams(t, 1), _ngrams(t, 2)] for t in token_arrays]
    scores: list[int] = []
    for i in range(m):
        p = Fraction(1)
        for n in (1, 2):
            hyp = ngrams[i][n - 1]
            hyp_total = sum(hyp.values())
            if hyp_total == 0:
                raise EvaluationError("INSUFFICIENT_SAMPLE", "Empty n-gram denominator.")
            clipped = 0
            for gram, count in hyp.items():
                best = 0
                for j in range(m):
                    if j == i:
                        continue
                    c = ngrams[j][n - 1].get(gram, 0)
                    if c > best:
                        best = c
                clipped += min(count, best)
            p *= Fraction(clipped, hyp_total)
        scores.append(isqrt((100000000 * p.numerator) // p.denominator))
    return sum(scores) // m


def coverage(holdout_counts: dict[str, int], proposed_counts: dict[str, int]) -> tuple[int, Fraction]:
    """Category coverage over complete (unsampled) corpora.

    Returns (bps, min_ratio): for each reference category c the ratio
    (proposed_c/proposed_N)/(holdout_c/holdout_N); the bps value is
    min(10000, floor(10000 * min_ratio)). A missing category gives zero.
    """
    holdout_n = sum(holdout_counts.values())
    proposed_n = sum(proposed_counts.values())
    if holdout_n == 0 or proposed_n == 0:
        return 0, Fraction(0)
    min_ratio = None
    for cat, hc in holdout_counts.items():
        if hc <= 0:
            continue
        pc = proposed_counts.get(cat, 0)
        ratio = Fraction(pc * holdout_n, proposed_n * hc)
        if min_ratio is None or ratio < min_ratio:
            min_ratio = ratio
    if min_ratio is None:
        return 0, Fraction(0)
    bps = 10000 * min_ratio.numerator // min_ratio.denominator
    return min(10000, bps), min_ratio


def token_arrays(records: list[dict]) -> list[list[str]]:
    return [tokenize(r["title"], r["body"]) for r in records]


def category_counts(records: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in records:
        counts[r["category"]] = counts.get(r["category"], 0) + 1
    return counts


def metric_set(records: list[dict], m: int) -> dict:
    """MetricSet over the deterministic m-record sample."""
    sample = select_sample(records, m)
    arrays = token_arrays(sample)
    v = vendi(arrays)
    return {
        "sample_count": m,
        "vendi": {"numerator": str(v.numerator), "denominator": str(v.denominator)},
        "self_bleu_bps": self_bleu(arrays),
    }
