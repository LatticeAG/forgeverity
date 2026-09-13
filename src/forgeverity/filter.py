"""Deterministic candidate filtering (spec section 6.2).

Tokenize `title + "\\n" + body` by ASCII lowercase then maximal [a-z0-9]+
runs. Exact dedup compares token arrays; near-dedup compares the set of
unigrams and adjacent bigrams (distinct tuple tags) at the 0.95 boundary via
`20 * intersection >= 19 * union`. The holdout check covers exactly the
eligible set and runs before candidate/parent deduplication.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .canonical import J
from .ids import valid_id
from .schema import CATEGORY_RE, TEXT_ALLOWED_RE

TOKEN_RE = re.compile(r"[a-z0-9]+")

MAX_RECORDS_ARTIFACT = 4096
MAX_CANDIDATE_RECORDS = 1024
MIN_TOKENS = 8
MAX_TOKENS = 512
MAX_TOKEN_CHARS = 64
TITLE_MAX = 160
BODY_MAX = 8192

# §6.2 precedence order.
PRECEDENCE = (
    "SHAPE",
    "TEXT",
    "CATEGORY",
    "DUP_PARENT",
    "DUP_CANDIDATE",
    "NEAR_PARENT",
    "NEAR_CANDIDATE",
)


def tokenize(title: str, body: str) -> list[str]:
    """ASCII-lowercase maximal [a-z0-9]+ runs of title + LF + body."""
    return TOKEN_RE.findall((title + "\n" + body).lower())


def token_set(tokens: list[str]) -> set:
    """U(x): unigrams tagged ("u", t) and adjacent bigrams tagged ("b", a, b)."""
    out: set = set()
    prev = None
    for tok in tokens:
        out.add(("u", tok))
        if prev is not None:
            out.add(("b", prev, tok))
        prev = tok
    return out


def near_duplicate(intersection: int, union: int) -> bool:
    """True iff jaccard >= 0.95, inclusive: 20*inter >= 19*union."""
    return 20 * intersection >= 19 * union


def content_object(record: dict) -> dict:
    return {"title": record["title"], "body": record["body"], "category": record["category"]}


def content_key(record: dict) -> bytes:
    """J({title,body,category}) bytes — normalized content, ID excluded."""
    return J(content_object(record))


def _shape_error(rec: dict) -> str | None:
    """SHAPE: id validity is document-level; here: field presence/type/length."""
    if not isinstance(rec.get("id"), str) or not valid_id(rec.get("id"), "fvrec_"):
        # Callers treat invalid IDs as document errors before filtering; if one
        # slips through it is still a SHAPE-class failure, never silent.
        return "SHAPE"
    title, body, category = rec.get("title"), rec.get("body"), rec.get("category")
    if not isinstance(title, str) or not isinstance(body, str) or not isinstance(category, str):
        return "SHAPE"
    if not (1 <= len(title) <= TITLE_MAX):
        return "SHAPE"
    if not (1 <= len(body) <= BODY_MAX):
        return "SHAPE"
    if not (1 <= len(category) <= 32):
        return "SHAPE"
    return None


def _text_error(rec: dict) -> str | None:
    title, body = rec["title"], rec["body"]
    if not TEXT_ALLOWED_RE.match(title) or not TEXT_ALLOWED_RE.match(body):
        return "TEXT"
    tokens = tokenize(title, body)
    if not (MIN_TOKENS <= len(tokens) <= MAX_TOKENS):
        return "TEXT"
    for tok in tokens:
        if len(tok) > MAX_TOKEN_CHARS:
            return "TEXT"
    return None


def _category_error(rec: dict, categories: list[str]) -> str | None:
    cat = rec["category"]
    if not CATEGORY_RE.match(cat) or cat not in categories:
        return "CATEGORY"
    return None


@dataclass
class FilterResult:
    eligible: list[dict]  # passed SHAPE/TEXT/CATEGORY (pre-dedup)
    excluded: list[dict]  # [{record_id, code}]
    survivors: list[dict]  # retained after dedup
    holdout_leak: bool


def _survivor_order(rec: dict) -> tuple[bytes, bytes, str]:
    tokens = tokenize(rec["title"], rec["body"])
    return (J(tokens), content_key(rec), rec["id"])


def filter_candidates(
    records: list[dict],
    parent_records: list[dict],
    holdout_records: list[dict],
    categories: list[str],
) -> FilterResult:
    """Full candidate filter.

    - Eligibility: earliest applicable SHAPE/TEXT/CATEGORY code per record.
    - Holdout: any eligible record exactly or nearly matching the holdout is a
      batch-level leak (checked before dedup; nothing can be laundered away).
    - Dedup: eligible records evaluated once in ascending survivor order
      (J(token_array), J(content), record ID) against the union of the parent
      corpus and already-retained candidates, with per-record precedence
      DUP_PARENT, DUP_CANDIDATE, NEAR_PARENT, NEAR_CANDIDATE.
    """
    excluded: list[dict] = []
    eligible: list[dict] = []
    for rec in records:
        code = _shape_error(rec)
        if code is None:
            code = _text_error(rec)
        if code is None:
            code = _category_error(rec, categories)
        if code is None:
            eligible.append(rec)
        else:
            excluded.append({"record_id": rec["id"], "code": code})

    # Holdout comparison over exactly the eligible set, before dedup.
    holdout_exact: set[bytes] = set()
    holdout_sets: list[set] = []
    holdout_sizes: list[int] = []
    for hrec in holdout_records:
        toks = tokenize(hrec["title"], hrec["body"])
        holdout_exact.add(J(toks))
        uset = token_set(toks)
        holdout_sets.append(uset)
        holdout_sizes.append(len(uset))

    for rec in eligible:
        toks = tokenize(rec["title"], rec["body"])
        if J(toks) in holdout_exact:
            return FilterResult(eligible, excluded, [], True)
        uset = token_set(toks)
        for hset, hsize in zip(holdout_sets, holdout_sizes):
            inter = len(uset & hset)
            union = len(uset) + hsize - inter
            if near_duplicate(inter, union):
                return FilterResult(eligible, excluded, [], True)

    # Parent index: exact by J(token array); near via feature inverted index.
    parent_exact: dict[bytes, dict] = {}
    parent_sets: list[tuple[set, int]] = []
    feature_index: dict[object, list[int]] = {}
    parent_ids: dict[str, bytes] = {}
    for i, prec in enumerate(parent_records):
        toks = tokenize(prec["title"], prec["body"])
        parent_exact.setdefault(J(toks), prec)
        uset = token_set(toks)
        parent_sets.append((uset, len(uset)))
        parent_ids[prec["id"]] = content_key(prec)
        for feat in uset:
            feature_index.setdefault(feat, []).append(i)

    retained_exact: set[bytes] = set()
    retained_sets: list[set] = []
    retained_index: dict[object, list[int]] = {}
    survivors: list[dict] = []
    candidate_ids: set[str] = set()

    for rec in sorted(eligible, key=_survivor_order):
        toks = tokenize(rec["title"], rec["body"])
        tkey = J(toks)
        uset = token_set(toks)
        usize = len(uset)

        exact_parent = tkey in parent_exact
        exact_cand = tkey in retained_exact
        near_parent = False
        if not exact_parent:
            seen: set[int] = set()
            for feat in uset:
                for idx in feature_index.get(feat, ()):
                    if idx in seen:
                        continue
                    seen.add(idx)
                    pset, psize = parent_sets[idx]
                    # Prefilter: near requires 39*inter >= 19*(ux+uy).
                    if 39 * min(usize, psize) < 19 * (usize + psize):
                        continue
                    inter = len(uset & pset)
                    if near_duplicate(inter, usize + psize - inter):
                        near_parent = True
                        break
            if near_parent:
                pass
        near_cand = False
        if not exact_parent and not exact_cand and not near_parent:
            seen2: set[int] = set()
            for feat in uset:
                for idx in retained_index.get(feat, ()):
                    if idx in seen2:
                        continue
                    seen2.add(idx)
                    rset = retained_sets[idx]
                    rsize = len(rset)
                    if 39 * min(usize, rsize) < 19 * (usize + rsize):
                        continue
                    inter = len(uset & rset)
                    if near_duplicate(inter, usize + rsize - inter):
                        near_cand = True
                        break

        code = None
        if exact_parent:
            code = "DUP_PARENT"
        elif exact_cand:
            code = "DUP_CANDIDATE"
        elif near_parent:
            code = "NEAR_PARENT"
        elif near_cand:
            code = "NEAR_CANDIDATE"

        if code is None:
            survivors.append(rec)
            retained_exact.add(tkey)
            retained_sets.append(uset)
            ridx = len(retained_sets) - 1
            for feat in uset:
                retained_index.setdefault(feat, []).append(ridx)
            candidate_ids.add(rec["id"])
        else:
            excluded.append({"record_id": rec["id"], "code": code})

    # Reporting order is record-ID order for both lists.
    excluded.sort(key=lambda e: e["record_id"])
    survivors.sort(key=lambda r: r["id"])
    return FilterResult(eligible, excluded, survivors, False)


def record_id_conflicts(records: list[dict], parent_records: list[dict]) -> str | None:
    """A candidate ID repeated against the parent with different content is a
    submission error (RECORD_ID_CONFLICT). Identical content is DUP_PARENT."""
    parent_by_id = {r["id"]: content_key(r) for r in parent_records}
    for rec in records:
        rid = rec.get("id")
        if rid in parent_by_id:
            if not all(isinstance(rec.get(f), str) for f in ("title", "body", "category")):
                return rid
            if content_key(rec) != parent_by_id[rid]:
                return rid
    return None


def validate_candidate_document(records: object) -> list[dict]:
    """Document-level invariants for a candidate artifact body: valid unique
    record IDs sorted ascending. Violations invalidate the whole document."""
    from .errors import ApiError

    if not isinstance(records, list):
        raise ApiError(400, "SCHEMA", "Artifact records must be an array.")
    prev = None
    for i, rec in enumerate(records):
        if not isinstance(rec, dict) or not valid_id(rec.get("id"), "fvrec_"):
            raise ApiError(400, "SCHEMA", f"records[{i}].id must be a valid fvrec_ ID.")
        rid = rec["id"]
        if prev is not None and rid <= prev:
            raise ApiError(400, "SCHEMA", "Artifact records must be sorted by record ID with no repeats.")
        prev = rid
    return records
