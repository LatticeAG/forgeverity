# ForgeVerity

[![CI](https://github.com/LatticeAG/forgeverity/actions/workflows/ci.yml/badge.svg)](https://github.com/LatticeAG/forgeverity/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](pyproject.toml)
[![Protocol](https://img.shields.io/badge/protocol-fv.http%2F1-blue.svg)](#http-api)
[![Suite](https://img.shields.io/badge/suite-tickets--lexical--1-blue.svg)](#what-it-checks)

**ForgeVerity** is the LatticeAG deterministic acceptance gate for synthetic
training data. A data engineer pins a real-data reference, an immutable policy,
and a signed generator provenance assertion, then submits a synthetic candidate
batch against one immutable training-stream head. ForgeVerity filters invalid
and redundant candidates, measures the resulting proposed corpus with exact
rational arithmetic, and fails closed. Acceptance atomically advances the
stream head and issues a signed, hash-chained release receipt.

> Passing means exactly this: **"Passed tickets-lexical-1 checks; not a
> guarantee against model collapse."** ForgeVerity is a statistical gate, not a
> validated anti-collapse intervention.

## What it checks

Suite `tickets-lexical-1` (English ASCII support tickets only):

- **Filtering** — record shape, ASCII/token rules, closed category taxonomy,
  exact and near-duplicate removal against the parent corpus and within the
  candidate batch (Jaccard >= 0.95 on unigram+adjacent-bigram sets, compared as
  exact rationals), and a batch-level holdout-leak check that runs before any
  deduplication.
- **Metrics** — order-2 (Renyi) Vendi effective rank over the set-Jaccard
  kernel, precision-only self-BLEU-2 with integer square root, category
  coverage ratios, full-corpus synthetic fraction, filter fraction, and a
  `collapse_proxy_bps` display score. No floats, no eigensolver, no GPU:
  identical `DecisionCore` bytes on every supported machine.
- **Gate** — `TOO_FEW_VALID`, `FILTER_BUDGET`, `CORPUS_LIMIT`,
  `REPLACE_FORBIDDEN`, `SYNTHETIC_LIMIT`, `REFERENCE_DIVERSITY`,
  `PARENT_DIVERSITY`, `REPETITION`, `CATEGORY_LOSS`, evaluated in a fixed
  order; `HOLDOUT_LEAK` short-circuits. There is no override, warning-only
  mode, or pass-on-timeout path.
- **Provenance** — every mutation appends to a per-project Ed25519-signed,
  hash-chained audit log (`forgeverity.audit.v1` / `forgeverity.receipt.v1`
  domains). Accepted releases bind manifest, decision, policy, reference,
  suite, stream, and revision. `fv.sunlight-export/1` bundles are verifiable
  offline against an out-of-band pinned receipt root.

## Install

```bash
pip install -e .          # Python 3.12+
forgeverity --version
python -m forgeverity --version
```

TypeScript packages (`@forgeverity/schema`, `@forgeverity/verifier`) and the
static dashboard live under `packages/` and `apps/dashboard`:

```bash
npm run build -w packages/schema -w packages/verifier
npm test -w packages/schema -w packages/verifier
npm run build -w apps/dashboard
```

## Quick start (local)

```bash
forgeverity init --directory . --project fvprj_000000000000000000001 --json
forgeverity key generate --purpose receipt   --out secrets/receipt.json
forgeverity key generate --purpose origin    --out secrets/origin.json
forgeverity key generate --purpose generator --out secrets/generator.json
# write .devin/forgeverity-trust.json pinning the three public keys, then:
forgeverity token issue --principal fvact_000000000000000000001 --role admin --ttl-seconds 300 --out secrets/token.json
forgeverity serve --bind 127.0.0.1 --port 8742 &   # plus: forgeverity worker
export FORGEVERITY_TOKEN=...                        # contents of secrets/token.json
forgeverity reference register --train train.json --holdout holdout.json \
    --source fvsrc_000000000000000000001 --key-id fvkey_000000000000000000002 --json
forgeverity policy register --file policy.json --json
forgeverity stream create --policy sha256:... --reference fvref_... --json
forgeverity submit --request job.json --candidate candidate.json --wait --json
forgeverity report fvjob_... --json
forgeverity consume --stream fvstr_... --expected-revision 1 \
    --release sha256:... --consumer training-run --out corpus/ --json
forgeverity export sunlight --release sha256:... --out export.json --json
forgeverity verify export.json --trust .devin/forgeverity-trust.json --json
```

See `forgeverity <command> --help` for the exact flag contract of each command.

## Layout

| Path | Contents |
|---|---|
| `src/forgeverity/` | MIT Python core: `canonical`, `schema`, `filter`, `metrics`, `gate`, `store`, `audit`, `api`, `cli`, `forgedistill`, `verify`, `service` |
| `tests/` | Conformance vectors `TV-F--01..64`, HTTP catalog examples, store/race tests |
| `tests/vectors/` | Executable fixture materializer (spec §9.2) |
| `packages/schema` | TS canonicalize/digest/strict-decode/validators |
| `packages/verifier` | TS export-bundle verifier (historical mode) |
| `apps/dashboard` | Static TS dashboard (stream list, timeline, job/release/reference views) |

## HTTP API

Base path `/v1`, `Content-Type: application/json`, `Authorization: Bearer
<opaque 256-bit project-bound token>`, `X-FV-Project`, `X-Request-ID`,
`Idempotency-Key` on POST mutations. Endpoints: `GET /v1/capabilities`,
`PUT|GET /v1/blobs/{digest}`, `POST|GET /v1/references`,
`POST|GET /v1/policies`, `POST|GET /v1/streams`, `POST
/v1/streams/{id}/state`, `POST|GET /v1/jobs`, `POST /v1/jobs/{id}/cancel`,
`GET /v1/jobs/{id}/report`, `GET /v1/releases/{hash}`,
`GET /v1/releases/{hash}/export`, `POST /v1/consumptions`, `GET /v1/audit`,
`GET /v1/keys`, plus unauthenticated `/healthz` and `/readyz`.

## Hosted scoring

Hosted scoring is the paid LatticeAG surface and is **not** part of this MIT
repository. `forgeverity.hosted` exposes the documented stub interfaces; every
entry point raises `NotImplementedError` pointing at
<https://github.com/LatticeAG/forgeverity#hosted-scoring>. Local and hosted
builds share decision code and gate defaults; hosting never changes
thresholds.

## Security model (summary)

Reference issuers, project administrators, service receipt keys, and consumers
are separate trust roles. A receipt proves what the authorized gate recorded —
not that the gate operator or reference issuer was honest. Rejected data never
enters the release/consume interface; the candidate blob's holdout is never
readable by producers. Independent replay recomputes the deterministic
`DecisionCore`; an exported checkpoint detects later chain truncation.
