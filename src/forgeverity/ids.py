"""Identifier allocation and validation.

Every ID is `PREFIX` + 21 characters from [A-Za-z0-9_-], generated with a
CSPRNG in production. Prefixes never encode authorization.
"""

from __future__ import annotations

import re
import secrets

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
SUFFIX_LEN = 21

PREFIXES = (
    "fvprj_",
    "fvsrc_",
    "fvref_",
    "fvstr_",
    "fvrec_",
    "fvjob_",
    "fvent_",
    "fvkey_",
    "fvcon_",
    "fvwrk_",
    "fvreq_",
    "fvact_",
)


def new_id(prefix: str) -> str:
    if prefix not in PREFIXES:
        raise ValueError(f"unknown id prefix {prefix!r}")
    return prefix + "".join(secrets.choice(ALPHABET) for _ in range(SUFFIX_LEN))


def id_regex(prefix: str) -> re.Pattern[str]:
    return re.compile(r"^" + re.escape(prefix) + r"[A-Za-z0-9_-]{21}$")


def valid_id(value: object, prefix: str) -> bool:
    return isinstance(value, str) and bool(id_regex(prefix).match(value))


def csprng_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)
