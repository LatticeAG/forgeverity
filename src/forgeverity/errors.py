"""ForgeVerity typed errors.

`ApiError` carries an HTTP status plus a code from the closed error-code set
in spec section 9.1. `VerifyError` carries a code from the SDK verify failure
set in section 9.4. `EvaluationError` is raised by the deterministic pipeline
for non-computable input and maps to a FAILED job (or a verify failure code),
never to a numerical zero.
"""

from __future__ import annotations

# Closed error-code sets per HTTP status (spec section 9.1 table), plus the
# two job-error-only codes RESOURCE_LIMIT and ATTEMPT_LIMIT and the SDK-only
# REPLAY_MISMATCH.
CODES_BY_STATUS: dict[int, frozenset[str]] = {
    400: frozenset(
        {
            "INVALID_JSON",
            "DUPLICATE_KEY",
            "SCHEMA",
            "NONCANONICAL",
            "UNKNOWN_FIELD",
            "RECORD_ID_CONFLICT",
        }
    ),
    401: frozenset({"UNAUTHENTICATED", "TOKEN_EXPIRED"}),
    403: frozenset({"FORBIDDEN", "KEY_REVOKED", "SIGNATURE_INVALID", "TRUST_MISMATCH"}),
    404: frozenset({"NOT_FOUND"}),
    409: frozenset(
        {
            "REVISION_CONFLICT",
            "STREAM_PAUSED",
            "IDEMPOTENCY_CONFLICT",
            "TERMINAL_STATE",
            "NOT_READY",
            "RETRY_EXHAUSTED",
            "SUCCESSOR_EXISTS",
            "PREDECESSOR_INVALID",
            "LEASE_LOST",
        }
    ),
    413: frozenset({"BODY_LIMIT", "RECORD_LIMIT"}),
    422: frozenset(
        {"HASH_MISMATCH", "REFERENCE_INVALID", "GENERATION_BINDING", "UNSUPPORTED_VERSION"}
    ),
    429: frozenset({"RATE_LIMIT", "QUEUE_LIMIT"}),
    500: frozenset({"INTERNAL", "ARTIFACT_CORRUPT", "SIGNING_UNAVAILABLE"}),
    503: frozenset({"CLOCK_UNSAFE", "STORAGE_UNAVAILABLE", "WORKER_UNAVAILABLE"}),
}
JOB_ERROR_CODES = frozenset({"RESOURCE_LIMIT", "ATTEMPT_LIMIT"})
VERIFY_CODES = frozenset(
    {
        "SCHEMA",
        "HASH_MISMATCH",
        "SIGNATURE_INVALID",
        "TRUST_MISMATCH",
        "UNSUPPORTED_VERSION",
        "REPLAY_MISMATCH",
    }
)
RETRYABLE_CODES = frozenset({"RATE_LIMIT", "QUEUE_LIMIT", "CLOCK_UNSAFE", "STORAGE_UNAVAILABLE", "WORKER_UNAVAILABLE"})

STATUS_MESSAGES = {
    "INVALID_JSON": "Request body is not valid UTF-8 JSON.",
    "DUPLICATE_KEY": "Request body contains a duplicate object key.",
    "SCHEMA": "Request failed schema validation.",
    "NONCANONICAL": "Artifact body is not in canonical RFC8785 form.",
    "UNKNOWN_FIELD": "Request contains an unknown field.",
    "RECORD_ID_CONFLICT": "Record ID conflicts with existing corpus content.",
    "UNAUTHENTICATED": "Authentication credentials are missing or invalid.",
    "TOKEN_EXPIRED": "Bearer token is expired or revoked.",
    "FORBIDDEN": "The authenticated principal may not perform this operation.",
    "KEY_REVOKED": "A required key has been revoked.",
    "SIGNATURE_INVALID": "Signature verification failed.",
    "TRUST_MISMATCH": "The object does not match the pinned trust snapshot.",
    "NOT_FOUND": "The requested object does not exist.",
    "REVISION_CONFLICT": "Stream revision does not match.",
    "STREAM_PAUSED": "The stream is paused.",
    "IDEMPOTENCY_CONFLICT": "Idempotency key was reused with a different body.",
    "TERMINAL_STATE": "The job is already in a terminal state.",
    "NOT_READY": "The requested object is not ready yet.",
    "RETRY_EXHAUSTED": "The retry chain budget is exhausted.",
    "SUCCESSOR_EXISTS": "The rejected job already has a reserved successor.",
    "PREDECESSOR_INVALID": "The named retry predecessor is not usable.",
    "LEASE_LOST": "The worker lease was lost.",
    "BODY_LIMIT": "Request body exceeds the byte limit.",
    "RECORD_LIMIT": "Artifact exceeds the record limit.",
    "HASH_MISMATCH": "Digest does not match the supplied bytes.",
    "REFERENCE_INVALID": "The reference failed registration validation.",
    "GENERATION_BINDING": "Generation assertion fields do not match the request.",
    "UNSUPPORTED_VERSION": "Schema or suite version is not supported.",
    "RATE_LIMIT": "Rate limit exceeded.",
    "QUEUE_LIMIT": "Queue limit exceeded.",
    "INTERNAL": "Internal error.",
    "ARTIFACT_CORRUPT": "A referenced artifact is absent, malformed, or corrupt.",
    "SIGNING_UNAVAILABLE": "Receipt signing is unavailable.",
    "CLOCK_UNSAFE": "Service clock rollback detected.",
    "STORAGE_UNAVAILABLE": "Storage is unavailable.",
    "WORKER_UNAVAILABLE": "No worker or online binding is available.",
    "RESOURCE_LIMIT": "Job exceeded its resource limit.",
    "ATTEMPT_LIMIT": "Job exceeded its attempt limit.",
    "REPLAY_MISMATCH": "Recomputed decision does not match the recorded decision.",
}


class ApiError(Exception):
    """Error carrying an HTTP status and a closed-set code."""

    def __init__(self, status: int, code: str, message: str | None = None, retryable: bool | None = None):
        allowed = CODES_BY_STATUS.get(status)
        if allowed is not None and code not in allowed and code not in JOB_ERROR_CODES:
            raise ValueError(f"code {code} not permitted for status {status}")
        self.status = status
        self.code = code
        if retryable is None:
            retryable = code in RETRYABLE_CODES
        self.retryable = retryable
        msg = message if message is not None else STATUS_MESSAGES.get(code, code)
        self.message = msg[:256]
        super().__init__(f"{status} {code}: {self.message}")

    def body(self, request_id: str) -> dict:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "retryable": self.retryable,
                "request_id": request_id,
            }
        }


class EvaluationError(Exception):
    """A deterministic-pipeline input could not be evaluated (job FAILED)."""

    def __init__(self, code: str, message: str | None = None):
        self.code = code
        self.message = (message or STATUS_MESSAGES.get(code, code))[:256]
        super().__init__(f"{code}: {self.message}")


class VerifyError(Exception):
    """SDK verification failure carrying a verify-scoped code."""

    def __init__(self, code: str, message: str | None = None):
        if code not in VERIFY_CODES:
            raise ValueError(f"code {code} is not a verify failure code")
        self.code = code
        self.message = (message or STATUS_MESSAGES.get(code, code))[:256]
        super().__init__(f"{code}: {self.message}")
