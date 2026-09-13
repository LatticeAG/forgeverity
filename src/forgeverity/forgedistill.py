"""ForgeDistill adapter (spec section 10.3). ForgeDistill is an external
generator process owned by its own repo; this adapter exchanges exactly one
canonical JSON object per stream, validates the output, and signs the
Generation assertion with the configured generator key before upload. The
generator receives no holdout, reference hash, audit key, service token, or
server path."""

from __future__ import annotations

import json
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import audit as audit_mod
from .canonical import B, J
from .errors import ApiError
from .schema import validate_generate_request, validate_generated

MAX_STDOUT_BYTES = 16 * 1024 * 1024
MAX_STDERR_BYTES = 4096


class ForgeDistillAdapter:
    """Spawn the configured executable once per round: argv + clean env, no
    shell, stdin closed after the request. Output above 16 MiB, more than one
    JSON document, nonzero exit, timeout, or invalid schema aborts the round.
    A timeout kills the entire spawned process group."""

    def __init__(self, executable: str, args: list[str] | None = None, timeout_ms: int = 300000):
        self.executable = executable
        self.args = args or []
        self.timeout_ms = timeout_ms

    def _run(self, request: dict) -> dict:
        req = validate_generate_request(request)
        try:
            proc = subprocess.Popen(
                [self.executable, *self.args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={},
                start_new_session=True,
            )
        except (FileNotFoundError, PermissionError, OSError) as exc:
            raise ApiError(503, "WORKER_UNAVAILABLE", "ForgeDistill executable could not be launched.") from exc
        try:
            stdout, stderr = proc.communicate(input=J(req), timeout=self.timeout_ms / 1000)
        except subprocess.TimeoutExpired:
            try:
                import os, signal

                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            proc.wait()
            raise ApiError(503, "WORKER_UNAVAILABLE", "ForgeDistill timed out.")
        if proc.returncode != 0:
            raise ApiError(503, "WORKER_UNAVAILABLE", "ForgeDistill exited nonzero.")
        if len(stdout) > MAX_STDOUT_BYTES:
            raise ApiError(400, "SCHEMA", "ForgeDistill output exceeds 16 MiB.")
        # Exactly one JSON document (a single trailing newline is allowed).
        raw = stdout[:-1] if stdout.endswith(b"\n") else stdout
        try:
            text = raw.decode("utf-8", "strict")
            obj, end = json.JSONDecoder().raw_decode(text)
            if text[end:].strip():
                raise ApiError(400, "SCHEMA", "ForgeDistill emitted more than one document.")
        except UnicodeDecodeError as exc:
            raise ApiError(400, "SCHEMA", "ForgeDistill output is not UTF-8.") from exc
        except json.JSONDecodeError as exc:
            raise ApiError(400, "SCHEMA", "ForgeDistill output is not JSON.") from exc
        return validate_generated(obj)

    def generate_round(
        self,
        *,
        project_id: str,
        stream_id: str,
        expected_revision: int,
        round_no: int,
        seed: str,
        count: int,
        categories: list[str],
        feedback: list[str],
        key_id: str,
        key_pem: bytes,
        created_at_ms: int,
    ) -> dict:
        """One generate round -> {generation, artifact, candidate_hash}."""
        request = {
            "v": "fv.generate/1",
            "stream_id": stream_id,
            "round": round_no,
            "seed": seed,
            "count": count,
            "categories": categories,
            "feedback": feedback,
        }
        out = self._run(request)
        artifact = out["artifact"]
        candidate_hash = B(artifact)
        generation = audit_mod.make_generation_assertion(
            {
                "project_id": project_id,
                "stream_id": stream_id,
                "expected_revision": expected_revision,
                "candidate_hash": candidate_hash,
                "generator_version": out["generator_version"],
                "generator_config_hash": out["generator_config_hash"],
                "model_artifact_hash": out["model_artifact_hash"],
                "parent_model_hash": out["parent_model_hash"],
                "prompt_hash": out["prompt_hash"],
                "seed": out["seed"],
                "created_at_ms": created_at_ms,
                "key_id": key_id,
            },
            _load_priv(key_pem),
        )
        return {"generation": generation, "artifact": artifact, "candidate_hash": candidate_hash}


def _load_priv(pem: bytes) -> Ed25519PrivateKey:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    return load_pem_private_key(pem, password=None)
