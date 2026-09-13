"""SDK client binding (spec section 9.4): a typed HTTP client and a local
in-process client with the same surface. Errors throw ApiError (the Python
ErrorResponse analogue)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from .canonical import J
from .errors import ApiError
from .ids import new_id


class HttpClient:
    def __init__(self, base_url: str, token: str, project_id: str):
        self.base = base_url.rstrip("/")
        self.token = token
        self.project_id = project_id

    def _req(self, method: str, path: str, body=None, idem_key: str | None = None, raw_body: bytes | None = None):
        url = self.base + path
        data = raw_body if raw_body is not None else (J(body) if body is not None else None)
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("X-FV-Project", self.project_id)
        req.add_header("X-Request-ID", new_id("fvreq_"))
        req.add_header("Authorization", f"Bearer {self.token}")
        if idem_key:
            req.add_header("Idempotency-Key", idem_key)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as exc:
            try:
                obj = json.loads(exc.read())
                err = obj.get("error", {})
                raise ApiError(exc.code, err.get("code", "INTERNAL"), err.get("message", ""), retryable=err.get("retryable", False))
            except json.JSONDecodeError:
                raise ApiError(exc.code, "INTERNAL", "Non-JSON error response.")
        except urllib.error.URLError as exc:
            raise ApiError(503, "WORKER_UNAVAILABLE", f"Request failed: {exc.reason}") from exc

    def capabilities(self):
        return self._req("GET", "/v1/capabilities")[1]

    def get_blob(self, digest: str):
        return self._req("GET", f"/v1/blobs/{digest}")[1]

    def put_blob(self, digest: str, content: bytes):
        return self._req("PUT", f"/v1/blobs/{digest}", raw_body=content)

    def register_reference(self, body, idem_key=None):
        return self._req("POST", "/v1/references", body=body, idem_key=idem_key or new_id("fvreq_"))

    def put_policy(self, body, idem_key=None):
        return self._req("POST", "/v1/policies", body=body, idem_key=idem_key or new_id("fvreq_"))

    def get_policy(self, digest):
        return self._req("GET", f"/v1/policies/{digest}")[1]

    def get_reference(self, ref_id):
        return self._req("GET", f"/v1/references/{ref_id}")[1]

    def create_stream(self, body, idem_key=None):
        return self._req("POST", "/v1/streams", body=body, idem_key=idem_key or new_id("fvreq_"))

    def get_stream(self, stream_id):
        return self._req("GET", f"/v1/streams/{stream_id}")[1]

    def list_streams(self, **q):
        qs = "&".join(f"{k}={v}" for k, v in q.items() if v is not None)
        return self._req("GET", "/v1/streams" + ("?" + qs if qs else ""))[1]

    def set_stream_state(self, stream_id, state, idem_key=None):
        return self._req("POST", f"/v1/streams/{stream_id}/state", body={"state": state}, idem_key=idem_key or new_id("fvreq_"))

    def submit_job(self, body, idem_key=None):
        return self._req("POST", "/v1/jobs", body=body, idem_key=idem_key or new_id("fvreq_"))

    def get_job(self, job_id):
        return self._req("GET", f"/v1/jobs/{job_id}")[1]

    def list_jobs(self, stream_id, **q):
        qs = "&".join(f"{k}={v}" for k, v in q.items() if v is not None)
        return self._req("GET", f"/v1/jobs?stream_id={stream_id}" + ("&" + qs if qs else ""))[1]

    def cancel_job(self, job_id, idem_key=None):
        return self._req("POST", f"/v1/jobs/{job_id}/cancel", body=None, idem_key=idem_key or new_id("fvreq_"))

    def get_report(self, job_id):
        return self._req("GET", f"/v1/jobs/{job_id}/report")[1]

    def get_release(self, digest):
        return self._req("GET", f"/v1/releases/{digest}")[1]

    def get_export(self, digest):
        return self._req("GET", f"/v1/releases/{digest}/export")[1]

    def consume(self, body, idem_key=None):
        return self._req("POST", "/v1/consumptions", body=body, idem_key=idem_key or new_id("fvreq_"))

    def list_audit(self, **q):
        qs = "&".join(f"{k}={v}" for k, v in q.items() if v is not None)
        return self._req("GET", "/v1/audit" + ("?" + qs if qs else ""))[1]

    def get_keys(self):
        return self._req("GET", "/v1/keys")[1]


class LocalClient:
    """In-process client over a local Service — same surface, for CLI use on
    the machine hosting the deployment."""

    def __init__(self, service, token: str):
        self.service = service
        self.principal = service.authenticate(token)

    def capabilities(self):
        from .service import CAPABILITIES
        return CAPABILITIES

    def get_blob(self, digest):
        return self.service.get_blob(digest, self.principal["role"])

    def put_blob(self, digest, content):
        return self.service.put_blob(content, digest, self.principal["role"])

    def register_reference(self, body, idem_key=None):
        return self.service.register_reference(body)

    def put_policy(self, body, idem_key=None):
        return self.service.put_policy(body)

    def get_policy(self, digest):
        return self.service.get_policy_object(digest)

    def get_reference(self, ref_id):
        return self.service.get_reference(ref_id)

    def create_stream(self, body, idem_key=None):
        return self.service.create_stream(body)

    def get_stream(self, stream_id):
        return self.service.get_stream_obj(stream_id)

    def list_streams(self, after=0, limit=50, **q):
        return self.service.list_streams(after, limit)

    def set_stream_state(self, stream_id, state, idem_key=None):
        return self.service.set_stream_state(stream_id, {"state": state})

    def submit_job(self, body, idem_key=None):
        return self.service.submit_job(body, self.principal)

    def get_job(self, job_id):
        return self.service.get_job_obj(job_id)

    def list_jobs(self, stream_id, after=0, limit=50, **q):
        return self.service.list_jobs(stream_id, after, limit)

    def cancel_job(self, job_id, idem_key=None):
        return self.service.cancel_job(job_id, self.principal)

    def get_report(self, job_id):
        return self.service.get_report(job_id)

    def get_release(self, digest):
        return self.service.get_release_envelope(digest)

    def get_export(self, digest):
        return self.service.export_bundle(digest)

    def consume(self, body, idem_key=None):
        return self.service.consume(body, self.principal)

    def list_audit(self, after=0, limit=50, **q):
        return self.service.list_audit(after, limit)

    def get_keys(self):
        return self.service.get_keys()
