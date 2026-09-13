"""HTTP API (spec section 9). Thin transport over Service: authentication,
roles, idempotency, pagination cursors, and the closed error-code table.
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .canonical import B, J, MAX_BODY_BYTES, decode_json
from .errors import ApiError
from .ids import id_regex
from .service import CAPABILITIES, READS_PER_MINUTE, MUTATIONS_PER_MINUTE, Service

REQUEST_ID_RE = id_regex("fvreq_")
IDEM_RE = id_regex("fvreq_")
DIGEST_PATH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

MUTATING = {"POST", "PUT"}


class RequestCtx:
    def __init__(self, method, path, headers, body: bytes, services, clock):
        self.method = method
        self.path = path
        self.raw_path, _, self.query = path.partition("?")
        self.headers = headers
        self.body = body
        self.services = services
        self.clock = clock
        self.service: Service | None = None
        self.principal: dict | None = None
        self.request_id = ""
        self.replay_response: tuple[int, dict] | None = None
        self.idem: dict | None = None


def _header(headers, name) -> str | None:
    return headers.get(name)


def handle(ctx: RequestCtx) -> tuple[int, dict | object, dict]:
    """Dispatch one request; returns (status, json_body, extra_headers)."""
    extra: dict[str, str] = {}
    try:
        status, body = _dispatch(ctx)
        return status, body, extra
    except _Replay as replay:
        return replay.status, replay.body, {"Idempotent-Replay": "true"}
    except ApiError as exc:
        headers = {}
        if exc.status == 429:
            headers["Retry-After"] = str(getattr(exc, "retry_after", 1))
        return exc.status, exc.body(ctx.request_id or "fvreq_" + "0" * 21), headers


def _dispatch(ctx: RequestCtx) -> tuple[int, object]:
    path = ctx.raw_path
    if path == "/healthz" and ctx.method == "GET":
        return 200, {"status": "alive"}
    if path == "/readyz" and ctx.method == "GET":
        return _readyz(ctx)

    # Required headers on every API request.
    project_id = _header(ctx.headers, "X-FV-Project")
    request_id = _header(ctx.headers, "X-Request-ID")
    if not project_id or not id_regex("fvprj_").match(project_id):
        raise ApiError(400, "SCHEMA", "Missing or invalid X-FV-Project header.")
    if not request_id or not REQUEST_ID_RE.match(request_id):
        raise ApiError(400, "SCHEMA", "Missing or invalid X-Request-ID header.")
    ctx.request_id = request_id
    service = ctx.services.get(project_id)
    if service is None:
        raise ApiError(404, "NOT_FOUND", "Unknown project.")
    ctx.service = service

    ctx.principal = _authenticate(ctx, service, project_id)
    # Spec 6.1 order: authentication and role, then idempotency replay lookup.
    required = _required_role(ctx.method, ctx.raw_path)
    if required is not None:
        _role(ctx, required)
    if ctx.method in MUTATING:
        _idempotency_lookup(ctx)

    status, obj = _route(ctx)
    return status, obj


def _required_role(method: str, path: str) -> str | None:
    """Least-privileged role for mutating endpoints, for the pre-idempotency
    authorization check. Read endpoints admit every role."""
    parts = [p for p in path.split("/") if p]
    if method == "PUT" and len(parts) == 3 and parts[:2] == ["v1", "blobs"]:
        return "producer"
    if method != "POST":
        return None
    if path in ("/v1/references", "/v1/policies", "/v1/streams"):
        return "admin"
    if len(parts) == 4 and parts[:2] == ["v1", "streams"] and parts[3] == "state":
        return "admin"
    if path == "/v1/jobs":
        return "producer"
    if len(parts) == 4 and parts[:2] == ["v1", "jobs"] and parts[3] == "cancel":
        return "producer"
    if path == "/v1/consumptions":
        return "consumer"
    return None


def _readyz(ctx: RequestCtx) -> tuple[int, object]:
    reasons = []
    for service in ctx.services.values():
        reasons.extend(service.ready_reasons())
    if reasons:
        return 503, {"status": "not_ready", "reason": reasons[0]}
    return 200, {"status": "ready", "schema_version": 1}


def _authenticate(ctx: RequestCtx, service: Service, project_id: str) -> dict:
    auth = _header(ctx.headers, "Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise ApiError(401, "UNAUTHENTICATED", "Missing bearer token.")
    token = auth[7:]
    try:
        principal = service.authenticate(token)
    except ApiError as exc:
        if exc.code == "UNAUTHENTICATED":
            # The token may be bound to a different configured project.
            for pid, other in ctx.services.items():
                if pid == project_id:
                    continue
                try:
                    other.authenticate(token)
                    raise ApiError(403, "FORBIDDEN", "Token is bound to a different project.")
                except ApiError as inner:
                    if inner.code == "FORBIDDEN":
                        raise
                    continue
        raise
    return principal


def _idempotency_lookup(ctx: RequestCtx) -> None:
    key = _header(ctx.headers, "Idempotency-Key")
    if ctx.method == "POST":
        if not key or not IDEM_RE.match(key):
            raise ApiError(400, "SCHEMA", "Missing or invalid Idempotency-Key header.")
        ctx.idem = {
            "principal": ctx.principal["principal_id"],
            "method": ctx.method,
            "path": ctx.raw_path,
            "key": key,
            "request_hash": _request_hash(ctx),
        }
        service = ctx.service
        row = service.idem_lookup(ctx.idem)
        if row is not None:
            if ctx.idem["request_hash"] is None or ctx.idem["request_hash"] != row["request_hash"]:
                raise ApiError(409, "IDEMPOTENCY_CONFLICT", "Idempotency key reused with a different body.")
            raise _Replay(int(row["status"]), decode_json(row["response_json"].encode("utf-8")))
    elif ctx.method == "PUT":
        pass  # PUT blob identity is its digest; no key required.


class _Replay(Exception):
    def __init__(self, status: int, body):
        self.status = status
        self.body = body


def _request_hash(ctx: RequestCtx) -> str | None:
    try:
        return B(decode_json(ctx.body))
    except ApiError:
        return None


def _role(ctx: RequestCtx, *roles: str) -> None:
    if ctx.principal["role"] not in roles and ctx.principal["role"] != "admin":
        raise ApiError(403, "FORBIDDEN", "Insufficient role.")


def _json_body(ctx: RequestCtx) -> object:
    if len(ctx.body) > ctx.service.limits.get("body_bytes", MAX_BODY_BYTES):
        raise ApiError(413, "BODY_LIMIT", "Request body too large.")
    return decode_json(ctx.body)


def _route(ctx: RequestCtx) -> tuple[int, object]:
    m, path, svc = ctx.method, ctx.raw_path, ctx.service
    idem = ctx.idem
    parts = [p for p in path.split("/") if p]

    if m == "GET" and path == "/v1/capabilities":
        _rate(ctx, "read")
        return 200, CAPABILITIES

    if path.startswith("/v1/blobs/") and len(parts) == 3:
        digest = parts[2]
        if not DIGEST_PATH_RE.match(digest):
            raise ApiError(400, "SCHEMA", "Invalid digest.")
        if m == "PUT":
            _role(ctx, "producer")
            _rate(ctx, "mut")
            return svc.put_blob(ctx.body, digest, ctx.principal["role"])
        if m == "GET":
            _rate(ctx, "read")
            return 200, svc.get_blob(digest, ctx.principal["role"])

    if path == "/v1/references":
        if m == "POST":
            _role(ctx, "admin")
            _rate(ctx, "mut")
            return svc.register_reference(_json_body(ctx), idem=idem)
    elif len(parts) == 3 and parts[:2] == ["v1", "references"] and m == "GET":
        _rate(ctx, "read")
        _require_id(parts[2], "fvref_")
        return 200, svc.get_reference(parts[2])

    if path == "/v1/policies":
        if m == "POST":
            _role(ctx, "admin")
            _rate(ctx, "mut")
            return svc.put_policy(_json_body(ctx), idem=idem)
    elif len(parts) == 3 and parts[:2] == ["v1", "policies"] and m == "GET":
        _rate(ctx, "read")
        if not DIGEST_PATH_RE.match(parts[2]):
            raise ApiError(400, "SCHEMA", "Invalid digest.")
        return 200, svc.get_policy_object(parts[2])

    if path == "/v1/streams":
        if m == "POST":
            _role(ctx, "admin")
            _rate(ctx, "mut")
            return svc.create_stream(_json_body(ctx), idem=idem)
        if m == "GET":
            _rate(ctx, "read")
            after, limit = _page_args(ctx)
            return 200, svc.list_streams(after, limit)
    elif len(parts) >= 3 and parts[:2] == ["v1", "streams"]:
        _require_id(parts[2], "fvstr_")
        if len(parts) == 3 and m == "GET":
            _rate(ctx, "read")
            return 200, svc.get_stream_obj(parts[2])
        if len(parts) == 4 and parts[3] == "state" and m == "POST":
            _role(ctx, "admin")
            _rate(ctx, "mut")
            return 200, svc.set_stream_state(parts[2], _json_body(ctx), idem=idem)

    if path == "/v1/jobs":
        if m == "POST":
            _role(ctx, "producer")
            return svc.submit_job(_json_body(ctx), ctx.principal, idem=idem)
        if m == "GET":
            _rate(ctx, "read")
            q = parse_qs(ctx.query)
            stream_id = q.get("stream_id", [None])[0]
            if not stream_id or not id_regex("fvstr_").match(stream_id):
                raise ApiError(400, "SCHEMA", "jobs list requires a stream_id.")
            after, limit = _page_args(ctx)
            return 200, svc.list_jobs(stream_id, after, limit)
    elif len(parts) >= 3 and parts[:2] == ["v1", "jobs"]:
        _require_id(parts[2], "fvjob_")
        if len(parts) == 3 and m == "GET":
            _rate(ctx, "read")
            return 200, svc.get_job_obj(parts[2])
        if len(parts) == 4 and parts[3] == "cancel" and m == "POST":
            _role(ctx, "producer")
            _rate(ctx, "mut")
            return 200, svc.cancel_job(parts[2], ctx.principal, idem=idem)
        if len(parts) == 4 and parts[3] == "report" and m == "GET":
            _rate(ctx, "read")
            return 200, svc.get_report(parts[2])

    if len(parts) == 3 and parts[:2] == ["v1", "releases"] and m == "GET":
        _rate(ctx, "read")
        if not DIGEST_PATH_RE.match(parts[2]):
            raise ApiError(400, "SCHEMA", "Invalid digest.")
        return 200, svc.get_release_envelope(parts[2])
    if len(parts) == 4 and parts[:2] == ["v1", "releases"] and parts[3] == "export" and m == "GET":
        _rate(ctx, "read")
        if not DIGEST_PATH_RE.match(parts[2]):
            raise ApiError(400, "SCHEMA", "Invalid digest.")
        return 200, svc.export_bundle(parts[2])

    if path == "/v1/consumptions" and m == "POST":
        _role(ctx, "consumer")
        _rate(ctx, "mut")
        return svc.consume(_json_body(ctx), ctx.principal, idem=idem)

    if path == "/v1/audit" and m == "GET":
        _rate(ctx, "read")
        after, limit = _page_args(ctx)
        return 200, svc.list_audit(after, limit)

    if path == "/v1/keys" and m == "GET":
        _rate(ctx, "read")
        return 200, svc.get_keys()

    raise ApiError(404, "NOT_FOUND", "Unknown endpoint.")


def _require_id(value: str, prefix: str) -> None:
    if not id_regex(prefix).match(value):
        raise ApiError(400, "SCHEMA", f"Invalid {prefix} ID.")


def _page_args(ctx: RequestCtx) -> tuple[int, int]:
    q = parse_qs(ctx.query)
    if "cursor" in q:
        if "after" in q or "limit" in q:
            raise ApiError(400, "SCHEMA", "cursor requests omit after and limit.")
        return ctx.service.parse_cursor(q["cursor"][0]), 50
    after = q.get("after", ["0"])[0]
    limit = q.get("limit", ["50"])[0]
    try:
        after_i, limit_i = int(after), int(limit)
    except ValueError:
        raise ApiError(400, "SCHEMA", "Invalid pagination parameters.")
    if after_i < 0 or not (1 <= limit_i <= 100):
        raise ApiError(400, "SCHEMA", "Invalid pagination parameters.")
    return after_i, limit_i


def _rate(ctx: RequestCtx, kind: str) -> None:
    if kind == "read":
        ctx.service.rate_limit(f"read:{ctx.service.store.project_id}", READS_PER_MINUTE, 60000)
    else:
        ctx.service.rate_limit(f"mut:{ctx.service.store.project_id}", MUTATIONS_PER_MINUTE, 60000)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    services: dict[str, Service] = {}
    clock = None

    def log_message(self, fmt, *args):  # quiet; structured logs go elsewhere
        pass

    def _handle(self, method: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY_BYTES:
            self._reply(413, {"error": {"code": "BODY_LIMIT", "message": "Request body too large.", "retryable": False, "request_id": "fvreq_" + "0" * 21}})
            return
        body = self.rfile.read(length) if length else b""
        ctx = RequestCtx(method, self.path, self.headers, body, self.services, self.clock)
        try:
            status, obj, extra = handle(ctx)
        except _Replay as replay:
            self._reply(replay.status, replay.body, {"Idempotent-Replay": "true"})
            return
        except Exception:
            self._reply(
                500,
                {"error": {"code": "INTERNAL", "message": "Internal error.", "retryable": False,
                           "request_id": ctx.request_id or "fvreq_" + "0" * 21}},
            )
            return
        self._reply(status, obj, extra)

    def _reply(self, status: int, obj, extra: dict | None = None) -> None:
        data = J(obj)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy", "default-src 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_PUT(self):
        self._handle("PUT")


class ApiServer:
    """Threading HTTP server hosting one or more project services."""

    def __init__(self, services: dict[str, Service], bind: str = "127.0.0.1", port: int = 8742):
        self.services = services

        class _H(Handler):
            pass

        _H.services = services
        self.httpd = ThreadingHTTPServer((bind, port), _H)
        self.httpd.daemon_threads = True

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    def serve_forever(self):
        self.httpd.serve_forever()

    def start_background(self) -> threading.Thread:
        t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        t.start()
        return t

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
