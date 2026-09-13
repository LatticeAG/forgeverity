/**
 * ForgeVerity dashboard API client — maps the §9 HTTP surface one-to-one.
 * The bearer token is supplied by the operator per session and is never
 * persisted by this client.
 */

import type {
  AuditPage,
  DecisionCore,
  Job,
  KeysResponse,
  ListPage,
  Manifest,
  Policy,
  Reference,
  Release,
  ReleaseEnvelope,
  Stream,
} from "@forgeverity/schema";

export class ApiClient {
  constructor(
    private readonly baseUrl: string,
    private token: string | null,
  ) {}

  setToken(token: string | null): void {
    this.token = token;
  }

  private async req<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {};
    if (this.token !== null) headers["authorization"] = `Bearer ${this.token}`;
    if (body !== undefined) headers["content-type"] = "application/json";
    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    const parsed = text === "" ? null : (JSON.parse(text) as unknown);
    if (!res.ok) {
      const err = parsed as { error?: { code?: string; message?: string } } | null;
      const code = err?.error?.code ?? `HTTP_${res.status}`;
      throw new ApiError(code, err?.error?.message ?? res.statusText);
    }
    return parsed as T;
  }

  listStreams(cursor?: string): Promise<ListPage<Stream>> {
    return this.req("GET", `/v1/streams${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ""}`);
  }

  getStream(id: string): Promise<Stream> {
    return this.req("GET", `/v1/streams/${encodeURIComponent(id)}`);
  }

  listJobs(streamId: string, cursor?: string): Promise<ListPage<Job>> {
    return this.req(
      "GET",
      `/v1/jobs?stream_id=${encodeURIComponent(streamId)}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
    );
  }

  getJob(id: string): Promise<Job> {
    return this.req("GET", `/v1/jobs/${encodeURIComponent(id)}`);
  }

  getJobReport(id: string): Promise<DecisionCore> {
    return this.req("GET", `/v1/jobs/${encodeURIComponent(id)}/report`);
  }

  getReleaseEnvelope(hash: string): Promise<ReleaseEnvelope> {
    return this.req("GET", `/v1/releases/${encodeURIComponent(hash)}`);
  }

  /** Committed CAS object by digest (manifest, decision, policy, corpus). */
  getBlob<T>(digest: string): Promise<T> {
    return this.req("GET", `/v1/blobs/${encodeURIComponent(digest)}`);
  }

  getManifest(digest: string): Promise<Manifest> {
    return this.getBlob<Manifest>(digest);
  }

  getDecision(digest: string): Promise<DecisionCore> {
    return this.getBlob<DecisionCore>(digest);
  }

  getPolicyObject(digest: string): Promise<Policy> {
    return this.req("GET", `/v1/policies/${encodeURIComponent(digest)}`);
  }

  getReference(id: string): Promise<Reference> {
    return this.req("GET", `/v1/references/${encodeURIComponent(id)}`);
  }

  listAudit(cursor?: string): Promise<AuditPage> {
    return this.req("GET", `/v1/audit${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ""}`);
  }

  getKeys(): Promise<KeysResponse> {
    return this.req("GET", `/v1/keys`);
  }
}

export class ApiError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}
