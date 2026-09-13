/**
 * ForgeVerity dashboard shell (spec section 13).
 *
 * Read-mostly static views over the HTTP API: stream list, stream timeline,
 * job detail, release detail, and reference/policy detail. Tables are the
 * primary rendering (accessible alternative to plots); keyboard navigable;
 * manual refresh plus 5-second polling. There is deliberately no accept
 * override, no policy editing, and no "collapse-proof" badge anywhere here.
 */

import { ApiClient } from "./api.js";
import {
  SCOPE_WARNING,
  jobDetail,
  releaseGraph,
  referencePolicyView,
  streamRow,
  timelineSeries,
  verifyCommand,
  type DecisionPoint,
} from "./views.js";
import type { DecisionCore, Job, Manifest, Release, Stream } from "@forgeverity/schema";

type Route =
  | { name: "streams" }
  | { name: "stream"; id: string }
  | { name: "job"; id: string }
  | { name: "release"; hash: string }
  | { name: "refpol"; policyHash: string };

const root = document.getElementById("app") as HTMLElement;
const tokenInput = document.getElementById("token") as HTMLInputElement;
const refreshButton = document.getElementById("refresh") as HTMLButtonElement;
const scopeEl = document.getElementById("scope") as HTMLElement;

scopeEl.textContent = SCOPE_WARNING;
scopeEl.setAttribute("role", "note");

const baseUrl = (document.getElementById("base-url") as HTMLInputElement).value;
const client = new ApiClient(baseUrl, null);

tokenInput.addEventListener("change", () => {
  // Held in memory only; never persisted to storage or embedded in markup.
  client.setToken(tokenInput.value === "" ? null : tokenInput.value);
  void render();
});
refreshButton.addEventListener("click", () => void render());

function route(): Route {
  const h = location.hash.slice(1).split("/");
  if (h[0] === "stream" && h[1]) return { name: "stream", id: decodeURIComponent(h[1]) };
  if (h[0] === "job" && h[1]) return { name: "job", id: decodeURIComponent(h[1]) };
  if (h[0] === "release" && h[1]) return { name: "release", hash: decodeURIComponent(h[1]) };
  if (h[0] === "refpol" && h[1]) return { name: "refpol", policyHash: decodeURIComponent(h[1]) };
  return { name: "streams" };
}

window.addEventListener("hashchange", () => void render());

function el(tag: string, attrs: Record<string, string> = {}, text?: string): HTMLElement {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  if (text !== undefined) e.textContent = text;
  return e;
}

function table(headers: string[], rows: string[][]): HTMLElement {
  const t = el("table", { role: "table" });
  const thead = el("thead");
  const tr = el("tr");
  for (const h of headers) tr.appendChild(el("th", { scope: "col" }, h));
  thead.appendChild(tr);
  const tbody = el("tbody");
  for (const row of rows) {
    const r = el("tr", { tabindex: "0" });
    for (const cell of row) r.appendChild(el("td", {}, cell));
    tbody.appendChild(r);
  }
  t.appendChild(thead);
  t.appendChild(tbody);
  return t;
}

async function render(): Promise<void> {
  const r = route();
  root.replaceChildren();
  try {
    if (r.name === "streams") await renderStreams();
    else if (r.name === "stream") await renderStream(r.id);
    else if (r.name === "job") await renderJob(r.id);
    else if (r.name === "release") await renderRelease(r.hash);
    else await renderRefPol(r.policyHash);
  } catch (exc) {
    root.appendChild(el("p", { role: "alert" }, `Failed to load view: ${(exc as Error).message}`));
  }
}

async function renderStreams(): Promise<void> {
  root.appendChild(el("h2", {}, "Streams"));
  const page = await client.listStreams();
  const rows: string[][] = [];
  for (const s of page.items) {
    const jobs = await client.listJobs(s.id);
    const latest = [...jobs.items].reverse().find((j) => j.receipt_hash !== null) ?? jobs.items[jobs.items.length - 1] ?? null;
    const v = streamRow(s, latest);
    rows.push([v.id, v.state, String(v.revision), v.reference_pin, v.policy_pin, v.head, v.latest_verdict]);
  }
  root.appendChild(
    table(["stream", "state", "rev", "reference pin", "policy pin", "head", "latest verdict"], rows),
  );
  const nav = el("nav", { "aria-label": "streams" });
  for (const s of page.items) {
    nav.appendChild(el("a", { href: `#/stream/${encodeURIComponent(s.id)}` }, `open ${s.id}`));
    nav.appendChild(document.createTextNode(" "));
  }
  root.appendChild(nav);
}

async function renderStream(id: string): Promise<void> {
  const stream = await client.getStream(id);
  root.appendChild(el("h2", {}, `Stream ${stream.id}`));
  root.appendChild(
    el(
      "p",
      {},
      `state ${stream.state} · revision ${stream.revision} · reference ${stream.reference_hash} · policy ${stream.policy_hash}`,
    ),
  );

  const jobs = await client.listJobs(id);
  const points: DecisionPoint[] = [];
  const seen = new Set<string>();
  for (const job of jobs.items) {
    if (job.release_hash === null || seen.has(job.release_hash)) continue;
    seen.add(job.release_hash);
    let release: Release;
    try {
      release = (await client.getReleaseEnvelope(job.release_hash)).release;
    } catch {
      continue;
    }
    let decision: DecisionCore | null = null;
    if (release.decision_hash !== null) {
      try {
        decision = await client.getDecision(release.decision_hash);
      } catch {
        decision = null;
      }
    }
    points.push({ release, decision, job });
  }
  for (const s of timelineSeries(points)) {
    root.appendChild(el("h3", {}, s.label));
    root.appendChild(
      table(
        ["revision", "value", "verdict"],
        s.points.map((p) => [String(p.revision), p.value === null ? "gap" : String(p.value), p.verdict]),
      ),
    );
  }

  const nav = el("nav", { "aria-label": "stream detail" });
  nav.appendChild(
    el(
      "a",
      { href: `#/refpol/${encodeURIComponent(stream.policy_hash)}` },
      "reference/policy detail",
    ),
  );
  nav.appendChild(document.createTextNode(" "));
  if (stream.head_release_hash) {
    nav.appendChild(el("a", { href: `#/release/${encodeURIComponent(stream.head_release_hash)}` }, "head release"));
  }
  root.appendChild(nav);

  root.appendChild(el("h3", {}, "Jobs"));
  root.appendChild(
    table(
      ["job", "state", "attempt", "decision"],
      jobs.items.map((j) => [j.id, j.state, String(j.attempt), j.decision_hash ?? "none"]),
    ),
  );
  const jnav = el("nav", { "aria-label": "jobs" });
  for (const j of jobs.items) {
    jnav.appendChild(el("a", { href: `#/job/${encodeURIComponent(j.id)}` }, `open ${j.id}`));
    jnav.appendChild(document.createTextNode(" "));
  }
  root.appendChild(jnav);
}

async function renderJob(id: string): Promise<void> {
  const job = await client.getJob(id);
  let decision: DecisionCore | null = null;
  try {
    decision = await client.getJobReport(id);
  } catch {
    decision = null;
  }
  const d = jobDetail(job, decision);
  root.appendChild(el("h2", {}, `Job ${d.job_id}`));
  root.appendChild(
    table(
      ["field", "value"],
      [
        ["state", d.state],
        ["verdict", d.verdict],
        ["submitted", d.submitted_count === null ? "gap" : String(d.submitted_count)],
        ["retained", d.retained_count === null ? "gap" : String(d.retained_count)],
        ["reasons", d.reasons.join(", ") || "none"],
        ["policy pin", d.pins.policy_hash],
        ["reference pin", d.pins.reference_hash],
        ["trust pin", d.pins.trust_hash],
        ["receipt", d.receipt_status],
      ],
    ),
  );
  if (d.exclusions.length > 0) {
    root.appendChild(el("h3", {}, "Exclusions"));
    root.appendChild(
      table(
        ["record", "code"],
        d.exclusions.map((e) => [e.record_id, e.code]),
      ),
    );
  }
  if (d.sample_sizes.reference !== null) {
    root.appendChild(el("h3", {}, "Sample sizes"));
    root.appendChild(
      table(
        ["sample", "count"],
        [
          ["reference", String(d.sample_sizes.reference)],
          ["parent", String(d.sample_sizes.parent)],
          ["proposed", String(d.sample_sizes.proposed)],
        ],
      ),
    );
  }
}

async function renderRelease(hash: string): Promise<void> {
  const env = await client.getReleaseEnvelope(hash);
  const manifest = await client.getManifest(env.release.manifest_hash);
  let decision: DecisionCore | null = null;
  if (env.release.decision_hash !== null) {
    try {
      decision = await client.getDecision(env.release.decision_hash);
    } catch {
      decision = null;
    }
  }
  const g = releaseGraph(env.release, manifest, decision);
  root.appendChild(el("h2", {}, `Release ${hash}`));
  root.appendChild(
    table(
      ["node", "kind"],
      g.nodes.map((n) => [n.digest, n.kind]),
    ),
  );
  root.appendChild(
    table(
      ["from", "to", "edge"],
      g.edges.map((e) => [e.from, e.to, e.kind]),
    ),
  );
  root.appendChild(el("h3", {}, "Verify locally"));
  const cmd = el("code", {}, verifyCommand(hash));
  cmd.setAttribute("aria-label", "local verification command");
  root.appendChild(cmd);
}

async function renderRefPol(policyHash: string): Promise<void> {
  const policy = await client.getPolicyObject(policyHash);
  const reference = await client.getReference(policy.reference_id);
  const v = referencePolicyView(reference, policy.reference_hash, policy, policyHash);
  root.appendChild(el("h2", {}, "Reference / policy"));
  root.appendChild(
    table(
      ["field", "value"],
      [
        ["reference", v.reference_id],
        ["suite", v.suite],
        ["origin source", v.origin_source],
        ["train", v.train_hash],
        ["holdout", `${v.holdout_hash} (digest only — text withheld)`],
        ["categories", v.categories.join(", ")],
      ],
    ),
  );
  root.appendChild(el("h3", {}, "Gate thresholds"));
  root.appendChild(
    table(
      ["gate", "value"],
      v.gates.map((g) => [g.name, String(g.value)]),
    ),
  );
}

// 5-second polling plus manual refresh; no WebSocket/SSE in v1.
setInterval(() => void render(), 5000);
void render();
