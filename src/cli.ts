import { mkdir, readFile, writeFile } from "node:fs/promises";
import { appendProvenanceRecord, contentDigestOfText, readProvenanceRegistry,
  type ProvenanceOrigin, type ProvenanceTrust } from "./provenance.js";
import { validateAgentCard } from "./a2a/card.js";
import {
  appendDelegationRecord,
  evaluateDelegatedToolCall,
  grantIdOf,
  readDelegationRegistry,
  type DelegatedDecision,
  type DelegationGrant,
  type DelegationRecord,
} from "./a2a/delegation.js";
import { isJsonObject, type JsonObject } from "./lib/json.js";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { diffSnapshots, type SnapshotDiff } from "./diff.js";
import { scanRoot } from "./discover.js";
import { evaluatePolicy, type Allowlist } from "./policy.js";
import { findingsOf, renderMarkdownReport, scanReportOf } from "./report.js";
import { resolveFromProcessEnv } from "./parse.js";
import { readGatewayConfig } from "./gateway/config.js";
import { createGateway } from "./gateway/server.js";
import { verifyLedger } from "./gateway/ledger.js";
import { verifyChain } from "./lib/chain.js";
import { fingerprintOf, readSnapshotFile, snapshotOf, writeSnapshotFile } from "./snapshot.js";
import { VERSION } from "./version.js";

interface CommandLine {
  readonly command: string;
  readonly positional: readonly string[];
  readonly flags: ReadonlyMap<string, string | true>;
}

const FLAG_WITH_VALUE = new Set(["--allowlist", "--config", "--out", "--root", "--origin", "--trust", "--source", "--labeled-by", "--from", "--to", "--tools", "--granted-by", "--expires-at", "--revoked-by", "--grant", "--tool", "--identity", "--arguments", "--via", "--now"]);

function parseCommandLine(argv: readonly string[]): CommandLine | null {
  if (argv.length === 0) return null;
  const [command, ...rest] = argv;
  if (command === undefined) return null;
  const positional: string[] = [];
  const flags = new Map<string, string | true>();
  for (let i = 0; i < rest.length; i++) {
    const token = rest[i]!;
    if (!token.startsWith("--")) {
      positional.push(token);
      continue;
    }
    if (FLAG_WITH_VALUE.has(token)) {
      const value = rest[i + 1];
      if (value === undefined || value.startsWith("--")) return null;
      flags.set(token, value);
      i++;
    } else {
      flags.set(token, true);
    }
  }
  return { command, positional, flags };
}

const USAGE = `rulehouse ${VERSION} — Continuous assurance for Atlassian MCP configurations

Usage:
  rulehouse scan <root> [--allowlist <file>] [--out <dir>] [--strict]
  rulehouse diff <baseline.json> <current.json>
  rulehouse verify <snapshot.json> --root <root>
  rulehouse serve --config <file>
  rulehouse ledger <file.jsonl>
  rulehouse provenance register <registry.jsonl> <file> --origin <o> --trust <t> --source <label> --labeled-by <who>
  rulehouse provenance inspect <registry.jsonl> <file>
  rulehouse a2a validate <card.json|->
  rulehouse a2a delegate <registry.jsonl> --from <delegator> --to <delegatee> --tools <csv> --granted-by <who> [--expires-at <iso>]
  rulehouse a2a revoke <registry.jsonl> <grantId> --revoked-by <who>
  rulehouse a2a inspect <registry.jsonl> [--grant <id>]
  rulehouse a2a simulate <registry.jsonl> --config <gateway config> --identity <name> --tool <tool> [--arguments <json object>] [--via <grantId,...>] [--now <iso>]
  rulehouse help

Commands:
  scan     Walk <root>, inventory every recognized MCP client configuration,
           evaluate the policy set, and write snapshot.json, report.json, and
           report.md into <dir> (default: ./rulehouse-out). With --strict the
           exit code is 1 when any finding exists.
  diff     Compare two snapshots. Exit code 1 when anything changed.
  verify   Re-derive the SHA-256 of every input file recorded in a snapshot
           (resolved against --root) and re-compute the snapshot fingerprint.
           Exit code 0 when every digest matches, 1 on drift, 2 on error.
  ledger   Verify the append-only hash chain of a decision ledger or
           provenance registry. Exit 0 intact, 1 broken, 2 error.
  provenance
           Register content trust by digest, or inspect what trust a content
           file (or "-" for stdin) resolves to. The gateway consults this
           registry per request: a policy rule with provenanceChecks only
           grants effect when the named argument's content resolves to an
           accepted declared trust. Re-registering a digest supersedes the
           previous record; the chain keeps the full history.
  a2a      Validate A2A agent cards, and govern delegation of authority
           between identities: grants, revocations, and offline evaluation of
           a delegated tool call. A delegated call is allowed only when every
           identity on the grant chain -- the acting agent and each delegator
           up to the root -- is allowed by its own existing gateway policies,
           so a delegatee can never exceed its delegator. This evaluates
           delegation decisions; it does not intercept A2A traffic, which
           requires a validated control point.

Credentials are never emitted: configuration secrets are stored only as
SHA-256 fingerprint prefixes.
`;

function stringList(value: unknown): readonly string[] | null {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string")
    ? (value as readonly string[])
    : null;
}

async function loadAllowlist(path: string, flagValue: string): Promise<Allowlist> {
  const text = await readFile(path, "utf8");
  const parsed: unknown = JSON.parse(text);
  const direct = stringList(parsed);
  const nested = typeof parsed === "object" && parsed !== null ? stringList((parsed as Record<string, unknown>)["urlPrefixes"]) : null;
  const prefixes = direct ?? nested;
  if (prefixes === null) {
    throw new Error(`allowlist ${path} must be a JSON array of URL prefixes or {"urlPrefixes": [...]}`);
  }
  return { urlPrefixes: prefixes, source: flagValue };
}

async function commandScan(options: CommandLine): Promise<number> {
  const root = options.positional[0];
  if (root === undefined) {
    process.stderr.write('scan requires a <root> directory\n');
    return 2;
  }
  const allowlistFlag = options.flags.get("--allowlist");
  const allowlist = typeof allowlistFlag === "string" ? await loadAllowlist(allowlistFlag, allowlistFlag) : null;

  const scan = await scanRoot(root, resolveFromProcessEnv);
  const evaluation = evaluatePolicy(scan.inventory, allowlist);
  const snapshot = snapshotOf(scan, new Date().toISOString());
  const report = scanReportOf(snapshot, evaluation, new Date().toISOString());
  const findings = findingsOf(report);

  const outDir = typeof options.flags.get("--out") === "string" ? (options.flags.get("--out") as string) : "rulehouse-out";
  await mkdir(outDir, { recursive: true });
  await writeSnapshotFile(snapshot, join(outDir, "snapshot.json"));
  await writeFile(join(outDir, "report.json"), `${JSON.stringify(report, null, 2)}\n`, "utf8");
  await writeFile(join(outDir, "report.md"), renderMarkdownReport(report, findings), "utf8");

  process.stdout.write(`scanned ${scan.inputs.length} file(s) under ${root}\n`);
  process.stdout.write(`inventory: ${scan.inventory.length} registration(s), ${scan.diagnostics.length} diagnostic(s)\n`);
  process.stdout.write(`findings: ${findings.length} (snapshot ${snapshot.fingerprint})\n`);
  for (const finding of findings) {
    process.stdout.write(`  [${finding.severity}] ${finding.ruleId} ${finding.subject}: ${finding.message}\n`);
  }
  process.stdout.write(`outputs written to ${outDir}/ (snapshot.json, report.json, report.md)\n`);
  return options.flags.get("--strict") === true && findings.length > 0 ? 1 : 0;
}

function describeDiff(change: SnapshotDiff): string {
  const lines: string[] = [];
  for (const input of change.inputs) {
    lines.push(`input ${input.kind}: ${input.path}`);
  }
  for (const server of change.servers) {
    for (const added of server.added) lines.push(`registration added on ${server.serverKey}: ${added}`);
    for (const removed of server.removed) lines.push(`registration removed from ${server.serverKey}: ${removed}`);
    for (const changed of server.changed) {
      lines.push(`registration changed on ${server.serverKey}: ${changed.location}`);
      for (const field of changed.fields) {
        lines.push(`  ${field.field}: ${field.from} -> ${field.to}`);
      }
    }
  }
  return lines.join("\n");
}

async function commandDiff(options: CommandLine): Promise<number> {
  const [baselinePath, currentPath] = options.positional;
  if (baselinePath === undefined || currentPath === undefined) {
    process.stderr.write("diff requires <baseline.json> <current.json>\n");
    return 2;
  }
  const baseline = await readSnapshotFile(baselinePath);
  const current = await readSnapshotFile(currentPath);
  if (!baseline.ok) {
    process.stderr.write(`${baseline.error}\n`);
    return 2;
  }
  if (!current.ok) {
    process.stderr.write(`${current.error}\n`);
    return 2;
  }
  for (const [label, snapshot] of [["baseline", baseline.snapshot], ["current", current.snapshot]] as const) {
    const recomputed = fingerprintOf(snapshot.inputs, snapshot.inventory, snapshot.diagnostics);
    if (recomputed !== snapshot.fingerprint) {
      process.stderr.write(`${label} snapshot fingerprint mismatch: recorded ${snapshot.fingerprint}, content hashes to ${recomputed}\n`);
      return 2;
    }
  }
  const change = diffSnapshots(baseline.snapshot, current.snapshot);
  process.stdout.write(`${baselinePath} -> ${currentPath}\n${change.summary}\n`);
  const detail = describeDiff(change);
  if (detail.length > 0) process.stdout.write(`${detail}\n`);
  return change.changeCount > 0 ? 1 : 0;
}

async function commandVerify(options: CommandLine): Promise<number> {
  const snapshotPath = options.positional[0];
  const root = options.flags.get("--root");
  if (snapshotPath === undefined || typeof root !== "string") {
    process.stderr.write("verify requires <snapshot.json> --root <root>\n");
    return 2;
  }
  const loaded = await readSnapshotFile(snapshotPath);
  if (!loaded.ok) {
    process.stderr.write(`${loaded.error}\n`);
    return 2;
  }
  const snapshot = loaded.snapshot;
  let drift = 0;
  for (const input of snapshot.inputs) {
    const path = join(root, input.path);
    let actual: string;
    try {
      actual = createHash("sha256").update(await readFile(path)).digest("hex");
    } catch (error) {
      drift++;
      process.stdout.write(`MISSING  ${input.path} (unreadable: ${(error as Error).message})\n`);
      continue;
    }
    if (actual === input.sha256) {
      process.stdout.write(`OK       ${input.path} ${input.sha256}\n`);
    } else {
      drift++;
      process.stdout.write(`MODIFIED ${input.path} recorded ${input.sha256} actual ${actual}\n`);
    }
  }
  const recomputed = fingerprintOf(snapshot.inputs, snapshot.inventory, snapshot.diagnostics);
  const fingerprintOk = recomputed === snapshot.fingerprint;
  process.stdout.write(fingerprintOk ? `fingerprint verified: ${snapshot.fingerprint}\n` : `fingerprint mismatch: recorded ${snapshot.fingerprint}, content hashes to ${recomputed}\n`);
  return !fingerprintOk || drift > 0 ? 1 : 0;
}


async function commandServe(options: CommandLine): Promise<number> {
  const configPath = options.flags.get("--config");
  if (typeof configPath !== "string") {
    process.stderr.write("serve requires --config <file>\n");
    return 2;
  }
  const text = await readFile(configPath, "utf8").catch(() => null);
  if (text === null) {
    process.stderr.write(`gateway config ${configPath} is unreadable\n`);
    return 2;
  }
  const loaded = readGatewayConfig(text, configPath, (name) => process.env[name]);
  for (const diagnostic of loaded.diagnostics) {
    process.stderr.write(`${diagnostic.subject}: ${diagnostic.message}\n`);
  }
  if (loaded.config === null) {
    process.stderr.write(`gateway config ${configPath} is not enforceable; refusing to start\n`);
    return 2;
  }
  const config = loaded.config;
  const handle = await createGateway(config, (name) => process.env[name]);
  await handle.listen();
  await new Promise<void>((resolve) => {
    const shutdown = (): void => {
      process.off("SIGINT", shutdown);
      process.off("SIGTERM", shutdown);
      handle.close().then(resolve, resolve);
    };
    handle.server.on("error", (error: Error) => {
      process.stderr.write(`gateway server error: ${error.message}\n`);
      shutdown();
    });
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
    process.stdout.write(`rulehouse gateway listening on ${handle.url}${config.listen.path} (ledger: ${config.ledgerPath})\n`);
  });
  return 0;
}

const PROVENANCE_ORIGINS: readonly ProvenanceOrigin[] = ["internal", "external", "derived"];
const PROVENANCE_TRUSTS: readonly ProvenanceTrust[] = ["trusted", "untrusted", "unverified"];

async function readContentSource(pathArg: string | undefined): Promise<string | null> {
  if (pathArg === undefined) return null;
  if (pathArg === "-") {
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
    return Buffer.concat(chunks).toString("utf8");
  }
  return await readFile(pathArg, "utf8").catch(() => null);
}

async function commandProvenance(options: CommandLine): Promise<number> {
  const verb = options.positional[0];
  const registryPath = options.positional[1];
  if (verb !== "register" && verb !== "inspect") {
    process.stderr.write('provenance requires a verb: "register" or "inspect"\n');
    return 2;
  }
  if (typeof registryPath !== "string") {
    process.stderr.write(`provenance ${verb} requires <registry.jsonl> <file|->\n`);
    return 2;
  }
  const text = await readContentSource(options.positional[2]);
  if (text === null) {
    process.stderr.write(`provenance ${verb} could not read content ${options.positional[2] ?? "(missing)"}\n`);
    return 2;
  }
  const digest = contentDigestOfText(text);

  if (verb === "register") {
    const flagValue = (name: string): string | null => {
      const value = options.flags.get(name);
      return typeof value === "string" ? value : null;
    };
    const origin = flagValue("--origin");
    const trust = flagValue("--trust");
    const source = flagValue("--source");
    const labeledBy = flagValue("--labeled-by");
    if (origin === null || trust === null || source === null || labeledBy === null
      || origin.length === 0 || source.length === 0 || labeledBy.length === 0) {
      process.stderr.write("provenance register requires --origin, --trust, --source, and --labeled-by\n");
      return 2;
    }
    if (!PROVENANCE_ORIGINS.includes(origin as ProvenanceOrigin)) {
      process.stderr.write(`--origin must be one of ${PROVENANCE_ORIGINS.join(", ")}, got "${origin}"\n`);
      return 2;
    }
    if (!PROVENANCE_TRUSTS.includes(trust as ProvenanceTrust)) {
      process.stderr.write(`--trust must be one of ${PROVENANCE_TRUSTS.join(", ")}, got "${trust}"\n`);
      return 2;
    }
    const integrity = await verifyChain(registryPath);
    if (!integrity.ok && integrity.problem !== null) {
      process.stderr.write(`${registryPath}: refusing to append; the chain is broken at entry ${integrity.breakAt}: ${integrity.problem}\n`);
      return 1;
    }
    let seq: number;
    try {
      seq = await appendProvenanceRecord(registryPath, {
        contentSha256: digest,
        origin: origin as ProvenanceOrigin,
        trust: trust as ProvenanceTrust,
        source,
        labeledBy,
        labeledAt: new Date().toISOString(),
      }, new Date().toISOString());
    } catch (error) {
      process.stderr.write(`provenance register could not append to ${registryPath}: ${(error as Error).message}\n`);
      return 2;
    }
    process.stdout.write(`registered ${digest} as trust=${trust} origin=${origin} source="${source}" labeled-by=${labeledBy} (entry ${seq} in ${registryPath})\n`);
    return 0;
  }

  const registry = await readProvenanceRegistry(registryPath);
  if (registry.corrupt !== null) {
    process.stderr.write(`${registryPath}: BROKEN at provenance registry: ${registry.corrupt}\n`);
    return 2;
  }
  const record = registry.records.get(digest);
  if (record === undefined) {
    process.stderr.write(`unclassified: ${digest} has no provenance record in ${registryPath}\n`);
    return 1;
  }
  process.stdout.write(`${digest}\n${JSON.stringify(record, null, 2)}\n`);
  return 0;
}

async function commandA2a(options: CommandLine): Promise<number> {
  const verb = options.positional[0];
  switch (verb) {
    case "validate":
      return await a2aValidate(options.positional[1]);
    case "delegate":
      return await a2aDelegate(options);
    case "revoke":
      return await a2aRevoke(options);
    case "inspect":
      return await a2aInspect(options);
    case "simulate":
      return await a2aSimulate(options);
    default:
      process.stderr.write('a2a requires a verb: "validate", "delegate", "revoke", "inspect", or "simulate"\n');
      return 2;
  }
}

function flagValueOf(options: CommandLine, name: string): string | null {
  const value = options.flags.get(name);
  return typeof value === "string" ? value : null;
}

async function a2aValidate(pathArg: string | undefined): Promise<number> {
  const text = await readContentSource(pathArg);
  if (text === null) {
    process.stderr.write(`a2a validate could not read ${pathArg ?? "(missing)"}; use "-" for stdin\n`);
    return 2;
  }
  const source = pathArg === undefined || pathArg === "-" ? "<stdin>" : pathArg;
  const { card, diagnostics } = validateAgentCard(text, source);
  for (const diagnostic of diagnostics) {
    process.stdout.write(`FINDING ${diagnostic.subject}: ${diagnostic.message}\n`);
  }
  if (card === null) {
    process.stderr.write(`${source} is not a usable agent card\n`);
    return 1;
  }
  const enabled = Object.entries(card.capabilities).filter(([, on]) => on).map(([field]) => field);
  process.stdout.write(`${source}: ${card.name} v${card.version} (protocol ${card.protocolVersion}, ${card.protocolMajor < 1 ? "legacy" : "v1"})\n`);
  for (const iface of card.interfaces) {
    process.stdout.write(`  interface ${iface.protocolBinding} ${iface.url}${iface.protocolVersion === null ? "" : ` (protocol ${iface.protocolVersion})`}\n`);
  }
  process.stdout.write(`  capabilities: ${enabled.length === 0 ? "none declared" : enabled.join(", ")}\n`);
  process.stdout.write(`  skills: ${card.skills.length}; security schemes: ${card.securitySchemes.length === 0 ? "none" : card.securitySchemes.join(", ")}; signed: ${card.signed ? "yes" : "no"}\n`);
  return diagnostics.length === 0 ? 0 : 1;
}

async function a2aDelegate(options: CommandLine): Promise<number> {
  const registryPath = options.positional[1];
  const from = flagValueOf(options, "--from");
  const to = flagValueOf(options, "--to");
  const toolsRaw = flagValueOf(options, "--tools");
  const grantedBy = flagValueOf(options, "--granted-by");
  const expiresAt = flagValueOf(options, "--expires-at");
  if (typeof registryPath !== "string" || from === null || to === null || toolsRaw === null || grantedBy === null
    || from.length === 0 || to.length === 0 || grantedBy.length === 0) {
    process.stderr.write("a2a delegate requires <registry.jsonl> --from <delegator> --to <delegatee> --tools <csv> --granted-by <who>\n");
    return 2;
  }
  const tools = toolsRaw.split(",").map((tool) => tool.trim()).filter((tool) => tool.length > 0);
  if (tools.length === 0) {
    process.stderr.write("--tools must name at least one tool pattern\n");
    return 2;
  }
  if (from === to) {
    process.stderr.write("a delegation from an identity to itself is a cycle and governs nothing\n");
    return 2;
  }
  if (expiresAt !== null && !Number.isFinite(Date.parse(expiresAt))) {
    process.stderr.write(`--expires-at must be an ISO timestamp, got "${expiresAt}"\n`);
    return 2;
  }
  const grantedAt = new Date().toISOString();
  const grant: Omit<DelegationGrant, "grantId"> = { delegator: from, delegatee: to, tools, grantedBy, grantedAt, expiresAt };
  return await appendGovernedRecord(registryPath, { kind: "grant", grantId: grantIdOf(grant), ...grant },
    `granted ${describeGrant(grant)}`);
}

function describeGrant(grant: Omit<DelegationGrant, "grantId">): string {
  return `authority of ${grant.delegator} over tools ${grant.tools.join(", ")} to ${grant.delegatee}`;
}

async function a2aRevoke(options: CommandLine): Promise<number> {
  const registryPath = options.positional[1];
  const grantId = options.positional[2];
  const revokedBy = flagValueOf(options, "--revoked-by");
  if (typeof registryPath !== "string" || typeof grantId !== "string" || revokedBy === null || revokedBy.length === 0) {
    process.stderr.write("a2a revoke requires <registry.jsonl> <grantId> --revoked-by <who>\n");
    return 2;
  }
  const registry = await readDelegationRegistry(registryPath);
  if (registry.corrupt !== null) {
    process.stderr.write(`${registryPath}: refusing to append; the chain is broken: ${registry.corrupt}\n`);
    return 1;
  }
  if (!registry.grants.has(grantId)) {
    process.stderr.write(`${registryPath}: no grant ${grantId}; revoke names an issuance, and only issuances can be revoked\n`);
    return 1;
  }
  return await appendGovernedRecord(registryPath, { kind: "revocation", grantId, revokedBy },
    `revoked ${grantId} (by ${revokedBy})`);
}

/**
 * Shared tail of both mutations: never append to a chain we cannot prove is
 * intact -- the Phase-3 lesson is a registry invariant, not a one-off fix.
 */
async function appendGovernedRecord(registryPath: string, record: DelegationRecord, description: string): Promise<number> {
  const integrity = await verifyChain(registryPath);
  if (!integrity.ok && integrity.problem !== null) {
    process.stderr.write(`${registryPath}: refusing to append; the chain is broken at entry ${integrity.breakAt}: ${integrity.problem}\n`);
    return 1;
  }
  let seq: number;
  try {
    seq = await appendDelegationRecord(registryPath, record, new Date().toISOString());
  } catch (error) {
    process.stderr.write(`a2a could not append to ${registryPath}: ${(error as Error).message}\n`);
    return 2;
  }
  process.stdout.write(`${description} (entry ${seq} in ${registryPath}, grant ${record.grantId})\n`);
  return 0;
}

async function a2aInspect(options: CommandLine): Promise<number> {
  const registryPath = options.positional[1];
  if (typeof registryPath !== "string") {
    process.stderr.write("a2a inspect requires <registry.jsonl>\n");
    return 2;
  }
  const registry = await readDelegationRegistry(registryPath);
  if (registry.corrupt !== null) {
    process.stderr.write(`${registryPath}: BROKEN: ${registry.corrupt}\n`);
    return 2;
  }
  const filter = flagValueOf(options, "--grant");
  const states = [...registry.grants.entries()]
    .filter(([id]) => filter === null || id === filter);
  if (filter !== null && states.length === 0) {
    process.stderr.write(`${registryPath}: no grant ${filter}\n`);
    return 1;
  }
  for (const [id, state] of states) {
    const g = state.grant;
    const status = state.revoked ? `REVOKED by ${state.revokedBy}` : "active";
    process.stdout.write(`${id}\n  ${g.delegator} -> ${g.delegatee} scope: ${g.tools.join(", ")}\n  granted by ${g.grantedBy} at ${g.grantedAt}; expires: ${g.expiresAt ?? "never"}; ${status}\n`);
  }
  if (states.length === 0) process.stdout.write(`${registryPath}: no delegation grants recorded\n`);
  return 0;
}

async function a2aSimulate(options: CommandLine): Promise<number> {
  const registryPath = options.positional[1];
  const configPath = flagValueOf(options, "--config");
  const identity = flagValueOf(options, "--identity");
  const tool = flagValueOf(options, "--tool");
  const argumentsJson = flagValueOf(options, "--arguments");
  const viaRaw = flagValueOf(options, "--via");
  const now = flagValueOf(options, "--now") ?? new Date().toISOString();
  if (typeof registryPath !== "string" || typeof configPath !== "string" || identity === null || tool === null) {
    process.stderr.write("a2a simulate requires <registry.jsonl> --config <file> --identity <name> --tool <tool> [--arguments <json object>] [--via <ids>] [--now <iso>]\n");
    return 2;
  }
  let args: JsonObject | null = null;
  if (argumentsJson !== null) {
    const parsed: unknown = JSON.parse(argumentsJson);
    if (!isJsonObject(parsed)) {
      process.stderr.write("--arguments must be a JSON object of tool arguments\n");
      return 2;
    }
    args = parsed;
  }
  const presented = viaRaw === null ? [] : viaRaw.split(",").map((id) => id.trim()).filter((id) => id.length > 0);
  const configText = await readFile(configPath, "utf8").catch(() => null);
  if (configText === null) {
    process.stderr.write(`gateway config ${configPath} is unreadable\n`);
    return 2;
  }
  const loaded = readGatewayConfig(configText, configPath, (name) => process.env[name]);
  if (loaded.config === null) {
    for (const diagnostic of loaded.diagnostics) process.stderr.write(`${diagnostic.subject}: ${diagnostic.message}\n`);
    process.stderr.write(`gateway config ${configPath} is not enforceable; refusing to simulate against it\n`);
    return 2;
  }
  const [delegations, provenance] = await Promise.all([
    readDelegationRegistry(registryPath),
    loaded.config.provenancePath === null ? Promise.resolve(null) : readProvenanceRegistry(loaded.config.provenancePath),
  ]);
  const decision = evaluateDelegatedToolCall({
    policies: loaded.config.policies,
    delegations,
    presented,
    identity,
    tool,
    args,
    registry: provenance,
    now,
  });
  process.stdout.write(`${JSON.stringify(renderDelegatedDecision(decision), null, 2)}\n`);
  return decision.allowed ? 0 : 1;
}

function renderDelegatedDecision(decision: DelegatedDecision): JsonObject {
  return {
    allowed: decision.allowed,
    approvalRequired: decision.approvalRequired,
    reason: decision.reason,
    chain: decision.chain.map((link) => ({ grantId: link.grantId, delegator: link.delegator, delegatee: link.delegatee })),
    ceilings: decision.ceilings.map((ceiling) => ({
      identity: ceiling.identity,
      kind: ceiling.decision.kind,
      ruleId: ceiling.decision.ruleId,
      approvalRequired: ceiling.decision.approvalRequired,
      reason: ceiling.decision.reason,
    })),
    provenance: decision.provenance.map((fact) => ({ argument: fact.argument, contentSha256: fact.contentSha256, trust: fact.trust })),
  };
}

async function commandLedger(pathArg: string | undefined): Promise<number> {
  if (pathArg === undefined) {
    process.stderr.write("ledger requires <file.jsonl>\n");
    return 2;
  }
  const verification = await verifyLedger(pathArg);
  if (verification.ok) {
    process.stdout.write(`${pathArg}: chain intact across ${verification.entries} entr${verification.entries === 1 ? "y" : "ies"}\n`);
    return 0;
  }
  process.stderr.write(`${pathArg}: BROKEN at entry ${verification.breakAt}: ${verification.problem}\n`);
  return 1;
}

export async function main(argv: readonly string[]): Promise<number> {
  const commandLine = parseCommandLine(argv);
  if (commandLine === null) {
    process.stderr.write(USAGE);
    return 2;
  }
  switch (commandLine.command) {
    case "scan":
      return await commandScan(commandLine);
    case "diff":
      return await commandDiff(commandLine);
    case "verify":
      return await commandVerify(commandLine);
    case "serve":
      return await commandServe(commandLine);
    case "ledger":
      return await commandLedger(commandLine.positional[0]);
    case "provenance":
      return await commandProvenance(commandLine);
    case "a2a":
      return await commandA2a(commandLine);
    case "help":
    case "--help":
    case "-h":
      process.stdout.write(USAGE);
      return 0;
    default:
      process.stderr.write(`unknown command "${commandLine.command}"\n\n${USAGE}`);
      return 2;
  }
}


