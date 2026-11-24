import type { ScanDiagnostic } from "../model.js";
import { isJsonObject, parseLooseJson, type Json, type JsonObject } from "../lib/json.js";

/**
 * Validation for A2A agent cards, the discovery document every A2A server
 * publishes. The card is where delegation governance begins: an agent can
 * only be granted authority once the control plane can say who it claims to
 * be, where it is reachable, and what it can do. Facts validated here are the
 * published v1.0 conformance rules, checked against research of the frozen
 * v1.0.0 spec -- not invented requirements.
 */

/** v1.0 well-known discovery path (v0.x deployments still serve `agent.json`). */
export const V1_CARD_WELL_KNOWN = "/.well-known/agent-card.json";
export const LEGACY_CARD_WELL_KNOWN = "/.well-known/agent.json";

/** Transport bindings the v1.0 spec names. Unknown values are diagnosed and retained so future bindings do not invalidate an otherwise honest card. */
const KNOWN_BINDINGS: readonly string[] = ["JSONRPC", "GRPC", "HTTP+JSON"];

export interface AgentInterface {
  readonly url: string;
  readonly protocolBinding: string;
  readonly protocolVersion: string | null;
}

export interface AgentCapabilities {
  readonly streaming: boolean;
  readonly pushNotifications: boolean;
  readonly stateTransitionHistory: boolean;
}

export interface AgentSkill {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly tags: readonly string[];
  readonly inputModes: readonly string[];
  readonly outputModes: readonly string[];
}

export interface AgentCard {
  readonly name: string;
  readonly description: string;
  /** The agent's own release version -- deliberately distinct from `protocolVersion`. */
  readonly version: string;
  readonly protocolVersion: string;
  /** Major of `protocolVersion`; decides which interface shape the spec expects. */
  readonly protocolMajor: number;
  readonly interfaces: readonly AgentInterface[];
  readonly capabilities: AgentCapabilities;
  readonly skills: readonly AgentSkill[];
  /** Declared security-scheme names, e.g. the oauth2 scheme on Atlassian's card. */
  readonly securitySchemes: readonly string[];
  /** Skill/security references that point at an undeclared scheme are diagnosed at read time, so the empty array below is a checked invariant, not an assumption. */
  readonly danglingSecurityReferences: readonly string[];
  /** True when the card carries at least one structurally valid JWS signature. */
  readonly signed: boolean;
  readonly documentationUrl: string | null;
}

export interface CardValidation {
  /**
   * The best-effort card. Null only when the document cannot serve as an
   * identity document at all -- unparseable, not an object, or missing core
   * identity fields. Every lesser defect rides along as a diagnostic.
   */
  readonly card: AgentCard | null;
  readonly diagnostics: readonly ScanDiagnostic[];
}

export function validateAgentCard(text: string, source: string): CardValidation {
  const diagnostics: ScanDiagnostic[] = [];
  const fail = (subject: string, message: string): void => {
    diagnostics.push({ source, subject: `/a2a-card${subject}`, message });
  };

  const parsed = parseLooseJson(text, source);
  if (parsed.value === null) {
    for (const diagnostic of parsed.diagnostics) fail("", diagnostic.message);
    return { card: null, diagnostics };
  }
  if (!isJsonObject(parsed.value)) {
    fail("", "agent card must be a JSON object");
    return { card: null, diagnostics };
  }
  const document = parsed.value;

  const name = requiredString(document, "name", fail);
  const description = requiredString(document, "description", fail);
  const version = requiredString(document, "version", fail, "the agent release version, distinct from protocolVersion");
  const protocolVersion = requiredString(document, "protocolVersion", fail);
  if (name === null || description === null || version === null || protocolVersion === null) {
    return { card: null, diagnostics };
  }
  const protocolMajor = majorOf(protocolVersion);
  if (protocolMajor === null) {
    fail("/protocolVersion", `must begin with a numeric major version, got "${protocolVersion}"`);
    return { card: null, diagnostics };
  }

  const interfaces = readInterfaces(document, protocolMajor, fail);
  const capabilities = readCapabilities(document["capabilities"], fail);
  const skills = readSkills(document["skills"], fail);
  const schemes = readSecuritySchemes(document["securitySchemes"], fail);
  const dangling = readSecurityRequirements(document["security"], schemes, fail);
  const signed = readSignatures(document["signatures"], fail);

  const documentationUrl = optionalUrl(document["documentationUrl"], "/documentationUrl", fail);

  if (protocolMajor < 1) {
    fail("/protocolVersion", `protocol ${protocolVersion} is a legacy pre-1.0 deployment: discovery via ${LEGACY_CARD_WELL_KNOWN}, single-JSON-RPC interface, no v1.0 conformance guarantees`);
  }

  return {
    card: {
      name,
      description,
      version,
      protocolVersion,
      protocolMajor,
      interfaces,
      capabilities,
      skills,
      securitySchemes: schemes,
      danglingSecurityReferences: dangling,
      signed,
      documentationUrl,
    },
    diagnostics,
  };
}

function requiredString(
  document: JsonObject,
  field: string,
  fail: (subject: string, message: string) => void,
  note?: string,
): string | null {
  const value = document[field];
  if (typeof value !== "string" || value.length === 0) {
    fail(`/${field}`, `is required and must be a non-empty string${note === undefined ? "" : ` (${note})`}`);
    return null;
  }
  return value;
}

function majorOf(protocolVersion: string): number | null {
  const major = protocolVersion.split(".", 1)[0];
  if (major === undefined || !/^\d+$/.test(major)) return null;
  return Number(major);
}

function readInterfaces(
  document: JsonObject,
  protocolMajor: number,
  fail: (subject: string, message: string) => void,
): readonly AgentInterface[] {
  const field = document["supportedInterfaces"];
  if (field === undefined) {
    if (protocolMajor >= 1) {
      fail("/supportedInterfaces", `is required in protocol v1.0 (the single "url" of v0.x became an array there); a card without it cannot say where the agent is reachable`);
    } else if (typeof document["url"] === "string" && document["url"].length > 0) {
      fail("/url", `legacy v0.x shape: a single URL speaks JSON-RPC only; v1.0 replaced it with a supportedInterfaces array and the well-known name moved from ${LEGACY_CARD_WELL_KNOWN} to ${V1_CARD_WELL_KNOWN}`);
      return interfaceList([{ url: document["url"], protocolBinding: "JSONRPC", protocolVersion: null }], fail);
    } else {
      fail("/supportedInterfaces", "is required: the card declares neither a supportedInterfaces array nor a legacy url");
    }
    return [];
  }
  if (!Array.isArray(field)) {
    fail("/supportedInterfaces", "must be an array of { url, protocolBinding, protocolVersion } objects");
    return [];
  }
  return interfaceList(field, fail);
}

function interfaceList(
  field: readonly Json[],
  fail: (subject: string, message: string) => void,
): readonly AgentInterface[] {
  const interfaces: AgentInterface[] = [];
  for (const [index, element] of field.entries()) {
    if (!isJsonObject(element)) {
      fail(`/supportedInterfaces/${index}`, "must be an object");
      continue;
    }
    const url = element["url"];
    if (typeof url !== "string" || url.length === 0) {
      fail(`/supportedInterfaces/${index}/url`, "is required and must be a string");
      continue;
    }
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url);
    } catch {
      fail(`/supportedInterfaces/${index}/url`, `is not a valid URL: ${url}`);
      continue;
    }
    if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
      fail(`/supportedInterfaces/${index}/url`, `must be an http(s) URL, got ${parsedUrl.protocol}`);
      continue;
    }
    if (parsedUrl.protocol === "http:") {
      fail(`/supportedInterfaces/${index}/url`, `is plaintext http; agent traffic on this interface is readable and rewritable by anything on the path`);
    }
    const binding = element["protocolBinding"];
    if (typeof binding !== "string" || binding.length === 0) {
      fail(`/supportedInterfaces/${index}/protocolBinding`, "is required and must be a binding name such as JSONRPC");
      continue;
    }
    if (!KNOWN_BINDINGS.includes(binding)) {
      fail(`/supportedInterfaces/${index}/protocolBinding`, `"${binding}" is not one of the bindings the validated spec revision names (${KNOWN_BINDINGS.join(", ")}); kept as declared for forward compatibility, but it is unverified`);
    }
    const protocolVersion = element["protocolVersion"];
    if (protocolVersion !== undefined && protocolVersion !== null && (typeof protocolVersion !== "string" || protocolVersion.length === 0)) {
      fail(`/supportedInterfaces/${index}/protocolVersion`, "must be a string when present");
      continue;
    }
    interfaces.push({ url, protocolBinding: binding, protocolVersion: typeof protocolVersion === "string" ? protocolVersion : null });
  }
  return interfaces;
}

const CAPABILITY_FIELDS: readonly (keyof AgentCapabilities)[] = ["streaming", "pushNotifications", "stateTransitionHistory"];

function readCapabilities(value: Json | undefined, fail: (subject: string, message: string) => void): AgentCapabilities {
  const defaults: AgentCapabilities = { streaming: false, pushNotifications: false, stateTransitionHistory: false };
  if (value === undefined) {
    fail("/capabilities", "is absent; every capability is treated as disabled -- the card declares nothing it can do");
    return defaults;
  }
  if (!isJsonObject(value)) {
    fail("/capabilities", "must be an object of boolean fields");
    return defaults;
  }
  const capabilities = { ...defaults };
  let malformed = false;
  for (const field of CAPABILITY_FIELDS) {
    const declared = value[field];
    if (declared === undefined) continue;
    if (typeof declared === "boolean") {
      capabilities[field] = declared;
    } else {
      malformed = true;
    }
  }
  if (malformed) fail("/capabilities", "every present field must be a boolean; non-boolean declarations are ignored and the capability stays disabled");
  return capabilities;
}

function readSkills(value: Json | undefined, fail: (subject: string, message: string) => void): readonly AgentSkill[] {
  if (value === undefined) {
    fail("/skills", "is absent; the card lists no skills an operator or a delegation scope could bind to");
    return [];
  }
  if (!Array.isArray(value)) {
    fail("/skills", "must be an array of skill objects");
    return [];
  }
  const skills: AgentSkill[] = [];
  const seen = new Set<string>();
  for (const [index, element] of value.entries()) {
    if (!isJsonObject(element)) {
      fail(`/skills/${index}`, "must be an object");
      continue;
    }
    const id = element["id"];
    const name = element["name"];
    const description = element["description"];
    const tags = element["tags"];
    // Absent mode lists mean the skill declares no media constraints, which
    // is different from declaring malformed ones -- only the latter fails.
    const inputModes = element["inputModes"] === undefined ? [] : stringList(element["inputModes"]);
    const outputModes = element["outputModes"] === undefined ? [] : stringList(element["outputModes"]);
    if (typeof id !== "string" || id.length === 0) {
      fail(`/skills/${index}/id`, "is required and must be a non-empty string");
      continue;
    }
    if (seen.has(id)) {
      fail(`/skills/${index}/id`, `duplicates skill id "${id}"`);
      continue;
    }
    if (typeof name !== "string" || name.length === 0) {
      fail(`/skills/${index}/name`, "is required and must be a non-empty string");
      continue;
    }
    if (typeof description !== "string" || description.length === 0) {
      fail(`/skills/${index}/description`, "is required and must be a non-empty string");
      continue;
    }
    if (!Array.isArray(tags) || tags.length === 0 || tags.some((tag) => typeof tag !== "string")) {
      fail(`/skills/${index}/tags`, "is required and must be a non-empty array of strings");
      continue;
    }
    if (inputModes === null || outputModes === null) {
      fail(`/skills/${index}/(in|out)putModes`, "must be an array of strings when present");
      continue;
    }
    seen.add(id);
    skills.push({ id, name, description, tags: tags as readonly string[], inputModes, outputModes });
  }
  return skills;
}

function readSecuritySchemes(
  value: Json | undefined,
  fail: (subject: string, message: string) => void,
): readonly string[] {
  if (value === undefined) return [];
  if (!isJsonObject(value)) {
    fail("/securitySchemes", "must be an object mapping scheme names to their declarations");
    return [];
  }
  const names = Object.keys(value);
  if (names.length === 0) fail("/securitySchemes", "declares no schemes; every request to this agent then runs on whatever the server accepts unchallenged");
  for (const [name, declaration] of Object.entries(value)) {
    if (isJsonObject(declaration) && typeof declaration["type"] === "string") continue;
    fail(`/securitySchemes/${name}`, "must be an object with a \"type\" field");
  }
  return names;
}

function readSecurityRequirements(
  value: Json | undefined,
  schemes: readonly string[],
  fail: (subject: string, message: string) => void,
): readonly string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    fail("/security", "must be an array of requirement objects");
    return [];
  }
  const declared = new Set(schemes);
  const dangling: string[] = [];
  const seen = new Set<string>();
  for (const [index, element] of value.entries()) {
    if (!isJsonObject(element)) {
      fail(`/security/${index}`, "must be an object");
      continue;
    }
    for (const name of Object.keys(element)) {
      if (declared.has(name)) continue;
      if (!seen.has(name)) {
        seen.add(name);
        dangling.push(name);
        fail(`/security/${index}`, `references security scheme "${name}" which the card does not declare`);
      }
    }
  }
  return dangling;
}

function readSignatures(value: Json | undefined, fail: (subject: string, message: string) => void): boolean {
  if (value === undefined) {
    fail("/signatures", "is absent: the card is unsigned, so its authenticity rests entirely on the channel it was retrieved over -- any intermediary between the server and the reader could have rewritten it");
    return false;
  }
  if (!Array.isArray(value)) {
    fail("/signatures", "must be an array of JWS signatures");
    return false;
  }
  const valid = value.filter((element) => {
    if (!isJsonObject(element)) return false;
    const protectedHeader = element["protected"];
    const signature = element["signature"];
    return typeof protectedHeader === "string" && protectedHeader.length > 0 && typeof signature === "string" && signature.length > 0;
  });
  if (valid.length !== value.length) {
    fail("/signatures", `${value.length - valid.length} of ${value.length} signature(s) are malformed (each needs non-empty "protected" and "signature" strings)`);
  }
  return valid.length > 0;
}

function optionalUrl(
  value: Json | undefined,
  subject: string,
  fail: (subject: string, message: string) => void,
): string | null {
  if (value === undefined) return null;
  if (typeof value !== "string" || value.length === 0) {
    fail(subject, "must be a string URL when present");
    return null;
  }
  try {
    new URL(value);
  } catch {
    fail(subject, `is not a valid URL: ${value}`);
    return null;
  }
  return value;
}

function stringList(value: Json | undefined): readonly string[] | null {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string")
    ? (value as readonly string[])
    : null;
}
