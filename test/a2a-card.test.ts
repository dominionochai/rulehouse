import test from "node:test";
import assert from "node:assert/strict";
import { validateAgentCard, type AgentCard } from "../src/a2a/card.js";

function card(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    name: "Operations Agent",
    description: "Runs runbook procedures against Jira and Confluence.",
    version: "2.4.1",
    protocolVersion: "1.0",
    supportedInterfaces: [
      { url: "https://agents.example.internal/a2a", protocolBinding: "JSONRPC", protocolVersion: "1.0" },
      { url: "https://agents.example.internal/a2a/rest", protocolBinding: "HTTP+JSON", protocolVersion: "1.0" },
    ],
    capabilities: { streaming: true, pushNotifications: false, stateTransitionHistory: true },
    skills: [
      { id: "runbook-execute", name: "Execute runbook", description: "Applies a runbook procedure.", tags: ["jira", "automation"] },
    ],
    securitySchemes: { oauth2: { type: "oauth2" } },
    security: [{ oauth2: ["read:issues"] }],
    ...overrides,
  };
}

function validate(document: Record<string, unknown>): { card: AgentCard | null; messages: string[] } {
  const { card, diagnostics } = validateAgentCard(JSON.stringify(document), "card.json");
  return { card, messages: diagnostics.map((diagnostic) => `${diagnostic.subject}: ${diagnostic.message}`) };
}

test("a v1.0 card with everything the spec names validates clean", () => {
  const result = validate(card({ signatures: [{ protected: "b64header", signature: "b64sig" }] }));
  assert.deepEqual(result.messages, []);
  assert.equal(result.card?.protocolMajor, 1);
  assert.equal(result.card?.interfaces.length, 2);
  assert.equal(result.card?.skills.length, 1);
  assert.equal(result.card?.signed, true);
  assert.deepEqual(result.card?.capabilities, { streaming: true, pushNotifications: false, stateTransitionHistory: true });
});

test("a card is unusable when it cannot state who it is", () => {
  const missingDescription = validate(card({ description: undefined }));
  assert.equal(missingDescription.card, null);
  assert.ok(missingDescription.messages.some((m) => m.startsWith("/a2a-card/description")));

  const notAnObject = validateAgentCard("[1,2,3]", "card.json");
  assert.equal(notAnObject.card, null);

  const nonsenseProtocol = validate(card({ protocolVersion: "latest" }));
  assert.equal(nonsenseProtocol.card, null);
  assert.ok(nonsenseProtocol.messages.some((m) => m.includes("/protocolVersion")));
});

test("v1.0 requires the supportedInterfaces array; the v0.x single url is diagnosed as legacy", () => {
  const dropped = validate(card({ supportedInterfaces: undefined }));
  assert.ok(dropped.messages.some((m) => m.startsWith("/a2a-card/supportedInterfaces") && m.includes("required in protocol v1.0")));
  assert.deepEqual(dropped.card?.interfaces, []);

  const legacy = validate(card({
    protocolVersion: "0.3.0",
    supportedInterfaces: undefined,
    url: "https://a2a.example.com/v1/rovo",
  }));
  assert.equal(legacy.card?.protocolMajor, 0);
  assert.equal(legacy.card?.interfaces.length, 1, "the single url is read as a JSON-RPC interface");
  assert.equal(legacy.card?.interfaces[0]?.protocolBinding, "JSONRPC");
  assert.ok(legacy.messages.some((m) => m.startsWith("/a2a-card/url") && m.includes("legacy v0.x shape")));
  assert.ok(legacy.messages.some((m) => m.startsWith("/a2a-card/protocolVersion") && m.includes("legacy pre-1.0")));
});

test("interface defects are diagnosed individually and never poison the whole card", () => {
  const result = validate(card({
    supportedInterfaces: [
      "not-an-object",
      { url: "https://good.example/a2a", protocolBinding: "GRPC" },
      { url: "ftp://agents.example/a2a", protocolBinding: "JSONRPC" },
      { url: "no-scheme", protocolBinding: "JSONRPC" },
      { url: "http://agents.example/a2a", protocolBinding: "JSONRPC" },
      { url: "https://future.example/a2a", protocolBinding: "HTTP+REST" },
    ],
  }));
  const subjects = result.messages.map((m) => m.split(":")[0]);
  assert.ok(subjects.includes("/a2a-card/supportedInterfaces/0"));
  assert.ok(subjects.includes("/a2a-card/supportedInterfaces/2/url"), "ftp is not an http(s) interface");
  assert.ok(subjects.includes("/a2a-card/supportedInterfaces/3/url"));
  assert.ok(subjects.includes("/a2a-card/supportedInterfaces/4/url"), "plaintext http is a finding");
  assert.ok(subjects.includes("/a2a-card/supportedInterfaces/5/protocolBinding"), "unknown bindings are named, not silently accepted");
  assert.equal(result.card?.interfaces.length, 3, "structurally valid interfaces survive: the good one, the plaintext one, the unknown-binding one");
  assert.ok(result.card?.interfaces.some((iface) => iface.url === "https://good.example/a2a" && iface.protocolBinding === "GRPC"));
});

test("a malformed skill is dropped with a diagnostic; absent skills are declared nothing, not hidden", () => {
  const result = validate(card({ skills: [
    { id: "ok", name: "Ok", description: "Fine.", tags: ["jira"] },
    { id: "no-tags", name: "No tags", description: "Missing required tags.", tags: [] },
    { id: "ok", name: "Duplicate", description: "Repeats the first id.", tags: ["x"] },
  ] }));
  assert.equal(result.card?.skills.length, 1);
  assert.ok(result.messages.some((m) => m.startsWith("/a2a-card/skills/1/tags")));
  assert.ok(result.messages.some((m) => m.startsWith("/a2a-card/skills/2/id") && m.includes("duplicates skill id \"ok\"")));

  const absent = validate(card({ skills: undefined }));
  assert.deepEqual(absent.card?.skills, []);
  assert.ok(absent.messages.some((m) => m.startsWith("/a2a-card/skills")));
});

test("security requirements that reference undeclared schemes are named exactly", () => {
  const result = validate(card({ securitySchemes: { oauth2: { type: "oauth2" } }, security: [{ oauth2: [] }, { apikey: [] }, { basic: [] }] }));
  assert.deepEqual(result.card?.danglingSecurityReferences, ["apikey", "basic"]);
  assert.ok(result.messages.some((m) => m.includes("\"apikey\" which the card does not declare")));
});

test("capabilities fields must be booleans; ignored declarations stay disabled", () => {
  const result = validate(card({ capabilities: { streaming: true, pushNotifications: "yes" } }));
  assert.deepEqual(result.card?.capabilities, { streaming: true, pushNotifications: false, stateTransitionHistory: false });
  assert.ok(result.messages.some((m) => m.startsWith("/a2a-card/capabilities") && m.includes("non-boolean")));

  const nothing = validate(card({ capabilities: undefined }));
  assert.deepEqual(nothing.card?.capabilities, { streaming: false, pushNotifications: false, stateTransitionHistory: false });
  assert.ok(nothing.messages.some((m) => m.startsWith("/a2a-card/capabilities") && m.includes("treated as disabled")));
});

test("signature coverage is structural: unsigned cards are diagnosed, malformed entries are counted", () => {
  const unsigned = validate(card({ signatures: undefined }));
  assert.equal(unsigned.card?.signed, false);
  assert.ok(unsigned.messages.some((m) => m.startsWith("/a2a-card/signatures") && m.includes("unsigned")));

  const malformed = validate(card({ signatures: [{ protected: "b64header" }, { protected: "h", signature: "s" }] }));
  assert.equal(malformed.card?.signed, true);
  assert.ok(malformed.messages.some((m) => m.includes("1 of 2 signature(s) are malformed")));
});

test("a documentationUrl must be a valid URL when present", () => {
  const ok = validate(card({ documentationUrl: "https://docs.example.com/agent" }));
  assert.equal(ok.card?.documentationUrl, "https://docs.example.com/agent");
  const bad = validate(card({ documentationUrl: "docs.example.com" }));
  assert.ok(bad.messages.some((m) => m.startsWith("/a2a-card/documentationUrl") && m.includes("not a valid URL")));
});
