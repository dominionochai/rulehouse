import test from "node:test";
import assert from "node:assert/strict";
import { authKey, endpointClassForUrl, serverKeyForUrl } from "../src/model.js";

test("every Atlassian endpoint generation collapses to one canonical server key", () => {
  const generations = [
    "https://mcp.atlassian.com/v2/mcp",
    "https://mcp.atlassian.com/v1/mcp",
    "https://mcp.atlassian.com/v1/mcp/authv2",
    "https://mcp.atlassian.com/v1/sse",
    "https://mcp.atlassian.com/v2/mcp?tools=all",
  ];
  const keys = new Set(generations.map(serverKeyForUrl));
  assert.deepEqual([...keys], ["atlassian:https://mcp.atlassian.com"]);
});

test("non-Atlassian server keys keep host and path, dropping query and trailing slash", () => {
  assert.equal(serverKeyForUrl("https://gw.example.com/mcp/?token=x"), "remote:https://gw.example.com/mcp");
  assert.notEqual(serverKeyForUrl("https://gw.example.com/mcp"), serverKeyForUrl("https://other.example.com/mcp"));
});

test("casing of the host is normalized, path casing is preserved", () => {
  assert.equal(serverKeyForUrl("https://GW.example.com/Mcp"), serverKeyForUrl("https://gw.example.com/Mcp"));
  assert.notEqual(serverKeyForUrl("https://gw.example.com/Mcp"), serverKeyForUrl("https://gw.example.com/mcp"));
});

test("unparseable urls keep a distinct, stable key", () => {
  assert.equal(serverKeyForUrl("not-a-url:::"), "unparseable:not-a-url:::");
});

test("endpoint classification matrix", () => {
  assert.equal(endpointClassForUrl("https://mcp.atlassian.com/v2/mcp"), "atlassian-v2");
  assert.equal(endpointClassForUrl("https://mcp.atlassian.com/v1/mcp"), "atlassian-v1");
  assert.equal(endpointClassForUrl("https://mcp.atlassian.com/v1/mcp/authv2"), "atlassian-v1");
  assert.equal(endpointClassForUrl("https://mcp.atlassian.com/v1/sse"), "atlassian-sse-legacy");
  assert.equal(endpointClassForUrl("https://gw.example.com/mcp"), "https-remote");
  assert.equal(endpointClassForUrl("http://gw.example.com/mcp"), "insecure-remote");
  assert.equal(endpointClassForUrl("http://mcp.atlassian.com/v2/mcp"), "insecure-remote");
  assert.equal(endpointClassForUrl("::bad::"), "unparseable-url");
});

test("authKey distinguishes the paths a policy-parity check must distinguish", () => {
  assert.equal(authKey({ kind: "oauth" }), "oauth");
  assert.equal(authKey({ kind: "api-token", scheme: "basic", username: null, credential: null, problem: null }), "token:basic");
  assert.equal(authKey({ kind: "api-token", scheme: "bearer", username: null, credential: null, problem: null }), "token:bearer");
  assert.equal(authKey({ kind: "credential-header", header: "X-API-Key", credential: null, problem: null }), "header:x-api-key");
  assert.notEqual(authKey({ kind: "api-token", scheme: "basic", username: null, credential: null, problem: null }), authKey({ kind: "api-token", scheme: "bearer", username: null, credential: null, problem: null }));
});
