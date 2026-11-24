import test from "node:test";
import assert from "node:assert/strict";
import { canonicalize, normalizeJsonc, parseLooseJson, sha256Hex } from "../src/lib/json.js";

test("normalizeJsonc drops line and block comments", () => {
  const text = `{
    // single line
    "a": 1, /* inline block */
    "b": [2, 3] // trailing comment
  }`;
  assert.deepEqual(JSON.parse(normalizeJsonc(text)), { a: 1, b: [2, 3] });
});

test("normalizeJsonc strips trailing commas in every position", () => {
  const text = '{"a": [1, 2,], "b": {"c": 3,},}';
  assert.deepEqual(JSON.parse(normalizeJsonc(text)), { a: [1, 2], b: { c: 3 } });
});

test("normalizeJsonc treats comment lookalikes inside strings as data", () => {
  const text = '{"url": "https://mcp.atlassian.com/v2/mcp?a=/*not-a-comment*/"}';
  assert.deepEqual(JSON.parse(normalizeJsonc(text)), { url: "https://mcp.atlassian.com/v2/mcp?a=/*not-a-comment*/" });
});

test("normalizeJsonc handles escaped quotes and backslashes in strings", () => {
  const text = '{"a": "quote \\" here // still string", "b": "back \\\\ slash"}';
  assert.deepEqual(JSON.parse(normalizeJsonc(text)), { a: 'quote " here // still string', b: "back \\ slash" });
});

test("normalizeJsonc keeps live commas that precede elements", () => {
  const text = '[1, 2, 3]';
  assert.deepEqual(JSON.parse(normalizeJsonc(text)), [1, 2, 3]);
});

test("normalizeJsonc drops a trailing comma even with a comment between it and the closer", () => {
  const text = '{"a": 1, // note\n}';
  assert.deepEqual(JSON.parse(normalizeJsonc(text)), { a: 1 });
});

test("canonicalize is independent of key order and stable", () => {
  const a = { z: 1, a: { y: 2, b: 3 } };
  const b = { a: { b: 3, y: 2 }, z: 1 };
  assert.equal(canonicalize(a), canonicalize(b));
  assert.equal(canonicalize(a), '{"a":{"b":3,"y":2},"z":1}');
});

test("canonicalize keeps array order significant", () => {
  assert.notEqual(canonicalize([1, 2]), canonicalize([2, 1]));
});

test("sha256Hex is deterministic", () => {
  assert.equal(sha256Hex("rulehouse"), sha256Hex("rulehouse"));
  assert.notEqual(sha256Hex("rulehouse"), sha256Hex("rulehousE"));
});

test("parseLooseJson reports malformed input as a diagnostic instead of throwing", () => {
  const result = parseLooseJson('{"a": tru}', "bad.json");
  assert.equal(result.value, null);
  assert.equal(result.diagnostics.length, 1);
  assert.match(result.diagnostics[0]!.message, /parseable as JSON/);
});

test("parseLooseJson accepts JSONC features", () => {
  const result = parseLooseJson('{ // c\n"a": 1,\n}', "ok.json");
  assert.deepEqual(result.value, { a: 1 });
  assert.equal(result.diagnostics.length, 0);
});
