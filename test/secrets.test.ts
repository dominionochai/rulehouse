import test from "node:test";
import assert from "node:assert/strict";
import {
  decomposeAuthorizationHeader,
  envReference,
  fingerprintInlineSecret,
  unresolvedSecret,
} from "../src/lib/secrets.js";

const TOKEN = "RHO-SYNTHETIC-TOKEN-0001";
const basic = (username: string, token: string): string =>
  `Basic ${Buffer.from(`${username}:${token}`, "utf8").toString("base64")}`;

test("inline fingerprints are stable and content-derived", () => {
  const first = fingerprintInlineSecret(TOKEN);
  const second = fingerprintInlineSecret(TOKEN);
  assert.equal(first.fingerprint, second.fingerprint);
  assert.match(first.fingerprint, /^sha256:[0-9a-f]{16}$/);
  assert.equal(first.length, TOKEN.length);
});

test("fingerprints never contain the raw secret", () => {
  const fingerprint = JSON.stringify(fingerprintInlineSecret(TOKEN));
  assert.ok(!fingerprint.includes(TOKEN));
});

test("basic auth decomposes into a username and a fingerprint only", () => {
  const parts = decomposeAuthorizationHeader(basic("svc@corp.example", TOKEN), () => undefined);
  assert.equal(parts.scheme, "basic");
  assert.equal(parts.username, "svc@corp.example");
  assert.equal(parts.malformed, null);
  assert.ok(parts.secret !== null);
  assert.equal(parts.secret.origin, "inline");
  const serialized = JSON.stringify(parts);
  assert.ok(!serialized.includes(TOKEN));
});

test("basic auth with a non-base64 credential fails closed", () => {
  const parts = decomposeAuthorizationHeader("Basic not base64!!", () => undefined);
  assert.equal(parts.scheme, "basic");
  assert.match(parts.malformed ?? "", /not valid base64/);
  assert.equal(parts.secret, null);
});

test("basic auth padding and character-set validation", () => {
  assert.match(decomposeAuthorizationHeader("Basic abcd", () => undefined).malformed ?? "", /username:password/);
  assert.match(decomposeAuthorizationHeader("Basic ad=bc", () => undefined).malformed ?? "", /not valid base64/);
});

test("bearer tokens are fingerprinted without retaining the value", () => {
  const parts = decomposeAuthorizationHeader(`Bearer ${TOKEN}`, () => undefined);
  assert.equal(parts.scheme, "bearer");
  assert.equal(parts.username, null);
  assert.ok(parts.secret !== null);
  assert.ok(!JSON.stringify(parts).includes(TOKEN));
});

test("whole-value env references resolve through the supplied resolver", () => {
  const parts = decomposeAuthorizationHeader("Bearer ${ATLASSIAN_SERVICE_KEY}", (name) => (name === "ATLASSIAN_SERVICE_KEY" ? TOKEN : undefined));
  assert.equal(parts.scheme, "bearer");
  assert.equal(parts.secret?.origin, "environment");
  assert.equal(parts.secret?.envVar, "ATLASSIAN_SERVICE_KEY");
  assert.ok(!JSON.stringify(parts).includes(TOKEN));
});

test("unresolved env references produce an explicit unresolved credential", () => {
  const parts = decomposeAuthorizationHeader("Bearer ${MISSING_VAR}", () => undefined);
  assert.equal(parts.secret?.origin, "unresolved");
  assert.equal(parts.malformed, null);
});

test("whole-value env reference is recognized even for basic scheme", () => {
  const parts = decomposeAuthorizationHeader("${ATLASSIAN_SERVICE_KEY}", () => "some-token-material");
  assert.equal(parts.scheme, "env");
  assert.equal(parts.secret?.origin, "environment");
});

test("partial env interpolation is diagnosed, not guessed", () => {
  const parts = decomposeAuthorizationHeader("Bearer pre-${SUFFIX}-post", () => "x");
  assert.match(parts.malformed ?? "", /env interpolation/);
});

test("missing separator and unsupported schemes are reported", () => {
  assert.match(decomposeAuthorizationHeader("JustAToken", () => undefined).malformed ?? "", /separator/);
  assert.match(decomposeAuthorizationHeader("Digest abc", () => undefined).malformed ?? "", /unsupported authorization scheme/);
});

test("unresolvedSecret marks the variable but carries no material", () => {
  const secret = unresolvedSecret("SOME_VAR");
  assert.equal(secret.origin, "unresolved");
  assert.equal(secret.fingerprint, "");
  assert.equal(secret.envVar, "SOME_VAR");
});

test("envReference matches whole-value references only", () => {
  assert.equal(envReference("${VALID_NAME}")?.name, "VALID_NAME");
  assert.equal(envReference("${_ok2}")?.name, "_ok2");
  assert.equal(envReference("prefix ${NAME}"), null);
  assert.equal(envReference("${1BAD}"), null);
});
