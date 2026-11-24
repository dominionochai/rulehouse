import { sha256Hex } from "./json.js";

/**
 * How a credential enters the system. `inline` means the secret material was
 * written into a configuration file itself; `environment` means the file
 * references an environment variable; `unresolved` means a variable reference
 * whose value is not available to the scanner (managed by a secret store, a
 * client keychain, or simply unset in this shell).
 */
export type CredentialOrigin = "inline" | "environment" | "unresolved";

/**
 * The only representation of secret material that exists anywhere downstream
 * of parsing: a SHA-256 fingerprint prefix and non-secret descriptive facts.
 * The type system makes forgetting to fingerprint a secret a compile error,
 * because there is no field to put the raw value in.
 *
 * Fingerprints are stable, so an engineer holding the original token can
 * hash it locally (`printf '%s' "$TOKEN" | sha256sum`) and confirm the prefix
 * matches the one in a Rulehouse report — cross-checking evidence without the
 * report ever having contained the token.
 */
export interface SecretFingerprint {
  readonly origin: CredentialOrigin;
  /** `sha256:<first 16 hex chars>` — never contains the secret itself. */
  readonly fingerprint: string;
  /**
   * A one-character wildcard probe (first and last character) to help
   * engineers recognize WHICH configured value a fingerprint refers to when
   * they legitimately hold the secret. Two characters cannot reconstruct a
   * strong token but do make multi-credential reports navigable.
   */
  readonly probe: string;
  readonly length: number;
  /** Environment-variable name for `origin: "environment"` values. */
  readonly envVar: string | null;
}

export function fingerprintInlineSecret(raw: string): SecretFingerprint {
  return {
    origin: "inline",
    fingerprint: `sha256:${sha256Hex(raw).slice(0, 16)}`,
    probe: probeOf(raw),
    length: raw.length,
    envVar: null,
  };
}

export function fingerprintEnvSecret(raw: string, envVar: string): SecretFingerprint {
  return {
    origin: "environment",
    fingerprint: `sha256:${sha256Hex(raw).slice(0, 16)}`,
    probe: probeOf(raw),
    length: raw.length,
    envVar,
  };
}

export function unresolvedSecret(envVar: string): SecretFingerprint {
  return { origin: "unresolved", fingerprint: "", probe: "?", length: 0, envVar };
}

function probeOf(raw: string): string {
  if (raw.length === 0) return "?";
  if (raw.length === 1) return `${raw}?`;
  return `${raw[0]}…${raw[raw.length - 1]}`;
}

export type AuthorizationScheme = "basic" | "bearer" | "env" | null;

/**
 * Decomposed contents of an `Authorization` header. For Basic auth the
 * username (typically an Atlassian account email) is deliberately retained —
 * it is not secret and it is exactly the attribution fact a security team
 * needs for the API-token path — while the token is reduced to a
 * fingerprint. For Bearer auth only the fingerprint exists, since the entire
 * value is the credential.
 */
export interface AuthorizationParts {
  readonly scheme: AuthorizationScheme;
  readonly username: string | null;
  readonly secret: SecretFingerprint | null;
  readonly malformed: string | null;
}

const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;

/**
 * Splits an `Authorization` header value into its non-secret parts, or
 * explains why it could not be split. Lenient anything-to-string decoding of
 * base64 is one of the classic ways scanners leak or misclassify
 * credentials, so the decoder here validates shape first and fails closed to
 * `malformed` rather than guessing.
 */
export function decomposeAuthorizationHeader(value: string, resolveEnv: (name: string) => string | undefined): AuthorizationParts {
  const env = envReference(value);
  if (env !== null) {
    const resolved = resolveEnv(env.name);
    return {
      scheme: "env",
      username: null,
      secret: resolved === undefined || resolved.length === 0 ? unresolvedSecret(env.name) : fingerprintEnvSecret(resolved, env.name),
      malformed: null,
    };
  }

  const schemeEnd = value.indexOf(" ");
  if (schemeEnd < 0) {
    return { scheme: null, username: null, secret: null, malformed: "missing scheme/value separator" };
  }
  const scheme = value.slice(0, schemeEnd).toLowerCase();
  const rest = value.slice(schemeEnd + 1).trim();
  if (rest.length === 0) {
    return { scheme: null, username: null, secret: null, malformed: `empty credential part after scheme "${scheme}"` };
  }
  const credentialEnv = envReference(rest);
  if (credentialEnv !== null) {
    if (scheme === "basic" || scheme === "bearer") {
      const resolved = resolveEnv(credentialEnv.name);
      return {
        scheme,
        username: null,
        secret: resolved === undefined || resolved.length === 0 ? unresolvedSecret(credentialEnv.name) : fingerprintEnvSecret(resolved, credentialEnv.name),
        malformed: null,
      };
    }
    return { scheme: null, username: null, secret: null, malformed: `env reference with unsupported authorization scheme "${scheme}"` };
  }
  if (rest.includes("${")) {
    return { scheme: null, username: null, secret: null, malformed: `credential embeds partial env interpolation after scheme "${scheme}"; only whole-value $\{VAR\} references are supported` };
  }

  if (scheme === "basic") {
    if (!BASE64_PATTERN.test(rest) || rest.length % 4 !== 0) {
      return { scheme: "basic", username: null, secret: null, malformed: "credential part is not valid base64" };
    }
    let decoded: string;
    try {
      decoded = Buffer.from(rest, "base64").toString("utf8");
    } catch {
      return { scheme: "basic", username: null, secret: null, malformed: "base64 payload decodes to invalid UTF-8" };
    }
    const separator = decoded.indexOf(":");
    if (separator < 0 || separator === 0 || separator === decoded.length - 1) {
      return { scheme: "basic", username: null, secret: null, malformed: "base64 payload is not username:password shaped" };
    }
    return {
      scheme: "basic",
      username: decoded.slice(0, separator),
      secret: fingerprintInlineSecret(decoded.slice(separator + 1)),
      malformed: null,
    };
  }

  if (scheme === "bearer") {
    const envRef = envReference(rest);
    if (envRef !== null) {
      const resolved = resolveEnv(envRef.name);
      return {
        scheme: "bearer",
        username: null,
        secret: resolved === undefined || resolved.length === 0 ? unresolvedSecret(envRef.name) : fingerprintEnvSecret(resolved, envRef.name),
        malformed: null,
      };
    }
    return { scheme: "bearer", username: null, secret: fingerprintInlineSecret(rest), malformed: null };
  }

  return { scheme: null, username: null, secret: null, malformed: `unsupported authorization scheme "${scheme}"` };
}

const ENV_REFERENCE_PATTERN = /^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$/;

/** A header value that is exactly one `${VAR}` reference, else null. */
export function envReference(value: string): { readonly name: string } | null {
  const match = ENV_REFERENCE_PATTERN.exec(value);
  return match === null ? null : { name: match[1]! };
}
