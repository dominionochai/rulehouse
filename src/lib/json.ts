import { createHash } from "node:crypto";

/**
 * The JSON subset Rulehouse operates on. Accepting `readonly` types everywhere
 * keeps parsed configurations immutable, which is what lets the parser hand
 * the same object to inventory, policy, and snapshot code without any of them
 * being able to disturb another's view.
 */
export type Json =
  | string
  | number
  | boolean
  | null
  | readonly Json[]
  | { readonly [key: string]: Json };

export interface ParseDiagnostic {
  readonly source: string;
  readonly message: string;
}

/**
 * Canonical JSON serialization: object keys sorted, no insignificant
 * whitespace. Two values serialize identically if and only if they are
 * structurally equal, which is the property the snapshot hash relies on to
 * make drift detection reproducible across runs, machines, and key orderings.
 */
export function canonicalize(value: Json): string {
  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "number":
    case "boolean":
      return String(value);
    case "object":
      if (value === null) return "null";
      if (Array.isArray(value)) {
        return `[${value.map(canonicalize).join(",")}]`;
      }
      return `{${Object.entries(value)
        .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
        .map(([key, element]) => `${JSON.stringify(key)}:${canonicalize(element)}`)
        .join(",")}}`;
  }
}

export function sha256Hex(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}

/**
 * Parses JSON or JSONC text into a mutable-free Json tree. Tolerates the two
 * relaxations VS Code's `mcp.json` and other editor configs allow in practice
 * — comments and trailing commas — via `normalizeJsonc`, and reports every
 * failure as a diagnostic instead of throwing, because a scanner that refuses
 * to run over one malformed file leaves the rest of the fleet unaudited.
 */
export function parseLooseJson(text: string, source: string): { readonly value: Json; readonly diagnostics: readonly ParseDiagnostic[] } {
  const normalized = normalizeJsonc(text);
  let parsed: unknown;
  try {
    parsed = JSON.parse(normalized);
  } catch (error) {
    return {
      value: null,
      diagnostics: [{ source, message: `not parseable as JSON/JSONC: ${(error as Error).message}` }],
    };
  }
  if (!isJson(parsed)) {
    return { value: null, diagnostics: [{ source, message: "document contains no JSON-representable value" }] };
  }
  return { value: parsed, diagnostics: [] };
}

function isJson(value: unknown): value is Json {
  if (value === null) return true;
  switch (typeof value) {
    case "string":
    case "number":
    case "boolean":
      return true;
    case "object":
      if (Array.isArray(value)) return value.every(isJson);
      return Object.values(value).every(isJson);
    default:
      return false;
  }
}

/**
 * One pass, one state machine: drops comments and strips a comma whose only
 * successors before its closing bracket are whitespace or comments (i.e. a
 * trailing comma), while correctly treating string contents — including the
 * `//` in "https://…" and escaped quotes — as opaque data.
 *
 * The algorithm tracks the output index of every code-context comma and, on
 * each closing bracket, un-records commas separated from it by whitespace
 * only. A comma before a live element (e.g. the one after `1` in `[1,2,3]`)
 * never clears the test because the element appears between it and the
 * bracket.
 */
export function normalizeJsonc(text: string): string {
  type State = "code" | "string" | "escape" | "line-comment" | "block-comment";

  let out = "";
  let state: State = "code";
  const openCommas: number[] = [];

  const isSpace = (ch: string): boolean => ch === " " || ch === "\t" || ch === "\n" || ch === "\r";

  const tailIsBlankFrom = (index: number): boolean => {
    for (let i = index; i < out.length; i++) {
      if (!isSpace(out[i]!)) return false;
    }
    return true;
  };

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    switch (state) {
      case "string":
        out += ch;
        if (ch === "\\") state = "escape";
        else if (ch === '"') state = "code";
        break;
      case "escape":
        out += ch;
        state = "string";
        break;
      case "line-comment":
        if (ch === "\n") {
          out += ch;
          state = "code";
        }
        break;
      case "block-comment":
        if (ch === "*" && text[i + 1] === "/") {
          state = "code";
          i++;
        }
        break;
      case "code":
        if (ch === '"') {
          out += ch;
          state = "string";
        } else if (ch === "/" && text[i + 1] === "/") {
          state = "line-comment";
          i++;
        } else if (ch === "/" && text[i + 1] === "*") {
          state = "block-comment";
          i++;
        } else if (ch === ",") {
          openCommas.push(out.length);
          out += ch;
        } else if (ch === "}" || ch === "]") {
          while (openCommas.length > 0) {
            const last = openCommas[openCommas.length - 1]!;
            if (!tailIsBlankFrom(last + 1)) break;
            openCommas.pop();
            out = out.slice(0, last);
          }
          out += ch;
        } else {
          out += ch;
        }
        break;
    }
  }

  return out;
}
