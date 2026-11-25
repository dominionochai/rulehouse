import type { Json, ParseDiagnostic } from "./json.js";

type MutableJsonObject = { [key: string]: Json };

export interface TomlResult {
  /**
   * Always a mutable-free JSON object: every successfully parsed statement
   * contributes its part, every rejected statement is reported and skipped.
   */
  readonly value: Json;
  readonly diagnostics: readonly ParseDiagnostic[];
}

/**
 * A strict, character-stream TOML subset, sufficient for client
 * configurations like Codex's `config.toml` (`[mcp_servers.name]` tables,
 * string/integer/boolean values, arrays, comments) and deliberately nothing
 * else. Every construction outside the subset produces a diagnostic naming
 * the exact defect and the parser resyncs to the next statement, so one
 * exotic value never costs visibility into the rest of the file. It throws
 * on nothing and terminates on every input.
 *
 * The subset: bare and quoted keys (dotted), `[table]` / `[a.b]` headers,
 * basic strings with escapes, literal strings, integers (with `_` groups),
 * booleans, arrays (multi-line, nested, trailing commas), and comments.
 * Inline tables, floats, dates, and array-of-tables are rejected loudly.
 */
export function parseToml(text: string, source: string): TomlResult {
  return new TomlParser(text, source).parseDocument();
}

class TomlParser {
  private pos = 0;
  private readonly diagnostics: ParseDiagnostic[] = [];
  private readonly root: MutableJsonObject = {};
  /** The table that plain key-values currently belong to. */
  private current: MutableJsonObject = this.root;
  private readonly headerTables = new Set<string>();

  constructor(
    private readonly text: string,
    private readonly source: string,
  ) {}

  parseDocument(): TomlResult {
    if (this.text.charCodeAt(0) === 0xfeff) this.pos = 1;
    for (;;) {
      this.skipBlanks();
      if (this.peek() === null) break;
      if (this.peek() === "[") this.parseTableHeader();
      else this.parseKeyValuePair();
    }
    return { value: this.root, diagnostics: this.diagnostics };
  }

  private fail(message: string): void {
    this.diagnostics.push({ source: this.source, message });
  }

  /**
   * The only character accessors: at end of input every read answers null, so
   * no branch in the machine can walk past the buffer.
   */
  private peek(): string | null {
    return this.pos < this.text.length ? (this.text[this.pos] ?? null) : null;
  }

  private next(): string | null {
    const character = this.peek();
    if (character !== null) this.pos += 1;
    return character;
  }

  private skipInline(): void {
    while (this.peek() === " " || this.peek() === "\t") this.pos += 1;
  }

  private skipBlanks(): void {
    for (;;) {
      const character = this.peek();
      if (character === " " || character === "\t" || character === "\n" || character === "\r") {
        this.pos += 1;
        continue;
      }
      if (character === "#") {
        while (this.peek() !== null && this.peek() !== "\n") this.pos += 1;
        continue;
      }
      return;
    }
  }

  /**
   * Consumes tokens to the end of the current statement: a newline at bracket
   * depth zero, or a closing bracket, while stepping over intact strings so a
   * newline inside one never ends the resync. After it, the document loop can
   * continue at the next statement without misattributing keys.
   */
  private skipPastStatement(): void {
    let depth = 0;
    for (;;) {
      const character = this.next();
      if (character === null) return;
      if (character === "\"") this.skipBasicStringTail();
      else if (character === "'") this.skipLiteralStringTail();
      else if (character === "[") depth += 1;
      else if (character === "]") {
        depth -= 1;
        if (depth <= 0) return;
      } else if (character === "\n" && depth <= 0) return;
    }
  }

  private skipBasicStringTail(): void {
    for (;;) {
      const character = this.next();
      if (character === null || character === "\"") return;
      if (character === "\n") {
        this.pos -= 1;
        return;
      }
      if (character === "\\") {
        if (this.next() === null) return;
      }
    }
  }

  private skipLiteralStringTail(): void {
    for (;;) {
      const character = this.next();
      if (character === null || character === "'") return;
      if (character === "\n") {
        this.pos -= 1;
        return;
      }
    }
  }

  private skipRestOfLine(): void {
    while (this.peek() !== null && this.peek() !== "\n") this.pos += 1;
  }

  private isBareKeyCharacter(character: string): boolean {
    return /[A-Za-z0-9_-]/.test(character);
  }

  private parseKeyPath(): readonly string[] | null {
    const segments: string[] = [];
    for (;;) {
      this.skipInline();
      const character = this.peek();
      let segment: string | null = null;
      if (character === "\"") segment = this.parseBasicString();
      else if (character === "'") segment = this.parseLiteralString();
      else if (character !== null && this.isBareKeyCharacter(character)) {
        const start = this.pos;
        while (this.peek() !== null && this.isBareKeyCharacter(this.peek()!)) this.pos += 1;
        segment = this.text.slice(start, this.pos);
      } else this.fail(`expected a key, found ${describe(character)}`);
      if (segment === null) return null;
      segments.push(segment);
      this.skipInline();
      if (this.peek() === ".") {
        this.pos += 1;
        continue;
      }
      return segments;
    }
  }

  private displayPath(path: readonly string[]): string {
    return path.map((segment) => JSON.stringify(segment)).join(".");
  }

  private parseTableHeader(): void {
    this.pos += 1;
    if (this.peek() === "[") {
      this.fail("array-of-tables ([[name]]) is outside the supported subset; keys up to the next table header were skipped");
      this.pos += 1;
      this.skipRestOfLine();
      this.current = {};
      return;
    }
    const path = this.parseKeyPath();
    if (path === null) {
      this.skipPastStatement();
      return;
    }
    this.skipInline();
    if (this.next() !== "]") {
      this.fail(`expected "]" to close table header [${this.displayPath(path)}]`);
      this.skipPastStatement();
      return;
    }
    this.endOfStatement();
    this.openTable(path);
  }

  /**
   * A header opens its table for all following key-values. A failed header
   * parks `current` on a detached table, so the keys after a rejected header
   * land in a quarantine object instead of silently inheriting the previous
   * table's identity.
   */
  private openTable(path: readonly string[]): void {
    const canonical = this.displayPath(path);
    if (this.headerTables.has(canonical)) {
      this.fail(`duplicate table header [${this.displayPath(path)}]; the first declaration was kept`);
      this.current = {};
      return;
    }
    let node = this.root;
    for (const [index, segment] of path.entries()) {
      const existing = node[segment];
      if (existing === undefined) {
        const fresh: MutableJsonObject = {};
        node[segment] = fresh;
        node = fresh;
        continue;
      }
      if (isMutableJsonObject(existing)) {
        node = existing;
        continue;
      }
      this.fail(`table header [${this.displayPath(path)}] conflicts with an existing non-table value at "${this.displayPath(path.slice(0, index + 1))}"`);
      this.current = {};
      return;
    }
    this.headerTables.add(canonical);
    this.current = node;
  }

  private parseKeyValuePair(): void {
    this.skipInline();
    const path = this.parseKeyPath();
    if (path === null) {
      this.skipPastStatement();
      return;
    }
    this.skipInline();
    if (this.next() !== "=") {
      this.fail(`expected "=" after key ${this.displayPath(path)}`);
      this.skipPastStatement();
      return;
    }
    const value = this.parseValue();
    if (value === null) {
      this.skipPastStatement();
      return;
    }
    this.assign(path, value);
    this.endOfStatement();
  }

  /**
   * Statements are line-delimited: after one, only trailing whitespace, a
   * comment, or the newline may follow. Anything else means two statements
   * share a line, which TOML forbids and which would otherwise be misread as
   * a new key.
   */
  private endOfStatement(): void {
    this.skipInline();
    const character = this.peek();
    if (character === null || character === "\n" || character === "\r" || character === "#") return;
    this.fail(`unexpected content after the statement: ${describe(character)}`);
    this.skipPastStatement();
  }

  /**
   * Walks (creating as needed) the tables the dotted key addresses, then
   * stores the value. First-written values win: redefinitions keep the
   * earlier evidence and say so, which matters downstream because a file
   * where `enabled = false` is shadowed by `enabled = true` must not present
   * whichever line happened to come last.
   */
  private assign(path: readonly string[], value: Json): void {
    let node = this.current;
    for (const segment of path.slice(0, -1)) {
      const existing = node[segment];
      if (existing === undefined) {
        const fresh: MutableJsonObject = {};
        node[segment] = fresh;
        node = fresh;
        continue;
      }
      if (isMutableJsonObject(existing)) {
        node = existing;
        continue;
      }
      this.fail(`dotted key ${this.displayPath(path)} descends through "${segment}", which already holds a non-table value`);
      return;
    }
    const last = path[path.length - 1]!;
    if (node[last] !== undefined) {
      this.fail(`duplicate key ${this.displayPath(path)}; the first value was kept`);
      return;
    }
    node[last] = value;
  }

  private parseValue(): Json | null {
    this.skipInline();
    const character = this.peek();
    if (character === null) {
      this.fail("expected a value but reached end of input");
      return null;
    }
    if (character === "\"") return this.parseBasicString();
    if (character === "'") return this.parseLiteralString();
    if (character === "[") return this.parseArray();
    if (character === "{") {
      this.fail("inline tables ({ key = value }) are outside the supported subset; the value was skipped");
      return null;
    }
    if (character === "t") return this.parseKeyword("true", true);
    if (character === "f") return this.parseKeyword("false", false);
    if (/[0-9+-]/.test(character)) return this.parseInteger();
    this.fail(`unsupported value syntax starting with ${describe(character)}`);
    return null;
  }

  private parseKeyword(word: string, value: Json): Json | null {
    if (this.text.startsWith(word, this.pos)) {
      const after = this.text[this.pos + word.length] ?? "";
      if (after === "" || /[\s,#\]}]/.test(after)) {
        this.pos += word.length;
        return value;
      }
    }
    this.fail(`unsupported value syntax near "${word}${afterCharacters(this.text, this.pos)}"`);
    return null;
  }

  private parseInteger(): Json | null {
    let negative = false;
    if (this.peek() === "-" || this.peek() === "+") {
      negative = this.peek() === "-";
      this.pos += 1;
    }
    const start = this.pos;
    let index = start;
    while (index < this.text.length && /[0-9_]/.test(this.text[index]!)) index += 1;
    if (index === start) {
      this.fail("expected a number");
      return null;
    }
    const digits = this.text.slice(start, index);
    if (digits.startsWith("_") || digits.endsWith("_") || digits.includes("__")) {
      this.fail(`integer "${digits}" misuses underscores; they must sit between digits`);
      return null;
    }
    if (digits.length > 1 && digits[0] === "0") {
      this.fail(`integer "${digits}" has leading zeros; binary/octal/hex forms are outside the supported subset`);
      return null;
    }
    const after = this.text[index] ?? "";
    if (/[.eE]/.test(after)) {
      this.fail(`floats are outside the supported subset; the value starting at "${digits}${after}" was skipped`);
      return null;
    }
    if (after === "T" || after === "Z" || after === ":" || after === "-") {
      this.fail(`dates and times are outside the supported subset; the value starting at "${digits}" was skipped`);
      return null;
    }
    this.pos = index;
    return negative ? -Number(digits.replace(/_/g, "")) : Number(digits.replace(/_/g, ""));
  }

  private parseBasicString(): string | null {
    this.pos += 1;
    let out = "";
    for (;;) {
      const character = this.next();
      if (character === "\"") return out;
      if (character === null) {
        this.fail("unterminated basic string");
        return null;
      }
      if (character === "\n") {
        this.pos -= 1;
        this.fail("unterminated basic string");
        return null;
      }
      if (character !== "\\") {
        out += character;
        continue;
      }
      const escape = this.next();
      switch (escape) {
        case "b": out += "\b"; break;
        case "t": out += "\t"; break;
        case "n": out += "\n"; break;
        case "f": out += "\f"; break;
        case "r": out += "\r"; break;
        case "\"": out += "\""; break;
        case "\\": out += "\\"; break;
        case "u":
        case "U": {
          const width = escape === "u" ? 4 : 8;
          const hex = this.text.slice(this.pos, this.pos + width);
          if (hex.length !== width || !/^[0-9a-fA-F]+$/.test(hex)) {
            this.fail(`invalid unicode escape \\${escape}${hex}`);
            return null;
          }
          const codePoint = Number.parseInt(hex, 16);
          if (codePoint > 0x10ffff || (codePoint >= 0xd800 && codePoint <= 0xdfff)) {
            this.fail(`\\${escape}${hex} is not a scalar unicode code point`);
            return null;
          }
          out += String.fromCodePoint(codePoint);
          this.pos += width;
          break;
        }
        case null:
          this.fail("unterminated basic string");
          return null;
        default:
          this.fail(`unsupported escape \\${escape} in basic string`);
          return null;
      }
    }
  }

  private parseLiteralString(): string | null {
    this.pos += 1;
    const newline = this.text.indexOf("\n", this.pos);
    const end = this.text.indexOf("'", this.pos);
    if (end === -1 || (newline !== -1 && newline < end)) {
      this.pos = newline === -1 ? this.text.length : newline;
      this.fail(end === -1 ? "unterminated literal string" : "literal strings cannot span lines in this subset");
      return null;
    }
    const value = this.text.slice(this.pos, end);
    this.pos = end + 1;
    return value;
  }

  private parseArray(): Json | null {
    this.pos += 1;
    const items: Json[] = [];
    for (;;) {
      this.skipBlanks();
      const character = this.peek();
      if (character === null) {
        this.fail("unterminated array");
        return null;
      }
      if (character === "]") {
        this.pos += 1;
        return items;
      }
      const item = this.parseValue();
      if (item === null) {
        this.skipPastStatement();
        return null;
      }
      items.push(item);
      this.skipBlanks();
      const separator = this.next();
      if (separator === ",") continue;
      if (separator === "]") return items;
      this.fail(`expected "," or "]" in array, found ${describe(separator)}`);
      this.skipPastStatement();
      return null;
    }
  }
}

function isMutableJsonObject(value: Json): value is MutableJsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function describe(character: string | null): string {
  return character === null ? "end of input" : `"${character}"`;
}

function afterCharacters(text: string, pos: number): string {
  return text.slice(pos, pos + 8);
}
