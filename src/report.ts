import type { InventoryEntry, ScanDiagnostic } from "./model.js";
import type { RuleVerdict } from "./policy.js";
import { RULE_CATALOG } from "./policy.js";
import type { Snapshot } from "./snapshot.js";
import { VERSION } from "./version.js";

export interface ScanReport {
  readonly tool: "rulehouse-continuous-assurance";
  readonly version: string;
  readonly generatedAt: string;
  readonly root: string;
  readonly fingerprint: string;
  readonly inventorySize: number;
  readonly inputs: readonly { readonly path: string; readonly sha256: string; readonly bytes: number }[];
  readonly diagnostics: readonly ScanDiagnostic[];
  readonly inventory: readonly InventoryEntry[];
  readonly verdicts: readonly RuleVerdict[];
}

export function scanReportOf(
  snapshot: Snapshot,
  evaluation: { readonly verdicts: readonly RuleVerdict[] },
  generatedAt: string,
): ScanReport {
  return {
    tool: "rulehouse-continuous-assurance",
    version: VERSION,
    generatedAt,
    root: snapshot.root,
    fingerprint: snapshot.fingerprint,
    inventorySize: snapshot.inventory.length,
    inputs: snapshot.inputs,
    diagnostics: snapshot.diagnostics,
    inventory: snapshot.inventory,
    verdicts: evaluation.verdicts,
  };
}

export function findingsOf(report: ScanReport): readonly RuleVerdict[] {
  const severityRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  return report.verdicts
    .filter((verdict) => verdict.status === "finding")
    .sort((a, b) =>
      (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9)
      || a.ruleId.localeCompare(b.ruleId)
      || a.subject.localeCompare(b.subject),
    );
}

function authSummary(entry: InventoryEntry): string {
  switch (entry.auth.kind) {
    case "oauth":
      return "OAuth 2.1";
    case "api-token": {
      const scope = entry.auth.username !== null ? ` as ${entry.auth.username}` : "";
      return `API token (${entry.auth.scheme})${scope}`;
    }
    case "credential-header":
      return `credential header ${entry.auth.header}`;
    case "unknown":
      return `unclassified: ${entry.auth.reason}`;
  }
}

function cell(text: string): string {
  return text.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

/**
 * Renders the evidence-grade Markdown report. Passes and findings are both
 * enumerated, every verdict carries its file-and-pointer subject, and the
 * evidence section lists the SHA-256 of every input file plus the snapshot
 * fingerprint, so another engineer can verify each claim against the exact
 * bytes analyzed without re-running anything.
 */
export function renderMarkdownReport(report: ScanReport, findings: readonly RuleVerdict[]): string {
  const lines: string[] = [];
  const push = (line: string = ""): void => {
    lines.push(line);
  };

  push("# Rulehouse Continuous Assurance — Security Report");
  push();
  push(`- Scan root: \`${report.root}\``);
  push(`- Generated: ${report.generatedAt}`);
  push(`- Tool: rulehouse v${report.version}`);
  push(`- Snapshot fingerprint: \`${report.fingerprint}\``);
  push(`- Registrations: ${report.inventorySize}`);
  push(`- Findings: **${findings.length}**`);
  push();

  push("## Inventory");
  push();
  push("| Client | Server | Transport | Endpoint | Auth | Source |");
  push("| --- | --- | --- | --- | --- | --- |");
  for (const entry of report.inventory) {
    push(
      `| ${cell(entry.client)} | ${cell(entry.serverName)} | ${cell(entry.transport)} | ${cell(entry.endpointClass)} | ${cell(authSummary(entry))} | \`${cell(entry.source.file)}\`${cell(entry.source.pointer)} |`,
    );
  }
  push();

  push("## Findings");
  push();
  if (findings.length === 0) {
    push("None. Every in-scope rule passed on every in-scope element.");
  } else {
    push("| Rule | Severity | Subject | Detail |");
    push("| --- | --- | --- | --- |");
    for (const finding of findings) {
      push(`| ${cell(finding.ruleId)} | ${cell(finding.severity)} | \`${cell(finding.subject)}\` | ${cell(finding.message)} |`);
    }
  }
  push();

  push("## Policy verification detail");
  push();
  const ruleIds = [...new Set(report.verdicts.map((verdict) => verdict.ruleId))].sort();
  for (const ruleId of ruleIds) {
    const group = report.verdicts.filter((verdict) => verdict.ruleId === ruleId);
    const catalog = RULE_CATALOG.get(ruleId);
    const findingCount = group.filter((verdict) => verdict.status === "finding").length;
    const passCount = group.filter((verdict) => verdict.status === "pass").length;
    push(`### ${ruleId} — ${catalog?.title ?? "adaptive rule"}`);
    push();
    if (catalog !== undefined) {
      push(catalog.rationale);
      push();
    }
    push(`Findings: ${findingCount} · Explicit passes: ${passCount} · Out of scope: ${group.length - findingCount - passCount}`);
    push();
    for (const verdict of group) {
      if (verdict.status === "finding") {
        push(`- ❌ \`${verdict.subject}\` — ${verdict.message}`);
      }
    }
    for (const verdict of group) {
      if (verdict.status === "pass") {
        push(`- ✅ \`${verdict.subject}\` — ${verdict.message}`);
      }
    }
    for (const verdict of group) {
      if (verdict.status === "not-applicable") {
        push(`- ⚪ ${verdict.message}`);
      }
    }
    push();
  }

  push("## Parse diagnostics");
  push();
  if (report.diagnostics.length === 0) {
    push("None. Every scanned file parsed cleanly.");
  } else {
    for (const diagnostic of report.diagnostics) {
      push(`- \`${diagnostic.source}\`${cell(diagnostic.subject)} — ${cell(diagnostic.message)}`);
    }
  }
  push();

  push("## Evidence");
  push();
  push("| Input file | SHA-256 | Bytes |");
  push("| --- | --- | --- |");
  for (const input of report.inputs) {
    push(`| \`${cell(input.path)}\` | \`${input.sha256}\` | ${input.bytes} |`);
  }
  push();
  push("Verification for another engineer:");
  push();
  push("```sh");
  push(`sha256sum ${report.inputs.map((input) => `<root>/${input.path}`).join(" ")}`);
  push("```");
  push();
  push("Each digest must match the SHA-256 above; if it does, the findings in this report describe exactly those bytes.");

  return `${lines.join("\n")}\n`;
}
