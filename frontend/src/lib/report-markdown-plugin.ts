import { unified } from "unified";
import remarkParse from "remark-parse";
import remarkGfm from "remark-gfm";
import { visit } from "unist-util-visit";
import type { Plugin } from "unified";
import type { Root } from "mdast";

/**
 * `render_markdown()` (backend/app/services/report_render.py) emits
 * 100%-deterministic Markdown — only the prose paragraphs are LLM-written,
 * every heading/table/line shape is fixed. This module recognizes three of
 * those fixed shapes at the mdast level (the parsed-Markdown tree, before
 * react-markdown turns it into React) and retags them so `markdown.tsx` can
 * render real app components instead of generic HTML — the same
 * recognize-a-shape/retag-it idiom `remark-gfm` itself uses for tables.
 *
 * Anything that doesn't match falls through untouched: a future wording
 * change in `report_render.py` degrades to plain rendering, not a mis-render.
 */

const PILLAR_SUMMARY_HEADER = ["Pillar", "Critical", "High", "Medium", "Low"];
const RESOURCE_TABLE_HEADER = ["Resource", "Region", "Detail", "Status"];

/** The one place that knows what these two tables' headers look like — used
 *  by both the in-body retagging below and `parseSeverityTotals`, so the two
 *  can't drift apart. */
function classifyTable(headerTexts: string[]): "report-pillar-summary" | "report-resource-table" | null {
  if (arraysEqual(headerTexts, PILLAR_SUMMARY_HEADER)) return "report-pillar-summary";
  if (arraysEqual(headerTexts, RESOURCE_TABLE_HEADER)) return "report-resource-table";
  return null;
}

function arraysEqual(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/** Plain-text content of a table cell, whatever inline markup it holds. */
function nodeText(node: any): string {
  if (node.type === "text" || node.type === "inlineCode") return node.value;
  if (Array.isArray(node.children)) return node.children.map(nodeText).join("");
  return "";
}

interface CheckMetaMatch {
  checkId: string;
  severity: string;
  category: string | null;
}

/** Matches the exact shape `` `{check_id}` · **{Severity}**`` (+ optional
 *  ` · {category}`) that `render_markdown()` always emits for a check's
 *  meta line — inline code, then a literal " · ", then a bold-only severity
 *  word, then an optional second " · category" text run. */
function matchCheckMeta(children: any[]): CheckMetaMatch | null {
  if (children.length !== 3 && children.length !== 4) return null;
  const [codeNode, sepNode, strongNode, catNode] = children;
  if (codeNode.type !== "inlineCode") return null;
  if (sepNode.type !== "text" || sepNode.value !== " · ") return null;
  if (strongNode.type !== "strong" || strongNode.children?.length !== 1) return null;
  const severityChild = strongNode.children[0];
  if (severityChild.type !== "text") return null;

  let category: string | null = null;
  if (children.length === 4) {
    if (catNode.type !== "text") return null;
    const match = / · (.+)$/.exec(catNode.value);
    if (!match) return null;
    category = match[1];
  }
  return { checkId: codeNode.value, severity: severityChild.value.toLowerCase(), category };
}

/** The remark plugin: retags the check-meta paragraph as a `div` react-markdown
 *  can intercept, and stamps a `className` onto the two tables it recognizes. */
export const reportMarkdownPlugin: Plugin<[], Root> = () => (tree) => {
  visit(tree, "paragraph", (node: any) => {
    const match = matchCheckMeta(node.children ?? []);
    if (!match) return;
    node.data = {
      ...node.data,
      hName: "div",
      hProperties: {
        className: "report-check-meta",
        "data-check-id": match.checkId,
        "data-severity": match.severity,
        "data-category": match.category ?? "",
      },
    };
  });

  // The two recognized tables are replaced wholesale — `hChildren: []` tells
  // mdast-util-to-hast to discard the original thead/tbody/tr/td structure
  // rather than nest it inside the new element — because their data (which
  // column is "Critical", which cell is the Status column) is far easier to
  // read off the mdast rows directly, here, than to reconstruct later from
  // react-markdown's already-rendered `th`/`td` component tree, which has no
  // built-in notion of "which column am I."  The row data travels as a single
  // JSON `data-rows` attribute; `markdown.tsx`'s `div` override renders a
  // fully custom table from it.
  visit(tree, "table", (node: any) => {
    const headerRow = node.children?.[0];
    if (!headerRow) return;
    const className = classifyTable(headerRow.children.map(nodeText));
    if (!className) return;

    const dataRows = node.children.slice(1).map((row: any) => row.children.map(nodeText));
    node.data = {
      ...node.data,
      hName: "div",
      hProperties: { className, "data-rows": JSON.stringify(dataRows) },
      hChildren: [],
    };
  });
};

/** Groups each `###` finding heading together with everything up to the next
 *  heading (of any level) or `---` into one wrapper node, so print CSS has a
 *  single element per finding to apply `break-inside: avoid` to.
 *
 *  Without this, `render_markdown()`'s output is a flat run of siblings — an
 *  `h3`, the check-meta line, prose paragraphs, a remediation code block, the
 *  resource table — with nothing marking where one finding ends and the next
 *  begins. Chrome's print pagination then splits between any two of those
 *  siblings, which is what stranded a heading at the bottom of a page while
 *  its own content started the next (see the print-CSS work this plugin was
 *  added for). `##` pillar headings and `---` rules are left untouched: only
 *  the run following an `###` is wrapped. */
function sectionizeFindings(children: any[]): any[] {
  const result: any[] = [];
  let current: any[] | null = null;

  const flush = () => {
    if (!current) return;
    result.push({
      type: "reportSubsection",
      children: current,
      data: { hName: "div", hProperties: { className: "report-subsection" } },
    });
    current = null;
  };

  for (const node of children) {
    const isBoundary = (node.type === "heading" && node.depth <= 3) || node.type === "thematicBreak";
    if (isBoundary) {
      flush();
      if (node.type === "heading" && node.depth === 3) {
        current = [node];
      } else {
        result.push(node);
      }
      continue;
    }
    (current ?? result).push(node);
  }
  flush();
  return result;
}

/** Registered alongside `reportMarkdownPlugin` in `markdown.tsx`. Order
 *  relative to it doesn't matter: this only inspects `node.type`
 *  (`heading`/`thematicBreak`), which `reportMarkdownPlugin` never changes —
 *  it only adds `data.hName` to paragraph/table nodes it retags. */
export const sectionizeReportPlugin: Plugin<[], Root> = () => (tree: any) => {
  tree.children = sectionizeFindings(tree.children);
};

export interface ReportSeverityTotals {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

/** Sums the Pillar Summary table's columns — the same table
 *  `classifyTable` recognizes above, parsed once via a throwaway pass so the
 *  report's stat band agrees with the numbers rendered in the body. */
export function parseSeverityTotals(content: string): ReportSeverityTotals {
  const totals: ReportSeverityTotals = { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
  const tree = unified().use(remarkParse).use(remarkGfm).parse(content);

  visit(tree, "table", (node: any) => {
    const headerRow = node.children?.[0];
    if (!headerRow) return;
    if (classifyTable(headerRow.children.map(nodeText)) !== "report-pillar-summary") return;
    for (const row of node.children.slice(1)) {
      const [, critical, high, medium, low] = row.children.map(nodeText);
      totals.critical += Number(critical) || 0;
      totals.high += Number(high) || 0;
      totals.medium += Number(medium) || 0;
      totals.low += Number(low) || 0;
    }
  });

  totals.total = totals.critical + totals.high + totals.medium + totals.low;
  return totals;
}

/** `## ` headings that are not pillars.
 *
 *  The renderer emits one `##` per WAF pillar plus these fixed sections, so
 *  the table of contents has to exclude them by name — there is nothing in
 *  the Markdown itself that distinguishes "Key Themes" from "Reliability".
 *  Key Themes, Remediation Plan, Live-State Reconciliation and Evidence
 *  Appendix appear in `deep` mode only; listing them unconditionally is
 *  harmless and means the two modes share one code path.
 *
 *  Mirrors `backend/app/agents/report_ledger.py::NON_PILLAR_SECTIONS`, which
 *  makes the same exclusion for the same reason on the verification side.
 *  Adding a section to the renderer means adding it in both places. */
const NON_PILLAR_SECTIONS = new Set([
  "Executive Summary",
  "Pillar Summary",
  "Key Themes",
  "Remediation Plan",
  "Live-State Reconciliation",
  "Evidence Appendix",
]);

/** Plain-text pillar names in document order, for the table of contents —
 *  a line scan is enough here, no need for a second mdast pass. */
export function extractPillarHeadings(content: string): string[] {
  const headings: string[] = [];
  for (const line of content.split("\n")) {
    const match = /^## (.+)$/.exec(line.trim());
    if (!match) continue;
    const heading = match[1].trim();
    if (NON_PILLAR_SECTIONS.has(heading)) continue;
    headings.push(heading);
  }
  return headings;
}
