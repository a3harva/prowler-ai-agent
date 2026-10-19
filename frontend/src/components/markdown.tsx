import { Children, isValidElement, type ReactNode } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { reportMarkdownPlugin, sectionizeReportPlugin } from "@/lib/report-markdown-plugin";
import { slugify } from "@/lib/slugify";
import { SeverityChip, type Severity } from "@/components/severity-chip";
import { ReportResourceStatus } from "@/components/report-resource-status";

/**
 * Renders a generated report as styled Markdown.
 *
 * `remark-gfm` is required, not optional: every report is mostly tables (the
 * pillar summary, and the affected-resources table under each check), and those
 * are GitHub-flavoured rather than CommonMark — without it they render as
 * literal pipes.
 *
 * `reportMarkdownPlugin` recognizes three of `render_markdown()`'s fixed,
 * machine-generated shapes (the check_id/severity/category line, the Pillar
 * Summary table, the Affected resources table — see
 * `lib/report-markdown-plugin.ts`) and retags them so they render through
 * this app's own `SeverityChip`/`ReportResourceStatus` rather than generic
 * HTML. A wording change upstream simply stops matching and falls back to
 * plain rendering — it can't mis-render.
 *
 * Element styling is written out here rather than pulled from a typography
 * plugin, because the app's palette and type scale already exist as tokens and
 * a prose plugin would introduce a second, competing set.
 */

function textContent(node: ReactNode): string {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(textContent).join("");
  if (isValidElement(node)) return textContent((node.props as { children?: ReactNode }).children);
  return "";
}

const SEVERITY_TEXT_CLASS: Record<string, string> = {
  Critical: "text-sev-critical",
  High: "text-sev-high",
  Medium: "text-sev-medium",
  Low: "text-sev-low",
};

/** `render_markdown()`'s `_summary_table()` — one row per pillar, columns
 *  Pillar/Critical/High/Medium/Low. Rendered as a real table with each
 *  severity column colored by its token, instead of plain grey numerals. */
function PillarSummaryTable({ rows }: { rows: string[][] }) {
  return (
    <div className="mb-4 overflow-x-auto rounded-md border border-hairline">
      <table className="w-full border-collapse text-left text-xs">
        <thead className="bg-subtle">
          <tr>
            {["Pillar", "Critical", "High", "Medium", "Low"].map((h) => (
              <th key={h} className="border-b border-hairline px-3 py-2 font-medium text-ink">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map(([pillar, critical, high, medium, low], i) => (
            <tr key={i}>
              <td className="border-b border-hairline px-3 py-2 align-top text-ink-secondary">
                {pillar}
              </td>
              {[critical, high, medium, low].map((value, j) => {
                const label = ["Critical", "High", "Medium", "Low"][j];
                return (
                  <td
                    key={j}
                    className={`border-b border-hairline px-3 py-2 align-top font-medium tabular-nums ${SEVERITY_TEXT_CLASS[label]}`}
                  >
                    {value}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** `render_markdown()`'s `_resource_table()` — the Status column becomes a
 *  real pill (`ReportResourceStatus`) instead of plain "Open"/"Accepted
 *  Risk — {reason}" text. */
function ResourceTable({ rows }: { rows: string[][] }) {
  return (
    <div className="mb-4 overflow-x-auto rounded-md border border-hairline">
      <table className="w-full border-collapse text-left text-xs">
        <thead className="bg-subtle">
          <tr>
            {["Resource", "Region", "Detail", "Status"].map((h) => (
              <th key={h} className="border-b border-hairline px-3 py-2 font-medium text-ink">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map(([resource, region, detail, status], i) => (
            <tr key={i}>
              <td className="border-b border-hairline px-3 py-2 align-top font-mono text-ink">
                {resource}
              </td>
              <td className="border-b border-hairline px-3 py-2 align-top text-ink-secondary">
                {region}
              </td>
              <td className="border-b border-hairline px-3 py-2 align-top text-ink-secondary">
                {detail}
              </td>
              <td className="border-b border-hairline px-3 py-2 align-top">
                <ReportResourceStatus text={status} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Markdown({ content }: { content: string }) {
  return (
    <div className="max-w-none text-sm leading-relaxed text-ink">
      <ReactMarkdown
        remarkPlugins={[remarkGfm, reportMarkdownPlugin, sectionizeReportPlugin]}
        components={{
          h1: ({ children }) => (
            <h1 className="mb-3 mt-1 text-2xl font-light tracking-tight text-ink">{children}</h1>
          ),
          h2: ({ children }) => (
            <h2
              id={slugify(textContent(children))}
              className="mb-3 mt-8 scroll-mt-20 border-b border-hairline pb-2 text-lg font-medium text-ink"
            >
              {children}
            </h2>
          ),
          h3: ({ children }) => (
            <h3 className="mb-2 mt-6 text-base font-medium text-ink">{children}</h3>
          ),
          p: ({ children }) => <p className="mb-3 text-ink-secondary">{children}</p>,
          div: (props) => {
            const { className, children, ...rest } = props as {
              className?: string;
              children?: ReactNode;
              [key: string]: unknown;
            };
            if (className === "report-check-meta") {
              const checkId = rest["data-check-id"] as string;
              const severity = rest["data-severity"] as Severity;
              const category = rest["data-category"] as string;
              return (
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <SeverityChip severity={severity} />
                  <span className="font-mono text-[11px] text-ink-muted">{checkId}</span>
                  {category && <span className="text-xs text-ink-muted">· {category}</span>}
                </div>
              );
            }
            if (className === "report-pillar-summary") {
              const rows = JSON.parse((rest["data-rows"] as string) ?? "[]") as string[][];
              return <PillarSummaryTable rows={rows} />;
            }
            if (className === "report-resource-table") {
              const rows = JSON.parse((rest["data-rows"] as string) ?? "[]") as string[][];
              return <ResourceTable rows={rows} />;
            }
            return <div className={className}>{children}</div>;
          },
          ul: ({ children }) => (
            <ul className="mb-3 list-disc space-y-1 pl-5 text-ink-secondary">{children}</ul>
          ),
          ol: ({ children }) => (
            <ol className="mb-3 list-decimal space-y-1 pl-5 text-ink-secondary">{children}</ol>
          ),
          strong: ({ children }) => <strong className="font-medium text-ink">{children}</strong>,
          a: ({ href, children }) => (
            <a
              href={href}
              target="_blank"
              rel="noreferrer noopener"
              className="text-brand underline underline-offset-2"
            >
              {children}
            </a>
          ),
          hr: () => <hr className="my-8 border-hairline" />,
          // Tables scroll inside their own container. A resource table can carry
          // a long fully-qualified resource id, and the page body must never
          // scroll sideways because of one cell. This is the fallback path for
          // any table `reportMarkdownPlugin` doesn't recognize — the two it does
          // recognize are replaced wholesale (see the `div` branches above).
          table: ({ children }) => (
            <div className="mb-4 overflow-x-auto rounded-md border border-hairline">
              <table className="w-full border-collapse text-left text-xs">{children}</table>
            </div>
          ),
          thead: ({ children }) => <thead className="bg-subtle">{children}</thead>,
          th: ({ children }) => (
            <th className="border-b border-hairline px-3 py-2 font-medium text-ink">{children}</th>
          ),
          td: ({ children }) => (
            <td className="border-b border-hairline px-3 py-2 align-top text-ink-secondary">
              {children}
            </td>
          ),
          code: ({ className, children }) => {
            // react-markdown gives a fenced block a language- class and an
            // inline span none; that is the only reliable way to tell them
            // apart at this level.
            const isBlock = Boolean(className?.startsWith("language-"));
            if (isBlock) {
              return <code className="font-mono text-xs leading-relaxed">{children}</code>;
            }
            return (
              <code className="rounded bg-subtle px-1 py-0.5 font-mono text-[0.85em] text-ink">
                {children}
              </code>
            );
          },
          pre: ({ children }) => (
            <pre className="mb-4 overflow-x-auto rounded-md border border-hairline bg-subtle p-3">
              {children}
            </pre>
          ),
          blockquote: ({ children }) => (
            <blockquote className="mb-3 border-l-2 border-hairline pl-3 text-ink-muted">
              {children}
            </blockquote>
          ),
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}
