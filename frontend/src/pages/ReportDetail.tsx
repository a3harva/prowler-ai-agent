import { useParams, Link } from "react-router-dom";
import { ArrowLeft, Download, LoaderCircle, Pencil, Printer, ShieldCheck, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { PageHeader, Panel } from "@/components/app-shell";
import { Markdown } from "@/components/markdown";
import { ReportState, type ReportStatus } from "@/components/report-state";
import { StatTile } from "@/components/stat-tile";
import { DonutChart, type DonutSlice } from "@/components/donut-chart";
import { ErrorState } from "@/components/states";
import { useStatus } from "@/components/status-region";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { apiClient, errorMessage } from "@/api/client";
import type { ReportCritique, ReportVerification } from "@/api/types";
import { useReport, useUpdateReportContent } from "@/hooks/queries";
import { formatTimestamp } from "@/lib/format";
import { extractPillarHeadings, parseSeverityTotals } from "@/lib/report-markdown-plugin";
import { slugify } from "@/lib/slugify";
import { cn } from "@/lib/utils";

/**
 * The report itself, rendered rather than shown as source — a document meant
 * for a customer should not be read as raw Markdown. The download still hands
 * over the .md file, which is the artifact anyone sends onward.
 *
 * react-markdown + remark-gfm are a deliberate addition to a dependency list
 * this repo otherwise keeps minimal: a report is mostly GitHub-flavoured
 * tables, and hand-rolling those would be worse than taking the two packages.
 */
export default function ReportDetail() {
  const { id } = useParams();
  const report = useReport(id ? Number(id) : undefined);
  const status = useStatus();
  const updateContent = useUpdateReportContent(id ? Number(id) : -1);
  const [downloading, setDownloading] = useState(false);
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [printPreview, setPrintPreview] = useState(false);

  // The sidebar and top bar live outside this page's own DOM subtree (they're
  // rendered by AppShell, a route ancestor), so a class scoped to this page's
  // wrapper div can't reach them with a descendant selector. Toggling the
  // class on <html> instead lets `.print-preview [data-print-hide]` in
  // index.css hide them too — the whole point of a *preview*, matching what
  // `@media print` already does unscoped for a real print job.
  useEffect(() => {
    document.documentElement.classList.toggle("print-preview", printPreview);
    return () => document.documentElement.classList.remove("print-preview");
  }, [printPreview]);

  const content = report.data?.content;

  const startEditing = () => {
    setDraft(content ?? "");
    setEditing(true);
  };

  const handleSave = async () => {
    try {
      await updateContent.mutateAsync(draft);
      status.succeed("Report updated");
      setEditing(false);
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't save that report."));
    }
  };
  const severityTotals = useMemo(() => (content ? parseSeverityTotals(content) : null), [content]);
  const pillarHeadings = useMemo(() => (content ? extractPillarHeadings(content) : []), [content]);
  const severitySlices: DonutSlice[] = severityTotals
    ? [
        { key: "critical", label: "Critical", value: severityTotals.critical, color: "var(--color-sev-critical)" },
        { key: "high", label: "High", value: severityTotals.high, color: "var(--color-sev-high)" },
        { key: "medium", label: "Medium", value: severityTotals.medium, color: "var(--color-sev-medium)" },
        { key: "low", label: "Low", value: severityTotals.low, color: "var(--color-sev-low)" },
      ]
    : [];

  const downloadBlob = async (path: string, filename: string, setBusy: (v: boolean) => void) => {
    if (!report.data) return;
    setBusy(true);
    try {
      const response = await apiClient.get(path, { responseType: "blob" });
      const url = window.URL.createObjectURL(response.data as Blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      status.succeed(`Downloaded ${filename}`);
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't download that report."));
    } finally {
      setBusy(false);
    }
  };

  const handleDownload = () =>
    downloadBlob(
      `/reports/${report.data?.id}/download`,
      `${report.data?.task_reference_id}.md`,
      setDownloading,
    );

  const handleDownloadPdf = () =>
    downloadBlob(
      `/reports/${report.data?.id}/download.pdf`,
      `${report.data?.task_reference_id}.pdf`,
      setDownloadingPdf,
    );

  if (report.error) {
    return (
      <ErrorState
        message={errorMessage(report.error, "Couldn't load that report.")}
        onRetry={() => report.refetch()}
      />
    );
  }

  const canEditOrPreview = report.data?.status === "completed" && !editing;

  return (
    <div className="space-y-6">
      {printPreview && (
        <div
          data-print-hide
          className="sticky top-0 z-30 flex items-center justify-between rounded-lg border border-hairline bg-panel px-4 py-2.5 shadow-md"
        >
          <span className="text-sm font-medium text-ink">Print preview</span>
          <div className="flex items-center gap-2">
            <Button size="sm" onClick={() => window.print()}>
              <Printer className="size-3.5" aria-hidden />
              Print
            </Button>
            <Button variant="outline" size="sm" onClick={() => setPrintPreview(false)}>
              <X className="size-3.5" aria-hidden />
              Exit preview
            </Button>
          </div>
        </div>
      )}

      <PageHeader
        title={report.data?.task_reference_id ?? "report"}
        description={
          report.data
            ? `Requested ${formatTimestamp(report.data.created_at)} · scan #${report.data.scan_id}`
            : "Loading…"
        }
        actions={
          <div data-print-hide className="flex items-center gap-2">
            <Button variant="outline" size="sm" asChild>
              <Link to="/reports">
                <ArrowLeft className="size-3.5" aria-hidden />
                All reports
              </Link>
            </Button>
            {canEditOrPreview && (
              <Button variant="outline" size="sm" onClick={startEditing}>
                <Pencil className="size-3.5" aria-hidden />
                Edit
              </Button>
            )}
            {canEditOrPreview && (
              <Button variant="outline" size="sm" onClick={() => setPrintPreview(true)}>
                <Printer className="size-3.5" aria-hidden />
                Print preview
              </Button>
            )}
            {report.data?.status === "completed" && (
              <Button variant="outline" size="sm" onClick={handleDownload} disabled={downloading}>
                {downloading ? (
                  <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
                ) : (
                  <Download className="size-3.5" aria-hidden />
                )}
                Download
              </Button>
            )}
            {report.data?.status === "completed" && report.data?.has_pdf && (
              <Button
                variant="outline"
                size="sm"
                onClick={handleDownloadPdf}
                disabled={downloadingPdf}
              >
                {downloadingPdf ? (
                  <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
                ) : (
                  <Download className="size-3.5" aria-hidden />
                )}
                Download PDF
              </Button>
            )}
          </div>
        }
      />

      {report.data && (
        <Panel className="space-y-3">
          <div className="flex flex-wrap items-center gap-3">
            <ReportState status={report.data.status as ReportStatus} />
            <span className="text-sm text-ink-secondary">
              {report.data.include_muted
                ? "Includes muted findings"
                : "Muted findings excluded"}
            </span>
            {report.data.skipped_finding_count > 0 && (
              <span className="text-sm text-ink-secondary">
                {report.data.skipped_finding_count} finding(s) omitted — recorded before
                remediation detail was captured
              </span>
            )}
            {report.data.unknown_category_count > 0 && (
              <span className="text-sm text-ink-secondary">
                {report.data.unknown_category_count} finding(s) had an unmapped category and were
                filed under Security
              </span>
            )}
            {report.data.content_edited_at && (
              <span className="text-sm text-ink-muted">
                Edited {formatTimestamp(report.data.content_edited_at)}
              </span>
            )}
          </div>
          {report.data.error_message && (
            <p className="text-sm text-status-fail">{report.data.error_message}</p>
          )}
        </Panel>
      )}

      {severityTotals && severityTotals.total > 0 && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
            <StatTile label="total findings" value={severityTotals.total} />
            <StatTile label="critical" value={severityTotals.critical} tone="warning" />
            <StatTile label="high" value={severityTotals.high} />
            <StatTile label="medium" value={severityTotals.medium} />
            <StatTile label="low" value={severityTotals.low} />
          </div>
          <Panel>
            <p className="card-title mb-4">by severity</p>
            <DonutChart slices={severitySlices} centerValue={severityTotals.total} centerLabel="findings" />
          </Panel>
        </>
      )}

      {report.data?.mode === "deep" && (
        <VerificationPanel
          verification={report.data.verification}
          critique={report.data.critique}
          instructions={report.data.instructions}
        />
      )}

      {pillarHeadings.length > 0 && !editing && (
        <div
          data-print-hide
          className="sticky top-0 z-10 flex flex-wrap gap-x-4 gap-y-1 rounded-lg border border-hairline bg-panel/95 px-4 py-2.5 text-sm backdrop-blur"
        >
          {pillarHeadings.map((heading) => (
            <a
              key={heading}
              href={`#${slugify(heading)}`}
              className="text-brand transition-colors hover:text-brand-hover"
            >
              {heading}
            </a>
          ))}
        </div>
      )}

      {editing ? (
        <Panel className="space-y-3">
          <Textarea
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            className="min-h-[60vh] font-mono text-xs"
            autoFocus
          />
          <div className="flex justify-end gap-2">
            <Button variant="outline" size="sm" onClick={() => setEditing(false)}>
              Cancel
            </Button>
            <Button size="sm" onClick={handleSave} disabled={updateContent.isPending}>
              {updateContent.isPending && <LoaderCircle className="size-3.5 animate-spin" aria-hidden />}
              Save
            </Button>
          </div>
        </Panel>
      ) : (
        content && (
          <Panel className="report-print-surface">
            <Markdown content={content} />
          </Panel>
        )
      )}
    </div>
  );
}


/** What was checked on a deep report, and what the reviewing pass thought.
 *
 *  Worth a panel rather than a footnote because it answers the question this
 *  whole pipeline exists to answer: an agent wrote the analysis, so how do you
 *  know it didn't lose a finding? The gates are the answer, and a reader who
 *  cannot see that they ran has to take it on trust.
 *
 *  The critique is presented as an opinion, not a warning — it is advisory by
 *  design, and by the time a document renders the deterministic gates have
 *  already passed. Styling it like a failure would misrepresent both. */
function VerificationPanel({
  verification,
  critique,
  instructions,
}: {
  verification: ReportVerification | null;
  critique: ReportCritique | null;
  instructions: string | null;
}) {
  if (!verification && !critique && !instructions) return null;

  const gates = verification?.gates_run ?? [];
  const checksPassed = verification?.passed && verification?.document_passed !== false;

  return (
    <Panel className="space-y-3">
      <p className="card-title">how this report was checked</p>

      {gates.length > 0 && (
        <div className="flex items-start gap-2 text-sm">
          <ShieldCheck
            className={cn(
              "mt-0.5 size-4 shrink-0",
              checksPassed ? "text-status-pass" : "text-status-fail",
            )}
            aria-hidden
          />
          <p className="text-ink-secondary">
            {checksPassed
              ? "Every finding in the database has a section in this document, every check referenced exists, the remediation plan accounts for each one exactly once, and no command was written by the model."
              : "Some checks did not pass — see the gate detail below."}{" "}
            <span className="text-ink-muted">
              Gates run: <span className="font-mono text-xs">{gates.join(", ")}</span>
            </span>
          </p>
        </div>
      )}

      {(verification?.failures ?? []).length > 0 && (
        <ul className="space-y-1 text-sm text-status-fail">
          {verification!.failures!.map((failure, i) => (
            <li key={i}>
              <span className="font-mono text-xs">{failure.gate}</span> — {failure.detail}
            </li>
          ))}
        </ul>
      )}

      {critique && (
        <div className="space-y-1 border-t border-hairline pt-3 text-sm">
          <p className="text-ink-secondary">
            <span className="text-ink">Review pass:</span> {critique.assessment}
          </p>
          {critique.issues.length > 0 && (
            <ul className="space-y-1 text-ink-muted">
              {critique.issues.map((issue, i) => (
                <li key={i}>
                  {issue.problem}
                  {issue.target && (
                    <span className="ml-1 font-mono text-xs">({issue.target})</span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {instructions && (
        <div className="border-t border-hairline pt-3 text-sm">
          <p className="text-ink-muted">Requested focus</p>
          <p className="mt-1 whitespace-pre-wrap text-ink-secondary">{instructions}</p>
        </div>
      )}
    </Panel>
  );
}
