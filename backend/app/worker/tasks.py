from __future__ import annotations

import json
import logging
import os
from typing import Any

from app.config import get_settings
from app.db import get_session_factory
from app.integrations.prowler_runner import (
    PROWLER_SUCCESS_EXIT_CODES,
    ScanLaunchError,
    kill_and_remove_container,
    launch_scan,
    summarize_failure,
    wait_for_scan,
)
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.integrations.gemini import (
    PILLAR_RESPONSE_SCHEMA,
    SUMMARY_RESPONSE_SCHEMA,
    generate_json,
)
import contextlib

from app import observability
from app.models.project import Project as ProjectModel
from app.services.errors import MarkdownValidationError, PdfRenderError
from app.services.importer import import_scan_results
from app.services.rbac import ALL_DEPARTMENTS
from app.services import report_pdf, report_render, reports as reports_service
from app.services.scans import (
    ProjectMissingError,
    ScanNotFoundError,
    finalize_scan_failure,
    mark_importing,
    mark_running,
)
from app.worker.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="scans.run_scan", bind=True, max_retries=0)
def run_scan_task(self, scan_id: int) -> None:
    """Runs unattended — the submitting request has already returned by the
    time this executes, so nothing here can surface an error to a browser
    tab. Every exit path, including an exception raised before the scan
    container even starts, must leave the `scans` row in a terminal state;
    a `running` row this task fails to finalize is exactly the "wedged job"
    the timeout ceiling exists to prevent, except worse, because nothing
    would ever un-wedge it.
    """
    settings = get_settings()
    db = get_session_factory()()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise ScanNotFoundError(scan_id)
        project = db.get(Project, scan.project_id)
        if project is None:
            # Named explicitly rather than left to blow up on the attribute
            # access two lines down, so the row's error_message says what is
            # actually wrong instead of "AttributeError: NoneType".
            raise ProjectMissingError(scan.project_id)
        reports_path = os.path.join(settings["REPORTS_PATH"], str(scan_id))

        try:
            container_id = launch_scan(
                scan_id=scan_id,
                project_id=project.project_id,
                target_sa_email=project.target_sa_email,
                prowler_image=settings["PROWLER_IMAGE"],
                docker_host=settings["DOCKER_HOST"],
                reports_path=settings["REPORTS_PATH"],
                host_reports_path=settings["HOST_REPORTS_PATH"],
                gcloud_adc_path=settings["GCLOUD_ADC_PATH"],
            )
        except ScanLaunchError as exc:
            # Never got a container id, so there was nothing to be "running" —
            # go straight to a terminal state rather than leaving the row
            # `queued` forever.
            mark_running(db, scan_id=scan_id, container_id="", reports_path=reports_path)
            finalize_scan_failure(
                db, scan_id=scan_id, exit_code=None, timed_out=False,
                error_message=f"failed to launch scanner container: {exc}",
            )
            return

        mark_running(db, scan_id=scan_id, container_id=container_id, reports_path=reports_path)

        result = wait_for_scan(
            container_id=container_id,
            docker_host=settings["DOCKER_HOST"],
            reports_path=settings["REPORTS_PATH"],
            scan_id=scan_id,
            timeout_seconds=int(settings["SCAN_TIMEOUT_SECONDS"]),
        )

        if result.timed_out or result.exit_code not in PROWLER_SUCCESS_EXIT_CODES:
            error_message = summarize_failure(
                exit_code=result.exit_code, timed_out=result.timed_out, log_text=result.log_text
            )
            finalize_scan_failure(
                db,
                scan_id=scan_id,
                exit_code=result.exit_code,
                timed_out=result.timed_out,
                error_message=error_message,
            )
            return

        # Container ran fine — hand off to the importer, which owns every
        # status this scan can land on from here (succeeded, schema_mismatch,
        # import_failed).
        scan = mark_importing(db, scan_id=scan_id, exit_code=result.exit_code)
        if scan.status != ScanStatus.importing:
            # Cancelled out from under us between the container finishing
            # and this line — mark_importing already refused to overwrite
            # that, so there is nothing left to import.
            return
        import_scan_results(db, scan_id=scan_id)
    except Exception as exc:
        # The docstring above promises a terminal state on *every* exit path.
        # Without this, only ScanLaunchError kept that promise: an OSError
        # from makedirs (a full disk), a missing project row, or anything
        # raised inside wait_for_scan/import left the row `queued` or
        # `running` for ever, with no timeout sweep able to reach it —
        # max_retries=0 and no on_failure hook means Celery will not come
        # back either.
        _finalize_unexpected_failure(db, scan_id=scan_id, exc=exc)
        # Re-raised so Celery still records the traceback. The row is already
        # terminal by this point, so the raise costs nothing but keeps the
        # cause visible in the worker log.
        raise
    finally:
        db.close()


def _finalize_unexpected_failure(db, *, scan_id: int, exc: Exception) -> None:
    """Best-effort terminal transition for an error nothing else handled.

    Rolls back first: the failure may have left the session mid-flush, and
    `finalize_scan_failure` commits — without the rollback that commit would
    raise too, and the row this exists to rescue would stay non-terminal
    anyway. Swallows its own errors for the same reason: it runs while an
    exception is already in flight, and a second one here would mask the
    first."""
    try:
        db.rollback()
        finalize_scan_failure(
            db,
            scan_id=scan_id,
            exit_code=None,
            timed_out=False,
            error_message=f"scan task failed unexpectedly: {type(exc).__name__}: {exc}",
        )
    except Exception:
        pass


@celery_app.task(name="scans.cleanup_cancelled_scan", max_retries=0)
def cleanup_cancelled_scan(scan_id: int, container_id: str | None) -> None:
    """Best-effort teardown of the sibling container after an operator
    cancels a scan from the UI. Split from the cancel itself because the API
    process has no Docker socket access (see docker-compose.local.yml) —
    only the worker does. Killing the container unblocks `run_scan_task`'s
    `docker wait` if that task is still alive; `finalize_scan_failure`'s own
    cancelled-status check is what stops it from then overwriting the
    cancellation with "failed". A no-op, quietly, if the container already
    exited or never existed — cancelling an already-orphaned scan (the
    container finished hours ago with nothing left to reap it) is exactly
    the case this button exists for."""
    if not container_id:
        return
    settings = get_settings()
    kill_and_remove_container(container_id=container_id, docker_host=settings["DOCKER_HOST"])


def _report_trace(report, project, *, mode: str):
    """The root-observation arguments for one report run.

    **Every field is read defensively, and that is the point rather than
    laziness.** `app/observability` promises that tracing can never fail a
    report, and it keeps that promise for every SDK call — but the *arguments*
    are assembled here, out of an ORM row, and an `AttributeError` raised while
    building them would fail the report before the SDK is ever reached. A
    guarantee with a hole in front of it is not one.

    That is not hypothetical: it was caught by three worker tests whose report
    double omits `graph_thread_id`, which is exactly the shape of a real future
    caller — a partially-loaded row, a column added behind a migration that has
    not run yet — that must not take a customer-facing document down with it.
    """
    reference = getattr(report, "task_reference_id", None)
    thread_id = getattr(report, "graph_thread_id", None) or reference
    project_label = getattr(project, "project_id", None) or getattr(report, "project_id", "?")
    return {
        "name": f"{mode} report",
        "trace_name": f"{mode} report \u00b7 {project_label}",
        # Groups every run of one report together, a resumed run included —
        # the same identity the graph checkpoints on.
        "session_id": str(thread_id) if thread_id else None,
        "user_id": str(getattr(report, "requested_by_user_id", "") or "") or None,
        "tags": ["report", mode],
        "metadata": {
            "report_id": getattr(report, "id", None),
            "scan_id": getattr(report, "scan_id", None),
            "include_muted": getattr(report, "include_muted", None),
            "task_reference_id": reference,
        },
    }


@celery_app.task(name="reports.generate_report", bind=True, max_retries=0)
def generate_report_task(self, report_id: int) -> None:
    """Writes one AI assessment report.

    Sequential, not parallel: three pillar calls plus one summary, ~12k input
    tokens in total against the reference scan. Threads would be the first in
    this codebase — which is deliberately one colour, sync throughout — for a
    job that already finishes in minutes while nobody watches.

    All-or-nothing, like the import pipeline. Any failure marks the row
    `failed` with a reason and stores no content; `max_retries=0` because the
    user retries by requesting a new report, which keeps the failed row and its
    error message in the history rather than overwriting them.
    """
    settings = get_settings()
    db = get_session_factory()()
    # An ExitStack rather than a `with` around the whole body: the trace wants
    # the project and the thread id in its attributes, and those are only known
    # after the two loads below. Entering it here keeps the existing try/except
    # contract — and its all-or-nothing guarantee — exactly as it was.
    stack = contextlib.ExitStack()
    try:
        report = reports_service.get_report(
            db, report_id=report_id, visible_department_ids=ALL_DEPARTMENTS
        )
        project = db.get(ProjectModel, report.project_id)
        stack.enter_context(
            observability.trace_run(**_report_trace(report, project, mode="standard"))
        )
        reports_service.mark_generating(db, report_id=report_id)

        # Read off the row, not re-decided here: the report records the mode it
        # was requested in, so a regeneration cannot silently differ from what
        # the user asked for.
        payload = reports_service.build_report_payload(
            db, project_id=report.project_id, include_muted=report.include_muted
        )

        narratives: dict[str, str] = {}
        explanations: dict[str, str] = {}
        for pillar, groups in payload["pillars"].items():
            result = generate_json(
                settings=settings,
                system_instruction=report_render.PILLAR_SYSTEM_PROMPT.format(pillar=pillar),
                user_content=report_render.pillar_user_content(pillar, groups),
                response_schema=PILLAR_RESPONSE_SCHEMA,
            )
            narratives[pillar] = result.get("pillar_narrative", "")
            for entry in result.get("findings", []):
                explanations[entry["check_id"]] = entry.get("explanation", "")

        # Fed the narratives just written, not the raw findings — cheap, and it
        # keeps the summary consistent with the body a reader is about to see.
        summary = generate_json(
            settings=settings,
            system_instruction=report_render.SUMMARY_SYSTEM_PROMPT,
            user_content=report_render.summary_user_content(
                narratives, payload["severity_counts"]
            ),
            response_schema=SUMMARY_RESPONSE_SCHEMA,
        )

        content = report_render.render_markdown(
            project_id=project.project_id,
            scan_id=report.scan_id,
            payload=payload,
            narratives=narratives,
            explanations=explanations,
            executive_summary=summary.get("executive_summary", ""),
        )
        # Step 3 — validate the rendered Markdown before it is stored.
        #
        # Deterministic first, and fatal. This is what would have caught the
        # double-fenced code blocks that shipped in the first generated report,
        # where the outer fence closed on the inner one and Terraform spilled
        # into the document as body text. A structurally broken customer-facing
        # artifact must not reach the database.
        problems = report_render.validate_markdown(content)
        if problems:
            raise MarkdownValidationError(
                f"{len(problems)} formatting problem(s): " + "; ".join(problems[:5])
            )

        # Step 3.5 — the PDF, from the exact same in-memory payload/
        # narratives/executive_summary used above, so the two artifacts can
        # never drift from each other. Fatal on failure, same all-or-nothing
        # reasoning as the Markdown validator just above: a report with
        # Markdown but no PDF is a half-written customer-facing artifact.
        try:
            pdf_content = report_pdf.render_pdf_bytes(
                project_id=project.project_id,
                scan_id=report.scan_id,
                payload=payload,
                narratives=narratives,
                explanations=explanations,
                executive_summary=summary.get("executive_summary", ""),
            )
        except Exception as exc:
            raise PdfRenderError(f"could not render report PDF: {exc}") from exc

        # Then the model review — advisory only, and deliberately so. It reads
        # the finished document and reports formatting issues; it is never asked
        # to return a corrected version, because that would hand it the
        # remediation commands to paraphrase, which is the single thing this
        # feature's design exists to prevent. Its opinion is recorded, not
        # obeyed, and a failure here does not fail the report.
        format_warnings = None
        try:
            review = generate_json(
                settings=settings,
                system_instruction=report_render.MARKDOWN_REVIEW_PROMPT,
                user_content=content,
                response_schema=report_render.MARKDOWN_REVIEW_SCHEMA,
            )
            issues = review.get("issues") or []
            if issues:
                format_warnings = json.dumps(issues)
        except Exception:
            # A review that cannot run is not a reason to discard a valid
            # report the deterministic validator has already passed.
            pass

        reports_service.finalize_report(
            db,
            report_id=report_id,
            content=content,
            pdf_content=pdf_content,
            skipped=payload["skipped_finding_count"],
            unknown_categories=payload["unknown_category_count"],
            format_warnings=format_warnings,
        )
    except Exception as exc:
        # Same guarantee run_scan_task makes: no path leaves the row
        # non-terminal. Rollback first because finalize commits.
        try:
            db.rollback()
            reports_service.fail_report(
                db,
                report_id=report_id,
                error_message=f"{type(exc).__name__}: {exc}",
            )
        except Exception:
            pass
        raise
    finally:
        db.close()
        # Closes the root span before the buffer is pushed, so the trace is
        # complete rather than missing the observation that contains it.
        stack.close()
        # Standard mode is traced too — comparing the two pipelines on the same
        # project is most of why the trace exists.
        observability.flush()


@celery_app.task(name="reports.generate_deep_report", bind=True, max_retries=0)
def generate_deep_report_task(self, report_id: int) -> None:
    """Writes one AI assessment report via the LangGraph agent.

    Same contract as `generate_report_task` above, and deliberately so: all or
    nothing, `max_retries=0`, and no exit path that leaves the row
    non-terminal. What differs is what happens in between — instead of one
    Gemini call per pillar, the graph investigates with tools, correlates
    across pillars, plans the remediation sequence, and puts the result through
    six deterministic gates and a critique before anything renders.

    **Re-enqueueing this task for the same report_id resumes it.** The graph is
    checkpointed on `report.graph_thread_id`, so a run that died to a Vertex
    outage on the fourth of five pillars restarts on the fourth, not the first.
    That is the whole reason for the LangGraph dependency, and it is why the
    row is left `failed` with a reason rather than rolled back to `queued`:
    the failure should be visible and the resume should be a decision.

    The gates are what make the counts trustworthy, and they are the reason
    this can be agentic at all. `app/agents/report_ledger.py` has the detail.
    """
    settings = get_settings()
    db = get_session_factory()()
    # See generate_report_task for why this is an ExitStack and not a `with`
    # around the whole body.
    stack = contextlib.ExitStack()
    try:
        report = reports_service.get_report(
            db, report_id=report_id, visible_department_ids=ALL_DEPARTMENTS
        )
        project = db.get(ProjectModel, report.project_id)
        thread_id = report.graph_thread_id or report.task_reference_id
        run_span = stack.enter_context(
            observability.trace_run(**_report_trace(report, project, mode="deep"))
        )
        reports_service.mark_generating(db, report_id=report_id)

        initial = {
            "report_id": report.id,
            "project_pk": report.project_id,
            "project_id": project.project_id,
            "scan_id": report.scan_id,
            "include_muted": report.include_muted,
            "instructions": report.instructions,
            # Carried in state as well as in the run config: `configurable` is
            # not reachable from a node without threading a `RunnableConfig`
            # through all thirteen of them, and the nodes are deliberately
            # plain functions of state. This is the key a node looks the run's
            # live container up by.
            "graph_thread_id": thread_id,
        }

        # Imported here rather than at module scope so the worker starts even
        # if the agent package cannot import — a broken deep path must not
        # take scans and standard reports down with it.
        from app.agents.checkpointer import checkpointer_for
        from app.agents.cloud_context import open_cloud_context
        from app.agents.report_graph import build_graph, recursion_limit_for

        # **Opened around the whole graph run, not inside `recon`.** One
        # container serves the run: `recon` fills the snapshot and then
        # `investigate_pillar` spends the rest of the budget on follow-ups, and
        # a container that closed when `recon` returned would leave the
        # investigator with a tool that never works. Yields None rather than
        # raising when live context cannot be had — a report must still be
        # produced, with a banner naming the reason.
        stack.enter_context(
            open_cloud_context(
                settings=settings,
                thread_id=thread_id,
                project_id=project.project_id,
                target_sa_email=project.target_sa_email,
            )
        )

        with checkpointer_for(settings.database_url) as checkpointer:
            # Compiled inside the `with` because the checkpointer belongs to
            # `compile()`, not to run config — see `build_graph`.
            graph = build_graph(checkpointer)
            config = {
                "configurable": {"thread_id": thread_id},
                # Sized for the maximum pillar count rather than this
                # project's, so the ceiling does not move between reports.
                "recursion_limit": recursion_limit_for(6),
            }

            # **Resuming takes `None`, not the input.** Re-invoking with the
            # initial state restarts the graph from START and re-runs every
            # node that already succeeded — verified directly, not assumed:
            # a three-node graph interrupted after the first node and
            # re-invoked with its input produced ['a', 'a', 'b', 'c'], while
            # the same graph resumed with None produced ['a', 'b', 'c'].
            #
            # `snapshot.next` is the tell. It is non-empty only when a run
            # stopped with work still pending, which is exactly the
            # interrupted case; a fresh thread and a completed one both report
            # nothing pending.
            snapshot = graph.get_state(config)
            resuming = bool(snapshot.next)
            if resuming:
                logger.info(
                    "deep report %s resuming thread %s at %s",
                    report_id,
                    thread_id,
                    snapshot.next,
                )

            final = graph.invoke(
                None if resuming else initial,
                config=config,
                # Checkpoint written before the next node starts, not batched
                # to the end of the run. Costs a write per node and buys the
                # resume guarantee this whole path exists for.
                durability="sync",
            )

        verification = final.get("verification") or {}
        _record_run_scores(run_span, final)

        # The graph ends early when the deterministic gates still fail after
        # the repair budget. Rendering anyway would produce exactly the
        # document those gates exist to prevent.
        if not verification.get("passed"):
            failures = verification.get("failures") or []
            raise MarkdownValidationError(
                f"{len(failures)} ledger gate failure(s) survived repair: "
                + "; ".join(f"{f['gate']}: {f['detail']}" for f in failures[:3])
            )

        problems = final.get("document_problems") or []
        if problems:
            raise MarkdownValidationError(
                f"{len(problems)} problem(s) in the rendered document: " + "; ".join(problems[:5])
            )

        content = final.get("content")
        if not content:
            raise MarkdownValidationError("the graph finished without producing a document")

        # The PDF is built from the same in-memory objects as the Markdown, so
        # the two artifacts cannot drift — the invariant the standard path
        # already holds.
        payload = final["ledger"]
        narratives = {
            p: e.get("narrative", "") for p, e in (final.get("pillar_analysis") or {}).items()
        }
        explanations = {
            c: e.get("explanation", "") for c, e in (final.get("check_analysis") or {}).items()
        }
        try:
            pdf_content = report_pdf.render_pdf_bytes(
                project_id=project.project_id,
                scan_id=report.scan_id,
                payload=payload,
                narratives=narratives,
                explanations=explanations,
                executive_summary=final.get("executive_summary", ""),
                analysis=deep_report_analysis(final),
                live_context=_live_context_of(final),
            )
        except Exception as exc:
            raise PdfRenderError(f"could not render report PDF: {exc}") from exc

        reports_service.finalize_report(
            db,
            report_id=report_id,
            content=content,
            pdf_content=pdf_content,
            skipped=payload["skipped_finding_count"],
            unknown_categories=payload["unknown_category_count"],
            analysis={
                "themes": final.get("themes") or [],
                "remediation_plan": final.get("remediation_plan") or [],
                "pillar_analysis": final.get("pillar_analysis") or {},
                "check_analysis": final.get("check_analysis") or {},
                # The live-state verdicts, kept beside the prose they annotate.
                # A verdict is the sentence a customer is most likely to act on
                # and the one most likely to be disputed months later, so it is
                # stored with the citation that backs it rather than only
                # surviving inside the rendered Markdown.
                "reconciliation": final.get("reconciliation") or {},
                "executive_summary": final.get("executive_summary", ""),
                "strategy": final.get("strategy", ""),
                "notes": final.get("notes") or [],
            },
            verification=verification,
            critique=final.get("critique"),
            # Assembled by the same function the renderer uses, so the stored
            # row and the rendered banner cannot disagree. The command log it
            # carries — every attempt, successes and failures alike — is what
            # the evidence appendix renders and checks `evidence_id` citations
            # against, stored on the row for the reason
            # `analysis` is: a disputed sentence has to be traceable to the
            # command that produced it, months later.
            live_context=_live_context_of(final),
        )
    except Exception as exc:
        # Same guarantee every other long task makes. Rollback first because
        # finalize commits.
        try:
            db.rollback()
            reports_service.fail_report(
                db,
                report_id=report_id,
                error_message=f"{type(exc).__name__}: {exc}",
            )
        except Exception:
            pass
        raise
    finally:
        db.close()
        stack.close()
        # The trace is buffered off-thread and this is a prefork child that may
        # be recycled the moment the task returns. Without this the traces most
        # worth having — the long, expensive, late ones — are exactly the ones
        # lost. Never raises; see app/observability.
        observability.flush()


def _record_run_scores(span: Any, final: dict) -> None:
    """Run-level scores, so a run's quality is legible without opening it.

    Called **before** the gate check raises, deliberately: a run whose gates
    survived repair is exactly the one whose numbers someone will later want to
    compare against a run that passed. Scoring only the successes would make
    the gate pass rate a metric that can never be below 1.

    Every field is read defensively for the same reason `_report_trace` is:
    tracing may never fail a report, and an `AttributeError` assembling a score
    would do it from outside the SDK's own guard.
    """
    verification = final.get("verification") or {}
    gates_run = [str(g) for g in (verification.get("gates_run") or [])]
    if gates_run:
        failed = {str(f.get("gate")) for f in (verification.get("failures") or []) if f.get("gate")}
        # `document_problems` is a list of strings, not gate dicts, and it mixes
        # C4/C5 (which prefix themselves) with `validate_markdown`'s output
        # (which does not). Anything unattributable is charged to `markdown`,
        # the gate those problems are folded into by `verify_rendered`.
        for problem in verification.get("document_problems") or []:
            head = str(problem).split(":", 1)[0].strip()
            failed.add(head if head in gates_run else "markdown")
        passed = [g for g in gates_run if g not in failed]
        comment = f"{len(passed)}/{len(gates_run)} gates passed"
        if failed:
            comment += f"; failed: {', '.join(sorted(failed))}"
        observability.score(span, "gate_pass_rate", len(passed) / len(gates_run), comment=comment)

    observability.score(span, "revisions", float(final.get("revision_count") or 0))

    critique = final.get("critique") or {}
    verdict = critique.get("verdict")
    if verdict:
        observability.score(
            span,
            "critique_verdict",
            str(verdict),
            comment=str(critique.get("assessment") or "")[:500] or None,
        )


def _live_context_of(final: dict) -> dict:
    """The live-context bundle, out of a finished run.

    Duplicated from `agents/report_nodes.live_context_of` in shape but not in
    source, for exactly the reason `deep_report_analysis` below is: that one
    reads graph state mid-run, this one reads the returned final state, and the
    worker does not import a node module to reshape a dict it already holds.

    `unavailable` is the default rather than an error. A resumed run whose
    checkpoint predates this feature genuinely did not check anything, and the
    banner saying so is the correct output.
    """
    return {
        "status": final.get("live_context_status") or "unavailable",
        "reason": final.get("live_context_reason"),
        "snapshot": final.get("live_snapshot") or {},
        # Every attempt, successes and failures alike — what the evidence
        # appendix renders and checks `evidence_id` citations against. Stored
        # on the row for the reason `analysis` is: a
        # disputed sentence has to be traceable to the command that produced
        # it, months later.
        "command_log": final.get("command_log") or [],
        # Defaults to `not_applicable`, not `unavailable`: a run that
        # predates the org probe did not ask and was not refused, and recording
        # a denial that never happened is the same dishonesty the banner exists
        # to prevent.
        #
        # **The duplication above is why this key was missing for one live
        # run.** `report_nodes.live_context_of` grew the key and this function
        # did not, so the renderer knew about org context and the stored row
        # did not. Any field added to one belongs in the other in the same edit.
        "organization": {
            "status": final.get("org_context_status") or "not_applicable",
            "reason": final.get("org_context_reason"),
        },
    }


def deep_report_analysis(final: dict) -> dict:
    """The narrow bundle both renderers consume, out of a finished run.

    Duplicated from `agents/report_nodes.build_analysis` in shape but not in
    source: that one reads graph state mid-run, this one reads the returned
    final state. Kept here so the worker does not import a node module to
    reshape a dict it already holds.
    """
    return {
        "themes": final.get("themes") or [],
        "remediation_plan": final.get("remediation_plan") or [],
        "pillar_analysis": {
            p: e.get("analysis", "") for p, e in (final.get("pillar_analysis") or {}).items()
        },
        "check_context": {
            c: e.get("why_here", "") for c, e in (final.get("check_analysis") or {}).items()
        },
        "reconciliation": final.get("reconciliation") or {},
    }
