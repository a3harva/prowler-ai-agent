"""The one place a service-layer error decides what HTTP status it deserves.

Before this module every router hand-wrote the same mapping:

    except OrganizationNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc

Thirty-one blocks of it across seven routers, each one a chance to catch the
wrong class, forget an endpoint, or answer 404 where its neighbour answered
409. Two different modules had even defined a class called
``OrganizationNotFoundError``, so an `except` on the wrong import silently
never matched and the error escaped as a 500.

The status now lives on the exception, next to the rule that raises it, and
``api/main.py`` translates every ``ServiceError`` in one handler. A new error
type needs no router change at all.

The base is deliberately ``Exception``, not ``RuntimeError``: these are
expected outcomes of a request (a name already taken, a row that is gone),
not evidence that something is broken. Anything that really is broken keeps
raising whatever it raises today and still becomes a 500.

Auth is out of scope on purpose — `routers/auth.py` catches `GoogleOAuthError`,
`DomainNotAllowedError` and `TokenError` to do something other than this
mapping (one prefixes the message, one answers with a redirect rather than an
error at all). Those handlers earn their place and stay hand-written.
"""

from __future__ import annotations


class ServiceError(Exception):
    """Base for every deliberate service-layer failure.

    `status_code` is the HTTP status `api/main.py` answers with, and `str(exc)`
    becomes the response detail — which is why every subclass below builds a
    message a person could act on.
    """

    status_code = 500


class NotFoundError(ServiceError):
    """A named row does not exist, or is soft-deleted and so invisible here."""

    status_code = 404


class ConflictError(ServiceError):
    """The request collides with something already stored — a duplicate id, or
    a state transition that has already happened."""

    status_code = 409


class InvalidRequestError(ServiceError):
    """Well-formed, but asks for something the current state does not allow."""

    status_code = 400


class UnprocessableError(ServiceError):
    """Understood and permitted, but the data behind it cannot support it —
    a scan whose output is missing or unparseable, most often."""

    status_code = 422


class PermissionDeniedError(ServiceError):
    """The caller is signed in but holds no grant that covers this row."""

    status_code = 403


class UpstreamUnavailableError(ServiceError):
    """A third-party system this request depends on did not answer."""

    status_code = 502


class MarkdownValidationError(UnprocessableError):
    """The rendered report is structurally broken Markdown.

    Fatal by design. The first generated report contained 43 double-fenced code
    blocks whose contents escaped into the document as prose — valid text, badly
    wrong output. Storing that and letting someone notice later is worse than
    failing and regenerating.
    """


class PdfRenderError(UnprocessableError):
    """WeasyPrint could not turn the report payload into a PDF.

    Fatal, by the same all-or-nothing reasoning `MarkdownValidationError`
    already applies here: a report that has Markdown content but silently no
    PDF is a half-written customer-facing artifact, which this feature's own
    design principle treats as worse than a clear failure to retry.
    """


class ReportPdfNotAvailableError(NotFoundError):
    """The report has no PDF — most often a report generated before this
    feature shipped, since generation is all-or-nothing going forward."""

    def __init__(self, report_id: int):
        super().__init__(f"report {report_id} has no PDF available")
        self.report_id = report_id
