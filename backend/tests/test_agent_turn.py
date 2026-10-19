"""The tool-calling loop, with the model faked out.

These exist for the request *shape* the loop builds, which no amount of
tool-level testing reaches: the tools were all correct when a real
conversation failed with

    400 INVALID_ARGUMENT — Please ensure that the number of function response
    parts is equal to the number of function call parts of the function call
    turn.

because the loop answered a two-call turn with two separate contents instead
of one content with two parts.
"""

import pytest

from app.integrations import gemini_agent
from app.models.agent import AgentMessage, MessageRole
from app.services import agent as agent_service
from tests.test_agent_tools import (
    _Current,
    _make_finding,
    _make_project,
    _make_scan,
    _make_user,
)


class _FakeCall:
    def __init__(self, name, args=None, call_id=None):
        self.name = name
        self.args = args or {}
        self.id = call_id


class _FakeResponse:
    """Stands in for the SDK's response object.

    `content` is deliberately a real `types.Content`, because the loop appends
    it to history verbatim and a plain stub would hide any shape problem there.
    """

    def __init__(self, *, calls=(), text=""):
        from google.genai import types

        self._calls = list(calls)
        self.text = text
        parts = [types.Part.from_text(text=text or " ")]
        self.candidates = [types.Candidate(content=types.Content(role="model", parts=parts))]
        self.function_calls = self._calls
        self.usage_metadata = None


def _seed(db):
    project, dept = _make_project(db, "a")
    user = _make_user(db, "editor@example.test", dept.id)
    scan = _make_scan(db, project, user)
    _make_finding(db, project, scan, check_id="c1", resource="r1")
    db.commit()
    return project, dept, user


def _install_fake_model(monkeypatch, responses):
    """Feeds `responses` to the loop in order and captures what it sent."""
    captured = {"contents": None}
    calls = iter(responses)

    monkeypatch.setattr(gemini_agent, "build_client", lambda settings: object())
    monkeypatch.setattr(
        gemini_agent,
        "build_config",
        lambda **kwargs: object(),
    )

    def fake_generate(*, client, settings, contents, config):
        # Snapshot per call — the last one is what the assertions inspect.
        captured["contents"] = list(contents)
        return next(calls)

    monkeypatch.setattr(gemini_agent, "generate", fake_generate)
    return captured


def test_parallel_calls_are_answered_with_one_content_of_many_parts(
    db_session, monkeypatch
):
    """The regression guard for the 400.

    Two function calls in one model turn must be answered by exactly one
    content carrying two functionResponse parts.
    """
    project, dept, user = _seed(db_session)
    session = agent_service.create_session(
        db_session, project_pk=project.id, current=_Current(user)
    )

    captured = _install_fake_model(
        monkeypatch,
        [
            _FakeResponse(
                calls=[
                    _FakeCall("get_findings_summary", {}, "call-1"),
                    _FakeCall("list_services", {}, "call-2"),
                ]
            ),
            _FakeResponse(text="Here is the summary."),
        ],
    )

    result = agent_service.run_turn(
        db_session,
        session_id=session.id,
        message="summarise this project",
        current=_Current(user),
        settings={"GEMINI_AGENT_MODEL": "m", "GEMINI_AGENT_MAX_OUTPUT_TOKENS": "1024"},
    )
    assert result["answer"] == "Here is the summary."
    assert len(result["tool_calls"]) == 2

    # The second request carries: user turn, model turn, tool responses.
    contents = captured["contents"]
    tool_turns = [
        c
        for c in contents
        if any(getattr(p, "function_response", None) is not None for p in (c.parts or []))
    ]
    assert len(tool_turns) == 1, "two calls must be answered by ONE content"
    responses = [p for p in tool_turns[0].parts if p.function_response is not None]
    assert len(responses) == 2, "that one content must carry BOTH responses"
    assert {p.function_response.name for p in responses} == {
        "get_findings_summary",
        "list_services",
    }


def test_replay_rebuilds_one_content_per_round_not_per_call(db_session, monkeypatch):
    """The same bug, one turn later.

    Storing a replay row per call rather than per round reproduces the 400 on
    the *next* message, when the transcript is rebuilt — which is worse than
    the original, because the conversation then fails permanently rather than
    once.
    """
    project, dept, user = _seed(db_session)
    session = agent_service.create_session(
        db_session, project_pk=project.id, current=_Current(user)
    )

    _install_fake_model(
        monkeypatch,
        [
            _FakeResponse(
                calls=[
                    _FakeCall("get_findings_summary", {}, "call-1"),
                    _FakeCall("list_services", {}, "call-2"),
                ]
            ),
            _FakeResponse(text="Done."),
        ],
    )
    agent_service.run_turn(
        db_session,
        session_id=session.id,
        message="summarise",
        current=_Current(user),
        settings={"GEMINI_AGENT_MODEL": "m", "GEMINI_AGENT_MAX_OUTPUT_TOKENS": "1024"},
    )

    replayable = (
        db_session.query(AgentMessage)
        .filter(AgentMessage.session_id == session.id, AgentMessage.parts.isnot(None))
        .order_by(AgentMessage.id)
        .all()
    )
    tool_rows = [
        row
        for row in replayable
        if any("function_response" in (part or {}) for part in (row.parts or []))
    ]
    assert len(tool_rows) == 1, "one replay row per round, not per call"
    assert len(tool_rows[0].parts) == 2

    # And the rebuilt history keeps that shape.
    rebuilt = agent_service._replay_history(db_session, session_id=session.id)
    tool_turns = [
        c
        for c in rebuilt
        if any(getattr(p, "function_response", None) is not None for p in (c.parts or []))
    ]
    assert len(tool_turns) == 1
    assert len(tool_turns[0].parts) == 2


def test_display_rows_stay_one_per_call(db_session, monkeypatch):
    """Batching the *replay* rows must not collapse the transcript UI's own
    per-call rows — those are what render the "2 lookups" list."""
    project, dept, user = _seed(db_session)
    session = agent_service.create_session(
        db_session, project_pk=project.id, current=_Current(user)
    )
    _install_fake_model(
        monkeypatch,
        [
            _FakeResponse(
                calls=[
                    _FakeCall("get_findings_summary", {}, "call-1"),
                    _FakeCall("list_services", {}, "call-2"),
                ]
            ),
            _FakeResponse(text="Done."),
        ],
    )
    agent_service.run_turn(
        db_session,
        session_id=session.id,
        message="summarise",
        current=_Current(user),
        settings={"GEMINI_AGENT_MODEL": "m", "GEMINI_AGENT_MAX_OUTPUT_TOKENS": "1024"},
    )

    display = (
        db_session.query(AgentMessage)
        .filter(
            AgentMessage.session_id == session.id, AgentMessage.role == MessageRole.tool
        )
        .all()
    )
    assert {row.tool_name for row in display} == {"get_findings_summary", "list_services"}


def test_a_single_call_still_produces_one_part(db_session, monkeypatch):
    project, dept, user = _seed(db_session)
    session = agent_service.create_session(
        db_session, project_pk=project.id, current=_Current(user)
    )
    captured = _install_fake_model(
        monkeypatch,
        [
            _FakeResponse(calls=[_FakeCall("get_findings_summary", {}, "call-1")]),
            _FakeResponse(text="One thing."),
        ],
    )
    agent_service.run_turn(
        db_session,
        session_id=session.id,
        message="summarise",
        current=_Current(user),
        settings={"GEMINI_AGENT_MODEL": "m", "GEMINI_AGENT_MAX_OUTPUT_TOKENS": "1024"},
    )
    tool_turns = [
        c
        for c in captured["contents"]
        if any(getattr(p, "function_response", None) is not None for p in (c.parts or []))
    ]
    assert len(tool_turns) == 1
    assert len(tool_turns[0].parts) == 1
