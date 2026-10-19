"""LangGraph-driven report generation.

Everything here serves ONE feature: the `deep` report mode. The `standard`
mode (`worker/tasks.py::generate_report_task`) is untouched and remains the
default.

The report pipeline uses LangGraph for bounded durable execution. The chat
agent remains a separate, hand-rolled tool loop.

**LangGraph orchestrates. It does not talk to Gemini.** Every model call in
this package goes through `integrations/gemini_agent.py`, exactly as the chat
agent's does, so its three Gemini tool-calling fixes are kept: one
`Content` per parallel call round, `candidate.content` appended verbatim so
thought signatures survive, and Automatic Function Calling off. No LangChain
message types appear anywhere in this package.
"""
