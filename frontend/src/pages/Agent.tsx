import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowUp, Loader2, Wrench } from "lucide-react";
import { ActionBanner } from "@/components/action-banner";
import { Markdown } from "@/components/markdown";
import { ProjectPicker } from "@/components/project-picker";
import { Button } from "@/components/ui/button";
import { useStatus } from "@/components/status-region";
import { errorMessage } from "@/api/client";
import { cn } from "@/lib/utils";
import {
  useAgentMessages,
  useApplyAgentAction,
  useCreateAgentSession,
  useDiscardAgentAction,
  useOrganizations,
  useProjects,
  useSendAgentMessage,
} from "@/hooks/queries";
import type { AgentToolCall, PendingAction } from "@/api/types";

/**
 * Chat with one project's findings.
 *
 * Laid out as a chat surface rather than a form-over-a-panel: a centred
 * reading column, and one composer that starts in the middle of an empty
 * screen and settles to the bottom once a conversation exists. The project
 * lives as a pill *inside* the composer — the same place a chat app puts its
 * model picker — because choosing it is part of asking the question, not a
 * separate configuration step above it.
 *
 * The surface uses shared semantic tokens throughout. The reference for this
 * layout was a dark interface, but this page does not own a separate palette:
 * the global light/dark token sets in index.css style it with the rest of the
 * product. What is borrowed is the shape and interaction, not hardcoded colour.
 */

interface Turn {
  id: string;
  role: "user" | "assistant";
  text: string;
  toolCalls?: AgentToolCall[];
  pendingActions?: PendingAction[];
}

function ToolCallList({ calls }: { calls: AgentToolCall[] }) {
  const [open, setOpen] = useState(false);
  if (calls.length === 0) return null;
  return (
    <div className="mt-2">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="inline-flex items-center gap-1.5 text-xs text-ink-muted transition-colors hover:text-ink-secondary"
      >
        <Wrench className="size-3" aria-hidden />
        {calls.length} {calls.length === 1 ? "lookup" : "lookups"}
        <span aria-hidden>·</span>
        <span className="underline-offset-2 hover:underline">{open ? "hide" : "show"}</span>
      </button>
      {open && (
        <ul className="mt-1.5 space-y-1">
          {calls.map((call, i) => (
            <li key={`${call.name}-${i}`} className="rounded-md bg-subtle px-2.5 py-1.5">
              <p className="font-mono text-[11px] text-ink">{call.name}</p>
              {Object.keys(call.args).length > 0 && (
                <p className="mt-0.5 break-all font-mono text-[10px] text-ink-secondary">
                  {JSON.stringify(call.args)}
                </p>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

const SUGGESTIONS = [
  "Give me an overview of this project's posture",
  "Which checks affect the most resources?",
  "What are the critical findings?",
  "How do we score against CIS?",
];

export default function Agent() {
  const projects = useProjects();
  const organizations = useOrganizations();
  const { succeed, fail } = useStatus();

  const [projectId, setProjectId] = useState("");
  const [sessionId, setSessionId] = useState<number | undefined>();
  const [draft, setDraft] = useState("");
  const [turns, setTurns] = useState<Turn[]>([]);
  const [resolved, setResolved] = useState<Record<number, "applied" | "discarded">>({});
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const createSession = useCreateAgentSession();
  const sendMessage = useSendAgentMessage();
  const applyAction = useApplyAgentAction();
  const discardAction = useDiscardAgentAction();
  const history = useAgentMessages(sessionId);

  const selectedProject = (projects.data ?? []).find((p) => String(p.id) === projectId);
  const started = turns.length > 0;
  const locked = sessionId !== undefined;

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [turns, sendMessage.isPending]);

  // The textarea grows with its content up to a ceiling, so the composer reads
  // as a single-line pill for a short question and a small block for a long
  // one — rather than a permanently oversized box.
  //
  // Driven by an effect on `draft` rather than called inside the change and
  // submit handlers. Measuring in the handler reads `scrollHeight` **before**
  // React has re-rendered with the new value, so clearing the box after send
  // measured the text that was just cleared and the composer stayed tall for
  // the rest of the conversation.
  useEffect(() => {
    const el = inputRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(el.scrollHeight, 200)}px`;
  }, [draft, started]);

  async function ensureSession(): Promise<number> {
    if (sessionId !== undefined) return sessionId;
    const session = await createSession.mutateAsync(Number(projectId));
    setSessionId(session.id);
    return session.id;
  }

  async function submit(text: string) {
    const message = text.trim();
    if (!message || !projectId || sendMessage.isPending) return;
    setDraft("");
    setTurns((t) => [...t, { id: `u-${Date.now()}`, role: "user", text: message }]);
    try {
      const id = await ensureSession();
      const turn = await sendMessage.mutateAsync({ sessionId: id, message });
      setTurns((t) => [
        ...t,
        {
          id: `a-${Date.now()}`,
          role: "assistant",
          text: turn.answer,
          toolCalls: turn.tool_calls,
          pendingActions: turn.pending_actions,
        },
      ]);
    } catch (error) {
      const detail = errorMessage(error);
      fail(detail);
      setTurns((t) => [
        ...t,
        { id: `e-${Date.now()}`, role: "assistant", text: `**Something went wrong.** ${detail}` },
      ]);
    }
  }

  async function confirm(id: number) {
    try {
      const response = await applyAction.mutateAsync(id);
      setResolved((r) => ({ ...r, [id]: "applied" }));
      const count = (response.result as { muted_count?: number }).muted_count;
      succeed(count !== undefined ? `Applied to ${count} findings.` : "Change applied.");
      void history.refetch();
    } catch (error) {
      fail(errorMessage(error));
    }
  }

  async function discard(id: number) {
    try {
      await discardAction.mutateAsync(id);
      setResolved((r) => ({ ...r, [id]: "discarded" }));
      succeed("Discarded — nothing was changed.");
    } catch (error) {
      fail(errorMessage(error));
    }
  }

  const composer = (
    <div className="w-full">
      <div className="rounded-[26px] border border-hairline bg-panel px-2 py-2 shadow-[var(--shadow-lift)] transition-colors focus-within:border-brand-200">
        <div className="flex items-end gap-2">
          <textarea
            ref={inputRef}
            value={draft}
            rows={1}
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                void submit(draft);
              }
            }}
            disabled={!projectId || sendMessage.isPending}
            placeholder={
              projectId
                ? `Ask about ${selectedProject?.project_id ?? "this project"}`
                : "Choose a project to begin"
            }
            className="max-h-[200px] flex-1 resize-none bg-transparent px-3 py-2 text-sm text-ink outline-none placeholder:text-ink-muted disabled:cursor-not-allowed"
          />
          <div className="flex shrink-0 items-center gap-1.5 pb-0.5">
            <ProjectPicker
              projects={projects.data ?? []}
              organizations={organizations.data ?? []}
              value={projectId}
              onChange={setProjectId}
              disabled={locked}
            />
            <button
              type="button"
              onClick={() => void submit(draft)}
              disabled={!projectId || !draft.trim() || sendMessage.isPending}
              aria-label="Send message"
              className={cn(
                "flex size-9 items-center justify-center rounded-full transition-colors",
                !projectId || !draft.trim() || sendMessage.isPending
                  ? "bg-subtle text-ink-muted"
                  : "bg-brand text-primary-foreground hover:bg-brand-hover",
              )}
            >
              {sendMessage.isPending ? (
                <Loader2 className="size-4 animate-spin" aria-hidden />
              ) : (
                <ArrowUp className="size-4" aria-hidden />
              )}
            </button>
          </div>
        </div>
      </div>
      <p className="mt-2 px-3 text-center text-xs text-ink-muted">
        {locked
          ? "This conversation is bound to one project and cannot read or change any other."
          : "A conversation covers one project for its lifetime."}
      </p>
    </div>
  );

  // Empty: one centred column, composer in the middle of the screen.
  if (!started) {
    return (
      <div className="mx-auto flex min-h-[calc(100vh-9rem)] w-full max-w-3xl flex-col items-center justify-center gap-8 px-4">
        <div className="space-y-2 text-center">
          <h1 className="text-4xl font-light tracking-tight text-ink">
            {selectedProject ? "What should we look at?" : "Where should we start?"}
          </h1>
          <p className="text-sm text-ink-secondary">
            {selectedProject
              ? `Ask about ${selectedProject.project_id}, or prepare a triage action on its findings.`
              : "Pick a project from the composer below to begin."}
          </p>
        </div>

        {composer}

        {selectedProject && (
          <div className="flex flex-wrap justify-center gap-2">
            {SUGGESTIONS.map((suggestion) => (
              <button
                key={suggestion}
                type="button"
                onClick={() => void submit(suggestion)}
                className="rounded-full border border-hairline bg-panel px-3.5 py-1.5 text-xs text-ink-secondary transition-colors hover:border-brand-200 hover:text-ink"
              >
                {suggestion}
              </button>
            ))}
          </div>
        )}
      </div>
    );
  }

  // Active: messages scroll in the same column, composer settles to the bottom.
  return (
    <div className="mx-auto flex h-[calc(100vh-8rem)] w-full max-w-3xl flex-col px-4">
      <div className="flex items-center justify-between pb-3">
        <p className="text-sm text-ink-secondary">
          <span className="font-medium text-ink">{selectedProject?.project_id}</span>
        </p>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => {
            setSessionId(undefined);
            setTurns([]);
            setResolved({});
            setProjectId("");
            setDraft("");
          }}
        >
          New conversation
        </Button>
      </div>

      <div ref={scrollRef} className="flex-1 space-y-6 overflow-y-auto pb-6">
        {turns.map((turn) => (
          <div key={turn.id} className={turn.role === "user" ? "flex justify-end" : ""}>
            {turn.role === "user" ? (
              <p className="max-w-[80%] rounded-[20px] bg-subtle px-4 py-2.5 text-sm text-ink">
                {turn.text}
              </p>
            ) : (
              <div className="max-w-full">
                <Markdown content={turn.text} />
                {turn.toolCalls && <ToolCallList calls={turn.toolCalls} />}
                {turn.pendingActions && turn.pendingActions.length > 0 && (
                  <div className="mt-3 space-y-2">
                    {turn.pendingActions.map((action) => (
                      <ActionBanner
                        key={action.id}
                        action={action}
                        onConfirm={confirm}
                        onDiscard={discard}
                        busy={applyAction.isPending || discardAction.isPending}
                        resolved={resolved[action.id]}
                      />
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}

        {sendMessage.isPending && (
          <p className="inline-flex items-center gap-2 text-sm text-ink-muted">
            <Loader2 className="size-3.5 animate-spin" aria-hidden />
            Looking through the findings…
          </p>
        )}
      </div>

      <div className="pb-4">{composer}</div>
    </div>
  );
}
