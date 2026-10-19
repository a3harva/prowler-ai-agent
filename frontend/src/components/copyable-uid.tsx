import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { truncateMiddle } from "@/lib/format";
import { cn } from "@/lib/utils";

/**
 * A fully-qualified identifier: resource UID, service account, project id.
 *
 * Mono, because these are machine strings and column alignment is what makes
 * a list of them scannable. Middle-truncated rather than end-truncated,
 * because the distinguishing part is usually at the end — the reference scan
 * contains three different tables all named `gcp_cloud_assets` that differ
 * only by dataset, and end-truncation would render them identical.
 */
export function CopyableUid({
  value,
  max = 48,
  /** What to show instead of `value`. The full `value` is still what gets
   *  copied and what the tooltip reveals — this only trims noise that
   *  carries no information, never anything that distinguishes two rows. */
  display: displayOverride,
  className,
}: {
  value: string;
  max?: number;
  display?: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  const source = displayOverride ?? value;
  const display = truncateMiddle(source, max);
  const truncated = display !== value;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      // Clipboard is unavailable over plain http on some browsers. The full
      // value is in the tooltip and the title attribute either way, so this
      // degrades to "select it yourself" rather than breaking.
    }
  };

  const content = (
    <button
      type="button"
      onClick={copy}
      title={value}
      className={cn(
        "group inline-flex max-w-full items-center gap-1.5 rounded",
        "font-mono text-xs text-ink",
        "hover:text-brand focus-visible:text-brand",
        "transition-colors duration-150",
        className,
      )}
    >
      <span className="truncate">{display}</span>
      {copied ? (
        <Check className="size-3 shrink-0 text-status-pass" aria-hidden />
      ) : (
        <Copy
          className="size-3 shrink-0 opacity-0 transition-opacity duration-150 group-hover:opacity-60 group-focus-visible:opacity-60"
          aria-hidden
        />
      )}
      <span className="sr-only">{copied ? "Copied" : `Copy ${value}`}</span>
    </button>
  );

  if (!truncated) return content;

  return (
    <Tooltip>
      <TooltipTrigger asChild>{content}</TooltipTrigger>
      <TooltipContent className="max-w-[32rem] break-all font-mono text-xs">
        {value}
      </TooltipContent>
    </Tooltip>
  );
}
