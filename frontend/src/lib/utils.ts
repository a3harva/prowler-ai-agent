import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/** Shared geometry for every tinted status/severity pill — severity-chip,
 *  status-badge, compliance-status-badge, scan-state. Colour comes from
 *  each component's own tint/text/ring triad; this is only the shape. */
export const PILL_CLASS =
  "inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset"
