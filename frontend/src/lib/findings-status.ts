/** The one place that owns what the Findings table's `?status=` URL param
 *  means. Findings.tsx (the reader) and FindingsOverview.tsx (the writer,
 *  via its drill-down links) used to each hand-encode/decode this
 *  independently — the two sides disagreeing once already produced a real
 *  bug (a drill-through landing on an empty table). `encodeStatusParam`
 *  and `decodeStatusParam` are exact inverses of each other and are the
 *  only functions either page should touch. */

/** Findings.tsx's own default when no `status` param is present at all —
 *  this is a triage tool, so a first visit (or a link that doesn't care
 *  about status) opens on what's failing. */
export const DEFAULT_STATUS_FILTER = new Set(["FAIL"]);

/** Every status except PASS — what "hide passing findings" means on the
 *  Overview page, encoded as a URL scope so the Table page ends up
 *  showing exactly the same rows Overview just counted. */
export const NON_PASS_STATUSES = ["FAIL", "MANUAL", "RESOURCE_DOES_NOT_EXIST"];

/** `Set` -> URL param. An empty set is an explicit "no status filter",
 *  encoded as the literal "ALL" — the param's *absence* means something
 *  different (fall back to `DEFAULT_STATUS_FILTER`), so "no filter" has to
 *  be spelled out rather than left blank. */
export function encodeStatusParam(statuses: Set<string>): string {
  return statuses.size === 0 ? "ALL" : [...statuses].join(",");
}

/** URL param -> `Set`, the exact inverse of `encodeStatusParam`. */
export function decodeStatusParam(param: string | null): Set<string> {
  if (param === null) return new Set(DEFAULT_STATUS_FILTER);
  if (param === "ALL") return new Set();
  return new Set(param.split(","));
}

/** Same pairing as `encode`/`decodeStatusParam`, for the `?muted=` scope
 *  Overview's drill-down links send. Kept in one place for the same reason as
 *  status: the two sides hand-rolling this independently is exactly what
 *  produced the status drill-through bug once already. `null` means "don't
 *  narrow" — Overview only sends a value when it is hiding muted findings. */
export function encodeMutedParam(includeMuted: boolean): string | null {
  return includeMuted ? null : "false";
}

/** URL param -> `Set`, matching `mutedFilter`'s shape (the muted facet
 *  filter's own selection set). The exact inverse of `encodeMutedParam`. */
export function decodeMutedParam(param: string | null): Set<string> {
  return param === null ? new Set() : new Set([param]);
}
