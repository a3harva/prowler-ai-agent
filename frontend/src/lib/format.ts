/** Formatting helpers over Intl, so the app carries no date library. */

const DATE_TIME = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
});

const RELATIVE = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

/** Absolute local timestamp. `null` renders as an em dash rather than
 *  "Invalid Date", which is what `new Date(null)` would otherwise produce. */
export function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return DATE_TIME.format(date);
}

const RELATIVE_STEPS: Array<[Intl.RelativeTimeFormatUnit, number]> = [
  ["second", 60],
  ["minute", 60],
  ["hour", 24],
  ["day", 7],
  ["week", 4.348],
  ["month", 12],
  ["year", Number.POSITIVE_INFINITY],
];

/** "3 minutes ago". Used alongside, never instead of, the absolute value —
 *  a relative time on its own is unusable in an audit context. */
export function formatRelative(value: string | null | undefined): string {
  if (!value) return "never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "never";

  let delta = (date.getTime() - Date.now()) / 1000;
  for (const [unit, step] of RELATIVE_STEPS) {
    if (Math.abs(delta) < step) return RELATIVE.format(Math.round(delta), unit);
    delta /= step;
  }
  return RELATIVE.format(Math.round(delta), "year");
}

/** Elapsed time between two instants, for scan durations. Reads as "4m 12s"
 *  rather than a raw second count, which nobody can parse at a glance. */
export function formatDuration(
  from: string | null | undefined,
  to: string | null | undefined,
): string {
  if (!from) return "—";
  const start = new Date(from).getTime();
  const end = to ? new Date(to).getTime() : Date.now();
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) return "—";

  const totalSeconds = Math.floor((end - start) / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

/** Middle-truncation, for fully-qualified resource identifiers. Truncating
 *  the end would hide the part that actually distinguishes two resources —
 *  three tables all named `gcp_cloud_assets` differ only in their dataset. */
export function truncateMiddle(value: string, max = 48): string {
  if (value.length <= max) return value;
  const keep = Math.floor((max - 1) / 2);
  return `${value.slice(0, keep)}…${value.slice(-keep)}`;
}

export function pluralize(count: number, singular: string, plural?: string): string {
  return `${count} ${count === 1 ? singular : (plural ?? `${singular}s`)}`;
}

/** Every GCP service account ends `.iam.gserviceaccount.com`, so those 24
 *  characters distinguish nothing while crowding out the project name that
 *  does. Dropped for display only — the full address is still what gets
 *  copied and what the tooltip shows. */
const SA_SUFFIX = ".iam.gserviceaccount.com";

export function shortenServiceAccount(email: string): string {
  return email.endsWith(SA_SUFFIX) ? email.slice(0, -SA_SUFFIX.length) : email;
}
