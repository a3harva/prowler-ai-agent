/** ASCII kebab-case slug, shared by an anchor's `id` and whatever links to it
 *  via `href="#id"` — one function so the two ends can't drift apart. */
export function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}
