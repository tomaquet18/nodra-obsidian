import { merge3 } from "@nodra/sync-core";

/**
 * (NOTES question 415) An editor keeps typing on the note as it loaded it (its view, §20.2); the store now
 * shows a newer state of the note. Returns the editor's text rebased onto that state (three-way merge,
 * merge3), or null when it cannot: the editor then keeps its view and the leader keeps the out-of-date
 * edit as a conflict copy, as before. The caller only asks with every intent of this editor processed and
 * seen (nothing unprocessed, nothing in flight): never on a state the tab did not know.
 *
 * - `loaded`: the text of the editor's view; `sent`: the text of the last intent it sent on that view
 *   (null if none); `local`: the text now; `remote`: the text of the newer state.
 * - The merge base is `sent` when there is one: the text the user typed after it is what is still unsent,
 *   and the newer state is what became of it. Only if the newer state contains it (applying `sent`'s
 *   changes to it changes nothing): a sent edit that became a conflict copy is not in the note, and the
 *   next edit must follow that copy (Q414's chain), not the note.
 */
export function rebaseText(loaded: string, sent: string | null, local: string, remote: string): string | null {
  if (sent !== null) {
    const contained = merge3(loaded, sent, remote);
    if (contained.kind !== "resolved" || contained.text !== remote) return null;
  }
  const m = merge3(sent ?? loaded, local, remote);
  return m.kind === "resolved" ? m.text : null;
}
