import { describe, expect, it } from "vitest";
import { rebaseText } from "../src/rebase.js";

// (Q415) The editor keeps typing on the note as it loaded it; when the store shows a newer note, the
// editor's text is rebased onto it with the three-way merge (merge3, node-diff3). Conflict → null: the
// editor keeps its view and the leader makes the conflict copy (§20.2), so nothing is ever lost.
describe("rebaseText (Q415)", () => {
  const BASE = "line 1\nline 2\nline 3\nline 4\nline 5\n";
  const PLUGIN = "line 1 from obsidian\nline 2\nline 3\nline 4\nline 5\n";

  it("nothing sent yet: a remote change on another line merges into the text being typed", () => {
    expect(rebaseText(BASE, null, "line 1\nline 2\nline 3\nline 4\nline 5 typed\n", PLUGIN)).toBe("line 1 from obsidian\nline 2\nline 3\nline 4\nline 5 typed\n");
  });

  it("overlapping edits (the same line, or touching lines) → null", () => {
    expect(rebaseText(BASE, null, "line 1 typed\nline 2\nline 3\nline 4\nline 5\n", PLUGIN)).toBeNull();
    expect(rebaseText(BASE, null, "line 1\nline 2 typed\nline 3\nline 4\nline 5\n", PLUGIN)).toBeNull();
  });

  it("the likely production sequence: the pause already sent was merged into the note; the text typed since rebases on it", () => {
    const sent = "line 1\nline 2\nline 3\nline 4\nline 5 from the web\n";
    const merged = "line 1 from obsidian\nline 2\nline 3\nline 4\nline 5 from the web\n";
    const typing = "line 1\nline 2\nline 3\nline 4\nline 5 from the web, still typing\n";
    expect(rebaseText(BASE, sent, typing, merged)).toBe("line 1 from obsidian\nline 2\nline 3\nline 4\nline 5 from the web, still typing\n");
    // With the loaded text as the base instead, both sides changed line 5: a false conflict.
    expect(rebaseText(BASE, null, typing, merged)).toBeNull();
  });

  it("the pause sent is not in the newer note (it became a conflict copy) → null: the next edit follows that copy", () => {
    const sent = "line 1\nline 2\nline 3\nline 4\nline 5 from the web\n";
    expect(rebaseText(BASE, sent, "line 1\nline 2\nline 3\nline 4\nline 5 from the web, still typing\n", PLUGIN)).toBeNull();
  });

  it("the newer note is the result of this editor's own pause: the text is kept as typed", () => {
    const sent = "line 1\nline 2 sent\nline 3\nline 4\nline 5\n";
    const typing = "line 1\nline 2 sent, and more\nline 3\nline 4\nline 5\n";
    expect(rebaseText(BASE, sent, typing, sent)).toBe(typing);
  });

  it("no newer content: the text is kept", () => {
    expect(rebaseText(BASE, null, "anything", BASE)).toBe("anything");
  });

  it("CRLF text merges line by line and keeps its line endings", () => {
    const crlf = (s: string) => s.replaceAll("\n", "\r\n");
    expect(rebaseText(crlf(BASE), null, crlf("line 1\nline 2\nline 3\nline 4\nline 5 typed\n"), crlf(PLUGIN))).toBe(
      crlf("line 1 from obsidian\nline 2\nline 3\nline 4\nline 5 typed\n"),
    );
  });
});
