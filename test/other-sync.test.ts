import { describe, expect, it } from "vitest";
import { type SyncToolFacts, detectOtherSyncTools, keptConfirmations, observeSyncTools, parseConfirmations, unconfirmedSignals } from "../src/other-sync.js";

// §20.2 "Nodra es el único sincronizador de la carpeta": the known signals of another sync tool on the
// vault folder, from observed facts only (NOTES question 416). Each signal has a positive case and the
// negatives that must not trip it, false-positive traps included.

const none: SyncToolFacts = {
  basePath: "/Users/ana/Notes",
  stfolder: false,
  dropboxMarker: false,
  git: false,
  coreSyncEnabled: null,
  corePlugins: null,
  communityPlugins: null,
  obsidianGitData: null,
};
const ids = (over: Partial<SyncToolFacts>) => detectOtherSyncTools({ ...none, ...over }).map((s) => s.id);

describe("nothing found", () => {
  it("a plain vault: no signal", () => {
    expect(detectOtherSyncTools(none)).toEqual([]);
  });
  it("the base path unknown (not a desktop adapter): no path signal", () => {
    expect(ids({ basePath: null })).toEqual([]);
  });
});

describe("Obsidian Sync (the core Sync plugin on in this vault)", () => {
  it("core-plugins.json as an object (current Obsidian): sync true", () => {
    expect(ids({ corePlugins: JSON.stringify({ "file-explorer": true, sync: true }) })).toEqual(["obsidian-sync"]);
  });
  it("core-plugins.json as a list of enabled ids (older Obsidian)", () => {
    expect(ids({ corePlugins: JSON.stringify(["file-explorer", "sync"]) })).toEqual(["obsidian-sync"]);
  });
  it("sync false, absent, another id containing 'sync', or unreadable JSON: no signal", () => {
    expect(ids({ corePlugins: JSON.stringify({ sync: false, search: true }) })).toEqual([]);
    expect(ids({ corePlugins: JSON.stringify({ search: true }) })).toEqual([]);
    expect(ids({ corePlugins: JSON.stringify(["file-explorer", "sync-status"]) })).toEqual([]);
    expect(ids({ corePlugins: "{not json" })).toEqual([]);
  });
  it("Obsidian's live state wins over the file: just turned off, the file not rewritten yet", () => {
    expect(ids({ coreSyncEnabled: false, corePlugins: JSON.stringify({ sync: true }) })).toEqual([]);
    expect(ids({ coreSyncEnabled: true, corePlugins: JSON.stringify({ sync: false }) })).toEqual(["obsidian-sync"]);
  });
  it("says which tool and why", () => {
    expect(detectOtherSyncTools({ ...none, coreSyncEnabled: true })).toEqual([{ id: "obsidian-sync", tool: "Obsidian Sync", evidence: "The core Sync plugin is on in this vault." }]);
  });
});

describe("markers at the vault root", () => {
  it(".stfolder: Syncthing", () => {
    expect(detectOtherSyncTools({ ...none, stfolder: true })).toEqual([{ id: "syncthing", tool: "Syncthing", evidence: "The vault folder has a .stfolder marker." }]);
  });
  it(".dropbox: Dropbox", () => {
    expect(ids({ dropboxMarker: true })).toEqual(["dropbox"]);
  });
});

describe("Git that syncs on its own: .git AND obsidian-git enabled AND an automatic commit, push or pull", () => {
  const enabled = JSON.stringify(["dataview", "obsidian-git"]);
  const git = (data: Record<string, unknown> | string | null, over: Partial<SyncToolFacts> = {}) =>
    ids({ git: true, communityPlugins: enabled, obsidianGitData: data === null ? null : typeof data === "string" ? data : JSON.stringify(data), ...over });

  it("each automatic setting of obsidian-git counts", () => {
    expect(git({ autoSaveInterval: 5 })).toEqual(["git"]);
    expect(git({ autoPushInterval: 10 })).toEqual(["git"]);
    expect(git({ autoPullInterval: 10 })).toEqual(["git"]);
    expect(git({ autoPullOnBoot: true })).toEqual(["git"]);
  });
  it("its defaults (every interval 0, no pull on boot), or no data.json: no signal", () => {
    expect(git({ autoSaveInterval: 0, autoPushInterval: 0, autoPullInterval: 0, autoPullOnBoot: false, autoBackupAfterFileChange: true })).toEqual([]);
    expect(git(null)).toEqual([]);
    expect(git("{broken")).toEqual([]);
    expect(git({ autoSaveInterval: "5" })).toEqual([]); // obsidian-git stores numbers
  });
  it("a .git folder alone (commits by hand) is not a signal", () => {
    expect(ids({ git: true })).toEqual([]);
  });
  it("obsidian-git installed but not enabled, or enabled with no .git: no signal", () => {
    expect(git({ autoSaveInterval: 5 }, { communityPlugins: JSON.stringify(["dataview"]) })).toEqual([]);
    expect(git({ autoSaveInterval: 5 }, { communityPlugins: null })).toEqual([]);
    expect(git({ autoSaveInterval: 5 }, { git: false })).toEqual([]);
  });
});

describe("the vault folder inside a synced folder (whole folder names of its parents)", () => {
  const at = (basePath: string) => ids({ basePath });

  it("iCloud: Mobile Documents", () => {
    expect(at("/Users/ana/Library/Mobile Documents/iCloud~md~obsidian/Documents/Notes")).toEqual(["icloud-path"]);
    expect(at("/Users/ana/Library/Mobile Documents/com~apple~CloudDocs/Notes")).toEqual(["icloud-path"]);
  });
  it("Dropbox: Dropbox, Dropbox (Team), Library/CloudStorage/Dropbox*", () => {
    expect(at("C:\\Users\\ana\\Dropbox\\Notes")).toEqual(["dropbox-path"]);
    expect(at("/Users/ana/Dropbox (Acme)/Notes")).toEqual(["dropbox-path"]);
    expect(at("/Users/ana/Library/CloudStorage/Dropbox/Notes")).toEqual(["dropbox-path"]);
    expect(at("/Users/ana/Library/CloudStorage/Dropbox-Acme/Notes")).toEqual(["dropbox-path"]);
  });
  it("OneDrive: OneDrive, OneDrive - Org, Library/CloudStorage/OneDrive*", () => {
    expect(at("C:\\Users\\ana\\OneDrive\\Documents\\Notes")).toEqual(["onedrive-path"]);
    expect(at("C:\\Users\\ana\\OneDrive - Acme Corp\\Notes")).toEqual(["onedrive-path"]);
    expect(at("/Users/ana/Library/CloudStorage/OneDrive-Personal/Notes")).toEqual(["onedrive-path"]);
  });
  it("says where", () => {
    expect(detectOtherSyncTools({ ...none, basePath: "C:\\Users\\ana\\Dropbox\\Notes" })).toEqual([{ id: "dropbox-path", tool: "Dropbox", evidence: "The vault is inside a Dropbox folder: C:\\Users\\ana\\Dropbox\\Notes." }]);
  });
  it("traps: a name that merely contains the word, a similar name, or the vault's own folder name", () => {
    expect(at("/Users/ana/Dropbox notes/Notes")).toEqual([]);
    expect(at("/Users/ana/MyDropbox/Notes")).toEqual([]);
    expect(at("/Users/ana/Dropbox-backup/Notes")).toEqual([]); // the CloudStorage form only under Library/CloudStorage
    expect(at("C:\\Users\\ana\\OneDriveBackup\\Notes")).toEqual([]);
    expect(at("C:\\Users\\ana\\OneDrive backup\\Notes")).toEqual([]);
    expect(at("/Users/ana/Mobile Documents copy/Notes")).toEqual([]);
    expect(at("/Users/ana/Vaults/Dropbox")).toEqual([]); // a vault named Dropbox is not inside Dropbox
    expect(at("/Users/ana/Library/CloudStorage/GoogleDrive-ana@example.test/Notes")).toEqual([]); // not a §20.2 signal
  });
});

describe("several at once", () => {
  it("every signal is reported, each once", () => {
    expect(ids({ basePath: "/Users/ana/Dropbox/Notes", dropboxMarker: true, stfolder: true, coreSyncEnabled: true })).toEqual(["obsidian-sync", "syncthing", "dropbox", "dropbox-path"]);
  });
});

describe("the user's confirmation, bound to the exact signals", () => {
  const found = detectOtherSyncTools({ ...none, basePath: "/Users/ana/Dropbox/Notes", stfolder: true });

  it("nothing confirmed: every signal holds sync", () => {
    expect(unconfirmedSignals(found, []).map((s) => s.id)).toEqual(["syncthing", "dropbox-path"]);
  });
  it("all confirmed: none holds it", () => {
    expect(unconfirmedSignals(found, ["dropbox-path", "syncthing"])).toEqual([]);
  });
  it("a new signal asks again, for itself only", () => {
    expect(unconfirmedSignals(found, ["dropbox-path"]).map((s) => s.id)).toEqual(["syncthing"]);
  });
  it("a signal that disappeared drops its confirmation; the rest are kept, sorted", () => {
    expect(keptConfirmations(found, ["syncthing", "obsidian-sync", "dropbox-path"])).toEqual(["dropbox-path", "syncthing"]);
    expect(keptConfirmations([], ["syncthing"])).toEqual([]);
  });
  it("what the local storage holds is read defensively", () => {
    expect(parseConfirmations(["syncthing", "git"])).toEqual(["syncthing", "git"]);
    expect(parseConfirmations(null)).toEqual([]);
    expect(parseConfirmations("syncthing")).toEqual([]);
    expect(parseConfirmations(["syncthing", 3, "nonsense"])).toEqual(["syncthing"]);
  });
});

describe("observing the vault (over the DataAdapter)", () => {
  const adapter = (files: Record<string, string>, folders: string[] = []) => ({
    exists: async (p: string) => p in files || folders.includes(p),
    read: async (p: string) => {
      if (!(p in files)) throw new Error(`ENOENT ${p}`);
      return files[p]!;
    },
  });

  it("reads the markers at the root and the config files under the vault's config folder", async () => {
    const facts = await observeSyncTools({
      adapter: adapter(
        {
          ".cfg/core-plugins.json": '{"sync":true}',
          ".cfg/community-plugins.json": '["obsidian-git"]',
          ".cfg/plugins/obsidian-git/data.json": '{"autoSaveInterval":5}',
        },
        [".stfolder", ".dropbox", ".git"],
      ),
      configDir: ".cfg",
      basePath: "/Users/ana/Notes",
      coreSyncEnabled: null,
    });
    expect(facts).toEqual({
      basePath: "/Users/ana/Notes",
      stfolder: true,
      dropboxMarker: true,
      git: true,
      coreSyncEnabled: null,
      corePlugins: '{"sync":true}',
      communityPlugins: '["obsidian-git"]',
      obsidianGitData: '{"autoSaveInterval":5}',
    });
    expect(detectOtherSyncTools(facts).map((s) => s.id)).toEqual(["obsidian-sync", "syncthing", "dropbox", "git"]);
  });

  it("missing or unreadable files are null, never a failure", async () => {
    const broken = { exists: async () => true, read: async () => Promise.reject(new Error("EACCES")) };
    expect(await observeSyncTools({ adapter: broken, configDir: ".obsidian", basePath: null, coreSyncEnabled: false })).toMatchObject({ corePlugins: null, communityPlugins: null, obsidianGitData: null, coreSyncEnabled: false });
    expect(await observeSyncTools({ adapter: adapter({}), configDir: ".obsidian", basePath: null, coreSyncEnabled: null })).toEqual({ ...none, basePath: null });
  });
});
