// §20.2 "Nodra es el único sincronizador de la carpeta": the known signals of another sync tool on this
// vault folder (NOTES question 416). `observeSyncTools` gathers the facts through the DataAdapter;
// `detectOtherSyncTools` decides from them alone. Sync does not start while a signal the user has not
// confirmed is present (main.ts `restart`).

export interface SyncToolFacts {
  /** `FileSystemAdapter.getBasePath()`: the vault folder's absolute path; null when unknown. */
  readonly basePath: string | null;
  /** `.stfolder`, `.dropbox` and `.git` at the vault root. */
  readonly stfolder: boolean;
  readonly dropboxMarker: boolean;
  readonly git: boolean;
  /** Obsidian's live state of the core Sync plugin; null when the app does not expose it. */
  readonly coreSyncEnabled: boolean | null;
  /** The raw text of `<configDir>/core-plugins.json`, `community-plugins.json` and `plugins/obsidian-git/data.json`; null when missing or unreadable. */
  readonly corePlugins: string | null;
  readonly communityPlugins: string | null;
  readonly obsidianGitData: string | null;
}

export type SyncSignalId = "obsidian-sync" | "syncthing" | "dropbox" | "git" | "icloud-path" | "dropbox-path" | "onedrive-path";
const SIGNAL_IDS: readonly string[] = ["obsidian-sync", "syncthing", "dropbox", "git", "icloud-path", "dropbox-path", "onedrive-path"] satisfies SyncSignalId[];

export interface SyncSignal {
  readonly id: SyncSignalId;
  /** The tool, as the user knows it. */
  readonly tool: string;
  /** What was found, as a sentence. */
  readonly evidence: string;
}

const json = (text: string | null): unknown => {
  if (text === null) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
};
const isRecord = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null && !Array.isArray(x);

/** core-plugins.json is `{ id: enabled }` in current Obsidian and a list of enabled ids in older ones. */
function coreSyncOn(f: SyncToolFacts): boolean {
  if (f.coreSyncEnabled !== null) return f.coreSyncEnabled;
  const cfg = json(f.corePlugins);
  if (Array.isArray(cfg)) return cfg.includes("sync");
  return isRecord(cfg) && cfg.sync === true;
}

/**
 * obsidian-git (plugin id `obsidian-git`, settings in its data.json, DEFAULT_SETTINGS in its
 * src/constants.ts): `autoSaveInterval` (automatic commit-and-sync, minutes), `autoPushInterval`,
 * `autoPullInterval` (minutes; 0 is off) and `autoPullOnBoot`. A `.git` folder alone is committed by hand.
 */
function gitSyncsOnItsOwn(f: SyncToolFacts): boolean {
  if (!f.git) return false;
  const enabled = json(f.communityPlugins);
  if (!Array.isArray(enabled) || !enabled.includes("obsidian-git")) return false;
  const s = json(f.obsidianGitData);
  if (!isRecord(s)) return false;
  const on = (key: string) => typeof s[key] === "number" && s[key] > 0;
  return on("autoSaveInterval") || on("autoPushInterval") || on("autoPullInterval") || s.autoPullOnBoot === true;
}

/** Which synced folder the vault folder is inside, by the whole names of its parent folders. */
function syncedParents(basePath: string): Set<"icloud-path" | "dropbox-path" | "onedrive-path"> {
  const found = new Set<"icloud-path" | "dropbox-path" | "onedrive-path">();
  const parents = basePath.split(/[\\/]+/).filter((s) => s !== "").slice(0, -1);
  parents.forEach((name, i) => {
    const n = name.toLowerCase();
    const cloudStorage = i >= 2 && parents[i - 1]!.toLowerCase() === "cloudstorage" && parents[i - 2]!.toLowerCase() === "library";
    if (n === "mobile documents") found.add("icloud-path");
    if (n === "dropbox" || /^dropbox \(.+\)$/.test(n) || (cloudStorage && n.startsWith("dropbox"))) found.add("dropbox-path");
    if (n === "onedrive" || /^onedrive - .+$/.test(n) || (cloudStorage && n.startsWith("onedrive"))) found.add("onedrive-path");
  });
  return found;
}

export function detectOtherSyncTools(f: SyncToolFacts): SyncSignal[] {
  const out: SyncSignal[] = [];
  if (coreSyncOn(f)) out.push({ id: "obsidian-sync", tool: "Obsidian Sync", evidence: "The core Sync plugin is on in this vault." });
  if (f.stfolder) out.push({ id: "syncthing", tool: "Syncthing", evidence: "The vault folder has a .stfolder marker." });
  if (f.dropboxMarker) out.push({ id: "dropbox", tool: "Dropbox", evidence: "The vault folder has a .dropbox marker." });
  if (gitSyncsOnItsOwn(f)) out.push({ id: "git", tool: "Obsidian Git", evidence: "The vault is a Git repository and the Git plugin commits, pushes or pulls on its own." });
  if (f.basePath !== null) {
    const parents = syncedParents(f.basePath);
    if (parents.has("icloud-path")) out.push({ id: "icloud-path", tool: "iCloud Drive", evidence: `The vault is inside iCloud Drive: ${f.basePath}.` });
    if (parents.has("dropbox-path")) out.push({ id: "dropbox-path", tool: "Dropbox", evidence: `The vault is inside a Dropbox folder: ${f.basePath}.` });
    if (parents.has("onedrive-path")) out.push({ id: "onedrive-path", tool: "OneDrive", evidence: `The vault is inside a OneDrive folder: ${f.basePath}.` });
  }
  return out;
}

/** The signals the user has not confirmed: each one holds sync. */
export const unconfirmedSignals = (detected: readonly SyncSignal[], confirmed: readonly string[]): SyncSignal[] => detected.filter((s) => !confirmed.includes(s.id));

/** The confirmations still backed by a present signal; one whose signal disappeared is dropped. */
export const keptConfirmations = (detected: readonly SyncSignal[], confirmed: readonly string[]): string[] =>
  [...new Set(confirmed.filter((id) => detected.some((s) => s.id === id)))].sort();

/** What the vault's local storage holds, read defensively. */
export const parseConfirmations = (stored: unknown): string[] => (Array.isArray(stored) ? stored.filter((x): x is string => typeof x === "string" && SIGNAL_IDS.includes(x)) : []);

export interface SyncToolAdapter {
  exists(path: string): Promise<boolean>;
  read(path: string): Promise<string>;
}

/** The facts, through the vault's DataAdapter. A missing or unreadable file is null, never a failure. */
export async function observeSyncTools(o: { readonly adapter: SyncToolAdapter; readonly configDir: string; readonly basePath: string | null; readonly coreSyncEnabled: boolean | null }): Promise<SyncToolFacts> {
  const exists = (p: string) => o.adapter.exists(p).catch(() => false);
  const read = async (p: string) => ((await exists(p)) ? o.adapter.read(p).catch(() => null) : null);
  const [stfolder, dropboxMarker, git, corePlugins, communityPlugins, obsidianGitData] = await Promise.all([
    exists(".stfolder"),
    exists(".dropbox"),
    exists(".git"),
    read(`${o.configDir}/core-plugins.json`),
    read(`${o.configDir}/community-plugins.json`),
    read(`${o.configDir}/plugins/obsidian-git/data.json`),
  ]);
  return { basePath: o.basePath, stfolder, dropboxMarker, git, coreSyncEnabled: o.coreSyncEnabled, corePlugins, communityPlugins, obsidianGitData };
}
