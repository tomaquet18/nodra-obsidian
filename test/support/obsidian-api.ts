// A fake of the `obsidian` runtime module (the npm package ships types only), just what main.ts and
// panel-view.ts call, over happy-dom's DOM (the test files that load it run in `@vitest-environment
// happy-dom`; vitest.config.ts aliases `obsidian` here). It follows obsidian.d.ts; what it cannot show
// about the real app (layout, CSS, the sidebar itself) is listed in NOTES.md, question 412.

type Cls = string | string[];
interface ElOptions {
  readonly text?: string;
  readonly cls?: Cls;
  readonly href?: string;
  readonly type?: string;
  readonly attr?: Record<string, string | number | boolean | null>;
}

// Obsidian's additions to HTMLElement (installed once, on happy-dom's prototype).
const proto = HTMLElement.prototype as HTMLElement & Record<string, unknown>;
if (typeof proto.createEl !== "function") {
  proto.createEl = function (this: HTMLElement, tag: string, o?: ElOptions | string, cb?: (el: HTMLElement) => void) {
    const el = document.createElement(tag);
    const opts: ElOptions = typeof o === "string" ? { cls: o } : (o ?? {});
    if (opts.cls !== undefined) el.className = Array.isArray(opts.cls) ? opts.cls.join(" ") : opts.cls;
    if (opts.text !== undefined) el.textContent = opts.text;
    if (opts.href !== undefined) el.setAttribute("href", opts.href);
    if (opts.type !== undefined) el.setAttribute("type", opts.type);
    for (const [k, v] of Object.entries(opts.attr ?? {})) if (v !== null && v !== false) el.setAttribute(k, String(v));
    this.appendChild(el);
    cb?.(el);
    return el;
  } as never;
  proto.createDiv = function (this: HTMLElement, o?: ElOptions | string, cb?: (el: HTMLElement) => void) {
    return this.createEl("div", o, cb as never);
  } as never;
  proto.createSpan = function (this: HTMLElement, o?: ElOptions | string, cb?: (el: HTMLElement) => void) {
    return this.createEl("span", o, cb as never);
  } as never;
  proto.empty = function (this: HTMLElement) {
    while (this.firstChild) this.removeChild(this.firstChild);
  };
  proto.setText = function (this: HTMLElement, text: string) {
    this.textContent = text;
  };
  proto.appendText = function (this: HTMLElement, text: string) {
    this.appendChild(document.createTextNode(text));
  };
  proto.addClass = function (this: HTMLElement, ...cls: string[]) {
    this.classList.add(...cls);
  };
  proto.removeClass = function (this: HTMLElement, ...cls: string[]) {
    this.classList.remove(...cls);
  };
  proto.toggleClass = function (this: HTMLElement, cls: string, on: boolean) {
    this.classList.toggle(cls, on);
  };
  proto.hasClass = function (this: HTMLElement, cls: string) {
    return this.classList.contains(cls);
  };
  proto.setAttr = function (this: HTMLElement, name: string, value: string | number | boolean | null) {
    if (value === null || value === false) this.removeAttribute(name);
    else this.setAttribute(name, String(value));
  };
}

export const Platform = { isDesktopApp: false };
/** The desktop adapter, as far as main.ts reads it directly: files and folders by vault path, and the vault folder's absolute path. */
export class FileSystemAdapter {
  readonly files = new Map<string, string>();
  readonly folders = new Set<string>();
  constructor(public basePath = "/Users/ana/Notes") {}
  getFullPath(p: string): string {
    return p;
  }
  getBasePath(): string {
    return this.basePath;
  }
  async exists(p: string): Promise<boolean> {
    return this.files.has(p) || this.folders.has(p);
  }
  async read(p: string): Promise<string> {
    const text = this.files.get(p);
    if (text === undefined) throw new Error(`ENOENT: ${p}`);
    return text;
  }
}
export class TFile {}

export function setIcon(el: HTMLElement, icon: string): void {
  el.setAttribute("data-icon", icon);
}

export class Notice {
  static readonly shown: string[] = [];
  readonly messageEl: HTMLElement = document.createElement("div");
  constructor(message: string, _duration?: number) {
    Notice.shown.push(message);
    this.messageEl.textContent = message;
  }
  hide(): void {}
}

class ButtonComponent {
  readonly buttonEl: HTMLButtonElement;
  constructor(containerEl: HTMLElement) {
    this.buttonEl = containerEl.createEl("button");
  }
  setButtonText(text: string) {
    this.buttonEl.textContent = text;
    return this;
  }
  setCta() {
    this.buttonEl.classList.add("mod-cta");
    return this;
  }
  setWarning() {
    this.buttonEl.classList.add("mod-warning");
    return this;
  }
  setDisabled(disabled: boolean) {
    this.buttonEl.disabled = disabled;
    return this;
  }
  setIcon(icon: string) {
    setIcon(this.buttonEl, icon);
    return this;
  }
  onClick(cb: (evt: MouseEvent) => unknown) {
    this.buttonEl.addEventListener("click", (e) => void cb(e as MouseEvent));
    return this;
  }
}

class TextComponent {
  readonly inputEl: HTMLInputElement;
  constructor(containerEl: HTMLElement) {
    this.inputEl = containerEl.createEl("input", { type: "text" });
  }
  setValue(value: string) {
    this.inputEl.value = value;
    return this;
  }
  getValue() {
    return this.inputEl.value;
  }
  setPlaceholder(p: string) {
    this.inputEl.placeholder = p;
    return this;
  }
  setDisabled(disabled: boolean) {
    this.inputEl.disabled = disabled;
    return this;
  }
  onChange(cb: (value: string) => unknown) {
    this.inputEl.addEventListener("input", () => void cb(this.inputEl.value));
    return this;
  }
}

export class Setting {
  readonly settingEl: HTMLElement;
  readonly nameEl: HTMLElement;
  readonly descEl: HTMLElement;
  readonly controlEl: HTMLElement;
  constructor(containerEl: HTMLElement) {
    this.settingEl = containerEl.createDiv("setting-item");
    const info = this.settingEl.createDiv("setting-item-info");
    this.nameEl = info.createDiv("setting-item-name");
    this.descEl = info.createDiv("setting-item-description");
    this.controlEl = this.settingEl.createDiv("setting-item-control");
  }
  setName(name: string) {
    this.nameEl.textContent = name;
    return this;
  }
  setDesc(desc: string) {
    this.descEl.textContent = desc;
    return this;
  }
  setHeading() {
    this.settingEl.classList.add("setting-item-heading");
    return this;
  }
  setClass(cls: string) {
    this.settingEl.classList.add(cls);
    return this;
  }
  addButton(cb: (b: ButtonComponent) => unknown) {
    cb(new ButtonComponent(this.controlEl));
    return this;
  }
  addText(cb: (t: TextComponent) => unknown) {
    cb(new TextComponent(this.controlEl));
    return this;
  }
}

export class Modal {
  static readonly opened: Modal[] = [];
  readonly contentEl: HTMLElement = document.createElement("div");
  title = "";
  constructor(readonly app: App) {}
  setTitle(title: string) {
    this.title = title;
    return this;
  }
  open(): void {
    Modal.opened.push(this);
    this.onOpen();
  }
  close(): void {
    this.onClose();
  }
  onOpen(): void {}
  onClose(): void {}
}

export class PluginSettingTab {
  readonly containerEl: HTMLElement = document.createElement("div");
  constructor(
    readonly app: App,
    readonly plugin: Plugin,
  ) {}
  display(): void {}
}

export class ItemView {
  readonly app: App;
  readonly containerEl: HTMLElement = document.createElement("div");
  readonly contentEl: HTMLElement;
  private readonly cleanups: (() => void)[] = [];
  constructor(readonly leaf: WorkspaceLeaf) {
    this.app = leaf.workspace.app;
    this.containerEl.createDiv("view-header");
    this.contentEl = this.containerEl.createDiv("view-content");
  }
  register(cb: () => void): void {
    this.cleanups.push(cb);
  }
  async onOpen(): Promise<void> {}
  async onClose(): Promise<void> {}
  /** The fake's own: what Obsidian does when the leaf is closed. */
  async close(): Promise<void> {
    await this.onClose();
    for (const c of this.cleanups.splice(0)) c();
  }
}

export class WorkspaceLeaf {
  view: ItemView | null = null;
  constructor(readonly workspace: Workspace) {}
  async setViewState(state: { type: string; active?: boolean }): Promise<void> {
    const factory = this.workspace.factories.get(state.type);
    if (factory === undefined) throw new Error(`no view registered for ${state.type}`);
    this.view = factory(this);
    (this.view as { viewType?: string }).viewType = state.type;
    this.workspace.leaves.push(this);
    await this.view.onOpen();
  }
}

export class Workspace {
  readonly factories = new Map<string, (leaf: WorkspaceLeaf) => ItemView>();
  readonly leaves: WorkspaceLeaf[] = [];
  readonly revealed: WorkspaceLeaf[] = [];
  readonly rightLeaves: WorkspaceLeaf[] = [];
  private ready: (() => void)[] = [];
  constructor(readonly app: App) {}
  onLayoutReady(cb: () => void): void {
    this.ready.push(cb);
  }
  /** The fake's own: the layout is ready. */
  layoutReady(): void {
    for (const cb of this.ready.splice(0)) cb();
  }
  getLeavesOfType(type: string): WorkspaceLeaf[] {
    return this.leaves.filter((l) => (l.view as { viewType?: string } | null)?.viewType === type);
  }
  getRightLeaf(_split: boolean): WorkspaceLeaf {
    const leaf = new WorkspaceLeaf(this);
    this.rightLeaves.push(leaf);
    return leaf;
  }
  async revealLeaf(leaf: WorkspaceLeaf): Promise<void> {
    this.revealed.push(leaf);
  }
}

export class App {
  /** The vault's id (Obsidian's `app.appId`): the `vault` of an `obsidian://` URI. */
  appId = "a1b2c3d4e5f60718";
  readonly workspace: Workspace = new Workspace(this);
  readonly local = new Map<string, unknown>();
  readonly vault = {
    adapter: new FileSystemAdapter(),
    configDir: ".obsidian",
    on: () => ({}),
    getName: () => "Test vault",
    getAbstractFileByPath: () => null,
  };
  loadLocalStorage(key: string): unknown {
    return this.local.get(key) ?? null;
  }
  saveLocalStorage(key: string, value: unknown): void {
    this.local.set(key, value);
  }
}

export class Plugin {
  readonly ribbon: { icon: string; title: string; el: HTMLElement }[] = [];
  readonly commands: { id: string; name: string; callback: () => unknown }[] = [];
  readonly statusBar: HTMLElement[] = [];
  data: unknown = null;
  constructor(
    readonly app: App,
    readonly manifest: unknown,
  ) {}
  addRibbonIcon(icon: string, title: string, callback: (evt: MouseEvent) => unknown): HTMLElement {
    const el = document.createElement("div");
    el.addEventListener("click", (e) => void callback(e as MouseEvent));
    this.ribbon.push({ icon, title, el });
    return el;
  }
  registerView(type: string, factory: (leaf: WorkspaceLeaf) => ItemView): void {
    this.app.workspace.factories.set(type, factory);
  }
  addCommand(c: { id: string; name: string; callback: () => unknown }) {
    this.commands.push(c);
    return c;
  }
  addStatusBarItem(): HTMLElement {
    const el = document.createElement("div");
    this.statusBar.push(el);
    return el;
  }
  addSettingTab(_tab: PluginSettingTab): void {}
  /** `obsidian://<action>?…` handlers, by action (Obsidian passes the query as a record, plus `action`). */
  readonly protocolHandlers = new Map<string, (params: Record<string, string>) => unknown>();
  registerObsidianProtocolHandler(action: string, handler: (params: Record<string, string>) => unknown): void {
    this.protocolHandlers.set(action, handler);
  }
  registerEvent(_ref: unknown): void {}
  registerInterval(id: number): number {
    return id;
  }
  registerDomEvent(el: EventTarget, type: string, cb: (e: Event) => unknown): void {
    el.addEventListener(type, cb);
  }
  async loadData(): Promise<unknown> {
    return this.data;
  }
  async saveData(data: unknown): Promise<void> {
    this.data = data;
  }
}
