// What a device is called, by itself and by the server.
//
//   * The **label** (§29 `RegistryRecipient.label`) is chosen by the client when it enrolls and signed
//     into the registry, so it is authoritative: "Chrome on Windows", "Obsidian on macOS · Notes". It
//     names families only — never a version, a build or a model — and fits the bounds of
//     {@link fitDeviceLabel}. A label already in the registry never changes (§29 bullet 2).
//   * The **client family** is what the Worker parses from the User-Agent of the request that last
//     used a device's access (§19): the same two closed lists, never the raw header. It is unsigned and
//     the client shows it as "reported by the server", beside the label and never in its place.
//
// Both sides share these lists so the server can only ever report one of their members.

export const BROWSER_FAMILIES = ["Chrome", "Chromium", "Edge", "Firefox", "Safari", "Opera", "Samsung Internet", "Brave", "Obsidian"] as const;
export type BrowserFamily = (typeof BROWSER_FAMILIES)[number];

export const OS_FAMILIES = ["Windows", "macOS", "Linux", "ChromeOS", "Android", "iPhone", "iPad"] as const;
export type OsFamily = (typeof OS_FAMILIES)[number];

export interface ClientFamily {
  readonly browser: BrowserFamily | null;
  readonly os: OsFamily | null;
}

/** How much of a User-Agent is read: a real one is a few hundred characters. */
const MAX_UA = 512;

// First match wins, so the more specific token goes first: Edge, Opera, Samsung and Obsidian also say
// "Chrome", Chromium also says "Chrome", and almost every browser says "Safari".
const BROWSER_RULES: readonly (readonly [RegExp, BrowserFamily])[] = [
  [/\bobsidian\//i, "Obsidian"],
  [/\bEdg(?:e|A|iOS)?\//, "Edge"],
  [/\b(?:OPR|OPiOS)\/|\bOpera\b/, "Opera"],
  [/\bSamsungBrowser\//, "Samsung Internet"],
  [/\b(?:Firefox|FxiOS)\//, "Firefox"],
  [/\bChromium\//, "Chromium"],
  [/\b(?:Chrome|CriOS)\//, "Chrome"],
  [/\bVersion\/[\d.]+.*\bSafari\//, "Safari"],
];

// An iPhone says "like Mac OS X" and Android says "Linux", so both go before what they resemble.
const OS_RULES: readonly (readonly [RegExp, OsFamily])[] = [
  [/\biPhone\b/, "iPhone"],
  [/\biPad\b/, "iPad"],
  [/\bAndroid\b/, "Android"],
  [/\bCrOS\b/, "ChromeOS"],
  [/\bWindows\b/, "Windows"],
  [/\bMacintosh\b|\bMac OS X\b/, "macOS"],
  [/\bLinux\b|\bX11\b/, "Linux"],
];

const firstMatch = <T>(rules: readonly (readonly [RegExp, T])[], text: string): T | null => rules.find(([re]) => re.test(text))?.[1] ?? null;

/** The two families a User-Agent names, or null for each it does not. Never anything else from it. */
export function clientFamilyFromUserAgent(userAgent: string | null | undefined): ClientFamily {
  const ua = (userAgent ?? "").slice(0, MAX_UA);
  // A browser family needs the "Mozilla/5.0 (…)" shape every browser sends: "curl/8" or a bot is nobody's.
  if (!/^Mozilla\/5\.0 \(/.test(ua) || /bot\b|crawler|spider/i.test(ua)) return { browser: null, os: null };
  return { browser: firstMatch(BROWSER_RULES, ua), os: firstMatch(OS_RULES, ua) };
}

/** "Chrome on Windows", "Chrome", "Windows"; null when neither family is known. */
export function clientFamilyText(family: ClientFamily): string | null {
  if (family.browser !== null && family.os !== null) return `${family.browser} on ${family.os}`;
  return family.browser ?? family.os;
}

/** The part of `navigator` a browser's label is read from; every field may be missing. */
export interface NavigatorLike {
  readonly userAgent?: string;
  /** User-Agent Client Hints (Chromium): low-entropy values, no permission needed. */
  readonly userAgentData?: { readonly brands?: readonly { readonly brand: string }[]; readonly platform?: string } | undefined;
}

const BRANDS: Readonly<Record<string, BrowserFamily>> = {
  "Google Chrome": "Chrome",
  "Microsoft Edge": "Edge",
  Opera: "Opera",
  Brave: "Brave",
  "Samsung Internet": "Samsung Internet",
};

const PLATFORMS: Readonly<Record<string, OsFamily>> = {
  Windows: "Windows",
  macOS: "macOS",
  Linux: "Linux",
  "Chrome OS": "ChromeOS",
  "Chromium OS": "ChromeOS",
  ChromeOS: "ChromeOS",
  Android: "Android",
};

/** This browser's families: Client Hints where the browser has them, the User-Agent for the rest. */
export function browserClientFamily(nav: NavigatorLike | undefined): ClientFamily {
  const fromUa = clientFamilyFromUserAgent(nav?.userAgent);
  const brands = (nav?.userAgentData?.brands ?? []).map((b) => b.brand);
  const branded = brands.map((b) => BRANDS[b]).find((b) => b !== undefined) ?? (brands.includes("Chromium") ? "Chromium" : undefined);
  const platform = PLATFORMS[nav?.userAgentData?.platform ?? ""];
  return { browser: branded ?? fromUa.browser, os: platform ?? fromUa.os };
}

/** §29: the longest label a client writes, in code points. */
export const DEVICE_LABEL_MAX = 64;

const ELLIPSIS = "…";
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

/** Text a label can carry: well-formed, NFC (NCE refuses anything else, §23.2), one line, trimmed. */
function clean(text: string): string {
  return text.replace(LONE_SURROGATE, "�").normalize("NFC").replace(/\p{Cc}+/gu, " ").replace(/\s+/g, " ").trim();
}

/** `text` cut to `max` code points, with an ellipsis when it was longer. */
function cut(text: string, max: number): string {
  const points = [...text];
  if (points.length <= max) return text;
  return `${points.slice(0, Math.max(0, max - 1)).join("").trimEnd()}${ELLIPSIS}`.normalize("NFC");
}

/** Any text as a label: cleaned and within {@link DEVICE_LABEL_MAX}; "Device" when nothing is left. */
export function fitDeviceLabel(text: string): string {
  return cut(clean(text), DEVICE_LABEL_MAX) || "Device";
}

/** §35.2 / §35.4: a trusted browser's label. "Chrome on Windows"; "Web browser" when nothing is known. */
export function browserDeviceLabel(nav: NavigatorLike | undefined): string {
  const family = browserClientFamily(nav);
  if (family.browser === null) return family.os === null ? "Web browser" : `Browser on ${family.os}`;
  return fitDeviceLabel(clientFamilyText(family)!);
}

/** §35.4 for the plugin: "Obsidian on macOS · <vault name>", the name cut first when it is long. */
export function pluginDeviceLabel(os: OsFamily | null, vaultName: string): string {
  const prefix = os === null ? "Obsidian" : `Obsidian on ${os}`;
  const name = clean(vaultName);
  if (name === "") return prefix;
  const separator = " · ";
  return `${prefix}${separator}${cut(name, DEVICE_LABEL_MAX - [...prefix].length - [...separator].length)}`;
}
