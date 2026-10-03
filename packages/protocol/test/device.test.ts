import { describe, expect, it } from "vitest";
import {
  BROWSER_FAMILIES,
  DEVICE_LABEL_MAX,
  OS_FAMILIES,
  RootStateResponse,
  browserClientFamily,
  browserDeviceLabel,
  clientFamilyFromUserAgent,
  clientFamilyText,
  fitDeviceLabel,
  pluginDeviceLabel,
} from "../src/index.js";

// §29 `label` (what a device calls itself when it enrolls) and §19's server-reported client family:
// families only — never a version, a build, a model or the raw User-Agent.

const UA = {
  chromeWindows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
  edgeWindows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.2792.79",
  operaWindows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0",
  firefoxLinux: "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
  firefoxUbuntu: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
  chromiumLinux: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chromium/120.0.0.0 Chrome/120.0.0.0 Safari/537.36",
  safariMac: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
  safariIphone: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
  chromeIphone: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/129.0.6668.69 Mobile/15E148 Safari/604.1",
  edgeIphone: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 EdgiOS/129.0.2792.84 Mobile/15E148 Safari/605.1.15",
  firefoxIpad: "Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/131.0 Mobile/15E148 Safari/605.1.15",
  webviewIphone: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
  chromeAndroid: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
  edgeAndroid: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36 EdgA/129.0.2792.84",
  samsungAndroid: "Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36",
  firefoxAndroid: "Mozilla/5.0 (Android 14; Mobile; rv:131.0) Gecko/131.0 Firefox/131.0",
  chromeOs: "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
  obsidianMac: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) obsidian/1.7.4 Chrome/128.0.6613.186 Electron/32.2.5 Safari/537.36",
  obsidianWindows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) obsidian/1.8.10 Chrome/132.0.6834.196 Electron/34.3.0 Safari/537.36",
} as const;

describe("clientFamilyFromUserAgent: browser and OS families, nothing else", () => {
  it.each([
    [UA.chromeWindows, "Chrome", "Windows"],
    [UA.edgeWindows, "Edge", "Windows"],
    [UA.operaWindows, "Opera", "Windows"],
    [UA.firefoxLinux, "Firefox", "Linux"],
    [UA.firefoxUbuntu, "Firefox", "Linux"],
    [UA.chromiumLinux, "Chromium", "Linux"],
    [UA.safariMac, "Safari", "macOS"],
    [UA.safariIphone, "Safari", "iPhone"],
    [UA.chromeIphone, "Chrome", "iPhone"],
    [UA.edgeIphone, "Edge", "iPhone"],
    [UA.firefoxIpad, "Firefox", "iPad"],
    [UA.webviewIphone, null, "iPhone"],
    [UA.chromeAndroid, "Chrome", "Android"],
    [UA.edgeAndroid, "Edge", "Android"],
    [UA.samsungAndroid, "Samsung Internet", "Android"],
    [UA.firefoxAndroid, "Firefox", "Android"],
    [UA.chromeOs, "Chrome", "ChromeOS"],
    [UA.obsidianMac, "Obsidian", "macOS"],
    [UA.obsidianWindows, "Obsidian", "Windows"],
  ])("%s → %s on %s", (ua, browser, os) => {
    expect(clientFamilyFromUserAgent(ua)).toEqual({ browser, os });
  });

  it.each([
    ["absent", undefined],
    ["null", null],
    ["empty", ""],
    ["curl", "curl/8.4.0"],
    ["Node's fetch", "node"],
    ["Node's navigator", "Node.js/22"],
    ["a crawler", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"],
    ["garbage", "\u0000￿<script>alert(1)</script>"],
  ])("an odd User-Agent (%s) gives no family at all", (_what, ua) => {
    expect(clientFamilyFromUserAgent(ua)).toEqual({ browser: null, os: null });
  });

  it("a very long User-Agent is read only up to a bound, and still never answers more than families", () => {
    expect(clientFamilyFromUserAgent(`${UA.chromeWindows}${"x".repeat(100_000)}`)).toEqual({ browser: "Chrome", os: "Windows" });
    expect(clientFamilyFromUserAgent(`${"x".repeat(100_000)}${UA.chromeWindows}`)).toEqual({ browser: null, os: null });
  });

  it("whatever the input, every answer is a member of the two closed lists (no version, no model, no raw text)", () => {
    let seed = 42;
    const next = () => (seed = (seed * 1_103_515_245 + 12_345) % 2 ** 31);
    const pieces = [...Object.values(UA), "Windows", "Mac OS X", "Android 14", "iPhone", "CrOS", "Firefox/1", "Chrome/1", "Version/1 Safari/1", "Edg/1", "OPR/1", "SAMSUNG", "x86_64", "; ", " ", "(", ")"];
    for (let i = 0; i < 2_000; i++) {
      const ua = Array.from({ length: next() % 6 }, () => pieces[next() % pieces.length]).join("");
      const { browser, os } = clientFamilyFromUserAgent(ua);
      expect(browser === null || (BROWSER_FAMILIES as readonly string[]).includes(browser), ua).toBe(true);
      expect(os === null || (OS_FAMILIES as readonly string[]).includes(os), ua).toBe(true);
      const text = clientFamilyText({ browser, os });
      expect(text === null || /^[A-Za-z ]{1,48}$/.test(text), ua).toBe(true);
    }
  });
});

describe("browserClientFamily: User-Agent Client Hints first, the User-Agent as the fallback", () => {
  it("brands and platform win over a frozen or misleading User-Agent", () => {
    const nav = {
      userAgent: UA.chromeWindows,
      userAgentData: { brands: [{ brand: "Not)A;Brand" }, { brand: "Microsoft Edge" }, { brand: "Chromium" }], platform: "Linux" },
    };
    expect(browserClientFamily(nav)).toEqual({ browser: "Edge", os: "Linux" });
  });

  it.each([
    [[{ brand: "Google Chrome" }, { brand: "Chromium" }, { brand: "Not=A?Brand" }], "Chrome"],
    [[{ brand: "Brave" }, { brand: "Chromium" }, { brand: "Not_A Brand" }], "Brave"],
    [[{ brand: "Opera" }, { brand: "Chromium" }], "Opera"],
    [[{ brand: "Chromium" }, { brand: "Not_A Brand" }], "Chromium"],
  ])("brands %j → %s", (brands, browser) => {
    expect(browserClientFamily({ userAgentData: { brands, platform: "macOS" } })).toEqual({ browser, os: "macOS" });
  });

  it("an unknown brand list or platform falls back to the User-Agent, piece by piece", () => {
    expect(browserClientFamily({ userAgent: UA.firefoxLinux, userAgentData: { brands: [], platform: "" } })).toEqual({ browser: "Firefox", os: "Linux" });
    expect(browserClientFamily({ userAgent: UA.safariMac, userAgentData: { brands: [{ brand: "Something New" }], platform: "Chrome OS" } })).toEqual({ browser: "Safari", os: "ChromeOS" });
  });

  it("no navigator at all is no family", () => {
    expect(browserClientFamily(undefined)).toEqual({ browser: null, os: null });
  });
});

describe("the label a browser enrolls with (§29)", () => {
  it.each([
    [{ userAgent: UA.chromeWindows }, "Chrome on Windows"],
    [{ userAgent: UA.safariIphone }, "Safari on iPhone"],
    [{ userAgent: UA.firefoxLinux }, "Firefox on Linux"],
    [{ userAgent: UA.webviewIphone }, "Browser on iPhone"],
    [{ userAgent: "Mozilla/5.0 (Unknown) Firefox/131.0" }, "Firefox"],
    [{ userAgent: "Node.js/22" }, "Web browser"],
    [{}, "Web browser"],
    [undefined, "Web browser"],
  ])("%j → %s", (nav, label) => {
    expect(browserDeviceLabel(nav)).toBe(label);
  });
});

describe("the label the Obsidian plugin enrolls with (§29): the OS family and the vault's name", () => {
  it.each([
    ["macOS", "Notes", "Obsidian on macOS · Notes"],
    ["Windows", "Work", "Obsidian on Windows · Work"],
    [null, "Notes", "Obsidian · Notes"],
    ["Linux", "", "Obsidian on Linux"],
    ["Android", "   ", "Obsidian on Android"],
    [null, "", "Obsidian"],
  ] as const)("%s, %j → %s", (os, vault, label) => {
    expect(pluginDeviceLabel(os, vault)).toBe(label);
  });

  it("a long vault name is cut with an ellipsis, the prefix kept whole, within DEVICE_LABEL_MAX code points", () => {
    const label = pluginDeviceLabel("Windows", "A".repeat(500));
    expect([...label]).toHaveLength(DEVICE_LABEL_MAX);
    expect(label.startsWith("Obsidian on Windows · AAAA")).toBe(true);
    expect(label.endsWith("…")).toBe(true);
    // Emoji are counted as code points and never split into lone surrogates.
    const emoji = pluginDeviceLabel("macOS", "😀".repeat(200));
    expect([...emoji].length).toBeLessThanOrEqual(DEVICE_LABEL_MAX);
    expect(() => encodeURIComponent(emoji)).not.toThrow(); // throws on a lone surrogate
  });

  it("the vault name is normalized: NFC (a macOS name arrives decomposed), no control characters, collapsed spaces", () => {
    expect(pluginDeviceLabel("macOS", "Café")).toBe("Obsidian on macOS · Café");
    expect(pluginDeviceLabel("macOS", " a\nb\t\tc\u0000 ")).toBe("Obsidian on macOS · a b c");
    expect(pluginDeviceLabel("macOS", "x\ud800y")).toBe("Obsidian on macOS · x�y");
  });
});

describe("fitDeviceLabel: the constraints every label satisfies", () => {
  it("NFC, well-formed, no control characters, at most DEVICE_LABEL_MAX code points, never empty", () => {
    for (const raw of ["", " ", "\u0000", "é".repeat(100), "😀".repeat(100), "\ud800".repeat(3), `${"ab ".repeat(40)}`]) {
      const label = fitDeviceLabel(raw);
      expect(label.length).toBeGreaterThan(0);
      expect(label).toBe(label.normalize("NFC"));
      expect(() => encodeURIComponent(label)).not.toThrow();
      expect(/\p{Cc}/u.test(label)).toBe(false);
      expect([...label].length).toBeLessThanOrEqual(DEVICE_LABEL_MAX);
    }
  });

  it("the check above can fail: an unfitted name breaks two of its rules", () => {
    const raw = "é\u0000".repeat(100);
    expect(raw === raw.normalize("NFC") && [...raw].length <= DEVICE_LABEL_MAX).toBe(false);
  });
});

describe("§22 getRootState's deviceActivity: what a client accepts from the server", () => {
  const base = {
    kind: "ROOT_STATE",
    accountState: "ACTIVE",
    maxBlobBytes: 1,
    quotaBytes: 1,
    pendingBudgetBytes: 1,
    forDeletePendingBytes: 1,
    deleteManifestAllowance: 1,
    maxVaults: null,
    profile: null,
    configBlob: null,
    configVersion: null,
    vaults: [],
    escrowKey: { keyId: "ab".repeat(16), spki: "ab" },
  };
  const recipientId = "0190a1b2-0000-7000-8000-000000000001";

  it("absent (an older server) reads as no activity", () => {
    expect(RootStateResponse.parse(base).deviceActivity).toEqual([]);
  });

  it("families outside the closed lists read as unknown, never as text to show", () => {
    const parsed = RootStateResponse.parse({ ...base, deviceActivity: [{ recipientId, lastActiveAt: 3_600_000, browser: "Chrome 129 (build 6668)", os: "Revoked — click here" }] });
    expect(parsed.deviceActivity).toEqual([{ recipientId, lastActiveAt: 3_600_000, browser: null, os: null }]);
  });

  it("a malformed list costs the activity only, never the whole getRootState", () => {
    const parsed = RootStateResponse.parse({ ...base, deviceActivity: [{ recipientId: "not an id", lastActiveAt: -1 }] });
    expect(parsed.deviceActivity).toEqual([]);
    expect(parsed.accountState).toBe("ACTIVE");
  });
});
