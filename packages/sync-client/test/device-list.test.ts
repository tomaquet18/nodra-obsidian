import { REGISTRY_RECIPIENT, encodeRecord } from "@nodra/encoding/records";
import type * as P from "@nodra/protocol";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { type Device, browserDeviceLabel, pluginDeviceLabel, withServerActivity } from "../src/index.js";

// §19 + §29: the device list is the signed registry's; the server's activity report only adds
// `activity` beside it. And every label a client builds is one the registry can carry (NCE, §23.2).

type Listed = Omit<Device, "activity">;

const id = (n: number) => `0190a1b2-0000-7000-8000-${n.toString(16).padStart(12, "0")}`;
const listed: Listed[] = [
  { recipientId: id(1), type: "TRUSTED_BROWSER", label: "Chrome on Windows", status: "ACTIVE", thisDevice: true },
  { recipientId: id(2), type: "PLUGIN_INSTALLATION", label: "Obsidian on macOS · Notes", status: "ACTIVE", thisDevice: false },
  { recipientId: id(3), type: "TRUSTED_BROWSER", label: "Web browser", status: "REVOKED", thisDevice: false },
];

describe("withServerActivity: the server's report beside the signed list, never over it", () => {
  it("joins by recipient id (any case); a device the report omits has no activity", () => {
    const out = withServerActivity(listed, [
      { recipientId: id(2).toUpperCase(), lastActiveAt: 3_600_000, browser: "Obsidian", os: "macOS" },
      { recipientId: id(3), lastActiveAt: 7_200_000, browser: null, os: "Linux" },
    ]);
    expect(out.map((d) => [d.label, d.activity])).toEqual([
      ["Chrome on Windows", null],
      ["Obsidian on macOS · Notes", { lastActiveAt: 3_600_000, client: "Obsidian on macOS" }],
      ["Web browser", { lastActiveAt: 7_200_000, client: "Linux" }],
    ]);
  });

  it("a server reporting another name, a device the registry lacks, or two rows for one device changes nothing of the list", () => {
    const lying: P.DeviceActivityRow[] = [
      // A row cannot carry a label; even an object that tries is read for its activity only.
      { recipientId: id(1), lastActiveAt: 1, browser: "Chrome", os: "Windows", label: "Trusted, keep it", status: "ACTIVE" } as P.DeviceActivityRow,
      { recipientId: id(1), lastActiveAt: 2, browser: "Safari", os: "iPhone" },
      { recipientId: id(99), lastActiveAt: 3, browser: "Firefox", os: "Linux" },
    ];
    const out = withServerActivity(listed, lying);
    expect(out.map(({ activity: _, ...d }) => d)).toEqual(listed);
    expect(out[0]!.activity).toEqual({ lastActiveAt: 1, client: "Chrome on Windows" });
  });

  const row = fc.record({
    recipientId: fc.integer({ min: 1, max: 6 }).map(id),
    lastActiveAt: fc.nat(),
    browser: fc.constantFrom("Chrome", "Firefox", null),
    os: fc.constantFrom("Windows", null),
  }) as fc.Arbitrary<P.DeviceActivityRow>;
  /** The property: same devices, same order, same signed fields, whatever the server reports. */
  const keepsTheList = (merge: typeof withServerActivity) =>
    fc.check(
      fc.property(fc.array(row, { maxLength: 8 }), (reported) => {
        const out = merge(listed, reported);
        return JSON.stringify(out.map(({ activity: _, ...d }) => d)) === JSON.stringify(listed);
      }),
    );

  it("for any report, the list is exactly the registry's (property)", () => {
    expect(keepsTheList(withServerActivity).failed).toBe(false);
  });

  it("the property above can fail: a merge that lists what the server reports is caught", () => {
    const trusting: typeof withServerActivity = (devices, reported) => [
      ...withServerActivity(devices, reported),
      ...reported
        .filter((r) => !devices.some((d) => d.recipientId === r.recipientId))
        .map((r) => ({ recipientId: r.recipientId, type: "TRUSTED_BROWSER" as const, label: "Reported", status: "ACTIVE" as const, thisDevice: false, activity: null })),
    ];
    expect(keepsTheList(trusting).failed).toBe(true);
  });
});

describe("every label a client builds is one the signed registry can carry (§23.2 NCE)", () => {
  const encodes = (label: string) =>
    encodeRecord(REGISTRY_RECIPIENT, { recipient_id: new Uint8Array(16), type: "PLUGIN_INSTALLATION", public_key: new Uint8Array(1), label, status: "ACTIVE", added_version: 1, revoked_version: null });

  it("a vault named on macOS (decomposed), with control characters or a lone surrogate, still makes a label NCE accepts", () => {
    for (const name of ["Café", "a\u0000b", "x\ud800", "😀".repeat(100), "é".repeat(200)]) {
      expect(() => encodes(pluginDeviceLabel("macOS", name)), name).not.toThrow();
    }
    expect(() => encodes(browserDeviceLabel({ userAgent: "Mozilla/5.0 (Windows NT 10.0) Chrome/1.0" }))).not.toThrow();
  });

  it("the check above can fail: the label as it was built before (`Obsidian: <name>`) is refused for a decomposed name", () => {
    expect(() => encodes(`Obsidian: ${"Café"}`)).toThrow(/NFC/);
  });
});
