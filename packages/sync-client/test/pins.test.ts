import { describe, expect, it } from "vitest";
import { type AccountPins, laterPins } from "../src/trust.js";

// §26 "continuidad de pins" / §28.3: the account pins of an installation only move forward.

const pins = (configVersion: number): AccountPins => ({
  rootGeneration: 1,
  rootHash: "aa",
  genesisRootHash: "aa",
  registryVersion: configVersion,
  registryHash: `r${configVersion}`,
  configVersion,
});

describe("laterPins", () => {
  it("keeps the pins with the higher config_version, whichever side they are on", () => {
    expect(laterPins(pins(3), pins(5))).toEqual(pins(5));
    expect(laterPins(pins(5), pins(3))).toEqual(pins(5));
  });
  it("the first proof pins; nothing proved leaves the held pins", () => {
    expect(laterPins(undefined, pins(2))).toEqual(pins(2));
    expect(laterPins(pins(2), undefined)).toEqual(pins(2));
    expect(laterPins(undefined, undefined)).toBeUndefined();
  });
});
