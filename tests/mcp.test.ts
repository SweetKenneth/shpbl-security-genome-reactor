import test from "node:test";
import assert from "node:assert/strict";
import { inferPhenotypes, seedGenomes } from "../src";
test("public reactor output is JSON serializable", () => { const p = inferPhenotypes([{ hostId:"a", findings:[{signature:"x",severity:5}], complianceFailed:0, complianceTotal:1 }])[0]!; assert.equal(JSON.parse(JSON.stringify(seedGenomes(p))).length,3); });
