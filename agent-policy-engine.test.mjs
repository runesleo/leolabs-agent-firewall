import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

import * as engine from "./agent-policy-engine.mjs";
import {
  ADD8,
  ADD8_GOLDEN_VECTORS,
  DEPLOY_WALLET,
  EXIT_CODES,
  FACTORY,
  PROCESSOR,
  RELEASE_SCENARIOS,
  SCENARIOS,
  SELECTORS,
  USDT,
  accumulateRisk,
  add8,
  add8Circuit,
  buildReceipt,
  buildVaultReleaseReceipt,
  canonicalJson,
  decodeNetlist,
  evaluateIntent,
  evaluateVaultRelease,
  hashCommitment,
  intentFromRequest,
  normalizeIntent,
  okbFromWei,
  runGoldenVectors,
  verifyOnchainNetlist,
} from "./agent-policy-engine.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, "agent-firewall-cli.mjs");

function runCli(args, input) {
  const proc = spawnSync(process.execPath, [CLI, ...args], { input, encoding: "utf8" });
  return { code: proc.status, stdout: proc.stdout, stderr: proc.stderr };
}

const word = (n) => BigInt(n).toString(16).padStart(64, "0");
const addrWord = (a) => a.slice(2).toLowerCase().padStart(64, "0");

// Minimal canonical ABI encoder (static + dynamic bytes/string) used to build test calldata.
function abiEncode(selector, types, values) {
  const head = [];
  const tail = [];
  let tailOffset = types.length * 32;
  types.forEach((type, i) => {
    const v = values[i];
    if (type === "bytes" || type === "string") {
      const bytes = type === "string" ? Buffer.from(v, "utf8") : Buffer.from(v.slice(2), "hex");
      const padded = bytes.toString("hex").padEnd(Math.ceil(bytes.length / 32) * 64, "0");
      head.push(word(tailOffset));
      tail.push(word(bytes.length) + padded);
      tailOffset += 32 + padded.length / 2;
    } else if (type === "address") {
      head.push(addrWord(v));
    } else if (type === "bool") {
      head.push(word(v ? 1 : 0));
    } else {
      head.push(word(v));
    }
  });
  return selector + head.join("") + tail.join("");
}

const CREATE_CPU_CALL = abiEncode(
  SELECTORS.createCPU,
  ["string", "string", "string", "uint256", "uint256"],
  ["LeoLabs Builder Desk", "LEOLABS", "Agent firewall processor", 10000n, 66000000000000n],
);

// --- ADD8 netlist -----------------------------------------------------------

test("embedded netlist matches the weapon-pack evidence byte for byte", () => {
  const pack = JSON.parse(readFileSync(join(HERE, "add8-weapon-pack.json"), "utf8"));
  assert.equal(ADD8.netlistHex, pack.circuit.netlist_hex);
  const bytes = Buffer.from(ADD8.netlistHex.slice(2), "hex");
  assert.equal(bytes.length, ADD8.netlistBytes);
  assert.equal(createHash("sha256").update(bytes).digest("hex"), ADD8.netlistSha256);
  assert.equal(ADD8.netlistSha256, pack.circuit.netlist_sha256);
});

test("netlist decodes to 122 NAND gates with forward-only wiring", () => {
  const gates = decodeNetlist(ADD8.netlistHex);
  assert.equal(gates.length, ADD8.nNand);
  gates.forEach((g, k) => {
    const out = 2 + ADD8.nIn + k;
    assert.ok(g.a < out && g.b < out, `gate ${k} must only read earlier signals`);
  });
  assert.equal(ADD8.outputSignals.at(-1), 2 + ADD8.nIn + ADD8.nNand - 1);
});

test("taped ADD8 netlist reproduces every golden vector", () => {
  const vectors = runGoldenVectors();
  assert.equal(vectors.length, ADD8_GOLDEN_VECTORS.length);
  assert.ok(vectors.every((v) => v.ok), JSON.stringify(vectors));
  assert.equal(add8Circuit(100, 50, 0).packed, 150);
});

test("netlist agrees with arithmetic across a dense sweep", () => {
  for (let a = 0; a < 256; a += 3) {
    for (let b = 0; b < 256; b += 11) {
      for (const cin of [0, 1]) {
        assert.equal(add8Circuit(a, b, cin).packed, add8(a, b, cin).packed, `${a}+${b}+${cin}`);
      }
    }
  }
});

test("ADD8-style risk accumulation saturates on carry and reports the netlist engine", () => {
  const result = accumulateRisk([96, 200]);
  assert.equal(result.score, 255);
  assert.equal(result.saturated, true);
  assert.equal(result.steps.at(-1).carry, 1);
  assert.equal(result.engine, "nand-netlist");
  assert.equal(result.gatesPerStep, 122);
});

// --- policy decisions -------------------------------------------------------

test("real ADD8 tapeout and NAND mint transactions are allowed", () => {
  for (const key of ["tapeoutReal", "mintNandReal"]) {
    const result = evaluateIntent(SCENARIOS[key]);
    assert.equal(result.decision, "ALLOW", key);
    assert.equal(result.riskScore, 0, key);
    assert.deepEqual(result.reasonCodes, [], key);
    assert.equal(result.exitCode, EXIT_CODES.ALLOW);
  }
  assert.equal(SCENARIOS.tapeoutReal.data.slice(0, 10), SELECTORS.tapeout);
  assert.equal(SCENARIOS.mintNandReal.data.slice(0, 10), SELECTORS.mintNand);
});

test("wrong chain is hard denied", () => {
  const result = evaluateIntent(SCENARIOS.wrongChain);
  assert.equal(result.decision, "DENY");
  assert.ok(result.reasonCodes.includes("CHAIN_MISMATCH"));
  assert.equal(result.exitCode, EXIT_CODES.DENY);
});

test("unlimited ERC-20 approval is hard denied, bounded approval to a known spender is review", () => {
  const unlimited = evaluateIntent(SCENARIOS.unlimitedApproval);
  assert.equal(unlimited.decision, "DENY");
  assert.ok(unlimited.reasonCodes.includes("UNLIMITED_APPROVAL"));

  const bounded = evaluateIntent(SCENARIOS.boundedApproval);
  assert.equal(bounded.decision, "REVIEW");
  assert.deepEqual(bounded.reasonCodes, ["TOKEN_APPROVAL"]);
  assert.equal(bounded.exitCode, EXIT_CODES.REVIEW);
});

test("approval to an untrusted spender is denied even when bounded", () => {
  const result = evaluateIntent({
    chainId: 196,
    to: USDT,
    valueOkb: 0,
    data: SELECTORS.approve + addrWord("0x000000000000000000000000000000000000dead") + word(1),
  });
  assert.equal(result.decision, "DENY");
  assert.ok(result.reasonCodes.includes("APPROVAL_UNTRUSTED_SPENDER"));
});

test("approve amount is decoded positionally, and trailing bytes are rejected", () => {
  const trailing = SCENARIOS.unlimitedApproval.data + "00".repeat(32);
  const result = evaluateIntent({ chainId: 196, to: USDT, valueOkb: 0, data: trailing });
  assert.equal(result.decision, "DENY");
  assert.ok(result.reasonCodes.includes("ABI_DECODE_FAILED"));
  assert.ok(!result.reasonCodes.includes("TOKEN_APPROVAL"));
});

test("token transfer to an untrusted recipient is denied; trusted recipient is review", () => {
  const drain = evaluateIntent(SCENARIOS.tokenDrain);
  assert.equal(drain.decision, "DENY");
  assert.ok(drain.reasonCodes.includes("TOKEN_TRANSFER_UNTRUSTED_RECIPIENT"));

  const toDeployWallet = evaluateIntent({
    chainId: 196,
    to: USDT,
    valueOkb: 0,
    data: SELECTORS.transfer + addrWord(DEPLOY_WALLET) + word(5),
  });
  assert.equal(toDeployWallet.decision, "REVIEW");
  assert.deepEqual(toDeployWallet.reasonCodes, ["TOKEN_TRANSFER"]);
});

test("setApprovalForAll(true) is hard denied", () => {
  const result = evaluateIntent({
    chainId: 196,
    to: "0x3333333333333333333333333333333333333333",
    valueOkb: 0,
    data: SELECTORS.setApprovalForAll + addrWord(PROCESSOR) + word(1),
  });
  assert.equal(result.decision, "DENY");
  assert.ok(result.reasonCodes.includes("SET_APPROVAL_FOR_ALL"));
});

test("known Processor call above value ceiling is denied", () => {
  const result = evaluateIntent({ chainId: 196, to: PROCESSOR, valueOkb: 0.08, data: SCENARIOS.tapeoutReal.data });
  assert.equal(result.decision, "DENY");
  assert.ok(result.reasonCodes.includes("VALUE_LIMIT_EXCEEDED"));
});

test("zero-value unknown target is review, not automatic allow", () => {
  const result = evaluateIntent({ chainId: 196, to: "0x2222222222222222222222222222222222222222", valueOkb: 0, data: "0x12345678" });
  assert.equal(result.decision, "REVIEW");
  assert.ok(result.reasonCodes.includes("UNKNOWN_TARGET"));
});

test("unexpected selector on known Processor is denied", () => {
  const result = evaluateIntent({ chainId: 196, to: PROCESSOR, valueOkb: 0, data: SELECTORS.transfer + addrWord(DEPLOY_WALLET) + word(1) });
  assert.equal(result.decision, "DENY");
  assert.ok(result.reasonCodes.includes("SELECTOR_NOT_ALLOWED"));
});

test("malformed inputs fail closed", () => {
  const badTarget = evaluateIntent({ chainId: 196, to: "0x1234", valueOkb: 0, data: "0x" });
  assert.equal(badTarget.decision, "DENY");
  assert.ok(badTarget.reasonCodes.includes("MALFORMED_TARGET"));

  const badData = evaluateIntent({ chainId: 196, to: PROCESSOR, valueOkb: 0, data: "0xzz" });
  assert.equal(badData.decision, "DENY");
  assert.ok(badData.reasonCodes.includes("MALFORMED_CALLDATA"));

  const badValue = evaluateIntent({ chainId: 196, to: PROCESSOR, valueWei: "-5", data: "0x" });
  assert.equal(badValue.decision, "DENY");
  assert.ok(badValue.reasonCodes.includes("MALFORMED_VALUE"));
});

test("custom policy overrides the allowlist and thresholds", () => {
  const strict = evaluateIntent(SCENARIOS.tapeoutReal, { knownTargets: {}, maxValueOkb: 0.001 });
  assert.equal(strict.decision, "DENY");
  assert.ok(strict.reasonCodes.includes("UNKNOWN_VALUE_TARGET"));
  assert.ok(strict.reasonCodes.includes("VALUE_LIMIT_EXCEEDED"));
});

// --- intent normalisation ---------------------------------------------------

test("value is accepted as OKB, decimal wei, hex wei, or EIP-1193 envelope", () => {
  const tapeoutFeeHex = `0x${(1300000000000000n).toString(16)}`;
  assert.equal(okbFromWei("1300000000000000"), 0.0013);
  assert.equal(normalizeIntent({ chainId: 196, to: PROCESSOR, valueWei: tapeoutFeeHex }).valueWei, 1300000000000000n);
  assert.equal(normalizeIntent({ chainId: 196, to: PROCESSOR, valueOkb: "0.0013" }).valueWei, 1300000000000000n);
  assert.equal(normalizeIntent({ chainId: 196, to: PROCESSOR, value: tapeoutFeeHex }).valueOkb, "0.0013");
  assert.equal(normalizeIntent({ chainId: "0xc4", to: PROCESSOR }).chainId, 196);
  const envelope = intentFromRequest({
    method: "eth_sendTransaction",
    params: [{ to: PROCESSOR, value: tapeoutFeeHex, data: SCENARIOS.tapeoutReal.data, chainId: "0xc4" }],
  });
  const result = evaluateIntent(envelope);
  assert.equal(result.decision, "ALLOW");
  const unsupported = evaluateIntent({ method: "eth_sign", params: [] });
  assert.equal(unsupported.decision, "DENY");
  assert.ok(unsupported.reasonCodes.includes("UNSUPPORTED_REQUEST_METHOD"));
});

// --- receipts ---------------------------------------------------------------

test("commitment serialization is deterministic across key order", () => {
  assert.equal(canonicalJson({ b: 2, a: { d: 4, c: 3 } }), canonicalJson({ a: { c: 3, d: 4 }, b: 2 }));
});

test("commitment hash is stable and the receipt nests the commitment", async () => {
  const first = evaluateIntent(SCENARIOS.tokenDrain);
  const second = evaluateIntent(SCENARIOS.tokenDrain);
  assert.equal(await hashCommitment(first.commitment), await hashCommitment(second.commitment));
  const receipt = await buildReceipt(first);
  assert.equal(receipt.schema, "leolabs_agent_firewall_receipt/v3");
  assert.equal(receipt.commitment.schema, "leolabs_agent_firewall_commitment/v3");
  assert.match(receipt.commitmentHash, /^0x[0-9a-f]{64}$/);
  assert.equal(receipt.commitment.circuit.netlistSha256, ADD8.netlistSha256);
  assert.equal(receipt.commitment.decision, "DENY");
  assert.deepEqual(receipt.metadata, {});
});

// --- on-chain verification (mocked fetch; no network in tests) --------------

function abiBytes(bytes) {
  const hex = Buffer.from(bytes).toString("hex");
  const padded = hex + "0".repeat((64 - (hex.length % 64)) % 64);
  return `0x${(32n).toString(16).padStart(64, "0")}${BigInt(bytes.length).toString(16).padStart(64, "0")}${padded}`;
}

function fakeFetch(resultHex) {
  return async () => ({ ok: true, json: async () => ({ jsonrpc: "2.0", id: 1, result: resultHex }) });
}

test("verifyOnchainNetlist reports MATCH for the taped bytes and MISMATCH otherwise", async () => {
  const real = Buffer.from(ADD8.netlistHex.slice(2), "hex");
  const match = await verifyOnchainNetlist({ rpcs: ["mock://a"], fetchImpl: fakeFetch(abiBytes(real)) });
  assert.equal(match.status, "MATCH");
  assert.equal(match.bytes, ADD8.netlistBytes);

  const tampered = Buffer.from(real);
  tampered[10] ^= 1;
  const mismatch = await verifyOnchainNetlist({ rpcs: ["mock://a"], fetchImpl: fakeFetch(abiBytes(tampered)) });
  assert.equal(mismatch.status, "MISMATCH");
});

test("verifyOnchainNetlist fails closed when no RPC answers", async () => {
  const failing = async () => { throw new Error("offline"); };
  const report = await verifyOnchainNetlist({ rpcs: ["mock://a", "mock://b"], fetchImpl: failing });
  assert.equal(report.status, "UNVERIFIED");
  assert.equal(report.errors.length, 2);
});

// --- CLI contract -----------------------------------------------------------

test("CLI exit codes follow the decision and --json emits exactly one JSON document", () => {
  const allow = runCli(["evaluate", "--scenario", "tapeoutReal", "--json"]);
  assert.equal(allow.code, EXIT_CODES.ALLOW);
  const allowDoc = JSON.parse(allow.stdout);
  assert.equal(allowDoc.commitment.decision, "ALLOW");
  assert.equal(allowDoc.schema, "leolabs_agent_firewall_receipt/v3");

  const review = runCli(["evaluate", "--scenario", "boundedApproval", "--json"]);
  assert.equal(review.code, EXIT_CODES.REVIEW);

  const deny = runCli(["evaluate", "--scenario", "tokenDrain"]);
  assert.equal(deny.code, EXIT_CODES.DENY);
  assert.match(deny.stdout, /^decision\s+DENY/m);

  const missing = runCli(["evaluate", "--scenario", "nope", "--json"]);
  assert.equal(missing.code, EXIT_CODES.ERROR);
  assert.equal(JSON.parse(missing.stdout).status, "ERROR");
});

test("CLI reads an intent from stdin or file, honours --policy, and writes --receipt", () => {
  const dir = mkdtempSync(join(tmpdir(), "agent-firewall-"));
  const intentPath = join(dir, "intent.json");
  const policyPath = join(dir, "policy.json");
  const receiptPath = join(dir, "receipt.json");
  writeFileSync(intentPath, JSON.stringify(SCENARIOS.tapeoutReal));
  writeFileSync(policyPath, JSON.stringify({ maxValueOkb: 0.0001 }));

  const viaStdin = runCli(["evaluate", "--json"], JSON.stringify(SCENARIOS.mintNandReal));
  assert.equal(viaStdin.code, EXIT_CODES.ALLOW);

  const viaFile = runCli(["evaluate", "--intent", intentPath, "--policy", policyPath, "--json", "--receipt", receiptPath]);
  assert.equal(viaFile.code, EXIT_CODES.DENY);
  const written = JSON.parse(readFileSync(receiptPath, "utf8"));
  assert.ok(written.commitment.reasonCodes.includes("VALUE_LIMIT_EXCEEDED"));
  assert.equal(written.commitmentHash, JSON.parse(viaFile.stdout).commitmentHash);
});

test("CLI selftest and scenarios succeed offline", () => {
  const selftest = JSON.parse(execFileSync(process.execPath, [CLI, "selftest", "--json"], { encoding: "utf8" }));
  assert.equal(selftest.status, "PASS");
  const scenarios = JSON.parse(execFileSync(process.execPath, [CLI, "scenarios", "--json"], { encoding: "utf8" }));
  assert.deepEqual(
    scenarios.map((s) => [s.key, s.decision]),
    [
      ["tapeoutReal", "ALLOW"],
      ["mintNandReal", "ALLOW"],
      ["boundedApproval", "REVIEW"],
      ["unlimitedApproval", "DENY"],
      ["tokenDrain", "DENY"],
      ["wrongChain", "DENY"],
      ["unknownValueTarget", "DENY"],
    ],
  );
});

// ===========================================================================
// Independent-review regressions (P1/P2). Each test reproduces a reported bypass.
// ===========================================================================

const ONE_OKB_HEX = "0xde0b6b3a7640000";

// --- P1-1: conflicting / imprecise value representations ---------------------

test("P1-1 EIP-1193 value cannot be shadowed by a non-standard valueOkb field", () => {
  const result = evaluateIntent({
    method: "eth_sendTransaction",
    params: [{ chainId: 196, to: PROCESSOR, valueOkb: 0, value: ONE_OKB_HEX, data: SCENARIOS.tapeoutReal.data }],
  });
  assert.equal(result.decision, "DENY");
  assert.ok(result.reasonCodes.includes("CONFLICTING_VALUE_FIELDS"), result.reasonCodes.join(","));
  assert.equal(result.exitCode, EXIT_CODES.DENY);
  assert.equal(result.commitment.intent.valueWei, null);
});

test("P1-1 plain intents with more than one value representation are denied", () => {
  for (const extra of [{ valueOkb: 0, valueWei: "1" }, { valueOkb: 0, value: ONE_OKB_HEX }, { valueWei: "0", value: ONE_OKB_HEX }]) {
    const result = evaluateIntent({ chainId: 196, to: PROCESSOR, data: SCENARIOS.tapeoutReal.data, ...extra });
    assert.equal(result.decision, "DENY", JSON.stringify(extra));
    assert.ok(result.reasonCodes.includes("CONFLICTING_VALUE_FIELDS"), JSON.stringify(extra));
  }
});

test("P1-1 value ceiling is compared in exact wei (no float rounding)", () => {
  const justOver = evaluateIntent({ chainId: 196, to: PROCESSOR, valueWei: "20000000000000001", data: SCENARIOS.tapeoutReal.data });
  assert.equal(justOver.decision, "DENY");
  assert.ok(justOver.reasonCodes.includes("VALUE_LIMIT_EXCEEDED"));
  assert.equal(justOver.commitment.intent.valueWei, "20000000000000001");

  const exactlyAt = evaluateIntent({ chainId: 196, to: PROCESSOR, valueWei: "20000000000000000", data: SCENARIOS.tapeoutReal.data });
  assert.equal(exactlyAt.decision, "ALLOW");
  assert.equal(exactlyAt.commitment.policy.maxValueWei, "20000000000000000");
});

test("P1-1 numeric or malformed `value` is rejected instead of being reinterpreted", () => {
  for (const value of [0.0013, "1300000000000000", "0xzz", -1]) {
    const result = evaluateIntent({ chainId: 196, to: PROCESSOR, value, data: "0x" });
    assert.equal(result.decision, "DENY", String(value));
    assert.ok(result.reasonCodes.includes("MALFORMED_VALUE"), String(value));
  }
  assert.throws(() => engine.parseWei("1.5"), /wei/);
  assert.throws(() => engine.parseOkbToWei("0.0000000000000000001"), /18/);
  assert.equal(engine.parseOkbToWei("0.02"), 20000000000000000n);
  assert.equal(engine.formatOkb(20000000000000001n), "0.020000000000000001");
});

// --- P1-2: empty selector allowlist must not mean "any method" ---------------

test("P1-2 factory only accepts createCPU; arbitrary calldata is denied", () => {
  const arbitrary = evaluateIntent({ chainId: 196, to: FACTORY, valueOkb: 0.01, data: "0xdeadbeef" });
  assert.equal(arbitrary.decision, "DENY");
  assert.ok(arbitrary.reasonCodes.includes("SELECTOR_NOT_ALLOWED"));

  const create = evaluateIntent({ chainId: 196, to: FACTORY, valueOkb: "0.0066", data: CREATE_CPU_CALL });
  assert.equal(create.decision, "ALLOW", create.reasonCodes.join(","));
  assert.equal(create.riskScore, 0);
});

test("P1-2 an empty selector list means value-only: any non-empty calldata is denied", () => {
  const target = "0x4444444444444444444444444444444444444444";
  const policy = { knownTargets: { [target]: { label: "value-only sink", selectors: [] } } };
  const call = evaluateIntent({ chainId: 196, to: target, valueOkb: 0.001, data: "0xdeadbeef" }, policy);
  assert.equal(call.decision, "DENY");
  assert.ok(call.reasonCodes.includes("SELECTOR_NOT_ALLOWED"));

  const plain = evaluateIntent({ chainId: 196, to: target, valueOkb: 0.001, data: "0x" }, policy);
  assert.equal(plain.decision, "ALLOW");
});

// --- P1-3: invalid policy must not fail open ---------------------------------

test("P1-3 invalid policy values are rejected before any evaluation", () => {
  const oneOkb = { chainId: 196, to: PROCESSOR, valueOkb: 1, data: SCENARIOS.tapeoutReal.data };
  const unknownZero = { chainId: 196, to: "0x2222222222222222222222222222222222222222", valueOkb: 0, data: "0x12345678" };
  const bad = [
    [oneOkb, { maxValueOkb: "not-a-number" }, /maxValueOkb/],
    [unknownZero, { reviewThreshold: "oops" }, /reviewThreshold/],
    [unknownZero, { denyThreshold: "oops" }, /denyThreshold/],
    [unknownZero, { reviewThreshold: 90, denyThreshold: 80 }, /reviewThreshold.*denyThreshold|denyThreshold.*reviewThreshold/],
    [unknownZero, { denyThreshold: 999 }, /denyThreshold/],
    [oneOkb, { maxValueOkb: -1 }, /maxValueOkb/],
    [oneOkb, { maxValueOkb: 0.02, maxValueWei: "1" }, /maxValueOkb.*maxValueWei|maxValueWei.*maxValueOkb/],
    [oneOkb, { maxValueOKB: 5 }, /unknown policy field/i],
    [oneOkb, { chainId: "196" }, /chainId/],
    [oneOkb, { knownTargets: { "0x1234": { label: "x", selectors: [] } } }, /knownTargets/],
    [oneOkb, { knownTargets: { [PROCESSOR]: { label: "x", selectors: ["0xzz"] } } }, /selector/],
    [oneOkb, { knownTargets: { [PROCESSOR]: { label: "", selectors: [] } } }, /label/],
    [oneOkb, { knownTargets: { [PROCESSOR]: { label: "x", selectors: [SELECTORS.tapeout], extra: 1 } } }, /knownTargets/],
    [oneOkb, { knownTargets: [] }, /knownTargets/],
    [oneOkb, { trustedRecipients: ["nope"] }, /trustedRecipients/],
    [oneOkb, { trustedRecipients: [DEPLOY_WALLET, DEPLOY_WALLET.toUpperCase().replace("0X", "0x")] }, /trustedRecipients/],
    [oneOkb, { name: "" }, /name/],
    [oneOkb, null, /policy/],
  ];
  for (const [intent, policy, pattern] of bad) {
    assert.throws(() => evaluateIntent(intent, policy), (error) => {
      assert.ok(error instanceof engine.PolicyError, `PolicyError expected for ${JSON.stringify(policy)}`);
      assert.match(error.message, pattern);
      return true;
    }, JSON.stringify(policy));
  }
});

test("P1-3 CLI refuses an invalid policy file with exit 1 and a JSON error", () => {
  const dir = mkdtempSync(join(tmpdir(), "agent-firewall-policy-"));
  const policyPath = join(dir, "policy.json");
  writeFileSync(policyPath, JSON.stringify({ maxValueOkb: "not-a-number" }));
  const run = runCli(["evaluate", "--scenario", "tapeoutReal", "--policy", policyPath, "--json"]);
  assert.equal(run.code, EXIT_CODES.ERROR);
  const doc = JSON.parse(run.stdout);
  assert.equal(doc.status, "ERROR");
  assert.equal(doc.code, "POLICY_INVALID");
  assert.equal(run.stderr, "");
});

// --- P2-1: raw schema and ABI validation -------------------------------------

test("P2-1 raw intent fields are validated before decoding", () => {
  const cases = [
    [{ chainId: 196, to: PROCESSOR, valueOkb: 0, data: 123 }, "MALFORMED_CALLDATA"],
    [{ chainId: 196, to: PROCESSOR, valueOkb: 0, data: "0x12" }, "MALFORMED_CALLDATA"],
    [{ chainId: 196, to: PROCESSOR, valueOkb: 0, data: "0x7bd3ac" }, "MALFORMED_CALLDATA"],
    [{ chainId: "0xc4junk", to: PROCESSOR, valueOkb: 0, data: "0x" }, "MALFORMED_CHAIN_ID"],
    [{ chainId: "196abc", to: PROCESSOR, valueOkb: 0, data: "0x" }, "MALFORMED_CHAIN_ID"],
    [{ chainId: 196.5, to: PROCESSOR, valueOkb: 0, data: "0x" }, "MALFORMED_CHAIN_ID"],
    [{ to: PROCESSOR, valueOkb: 0, data: "0x" }, "MALFORMED_CHAIN_ID"],
    [{ chainId: 196, to: PROCESSOR.toUpperCase(), valueOkb: 0, data: "0x" }, "MALFORMED_TARGET"],
    [{ chainId: 196, to: `${PROCESSOR}00`, valueOkb: 0, data: "0x" }, "MALFORMED_TARGET"],
    [{ chainId: 196, to: PROCESSOR, valueOkb: 0, data: "0x", gasPrice: 1, bogusField: 1 }, "UNKNOWN_INTENT_FIELDS"],
  ];
  for (const [intent, code] of cases) {
    const result = evaluateIntent(intent);
    assert.equal(result.decision, "DENY", JSON.stringify(intent));
    assert.ok(result.reasonCodes.includes(code), `${JSON.stringify(intent)} → ${result.reasonCodes.join(",")}`);
  }
  const mixedCaseHex = evaluateIntent({ chainId: 196, to: PROCESSOR, valueOkb: 0, data: SCENARIOS.tapeoutReal.data.toUpperCase().replace("0X", "0x") });
  assert.equal(mixedCaseHex.decision, "ALLOW");
});

test("P2-1 known selectors must decode completely and exactly", () => {
  const cases = [
    ["tapeout selector without arguments", PROCESSOR, SELECTORS.tapeout],
    ["tapeout with wrong head offset", PROCESSOR, SCENARIOS.tapeoutReal.data.slice(0, 10) + word(0x80) + SCENARIOS.tapeoutReal.data.slice(74)],
    ["tapeout with trailing bytes", PROCESSOR, `${SCENARIOS.tapeoutReal.data}00`],
    ["tapeout with truncated netlist", PROCESSOR, SCENARIOS.tapeoutReal.data.slice(0, -64)],
    ["approve without amount", USDT, SELECTORS.approve + addrWord(PROCESSOR)],
    ["approve with dirty address word", USDT, SELECTORS.approve + `ff${addrWord(PROCESSOR).slice(2)}` + word(1)],
    ["transfer without amount", USDT, SELECTORS.transfer + addrWord(DEPLOY_WALLET)],
    ["transferFrom without amount", USDT, SELECTORS.transferFrom + addrWord(DEPLOY_WALLET) + addrWord(DEPLOY_WALLET)],
    ["setApprovalForAll without bool", "0x3333333333333333333333333333333333333333", SELECTORS.setApprovalForAll + addrWord(PROCESSOR)],
    ["setApprovalForAll with bool=2", "0x3333333333333333333333333333333333333333", SELECTORS.setApprovalForAll + addrWord(PROCESSOR) + word(2)],
    ["mint with one argument", engine.TRANSISTORS, SELECTORS.mintNand + word(0)],
    ["withdraw with arguments", PROCESSOR, SELECTORS.withdraw + word(0)],
    ["createCPU with truncated tail", FACTORY, CREATE_CPU_CALL.slice(0, -64)],
  ];
  for (const [label, to, data] of cases) {
    const result = evaluateIntent({ chainId: 196, to, valueOkb: 0, data });
    assert.equal(result.decision, "DENY", label);
    assert.ok(result.reasonCodes.includes("ABI_DECODE_FAILED"), `${label} → ${result.reasonCodes.join(",")}`);
    assert.ok(!result.reasonCodes.includes("TOKEN_APPROVAL") && !result.reasonCodes.includes("TOKEN_TRANSFER"), label);
  }
});

test("P2-1 tapeout payloads must be well-formed NAND netlists", () => {
  const badNetlist = abiEncode(SELECTORS.tapeout, ["bytes", "uint32", "uint32"], ["0x" + "00".repeat(6), 17n, 9n]);
  const result = evaluateIntent({ chainId: 196, to: PROCESSOR, valueWei: SCENARIOS.tapeoutReal.valueWei, data: badNetlist });
  assert.equal(result.decision, "DENY");
  assert.ok(result.reasonCodes.includes("TAPEOUT_NETLIST_INVALID"));

  const backwards = abiEncode(SELECTORS.tapeout, ["bytes", "uint32", "uint32"], ["0x00" + "0000ff" + "000002", 2n, 1n]);
  const backwardsResult = evaluateIntent({ chainId: 196, to: PROCESSOR, valueWei: SCENARIOS.tapeoutReal.valueWei, data: backwards });
  assert.ok(backwardsResult.reasonCodes.includes("TAPEOUT_NETLIST_INVALID"));

  const decoded = engine.decodeCalldata(SCENARIOS.tapeoutReal.data);
  assert.equal(decoded.error, null);
  assert.equal(decoded.args.nIn, 17n);
  assert.equal(decoded.args.nOut, 9n);
  assert.equal(decoded.args.netlist.length, 2 + ADD8.netlistBytes * 2);
  const revoke = evaluateIntent({ chainId: 196, to: PROCESSOR, valueOkb: 0, data: SELECTORS.setApprovalForAll + addrWord(PROCESSOR) + word(0) });
  assert.ok(!revoke.reasonCodes.includes("SET_APPROVAL_FOR_ALL"));
});

// --- P2-2: commitment must bind the full policy and resist metadata override --

test("P2-2 commitment hash changes when only a selector allowlist changes", async () => {
  const intent = { chainId: 196, to: PROCESSOR, valueOkb: 0, data: SELECTORS.withdraw };
  const a = evaluateIntent(intent, { knownTargets: { [PROCESSOR]: { label: "P", selectors: [SELECTORS.withdraw] } } });
  const b = evaluateIntent(intent, { knownTargets: { [PROCESSOR]: { label: "P", selectors: [SELECTORS.withdraw, SELECTORS.tapeout] } } });
  assert.equal(a.decision, b.decision);
  assert.notEqual(await hashCommitment(a.commitment), await hashCommitment(b.commitment));
  assert.deepEqual(a.commitment.policy.knownTargets, [{ address: PROCESSOR, label: "P", selectors: [SELECTORS.withdraw] }]);
  assert.equal(typeof a.commitment.policy.maxValueWei, "string");
  assert.ok(Array.isArray(a.commitment.rules) && a.commitment.rules.length > 0);
  assert.equal(a.commitment.accumulator.engine, "nand-netlist");
});

test("P2-2 receipt metadata is isolated and cannot override committed fields", async () => {
  const result = evaluateIntent(SCENARIOS.tokenDrain);
  const receipt = await buildReceipt(result, { decision: "ALLOW", riskScore: 0, reasonCodes: [], note: "ok" });
  assert.equal(receipt.commitment.decision, "DENY");
  assert.equal(receipt.commitment.riskScore, 96);
  assert.equal(receipt.decision, undefined);
  assert.deepEqual(receipt.metadata, { decision: "ALLOW", riskScore: 0, reasonCodes: [], note: "ok" });
  await assert.rejects(() => buildReceipt(result, "nope"), /metadata/);
});

test("P2-2 verifyReceipt recomputes the hash and re-evaluates the committed policy and intent", async () => {
  const receipt = await buildReceipt(evaluateIntent(SCENARIOS.boundedApproval, { reviewThreshold: 50 }));
  const ok = await engine.verifyReceipt(receipt);
  assert.equal(ok.valid, true, JSON.stringify(ok.checks));

  const tamperedDecision = structuredClone(receipt);
  tamperedDecision.commitment.decision = "ALLOW";
  const bad1 = await engine.verifyReceipt(tamperedDecision);
  assert.equal(bad1.valid, false);
  assert.ok(bad1.checks.some((c) => c.name === "commitmentHash" && !c.ok));

  const forgedHash = structuredClone(tamperedDecision);
  forgedHash.commitmentHash = await hashCommitment(forgedHash.commitment);
  const bad2 = await engine.verifyReceipt(forgedHash);
  assert.equal(bad2.valid, false);
  assert.ok(bad2.checks.some((c) => c.name === "reevaluation" && !c.ok));

  const wrongSchema = structuredClone(receipt);
  wrongSchema.schema = "something/else";
  assert.equal((await engine.verifyReceipt(wrongSchema)).valid, false);

  const denied = await buildReceipt(evaluateIntent({ chainId: 196, to: PROCESSOR, valueOkb: 0, value: ONE_OKB_HEX, data: "0x" }));
  assert.equal((await engine.verifyReceipt(denied)).valid, true);
});

test("P2-2 CLI verify subcommand exits 0 for a genuine receipt and 1 for a tampered one", () => {
  const dir = mkdtempSync(join(tmpdir(), "agent-firewall-verify-"));
  const receiptPath = join(dir, "receipt.json");
  const evaluated = runCli(["evaluate", "--scenario", "unlimitedApproval", "--json", "--receipt", receiptPath]);
  assert.equal(evaluated.code, EXIT_CODES.DENY);

  const genuine = runCli(["verify", "--receipt", receiptPath, "--json"]);
  assert.equal(genuine.code, 0, genuine.stdout);
  assert.equal(JSON.parse(genuine.stdout).valid, true);

  const doc = JSON.parse(readFileSync(receiptPath, "utf8"));
  doc.commitment.decision = "ALLOW";
  writeFileSync(receiptPath, JSON.stringify(doc));
  const tampered = runCli(["verify", "--receipt", receiptPath, "--json"]);
  assert.equal(tampered.code, EXIT_CODES.ERROR);
  assert.equal(JSON.parse(tampered.stdout).valid, false);
});

// --- Agent Firewall v2: AI Treasury / Vault Release ------------------------

test("V2 AI Treasury main demo releases only after transaction + SpendGuard + Quorum2of3 pass", () => {
  const result = evaluateVaultRelease(RELEASE_SCENARIOS.treasuryRelease);
  assert.equal(result.decision, "RELEASE");
  assert.equal(result.exitCode, 0);
  assert.equal(result.transaction.decision, "ALLOW");
  assert.equal(result.gates.transaction.status, "PASS");
  assert.equal(result.gates.spendGuard.status, "PASS");
  assert.equal(result.gates.spendGuard.spentTodayOkb, "0.004");
  assert.equal(result.gates.spendGuard.requestOkb, "0.005");
  assert.equal(result.gates.spendGuard.projectedOkb, "0.009");
  assert.equal(result.gates.spendGuard.dailyLimitOkb, "0.012");
  assert.equal(result.gates.quorum.status, "PASS");
  assert.equal(result.gates.quorum.approvals, 2);
  assert.equal(result.gates.quorum.threshold, 2);
  assert.equal(result.commitment.coProcessor.execution, "local policy engine; no wallet, signature or broadcast");
  assert.equal(result.commitment.coProcessor.tapeoutPrimitive.processor, PROCESSOR);
  assert.equal(result.commitment.coProcessor.tapeoutPrimitive.role, "transaction risk-score arithmetic only");
});

test("V2 Quorum2of3 holds an otherwise safe release when only one member approves", () => {
  const result = evaluateVaultRelease(RELEASE_SCENARIOS.quorumHold);
  assert.equal(result.transaction.decision, "ALLOW");
  assert.equal(result.gates.spendGuard.status, "PASS");
  assert.equal(result.gates.quorum.status, "HOLD");
  assert.equal(result.gates.quorum.approvals, 1);
  assert.equal(result.decision, "HOLD");
  assert.deepEqual(result.reasonCodes, ["QUORUM_NOT_MET"]);
  assert.equal(result.exitCode, 2);
});

test("V2 SpendGuard denies a release whose projected native OKB spend exceeds the daily cap", () => {
  const result = evaluateVaultRelease(RELEASE_SCENARIOS.spendGuardDeny);
  assert.equal(result.transaction.decision, "ALLOW");
  assert.equal(result.gates.spendGuard.status, "DENY");
  assert.equal(result.gates.spendGuard.projectedOkb, "0.015");
  assert.equal(result.gates.spendGuard.dailyLimitOkb, "0.012");
  assert.equal(result.decision, "DENY");
  assert.ok(result.reasonCodes.includes("SPEND_GUARD_EXCEEDED"));
  assert.equal(result.exitCode, 3);
});

test("V2 transaction firewall vetoes a hostile release even when budget and quorum pass", () => {
  const result = evaluateVaultRelease(RELEASE_SCENARIOS.hostileApproval);
  assert.equal(result.transaction.decision, "DENY");
  assert.ok(result.transaction.reasonCodes.includes("UNLIMITED_APPROVAL"));
  assert.equal(result.gates.spendGuard.status, "PASS");
  assert.equal(result.gates.quorum.status, "PASS");
  assert.equal(result.decision, "DENY");
  assert.deepEqual(result.reasonCodes, ["TRANSACTION_POLICY_DENY"]);
});

test("V2 vault controls are strict and fail closed on malformed Quorum2of3 state", () => {
  const duplicate = structuredClone(RELEASE_SCENARIOS.treasuryRelease);
  duplicate.controls.quorum.members[1].id = duplicate.controls.quorum.members[0].id;
  assert.throws(() => evaluateVaultRelease(duplicate), /duplicate member id/);

  const wrongThreshold = structuredClone(RELEASE_SCENARIOS.treasuryRelease);
  wrongThreshold.controls.quorum.threshold = 3;
  assert.throws(() => evaluateVaultRelease(wrongThreshold), /threshold must be exactly 2/);

  const extra = structuredClone(RELEASE_SCENARIOS.treasuryRelease);
  extra.controls.spendGuard.shadowBudget = "999";
  assert.throws(() => evaluateVaultRelease(extra), /unknown field/);
});

test("V2 vault release receipts bind controls and re-evaluate the full decision path", async () => {
  const receipt = await buildVaultReleaseReceipt(evaluateVaultRelease(RELEASE_SCENARIOS.treasuryRelease));
  const ok = await engine.verifyVaultReleaseReceipt(receipt);
  assert.equal(ok.valid, true, JSON.stringify(ok.checks));

  const tampered = structuredClone(receipt);
  tampered.commitment.controls.quorum.members[0].approved = !tampered.commitment.controls.quorum.members[0].approved;
  const badHash = await engine.verifyVaultReleaseReceipt(tampered);
  assert.equal(badHash.valid, false);
  assert.ok(badHash.checks.some((check) => check.name === "commitmentHash" && !check.ok));

  tampered.commitmentHash = await hashCommitment(tampered.commitment);
  const forged = await engine.verifyVaultReleaseReceipt(tampered);
  assert.equal(forged.valid, false);
  assert.ok(forged.checks.some((check) => check.name === "reevaluation" && !check.ok));
});

test("V2 CLI release and verify-release expose signer-safe exit codes", () => {
  const dir = mkdtempSync(join(tmpdir(), "agent-firewall-v2-"));
  const receiptPath = join(dir, "vault-release.json");

  const release = runCli(["release", "--scenario", "treasuryRelease", "--json", "--receipt", receiptPath]);
  assert.equal(release.code, 0, release.stdout);
  assert.equal(JSON.parse(release.stdout).commitment.decision, "RELEASE");

  const verified = runCli(["verify-release", "--receipt", receiptPath, "--json"]);
  assert.equal(verified.code, 0, verified.stdout);
  assert.equal(JSON.parse(verified.stdout).valid, true);

  const hold = runCli(["release", "--scenario", "quorumHold", "--json"]);
  assert.equal(hold.code, 2, hold.stdout);
  assert.equal(JSON.parse(hold.stdout).commitment.decision, "HOLD");

  const spendDeny = runCli(["release", "--scenario", "spendGuardDeny", "--json"]);
  assert.equal(spendDeny.code, 3, spendDeny.stdout);
  assert.equal(JSON.parse(spendDeny.stdout).commitment.decision, "DENY");

  const hostile = runCli(["release", "--scenario", "hostileApproval", "--json"]);
  assert.equal(hostile.code, 3, hostile.stdout);
  assert.ok(JSON.parse(hostile.stdout).commitment.reasonCodes.includes("TRANSACTION_POLICY_DENY"));
});

// --- P2-3: --json error path ---------------------------------------------------

test("P2-3 every CLI error path emits exactly one JSON document in --json mode and no stack traces", () => {
  const cases = [
    ["evaluate", "--scenario", "tapeoutReal", "--json", "--receipt"],
    ["evaluate", "--scenario", "tapeoutReal", "--json", "--bogus"],
    ["evaluate", "--intent", "/nonexistent/intent.json", "--json"],
    ["evaluate", "--json", "--intent"],
    ["verify", "--json"],
    ["verify-release", "--json"],
    ["release", "--json", "--scenario", "not-a-scenario"],
    ["bogus-command", "--json"],
  ];
  for (const args of cases) {
    const run = runCli(args, "");
    assert.equal(run.code, EXIT_CODES.ERROR, args.join(" "));
    const doc = JSON.parse(run.stdout);
    assert.equal(doc.status, "ERROR", args.join(" "));
    assert.equal(typeof doc.code, "string");
    assert.equal(typeof doc.error, "string");
    assert.equal(run.stderr, "", args.join(" "));
  }
  const human = runCli(["evaluate", "--scenario", "tapeoutReal", "--receipt"], "");
  assert.equal(human.code, EXIT_CODES.ERROR);
  assert.equal(human.stdout, "");
  assert.match(human.stderr, /^error: /);
  assert.doesNotMatch(human.stderr, /\n\s+at /);
});
