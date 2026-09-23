// LeoLabs Agent Firewall — deterministic pre-sign policy engine for X Layer.
//
// Runs identically in Node (CLI/tests) and in the browser (inspector). No dependencies.
// Nothing in this module signs, broadcasts, or talks to a wallet. The only network
// capability is an explicit read-only eth_call used to verify that the ADD8 netlist
// embedded here is byte-identical to circuitId=1 on the LeoLabs Processor.
//
// Fail-closed contract:
//   * an invalid POLICY throws PolicyError before anything is evaluated (CLI exit 1);
//   * an invalid INTENT never throws — it is evaluated to DENY with a schema reason code;
//   * native value is handled as exact wei (BigInt); floats never reach a comparison;
//   * calldata for every selector the engine knows must decode completely and canonically,
//     otherwise ABI_DECODE_FAILED is a hard deny;
//   * the receipt commits to the full normalized policy, the raw + normalized intent, every
//     rule row and the accumulator trace, so verifyReceipt() can re-derive the decision.

import {
  ADD8_CIRCUIT_ID,
  ADD8_FEES_WEI,
  ADD8_INPUT_LABELS,
  ADD8_N_IN,
  ADD8_N_NAND,
  ADD8_N_OUT,
  ADD8_NETLIST_BYTES,
  ADD8_NETLIST_HEX,
  ADD8_NETLIST_SHA256,
  ADD8_OUTPUT_LABELS,
  ADD8_OUTPUT_SIGNALS,
  ADD8_REAL_CALLS,
} from "./add8-netlist.mjs";

export const ENGINE_VERSION = "0.4.0";
export const COMMITMENT_SCHEMA = "leolabs_agent_firewall_commitment/v3";
export const RECEIPT_SCHEMA = "leolabs_agent_firewall_receipt/v3";
export const VAULT_RELEASE_COMMITMENT_SCHEMA = "leolabs_vault_release_commitment/v1";
export const VAULT_RELEASE_RECEIPT_SCHEMA = "leolabs_vault_release_receipt/v1";

export const CHAIN_ID = 196;

export const PROCESSOR = "0xa196ab8ef5ae052c13819e73f3cc3f4263faf744";
export const TRANSISTORS = "0x37b97b180919bb40d8060f3497c9c243b9c1caf5";
export const FACTORY = "0x1f09daefa827f02cbb40967cc91b259763760761";
export const USDT = "0x779ded0c9e1022225f8e0630b35a9b54be713736";
export const DEPLOY_WALLET = "0x1e1a2f7ac1bc6df29a1878c3f26b17dccdc16e15";

export const XLAYER_RPCS = Object.freeze([
  "https://rpc.xlayer.tech",
  "https://xlayerrpc.okx.com",
  "https://xlayer.drpc.org",
]);

export const SELECTORS = Object.freeze({
  tapeout: "0x7bd3ac1d", // tapeout(bytes,uint32,uint32)
  mintNand: "0x1b2ef1ca", // mint(uint256,uint256)
  withdraw: "0x3ccfd60b", // withdraw()
  createCPU: "0x47f9b5fd", // createCPU(string,string,string,uint256,uint256)
  approve: "0x095ea7b3",
  setApprovalForAll: "0xa22cb465",
  transfer: "0xa9059cbb",
  transferFrom: "0x23b872dd",
  netlist: "0x3fc4be56", // netlist(uint256) view returns (bytes)
  name: "0x06fdde03",
});

// Every selector the engine reasons about, with the exact ABI used for strict decoding.
export const ABI = Object.freeze({
  [SELECTORS.tapeout]: { name: "tapeout", inputs: [["netlist", "bytes"], ["nIn", "uint32"], ["nOut", "uint32"]] },
  [SELECTORS.mintNand]: { name: "mint", inputs: [["id", "uint256"], ["amount", "uint256"]] },
  [SELECTORS.withdraw]: { name: "withdraw", inputs: [] },
  [SELECTORS.createCPU]: {
    name: "createCPU",
    inputs: [["name", "string"], ["symbol", "string"], ["story", "string"], ["transistorSupply", "uint256"], ["mintPrice", "uint256"]],
  },
  [SELECTORS.approve]: { name: "approve", inputs: [["spender", "address"], ["amount", "uint256"]] },
  [SELECTORS.setApprovalForAll]: { name: "setApprovalForAll", inputs: [["operator", "address"], ["approved", "bool"]] },
  [SELECTORS.transfer]: { name: "transfer", inputs: [["to", "address"], ["amount", "uint256"]] },
  [SELECTORS.transferFrom]: { name: "transferFrom", inputs: [["from", "address"], ["to", "address"], ["amount", "uint256"]] },
  [SELECTORS.netlist]: { name: "netlist", inputs: [["circuitId", "uint256"]] },
  [SELECTORS.name]: { name: "name", inputs: [] },
});

export const EXIT_CODES = Object.freeze({ ALLOW: 0, ERROR: 1, REVIEW: 2, DENY: 3 });

export const ADD8 = Object.freeze({
  circuitId: ADD8_CIRCUIT_ID,
  name: "ADD8",
  nIn: ADD8_N_IN,
  nOut: ADD8_N_OUT,
  nNand: ADD8_N_NAND,
  netlistBytes: ADD8_NETLIST_BYTES,
  netlistSha256: ADD8_NETLIST_SHA256,
  netlistHex: ADD8_NETLIST_HEX,
  inputLabels: ADD8_INPUT_LABELS,
  outputLabels: ADD8_OUTPUT_LABELS,
  outputSignals: ADD8_OUTPUT_SIGNALS,
  realCalls: ADD8_REAL_CALLS,
  feesWei: ADD8_FEES_WEI,
});

// `selectors` is the exhaustive method allowlist of a known target. An empty list means
// "value-only": any non-empty calldata to that target is SELECTOR_NOT_ALLOWED.
export const DEFAULT_POLICY = Object.freeze({
  name: "LeoLabs X Layer Agent Firewall",
  version: "0.4.0",
  chainId: CHAIN_ID,
  maxValueOkb: 0.02,
  reviewThreshold: 40,
  denyThreshold: 80,
  knownTargets: {
    [PROCESSOR]: { label: "LeoLabs TapeOut Processor", selectors: [SELECTORS.tapeout] },
    [TRANSISTORS]: { label: "LEOLABS Transistors", selectors: [SELECTORS.mintNand] },
    [FACTORY]: { label: "TapeOut X Layer Factory", selectors: [SELECTORS.createCPU] },
    [USDT]: { label: "USDT (X Layer)", selectors: [SELECTORS.approve, SELECTORS.transfer, SELECTORS.transferFrom] },
  },
  trustedRecipients: [DEPLOY_WALLET],
});

const WEI_PER_OKB = 10n ** 18n;
const UINT32_MAX = (1n << 32n) - 1n;
const ADDRESS_MAX = (1n << 160n) - 1n;
const UINT256_MAX = (1n << 256n) - 1n;
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const SELECTOR_RE = /^0x[0-9a-fA-F]{8}$/;
const CALLDATA_RE = /^0x(?:[0-9a-fA-F]{2})*$/;

function padWord(value) {
  return BigInt(value).toString(16).padStart(64, "0");
}

function addressWord(address) {
  return address.slice(2).toLowerCase().padStart(64, "0");
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function present(value) {
  return value !== undefined && value !== null;
}

export const SCENARIOS = Object.freeze({
  tapeoutReal: {
    label: "Tapeout ADD8 (real tx)",
    chainId: CHAIN_ID,
    to: ADD8_REAL_CALLS.tapeout.to,
    valueWei: ADD8_REAL_CALLS.tapeout.valueWei,
    data: ADD8_REAL_CALLS.tapeout.data,
  },
  mintNandReal: {
    label: "Mint 122 NAND (real tx)",
    chainId: CHAIN_ID,
    to: ADD8_REAL_CALLS.mintNand.to,
    valueWei: ADD8_REAL_CALLS.mintNand.valueWei,
    data: ADD8_REAL_CALLS.mintNand.data,
  },
  boundedApproval: {
    label: "Bounded approval (2 USDT)",
    chainId: CHAIN_ID,
    to: USDT,
    valueOkb: 0,
    data: SELECTORS.approve + addressWord(PROCESSOR) + padWord(2_000_000n),
  },
  unlimitedApproval: {
    label: "Unlimited approval",
    chainId: CHAIN_ID,
    to: USDT,
    valueOkb: 0,
    data: SELECTORS.approve + addressWord(PROCESSOR) + "f".repeat(64),
  },
  tokenDrain: {
    label: "Token drain",
    chainId: CHAIN_ID,
    to: USDT,
    valueOkb: 0,
    data: SELECTORS.transfer + addressWord("0x000000000000000000000000000000000000dead") + padWord(1_000_000_000n),
  },
  wrongChain: {
    label: "Wrong chain",
    chainId: 1,
    to: PROCESSOR,
    valueWei: ADD8_REAL_CALLS.tapeout.valueWei,
    data: ADD8_REAL_CALLS.tapeout.data,
  },
  unknownValueTarget: {
    label: "Unknown target + value",
    chainId: CHAIN_ID,
    to: "0x1111111111111111111111111111111111111111",
    valueOkb: 0.08,
    data: "0x",
  },
});

export const RELEASE_SCENARIOS = Object.freeze({
  treasuryRelease: {
    label: "AI Treasury release · 2/3 approved",
    intent: {
      chainId: CHAIN_ID,
      to: PROCESSOR,
      valueOkb: "0.005",
      data: "0x",
      label: "AI Treasury → TapeOut Processor",
    },
    controls: {
      vaultId: "leolabs-ai-treasury",
      spendGuard: { spentTodayOkb: "0.004", dailyLimitOkb: "0.012" },
      quorum: {
        threshold: 2,
        members: [
          { id: "policy-agent", approved: true },
          { id: "risk-agent", approved: true },
          { id: "ops-agent", approved: false },
        ],
      },
    },
  },
  quorumHold: {
    label: "Quorum hold · only 1/3",
    intent: { chainId: CHAIN_ID, to: PROCESSOR, valueOkb: "0.005", data: "0x", label: "AI Treasury → TapeOut Processor" },
    controls: {
      vaultId: "leolabs-ai-treasury",
      spendGuard: { spentTodayOkb: "0.004", dailyLimitOkb: "0.012" },
      quorum: {
        threshold: 2,
        members: [
          { id: "policy-agent", approved: true },
          { id: "risk-agent", approved: false },
          { id: "ops-agent", approved: false },
        ],
      },
    },
  },
  spendGuardDeny: {
    label: "SpendGuard deny · daily cap",
    intent: { chainId: CHAIN_ID, to: PROCESSOR, valueOkb: "0.005", data: "0x", label: "AI Treasury → TapeOut Processor" },
    controls: {
      vaultId: "leolabs-ai-treasury",
      spendGuard: { spentTodayOkb: "0.010", dailyLimitOkb: "0.012" },
      quorum: {
        threshold: 2,
        members: [
          { id: "policy-agent", approved: true },
          { id: "risk-agent", approved: true },
          { id: "ops-agent", approved: false },
        ],
      },
    },
  },
  hostileApproval: {
    label: "Firewall deny · unlimited approval",
    intent: SCENARIOS.unlimitedApproval,
    controls: {
      vaultId: "leolabs-ai-treasury",
      spendGuard: { spentTodayOkb: "0.004", dailyLimitOkb: "0.012" },
      quorum: {
        threshold: 2,
        members: [
          { id: "policy-agent", approved: true },
          { id: "risk-agent", approved: true },
          { id: "ops-agent", approved: false },
        ],
      },
    },
  },
});

// ---------------------------------------------------------------------------
// ADD8 NAND netlist interpreter (same encoding the Processor stores on-chain)
// ---------------------------------------------------------------------------

export function normalizeHex(data) {
  if (typeof data !== "string") return "0x";
  const trimmed = data.trim();
  if (!trimmed) return "0x";
  return trimmed.startsWith("0x") || trimmed.startsWith("0X")
    ? `0x${trimmed.slice(2).toLowerCase()}`
    : `0x${trimmed.toLowerCase()}`;
}

export function decodeNetlist(hex = ADD8_NETLIST_HEX) {
  const clean = normalizeHex(hex).slice(2);
  if (clean.length % 14 !== 0) {
    throw new Error(`netlist hex length ${clean.length} is not a multiple of 7 bytes`);
  }
  const gates = [];
  for (let i = 0; i < clean.length; i += 14) {
    const op = parseInt(clean.slice(i, i + 2), 16);
    if (op !== 0) throw new Error(`unsupported opcode ${op} at gate ${gates.length}`);
    gates.push({
      a: parseInt(clean.slice(i + 2, i + 8), 16),
      b: parseInt(clean.slice(i + 8, i + 14), 16),
    });
  }
  return gates;
}

// Structural validation of a tapeout payload: 7-byte NAND gates, 3-byte signal ids that
// only reference constants, inputs or earlier gates, and output count within the gate count.
// The Processor's output-mapping convention is not modelled here.
export function validateNetlist(netlistHex, nIn, nOut) {
  const fail = (error) => ({ ok: false, error, nNand: null });
  if (typeof netlistHex !== "string" || !CALLDATA_RE.test(netlistHex)) return fail("netlist is not even-length hex");
  const clean = netlistHex.slice(2).toLowerCase();
  if (clean.length === 0) return fail("netlist is empty");
  if (clean.length % 14 !== 0) return fail(`netlist is ${clean.length / 2} bytes, not a multiple of the 7-byte gate size`);
  let inputs;
  let outputs;
  try {
    inputs = BigInt(nIn);
    outputs = BigInt(nOut);
  } catch {
    return fail("nIn/nOut are not integers");
  }
  if (inputs < 0n || outputs < 1n) return fail(`nIn=${inputs} nOut=${outputs}: need nIn ≥ 0 and nOut ≥ 1`);
  const nNand = clean.length / 14;
  if (2n + inputs + BigInt(nNand) > 1n << 24n) return fail("signal ids would overflow the 3-byte encoding");
  if (outputs > BigInt(nNand)) return fail(`nOut=${outputs} exceeds the ${nNand} gates in the netlist`);
  const base = 2 + Number(inputs);
  for (let k = 0; k < nNand; k += 1) {
    const at = k * 14;
    if (clean.slice(at, at + 2) !== "00") return fail(`gate ${k} has opcode 0x${clean.slice(at, at + 2)}; only NAND (0x00) is defined`);
    const a = parseInt(clean.slice(at + 2, at + 8), 16);
    const b = parseInt(clean.slice(at + 8, at + 14), 16);
    const out = base + k;
    if (a >= out || b >= out) return fail(`gate ${k} reads signal ${Math.max(a, b)} which is not defined before it (limit ${out - 1})`);
  }
  return { ok: true, error: null, nNand };
}

let cachedGates = null;
function add8Gates() {
  if (!cachedGates) cachedGates = decodeNetlist(ADD8_NETLIST_HEX);
  return cachedGates;
}

// Signal ids: 0 = constant 0, 1 = constant 1, 2..2+nIn-1 = inputs, then one id per gate.
export function evalNetlist(gates, nIn, inputBits) {
  if (inputBits.length !== nIn) throw new Error(`expected ${nIn} input bits, got ${inputBits.length}`);
  const signals = new Uint8Array(2 + nIn + gates.length);
  signals[1] = 1;
  for (let i = 0; i < nIn; i += 1) signals[2 + i] = inputBits[i] & 1;
  for (let k = 0; k < gates.length; k += 1) {
    const { a, b } = gates[k];
    const out = 2 + nIn + k;
    if (a >= out || b >= out) throw new Error(`gate ${k} reads a signal that is not yet defined`);
    signals[out] = 1 - (signals[a] & signals[b]);
  }
  return signals;
}

export function add8Circuit(a, b, cin = 0) {
  const aa = Number(a) & 0xff;
  const bb = Number(b) & 0xff;
  const cc = Number(cin) & 1;
  const bits = [];
  for (let i = 0; i < 8; i += 1) bits.push((aa >> i) & 1);
  for (let i = 0; i < 8; i += 1) bits.push((bb >> i) & 1);
  bits.push(cc);
  const signals = evalNetlist(add8Gates(), ADD8_N_IN, bits);
  const outBits = ADD8_OUTPUT_SIGNALS.map((id) => signals[id]);
  let sum = 0;
  for (let i = 0; i < 8; i += 1) sum |= outBits[i] << i;
  const cout = outBits[8];
  return { sum, cout, packed: sum | (cout << 8), bits: outBits, gates: ADD8_N_NAND };
}

// Arithmetic reference used only to cross-check the circuit result.
export function add8(a, b, cin = 0) {
  const total = (Number(a) & 0xff) + (Number(b) & 0xff) + (Number(cin) & 1);
  return { sum: total & 0xff, cout: (total >> 8) & 1, packed: total & 0x1ff };
}

export const ADD8_GOLDEN_VECTORS = Object.freeze([
  { a: 100, b: 50, cin: 0, expect: 150 },
  { a: 255, b: 1, cin: 0, expect: 256 },
  { a: 0xa5, b: 0x5a, cin: 1, expect: 256 },
  { a: 0, b: 0, cin: 0, expect: 0 },
  { a: 128, b: 128, cin: 0, expect: 256 },
]);

export function runGoldenVectors() {
  return ADD8_GOLDEN_VECTORS.map((v) => {
    const got = add8Circuit(v.a, v.b, v.cin).packed;
    return { ...v, got, ok: got === v.expect };
  });
}

// Risk weights are summed by the taped ADD8 circuit; a carry-out saturates the 8-bit score.
export function accumulateRisk(weights) {
  let sum = 0;
  let saturated = false;
  const steps = [];

  for (const raw of weights) {
    const weight = Math.max(0, Math.min(255, Number(raw) || 0));
    const circuit = add8Circuit(sum, weight, 0);
    const reference = add8(sum, weight, 0);
    if (circuit.packed !== reference.packed) {
      throw new Error(`CIRCUIT_ARITH_MISMATCH: netlist=${circuit.packed} arithmetic=${reference.packed}`);
    }
    const before = sum;
    if (circuit.cout) {
      sum = 255;
      saturated = true;
    } else {
      sum = circuit.sum;
    }
    steps.push({ before, add: weight, add8Packed: circuit.packed, carry: circuit.cout, after: sum });
    if (saturated) break;
  }

  return { score: sum, saturated, steps, engine: "nand-netlist", gatesPerStep: ADD8_N_NAND };
}

// ---------------------------------------------------------------------------
// Exact value arithmetic (wei as BigInt; OKB only as decimal strings)
// ---------------------------------------------------------------------------

// Shortest round-trip decimal of a JS number, with exponent notation expanded.
function numberToDecimalString(n) {
  const s = String(n);
  const m = /^(\d+)(?:\.(\d+))?e([+-]\d+)$/.exec(s);
  if (!m) return s;
  const digits = m[1] + (m[2] || "");
  const exp = Number(m[3]) - (m[2] || "").length;
  if (exp >= 0) return digits + "0".repeat(exp);
  const point = digits.length + exp;
  return point > 0 ? `${digits.slice(0, point)}.${digits.slice(point)}` : `0.${"0".repeat(-point)}${digits}`;
}

// Accepts a wei amount as a bigint or as a decimal / 0x-hex string. JS numbers are refused
// because wei amounts above 2^53 (≈0.009 OKB) cannot be represented exactly.
export function parseWei(value) {
  if (typeof value === "bigint") {
    if (value < 0n) throw new Error("wei amount must not be negative");
    return value;
  }
  if (typeof value === "string") {
    const s = value.trim();
    if (/^\d+$/.test(s)) return BigInt(s);
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
    throw new Error(`wei amount "${s}" must be a non-negative integer as a decimal or 0x-hex string`);
  }
  if (typeof value === "number") throw new Error("wei amount must be a string or bigint, not a JS number (exactness above 2^53)");
  throw new Error(`wei amount must be a string or bigint, got ${typeof value}`);
}

// Accepts an OKB amount as a plain decimal string ("0.0013"), a non-negative number (via its
// shortest round-trip decimal form) or a bigint (whole OKB). At most 18 decimal places.
export function parseOkbToWei(value) {
  let text;
  if (typeof value === "bigint") {
    if (value < 0n) throw new Error("OKB amount must not be negative");
    return value * WEI_PER_OKB;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || value < 0) throw new Error(`OKB amount must be a finite non-negative number, got ${value}`);
    text = numberToDecimalString(value);
  } else if (typeof value === "string") {
    text = value.trim();
  } else {
    throw new Error(`OKB amount must be a decimal string or number, got ${typeof value}`);
  }
  const m = /^(\d+)(?:\.(\d+))?$/.exec(text);
  if (!m) throw new Error(`OKB amount "${text}" is not a plain decimal (digits with an optional fraction)`);
  const fraction = m[2] || "";
  if (fraction.length > 18) throw new Error(`OKB amount "${text}" has ${fraction.length} decimal places; at most 18 are representable in wei`);
  return BigInt(m[1]) * WEI_PER_OKB + BigInt(fraction.padEnd(18, "0") || "0");
}

// EIP-1193 transaction objects carry native value only as a 0x-hex wei string.
function parseHexWei(value) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value.trim())) {
    throw new Error('EIP-1193 "value" must be a 0x-prefixed hex wei string');
  }
  return BigInt(value.trim());
}

export function formatOkb(wei) {
  if (typeof wei !== "bigint" || wei < 0n) throw new TypeError("formatOkb expects a non-negative bigint wei amount");
  const whole = wei / WEI_PER_OKB;
  const fraction = (wei % WEI_PER_OKB).toString().padStart(18, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : `${whole}`;
}

// Display-only helper (JS number). Never used for a policy comparison.
export function okbFromWei(weiLike) {
  if (weiLike === null || weiLike === undefined || weiLike === "") return 0;
  let wei;
  try {
    wei = parseWei(typeof weiLike === "number" ? String(weiLike) : weiLike);
  } catch {
    return Number.NaN;
  }
  return Number(wei) / 1e18;
}

function parseChainId(value) {
  const bad = () => new Error("chainId must be a non-negative integer as a number, decimal string or 0x-hex string");
  let n;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw bad();
    return value;
  }
  if (typeof value === "bigint") {
    n = value;
  } else if (typeof value === "string") {
    const s = value.trim();
    if (/^\d+$/.test(s) || /^0x[0-9a-fA-F]+$/.test(s)) n = BigInt(s);
    else throw bad();
  } else {
    throw bad();
  }
  if (n < 0n || n > BigInt(Number.MAX_SAFE_INTEGER)) throw bad();
  return Number(n);
}

// ---------------------------------------------------------------------------
// Intent normalisation (strict raw schema; never throws for a bad intent)
// ---------------------------------------------------------------------------

const TX_PASSTHROUGH_FIELDS = ["from", "gas", "gasLimit", "gasPrice", "maxFeePerGas", "maxPriorityFeePerGas", "nonce", "type", "accessList"];
const PLAIN_INTENT_FIELDS = new Set(["chainId", "to", "data", "input", "value", "valueWei", "valueOkb", "label", ...TX_PASSTHROUGH_FIELDS]);
const ENVELOPE_TX_FIELDS = new Set(["chainId", "to", "data", "input", "value", ...TX_PASSTHROUGH_FIELDS]);
const ENVELOPE_FIELDS = new Set(["method", "params", "chainId", "label", "id", "jsonrpc"]);
const SUPPORTED_METHODS = new Set(["eth_sendTransaction", "eth_signTransaction"]);

class IntentError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "IntentError";
    this.code = code;
  }
}

function isEnvelope(value) {
  return isPlainObject(value) && (typeof value.method === "string" || Array.isArray(value.params));
}

// Flattens an EIP-1193 request envelope {method, params:[tx]} into a plain intent. Throws
// IntentError for anything that is not a single, standard eth_sendTransaction /
// eth_signTransaction object; evaluateIntent() turns that into a DENY reason code.
export function intentFromRequest(request) {
  if (!isEnvelope(request)) return request;
  const { method } = request;
  if (typeof method !== "string" || !SUPPORTED_METHODS.has(method)) {
    throw new IntentError("UNSUPPORTED_REQUEST_METHOD",
      `request method ${describe(method ?? null)} is not eth_sendTransaction or eth_signTransaction`);
  }
  const unknownEnvelope = Object.keys(request).filter((key) => !ENVELOPE_FIELDS.has(key));
  if (unknownEnvelope.length) throw new IntentError("UNKNOWN_INTENT_FIELDS", `unknown request field(s): ${unknownEnvelope.join(", ")}`);
  if (!Array.isArray(request.params) || request.params.length !== 1 || !isPlainObject(request.params[0])) {
    throw new IntentError("MALFORMED_REQUEST", "params must be an array holding exactly one transaction object");
  }
  const tx = request.params[0];
  const nonStandardValue = Object.keys(tx).filter((key) => key === "valueOkb" || key === "valueWei");
  if (nonStandardValue.length) {
    throw new IntentError("CONFLICTING_VALUE_FIELDS",
      `EIP-1193 transactions carry native value only in "value" (0x-hex wei); found ${nonStandardValue.join(", ")}`);
  }
  const unknownTx = Object.keys(tx).filter((key) => !ENVELOPE_TX_FIELDS.has(key));
  if (unknownTx.length) throw new IntentError("UNKNOWN_INTENT_FIELDS", `unknown transaction field(s): ${unknownTx.join(", ")}`);
  if (present(tx.chainId) && present(request.chainId)) {
    let same = false;
    try {
      same = parseChainId(tx.chainId) === parseChainId(request.chainId);
    } catch {
      same = false;
    }
    if (!same) throw new IntentError("MALFORMED_CHAIN_ID", "transaction chainId and request chainId disagree");
  }
  return { ...tx, chainId: present(tx.chainId) ? tx.chainId : request.chainId, label: request.label };
}

export function normalizeIntent(rawIntent) {
  const errors = [];
  const out = {
    source: "plain",
    method: null,
    chainId: null,
    to: null,
    valueWei: null,
    valueOkb: null,
    valueSource: "none",
    data: null,
    label: "",
    errors,
  };
  const error = (code, detail) => errors.push({ code, detail });

  if (!isPlainObject(rawIntent)) {
    error("MALFORMED_REQUEST", "intent must be a JSON object");
    return out;
  }
  if (isEnvelope(rawIntent)) {
    out.source = "eip1193";
    out.method = typeof rawIntent.method === "string" ? rawIntent.method : null;
  }

  let flat;
  try {
    flat = intentFromRequest(rawIntent);
  } catch (caught) {
    if (!(caught instanceof IntentError)) throw caught;
    error(caught.code, caught.message);
    return out;
  }

  const unknown = Object.keys(flat).filter((key) => !PLAIN_INTENT_FIELDS.has(key));
  if (unknown.length) error("UNKNOWN_INTENT_FIELDS", `unknown intent field(s): ${unknown.join(", ")}`);

  if (!present(flat.chainId)) {
    error("MALFORMED_CHAIN_ID", "chainId is required");
  } else {
    try {
      out.chainId = parseChainId(flat.chainId);
    } catch (caught) {
      error("MALFORMED_CHAIN_ID", caught.message);
    }
  }

  if (typeof flat.to === "string" && ADDRESS_RE.test(flat.to)) {
    out.to = flat.to.toLowerCase();
  } else {
    error("MALFORMED_TARGET", "to must be a 0x-prefixed 20-byte hex address");
  }

  const valueFields = ["valueOkb", "valueWei", "value"].filter((key) => present(flat[key]));
  if (valueFields.length > 1) {
    error("CONFLICTING_VALUE_FIELDS", `native value given as ${valueFields.join(" and ")}; provide exactly one representation`);
    out.valueSource = "conflict";
  } else if (valueFields.length === 1) {
    const [key] = valueFields;
    out.valueSource = key;
    try {
      if (key === "valueOkb") out.valueWei = parseOkbToWei(flat.valueOkb);
      else if (key === "valueWei") out.valueWei = parseWei(flat.valueWei);
      else out.valueWei = parseHexWei(flat.value);
    } catch (caught) {
      error("MALFORMED_VALUE", caught.message);
    }
  } else {
    out.valueWei = 0n;
  }
  if (out.valueWei !== null) out.valueOkb = formatOkb(out.valueWei);

  const dataFields = ["data", "input"].filter((key) => present(flat[key]));
  let dataValue = dataFields.length ? flat[dataFields[0]] : "0x";
  if (dataFields.length === 2
    && !(typeof flat.data === "string" && typeof flat.input === "string" && flat.data.toLowerCase() === flat.input.toLowerCase())) {
    error("CONFLICTING_DATA_FIELDS", "data and input disagree; provide one calldata field");
    dataValue = null;
  }
  if (dataValue !== null) {
    if (typeof dataValue === "string" && CALLDATA_RE.test(dataValue) && (dataValue.length === 2 || dataValue.length >= 10)) {
      out.data = dataValue.toLowerCase();
    } else {
      error("MALFORMED_CALLDATA", "data must be 0x-prefixed even-length hex: either empty (0x) or at least a 4-byte selector");
    }
  }

  if (present(flat.label)) {
    if (typeof flat.label === "string") out.label = flat.label.trim();
    else error("MALFORMED_LABEL", "label must be a string");
  }

  return out;
}

// ---------------------------------------------------------------------------
// Policy validation (throws PolicyError; nothing is evaluated with an invalid policy)
// ---------------------------------------------------------------------------

export class PolicyError extends Error {
  constructor(message) {
    super(message);
    this.name = "PolicyError";
    this.code = "POLICY_INVALID";
  }
}

const POLICY_FIELDS = new Set(["name", "version", "chainId", "maxValueOkb", "maxValueWei", "reviewThreshold", "denyThreshold", "knownTargets", "trustedRecipients"]);

// Safe rendering of an arbitrary offending value inside an error message.
function describe(value) {
  if (typeof value === "bigint") return `${value}n`;
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

function requireNonEmptyString(value, field) {
  if (typeof value !== "string" || value.trim() === "") throw new PolicyError(`${field} must be a non-empty string`);
  return value.trim();
}

function requireThreshold(value, field) {
  if (!Number.isInteger(value) || value < 1 || value > 255) {
    throw new PolicyError(`${field} must be an integer between 1 and 255, got ${describe(value)}`);
  }
  return value;
}

export function normalizePolicy(overrides = {}) {
  if (!isPlainObject(overrides)) throw new PolicyError("policy overrides must be a JSON object");
  for (const key of Object.keys(overrides)) {
    if (!POLICY_FIELDS.has(key)) throw new PolicyError(`unknown policy field "${key}"`);
  }
  const has = (key) => overrides[key] !== undefined;
  if (has("maxValueOkb") && has("maxValueWei")) {
    throw new PolicyError("maxValueOkb and maxValueWei are mutually exclusive; set exactly one value ceiling");
  }
  const merged = { ...DEFAULT_POLICY, ...overrides };

  const name = requireNonEmptyString(merged.name, "name");
  const version = requireNonEmptyString(merged.version, "version");
  if (!Number.isSafeInteger(merged.chainId) || merged.chainId <= 0) {
    throw new PolicyError(`chainId must be a positive integer number, got ${describe(merged.chainId)}`);
  }

  let maxValueWei;
  try {
    maxValueWei = has("maxValueWei") ? parseWei(overrides.maxValueWei) : parseOkbToWei(merged.maxValueOkb);
  } catch (caught) {
    throw new PolicyError(`${has("maxValueWei") ? "maxValueWei" : "maxValueOkb"}: ${caught.message}`);
  }

  const reviewThreshold = requireThreshold(merged.reviewThreshold, "reviewThreshold");
  const denyThreshold = requireThreshold(merged.denyThreshold, "denyThreshold");
  if (reviewThreshold >= denyThreshold) {
    throw new PolicyError(`reviewThreshold (${reviewThreshold}) must be lower than denyThreshold (${denyThreshold})`);
  }

  if (!isPlainObject(merged.knownTargets)) throw new PolicyError("knownTargets must be an object keyed by 0x address");
  const knownTargets = new Map();
  for (const [address, spec] of Object.entries(merged.knownTargets)) {
    if (!ADDRESS_RE.test(address)) throw new PolicyError(`knownTargets: "${address}" is not a 20-byte 0x address`);
    const lower = address.toLowerCase();
    if (knownTargets.has(lower)) throw new PolicyError(`knownTargets: duplicate address ${lower}`);
    if (!isPlainObject(spec)) throw new PolicyError(`knownTargets[${lower}] must be an object with label and selectors`);
    for (const key of Object.keys(spec)) {
      if (key !== "label" && key !== "selectors") throw new PolicyError(`knownTargets[${lower}]: unknown field "${key}"`);
    }
    if (typeof spec.label !== "string" || spec.label.trim() === "") throw new PolicyError(`knownTargets[${lower}]: label must be a non-empty string`);
    if (!Array.isArray(spec.selectors)) {
      throw new PolicyError(`knownTargets[${lower}]: selectors must be an array of 4-byte 0x selectors (empty array = value-only target)`);
    }
    const selectors = [];
    for (const selector of spec.selectors) {
      if (typeof selector !== "string" || !SELECTOR_RE.test(selector)) {
        throw new PolicyError(`knownTargets[${lower}]: selector ${describe(selector)} is not a 4-byte 0x hex selector`);
      }
      const normalized = selector.toLowerCase();
      if (selectors.includes(normalized)) throw new PolicyError(`knownTargets[${lower}]: duplicate selector ${normalized}`);
      selectors.push(normalized);
    }
    selectors.sort();
    knownTargets.set(lower, { label: spec.label.trim(), selectors });
  }

  if (!Array.isArray(merged.trustedRecipients)) throw new PolicyError("trustedRecipients must be an array of 0x addresses");
  const trustedRecipients = new Set();
  for (const address of merged.trustedRecipients) {
    if (typeof address !== "string" || !ADDRESS_RE.test(address)) {
      throw new PolicyError(`trustedRecipients: ${describe(address)} is not a 20-byte 0x address`);
    }
    const lower = address.toLowerCase();
    if (trustedRecipients.has(lower)) throw new PolicyError(`trustedRecipients: duplicate address ${lower}`);
    trustedRecipients.add(lower);
  }

  return {
    name,
    version,
    chainId: merged.chainId,
    maxValueWei,
    maxValueOkb: formatOkb(maxValueWei),
    reviewThreshold,
    denyThreshold,
    knownTargets,
    trustedRecipients,
  };
}

function policyCommitment(policy) {
  return {
    name: policy.name,
    version: policy.version,
    chainId: policy.chainId,
    maxValueWei: policy.maxValueWei.toString(),
    reviewThreshold: policy.reviewThreshold,
    denyThreshold: policy.denyThreshold,
    knownTargets: [...policy.knownTargets.entries()]
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([address, spec]) => ({ address, label: spec.label, selectors: [...spec.selectors] })),
    trustedRecipients: [...policy.trustedRecipients].sort(),
  };
}

// Inverse of policyCommitment(): the overrides that reproduce a committed policy exactly.
export function policyOverridesFromCommitment(committed) {
  if (!isPlainObject(committed)) throw new PolicyError("committed policy must be an object");
  const knownTargets = {};
  for (const target of Array.isArray(committed.knownTargets) ? committed.knownTargets : []) {
    if (!isPlainObject(target)) throw new PolicyError("committed knownTargets entries must be objects");
    knownTargets[target.address] = { label: target.label, selectors: target.selectors };
  }
  return {
    name: committed.name,
    version: committed.version,
    chainId: committed.chainId,
    maxValueWei: committed.maxValueWei,
    reviewThreshold: committed.reviewThreshold,
    denyThreshold: committed.denyThreshold,
    knownTargets,
    trustedRecipients: committed.trustedRecipients,
  };
}

// ---------------------------------------------------------------------------
// Strict canonical ABI decoding for known selectors
// ---------------------------------------------------------------------------

function abiSignature(abi) {
  return `${abi.name}(${abi.inputs.map(([, type]) => type).join(",")})`;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

class AbiError extends Error {}

// Decodes calldata for a selector in ABI. Returns {selector, signature, args, error}:
//   data "0x"            → selector null, no error
//   unknown selector     → signature null, args null, no error (nothing to decode)
//   known selector       → args (bigint / lowercase address / boolean / 0x-hex / string) or error
// Only the canonical encoding is accepted: head offsets must point exactly where the tightly
// packed tail starts, padding must be zero, address words must have zero upper bytes, bool
// words must be 0 or 1, and no bytes may remain after the last argument.
export function decodeCalldata(data) {
  const result = { selector: null, signature: null, args: null, error: null };
  if (typeof data !== "string" || !/^0x(?:[0-9a-f]{2})*$/.test(data)) {
    return { ...result, error: "calldata is not normalized even-length lowercase hex" };
  }
  if (data === "0x") return result;
  if (data.length < 10) return { ...result, error: "calldata is shorter than a 4-byte selector" };
  result.selector = data.slice(0, 10);
  const abi = ABI[result.selector];
  if (!abi) return result;
  result.signature = abiSignature(abi);

  const body = data.slice(10);
  const fail = (message) => new AbiError(`${result.signature}: ${message}`);
  try {
    if (body.length % 64 !== 0) throw fail(`argument block is ${body.length / 2} bytes, not a multiple of 32`);
    const headWords = abi.inputs.length;
    if (body.length / 64 < headWords) throw fail(`expected ${headWords} head word(s), got ${body.length / 64}`);
    const args = {};
    let tailCursor = headWords * 32;
    abi.inputs.forEach(([name, type], index) => {
      const word = BigInt(`0x${body.slice(index * 64, index * 64 + 64)}`);
      switch (type) {
        case "uint256":
          args[name] = word;
          break;
        case "uint32":
          if (word > UINT32_MAX) throw fail(`${name} exceeds uint32`);
          args[name] = word;
          break;
        case "address":
          if (word > ADDRESS_MAX) throw fail(`${name}: upper 12 bytes of the address word are not zero`);
          args[name] = `0x${word.toString(16).padStart(40, "0")}`;
          break;
        case "bool":
          if (word > 1n) throw fail(`${name}: bool word must be 0 or 1, got ${word}`);
          args[name] = word === 1n;
          break;
        case "bytes":
        case "string": {
          if (word !== BigInt(tailCursor)) throw fail(`${name}: offset ${word} is not the canonical ${tailCursor}`);
          const lengthStart = tailCursor * 2;
          if (lengthStart + 64 > body.length) throw fail(`${name}: length word is outside the calldata`);
          const length = BigInt(`0x${body.slice(lengthStart, lengthStart + 64)}`);
          if (length > BigInt(body.length / 2)) throw fail(`${name}: declared length ${length} exceeds the calldata`);
          const lengthNum = Number(length);
          const padded = Math.ceil(lengthNum / 32) * 32;
          const dataStart = lengthStart + 64;
          if (dataStart + padded * 2 > body.length) throw fail(`${name}: declared ${lengthNum} bytes but the calldata ends early`);
          const raw = body.slice(dataStart, dataStart + lengthNum * 2);
          const padding = body.slice(dataStart + lengthNum * 2, dataStart + padded * 2);
          if (/[^0]/.test(padding)) throw fail(`${name}: padding bytes are not zero`);
          if (type === "bytes") {
            args[name] = `0x${raw}`;
          } else {
            try {
              args[name] = new TextDecoder("utf-8", { fatal: true }).decode(hexToBytes(raw));
            } catch {
              throw fail(`${name}: not valid UTF-8`);
            }
          }
          tailCursor += 32 + padded;
          break;
        }
        default:
          throw fail(`unsupported ABI type ${type}`);
      }
    });
    if (tailCursor * 2 !== body.length) throw fail(`${body.length / 2 - tailCursor} trailing byte(s) after the last argument`);
    result.args = args;
  } catch (caught) {
    if (!(caught instanceof AbiError)) throw caught;
    result.error = caught.message;
  }
  return result;
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

const RULE_TITLES = Object.freeze({
  CHAIN_OK: "X Layer chain",
  CHAIN_MISMATCH: "Wrong chain",
  KNOWN_TARGET: "Known destination",
  UNKNOWN_TARGET: "Unknown destination",
  UNKNOWN_VALUE_TARGET: "Unknown destination receives value",
  VALUE_OK: "Value ceiling",
  VALUE_LIMIT_EXCEEDED: "Value ceiling exceeded",
  NO_CALLDATA: "No calldata",
  CALLDATA_DECODED: "Calldata decoded",
  ABI_DECODE_FAILED: "Calldata does not match the method ABI",
  SELECTOR_ALLOWED: "Method allowlist",
  SELECTOR_NOT_ALLOWED: "Method not in allowlist",
  SELECTOR_ABI_UNKNOWN: "Allowlisted method without ABI",
  UNLIMITED_APPROVAL: "Unlimited ERC-20 approval",
  APPROVAL_UNTRUSTED_SPENDER: "Approval to untrusted spender",
  TOKEN_APPROVAL: "Token approval",
  SET_APPROVAL_FOR_ALL: "Global NFT/operator approval",
  OPERATOR_APPROVAL_REVOKED: "Operator approval revoked",
  TOKEN_TRANSFER_UNTRUSTED_RECIPIENT: "Token transfer to untrusted recipient",
  TOKEN_TRANSFER: "Token transfer",
  TAPEOUT_NETLIST_OK: "Tapeout netlist",
  TAPEOUT_NETLIST_INVALID: "Tapeout netlist invalid",
  MALFORMED_REQUEST: "Malformed request",
  UNSUPPORTED_REQUEST_METHOD: "Unsupported request method",
  UNKNOWN_INTENT_FIELDS: "Unknown intent fields",
  MALFORMED_CHAIN_ID: "Malformed chain id",
  MALFORMED_TARGET: "Malformed target",
  MALFORMED_VALUE: "Malformed value",
  CONFLICTING_VALUE_FIELDS: "Conflicting value fields",
  MALFORMED_CALLDATA: "Malformed calldata",
  CONFLICTING_DATA_FIELDS: "Conflicting calldata fields",
  MALFORMED_LABEL: "Malformed label",
});

function rule(code, status, weight, detail, hardDeny = false) {
  return { code, title: RULE_TITLES[code] || code, status, weight, detail, hardDeny };
}

export function toJsonSafe(value) {
  if (value === undefined || value === null) return value;
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "number") return Number.isFinite(value) ? value : String(value);
  if (typeof value === "string" || typeof value === "boolean") return value;
  if (Array.isArray(value)) {
    return value.map((item) => {
      const safe = toJsonSafe(item);
      return safe === undefined ? null : safe;
    });
  }
  if (typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value)) {
      const safe = toJsonSafe(value[key]);
      if (safe !== undefined) out[key] = safe;
    }
    return out;
  }
  return undefined;
}

export function evaluateIntent(rawIntent, policyOverrides = {}) {
  const policy = normalizePolicy(policyOverrides);
  const intent = normalizeIntent(rawIntent);
  const rules = [];
  let decoded = null;

  if (intent.errors.length) {
    for (const { code, detail } of intent.errors) rules.push(rule(code, "fail", 255, detail, true));
  } else {
    if (intent.chainId !== policy.chainId) {
      rules.push(rule("CHAIN_MISMATCH", "fail", 255, `Expected X Layer ${policy.chainId}, received ${intent.chainId}.`, true));
    } else {
      rules.push(rule("CHAIN_OK", "pass", 0, `chainId=${policy.chainId}`));
    }

    const known = policy.knownTargets.get(intent.to);
    if (known) {
      rules.push(rule("KNOWN_TARGET", "pass", 0, known.label));
    } else if (intent.valueWei > 0n) {
      rules.push(rule("UNKNOWN_VALUE_TARGET", "fail", 96,
        `${intent.valueOkb} OKB would be sent to a target outside the policy allowlist.`, true));
    } else {
      rules.push(rule("UNKNOWN_TARGET", "review", 48, "Zero-value call to an address outside the policy allowlist."));
    }

    if (intent.valueWei > policy.maxValueWei) {
      rules.push(rule("VALUE_LIMIT_EXCEEDED", "fail", 96,
        `${intent.valueOkb} OKB (${intent.valueWei} wei) > policy max ${policy.maxValueOkb} OKB (${policy.maxValueWei} wei).`, true));
    } else {
      rules.push(rule("VALUE_OK", "pass", 0, `${intent.valueOkb} OKB ≤ ${policy.maxValueOkb} OKB (compared in wei).`));
    }

    const isTrusted = (address) => policy.trustedRecipients.has(address) || policy.knownTargets.has(address);
    decoded = decodeCalldata(intent.data);
    if (decoded.error) {
      rules.push(rule("ABI_DECODE_FAILED", "fail", 255, `${decoded.error} Calldata that does not decode exactly is never signed.`, true));
    } else if (decoded.signature) {
      rules.push(rule("CALLDATA_DECODED", "pass", 0, `${decoded.signature} decoded canonically.`));
      const { args } = decoded;
      switch (decoded.selector) {
        case SELECTORS.approve:
          if (args.amount === UINT256_MAX) {
            rules.push(rule("UNLIMITED_APPROVAL", "fail", 200, "approve(spender, uint256.max) creates an unbounded token allowance.", true));
          } else if (!isTrusted(args.spender)) {
            rules.push(rule("APPROVAL_UNTRUSTED_SPENDER", "fail", 96,
              `Spender ${args.spender} is neither a known target nor a trusted recipient.`, true));
          } else {
            rules.push(rule("TOKEN_APPROVAL", "review", 56, `Approval amount ${args.amount} (raw units) for ${args.spender}.`));
          }
          break;
        case SELECTORS.setApprovalForAll:
          if (args.approved) {
            rules.push(rule("SET_APPROVAL_FOR_ALL", "fail", 200,
              `setApprovalForAll(${args.operator}, true) grants collection-wide operator rights.`, true));
          } else {
            rules.push(rule("OPERATOR_APPROVAL_REVOKED", "pass", 0, `setApprovalForAll(${args.operator}, false) revokes operator rights.`));
          }
          break;
        case SELECTORS.transfer:
        case SELECTORS.transferFrom:
          if (!isTrusted(args.to)) {
            rules.push(rule("TOKEN_TRANSFER_UNTRUSTED_RECIPIENT", "fail", 96,
              `${args.amount} raw units would move to ${args.to}, which is not a trusted recipient.`, true));
          } else {
            rules.push(rule("TOKEN_TRANSFER", "review", 48, `${args.amount} raw units to trusted recipient ${args.to}.`));
          }
          break;
        case SELECTORS.tapeout: {
          const netlist = validateNetlist(args.netlist, args.nIn, args.nOut);
          if (!netlist.ok) {
            rules.push(rule("TAPEOUT_NETLIST_INVALID", "fail", 255, `${netlist.error}.`, true));
          } else {
            const isAdd8 = args.netlist === ADD8_NETLIST_HEX && args.nIn === BigInt(ADD8_N_IN) && args.nOut === BigInt(ADD8_N_OUT);
            rules.push(rule("TAPEOUT_NETLIST_OK", "pass", 0,
              `${netlist.nNand} NAND gates, ${args.nIn} inputs, ${args.nOut} outputs, forward-only wiring${isAdd8 ? " — identical to the taped ADD8 netlist" : ""}.`));
          }
          break;
        }
        default:
          break;
      }
    }

    if (known) {
      if (intent.data === "0x") {
        rules.push(rule("NO_CALLDATA", "pass", 0, `Plain value transfer to ${known.label}; no method is called.`));
      } else if (known.selectors.includes(decoded.selector)) {
        rules.push(rule("SELECTOR_ALLOWED", "pass", 0, `${decoded.selector} is allowlisted for ${known.label}.`));
        if (!decoded.signature) {
          rules.push(rule("SELECTOR_ABI_UNKNOWN", "review", 48,
            `${decoded.selector} is allowlisted but this engine has no ABI for it; arguments were not inspected.`));
        }
      } else {
        rules.push(rule("SELECTOR_NOT_ALLOWED", "fail", 72,
          known.selectors.length
            ? `${decoded.selector} is not in the allowlist for ${known.label} (${known.selectors.join(", ")}).`
            : `${known.label} is a value-only target; no method calls are allowlisted.`, true));
      }
    }
  }

  const accumulator = accumulateRisk(rules.filter((r) => r.weight > 0).map((r) => r.weight));
  const hardDeny = rules.some((r) => r.hardDeny);
  let decision = "ALLOW";
  if (hardDeny || accumulator.score >= policy.denyThreshold) decision = "DENY";
  else if (accumulator.score >= policy.reviewThreshold) decision = "REVIEW";
  const reasonCodes = rules.filter((r) => r.status !== "pass").map((r) => r.code);

  const commitment = {
    schema: COMMITMENT_SCHEMA,
    engineVersion: ENGINE_VERSION,
    policy: policyCommitment(policy),
    intent: {
      source: intent.source,
      method: intent.method,
      chainId: intent.chainId,
      to: intent.to,
      valueWei: intent.valueWei === null ? null : intent.valueWei.toString(),
      valueOkb: intent.valueOkb,
      valueSource: intent.valueSource,
      data: intent.data,
      label: intent.label,
      raw: toJsonSafe(rawIntent) ?? null,
    },
    calldata: decoded && decoded.selector
      ? { selector: decoded.selector, signature: decoded.signature, args: decoded.args ? toJsonSafe(decoded.args) : null }
      : null,
    rules: rules.map((r) => ({ ...r })),
    accumulator: toJsonSafe(accumulator),
    decision,
    riskScore: accumulator.score,
    reasonCodes,
    circuit: {
      processor: PROCESSOR,
      chainId: CHAIN_ID,
      id: ADD8_CIRCUIT_ID,
      name: "ADD8",
      nNand: ADD8_N_NAND,
      netlistSha256: ADD8_NETLIST_SHA256,
      role: "risk-score accumulator: every add step is evaluated through the taped NAND netlist (local simulation, cross-checked against arithmetic)",
    },
  };

  return {
    decision,
    riskScore: accumulator.score,
    reasonCodes,
    exitCode: EXIT_CODES[decision],
    rules,
    accumulator,
    intent,
    policy,
    calldata: decoded,
    commitment,
  };
}

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

export function canonicalJson(value) {
  if (value === undefined) return "null";
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item === undefined ? null : item)).join(",")}]`;
  if (typeof value === "bigint") return JSON.stringify(value.toString());
  if (typeof value === "number") return Number.isFinite(value) ? JSON.stringify(value) : "null";
  if (value && typeof value === "object") {
    const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

export async function sha256Hex(input) {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function hashCommitment(commitment) {
  return `0x${await sha256Hex(canonicalJson(commitment))}`;
}

// Receipt layout: {schema, evaluatedAt, commitmentHash, commitment, metadata}. Only
// `commitment` is hashed; `metadata` is free-form context (e.g. an on-chain check) and can
// never shadow a committed field.
export async function buildReceipt(result, metadata = {}) {
  if (!result || !isPlainObject(result.commitment)) throw new TypeError("buildReceipt expects an evaluation result with a commitment");
  if (!isPlainObject(metadata)) throw new TypeError("receipt metadata must be a JSON object; it is stored under `metadata` and never overrides committed fields");
  const commitment = toJsonSafe(result.commitment);
  return {
    schema: RECEIPT_SCHEMA,
    evaluatedAt: new Date().toISOString(),
    commitmentHash: await hashCommitment(commitment),
    commitment,
    metadata: toJsonSafe(metadata),
  };
}

function decisionView(commitment) {
  return {
    decision: commitment.decision,
    riskScore: commitment.riskScore,
    reasonCodes: commitment.reasonCodes,
    rules: (commitment.rules || []).map((r) => ({ code: r.code, status: r.status, weight: r.weight, hardDeny: r.hardDeny })),
    intent: commitment.intent
      ? { chainId: commitment.intent.chainId, to: commitment.intent.to, valueWei: commitment.intent.valueWei, data: commitment.intent.data }
      : null,
    calldata: commitment.calldata,
    policy: commitment.policy,
  };
}

// Verifies a receipt offline: schema, engine version, commitment hash, and (by default) a
// re-evaluation of the committed raw intent under the committed policy.
export async function verifyReceipt(receipt, { reevaluate = true } = {}) {
  const checks = [];
  const check = (name, ok, detail) => checks.push({ name, ok, detail });
  if (!isPlainObject(receipt) || !isPlainObject(receipt.commitment)) {
    check("schema", false, "receipt must be an object with a `commitment` object");
    return { valid: false, checks, commitmentHash: null };
  }
  const commitment = receipt.commitment;
  check("schema", receipt.schema === RECEIPT_SCHEMA && commitment.schema === COMMITMENT_SCHEMA,
    `receipt ${receipt.schema} / commitment ${commitment.schema}`);
  check("engineVersion", commitment.engineVersion === ENGINE_VERSION,
    `receipt ${commitment.engineVersion}, this engine ${ENGINE_VERSION}`);
  const recomputed = await hashCommitment(commitment);
  const hashOk = recomputed === receipt.commitmentHash;
  check("commitmentHash", hashOk, hashOk ? `sha256 of the canonical commitment is ${recomputed}` : `receipt states ${receipt.commitmentHash}; the commitment hashes to ${recomputed}`);

  if (reevaluate) {
    try {
      const overrides = policyOverridesFromCommitment(commitment.policy);
      const again = evaluateIntent(commitment.intent ? commitment.intent.raw : undefined, overrides);
      const expected = canonicalJson(decisionView(commitment));
      const actual = canonicalJson(decisionView(again.commitment));
      const same = expected === actual;
      check("reevaluation", same, same
        ? `re-evaluated ${again.decision} (risk ${again.riskScore}) from the committed raw intent and policy`
        : `re-evaluation produced ${again.decision} (risk ${again.riskScore}, ${again.reasonCodes.join(",") || "no reason codes"}), which differs from the committed decision view`);
    } catch (caught) {
      check("reevaluation", false, `re-evaluation failed: ${caught && caught.message ? caught.message : String(caught)}`);
    }
  }

  return { valid: checks.every((c) => c.ok), checks, commitmentHash: recomputed };
}

// ---------------------------------------------------------------------------
// Agent Firewall v2 — AI Treasury / Vault Release pre-sign co-processor
// ---------------------------------------------------------------------------

export class VaultControlError extends Error {
  constructor(message) {
    super(message);
    this.name = "VaultControlError";
    this.code = "VAULT_CONTROL_INVALID";
  }
}

export const RELEASE_EXIT_CODES = Object.freeze({ RELEASE: 0, HOLD: 2, DENY: 3 });

function requireExactKeys(value, allowed, label) {
  if (!isPlainObject(value)) throw new VaultControlError(`${label} must be a JSON object`);
  const extra = Object.keys(value).filter((key) => !allowed.has(key));
  if (extra.length) throw new VaultControlError(`${label}: unknown field(s): ${extra.join(", ")}`);
}

export function normalizeVaultControls(rawControls) {
  requireExactKeys(rawControls, new Set(["vaultId", "spendGuard", "quorum"]), "controls");
  const vaultId = requireNonEmptyString(rawControls.vaultId, "controls.vaultId");

  requireExactKeys(rawControls.spendGuard, new Set(["spentTodayOkb", "dailyLimitOkb"]), "controls.spendGuard");
  let spentTodayWei;
  let dailyLimitWei;
  try {
    spentTodayWei = parseOkbToWei(rawControls.spendGuard.spentTodayOkb);
    dailyLimitWei = parseOkbToWei(rawControls.spendGuard.dailyLimitOkb);
  } catch (caught) {
    throw new VaultControlError(`SpendGuard: ${caught.message}`);
  }
  if (dailyLimitWei <= 0n) throw new VaultControlError("SpendGuard dailyLimitOkb must be greater than zero");

  requireExactKeys(rawControls.quorum, new Set(["threshold", "members"]), "controls.quorum");
  if (rawControls.quorum.threshold !== 2) throw new VaultControlError("Quorum2of3 threshold must be exactly 2");
  if (!Array.isArray(rawControls.quorum.members) || rawControls.quorum.members.length !== 3) {
    throw new VaultControlError("Quorum2of3 requires exactly three members");
  }
  const seen = new Set();
  const members = rawControls.quorum.members.map((member, index) => {
    requireExactKeys(member, new Set(["id", "approved"]), `controls.quorum.members[${index}]`);
    const id = requireNonEmptyString(member.id, `controls.quorum.members[${index}].id`);
    if (seen.has(id)) throw new VaultControlError(`Quorum2of3 duplicate member id "${id}"`);
    seen.add(id);
    if (typeof member.approved !== "boolean") {
      throw new VaultControlError(`controls.quorum.members[${index}].approved must be boolean`);
    }
    return { id, approved: member.approved };
  }).sort((a, b) => a.id.localeCompare(b.id));

  return {
    vaultId,
    spendGuard: {
      spentTodayWei,
      spentTodayOkb: formatOkb(spentTodayWei),
      dailyLimitWei,
      dailyLimitOkb: formatOkb(dailyLimitWei),
    },
    quorum: { threshold: 2, members },
  };
}

function releaseControlsCommitment(controls) {
  return {
    vaultId: controls.vaultId,
    spendGuard: {
      spentTodayWei: controls.spendGuard.spentTodayWei.toString(),
      spentTodayOkb: controls.spendGuard.spentTodayOkb,
      dailyLimitWei: controls.spendGuard.dailyLimitWei.toString(),
      dailyLimitOkb: controls.spendGuard.dailyLimitOkb,
    },
    quorum: {
      threshold: controls.quorum.threshold,
      members: controls.quorum.members.map((member) => ({ ...member })),
    },
  };
}

function releasePackageFromCommitment(commitment) {
  return {
    label: commitment.label || undefined,
    intent: commitment.transaction && commitment.transaction.intent ? commitment.transaction.intent.raw : undefined,
    controls: {
      vaultId: commitment.controls.vaultId,
      spendGuard: {
        spentTodayOkb: commitment.controls.spendGuard.spentTodayOkb,
        dailyLimitOkb: commitment.controls.spendGuard.dailyLimitOkb,
      },
      quorum: {
        threshold: commitment.controls.quorum.threshold,
        members: commitment.controls.quorum.members.map((member) => ({ ...member })),
      },
    },
  };
}

export function evaluateVaultRelease(rawPackage, policyOverrides = {}) {
  requireExactKeys(rawPackage, new Set(["label", "intent", "controls"]), "vault release package");
  if (!present(rawPackage.intent)) throw new VaultControlError("vault release package.intent is required");
  if (!present(rawPackage.controls)) throw new VaultControlError("vault release package.controls is required");
  const label = rawPackage.label === undefined ? null : requireNonEmptyString(rawPackage.label, "vault release package.label");
  const controls = normalizeVaultControls(rawPackage.controls);
  const transaction = evaluateIntent(rawPackage.intent, policyOverrides);

  const requestedWei = typeof transaction.intent.valueWei === "bigint" ? transaction.intent.valueWei : 0n;
  const projectedWei = controls.spendGuard.spentTodayWei + requestedWei;
  const spendPass = projectedWei <= controls.spendGuard.dailyLimitWei;
  const approvals = controls.quorum.members.filter((member) => member.approved).length;
  const quorumPass = approvals >= controls.quorum.threshold;

  const reasonCodes = [];
  if (transaction.decision === "DENY") reasonCodes.push("TRANSACTION_POLICY_DENY");
  else if (transaction.decision === "REVIEW") reasonCodes.push("TRANSACTION_POLICY_REVIEW");
  if (!spendPass) reasonCodes.push("SPEND_GUARD_EXCEEDED");
  if (!quorumPass) reasonCodes.push("QUORUM_NOT_MET");

  let decision = "RELEASE";
  if (transaction.decision === "DENY" || !spendPass) decision = "DENY";
  else if (transaction.decision === "REVIEW" || !quorumPass) decision = "HOLD";

  const gates = {
    transaction: {
      status: transaction.decision === "ALLOW" ? "PASS" : transaction.decision === "REVIEW" ? "HOLD" : "DENY",
      decision: transaction.decision,
      riskScore: transaction.riskScore,
      reasonCodes: [...transaction.reasonCodes],
    },
    spendGuard: {
      status: spendPass ? "PASS" : "DENY",
      scope: "native OKB only",
      spentTodayWei: controls.spendGuard.spentTodayWei.toString(),
      requestWei: requestedWei.toString(),
      projectedWei: projectedWei.toString(),
      dailyLimitWei: controls.spendGuard.dailyLimitWei.toString(),
      spentTodayOkb: controls.spendGuard.spentTodayOkb,
      requestOkb: formatOkb(requestedWei),
      projectedOkb: formatOkb(projectedWei),
      dailyLimitOkb: controls.spendGuard.dailyLimitOkb,
    },
    quorum: {
      status: quorumPass ? "PASS" : "HOLD",
      scheme: "Quorum2of3",
      approvals,
      threshold: controls.quorum.threshold,
      total: controls.quorum.members.length,
      members: controls.quorum.members.map((member) => ({ ...member })),
    },
  };

  const commitment = {
    schema: VAULT_RELEASE_COMMITMENT_SCHEMA,
    engineVersion: ENGINE_VERSION,
    label,
    transaction: toJsonSafe(transaction.commitment),
    controls: releaseControlsCommitment(controls),
    gates,
    decision,
    reasonCodes,
    coProcessor: {
      mode: "deterministic pre-sign transaction co-processor",
      execution: "local policy engine; no wallet, signature or broadcast",
      chainId: CHAIN_ID,
      tapeoutPrimitive: {
        processor: PROCESSOR,
        circuitId: ADD8_CIRCUIT_ID,
        circuit: "ADD8",
        nNand: ADD8_N_NAND,
        netlistSha256: ADD8_NETLIST_SHA256,
        role: "transaction risk-score arithmetic only",
      },
    },
  };

  return {
    decision,
    reasonCodes,
    exitCode: RELEASE_EXIT_CODES[decision],
    transaction,
    controls,
    gates,
    commitment,
  };
}

export async function buildVaultReleaseReceipt(result, metadata = {}) {
  if (!result || !isPlainObject(result.commitment)) throw new TypeError("buildVaultReleaseReceipt expects a vault release result with a commitment");
  if (!isPlainObject(metadata)) throw new TypeError("vault release receipt metadata must be a JSON object");
  const commitment = toJsonSafe(result.commitment);
  return {
    schema: VAULT_RELEASE_RECEIPT_SCHEMA,
    evaluatedAt: new Date().toISOString(),
    commitmentHash: await hashCommitment(commitment),
    commitment,
    metadata: toJsonSafe(metadata),
  };
}

export async function verifyVaultReleaseReceipt(receipt, { reevaluate = true } = {}) {
  const checks = [];
  const check = (name, ok, detail) => checks.push({ name, ok, detail });
  if (!isPlainObject(receipt) || !isPlainObject(receipt.commitment)) {
    check("schema", false, "receipt must be an object with a commitment object");
    return { valid: false, checks, commitmentHash: null };
  }
  const commitment = receipt.commitment;
  check("schema", receipt.schema === VAULT_RELEASE_RECEIPT_SCHEMA && commitment.schema === VAULT_RELEASE_COMMITMENT_SCHEMA,
    `receipt ${receipt.schema} / commitment ${commitment.schema}`);
  check("engineVersion", commitment.engineVersion === ENGINE_VERSION,
    `receipt ${commitment.engineVersion}, this engine ${ENGINE_VERSION}`);
  const recomputed = await hashCommitment(commitment);
  const hashOk = recomputed === receipt.commitmentHash;
  check("commitmentHash", hashOk, hashOk ? `sha256 of the canonical vault release commitment is ${recomputed}` : `receipt states ${receipt.commitmentHash}; commitment hashes to ${recomputed}`);

  if (reevaluate) {
    try {
      const overrides = policyOverridesFromCommitment(commitment.transaction.policy);
      const again = evaluateVaultRelease(releasePackageFromCommitment(commitment), overrides);
      const same = canonicalJson(commitment) === canonicalJson(again.commitment);
      check("reevaluation", same, same
        ? `re-evaluated vault release as ${again.decision} with transaction=${again.transaction.decision}, SpendGuard=${again.gates.spendGuard.status}, Quorum2of3=${again.gates.quorum.status}`
        : `vault release re-evaluation differs from the committed decision path`);
    } catch (caught) {
      check("reevaluation", false, `re-evaluation failed: ${caught && caught.message ? caught.message : String(caught)}`);
    }
  }

  return { valid: checks.every((entry) => entry.ok), checks, commitmentHash: recomputed };
}

// ---------------------------------------------------------------------------
// Read-only on-chain provenance check (eth_call only; never signs or broadcasts)
// ---------------------------------------------------------------------------

function decodeAbiBytes(hexResult) {
  const hex = normalizeHex(hexResult).slice(2);
  if (hex.length < 128) throw new Error("eth_call result is too short for ABI-encoded bytes");
  const offset = Number(BigInt(`0x${hex.slice(0, 64)}`)) * 2;
  if (offset + 64 > hex.length) throw new Error("eth_call result offset is outside the payload");
  const length = Number(BigInt(`0x${hex.slice(offset, offset + 64)}`)) * 2;
  if (offset + 64 + length > hex.length) throw new Error("eth_call result length exceeds the payload");
  return hexToBytes(hex.slice(offset + 64, offset + 64 + length));
}

async function ethCall(rpc, to, data, { fetchImpl = globalThis.fetch, timeoutMs = 8000 } = {}) {
  const controller = typeof AbortController === "function" ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
  try {
    const response = await fetchImpl(rpc, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to, data }, "latest"] }),
      signal: controller ? controller.signal : undefined,
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    if (payload.error) throw new Error(payload.error.message || "rpc error");
    if (!payload.result || payload.result === "0x") throw new Error("empty result");
    return payload.result;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export async function verifyOnchainNetlist({ rpcs = XLAYER_RPCS, fetchImpl = globalThis.fetch, circuitId = ADD8_CIRCUIT_ID } = {}) {
  const errors = [];
  const data = SELECTORS.netlist + padWord(BigInt(circuitId));
  for (const rpc of rpcs) {
    try {
      const raw = await ethCall(rpc, PROCESSOR, data, { fetchImpl });
      const bytes = decodeAbiBytes(raw);
      const sha256 = await sha256Hex(bytes);
      const match = sha256 === ADD8_NETLIST_SHA256 && bytes.length === ADD8_NETLIST_BYTES;
      return {
        status: match ? "MATCH" : "MISMATCH",
        rpc,
        processor: PROCESSOR,
        circuitId,
        bytes: bytes.length,
        sha256,
        expectedSha256: ADD8_NETLIST_SHA256,
        checkedAt: new Date().toISOString(),
        errors,
      };
    } catch (error) {
      errors.push({ rpc, error: error && error.message ? error.message : String(error) });
    }
  }
  return {
    status: "UNVERIFIED",
    processor: PROCESSOR,
    circuitId,
    expectedSha256: ADD8_NETLIST_SHA256,
    checkedAt: new Date().toISOString(),
    errors,
  };
}
