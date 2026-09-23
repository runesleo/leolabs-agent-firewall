#!/usr/bin/env node
// LeoLabs Agent Firewall CLI — pre-sign policy gate for agent pipelines.
//
//   node agent-firewall-cli.mjs evaluate --intent intent.json [--policy policy.json] [--json] [--receipt out.json] [--verify-onchain [--rpc URL]]
//   node agent-firewall-cli.mjs evaluate --scenario tapeoutReal [--json]
//   cat request.json | node agent-firewall-cli.mjs evaluate --json
//   node agent-firewall-cli.mjs verify --receipt out.json [--json] [--no-reevaluate]
//   node agent-firewall-cli.mjs scenarios [--json]
//   node agent-firewall-cli.mjs selftest [--json]
//   node agent-firewall-cli.mjs verify-onchain [--rpc URL] [--json]
//
// Exit codes: 0 ALLOW · 2 REVIEW · 3 DENY · 1 error, invalid policy, invalid receipt (fail closed).
// With --json, stdout carries exactly one JSON document — for errors {"status":"ERROR","code","error"} —
// and stderr stays empty. Without --json, errors are one `error: <message>` line on stderr, never a stack.
// This tool never signs, broadcasts, or connects a wallet.

import { readFileSync, writeFileSync } from "node:fs";
import process from "node:process";

import {
  ADD8,
  EXIT_CODES,
  PolicyError,
  RELEASE_SCENARIOS,
  SCENARIOS,
  VaultControlError,
  buildReceipt,
  buildVaultReleaseReceipt,
  evaluateIntent,
  evaluateVaultRelease,
  runGoldenVectors,
  verifyOnchainNetlist,
  verifyReceipt,
  verifyVaultReleaseReceipt,
} from "./agent-policy-engine.mjs";

const USAGE = `LeoLabs Agent Firewall CLI (X Layer, pre-sign co-processor)

Usage:
  agent-firewall-cli.mjs release --scenario <treasuryRelease|quorumHold|spendGuardDeny|hostileApproval> [--json] [--receipt <out.json>] [--verify-onchain [--rpc <url>]]
  agent-firewall-cli.mjs release --package <release.json> [--policy <file.json>] [--json] [--receipt <out.json>]
  agent-firewall-cli.mjs release            (reads vault release package JSON from stdin)
  agent-firewall-cli.mjs verify-release --receipt <file.json> [--json] [--no-reevaluate]
  agent-firewall-cli.mjs evaluate --intent <file.json> [--policy <file.json>] [--json] [--receipt <out.json>] [--verify-onchain [--rpc <url>]]
  agent-firewall-cli.mjs evaluate --scenario <name> [--json]
  agent-firewall-cli.mjs evaluate            (reads intent JSON from stdin)
  agent-firewall-cli.mjs verify --receipt <file.json> [--json] [--no-reevaluate]
  agent-firewall-cli.mjs scenarios [--json]
  agent-firewall-cli.mjs selftest [--json]
  agent-firewall-cli.mjs verify-onchain [--rpc <url>] [--json]

Vault release package:
  {"intent":{"chainId":196,"to":"0x…","valueOkb":"0.005","data":"0x"},"controls":{"vaultId":"...","spendGuard":{"spentTodayOkb":"0.004","dailyLimitOkb":"0.012"},"quorum":{"threshold":2,"members":[{"id":"a","approved":true},{"id":"b","approved":true},{"id":"c","approved":false}]}}}

Release exit codes: 0 RELEASE, 2 HOLD, 3 DENY, 1 error / invalid policy / invalid controls / invalid receipt.
Transaction exit codes: 0 ALLOW, 2 REVIEW, 3 DENY, 1 error / invalid policy / invalid receipt.`;

const COMMANDS = Object.freeze({
  release: { value: ["package", "policy", "receipt", "scenario", "rpc"], boolean: ["json", "verify-onchain", "help"] },
  "verify-release": { value: ["receipt"], boolean: ["json", "no-reevaluate", "help"] },
  evaluate: { value: ["intent", "policy", "receipt", "scenario", "rpc"], boolean: ["json", "verify-onchain", "help"] },
  verify: { value: ["receipt"], boolean: ["json", "no-reevaluate", "help"] },
  scenarios: { value: [], boolean: ["json", "help"] },
  selftest: { value: [], boolean: ["json", "help"] },
  "verify-onchain": { value: ["rpc"], boolean: ["json", "help"] },
});

class CliError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "CliError";
    this.code = code;
  }
}

function parseArgs(argv, spec) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }
    const eq = arg.indexOf("=");
    const key = eq === -1 ? arg.slice(2) : arg.slice(2, eq);
    if (spec.boolean.includes(key)) {
      if (eq !== -1) throw new CliError("USAGE", `--${key} does not take a value`);
      flags[key] = true;
    } else if (spec.value.includes(key)) {
      const value = eq === -1 ? argv[i + 1] : arg.slice(eq + 1);
      if (value === undefined || (eq === -1 && value.startsWith("--")) || value === "") {
        throw new CliError("USAGE", `--${key} requires a value`);
      }
      if (flags[key] !== undefined) throw new CliError("USAGE", `--${key} given more than once`);
      flags[key] = value;
      if (eq === -1) i += 1;
    } else {
      throw new CliError("USAGE", `unknown flag --${key}`);
    }
  }
  if (positional.length) throw new CliError("USAGE", `unexpected argument ${positional[0]}`);
  return flags;
}

function readJsonFile(path, what, code) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new CliError(code, `could not read ${what} ${path}: ${error.message}`);
  }
}

function readStdin() {
  try {
    return readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

function emitJson(payload) {
  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

function shortData(data) {
  if (data === null || data === undefined) return "—";
  return data.length > 22 ? `${data.slice(0, 22)}…(${(data.length - 2) / 2} bytes)` : data;
}

function printReceipt(receipt) {
  const c = receipt.commitment;
  const lines = [];
  lines.push(`decision   ${c.decision}   risk ${c.riskScore}/255${c.accumulator.saturated ? " (saturated)" : ""}`);
  lines.push(`intent     chain=${c.intent.chainId ?? "—"} to=${c.intent.to ?? "—"} value=${c.intent.valueOkb ?? "—"} OKB${c.intent.valueWei !== null ? ` (${c.intent.valueWei} wei)` : ""} data=${shortData(c.intent.data)}`);
  if (c.calldata) lines.push(`calldata   ${c.calldata.signature || `${c.calldata.selector} (no ABI)`}`);
  lines.push(`reasons    ${c.reasonCodes.length ? c.reasonCodes.join(", ") : "none"}`);
  for (const r of c.rules) {
    const mark = r.status === "pass" ? "ok  " : r.status === "review" ? "warn" : "FAIL";
    lines.push(`  [${mark}] ${r.code.padEnd(36)} ${r.weight ? `+${r.weight}` : ""}`.trimEnd());
  }
  lines.push(`circuit    ADD8 #${c.circuit.id} · ${c.circuit.nNand} NAND · netlist sha256 ${c.circuit.netlistSha256.slice(0, 16)}…`);
  lines.push(`commitment ${receipt.commitmentHash}`);
  if (receipt.metadata && receipt.metadata.onchain) {
    const o = receipt.metadata.onchain;
    lines.push(`onchain    ${o.status}${o.rpc ? ` via ${o.rpc}` : ""}`);
  }
  process.stdout.write(`${lines.join("\n")}\n`);
}

function printVaultReleaseReceipt(receipt) {
  const c = receipt.commitment;
  const tx = c.transaction;
  const spend = c.gates.spendGuard;
  const quorum = c.gates.quorum;
  const lines = [];
  lines.push(`release    ${c.decision}`);
  lines.push(`vault      ${c.controls.vaultId}`);
  lines.push(`tx-policy  ${c.gates.transaction.status} · ${tx.decision} · risk ${tx.riskScore}/255`);
  lines.push(`SpendGuard ${spend.status} · ${spend.spentTodayOkb} + ${spend.requestOkb} = ${spend.projectedOkb} / ${spend.dailyLimitOkb} OKB`);
  lines.push(`Quorum2of3 ${quorum.status} · ${quorum.approvals}/${quorum.total} approved`);
  lines.push(`reasons    ${c.reasonCodes.length ? c.reasonCodes.join(", ") : "none"}`);
  lines.push(`TapeOut    ADD8 #${c.coProcessor.tapeoutPrimitive.circuitId} · ${c.coProcessor.tapeoutPrimitive.nNand} NAND · risk arithmetic only`);
  lines.push(`commitment ${receipt.commitmentHash}`);
  if (receipt.metadata && receipt.metadata.onchain) {
    const o = receipt.metadata.onchain;
    lines.push(`onchain    ${o.status}${o.rpc ? ` via ${o.rpc}` : ""}`);
  }
  process.stdout.write(`${lines.join("\n")}\n`);
}

async function cmdRelease(flags) {
  let rawPackage;
  if (flags.scenario) {
    rawPackage = RELEASE_SCENARIOS[flags.scenario];
    if (!rawPackage) throw new CliError("UNKNOWN_RELEASE_SCENARIO", `unknown vault release scenario ${flags.scenario}`);
  } else if (flags.package) {
    rawPackage = readJsonFile(flags.package, "vault release package", "RELEASE_PACKAGE_READ_FAILED");
  } else {
    const text = readStdin().trim();
    if (!text) throw new CliError("RELEASE_PACKAGE_READ_FAILED", "no vault release package provided (use --package, --scenario, or stdin)");
    try {
      rawPackage = JSON.parse(text);
    } catch (error) {
      throw new CliError("RELEASE_PACKAGE_READ_FAILED", `stdin is not valid JSON: ${error.message}`);
    }
  }

  const policy = flags.policy ? readJsonFile(flags.policy, "policy", "POLICY_READ_FAILED") : {};
  const result = evaluateVaultRelease(rawPackage, policy);
  const metadata = {};
  if (flags["verify-onchain"]) metadata.onchain = await verifyOnchainNetlist(flags.rpc ? { rpcs: [flags.rpc] } : {});
  const receipt = await buildVaultReleaseReceipt(result, metadata);
  if (flags.receipt) {
    try {
      writeFileSync(flags.receipt, `${JSON.stringify(receipt, null, 2)}\n`);
    } catch (error) {
      throw new CliError("RECEIPT_WRITE_FAILED", `could not write receipt ${flags.receipt}: ${error.message}`);
    }
  }
  if (flags.json) emitJson(receipt);
  else printVaultReleaseReceipt(receipt);
  return result.exitCode;
}

async function cmdVerifyRelease(flags) {
  if (!flags.receipt) throw new CliError("USAGE", "verify-release requires --receipt <file.json>");
  const receipt = readJsonFile(flags.receipt, "vault release receipt", "RECEIPT_READ_FAILED");
  const report = await verifyVaultReleaseReceipt(receipt, { reevaluate: !flags["no-reevaluate"] });
  const commitment = receipt && typeof receipt === "object" && receipt.commitment && typeof receipt.commitment === "object" ? receipt.commitment : null;
  const payload = {
    status: report.valid ? "VALID" : "INVALID",
    valid: report.valid,
    receipt: flags.receipt,
    commitmentHash: report.commitmentHash,
    decision: commitment ? commitment.decision ?? null : null,
    transactionDecision: commitment && commitment.transaction ? commitment.transaction.decision ?? null : null,
    checks: report.checks,
  };
  if (flags.json) {
    emitJson(payload);
  } else {
    process.stdout.write(`vault receipt ${payload.status}   ${flags.receipt}\n`);
    if (commitment) process.stdout.write(`committed  ${payload.decision} · tx ${payload.transactionDecision}\n`);
    for (const c of report.checks) process.stdout.write(`  [${c.ok ? "ok  " : "FAIL"}] ${c.name.padEnd(16)} ${c.detail}\n`);
  }
  return report.valid ? 0 : EXIT_CODES.ERROR;
}

async function cmdEvaluate(flags) {
  let rawIntent;
  if (flags.scenario) {
    rawIntent = SCENARIOS[flags.scenario];
    if (!rawIntent) throw new CliError("UNKNOWN_SCENARIO", `unknown scenario ${flags.scenario}; run 'scenarios'`);
  } else if (flags.intent) {
    rawIntent = readJsonFile(flags.intent, "intent", "INTENT_READ_FAILED");
  } else {
    const text = readStdin().trim();
    if (!text) throw new CliError("INTENT_READ_FAILED", "no intent provided (use --intent, --scenario, or stdin)");
    try {
      rawIntent = JSON.parse(text);
    } catch (error) {
      throw new CliError("INTENT_READ_FAILED", `stdin is not valid JSON: ${error.message}`);
    }
  }

  const policy = flags.policy ? readJsonFile(flags.policy, "policy", "POLICY_READ_FAILED") : {};
  const result = evaluateIntent(rawIntent, policy); // PolicyError propagates → exit 1

  const metadata = {};
  if (flags["verify-onchain"]) {
    metadata.onchain = await verifyOnchainNetlist(flags.rpc ? { rpcs: [flags.rpc] } : {});
  }
  const receipt = await buildReceipt(result, metadata);

  if (flags.receipt) {
    try {
      writeFileSync(flags.receipt, `${JSON.stringify(receipt, null, 2)}\n`);
    } catch (error) {
      throw new CliError("RECEIPT_WRITE_FAILED", `could not write receipt ${flags.receipt}: ${error.message}`);
    }
  }
  if (flags.json) emitJson(receipt);
  else printReceipt(receipt);
  return result.exitCode;
}

async function cmdVerify(flags) {
  if (!flags.receipt) throw new CliError("USAGE", "verify requires --receipt <file.json>");
  const receipt = readJsonFile(flags.receipt, "receipt", "RECEIPT_READ_FAILED");
  const report = await verifyReceipt(receipt, { reevaluate: !flags["no-reevaluate"] });
  const commitment = receipt && typeof receipt === "object" && receipt.commitment && typeof receipt.commitment === "object" ? receipt.commitment : null;
  const payload = {
    status: report.valid ? "VALID" : "INVALID",
    valid: report.valid,
    receipt: flags.receipt,
    commitmentHash: report.commitmentHash,
    decision: commitment ? commitment.decision ?? null : null,
    riskScore: commitment ? commitment.riskScore ?? null : null,
    checks: report.checks,
  };
  if (flags.json) {
    emitJson(payload);
  } else {
    process.stdout.write(`receipt    ${payload.status}   ${flags.receipt}\n`);
    if (commitment) process.stdout.write(`committed  ${payload.decision} risk ${payload.riskScore}\n`);
    for (const c of report.checks) process.stdout.write(`  [${c.ok ? "ok  " : "FAIL"}] ${c.name.padEnd(16)} ${c.detail}\n`);
  }
  return report.valid ? 0 : EXIT_CODES.ERROR;
}

async function cmdScenarios(flags) {
  const rows = Object.entries(SCENARIOS).map(([key, scenario]) => {
    const r = evaluateIntent(scenario);
    return { key, label: scenario.label, decision: r.decision, riskScore: r.riskScore, reasonCodes: r.reasonCodes };
  });
  if (flags.json) {
    emitJson(rows);
  } else {
    for (const row of rows) {
      process.stdout.write(`${row.key.padEnd(20)} ${row.decision.padEnd(7)} ${String(row.riskScore).padStart(3)}  ${row.label}${row.reasonCodes.length ? `  [${row.reasonCodes.join(", ")}]` : ""}\n`);
    }
  }
  return 0;
}

async function cmdSelftest(flags) {
  const vectors = runGoldenVectors();
  const ok = vectors.every((v) => v.ok);
  const payload = {
    status: ok ? "PASS" : "FAIL",
    circuit: { id: ADD8.circuitId, nNand: ADD8.nNand, netlistBytes: ADD8.netlistBytes, netlistSha256: ADD8.netlistSha256 },
    vectors,
  };
  if (flags.json) {
    emitJson(payload);
  } else {
    process.stdout.write(`ADD8 netlist selftest: ${payload.status} (${vectors.filter((v) => v.ok).length}/${vectors.length} vectors through ${ADD8.nNand} NAND)\n`);
    for (const v of vectors) process.stdout.write(`  ${v.a} + ${v.b} + ${v.cin} = ${v.got} ${v.ok ? "ok" : `EXPECTED ${v.expect}`}\n`);
  }
  return ok ? 0 : EXIT_CODES.ERROR;
}

async function cmdVerifyOnchain(flags) {
  const report = await verifyOnchainNetlist(flags.rpc ? { rpcs: [flags.rpc] } : {});
  if (flags.json) {
    emitJson(report);
  } else {
    process.stdout.write(`on-chain netlist(${report.circuitId}) @ ${report.processor}: ${report.status}\n`);
    if (report.rpc) process.stdout.write(`  rpc ${report.rpc} · ${report.bytes} bytes · sha256 ${report.sha256}\n`);
    for (const e of report.errors || []) process.stdout.write(`  ${e.rpc}: ${e.error}\n`);
  }
  return report.status === "MATCH" ? 0 : EXIT_CODES.ERROR;
}

function reportError(error, asJson) {
  const code = error instanceof CliError ? error.code : error instanceof PolicyError ? error.code : error instanceof VaultControlError ? error.code : "INTERNAL_ERROR";
  const message = error && error.message ? error.message : String(error);
  if (asJson) {
    process.stdout.write(`${JSON.stringify({ status: "ERROR", code, error: message })}\n`);
  } else {
    process.stderr.write(`error: ${message}\n`);
  }
  return EXIT_CODES.ERROR;
}

async function main(argv) {
  const asJson = argv.includes("--json");
  try {
    const command = argv[0];
    if (!command || command === "--help" || command === "help") {
      if (asJson) throw new CliError("USAGE", "missing command (release | verify-release | evaluate | verify | scenarios | selftest | verify-onchain)");
      process.stdout.write(`${USAGE}\n`);
      return command ? 0 : EXIT_CODES.ERROR;
    }
    const spec = COMMANDS[command];
    if (!spec) throw new CliError("UNKNOWN_COMMAND", `unknown command "${command}" (release | verify-release | evaluate | verify | scenarios | selftest | verify-onchain)`);
    const flags = parseArgs(argv.slice(1), spec);
    if (flags.help) {
      process.stdout.write(`${USAGE}\n`);
      return 0;
    }
    switch (command) {
      case "release":
        return await cmdRelease(flags);
      case "verify-release":
        return await cmdVerifyRelease(flags);
      case "evaluate":
        return await cmdEvaluate(flags);
      case "verify":
        return await cmdVerify(flags);
      case "scenarios":
        return await cmdScenarios(flags);
      case "selftest":
        return await cmdSelftest(flags);
      case "verify-onchain":
        return await cmdVerifyOnchain(flags);
      default:
        throw new CliError("UNKNOWN_COMMAND", `unknown command "${command}"`);
    }
  } catch (error) {
    return reportError(error, asJson);
  }
}

const ARGV = process.argv.slice(2);
main(ARGV).then(
  (code) => {
    process.exitCode = code;
  },
  (error) => {
    process.exitCode = reportError(error, ARGV.includes("--json"));
  },
);
