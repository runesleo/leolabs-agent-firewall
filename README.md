# LeoLabs Agent Firewall v2 — AI Treasury pre-sign co-processor on X Layer

- **Live demo:** https://runesleo.github.io/leolabs-agent-firewall/
- **Public source:** https://github.com/runesleo/leolabs-agent-firewall

Deterministic policy engine + CLI + browser inspector that sits **in front of the signer** of an AI treasury on X Layer (`eip155:196`). It never connects a wallet, never signs, never broadcasts.

The v2 main path is an **AI Treasury / Vault Release**: a release reaches the signer only when the exact transaction passes the firewall, native-OKB **SpendGuard** remains inside its daily cap, and **Quorum2of3** reaches two approvals. The result is `RELEASE / HOLD / DENY` plus a vault-release receipt that re-verifies all three gates.

The transaction firewall remains fail-closed: it inspects the exact transaction about to be signed and rejects unsafe or ambiguous chain / target / value / calldata / approval conditions. TapeOut's real ADD8 circuit is used only for transaction risk-score arithmetic; SpendGuard and quorum are deterministic local pre-sign controls, not claimed as on-chain circuits.

Local browser acceptance readback is published in [`browser-acceptance-v2.json`](./browser-acceptance-v2.json); the deployed Pages build is independently verified in [`public-pages-acceptance.json`](./public-pages-acceptance.json) with all checks passing. A full-page screenshot was also captured for announcement/demo media (SHA-256 `2d85d2908a004ee211f2f8f1f4ecf23237b15327c709cbdfdb84ee896f1d0333`); repository hygiene intentionally excludes binary assets from this artifact path.

Given a transaction intent it returns:

- `ALLOW` / `REVIEW` / `DENY` (CLI exit code `0` / `2` / `3`; `1` = error, invalid policy or invalid receipt — fail closed)
- machine-readable reason codes and the rule table that produced them
- a 0–255 risk score **added by the taped ADD8 circuit** (122-NAND netlist, circuitId 1 on the LeoLabs Processor), with a per-step trace and carry-out saturation
- a receipt whose `commitment` (full normalized policy, raw + normalized intent, decoded calldata, every rule row, accumulator trace, decision) is hashed with SHA-256 over canonical JSON, and can be re-verified offline with `verify`

## Fail-closed contract

- An **invalid policy** throws `PolicyError` before anything is evaluated (CLI: exit `1`, code `POLICY_INVALID`). There is no fallback to defaults for a bad field.
- An **invalid intent** never throws: it is evaluated to `DENY` with a schema reason code, and still gets a receipt.
- Native value is handled as **exact wei** (`BigInt`); OKB amounts are parsed as decimal strings. Floats never reach a comparison.
- Calldata for every selector the engine knows must **decode completely and canonically**; anything else is `ABI_DECODE_FAILED` (hard deny).
- A known target's `selectors` list is exhaustive. **An empty list means value-only**: any non-empty calldata to that target is `SELECTOR_NOT_ALLOWED`. There is no "unrestricted" setting.

## Intent schema

Plain intent: `{chainId, to, data, <value>, label?}` plus ignored standard tx fields (`from, gas, gasLimit, gasPrice, maxFeePerGas, maxPriorityFeePerGas, nonce, type, accessList`). Any other field → `UNKNOWN_INTENT_FIELDS`.

| Field | Accepted | Otherwise |
|---|---|---|
| `chainId` | integer number, decimal string, or `0x` hex string; required | `MALFORMED_CHAIN_ID` |
| `to` | `0x` + 40 hex digits (lowercase `0x` prefix; digit case is free) | `MALFORMED_TARGET` |
| `data` (alias `input`) | `0x` (empty) or `0x` + even-length hex of ≥ 4 bytes; if both `data` and `input` are given they must be identical | `MALFORMED_CALLDATA` / `CONFLICTING_DATA_FIELDS` |
| value | **exactly one** of `valueOkb` (decimal string or number, ≤ 18 decimals), `valueWei` (decimal or `0x` hex string, or bigint — never a JS number), `value` (`0x` hex wei, EIP-1193 style); omitted = 0 | `MALFORMED_VALUE`; two or more → `CONFLICTING_VALUE_FIELDS` |
| `label` | string | `MALFORMED_LABEL` |

EIP-1193 envelope: `{"method":"eth_sendTransaction"|"eth_signTransaction","params":[tx],"chainId"?,"label"?}`. The transaction object carries native value **only** as `value` (`0x` hex wei); `valueOkb`/`valueWei` inside it → `CONFLICTING_VALUE_FIELDS`. Other methods → `UNSUPPORTED_REQUEST_METHOD`; `params` not exactly one object → `MALFORMED_REQUEST`. A `chainId` given both on the envelope and on the transaction must agree.

## Default policy

| Rule | Effect |
|---|---|
| schema violation (codes above) | hard DENY, evaluation stops at the schema stage |
| chain ≠ 196 | hard DENY (`CHAIN_MISMATCH`) |
| native value to an address outside the allowlist | hard DENY (`UNKNOWN_VALUE_TARGET`) |
| zero-value call to an unknown address | REVIEW (`UNKNOWN_TARGET`, +48) |
| native value above the ceiling (default 0.02 OKB), compared in wei | hard DENY (`VALUE_LIMIT_EXCEEDED`) |
| calldata of a known selector does not decode exactly | hard DENY (`ABI_DECODE_FAILED`) |
| `approve(spender, uint256.max)` | hard DENY (`UNLIMITED_APPROVAL`) |
| `approve` to a spender that is neither a known target nor a trusted recipient | hard DENY (`APPROVAL_UNTRUSTED_SPENDER`) |
| bounded `approve` to a known spender | REVIEW (`TOKEN_APPROVAL`, +56) |
| `setApprovalForAll(_, true)` | hard DENY (`SET_APPROVAL_FOR_ALL`) |
| `transfer` / `transferFrom` to an untrusted recipient | hard DENY (`TOKEN_TRANSFER_UNTRUSTED_RECIPIENT`) |
| `transfer` / `transferFrom` to a trusted recipient | REVIEW (`TOKEN_TRANSFER`, +48) |
| `tapeout(bytes,uint32,uint32)` whose netlist is not a well-formed NAND netlist | hard DENY (`TAPEOUT_NETLIST_INVALID`) |
| method not in the allowlist of a known target (including an empty allowlist) | hard DENY (`SELECTOR_NOT_ALLOWED`) |
| allowlisted method the engine has no ABI for | REVIEW (`SELECTOR_ABI_UNKNOWN`, +48) — arguments were not inspected |

Known targets by default: the LeoLabs Processor (`tapeout`), LEOLABS Transistors (`mint`), the X Layer TapeOut factory (`createCPU`), and X Layer USDT (`approve` / `transfer` / `transferFrom`). Trusted recipient by default: the deploy wallet. Empty calldata to a known target is a plain value transfer and is only subject to the value ceiling.

Soft weights are summed through the ADD8 netlist; `riskScore ≥ reviewThreshold (40)` → REVIEW, `≥ denyThreshold (80)` or any hard rule → DENY.

### Decoded ABIs

`tapeout(bytes,uint32,uint32)`, `mint(uint256,uint256)`, `withdraw()`, `createCPU(string,string,string,uint256,uint256)`, `approve(address,uint256)`, `setApprovalForAll(address,bool)`, `transfer(address,uint256)`, `transferFrom(address,address,uint256)`, `netlist(uint256)`, `name()`. Decoding accepts only the canonical encoding: head offsets must point exactly where the tightly packed tail starts, `bytes`/`string` padding must be zero, `string` must be valid UTF-8, address words must have zero upper 12 bytes, `bool` must be 0 or 1, `uint32` must fit, and no bytes may follow the last argument. Tapeout netlists must consist of 7-byte NAND gates (`0x00` + two 3-byte signal ids) that only reference constants, inputs or earlier gates, with `1 ≤ nOut ≤ gate count`; the Processor's output-mapping convention is not modelled.

### Policy file

`--policy policy.json` overrides top-level keys of `DEFAULT_POLICY` (`agent-policy-engine.mjs`); `knownTargets` and `trustedRecipients` replace the defaults wholesale. Validation is strict:

- allowed keys: `name, version, chainId, maxValueOkb, maxValueWei, reviewThreshold, denyThreshold, knownTargets, trustedRecipients` — anything else is rejected
- `maxValueOkb` (decimal string or number, ≤ 18 decimals) **or** `maxValueWei` (decimal / `0x` hex string), never both
- `reviewThreshold` and `denyThreshold`: integers 1–255 with `reviewThreshold < denyThreshold`
- `chainId`: positive integer number
- `knownTargets`: object keyed by `0x` address, each value exactly `{label: non-empty string, selectors: [4-byte 0x selectors]}`; duplicates (case-insensitive) are rejected
- `trustedRecipients`: array of `0x` addresses, no duplicates

## Run the inspector

From this directory:

```bash
python3 -m http.server 8787 --bind 127.0.0.1
```

Open `http://127.0.0.1:8787/agent-firewall.html`. The v2 scenario buttons cover the primary AI Treasury release plus three veto paths: insufficient Quorum2of3, SpendGuard daily-cap breach, and an unlimited-approval transaction blocked by the transaction firewall. The main release shows all three gates and whether the transaction is eligible to reach a signer.

“Verify TapeOut netlist (read-only)” performs `eth_call netlist(1)` against the existing Processor and compares SHA-256 with the embedded ADD8 netlist. “Verify release receipt” recomputes the commitment hash and re-evaluates transaction policy, SpendGuard and Quorum2of3. Latest browser acceptance readback is in `browser-acceptance-v2.json`; the separately captured full-page screenshot is kept outside the repository artifact path for public announcement/demo media.

## Use it from an agent (CLI)

```bash
node agent-firewall-cli.mjs scenarios                         # transaction scenarios
node agent-firewall-cli.mjs selftest                          # golden vectors through the 122-NAND netlist
node agent-firewall-cli.mjs release --scenario treasuryRelease # exit 0 = RELEASE
node agent-firewall-cli.mjs release --scenario quorumHold      # exit 2 = HOLD
node agent-firewall-cli.mjs release --scenario spendGuardDeny  # exit 3 = DENY
node agent-firewall-cli.mjs verify-release --receipt vault-release.json
node agent-firewall-cli.mjs evaluate --scenario tapeoutReal    # transaction-only path, exit 0
node agent-firewall-cli.mjs evaluate --scenario tokenDrain     # transaction-only path, exit 3
node agent-firewall-cli.mjs verify-onchain                     # read-only eth_call; exit 0 only on MATCH

# gate a live intent: stdin or --intent file, optional --policy, receipt to file
echo '{"chainId":196,"to":"0x…","valueWei":"1300000000000000","data":"0x…"}' \
  | node agent-firewall-cli.mjs evaluate --json --receipt receipt.json

# re-verify a receipt offline (hash + re-evaluation); exit 0 = valid, 1 = invalid
node agent-firewall-cli.mjs verify --receipt receipt.json --json
```

Flags are strict: unknown flags, missing flag values and stray arguments are errors. `--verify-onchain` (optionally `--rpc <url>`) attaches the netlist check to `metadata.onchain`.

### `--json` contract

With `--json`, stdout carries **exactly one JSON document** and stderr stays empty, including on errors, which are `{"status":"ERROR","code":"<CODE>","error":"<message>"}` with exit `1`. Error codes: `USAGE`, `UNKNOWN_COMMAND`, `UNKNOWN_SCENARIO`, `INTENT_READ_FAILED`, `POLICY_READ_FAILED`, `POLICY_INVALID`, `RECEIPT_READ_FAILED`, `RECEIPT_WRITE_FAILED`, `INTERNAL_ERROR`. Without `--json`, errors are a single `error: <message>` line on stderr and nothing on stdout; stack traces are never printed.

### Receipt

```json
{
  "schema": "leolabs_agent_firewall_receipt/v3",
  "evaluatedAt": "…",
  "commitmentHash": "0x…",
  "commitment": {
    "schema": "leolabs_agent_firewall_commitment/v3",
    "engineVersion": "0.4.0",
    "policy": { "name", "version", "chainId", "maxValueWei", "reviewThreshold", "denyThreshold", "knownTargets": [{ "address", "label", "selectors" }], "trustedRecipients" },
    "intent": { "source", "method", "chainId", "to", "valueWei", "valueOkb", "valueSource", "data", "label", "raw" },
    "calldata": { "selector", "signature", "args" },
    "rules": [ { "code", "title", "status", "weight", "detail", "hardDeny" } ],
    "accumulator": { "score", "saturated", "steps", "engine", "gatesPerStep" },
    "decision": "ALLOW | REVIEW | DENY", "riskScore": 0, "reasonCodes": [],
    "circuit": { "processor", "chainId", "id", "name", "nNand", "netlistSha256", "role" }
  },
  "metadata": {}
}
```

`commitmentHash` = `0x` + SHA-256 of the canonical JSON (sorted keys, no whitespace) of `commitment` only. `metadata` is free-form context and is never hashed and can never shadow a committed field. `verify` checks the schema, the engine version, the hash, and re-evaluates `commitment.intent.raw` under `commitment.policy`, comparing decision, risk score, reason codes, rule codes/status/weights, normalized intent, decoded calldata and policy.

## Test

```bash
node --test agent-policy-engine.test.mjs
```

Covers: netlist bytes/sha256 pinned to the weapon-pack evidence, gate-count and wiring sanity, golden vectors and a dense sweep through the netlist, saturation, every transaction scenario decision, strict intent/policy/ABI fail-closed paths, exact-wei handling, receipt commitment/verification, mocked on-chain MATCH/MISMATCH/UNVERIFIED, CLI contracts, plus Agent Firewall v2 vault-release behavior: AI Treasury RELEASE, Quorum2of3 HOLD, SpendGuard DENY, transaction-firewall veto, malformed quorum fail-closed behavior, full vault-release receipt binding and `release` / `verify-release` signer-safe exit codes. Current regression: **48 / 48 pass**. No network access in tests.

## Live X Layer evidence reused (no new deployment)

- Processor: `0xa196ab8ef5ae052c13819e73f3cc3f4263faf744` (`name()` = LeoLabs Builder Desk, `symbol()` = LEOLABS)
- Deployment: 10,000 transistor supply, 0.000066 OKB mint price, create tx `0xf5bc61149d25121fc71f9bf2018eeb036785c1e7395812bf6f8d15ade857195d`
- Circuit: ADD8, circuitId `1`, 122 NAND, netlist 854 bytes, sha256 `02fe72d480e686551ea00cc03ca11857225bfed4845a89a903649118e3723eea`
- Tapeout tx: `0xf7fa9ee1e4f05226a211aad101cce2856af62d71b8f609a3c5b48f1ac3047068`
- Clean public deployment disclosure: [`DEPLOYMENT.md`](./DEPLOYMENT.md)
- Circuit evidence: `add8-weapon-pack.json`, `xlayer-add8-tapeout-receipt.json`

`add8-netlist.mjs` is generated from `add8-weapon-pack.json` by `gen_add8_netlist_module.py`; regenerate it instead of editing it.

## Scope honesty

circuitId 1 is an 8-bit adder. The firewall's rule logic runs in this local deterministic engine; only the risk-score addition is executed through the taped netlist (bit-for-bit simulation, cross-checked against arithmetic on every step, hash-verifiable against the chain). A dedicated on-chain policy circuit would be a later tapeout — it costs gas and is not part of this demo. EIP-55 checksums are not validated (no keccak without dependencies); addresses are compared case-insensitively.

## File roles

### PRODUCT (demo path)
- `agent-policy-engine.mjs` — policy engine, Quorum2of3 + SpendGuard vault-release controls, ADD8 netlist interpreter, transaction/vault receipts and read-only on-chain check
- `agent-firewall-cli.mjs` — CLI for agent pipelines (`release`, `verify-release`, transaction evaluation, receipts, `verify-onchain`)
- `agent-firewall.html` — Agent Firewall v2 AI Treasury browser inspector (static, no build step)
- `browser-acceptance-v2.json` — live browser DOM/readback acceptance evidence; screenshot is kept as external announcement/demo media per repository hygiene
- `add8-netlist.mjs` — generated netlist module (from `add8-weapon-pack.json`)
- `gen_add8_netlist_module.py` — generator for the module above
- `agent-policy-engine.test.mjs` — dependency-free tests

### KEEP (evidence / reproducibility)
- `add8-weapon-pack.json`, `add8-netlist.hex`, `build_add8_netlist.py` — circuit construction and calldata
- `xlayer-add8-tapeout-receipt.json`, `xlayer-create-done.json`, `xlayer-ready-receipt.json`, `add8-tx-scan.json` — on-chain receipts
- `add8-demo.html` — narrow arithmetic proof page (superseded by the inspector, still valid evidence)

### EXCLUDE FROM DEMO PATH (operational history; can move money, sign, submit, or post)
- `add8_tapeout_autopilot.py`, `poll_funding_and_tapeout.py`, `ai_wallet_agentic_*.cjs`, `*-receipt.json` for funding/top-up
- `submit_hackathon_form*.py`, `form-submit-receipt*.json`
- `post_bip_tweet_cdp*.py`, `bip-post-receipt.json`
- tapeout.net probing scripts and captures (`ui_*.py`, `probe_*.py`, `parse_*.py`, `fetch_canvas_js.py`, `*.out`, `bundle-*.json`, `l2-*.js*`, `CreateCpu-*.js*`, `create-i18n.json`, `chunk-parse-summary.json`, `crosschain-factory-probe.json`, `deployfee-bounded.json`, `l2-addrs.json`, `open_wallet_connect.py`)

Nothing in the product path imports or calls anything in the excluded group.
