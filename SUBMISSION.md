# TapeOut Genesis Transistor Hackathon — Agent Firewall v2 Submission Pack

Status: **v2 product + browser acceptance complete. Public GitHub/X links must point to this v2 build before the official Google Form is submitted.**

## Positioning

**LeoLabs Agent Firewall v2** is a deterministic **pre-sign transaction co-processor for AI treasuries on X Layer**.

It sits immediately before a signer and evaluates a proposed vault release through three gates:

1. the exact transaction must pass a fail-closed transaction firewall;
2. projected native-OKB spend must stay within **SpendGuard**;
3. **Quorum2of3** must reach two approvals.

The system emits `RELEASE / HOLD / DENY` plus a tamper-evident vault-release receipt that independently re-evaluates the transaction, SpendGuard and quorum state.

The TapeOut primitive is real but deliberately scoped: the existing X Layer Processor stores ADD8 circuitId 1 (122 NAND). Transaction risk-score additions execute through that taped netlist in the deterministic engine, and the browser can read the 854-byte netlist back from X Layer with `eth_call` and SHA-256 match it against the embedded bytes. **Quorum2of3 and SpendGuard are local pre-sign controls; this submission does not claim they are already deployed as on-chain circuits.**

## Google Form fields

### Project Name

LeoLabs Agent Firewall

### Project Description

LeoLabs Agent Firewall v2 is a deterministic pre-sign transaction co-processor for AI treasuries on X Layer. Before a vault release can reach a signer, the exact transaction must pass a fail-closed firewall, native-OKB SpendGuard must remain inside its daily cap, and Quorum2of3 must reach two approvals. It returns RELEASE / HOLD / DENY and a tamper-evident receipt that re-verifies the full decision path. Transaction risk-score arithmetic uses a real TapeOut ADD8 circuit on the existing LeoLabs Processor (circuitId 1, 122 NAND); the browser independently reads its 854-byte netlist from X Layer via eth_call and SHA-256 matches it. Demo mode never connects a wallet, signs or broadcasts.

Processor: `0xa196ab8ef5ae052c13819e73f3cc3f4263faf744`
TapeOut tx: `0xf7fa9ee1e4f05226a211aad101cce2856af62d71b8f609a3c5b48f1ac3047068`
Deploy wallet: `0x1e1a2f7ac1bc6df29a1878c3f26b17dccdc16e15`
Deployment disclosure: 10,000 transistor supply · 0.000066 OKB mint price · create tx `0xf5bc61149d25121fc71f9bf2018eeb036785c1e7395812bf6f8d15ade857195d`

### X Account

@runes_leo

### Telegram

@runes_leo

### Contact Email

Use the existing contact email already stored in the form session.

### GitHub Repository

`PENDING_V2_PUBLIC_GITHUB_URL`

Do not reuse the old Builder Desk PR unless it visibly contains this Agent Firewall v2 source, demo and acceptance evidence.

### X Post Link

`PENDING_V2_PUBLIC_X_POST`

The X post must introduce **Agent Firewall v2**, not the older Builder Desk launch.

## Verified acceptance

- [x] Existing X Layer Processor live: `0xa196...f744`
- [x] Real TapeOut circuit: ADD8, circuitId 1, 122 NAND
- [x] Real tapeout transaction linked
- [x] Full regression: **48 / 48 tests pass**
- [x] Main AI Treasury release: **RELEASE**
- [x] Release receipt: **VALID**
- [x] Browser live acceptance completed
- [x] Browser-side `eth_call netlist(1)`: **MATCH**
- [x] Browser ADD8 self-test: **5 / 5 PASS**
- [x] Quorum2of3 1/3 scenario: **HOLD / BLOCKED**
- [x] SpendGuard breach: **DENY / BLOCKED**
- [x] Unlimited approval: **DENY / risk 200 / BLOCKED**
- [x] Demo exposes no wallet-connect path
- [x] Browser readback evidence: `browser-acceptance-v2.json`; full-page screenshot captured separately for announcement/demo media (SHA-256 `2d85d2908a004ee211f2f8f1f4ecf23237b15327c709cbdfdb84ee896f1d0333`)
- [ ] Push curated v2 source/evidence to public GitHub
- [ ] Publish new Agent Firewall v2 X announcement
- [ ] Put those two public URLs into the Google Form
- [ ] Submit form and capture the final recorded-response receipt

## Judge-facing differentiation

The strongest distinction is the execution boundary, not a generic “AI permission” label:

- exact transaction-intent inspection immediately before signing;
- independent transaction / SpendGuard / Quorum2of3 gates;
- fail-closed ABI, chain, target, value and approval enforcement;
- signer-safe CLI exit codes;
- deterministic, re-verifiable release receipts;
- real X Layer TapeOut netlist provenance for risk arithmetic.

## Scope honesty

The existing Processor and ADD8 circuit are on X Layer mainnet. The **Agent Firewall v2 co-processor itself is local deterministic pre-sign software**. It does not claim that the vault, Quorum2of3 or SpendGuard have been newly deployed on-chain.
