# LeoLabs Agent Firewall v2 — 90-second Judge Demo

## 0–12s — Problem + product

AI agents can reason correctly and still hand a dangerous transaction to a signer.

**LeoLabs Agent Firewall v2** is a deterministic **pre-sign transaction co-processor** for AI treasuries on X Layer. A vault release reaches the signer only when three independent gates clear:

1. exact transaction firewall;
2. native-OKB **SpendGuard**;
3. **Quorum2of3** approval.

The demo never connects a wallet, signs, or broadcasts.

## 12–28s — Real TapeOut provenance

Point to the right-side provenance panel:

- X Layer chainId `196`
- Processor `0xa196ab8ef5ae052c13819e73f3cc3f4263faf744`
- ADD8 circuitId `1`
- `122 NAND`
- embedded netlist SHA-256 `02fe72d480e686551ea00cc03ca11857225bfed4845a89a903649118e3723eea`

Click **Verify TapeOut netlist (read-only)**.

Expected: **MATCH**.

Explain: the browser performs `eth_call netlist(1)`, decodes 854 bytes, hashes them, and verifies that the exact taped ADD8 bytes match the arithmetic primitive embedded in this build.

## 28–48s — Main AI Treasury release

Select **AI Treasury release · 2/3 approved**.

Expected:

- decision: **RELEASE**
- Transaction Firewall: `PASS · ALLOW · risk 0`
- SpendGuard: `0.004 + 0.005 = 0.009 / 0.012 OKB`
- Quorum2of3: `PASS · 2/3 approved`
- Signer action: **ELIGIBLE FOR SIGNER**

Click **Verify release receipt**.

Expected: **VALID**.

The receipt commits to the normalized transaction, transaction-policy decision, SpendGuard state and Quorum2of3 state, then re-evaluates the complete release path.

## 48–68s — Two control-plane vetoes

Select **Quorum hold · only 1/3**.

Expected:

- **HOLD**
- `QUORUM_NOT_MET`
- signer action: **BLOCKED**

Then select **SpendGuard deny · daily cap**.

Expected:

- **DENY**
- `SPEND_GUARD_EXCEEDED`
- projected spend `0.015 OKB > 0.012 OKB`
- signer action: **BLOCKED**

## 68–80s — Hostile transaction veto

Select **Firewall deny · unlimited approval**.

Expected:

- **DENY**
- Transaction Firewall: `DENY · DENY · risk 200`
- signer action: **BLOCKED**

The important point: even with budget and quorum available, the exact transaction can still veto the release.

## 80–90s — Agent integration + scope honesty

Show the CLI block:

- `release`: exit `0 = RELEASE`, `2 = HOLD`, `3 = DENY`, `1 = malformed input/control/receipt`
- `verify-release`: independently verifies the committed release receipt
- `verify-onchain`: read-only X Layer provenance check

Close with:

> Agent Firewall v2 protects the final execution boundary before signing. Quorum2of3 and SpendGuard are deterministic local pre-sign controls; TapeOut's real ADD8 circuit is the verifiable arithmetic primitive used in transaction-risk accumulation.

## Acceptance evidence

Latest browser live acceptance: `browser-acceptance-v2.json`

A full-page screenshot was captured separately for announcement/demo media (SHA-256 `2d85d2908a004ee211f2f8f1f4ecf23237b15327c709cbdfdb84ee896f1d0333`); repo hygiene excludes binary assets from this artifact path.

Verified paths:

- RELEASE + receipt VALID
- browser-side X Layer netlist MATCH
- Quorum HOLD
- SpendGuard DENY
- hostile approval DENY
- 5/5 browser ADD8 vectors PASS
- no wallet UI

## Demo safety

The judge demo is local/read-only except for public X Layer RPC `eth_call`. It does not connect a wallet, request accounts, sign, broadcast, deploy, mint, tape out, spend funds, post to X, or submit the hackathon form.
