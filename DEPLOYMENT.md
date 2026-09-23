# Public X Layer Deployment Disclosure

These are the public deployment facts used by the Agent Firewall v2 hackathon submission.

## Processor

- Network: X Layer
- Chain ID: `196`
- Factory: `0x1f09daefa827f02cbb40967cc91b259763760761`
- Processor: `0xa196ab8ef5ae052c13819e73f3cc3f4263faf744`
- Transistors: `0x37b97b180919bb40d8060f3497c9c243b9c1caf5`
- Deploy wallet: `0x1e1a2f7ac1bc6df29a1878c3f26b17dccdc16e15`
- Processor name: `LeoLabs Builder Desk`
- Symbol: `LEOLABS`
- Transistor supply: **10,000**
- Mint price: **0.000066 OKB / transistor**
- Factory create fee paid: **0.0066 OKB**
- Create transaction: `0xf5bc61149d25121fc71f9bf2018eeb036785c1e7395812bf6f8d15ade857195d`

The fixed transistor supply is the public supply bound for this Processor. Agent Firewall v2 reuses this already-live Processor; it does not redeploy it.

## TapeOut circuit

- Circuit: `ADD8`
- Circuit ID: `1`
- NAND gates: **122**
- Netlist bytes: **854**
- Netlist SHA-256: `02fe72d480e686551ea00cc03ca11857225bfed4845a89a903649118e3723eea`
- NAND mint transaction: `0x63160f5bd22ac6dca4b2d20436e9eb329e91d1e52c065bb55c221a8dd322062a`
- TapeOut transaction: `0xf7fa9ee1e4f05226a211aad101cce2856af62d71b8f609a3c5b48f1ac3047068`

Browser acceptance independently read `netlist(1)` from the Processor on X Layer and matched all 854 bytes to the embedded ADD8 netlist.

## Scope

The Processor and ADD8 circuit above are on X Layer mainnet. Agent Firewall v2's transaction rules, SpendGuard and Quorum2of3 remain local deterministic pre-sign software in this MVP.
