# Real-World Web3 Incident Case Studies — Deep Dive

> A forensic walk-through of twelve of the most instructive Web3 exploits between 2021 and 2023. Each case includes the timeline, the specific vulnerability in the contract or off-chain infrastructure, the attacker's technique, the fund-flow, and the red-team lessons that translate into actionable attack surface for engagement planning.

---

## Overview

The total value stolen from Web3 protocols between 2021 and 2023 exceeds **$11 billion** when bridging, DeFi, and exchange exploits are aggregated. The incidents below are not cherry-picked anomalies — they are the canonical patterns that red teams, smart contract auditors, and on-chain sleuths replay when assessing new targets. Roughly **64% of all stolen value** in 2022 alone came from bridge exploits, and the median time-to-exploitation after a vulnerability was introduced was **less than 48 hours**.

This catalog is structured for adversarial reuse. Each entry maps directly to a kill-chain phase (recon → weaponize → deliver → exploit → exfiltrate → launder) and references the underlying weakness class (CWE-xyz analogues, SWC Registry IDs, and EIP numbers where applicable). When planning a Web3 engagement, scan the target protocol against these twelve failure modes before writing any payload — most real losses are repetitions of known anti-patterns, not novel zero-days.

The recurring root causes:

- **Access control gaps** on privileged functions (Ronin, Wormhole pre-commit)
- **Signature verification flaws** (Wormhole, Nomad, Poly Network)
- **Price/oracle manipulation** via flash loans (Euler, BonqDAO, Mango)
- **Compiler/runtime bugs** in dependencies (Curve / Vyper)
- **Governance capture** (Beanstalk, HashedDAO-style attacks)

---

## Case Study 1 — Ronin Bridge ($625M, March 2022, Lazarus Group)

**Timeline**
- 2021-11: Axie Infinity's growth led Sky Mavis to sign a massive transaction workload; an Axie employee was phished by a fake LinkedIn offer, executing a trojanized PDF.
- 2022-03-23: The attacker (later attributed to DPRK's **Lazarus Group / APT38**) used the compromised keys to approve two fraudulent withdrawals.
- 2022-03-29: The hack was discovered only after a user reported being unable to withdraw 5,000 ETH.

**Vulnerability**
Sky Mavis operated a sidechain (Ronin) bridged to Ethereum via 9 validator keys. The bridge required **5 of 9 signatures** for a withdrawal. By December 2021, Sky Mavis had, under load, granted **gas-free transaction signing** services to Axie DAO — and the DAO's signer had been left on the validator whitelist. The Lazarus operator obtained 4 of the 9 keys (via the phishing + gas-relay abuse), leaving only one additional signature required to bypass quorum entirely.

**Attacker Technique**
A crafted message resembling a normal withdrawal was submitted with 5 signatures (4 stolen + 1 DAO-signed). The bridge contract `0xa6a26c2c7ffc0a5f1f8a7a1f5f5f5f5f5f5f5f5f5` (Ronin-Ethereum bridge) verified the signature set and released 173,600 ETH + 25.5M USDC in a single transaction.

**Fund Flow**
- Funds moved to `0x098B716B8Aaf21512996dC57EB0615e2383E2f96`
-bridged out through Tornado Cash in small chunks, swapped via THORChain, and eventually parked in Bitcoin mixers. ~$30M was recovered in 2023 through a white-hat arrangement with the Norwegian police (Økokrim).

**Red Team Lessons**
- Treat validator key custody as a separate threat model from smart-contract code.
- Enforce on-chain heartbeats that fail-close when quorum signing falls below threshold for N blocks.
- Phishing of key custodians is the #1 initial-access vector for bridge protocols; tabletop this scenario explicitly.

---

## Case Study 2 — Wormhole Bridge ($326M, February 2022)

**Timeline**
- 2022-02-02 06:03 UTC: An attacker first attempted to exploit the Solana side of the bridge.
- 2022-02-02 09:30 UTC: After the Wormhole guardian network started upgrading, the attacker exploited the *unchanged* Solana program at `wormDTJZ8rfnGCEsLdwJbiSpgtf TyrusTnrH7DrjbFH` and minted 120,000 whETH without backing.
- 2022-02-02 14:00 UTC: Wormhole offered a $10M bug bounty; attacker ignored it.

**Vulnerability**
Wormhole's `parse_vaa` (Verified Action Approval) logic on Solana allowed a "post-commit" signature injection. The guardian set signed message hashes with the **Secp256k1 instruction**, but the Solana program failed to verify that the `signature_set` had not been re-used across two distinct message bodies. An attacker could craft a VAA whose sysvar account claimed verification without an actual guardian signature being checked.

**Attacker Technique**
The exploit used a sequence of cross-program invocations: deposit a tiny amount → obtain a legitimate VAA → mutate the instruction data inside the same transaction → re-use the cached signature_set to mint 120,000 whETH on Solana → bridge it to Ethereum as native ETH.

**Fund Flow**
Funds settled at `0x629e7Da20197a5429d30da36E77d06CdF796b71A` on Ethereum, eventually laundered via Tornado Cash and Railgun. As of 2024, **~$0 has been recovered**, but Jump Crypto (Wormhole's parent) reimbursed all users.

**Red Team Lessons**
- Signature-set caching across distinct messages is a critical anti-pattern — every VAA must bind to its specific payload via a hash commitment.
- Cross-chain message verification must reject replay across chains; include `chain_id` and `nonce` in the signed envelope.

---

## Case Study 3 — Nomad Bridge ($190M, August 2022)

**Timeline**
- 2022-08-01: A routine update initialized the Replica contract's `committedRoot` to `0x00`.
- 2022-08-02 18:00 UTC: A first attacker exploited the resulting flaw. Within ~6 hours, the exploit became **copy-paste trivial**: anyone modifying the `recipient` and `amount` fields of a published transaction and re-broadcasting it would receive funds.

**Vulnerability**
Nomad's `process(bytes memory _message)` function verified a Merkle proof against the committed root. Because the root was initialized to zero, **any message hash whose value was `0x00..00` would trivially satisfy the proof**. Worse, the contract used a hash that started with zero for an empty message slot. The verification logic was:

```solidity
function acceptableAt(bytes32 _root, uint256 _leaf, uint256 _index) internal view returns (bool) {
    return (message[_root] && _index >= validRoot[_root]);
}
```

When `_root == bytes32(0)`, the equality check against `0x00` zero-padded messages trivially passed.

**Attacker Technique**
Hundreds of independent "copycat" addresses simply copied an existing transaction from Etherscan, changed the calldata to send the funds to their own address, and submitted it. There was no sophisticated attacker — it was a crowd-sourced drain.

**Fund Flow**
~$190M drained across 900+ addresses. **~$36M was voluntarily returned** by white-hats who had front-run the malicious actors. The Nomad team recovered funds via negotiations and a $1.9M bounty fund.

**Red Team Lessons**
- Sentinel value initialization (`bytes32(0)`, `address(0)`) is a high-severity code smell in any Merkle/proof system.
- "Anyone can drain" bugs spread virally; the time between first and thousandth exploit was ~4 hours.

---

## Case Study 4 — Euler Finance ($197M, March 2023)

**Timeline**
- 2023-03-13 02:50 UTC: An attacker manipulated Euler's donation mechanism.
- 2023-03-13 09:00 UTC: Euler paused the protocol.
- 2023-04-04: After on-chain negotiation, the attacker returned **all $197M** plus the saved ETH from a $1M bounty reward.

**Vulnerability**
Euler's `EToken` contract exposed a `donateToReserves` function that allowed a user to burn their eTokens without repayment. Combined with a **liquidity-check bypass** enabled by the protocol's leveraged liquidation logic, an attacker could:
1. Deposit 30M DAI as collateral.
2. Mint leveraged positions of wstETH and USDC.
3. Use `donateToReserves` to drive a debt-position underwater.
4. Trigger self-liquidation at a favorable discount, extracting the protocol's reserves.

The root cause: a missing check in the `liquidate` function — the protocol only verified that the violator owed more than was healthy, but **failed to enforce that the donated reserve equaled the debt obligation**.

**Attacker Technique**
Flash-loaned 30M DAI from Aave, executed the donate-and-self-liquidate sequence, repaid the flash loan, and netted ~$197M. The exploit transaction: `0xc310a0bef21634019cc415c1aa0ad6e84bf0b2ec5f7e9e1ba7c5cf3b1e9d1f2`.

**Fund Flow**
Initially moved through Tornado Cash, then into a decoy decoy-Ethereum chain. The attacker ultimately returned everything after a multi-week negotiation.

**Red Team Lessons**
- Flash-loan stress testing is mandatory: every privileged economic function must be tested under 30-second repayment cycles.
- "Donation" primitives that move value out of the protocol without burning equivalent debt are universally dangerous.

---

## Case Study 5 — Mango Markets ($114M, September 2022)

**Timeline**
- 2022-09-14: Avi Eisenberg (a self-described "high-leverage trader") opened two large MNGO perpetual positions.
- 2022-09-15: He pumped the spot MNGO price with borrowed USDC on three venues, causing his perp position to show ~$400M profit.
- 2022-09-15: He withdrew $114M from Mango's treasury.

**Vulnerability**
Mango's perp market used the **spot price of MNGO** (a low-liquidity token) as the sole oracle for its perpetual futures. There was no staleness check, no TWAP, and no liquidity-weighted aggregation.

**Attacker Technique**
A straightforward manipulation: borrow capital, push the spot price up 10x via thin order books, harvest the inflated PnL on perp positions, withdraw. Eisenberg's defense (later in court) was that he had merely "traded according to the protocol's rules."

**Fund Flow**
$114M drained. After negotiation, Eisenberg returned $67M and kept $47M as a "settlement." He was later arrested in Puerto Rico (December 2022) and convicted of commodities fraud in 2024.

**Red Team Lessons**
- Low-liquidity assets are not suitable as collateral or as perp underliers without TWAP protection.
- "According to protocol rules" is not a defense in the US court system — but the protocol is still out the funds.

---

## Case Study 6 — Curve Finance Vyper Compiler Bug ($70M+, July 2023)

**Timeline**
- 2023-07-30: Vyper announced that versions **0.2.15, 0.3.0, and 0.3.1** contained a re-entrancy lock bug for certain functions.
- 2023-07-30 20:00 UTC: Multiple Curve liquidity pools using these versions were exploited.

**Vulnerability**
The Vyper compiler failed to correctly emit the re-entrancy guard (`NONREENTRANT` slot) for functions with certain argument counts. The result: functions that the developer *believed* were protected by `@nonreentrant` were in fact callable during their own callback. This is a compiler bug — not a logic error in the Curve contract source.

**Attacker Technique**
A standard re-entrancy attack against the affected Curve pools: `remove_liquidity` callback triggered a re-entry into `add_liquidity`, draining balances. Pools affected: tricrypto-2, alETH, jpeg, msETH, CRV/ETH.

**Fund Flow**
~$70M drained, of which ~$52M was later returned by white-hats who used the same exploit to "rescue" funds. Curve's founder (Michael Egorov) also took out multi-million dollar Aave loans to defend the CRV peg against liquidation cascades.

**Red Team Lessons**
- Treat every compiler as untrusted; pin versions and audit bytecode diffs against source.
- Re-entrancy guards are not absolute — verify the compiled EVM bytecode contains the expected storage slot write at function entry.

---

## Case Study 7 — Poly Network ($611M, August 2021)

**Timeline**
- 2021-08-10 13:38 UTC: The attacker called `verifyHeaderAndExecuteTx` on the Ethereum cross-chain manager contract.
- 2021-08-10: ~$611M drained across Ethereum, BSC, and Polygon in a single morning.
- 2021-08-12: The attacker began returning funds; by 2021-08-23, **all $611M was recovered**.

**Vulnerability**
The `EthCrossChainManager` contract stored a reference to the keeper contract (`EthCrossChainManagerProxy`) at a known address. The `verifyHeaderAndExecuteTx` function loaded the keeper public keys from storage to verify the message signature, but the keeper keys **were modifiable by the manager itself**. The attacker crafted a cross-chain message whose payload was a `putCurEpochConsumePubKeyList` call — i.e., a message that replaced the keeper set with the attacker's own keys.

**Attacker Technique**
Once the keeper set was overwritten, the attacker's signature was valid by definition. They then approved withdrawals of every major asset. The attacker (MrWhiteHat / "Poly Network Punk") claimed it was a "white hat" operation from the start.

**Fund Flow**
Funds moved to `0xC8a65Fadf0e0DDAf421F28FEAb69Bf6E2E589963`. After three days of negotiations mediated via on-chain messages and EtherScan comments, the attacker returned everything. Poly paid a $500K bounty.

**Red Team Lessons**
- Privileged keeper/key-set mutation paths must be impossible to trigger via cross-chain messages.
- "Self-modifying authority" anti-patterns are catastrophic in bridges.

---

## Case Study 8 — Wintermute DeFi Exploit ($160M, September 2022)

**Timeline**
- 2022-09-20: Wintermute's "smart" contract for high-pace optimal route operations was exploited for $160M.

**Vulnerability**
The exploit targeted a privileged function in Wintermute's EOA-managed contract that used **`delegatecall`** with a function selector that the contract computed via address arithmetic. A bug in the address derivation meant anyone could compute the selector and invoke arbitrary logic on the Wintermute contract.

**Attacker Technique**
The attacker crafted calldata that triggered `delegatecall` to an attacker-controlled contract, which then transferred all approved tokens out.

**Fund Flow**
$160M drained across 70+ tokens. ~$20M of stablecoins on Travis-Verse was deemed unrecoverable. The remainder was largely recovered through Wintermute's own market-making.

**Red Team Lessons**
- `delegatecall` is the most dangerous opcode in EVM; any contract using it must have immutable target addresses.
- Address arithmetic to derive selectors is an attack surface — use constant selectors and emit them in events.

---

## Case Study 9 — BonqDAO Oracle Attack ($120M, February 2023)

**Timeline**
- 2023-02-01 18:00 UTC: An attacker manipulated the TWAP price of AllianceBlock (ALBT) on the Tellor oracle feed.
- 2023-02-02: BonqDAO paused the protocol.

**Vulnerability**
BonqDAO used the **Tellor** oracle, which accepted submissions from any "reporter" who staked TRB. The protocol averaged the last N submissions into a TWAP, but did not bound the deviation from the prior value. An attacker could submit a wildly inflated ALBT price, have their position valued at the inflated level, and mint BEUR stablecoins against phantom collateral.

**Attacker Technique**
The attacker flash-loaned ETH → bought TRB → became a Tellor reporter → submitted a 1000x-inflated ALBT price → opened a BonqDAO vault → minted BEUR → swapped for other assets.

**Fund Flow**
~$120M drained (mostly in ALBT, BEUR). BonqDAO halted the bridge, ALBT price crashed 30%.

**Red Team Lessons**
- Oracles with reporter-staking but no median/trimmed-mean aggregation are manipulable.
- TWAP windows of <10 minutes provide no real protection against flash-loan-funded manipulation.

---

## Case Study 10 — Beanstalk Governance Attack ($182M, April 2022)

**Timeline**
- 2022-04-17: A proposal (BIP-18) was submitted to Beanstalk governance.
- 2022-04-17: The attacker used a flash loan to acquire enough Stalk (governance token) to pass the proposal immediately.

**Vulnerability**
Beanstalk's governance allowed proposals to be **passed within the same transaction they were proposed**, provided sufficient Stalk voted yes. Stalk could be acquired by depositing assets into the Silo, which had no time-lock.

**Attacker Technique**
Flash-loan ~$1B from Aave → deposit into Beanstalk Silo → receive Stalk → vote yes on a malicious proposal that transferred all treasury funds to the attacker → repay the flash loan. Total realized: $182M.

**Fund Flow**
Largely laundered through Tornado Cash. Beanstalk relaunched later in 2022 with a governance timelock.

**Red Team Lessons**
- Governance timelocks of at least 48 hours are non-negotiable for any protocol holding user funds.
- Flash-loan-resistant governance requires either snapshot voting off-chain or vested voting tokens.

---

## Case Study 11 — HashedDAO Governance Attack Pattern

**Pattern (generalized)**
Governance tokens distributed via liquidity mining are often concentrated in a few large holders (often the deployer, the treasury, or early LPs). An attacker who can compromise or social-engineer one large holder gains effective supermajority. In several incidents catalogued under this pattern (including the 2022 Saddle DAO incident and the 2023 Tornado Cash governance issues), the attacker targeted off-chain infrastructure (Discord, snapshot servers) to forge or steal votes.

**Red Team Lessons**
- Off-chain governance infrastructure (Snapshot nodes, multisig signers) is part of the attack surface.
- Multi-sig + DAO hybrid structures need explicit "who can do what" matrices.

---

## Case Study 12 — Wormhole Pre-Commit Exploit (Theoretical + Near-Miss)

In 2022-2023, multiple near-misses were disclosed by Wormhole guardians: a class of vulnerability in which a guardian would sign a VAA, the VAA would be **observable on a mempool**, and a sandwich attacker could race the legitimate relayer to claim the resulting bridge action. Wormhole mitigated by introducing pre-commit hashes: guardians first agree on a `bytes32` commitment, and only after the commitment is finalized do they sign the actual VAA.

**Red Team Lessons**
- Mempool visibility of signed cross-chain messages enables sandwich attacks.
- Pre-commit / commit-reveal patterns eliminate the front-running window.

---

## Hands-on

### Reproduce the Euler attack locally with Foundry

```bash
mkdir euler-repro && cd euler-repro
forge init
forge install Euler-xyz/euler-v2-contracts
# Add a test contract that mocks the donateToReserves + liquidate path
forge test -vvv --match-contract EulerRepro
```

The test contract borrows 30M DAI from a forked Aave V3, executes the donate path, then self-liquidates to demonstrate the fund extraction.

### Re-run the Curve Vyper re-entrancy against a forked mainnet

```bash
anvil --fork-url $RPC_URL --fork-block-number 17800000
cast send 0x...targetPool "remove_liquidity(uint256)" 100000000
# Inside the callback, the attacker's contract re-enters add_liquidity
```

### Inspect the Ronin validator set quorum

```bash
cast call 0xa6a26c2c7ffc0a5f1f8a7a1f5f5f5f5f5f5f5f5f5 \
  "getQuorumThreshold() (uint256)"
cast call 0xa6a26c2c7ffc0a5f1f8a7a1f5f5f5f5f5f5f5f5f5 \
  "getValidators() (address[])"
```

### Echidna property test for re-entrancy guards

```bash
echidna-test contract.sol --contract MyToken --test-mode property \
  --config echidna.yaml
```

### Slither scan for the donation pattern

```bash
slither . --detect reentrancy-no-eth,reentrancy-benign,reentrancy-eth
slither . --detect suicidental,arbitrary-send,controlled-delegatecall
```

---

## References

1. CertiK Skynet — Ronin Network hack analysis: https://www.certik.com/resources/blog/281VfXWBEWnWzpWc2EWU9F-ronin-network-hack-analysis
2. OpenZeppelin — ReentrancyGuard pattern: https://docs.openzeppelin.com/contracts/5.x/api/utils#ReentrancyGuard
3. Wormhole post-mortem (2022-02-24): https://wormhole.com/wormhole-incident-report/
4. Nomad Bridge analysis by Paradigm: https://www.paradigm.xyz/2022/08/nomad-bridge
5. Euler Finance post-mortem (2023-04-04): https://rekt.news/euler-rekt-2/
6. Chainalysis — 2022 Crypto Crime Report (Lazarus attribution): https://www.chainalysis.com/reports/2022-crypto-crime-report-preview
7. Vyper re-entrancy lock bug disclosure (CVE-2023-32695 analog): https://hackmd.io/@vyperlang/HJ-7n0Vfh
8. Curve Finance official statement (2023-07-30): https://curve.fi/tw/curve-dao/4174-statement-regarding-the-exploit
9. Poly Network incident report (SlowMist): https://slowmist.medium.com/the-attack-on-poly-network-9d9b8a16bda7
10. Beanstalk post-mortem (Trail of Bits): https://blog.trailofbits.com/2022/04/21/beanstalk-farms-182-million-governance-attack-post-mortem/
11. Compound Finance — Time-locks and governance best practices: https://docs.compound.finance/v2/governance/
12. Solana Wormhole exploit writeup (Neodyme): https://neodyme.io/en/blog/wormhole_post_mortem/
13. Ethereum.org — Bridge security guidance: https://ethereum.org/en/developers/docs/bridges/
14. DeFiYield REKT database (incident leaderboard): https://de.fi/rekt-database
15. Flashbots — MEV-Boost and oracle sandwich research: https://writings.flashbots.net/writings/
