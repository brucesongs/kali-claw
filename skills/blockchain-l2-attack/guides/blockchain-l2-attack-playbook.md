# Layer-2 Blockchain Attack Playbook — End-to-End Workflow Guide

> Deep-dive companion to `skills/blockchain-l2-attack/SKILL.md`.
>
> Audience: auditors and security engineers who know what Slither, Mythril, and Foundry do (the L1 stuff in `skills/blockchain-web3`), and want a battle-tested playbook for taking an L2 protocol — bridge, rollup, sidechain, payment channel, account abstraction — from raw scope to a defensible audit report, without missing the bug that drains the protocol.

---

## 1. Why an L2 Playbook, Not Just the L1 Playbook

The L1 playbook (`skills/blockchain-web3/guides/smart-contract-audit-playbook.md`) covers: source verification, Slither/Mythril/Echidna, mainnet fork, exploit PoC, report. That playbook assumes one EVM chain and one contract deployment.

L2 breaks every one of those assumptions:

1. **Two or more chains are in scope.** A bridge has source, destination, and possibly a third "settlement" chain. Source ≠ deployed on each chain must be verified independently.
2. **The contract is not the only attack surface.** The sequencer, prover, validator set, and relayer are equally in scope. A perfect contract audit misses the Wormhole / Ronin / Multichain class of bugs entirely.
3. **The cryptography is non-trivial.** ZK proof systems, BLS signature aggregation, threshold MPC, and HTLC preimage commitments require specialist review. "Looks correct" is worse than no review.
4. **The threat model includes censorship and liveness.** An L1 audit assumes the chain is live. An L2 audit must consider: what if the sequencer goes down? What if a validator colludes? What if the prover is DoSed?
5. **The economic attack surface is larger.** Bridges concentrate TVL from multiple chains. A single bug drains everything. The cost of a missed finding is not a CVE — it's a $100M+ exit.

This guide walks through the seven-phase L2 audit, with the exact commands, decision points, and real-world exploit references.

---

## 2. L2 Architecture Comparison

Before any tooling, classify what you're auditing. The audit approach is fundamentally different for each L2 family.

### 2.1 Comparison Table

| Property | Optimistic Rollup | ZK Rollup | Polygon PoS (Sidechain) | Plasma (Legacy) | State Channel |
|---|---|---|---|---|---|
| **Examples** | Optimism, Arbitrum, Base, Boba | zkSync Era, StarkNet, Polygon zkEVM, Scroll, Linea | Polygon PoS, Gnosis Chain, Palm | OMG Network (legacy) | Lightning, Raiden |
| **Security model** | Fraud proofs (assume valid until challenged) | Validity proofs (every state transition proven) | Independent consensus (own validator set) | Fraud proofs on Merkle tree | Off-chain; settle on L1 |
| **L1 dependency** | Strong (data + fraud proofs on L1) | Strong (data + validity proofs on L1) | Weak (only checkpoints to L1) | Medium (data root on L1) | Strong (channel opens/closes on L1) |
| **Challenge window** | ~7 days | None (instant finality via proof) | N/A (own finality) | ~7 days | Variable (depends on channel config) |
| **Off-chain components** | Sequencer, validator | Prover, sequencer, aggregator | Validator set, Bor/Heimdall | Operator | Lightning daemon, WatchTower |
| **Key attack class** | Sequencer DoS, fraud-proof gaming | Prover/verifier bugs, trusted setup | Validator concentration, checkpoint censorship | Exit-game DoS | Channel jam, HTLC pin |
| **Censorship resistance** | L1 forced-inclusion escape hatch | L1 forced-inclusion escape hatch | None (Polygon validator set can censor) | L1 forced-exit (limited) | Channel participants only |
| **Finality** | ~7 days (after challenge window) | Minutes (after proof) | ~5 min (checkpoint cadence) | ~7 days | Instant (off-chain) |

### 2.2 Bridge Type Taxonomy

| Bridge Type | How it works | Failure mode | Notable incidents |
|---|---|---|---|
| **Lock-mint** | Lock tokens on source chain, mint wrapped tokens on destination | Mint authority compromised (key theft, signature forgery) | Wormhole (2022, $326M), Multichain (2023, $1.5B+) |
| **Burn-mint** | Burn tokens on source, mint native on destination | Same as lock-mint (mint authority) | Often paired with lock-mint |
| **Liquidity** | Both sides hold tokens; off-chain relayer moves messages | Accounting drift between sides | Nomad (2022, $190M) |
| **Validator-based** | Validator set signs off on cross-chain messages | Validator set compromise (social eng, key theft) | Ronin (2022, $625M), Poly Network (2021, $611M), Horizon (2022, $100M), Orbit (2024, $80M) |

### 2.3 Threat Model Matrix

For each L2 protocol, fill in:

```
┌─────────────────────────────────────────────────────────────┐
│ THREAT MODEL: <protocol name>                                │
├─────────────────────────────────────────────────────────────┤
│ Chain IDs in scope:  L1=?, L2_source=?, L2_dest=?            │
│ Bridge type:         lock-mint / burn-mint / liquidity /     │
│                      validator-based                          │
│ Trust assumption:    who can mint unlimited on dest?         │
│                      who can censor exits on source?         │
│ Off-chain components:sequencer, prover, validator set,       │
│                      relayer, multisig signer set            │
│ Authorization scope: what's in/out of scope per the bounty?  │
│ Deployment state:    pre-deploy / testnet / mainnet          │
│ Deliverable:         internal report / Immunefi / C4 / Cantina│
│ Timeline:            days/weeks                               │
└─────────────────────────────────────────────────────────────┘
```

If any of these are unclear, stop and resolve before proceeding.

---

## 3. Real-World Exploit Deep-Dives

The six most expensive L2 hacks, with root cause, attack path, and the audit pattern that would have caught each.

### 3.1 Ronin Bridge (2022, $625M)

**Root cause**: 5-of-9 validator multisig socially engineered down to effective 5-of-5.

**Attack path**:
1. Ronin bridge required 5-of-9 validator signatures to release funds.
2. Sky Mavis (the operator) had 4 of 9 validator keys.
3. Attackers social-engineered a fake "interview" process, got a Sky Mavis employee to open a malicious PDF, compromising 4 keys.
4. The 5th key was on a node that had been DDoSed into a restart loop, and a backup key was used (the attacker got it via SSH key leak).
5. Attacker submitted a withdrawal with all 5 keys. Bridge released $625M.

**Audit pattern that would catch it**:
- Read the verifier contract; count the actual `require` threshold.
- Read the off-chain signer documentation; check operational security.
- HIGH finding: 5-of-9 is below majority (M=5, N=9, M < N/2 is false but M=N/2 is too low for a $1B bridge).
- HIGH finding: validator key custodianship procedures (interviews, PDF opens) is operational risk.

**Replay**:
```bash
# Ethereum block ~14377441 (March 2022)
anvil --fork-url $MAINNET_RPC --fork-block-number 14377441 --port 8545 &
cast call 0xA0c68C638235ee32673e8E824d339D52B2Bf2E54 "getSigners()" --rpc-url http://localhost:8545
```

### 3.2 Poly Network (2021, $611M)

**Root cause**: Single keeper key compromised; keeper can replace the signer set.

**Attack path**:
1. Poly Network's `EthCrossChainManager` had a single keeper address with the ability to update the signer set.
2. The keeper key was stored on an unencrypted backup.
3. Attacker stole the keeper key, called `changeKeeper(attacker)`, replacing the keeper with their own address.
4. Attacker then called `verifyHeaderAndExecuteTx` with arbitrary payloads, draining the bridge.

**Audit pattern that would catch it**:
- Read the keeper role in the contract; trace every privileged function.
- HIGH finding: single keeper key for a $600M bridge.
- HIGH finding: keeper can replace keeper (no timelock, no multisig).

**Replay**:
```bash
# Ethereum block ~12975000 (August 2021)
anvil --fork-url $MAINNET_RPC --fork-block-number 12975000 --port 8545 &
cast call 0x8388f7F72B33CaacC5DB5d0bcF022CF0158E2FA5 "keeper()" --rpc-url http://localhost:8545
```

### 3.3 Wormhole (2022, $326M)

**Root cause**: Signature verification bypass on the Solana side.

**Attack path**:
1. Wormhole's `postMessage()` on Solana verified an Ed25519 signature.
2. The verifier checked that the signature was valid against the Solana `Sysvar Instruction` account, NOT against the registered Guardian set.
3. The attacker crafted a Solana instruction that presented a "valid" signature from any address (the Sysvar).
4. The bridge minted 120,000 wETH on Solana.

**Audit pattern that would catch it**:
- Read the verifier; confirm it checks the *registered* signers, not just any signature.
- HIGH finding: signature verification is against the wrong account.
- Cross-check: the verifier address vs. the registered Guardian set.

**Replay**:
```bash
# Ethereum block ~14282107 (February 2022)
anvil --fork-url $MAINNET_RPC --fork-block-number 14282107 --port 8545 &
# The Solana side requires a Solana RPC + validator
solana-test-validator --fork 130889732 &
```

### 3.4 Nomad (2022, $190M)

**Root cause**: Misinitialized Merkle root — set to `0x00`.

**Attack path**:
1. Nomad's bridge used Merkle proofs to verify cross-chain messages.
2. During a routine upgrade, the Merkle root was initialized to `bytes32(0)`.
3. Any message whose hash starts with `0x00` was "in the tree" (because the root was zero).
4. The first attacker discovered this and crafted a message; then hundreds of copy-paste attackers drained the rest.

**Audit pattern that would catch it**:
- Read the deployment scripts; check every storage slot initialization.
- HIGH finding: Merkle root initialized to zero.
- Fuzzing: invariant "every processed message has a valid inclusion proof" would have caught it.

**Replay**:
```bash
# Ethereum block ~15259350 (August 2022)
anvil --fork-url $MAINNET_RPC --fork-block-number 15259350 --port 8545 &
forge test --match-test test_PoC_NomadIndiscriminateProcess -vvvv \
  --fork-url $MAINNET_RPC --fork-block-number 15259350
```

### 3.5 Multichain / Anyswap (2023, $1.5B+)

**Root cause**: MPC threshold signer compromised via coercion of custodians in China.

**Attack path**:
1. Multichain used an MPC (multi-party computation) threshold signer with a small set of custodians.
2. The custodians were located primarily in China.
3. In 2023, the CEO was detained by Chinese authorities; the custodial keys were surrendered (under coercion).
4. Attackers got full mint authority across many chains; minted unlimited tokens.

**Audit pattern that would catch it**:
- Operational review: where are the MPC signers located? Are they subject to coercion?
- HIGH finding: signer set concentrated in one legal jurisdiction.
- HIGH finding: no geographic distribution, no HSM requirement.

**Replay**: This is an operational failure, not a contract bug. The "replay" is a tabletop exercise: simulate the same custody setup and demonstrate the single-point-of-failure.

### 3.6 Horizon (2022, $100M)

**Root cause**: 2-of-5 validator multisig with 2 keys compromised.

**Attack path**:
1. Harmony's Horizon bridge used a 2-of-5 multisig.
2. The threshold is below majority (M=2, N=5, M < N/2).
3. Two validator keys were compromised (likely via SSH private-key leak).
4. Attacker submitted a withdrawal with 2 signatures; bridge released $100M.

**Audit pattern that would catch it**:
- Read the threshold: `cast call 0xBridge "threshold()"`.
- HIGH finding: 2-of-5 threshold is below majority.
- HIGH finding: no timelock on validator-set changes.

**Replay**:
```bash
# Harmony block ~19743149 (June 2022)
anvil --fork-url $HARMONY_RPC --fork-block-number 19743149 --port 8545 &
cast call 0x...HorizonBridge "threshold()" --rpc-url http://localhost:8545
```

### 3.7 Summary: Common Patterns

Across all six incidents:
1. **Threshold too low**: Ronin (5-of-9), Horizon (2-of-5). Defense: M > N/2, ideally M >= 2N/3.
2. **Single-key admin**: Poly Network keeper. Defense: multisig + timelock.
3. **Signature verification bug**: Wormhole. Defense: verify against registered signers, not any signature.
4. **Storage initialization bug**: Nomad. Defense: initialize every storage slot in constructors; fuzz the init.
5. **Operational failure**: Multichain (custody in one jurisdiction). Defense: distribute signers across jurisdictions, HSMs.

---

## 4. Audit Methodology — The Seven-Phase Process

```
Phase 1           Phase 2           Phase 3           Phase 4           Phase 5           Phase 6           Phase 7
Threat Model   →  Component Map  →  Contract Audit →  Off-Chain Audit → Cross-Chain     →  Exploit PoC    →  Report +
                                                                                  Fuzz +
   │                 │                 │                 │                 │                 │                 │
   ▼                 ▼                 ▼                 ▼                 ▼                 ▼                 ▼
Chain IDs,         L1 bridge,         Slither/Mythril/  Sequencer,        Replay past       Forge PoC on      Severity +
bridge type,       L2 bridge,         Echidna on        validator set,    incidents on      anvil fork at     defense recs
trust assumption   sequencer,         bridge wrapper    multisig          a fork            pre-incident      per component
                   prover, validator                                          block
```

### 4.1 Phase 1: Threat Model & Scope

Document (in writing):
- Chain IDs in scope.
- Bridge type (lock-mint / burn-mint / liquidity / validator-based).
- Trust assumptions: who can mint unlimited on destination? who can censor exits on source?
- Off-chain components in scope: sequencer, prover, validator set, relayer.
- Authorization: scope rules, bug bounty terms, "no live mainnet attack" rule.
- Deployment state: pre-deploy / testnet / mainnet.
- Deliverable: internal report / Immunefi / C4 / Cantina.
- Timeline.

### 4.2 Phase 2: Component Map

Identify every address in the L2 system:
```bash
# Enumerate via the protocol docs + Etherscan labels
cast interface 0xBridgeL1 --rpc-url $L1_RPC > bridge_l1.abi
cast interface 0xBridgeL2 --rpc-url $L2_RPC > bridge_l2.abi

# Find every privileged function
cat bridge_l1.abi | grep -E 'function (deposit|withdraw|finalize|mint|burn|escape|prove|pause|setThreshold|changeKeeper|upgrade)'
cat bridge_l2.abi | grep -E 'function (mint|burn|process|finalize|pause|setPeer|upgrade)'

# Read the proxy implementation (if upgradeable)
cast storage 0xBridge 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url $L1_RPC
```

### 4.3 Phase 3: Contract Audit

Standard Slither + Mythril + Echidna pass, with bridge-aware detectors:
```bash
slither src/ --filter-paths "lib|test|mocks"
slither src/bridge/ --detect reentrancy,arbitrary-send-eth,unchecked-transfer,controlled-delegatecall,tx-origin,timestamp,dangerous-strict-equality,assembly,suicidal,centralized-risk,uninitialized-state-variable
myth analyze src/bridge/L1Bridge.sol --modules transaction_order_independence,ether_thief --max-depth 50
echidna-test echidna/LockMintEchidna.sol --contract LockMintEchidna --test-mode property --test-limit 100000
```

### 4.4 Phase 4: Off-Chain Audit

This is where L2 audits diverge from L1. Map and review:

**Sequencer** (Optimistic/ZK rollup):
- Who operates it? Single entity or decentralized?
- Can it censor? What's the forced-inclusion escape hatch (OP `enqueue`, Arbitrum `L2ToL1MessagePasser`)?
- Can a single sequencer key compromise mint authority?

**Validator set** (Polygon PoS, Ronin, Horizon):
- What's the threshold (M-of-N)?
- What's the stake distribution?
- Can social engineering reduce effective threshold?

**Prover / Aggregator** (ZK rollups):
- Who runs the prover?
- Is the trusted-setup ceremony transcript published?
- Is the verifier contract matched to the trusted-setup SRS?

**Relayer daemon** (Wormhole, Multichain):
- Where does it run?
- Does it have access to validator keys?
- Is the daemon host hardened?

### 4.5 Phase 5: Cross-Chain Replay

Replay a past incident on a fork:
```bash
anvil --fork-url $MAINNET_RPC --fork-block-number <pre-incident-block> --port 8545 &
cast rpc --rpc-url http://localhost:8545 anvil_impersonateAccount 0xAttacker
cast send --rpc-url http://localhost:8545 --from 0xAttacker --unlocked 0xBridge <exploit-calldata>
# Verify same loss occurred
cast balance 0xAttacker --rpc-url http://localhost:8545
```

### 4.6 Phase 6: Exploit PoC

Run the exploit as a forge test against the fork:
```bash
forge test --match-test test_PoC_<IncidentName> -vvvv \
  --fork-url $MAINNET_RPC \
  --fork-block-number <pre-incident-block> 2>&1 | tee evidence/poc_trace.log
```

### 4.7 Phase 7: Report

For every finding, document:
- Affected component (contract, sequencer, validator set, prover).
- Trust assumption violated.
- Exploitability under realistic conditions.
- Defense recommendation.

---

## 5. Lab Setup

### 5.1 Foundry + Anvil (Required)

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Verify
forge --version && cast --version && anvil --version && chisel --version

# Start a mainnet fork
export MAINNET_RPC=https://eth-mainnet.g.alchemy.com/v2/$ALCHEMY_KEY
anvil --fork-url $MAINNET_RPC --fork-block-number 19000000 --port 8545 &
```

### 5.2 OP Stack Bedrock Devnet

```bash
git clone https://github.com/ethereum-optimism/optimism.git
cd optimism
make install

# Bring up the devnet
make devnet-up

# Verify:
# - L1 geth on localhost:8545
# - L2 rollup node
# - L2 geth on localhost:9545
# - Deployer

cast block-number --rpc-url http://localhost:9545  # L2
cast block-number --rpc-url http://localhost:8545  # L1

# Tear down
make devnet-down
```

### 5.3 Arbitrum Nitro Dev Node

```bash
# Pull the Nitro dev node
docker pull ghcr.io/offchainlabs/nitro-node-devnode:latest

# Run it
docker run -d -p 8547:8547 -p 9642:9642 \
  -v /tmp/arbitrum:/home/user/.arbitrum \
  ghcr.io/offchainlabs/nitro-node-devnode:latest \
  --node.feed.input.url=wss://feed.arbitrum.io/feed \
  --node.seq-coordinate-url=wss://seq.coordinator

# Verify
cast chain-id --rpc-url http://localhost:8547  # should be 4121 (Arbitrum local)
```

### 5.4 zkSync Era Local Node

```bash
# Use the zkSync testing docker image
docker pull matterlabs/local-node:latest
docker run -d -p 8011:8011 -p 3050:3050 matterlabs/local-node:latest

# Verify
cast chain-id --rpc-url http://localhost:3050
```

### 5.5 StarkNet Devnet

```bash
pip3 install starknet-devnet
starknet-devnet --host 0.0.0.0 --port 5050 &
```

### 5.6 Lightning Network Regtest Cluster

```bash
# Option 1: Polar Lightning (GUI)
docker run -d -p 8081:8081 -v ~/polar:/data polarlightning/polar:1.0.0

# Option 2: Manual c-lightning
sudo apt install -y lightningd lightning-cli
for i in 1 2 3; do
  mkdir -p /tmp/l$i
  lightningd --network=regtest \
    --lightning-dir=/tmp/l$i \
    --addr=127.0.0.1:$((7000+i)) \
    --rpc-file=lightning-rpc &
done

# Open channels: A -> B, B -> C
lightning-cli --lightning-dir=/tmp/l1 fundchannel \
  $(lightning-cli --lightning-dir=/tmp/l2 getinfo | jq -r .id) 1000000
```

### 5.7 Bridge Simulator

For testing bridge logic without a full L2:
```solidity
// Lab: a minimal lock-mint bridge for testing
contract LabLockMintBridge {
    mapping(uint256 => mapping(address => uint256)) public locked;  // chainId => user => amount
    mapping(uint256 => mapping(address => uint256)) public minted;
    uint256 public sourceChainId;
    uint256 public destChainId;

    constructor(uint256 _src, uint256 _dst) {
        sourceChainId = _src;
        destChainId = _dst;
    }

    function lock(address from, uint256 amount) external payable {
        require(msg.value == amount, "wrong amount");
        locked[sourceChainId][from] += amount;
    }

    function mint(address to, uint256 amount, uint256 sourceNonce) external {
        // In a real bridge, this is called by the relayer with a proof
        minted[destChainId][to] += amount;
    }

    function invariant_mint_le_lock(address user) external view returns (bool) {
        return minted[destChainId][user] <= locked[sourceChainId][user];
    }
}
```

---

## 6. Defense Recommendations (by Component)

### 6.1 Bridge Defenses

| Defense | Implementation | Effectiveness |
|---|---|---|
| **Rate limiting** | Cap mintable-per-block to N% of TVL | Slows attack; buys time to pause |
| **Timelock on validator-set changes** | 24-48h delay on any threshold/signer change | Lets users exit before malicious change |
| **M-of-N multisig with M > N/2** | Raise threshold above majority | Resists minority collusion |
| **Geographic distribution + HSMs** | Signers across >=3 jurisdictions, keys in HSMs | Resists coercion + key theft |
| **Pausable + Sentinel** | Auto-pause on anomalous mint volume | Limits blast radius |
| **Replay protection with chain-ID** | Every message commits to (src, dst, nonce) chains | Prevents cross-chain replay |
| **Multi-sig + WatchTower** | Independent watchers monitor for invalid state | Catches fraud proofs / invalid mints |

### 6.2 Rollup Defenses

| Defense | Implementation | Effectiveness |
|---|---|---|
| **Forced-inclusion escape hatch** | L1 deposit feed (OP, Arbitrum) | Users can always exit |
| **Decentralized sequencer set** | Multiple sequencers, failover protocol | Resists sequencer DoS |
| **Fraud-proof window >= 7 days** | Long enough for honest watchers | Catches invalid state |
| **Validity proofs (ZK)** | Every transition proven | No challenge window needed |
| **Trusted setup transparency** | Published Powers of Tau ceremony | Auditable setup |

### 6.3 Lightning Network Defenses

| Defense | Implementation | Effectiveness |
|---|---|---|
| **Max HTLCs per channel limit** | Cap at ~483 (BOLT) or lower | Limits pin attack damage |
| **Anchor commitments** | CPFP-enabled fee bumping | Prevents fee-pin of penalty txs |
| **WatchTower service** | Third-party monitoring for old-state closes | Allows users to be offline |
| **Wumbo channels** | Larger channels absorb HTLC pin | Reduces relative pin impact |

### 6.4 ERC-4337 Defenses

| Defense | Implementation | Effectiveness |
|---|---|---|
| **Decentralized bundler network** | Multiple competing bundlers | Resists censorship |
| **Paymaster ReentrancyGuard + deposit decrement** | OZ pattern on every withdrawal | Prevents double-withdrawal |
| **Off-chain bundle simulation** | Bundler simulates full bundle before submission | Catches bundle-reverting ops |
| **Factory with commit-reveal** | Salt + commit hash on deployment | Prevents factory front-running |

---

## 7. Report Template

### 7.1 Finding Template

```markdown
### [SEVERITY] Title

**Severity**: CRITICAL / HIGH / MEDIUM / LOW
**Component**: <contract address or off-chain component>
**Location**: <file:line or config key>

**Description**:
<One paragraph explaining the bug. Be specific about which line of code,
which configuration option, or which off-chain procedure is at fault.>

**Impact**:
<What an attacker can do. Be concrete: "drain the entire bridge TVL of $X",
"censor all L2 transactions indefinitely", "mint unlimited tokens on the
destination chain".>

**Proof of Concept**:
<Link to the forge test or cast replay. Include the exact command to
reproduce:>
```
forge test --match-test test_PoC_<Name> -vvvv \
  --fork-url $MAINNET_RPC --fork-block-number <N>
```

**Recommendation**:
<Specific, actionable fix. Not "improve security" — "raise the multisig
threshold from 2-of-5 to 4-of-5, distribute signers across >=3 jurisdictions,
and move keys to HSMs".>
```

### 7.2 Severity Rubric

| Severity | Definition | L2 Examples |
|---|---|---|
| **CRITICAL** | Funds at immediate risk; single transaction drains TVL | Bridge mint-without-lock; multisig threshold bypass; signature forgery accepted |
| **HIGH** | Significant impact, requires specific conditions | Sequencer censorship with no escape hatch; Paymaster double-withdrawal; HTLC pin DoS; ZK verifier accepts forged proof |
| **MEDIUM** | Defense-in-depth concern; not exploitable alone | Slither HIGH finding on `nonReentrant`-protected function; short fraud-proof window; Nakamoto coefficient between 5-10 |
| **LOW** | Code quality / informational | Style findings; missing NatSpec; low test coverage |

---

## 8. Common Pitfalls (Don't Do These)

1. **Auditing only the contract, ignoring the off-chain components.** Wormhole, Ronin, Multichain, Horizon were all off-chain compromises. If your audit doesn't cover the validator set, sequencer, and prover, you missed the most likely attack path.
2. **Trusting the spec sheet for the threshold.** "5-of-9 multisig" on a spec is not proof it's enforced. Read the verifier contract, count the actual `require` threshold, and check for any path that bypasses the threshold.
3. **Not initializing storage.** The Nomad bug was a Merkle root initialized to `bytes32(0)`. Every storage slot must be explicitly initialized in the constructor or initializer.
4. **Using `tx.origin` for auth in L2.** L2 users are often behind smart-contract wallets (account abstraction). `require(msg.sender == tx.origin)` forbids them entirely. Use EIP-2771 meta-transactions instead.
5. **Skipping the replay protection.** Cross-chain messages must commit to (source chain ID, destination chain ID, nonce). Without this, a message on chain A can be replayed on chain B.
6. **Not testing the forced-inclusion escape hatch.** The OP Stack and Arbitrum both have L1 → L2 forced-inclusion paths. If these don't work when the sequencer is down, the chain is effectively censorable.
7. **Treating ZK as magic.** ZK proof systems require specialist review. If you're not an expert, partner with one. A "looks correct" verifier audit is worse than no audit.
8. **Running mainnet PoCs without explicit authorization.** A single broadcast tx on mainnet triggers real liquidations. Always use `anvil --fork-url`.

---

## 9. External Resources

### 9.1 Incident Databases

- Rekt Leaderboard: [rekt.news/leaderboard](https://rekt.news/leaderboard/) — ranked by $ lost
- DeFi Yields Rekt Database: [defiyields.app/rekt-database](https://defiyields.app/rekt-database)
- SoK: Cross-Chain Bridges (academic survey): [arxiv.org/abs/2208.00865](https://arxiv.org/abs/2208.00865)

### 9.2 Post-Mortems

- Wormhole (2022): [wormhole.com/wormhole-incident-report](https://wormhole.com/wormhole-incident-report/)
- Nomad (2022, samczsun): [paradigm.xyz/article/nomad-bridge-exploit](https://www.paradigm.xyz/article/2022/08/nomad-bridge-exploit)
- Ronin (2022, Sky Mavis): [roninblockchain.substack.com/p/ronin-exploit-postmortem](https://roninblockchain.substack.com/p/ronin-exploit-postmortem)
- Poly Network (2021): [rekt.news/polynetwork-rekt](https://rekt.news/polynetwork-rekt/)
- Multichain (2023): [rekt.news/multichain-rekt-2](https://rekt.news/multichain-rekt-2/)
- Horizon (2022): [rekt.news/harmony-rekt](https://rekt.news/harmony-rekt/)

### 9.3 Specs & Docs

- Lightning BOLT Specs: [github.com/lightning/bolts](https://github.com/lightning/bolts)
- OP Stack Docs: [docs.optimism.io](https://docs.optimism.io/)
- Arbitrum Nitro Docs: [docs.arbitrum.io](https://docs.arbitrum.io/)
- zkSync Docs: [docs.zksync.io](https://docs.zksync.io/)
- StarkNet Book: [book.cairo-lang.org](https://book.cairo-lang.org/)
- Polygon PoS Docs: [wiki.polygon.technology](https://wiki.polygon.technology/)
- ERC-4337: [eips.ethereum.org/EIPS/eip-4337](https://eips.ethereum.org/EIPS/eip-4337)
- EIP-4844 (Blobs): [eips.ethereum.org/EIPS/eip-4844](https://eips.ethereum.org/EIPS/eip-4844)
- Celestia Docs: [docs.celestia.org](https://docs.celestia.org/)
- EigenDA Docs: [docs.eigenda.xyz](https://docs.eigenda.xyz/)

### 9.4 Tooling

- Foundry: [book.getfoundry.sh](https://book.getfoundry.sh/)
- Slither: [github.com/crytic/slither](https://github.com/crytic/slither)
- Mythril: [github.com/Consensys/mythril](https://github.com/Consensys/mythril)
- Echidna: [github.com/crytic/echidna](https://github.com/crytic/echidna)
- Tenderly: [tenderly.co](https://tenderly.co/)
- Forta: [forta.org](https://forta.org/)
- OpenZeppelin Defender: [defender.openzeppelin.com](https://defender.openzeppelin.com/)
- Immunefi: [immunefi.com](https://immunefi.com/)

---

## 10. Conclusion

L2 security is fundamentally harder than L1 security because:

1. **Multiple attack surfaces**: contracts + sequencer + prover + validator set + multisig + relayer.
2. **Cryptography is non-trivial**: ZK proofs, BLS, threshold signatures require specialist review.
3. **Censorship and liveness are first-class**: the chain can go down, the sequencer can censor, the validator set can collude.
4. **Bridges are the juiciest target**: $2.8B+ stolen to date. Every bridge audit is high-stakes.

The good news: every L2 incident had a root cause that was findable with the right methodology. The Ronin multisig was findable by reading the threshold. The Nomad root was findable by reading the deployment script. The Wormhole verifier was findable by tracing which account it actually checked.

Audit every component. Trust no spec sheet. Initialize every storage slot. Distribute every signer. Pause on every anomaly.

---

End of `guides/blockchain-l2-attack-playbook.md`.
