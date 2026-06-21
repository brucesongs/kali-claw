# Layer-2 Blockchain Attack Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.
> All commands assume a local anvil fork or L2 devnet — never run exploit PoCs against mainnet contracts without explicit authorization (engagement scope, bug bounty terms, or self-audit of owned contracts).

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Static Analysis | 2 | MEDIUM - HIGH |
| B. Bridge Replay (Real Incidents) | 3 | CRITICAL |
| C. Sequencer & Fraud-Proof Analysis | 2 | HIGH |
| D. ZK Soundness | 1 | HIGH |
| E. Lightning Network & HTLC | 1 | HIGH |
| F. Account Abstraction (ERC-4337) | 1 | HIGH |
| G. Validator Set / Multisig Analysis | 1 | HIGH |
| H. DA Layer & Property Invariants | 1 | MEDIUM |
| **Total** | **12** | **MEDIUM - CRITICAL** |

---

## A. Static Analysis

### TC-L2-001: Slither Bridge-Specific Detector Run

| Field | Value |
|------|-----|
| **ID** | TC-L2-001 |
| **Name** | Slither Bridge-Specific Detector Run |
| **Severity** | HIGH |
| **Category** | Static Analysis |
| **Objective** | Run Slither's bridge-aware detector set on the L2 contract surface (bridge wrappers, ERC-4337 entrypoint, rollup inbox/outbox) to surface the failure modes that have actually drained bridges in production. |
| **Prerequisites** | `pip3 install slither-analyzer solc-select`; `solc-select install 0.8.24 && solc-select use 0.8.24`; L2 contract repo cloned with `forge install` run. |
| **Test Steps** | 1. `slither src/ --filter-paths "lib\|test\|mocks\|script" --json slither_l2.json`<br>2. Triage HIGH findings: `jq '.results.detectors[] \| select(.impact=="High") \| {check, first_slot, description}' slither_l2.json`<br>3. Run bridge-specific detector set: `slither src/bridge/ --detect reentrancy,reentrancy-eth,arbitrary-send-eth,unchecked-transfer,controlled-delegatecall,tx-origin,timestamp,dangerous-strict-equality,assembly,suicidal,centralized-risk,uninitialized-state-variable`<br>4. For every `uninitialized-state-variable` finding, manually verify against deployment scripts — this is the Nomad bug class. |
| **Expected Results** | Detector report covers all bridge/rollup/account-abstraction contracts in scope; HIGH findings reviewable within 2-3 hours; each finding mapped to a known incident class (Wormhole, Nomad, Ronin, etc.). |
| **False Positive Risk** | MEDIUM — Slither flags patterns, not exploits. A `reentrancy-benign` finding on a `nonReentrant`-protected bridge function is informational. Manual confirmation required for any CRITICAL claim. |
| **Remediation (defense)** | Apply Checks-Effects-Interactions on bridge lock/mint/burn functions; initialize storage in constructors; use `nonReentrant`; whitelist trusted callers. |
| **Related Tools** | slither, jq, solc-select |

### TC-L2-002: Mythril Signature Aggregation Verification

| Field | Value |
|------|-----|
| **ID** | TC-L2-002 |
| **Name** | Mythril Symbolic Execution on Bridge Verifier |
| **Severity** | HIGH |
| **Category** | Static Analysis |
| **Objective** | Use symbolic execution to find signature-bypass, replay, and arithmetic bugs in bridge signature verifiers and message-passing contracts that pattern-based detectors miss. |
| **Prerequisites** | `pip3 install mythril`; bridge verifier contract compiles in solc 0.8+; 10-30 min wall-clock budget per contract. |
| **Test Steps** | 1. `myth analyze src/bridge/Verifier.sol --modules transaction_order_independence,ether_thief,arbitrary_send_eth --max-depth 50 -o json > mythril_verifier.json`<br>2. Filter for unique SWC IDs: `jq '.issues[] \| {swc_id, title, severity}' mythril_verifier.json \| sort -u`<br>3. For each counterexample, extract the call trace: `myth analyze src/bridge/Verifier.sol --verbose --modules transaction_order_independence 2>&1 \| tee trace.log`<br>4. Reproduce the counterexample as a forge test with a forged signature payload. |
| **Expected Results** | 1-5 counterexamples per verifier for any non-trivial logic; counterexamples are reproducible as forge tests on a mainnet fork. |
| **False Positive Risk** | HIGH — Mythril reports any feasible counterexample, not all of which are exploitable in practice. Reproduce as a forge PoC before promoting to a finding. |
| **Remediation (defense)** | Eliminate the counterexample by tightening preconditions or applying the EIP-712 typed-data pattern with chain-ID commitment. |
| **Related Tools** | mythril, forge, jq |

---

## B. Bridge Replay (Real Incidents)

### TC-L2-003: Wormhole Exploit Fork Replay

| Field | Value |
|------|-----|
| **ID** | TC-L2-003 |
| **Name** | Wormhole 2022 $326M Exploit Fork Replay |
| **Severity** | CRITICAL |
| **Category** | Bridge Replay |
| **Objective** | Reproduce the 2022 Wormhole exploit on a local anvil fork at the pre-incident Ethereum block (~14282107) — verify the signature-bypass path and use it as a regression test for patched verifiers. |
| **Prerequisites** | `MAINNET_RPC` env var (Alchemy/Infura/Ankr); the exploit tx hash from the Wormhole post-mortem; `anvil` running locally. |
| **Test Steps** | 1. `anvil --fork-url $MAINNET_RPC --fork-block-number 14282107 --port 8545 &`<br>2. Confirm fork state: `cast block-number --rpc-url http://localhost:8545` should echo `14282107`<br>3. Impersonate the attacker EOA: `cast rpc --rpc-url http://localhost:8545 anvil_impersonateAccount 0x629e7Da20197a5429d70DA521639708c5a6d8242`<br>4. Fund the attacker: `cast rpc --rpc-url http://localhost:8545 anvil_setBalance 0x629e7... 0x1000000000000000000`<br>5. Decode the exploit calldata via `cast 4byte-decode`<br>6. Replay the attack tx: `cast send --rpc-url http://localhost:8545 --from 0x629e7... --unlocked 0xf92cD566FEEA490390d4feA1959B6c00e96964Bc <calldata>`<br>7. Verify the Wormhole wETH balance drops to 0 (Solana-side mint simulated). |
| **Expected Results** | Original exploit succeeds on the fork (proves the fork is faithful); patched verifier reverts with `"invalid guardian signature"`. |
| **False Positive Risk** | LOW — fork replay is deterministic at a fixed block. Variability comes from RPC node drift. |
| **Remediation (defense)** | Verify signatures against the registered Guardian set (not Sysvar); rotate the Guardian set on suspicion of compromise; add rate limiting on mints. |
| **Related Tools** | anvil, cast, forge |

### TC-L2-004: Nomad Indiscriminate-Call Fork Replay

| Field | Value |
|------|-----|
| **ID** | TC-L2-004 |
| **Name** | Nomad 2022 $190M Indiscriminate-Call Fork Replay |
| **Severity** | CRITICAL |
| **Category** | Bridge Replay |
| **Objective** | Reproduce the 2022 Nomad exploit on a local anvil fork — verify that ANY address could drain the bridge by replaying a single calldata pattern with a modified recipient field. |
| **Prerequisites** | `MAINNET_RPC` env var; pre-incident block ~15259350; forge project with `test/NomadPoC.t.sol` written. |
| **Test Steps** | 1. `anvil --fork-url $MAINNET_RPC --fork-block-number 15259350 --port 8545 &`<br>2. Run the forge PoC: `forge test --match-test test_PoC_NomadIndiscriminateProcess -vvvv --fork-url $MAINNET_RPC --fork-block-number 15259350`<br>3. The test crafts a message with hash starting at `0x00` (because the bridge's Merkle root was initialized to zero), calls `process(bytes)`, and asserts the test contract's balance increased.<br>4. Verify the test passes on the unpatched contract; then swap in a patched contract with proper Merkle root initialization and verify the test reverts. |
| **Expected Results** | Unpatched: any properly-formatted message drains funds. Patched: process() reverts with `"message not in Merkle tree"`. |
| **False Positive Risk** | LOW — deterministic fork replay. |
| **Remediation (defense)** | Initialize the Merkle root to a non-zero value; require inclusion proofs; add replay protection with chain-ID commitment. |
| **Related Tools** | anvil, cast, forge |

### TC-L2-005: Ronin / Horizon Validator Multisig Compromise Simulation

| Field | Value |
|------|-----|
| **ID** | TC-L2-005 |
| **Name** | Ronin / Horizon Validator Multisig Compromise Simulation |
| **Severity** | CRITICAL |
| **Category** | Bridge Replay |
| **Objective** | Simulate the social-engineering path that reduced effective thresholds on the Ronin (5-of-9 spec, 5 keys compromised) and Horizon (2-of-5 spec, 2 keys compromised) bridges, demonstrating why threshold must be M > N/2 with HSMs. |
| **Prerequisites** | Local forge project with `test/ValidatorThresholdPoC.t.sol` written; Gnosis Safe available locally for threshold simulation. |
| **Test Steps** | 1. Deploy a 5-of-9 validator multisig in the forge test<br>2. Simulate 5 compromised validator keys (via `vm.prank`)<br>3. Submit a forged message with 5 signatures<br>4. Verify the multisig accepts and the bridge releases funds<br>5. Repeat with 4 compromised keys — should revert with `"insufficient signatures"`<br>6. For Horizon: deploy a 2-of-5 multisig, demonstrate 2 keys suffice. |
| **Expected Results** | Ronin (5-of-9): 5 forged sigs succeeds, 4 fails. Horizon (2-of-5): 2 forged sigs succeeds. Threshold analysis: M <= N/2 is insecure. |
| **False Positive Risk** | LOW — this is a simulation, not a mainnet replay. |
| **Remediation (defense)** | Raise threshold to M > N/2 (e.g., 4-of-5, 7-of-9); distribute signers across jurisdictions; use HSMs; add 24-48h timelock on validator-set changes. |
| **Related Tools** | forge, Gnosis Safe |

---

## C. Sequencer & Fraud-Proof Analysis

### TC-L2-006: OP Stack Bedrock Sequencer Failure + Forced-Inclusion Test

| Field | Value |
|------|-----|
| **ID** | TC-L2-006 |
| **Name** | OP Stack Sequencer Failure + L1 Forced-Inclusion Escape Hatch |
| **Severity** | HIGH |
| **Category** | Sequencer & Fraud-Proof |
| **Objective** | Stand up a local OP Stack Bedrock devnet, kill the sequencer, and verify the L1 `depositTransaction` forced-inclusion escape hatch still works (users can always exit via L1). |
| **Prerequisites** | Local Docker; `git clone https://github.com/ethereum-optimism/optimism.git`; `make install && make devnet-up` completes successfully; L1 RPC on `localhost:8545`, L2 RPC on `localhost:9545`. |
| **Test Steps** | 1. `make devnet-up` from the optimism repo; wait ~30s for setup.<br>2. Verify L2 producing blocks: `cast block-number --rpc-url http://localhost:9545`<br>3. Send a normal tx (goes through sequencer): `cast send --rpc-url http://localhost:9545 --private-key $DEV_PRIVATE_KEY 0xDead 1ether`<br>4. Kill the sequencer: `docker stop op-devnet-sequencer`<br>5. Try a normal L2 tx — should hang (sequencer is dead).<br>6. Send a forced-inclusion tx via L1 deposit feed: `cast send --rpc-url http://localhost:8545 --private-key $DEV_PRIVATE_KEY 0xDepositFeed "depositTransaction(address,uint256,uint256,bool,bytes)" 0xDead 1ether 100000 false "0x"`<br>7. Wait ~3 L1 blocks, verify the L2 node picks it up via the deposit feed. |
| **Expected Results** | Forced-inclusion tx confirms on L2 even with the sequencer offline; users can always exit. |
| **False Positive Risk** | LOW — deterministic devnet. |
| **Remediation (defense)** | Maintain the forced-inclusion escape hatch; document user exit procedure; test it in CI on every OP Stack upgrade. |
| **Related Tools** | optimism devnet, cast, docker |

### TC-L2-007: Optimistic Rollup Fraud-Proof Soundness Review

| Field | Value |
|------|-----|
| **ID** | TC-L2-007 |
| **Name** | Optimistic Rollup Fraud-Proof Window + Soundness Review |
| **Severity** | HIGH |
| **Category** | Sequencer & Fraud-Proof |
| **Objective** | Verify the rollup's challenge window is long enough for honest watchers (>= 7 days) and that the fraud-proof submission path is sound against DoS. |
| **Prerequisites** | L1 RPC; L2 RPC; address of the L2OutputOracle contract on L1; `op-challenger` daemon available. |
| **Test Steps** | 1. Read the challenge window from L2OutputOracle: `cast call 0xL2OutputOracle "FINALIZATION_PERIOD_SECONDS()" --rpc-url $L1_RPC`; should be >= 604800 (7 days).<br>2. Submit a fake output (simulated attack): `cast send --rpc-url $L1_RPC --private-key $DEV $L2OutputOracle "proposeL2Output(bytes32,uint256,bytes32,uint256)" <fake_root> <block> <prev> <timestamp>`<br>3. Run `op-challenger` to detect and challenge the fake output within the window.<br>4. Verify the challenger succeeds: fake output is deleted via fraud proof.<br>5. If `op-challenger` fails to detect, that's a HIGH finding. |
| **Expected Results** | Challenger catches the fake output within the 7-day window; fraud-proof submission path is not DoS-able. |
| **False Positive Risk** | MEDIUM — the fake output may not be invalid in all respects; need to ensure it represents a real state transition divergence. |
| **Remediation (defense)** | Increase challenge window if < 7 days; run redundant challenger infrastructure (multiple independent watchers); monitor L2OutputOracle proposals in real time. |
| **Related Tools** | op-challenger, cast, forge |

---

## D. ZK Soundness

### TC-L2-008: ZK Rollup Verifier Fake-Proof Resistance Test

| Field | Value |
|------|-----|
| **ID** | TC-L2-008 |
| **Name** | ZK Rollup Verifier Fake-Proof Resistance Test |
| **Severity** | HIGH |
| **Category** | ZK Soundness |
| **Objective** | Verify that the ZK rollup verifier contract rejects every random/forged "proof" submitted to it, and that the trusted setup (where applicable) matches the published ceremony. |
| **Prerequisites** | L1 RPC; address of the ZK verifier contract; Slither + Mythril installed; trusted setup transcript available for verification. |
| **Test Steps** | 1. Run Slither on the verifier: `slither src/Verifier.sol --detect dangerous-strict-equality,arithmetic,assembly,controlled-delegatecall`<br>2. Write a Foundry fuzz test `testFuzz_VerifierRejectsRandomProof(bytes calldata fakeProof)` — should revert or return false for any input<br>3. For trusted-setup systems (PLONK, Groth16): `verify --transcript transcript.json` against the published Powers of Tau ceremony<br>4. For universal-SRS systems (Halo2): confirm no trusted setup is referenced in the verifier<br>5. Submit a forged proof to the verifier on a fork and confirm rejection. |
| **Expected Results** | Verifier rejects every random input; trusted setup (where applicable) matches the published ceremony; no Slither HIGH findings on the verifier contract. |
| **False Positive Risk** | LOW — for random inputs, the verifier must reject 100% of the time (cryptographic soundness). |
| **Remediation (defense)** | Use audited proving systems; publish ceremony transcripts; prefer universal SRS (Halo2, Aztec); independent verifier contract audits. |
| **Related Tools** | slither, forge, mythril, powers-of-tau tools |

---

## E. Lightning Network & HTLC

### TC-L2-009: Lightning Network HTLC Pin Attack (Regtest Lab)

| Field | Value |
|------|-----|
| **ID** | TC-L2-009 |
| **Name** | Lightning Network HTLC Pin Attack (Regtest) |
| **Severity** | HIGH |
| **Category** | Lightning & HTLC |
| **Objective** | Demonstrate the HTLC-pin DoS attack against a Lightning routing node (victim B), tie up its channel capital in pending HTLCs until CLTV expiry, and measure the impact. |
| **Prerequisites** | Lightning daemon installed (c-lightning or LND); regtest cluster of >= 3 nodes (A <-> B <-> C) with channels open; bitcoind in regtest mode. |
| **Test Steps** | 1. Bring up the regtest cluster (Polar Lightning or manual c-lightning setup).<br>2. Open channels A -> B and B -> C with 1,000,000 sat each.<br>3. Verify routing works: pay from A to C through B.<br>4. From A, generate 483 invoices (BOLT max HTLCs per channel) on C, each for 1000 msat with a 1000-block CLTV.<br>5. Pay each invoice from A through B to C: `lightning-cli --lightning-dir=/tmp/l1 pay ...`<br>6. Observe B's channel state: `lightning-cli --lightning-dir=/tmp/l2 listpeers` shows 483 pending HTLCs.<br>7. Verify B cannot forward any new HTLCs (capital pinned).<br>8. Measure how long until the HTLCs expire (CLTV) and B can settle. |
| **Expected Results** | B's channel is pinned — capital locked in 483 pending HTLCs, no new forwards possible until CLTV expiry. |
| **False Positive Risk** | LOW — regtest is deterministic. |
| **Remediation (defense)** | Limit max HTLCs per channel; use anchor-commitment format for fee bumping; deploy a WatchTower service; monitor for HTLC-pin patterns. |
| **Related Tools** | c-lightning, LND, Polar Lightning |

---

## F. Account Abstraction (ERC-4337)

### TC-L2-010: ERC-4337 Bundler Griefing + Paymaster Solvency Test

| Field | Value |
|------|-----|
| **ID** | TC-L2-010 |
| **Name** | ERC-4337 Bundler Griefing + Paymaster Solvency Test |
| **Severity** | HIGH |
| **Category** | Account Abstraction |
| **Objective** | Verify the ERC-4337 EntryPoint handles bundle-reverting UserOperations safely and that the Paymaster cannot be drained via double-withdrawal bugs. |
| **Prerequisites** | `@account-abstraction/contracts` installed; local EntryPoint deployed on anvil; forge test suite with `test/BundlerGrief.t.sol` and `test/PaymasterGrief.t.sol` written. |
| **Test Steps** | 1. Deploy the canonical EntryPoint locally<br>2. Submit a UserOperation whose `callData` reverts only in bundle context (gas-context check)<br>3. Verify the bundler rejects it before inclusion (off-chain simulation)<br>4. If the bundler accepts it, demonstrate that the whole bundle reverts, griefing other users<br>5. Deploy a Paymaster with a deliberate double-withdrawal bug (no balance decrement)<br>6. Demonstrate the double-withdrawal: `pm.deposit{value: 1 ether}(); pm.withdrawTo(...); pm.withdrawTo(...);`<br>7. Assert attacker drains > 1 ETH from a 1 ETH deposit. |
| **Expected Results** | Bundler rejects bundle-context-reverting ops (or the EntryPoint isolates failures via try/catch); Paymaster bug allows double-withdrawal (HIGH finding). |
| **False Positive Risk** | MEDIUM — the EntryPoint's failure isolation must be carefully tested; some reverts may be legitimate. |
| **Remediation (defense)** | Bundler must run off-chain simulation matching on-chain execution; Paymaster must decrement deposits on withdrawal; use ReentrancyGuard on Paymaster. |
| **Related Tools** | forge, @account-abstraction/contracts |

---

## G. Validator Set / Multisig Analysis

### TC-L2-011: Polygon PoS / Multisig Threshold & Geographic Distribution Review

| Field | Value |
|------|-----|
| **ID** | TC-L2-011 |
| **Name** | Polygon PoS Validator Set + Multisig Threshold Review |
| **Severity** | HIGH |
| **Category** | Validator Analysis |
| **Objective** | Compute the Nakamoto coefficient (minimum validators controlling >33% of stake) for Polygon PoS, and audit any off-chain multisig threshold (M-of-N) for M > N/2 with geographic distribution. |
| **Prerequisites** | L1 RPC; Polygon StakeManager ABI; on-chain multisig contract address; `web3.py` installed. |
| **Test Steps** | 1. Read the Polygon validator set: `cast call 0x5e3Ef299fDDf15eAa483AE762359C841972A5eC2 "getCurrentValidatorSet()" --rpc-url $L1_RPC`<br>2. Run `python3 scripts/polygon_nakamoto.py --rpc $L1_RPC` — outputs the Nakamoto coefficient (33% threshold)<br>3. If N <= 5: HIGH finding (chain is effectively centralized)<br>4. Read any off-chain multisig threshold: `cast call 0xMultisig "threshold()"`<br>5. If `threshold <= N/2`: HIGH finding (threshold below majority)<br>6. Document the geographic distribution of signers (operational review, not on-chain). |
| **Expected Results** | Nakamoto coefficient (33%) >= 10 for a healthy PoS chain; multisig threshold M > N/2; signers distributed across >= 3 jurisdictions. |
| **False Positive Risk** | MEDIUM — the Nakamoto coefficient depends on the chosen threshold (33%, 50%, 66%). Document the threshold used. |
| **Remediation (defense)** | Increase validator set diversity; raise multisig threshold to M > N/2; move keys to HSMs; distribute signers across jurisdictions. |
| **Related Tools** | cast, python3, web3.py |

---

## H. DA Layer & Property Invariants

### TC-L2-012: Bridge Lock-Mint Accounting Invariant Test

| Field | Value |
|------|-----|
| **ID** | TC-L2-012 |
| **Name** | Bridge Lock-Mint Accounting Invariant Test |
| **Severity** | MEDIUM |
| **Category** | DA Layer & Property Invariants |
| **Objective** | Define and verify the lock-mint accounting invariant — every mint on the destination chain corresponds to a lock on the source chain — using Echidna invariant fuzzing over minutes-to-hours of execution. |
| **Prerequisites** | Echidna installed; `echidna/LockMintEchidna.sol` harness written; L1 + L2 bridge contracts deployed locally. |
| **Test Steps** | 1. Write the Echidna harness with `echidna_mint_le_lock()` returning `l2.totalMinted() <= l1.totalLocked()`<br>2. Run: `echidna-test echidna/LockMintEchidna.sol --contract LockMintEchidna --test-mode property --test-limit 100000 --seq-len 5 --workers 4`<br>3. If Echidna finds a counterexample: extract the call sequence, reproduce as a forge test, document as a CRITICAL finding<br>4. Also run the round-trip invariant: `echidna_round_trip_no_loss(uint256 amount)` — lock then unlock should leave balances unchanged<br>5. Test the replay-protection invariant: same-nonce deposits must fail. |
| **Expected Results** | No counterexamples to `echidna_mint_le_lock`; round-trip invariant holds; replay protection reverts on duplicate nonces. |
| **False Positive Risk** | LOW — Echidna counterexamples are concrete exploits, not theoretical concerns. |
| **Remediation (defense)** | Apply Checks-Effects-Interactions on lock/mint/burn; add nonce-based replay protection; use a Sentinel to pause on mint-without-lock anomalies. |
| **Related Tools** | echidna, forge |

---

## Severity Rubric

| Severity | Definition | L2 Examples |
|----------|------------|-------------|
| **CRITICAL** | Funds at immediate risk; single transaction drains TVL | Bridge mint-without-lock; multisig threshold bypass; signature forgery accepted |
| **HIGH** | Significant impact, requires specific conditions | Sequencer censorship with no escape hatch; Paymaster double-withdrawal; HTLC pin DoS; ZK verifier accepts forged proof |
| **MEDIUM** | Defense-in-depth concern; not exploitable alone | Slither HIGH finding on `nonReentrant`-protected function; short fraud-proof window (5 days instead of 7); Nakamoto coefficient between 5-10 |
| **LOW** | Code quality / informational | Slither style findings; missing NatSpec; low test coverage on a leaf function |

---

## Test Case Selection Guide

| If auditing a... | Start with these TCs |
|---|---|
| Cross-chain bridge (any type) | TC-L2-001, TC-L2-002, TC-L2-003, TC-L2-004, TC-L2-005, TC-L2-012 |
| Optimistic rollup | TC-L2-001, TC-L2-006, TC-L2-007 |
| ZK rollup | TC-L2-001, TC-L2-008 |
| Polygon PoS or sidechain | TC-L2-001, TC-L2-011 |
| Lightning Network node | TC-L2-009 |
| ERC-4337 / account abstraction | TC-L2-010 |
| DA layer integration | TC-L2-001, TC-L2-008 (KZG verifier) |
| Post-incident forensic replay | TC-L2-003, TC-L2-004, TC-L2-005 (or fork-replay for the specific incident) |

---

End of `test-cases.md`. For the full audit workflow, see `guides/blockchain-l2-attack-playbook.md`.
