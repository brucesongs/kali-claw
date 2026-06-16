# Blockchain & Web3 Security Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.
> All commands assume a local anvil fork or testnet — never run exploit PoCs against mainnet contracts without explicit authorization (engagement scope, bug bounty terms, or self-audit of owned contracts).

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Static Analysis | 3 | LOW - HIGH |
| B. Dynamic Testing | 2 | MEDIUM - HIGH |
| C. Property & Invariant Testing | 2 | MEDIUM - HIGH |
| D. Exploit PoC | 3 | CRITICAL - HIGH |
| E. Defense Validation | 2 | MEDIUM - HIGH |
| **Total** | **12** | **LOW - CRITICAL** |

---

## A. Static Analysis

### TC-BW-001: Slither Full Detector Run

| Field | Value |
|------|-----|
| **ID** | TC-BW-001 |
| **Name** | Slither Full Detector Run |
| **Severity** | HIGH |
| **Category** | Static Analysis |
| **Objective** | Establish baseline finding list by running Slither's ~90 detectors over the contract repository, then triage HIGH/CRITICAL findings before deeper analysis. |
| **Prerequisites** | `pip3 install slither-analyzer solc-select`; `solc-select install 0.8.24 && solc-select use 0.8.24`; contract source repo cloned with `forge install` run. |
| **Test Steps** | 1. `slither . --filter-paths "lib\|test\|script\|mocks" --json slither_report.json`<br>2. Triage HIGH impact: `jq '.results.detectors[] \| select(.impact=="High") \| {check, first_slot, description}' slither_report.json`<br>3. Cross-reference each finding's `check` field against SWC IDs (see `payloads.md` §2)<br>4. Manually verify each HIGH finding in source — Slither false positives are common on intentionally-safe patterns (e.g., `nonReentrant` already applied) |
| **Expected Results** | Detector report covers all source files in scope; HIGH findings are reviewable within 1-2 hours; SWC IDs assigned for downstream report writing. |
| **False Positive Risk** | MEDIUM — Slither flags patterns, not exploits. A `reentrancy-benign` finding on a `nonReentrant`-protected function is informational, not exploitable. Manual confirmation is mandatory for any CRITICAL claim. |
| **Remediation (defense)** | Apply Checks-Effects-Interactions, OpenZeppelin `ReentrancyGuard`, and run Slither in CI to prevent regressions. |
| **Related Tools** | slither, jq, solc-select |

### TC-BW-002: Mythril Symbolic Execution (Deep Mode)

| Field | Value |
|------|-----|
| **ID** | TC-BW-002 |
| **Name** | Mythril Symbolic Execution (Deep Mode) |
| **Severity** | HIGH |
| **Category** | Static Analysis |
| **Objective** | Use symbolic execution to find arithmetic, reentrancy, and access-control bugs that pattern-based detectors miss — particularly in functions with deep branching. |
| **Prerequisites** | `pip3 install mythril`; contract compiles in solc 0.8+; 5-30 min wall-clock budget per contract. |
| **Test Steps** | 1. `myth analyze src/Vault.sol --execution-timeout 600 --max-depth 50 -o json > mythril_vault.json`<br>2. Filter for unique SWC IDs: `jq '.issues[] \| {swc_id, title, severity}' mythril_vault.json \| sort -u`<br>3. For each counterexample, extract the call trace: `myth analyze src/Vault.sol --verbose --modules reentrancy 2>&1 \| tee trace.log`<br>4. Reproduce the counterexample as a forge test to confirm exploitability |
| **Expected Results** | 1-5 counterexamples per contract for any non-trivial logic; counterexamples are reproducible as forge tests on a mainnet fork. |
| **False Positive Risk** | HIGH — Mythril reports any feasible counterexample, not all of which are exploitable in practice (e.g., requires an unlikely initial state). Reproduce as a forge PoC before promoting to a finding. |
| **Remediation (defense)** | Eliminate the counterexample by tightening preconditions or applying guardrails (e.g., `nonReentrant`). |
| **Related Tools** | mythril, forge, jq |

### TC-BW-003: Solhint Lint (Code Quality Baseline)

| Field | Value |
|------|-----|
| **ID** | TC-BW-003 |
| **Name** | Solhint Lint (Code Quality Baseline) |
| **Severity** | LOW |
| **Category** | Static Analysis |
| **Objective** | Enforce code quality and security style rules — surfaces code smells (shadowing, unused vars, missing NatSpec) that often correlate with logic bugs. |
| **Prerequisites** | `npm install -g solhint`; a `.solhint.json` config in the repo (recommended: `solhint --init` with the `solhint:recommended` ruleset). |
| **Test Steps** | 1. `solhint 'src/**/*.sol' --max-warnings 0 --formatter stylish`<br>2. Categorize findings: `solhint 'src/**/*.sol' --formatter unix \| awk -F: '{print $5}' \| sort \| uniq -c \| sort -rn`<br>3. Promote any `security/` rule violations to the audit report (e.g., `security/no-tx-origin`, `security/no-inline-assembly`) |
| **Expected Results** | 0 `security/`-prefixed violations; <10 `best-practise/`-prefixed violations per 1000 LOC. |
| **False Positive Risk** | LOW — Solhint is deterministic; a `security/` rule violation is a real concern. |
| **Remediation (defense)** | Fix all `security/` violations before deployment; integrate Solhint into pre-commit hooks. |
| **Related Tools** | solhint |

---

## B. Dynamic Testing

### TC-BW-004: Foundry Test Suite Execution with Stack Traces

| Field | Value |
|------|-----|
| **ID** | TC-BW-004 |
| **Name** | Foundry Test Suite Execution with Stack Traces |
| **Severity** | MEDIUM |
| **Category** | Dynamic Testing |
| **Objective** | Run the project's existing test suite, confirm it actually exercises the critical paths, and identify any untested external/public functions. |
| **Prerequisites** | Foundry installed (`foundryup`); `forge build` succeeds; `forge coverage` available. |
| **Test Steps** | 1. `forge test -vvv` (run all tests with traces)<br>2. `forge coverage --report lcov` then `lcov --summary lcov.info`<br>3. List uncovered external/public functions: `lcov --extract lcov.info 'src/**' \| grep -E 'FNDA:0'`<br>4. For each uncovered function, write a test or flag it as a finding |
| **Expected Results** | ≥80% line coverage on `src/`; every external/public function has at least one test. |
| **False Positive Risk** | MEDIUM — high coverage does not imply good test quality. A function can be "covered" by a happy-path test that misses every edge case. Inspect tests, not just coverage %. |
| **Remediation (defense)** | Add property tests (see TC-BW-006, TC-BW-007) for every external function with state-mutating logic. |
| **Related Tools** | forge, lcov |

### TC-BW-005: Mainnet Fork Replay of Past Incident

| Field | Value |
|------|-----|
| **ID** | TC-BW-005 |
| **Name** | Mainnet Fork Replay of Past Incident |
| **Severity** | HIGH |
| **Category** | Dynamic Testing |
| **Objective** | Reproduce a known past exploit (e.g., 2022 Nomad, 2023 Euler, 2024 Curve) on a local anvil fork at the block just before the incident — verify the exploit path and use it as a regression test against the patched code. |
| **Prerequisites** | `MAINNET_RPC` env var (Alchemy/Infura/Ankr); incident tx hash and pre-incident block number from Rekt.news or the post-mortem. |
| **Test Steps** | 1. `anvil --fork-url $MAINNET_RPC --fork-block-number <pre-incident-block> --port 8545 &`<br>2. Confirm fork state: `cast block-number --rpc-url http://localhost:8545`<br>3. Impersonate the attacker EOA: `cast rpc --rpc-url http://localhost:8545 anvil_impersonateAccount <attacker>`<br>4. Replay the attack tx: `cast send --rpc-url http://localhost:8545 --from <attacker> <exploit-calldata>` (decode via `cast 4byte-decode`)<br>5. Verify the same loss occurred (e.g., `cast balance <vault>` dropped to 0)<br>6. Swap in the patched contract code, re-run steps 1-5, verify the attack fails |
| **Expected Results** | Original exploit succeeds on the fork (proves the fork is faithful); patched version reverts. |
| **False Positive Risk** | LOW — fork replay is deterministic at a fixed block. Variability comes from RPC node drift, not the test. |
| **Remediation (defense)** | Add the replay test as a permanent regression test in the project's CI. |
| **Related Tools** | anvil, cast, forge |

---

## C. Property & Invariant Testing

### TC-BW-006: Echidna Property-Based Fuzzing

| Field | Value |
|------|-----|
| **ID** | TC-BW-006 |
| **Name** | Echidna Property-Based Fuzzing |
| **Severity** | HIGH |
| **Category** | Property Testing |
| **Objective** | Define and falsify invariants (accounting consistency, no-loss round trips, monotonic state) using Echidna's coverage-guided fuzzer over minutes-to-hours of execution. |
| **Prerequisites** | Echidna installed (`/usr/local/bin/echidna`); `echidna/ContractEchidna.sol` with `echidna_*` invariant functions written; `echidna.yaml` config. |
| **Test Steps** | 1. Write invariants in `echidna/VaultEchidna.sol` (see `payloads.md` §4 for templates)<br>2. `echidna-test echidna/VaultEchidna.sol --contract VaultEchidna --config echidna.yaml`<br>3. If a counterexample is found, Echidna prints the call sequence — capture it: `echidna-test ... 2>&1 \| tee corpus/counterexample.log`<br>4. Translate the call sequence into a forge PoC test<br>5. Iterate: add the failing sequence to the corpus, mutate, re-run |
| **Expected Results** | After 50k-500k test sequences, either (a) no counterexamples (invariant holds) or (b) counterexamples are reproducible and actionable. |
| **False Positive Risk** | MEDIUM — Echidna invariants must be written correctly. A buggy invariant (e.g., asserts a wrong condition) reports false positives. Peer-review invariants before treating results as authoritative. |
| **Remediation (defense)** | Fix the contract so the invariant holds under all inputs; re-run Echidna to confirm. |
| **Related Tools** | echidna, forge |

### TC-BW-007: Foundry Invariant (Stateful) Testing

| Field | Value |
|------|-----|
| **ID** | TC-BW-007 |
| **Name** | Foundry Invariant (Stateful) Testing |
| **Severity** | MEDIUM |
| **Category** | Property Testing |
| **Objective** | Use Foundry's built-in invariant fuzzer to drive random call sequences against a handler contract — faster integration than Echidna, runs in `forge test`. |
| **Prerequisites** | Foundry installed; `test/handlers/ContractHandler.sol` written (constrains fuzzer inputs to valid ranges); `invariant_*` functions in the test contract. |
| **Test Steps** | 1. Write a handler contract that wraps every external function with `bound()` constraints (see `payloads.md` §5)<br>2. Write `invariant_TotalSharesNeverNegative()` etc. in the test contract<br>3. `forge config set invariant.runs 256 && forge config set invariant.depth 500`<br>4. `forge test --match-test invariant_ -vvv`<br>5. If a counterexample is found, Foundry prints the handler call sequence; reproduce in a focused unit test |
| **Expected Results** | Invariants hold across 256 runs × 500-depth sequences (128k calls); failures have a minimal repro case. |
| **False Positive Risk** | MEDIUM — handler contracts can over-constrain inputs (masking bugs) or under-constrain them (triggering uninteresting reverts). Review the handler against the contract's external surface. |
| **Remediation (defense)** | Fix the contract; tighten the handler if the failure was an out-of-scope input. |
| **Related Tools** | forge |

### TC-BW-008: Certora Formal Verification Rule

| Field | Value |
|------|-----|
| **ID** | TC-BW-008 |
| **Name** | Certora Formal Verification Rule |
| **Severity** | HIGH |
| **Category** | Property Testing |
| **Objective** | Use Certora Prover to mathematically prove (or counterexample) critical invariants — for the highest-stakes properties (e.g., total deposits ≥ sum of withdrawable balances), no fuzzing substitute exists. |
| **Prerequisites** | Certora Prover installed and licensed (`certoraRun` on PATH); `specs/Contract.spec` written in CVL (Certora Verification Language); SMT solver (Z3) available. |
| **Test Steps** | 1. Write `specs/Vault.spec` declaring the rule: `rule noNegativeBalances { ... }`<br>2. `certoraRun src/Vault.sol --verify Vault:specs/Vault.spec --msg "vault: accounting"`<br>3. Inspect the report HTML for passed/failed rules<br>4. For any failing rule, click through to the counterexample call trace; reproduce in forge |
| **Expected Results** | All declared rules pass (green); failing rules have concrete counterexamples. |
| **False Positive Risk** | LOW — Certora is sound (no false positives on the rules it can express). Risk is in writing a too-weak rule that passes while missing the real bug. |
| **Remediation (defense)** | Tighten the spec to cover the counterexample; fix the contract to make the rule hold. |
| **Related Tools** | certoraRun, z3 |

---

## D. Exploit PoC

### TC-BW-009: Reentrancy Exploit PoC

| Field | Value |
|------|-----|
| **ID** | TC-BW-009 |
| **Name** | Reentrancy Exploit PoC |
| **Severity** | CRITICAL |
| **Category** | Exploit PoC |
| **Objective** | Write a concrete forge test that drains a vulnerable vault via reentrancy — proves the bug is exploitable, not theoretical. |
| **Prerequisites** | A contract with state written after an external call (CEI violation); Foundry installed; anvil fork running (optional — local deploy works for this PoC). |
| **Test Steps** | 1. Write the attacker contract with a `receive()` hook that re-enters `withdraw()` (see `payloads.md` §6.1)<br>2. Write the forge test: deploy vault → fund attacker → call `attacker.pwn()` → assert vault balance == 0<br>3. `forge test --match-test test_PoC_DrainViaReentrancy -vvvv`<br>4. Capture the trace for the report: `... -vvvv 2>&1 \| tee evidence/poc_reentrancy.log` |
| **Expected Results** | Vault balance reaches 0 in a single tx; attacker's balance > initial funding; trace shows the recursive `withdraw()` call chain. |
| **False Positive Risk** | LOW — a passing PoC is unambiguous evidence. The risk is the PoC contract having a different bug that masks the original (verify by also patching the vault and confirming the PoC now fails). |
| **Remediation (defense)** | Apply CEI; add `nonReentrant`; add an invariant test (`invariant_VaultBalanceMatchesAccounting`). |
| **Related Tools** | forge, anvil |

### TC-BW-010: Flash Loan + Oracle Manipulation PoC

| Field | Value |
|------|-----|
| **ID** | TC-BW-010 |
| **Name** | Flash Loan + Oracle Manipulation PoC |
| **Severity** | CRITICAL |
| **Category** | Exploit PoC |
| **Objective** | Borrow uncollateralized via Aave/Balancer, manipulate a spot-price oracle (Uniswap V2 reserves), exploit a lending protocol that trusts the spot price, repay the flash loan in the same tx. |
| **Prerequisites** | Anvil mainnet fork at a fixed block; Aave V3 + Uniswap V2 deployed on the fork; a victim contract using `IUniswapV2Pair.getReserves()` as a price source. |
| **Test Steps** | 1. `anvil --fork-url $MAINNET_RPC --fork-block-number 19000000 &`<br>2. Write `FlashLoanOracleAttacker` implementing `IFlashLoanReceiver` (see `payloads.md` §6.5)<br>3. In `executeOperation`: dump borrowed WETH into the pair → call `victim.borrow()` against the inflated price → reverse the swap → repay<br>4. `forge test --match-test test_PoC_FlashLoanOracle --fork-url http://localhost:8545 -vvvv`<br>5. Assert attacker profit > 0 and victim loss > 0 |
| **Expected Results** | Attacker extracts > $1M equivalent in a single tx; the trace shows the flash loan → price manipulation → victim borrow → unwind sequence. |
| **False Positive Risk** | MEDIUM — fork state drift between RPC providers can break the PoC. Pin the block number; use the same RPC provider as the production deployment if possible. |
| **Remediation (defense)** | Replace spot-price oracles with TWAP (Uniswap V3 `observe()`); add multi-block price consistency checks; add a sanity cap on borrow size relative to pair liquidity. |
| **Related Tools** | forge, anvil, cast |

### TC-BW-011: Integer Overflow / Access Control Bypass PoC

| Field | Value |
|------|-----|
| **ID** | TC-BW-011 |
| **Name** | Integer Overflow / Access Control Bypass PoC |
| **Severity** | HIGH |
| **Category** | Exploit PoC |
| **Objective** | Demonstrate two bug classes in one test: (a) arithmetic wrap in a pre-0.8.0 contract or `unchecked {}` block, and (b) missing access control on a privileged function. |
| **Prerequisites** | A contract with either (a) arithmetic under untrusted input and no overflow check, or (b) an admin/destroy function lacking an `onlyOwner` or `onlyRole` modifier. |
| **Test Steps** | 1. **Overflow PoC**: call `buy(type(uint256).max / 1 ether + 1)` — assert caller receives tokens while paying ~0<br>2. **Access control PoC**: call `destroy()` from a non-owner address — assert it succeeds (the bug)<br>3. `forge test --match-test test_PoC_Overflow -vvvv` and `forge test --match-test test_PoC_AccessControl -vvvv` |
| **Expected Results** | Overflow PoC: attacker receives a huge token balance for ~0 cost. Access control PoC: arbitrary caller triggers `selfdestruct` or admin action. |
| **False Positive Risk** | LOW — both classes are unambiguous. For overflow, double-check the compiler version (`solc-select use 0.7.6` to reproduce pre-0.8 semantics). |
| **Remediation (defense)** | Upgrade to Solidity 0.8+; remove unnecessary `unchecked {}` blocks; apply `AccessControl` from OpenZeppelin to every privileged function. |
| **Related Tools** | forge, solc-select |

---

## E. Defense Validation

### TC-BW-012: OpenZeppelin ReentrancyGuard / AccessControl Integration Test

| Field | Value |
|------|-----|
| **ID** | TC-BW-012 |
| **Name** | OpenZeppelin ReentrancyGuard / AccessControl Integration Test |
| **Severity** | HIGH |
| **Category** | Defense Validation |
| **Objective** | From the defense side, confirm that the OpenZeppelin defenses (ReentrancyGuard, AccessControl) are correctly inherited and that the same reentrancy/access-control PoCs from TC-BW-009 / TC-BW-011 now fail. |
| **Prerequisites** | Contract updated to inherit `ReentrancyGuard` and `AccessControl`; `nonReentrant` modifier on every external function with an external call; `onlyRole(GUARDIAN_ROLE)` on every privileged function. |
| **Test Steps** | 1. Re-run TC-BW-009's attacker contract against the patched vault → expect revert with `ReentrancyGuard: reentrant call`<br>2. Re-run TC-BW-011's access-control PoC → expect revert with `AccessControl: account <addr> is missing role <role>`<br>3. `forge test --match-test test_PoC_DrainViaReentrancy -vvv` (should FAIL on the patched contract = PASS for defense)<br>4. Confirm invariants (`invariant_VaultBalanceMatchesAccounting`) now hold |
| **Expected Results** | Both exploit PoCs revert cleanly; invariants hold across all fuzz runs. |
| **False Positive Risk** | LOW — passing PoC (reverts on patched) is a clean signal. The risk is over-fitting: the defense might prevent the specific PoC but not the underlying class. Add a variant PoC that attacks via a different external function. |
| **Remediation (defense)** | Add the regression PoCs to CI; document the defense mechanism in the audit report's "Mitigation Verified" section. |
| **Related Tools** | forge, @openzeppelin/contracts |

### TC-BW-013: Multi-Sig + Timelock Governance Review

| Field | Value |
|------|-----|
| **ID** | TC-BW-013 |
| **Name** | Multi-Sig + Timelock Governance Review |
| **Severity** | MEDIUM |
| **Category** | Defense Validation |
| **Objective** | Verify that admin keys are behind a Gnosis Safe with M-of-N signers (M ≥ 3, N ≥ 5), and that every admin action (upgrade, parameter change, fund move) is gated by a 48h+ timelock. |
| **Prerequisites** | Target protocol deployed; admin Safe address known; TimelockController address known; access to Etherscan to verify on-chain setup. |
| **Test Steps** | 1. Verify the Safe setup: `cast call <safe> "getThreshold()" --rpc-url $RPC` (should return ≥ 3)<br>2. Verify owners: `cast call <safe> "getOwners()" --rpc-url $RPC` (should return ≥ 5 distinct addresses, ideally across different entities)<br>3. Verify the TimelockController `minDelay`: `cast call <timelock> "getMinDelay()" --rpc-url $RPC` (should return ≥ 172800 = 48h)<br>4. Confirm that the privileged roles on the contract (`DEFAULT_ADMIN_ROLE`, `GUARDIAN_ROLE`, etc.) are assigned to the TimelockController, not to an EOA<br>5. Submit a benign upgrade proposal; confirm it sits in the timelock queue for ≥ 48h before execution |
| **Expected Results** | Safe threshold ≥ 3 of ≥ 5 owners; timelock ≥ 48h; no privileged role is held by an EOA directly. |
| **False Positive Risk** | MEDIUM — a Safe with threshold 3-of-5 is weak if 3 signers share infrastructure (same laptop image, same email provider). Review the signer set's operational independence, not just the on-chain threshold. |
| **Remediation (defense)** | Increase threshold if TVL > $10M; require signers from ≥ 2 organizations; publish every upgrade to a governance forum ≥ 7 days before queueing on-chain. |
| **Related Tools** | cast, gnosis-safe |

---

## Summary Table

| ID | Name | Severity | Category |
|------|------|----------|----------|
| TC-BW-001 | Slither Full Detector Run | HIGH | Static Analysis |
| TC-BW-002 | Mythril Symbolic Execution (Deep Mode) | HIGH | Static Analysis |
| TC-BW-003 | Solhint Lint (Code Quality Baseline) | LOW | Static Analysis |
| TC-BW-004 | Foundry Test Suite Execution with Stack Traces | MEDIUM | Dynamic Testing |
| TC-BW-005 | Mainnet Fork Replay of Past Incident | HIGH | Dynamic Testing |
| TC-BW-006 | Echidna Property-Based Fuzzing | HIGH | Property Testing |
| TC-BW-007 | Foundry Invariant (Stateful) Testing | MEDIUM | Property Testing |
| TC-BW-008 | Certora Formal Verification Rule | HIGH | Property Testing |
| TC-BW-009 | Reentrancy Exploit PoC | CRITICAL | Exploit PoC |
| TC-BW-010 | Flash Loan + Oracle Manipulation PoC | CRITICAL | Exploit PoC |
| TC-BW-011 | Integer Overflow / Access Control Bypass PoC | HIGH | Exploit PoC |
| TC-BW-012 | OpenZeppelin ReentrancyGuard / AccessControl Integration Test | HIGH | Defense Validation |
| TC-BW-013 | Multi-Sig + Timelock Governance Review | MEDIUM | Defense Validation |

---

**Related files**: `SKILL.md`, `payloads.md`, `guides/smart-contract-audit-playbook.md`
**SWC Registry**: [swcregistry.io](https://swcregistry.io)
**Foundry book**: [book.getfoundry.sh](https://book.getfoundry.sh)
